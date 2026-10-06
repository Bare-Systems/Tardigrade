//! Deterministic, offline certification-path validation fixtures (#345).

const std = @import("std");
const crypto = @import("crypto");
const der = @import("der.zig");
const name_constraints = @import("name_constraints.zig");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const pem = @import("pem.zig");
const validator = @import("path_validator.zig");
const x509 = @import("x509.zig");

const testing = std.testing;
const validation_time: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z
const openssl_root_pem = @embedFile("testdata/path_validator_ed25519_root.crt");
const openssl_leaf_pem = @embedFile("testdata/path_validator_ed25519_leaf.crt");
const rsa_root_pem = @embedFile("testdata/path_validator_rsa_root.crt");
const rsa_key_encipherment_leaf_pem = @embedFile("testdata/path_validator_rsa_key_encipherment_leaf.crt");
const rsa_digital_signature_leaf_pem = @embedFile("testdata/path_validator_rsa_digital_signature_leaf.crt");

fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
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
    var buffer: [64]u8 = undefined;
    const len = try oid.encodeComponents(components, &buffer);
    return tlv(arena, 0x06, &.{buffer[0..len]});
}

fn algorithmEd25519(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &oid.well_known.ed25519)});
}

fn nameWithCn(arena: std.mem.Allocator, common_name: []const u8) ![]u8 {
    const attribute = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{common_name}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{attribute})});
}

fn nameWithCnAndEmail(arena: std.mem.Allocator, common_name: []const u8, email: []const u8) ![]u8 {
    const common_name_attribute = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{common_name}),
    });
    const email_attribute = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.email_address),
        try tlv(arena, 0x16, &.{email}),
    });
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x31, &.{common_name_attribute}),
        try tlv(arena, 0x31, &.{email_attribute}),
    });
}

fn validity(arena: std.mem.Allocator, not_before: []const u8, not_after: []const u8) ![]u8 {
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{not_before}),
        try tlv(arena, 0x17, &.{not_after}),
    });
}

fn seed(id: u8) [32]u8 {
    return [_]u8{id} ** 32;
}

fn publicKey(id: u8) ![32]u8 {
    var key = try crypto.pure_zig.SoftwareSigningKey.fromSeed(seed(id));
    defer key.deinit();
    return key.publicKey();
}

fn spkiEd25519(arena: std.mem.Allocator, key_id: u8) ![]u8 {
    const public_key = try publicKey(key_id);
    const bits = [_]u8{0} ++ public_key;
    return tlv(arena, 0x30, &.{
        try algorithmEd25519(arena),
        try tlv(arena, 0x03, &.{&bits}),
    });
}

fn extensionTlv(
    arena: std.mem.Allocator,
    components: []const u32,
    critical: bool,
    value: []const u8,
) ![]u8 {
    if (critical) {
        return tlv(arena, 0x30, &.{
            try oidTlv(arena, components),
            try tlv(arena, 0x01, &.{&[_]u8{0xff}}),
            try tlv(arena, 0x04, &.{value}),
        });
    }
    return tlv(arena, 0x30, &.{
        try oidTlv(arena, components),
        try tlv(arena, 0x04, &.{value}),
    });
}

fn basicConstraintsValue(arena: std.mem.Allocator, is_ca: bool, path_len: ?u8) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (is_ca) try parts.append(arena, try tlv(arena, 0x01, &.{&[_]u8{0xff}}));
    if (path_len) |limit| try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{limit}}));
    return tlv(arena, 0x30, parts.items);
}

fn keyUsageValue(arena: std.mem.Allocator, named_bits: u8) ![]u8 {
    var unused: u8 = 0;
    var probe = named_bits;
    while (probe & 1 == 0 and unused < 7) : (unused += 1) probe >>= 1;
    return tlv(arena, 0x03, &.{&[_]u8{ unused, named_bits }});
}

const Eku = enum { absent, server, client, any };

fn ekuValue(arena: std.mem.Allocator, eku: Eku) ![]u8 {
    const components: []const u32 = switch (eku) {
        .server => &oid.well_known.server_auth,
        .client => &oid.well_known.client_auth,
        .any => &oid.well_known.any_ext_key_usage,
        .absent => unreachable,
    };
    return tlv(arena, 0x30, &.{try oidTlv(arena, components)});
}

const GeneralNameSpec = union(enum) {
    dns: []const u8,
    email: []const u8,
    uri: []const u8,
    ip: []const u8,
    directory_cn: []const u8,
    registered_id: []const u32,
};

fn generalNameValue(arena: std.mem.Allocator, name: GeneralNameSpec) ![]const u8 {
    return switch (name) {
        .dns => |value| tlv(arena, 0x82, &.{value}),
        .email => |value| tlv(arena, 0x81, &.{value}),
        .uri => |value| tlv(arena, 0x86, &.{value}),
        .ip => |value| tlv(arena, 0x87, &.{value}),
        .directory_cn => |value| tlv(arena, 0xa4, &.{try nameWithCn(arena, value)}),
        .registered_id => |components| blk: {
            var buffer: [64]u8 = undefined;
            const len = try oid.encodeComponents(components, &buffer);
            break :blk tlv(arena, 0x88, &.{buffer[0..len]});
        },
    };
}

fn sanValue(arena: std.mem.Allocator, names: []const GeneralNameSpec) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    for (names) |name| try parts.append(arena, try generalNameValue(arena, name));
    return tlv(arena, 0x30, parts.items);
}

const NameConstraintsSpec = struct {
    permitted: []const GeneralNameSpec = &.{},
    excluded: []const GeneralNameSpec = &.{},
    critical: bool = true,
};

const PolicyQualifierSpec = union(enum) {
    cps: []const u8,
    user_notice: []const u8,
    user_notice_negative_number: []const u8,
    user_notice_nonminimal_number: []const u8,
    unsupported: []const u32,
};

const PolicySpec = struct {
    policy: []const u32,
    qualifiers: []const PolicyQualifierSpec = &.{},
};

fn certificatePoliciesValue(arena: std.mem.Allocator, policies: []const PolicySpec) ![]u8 {
    var policy_parts: std.ArrayList([]const u8) = .empty;
    defer policy_parts.deinit(arena);
    for (policies) |policy_spec| {
        var info_parts: std.ArrayList([]const u8) = .empty;
        defer info_parts.deinit(arena);
        try info_parts.append(arena, try oidTlv(arena, policy_spec.policy));
        if (policy_spec.qualifiers.len != 0) {
            var qualifier_parts: std.ArrayList([]const u8) = .empty;
            defer qualifier_parts.deinit(arena);
            for (policy_spec.qualifiers) |qualifier| {
                const qualifier_oid: []const u32 = switch (qualifier) {
                    .cps => &oid.well_known.policy_qualifier_cps,
                    .user_notice => &oid.well_known.policy_qualifier_user_notice,
                    .user_notice_negative_number => &oid.well_known.policy_qualifier_user_notice,
                    .user_notice_nonminimal_number => &oid.well_known.policy_qualifier_user_notice,
                    .unsupported => |components| components,
                };
                const value = switch (qualifier) {
                    .cps => |uri| try tlv(arena, 0x16, &.{uri}),
                    .user_notice => |text| try tlv(arena, 0x30, &.{try tlv(arena, 0x0c, &.{text})}),
                    .user_notice_negative_number => |organization| try tlv(arena, 0x30, &.{try tlv(arena, 0x30, &.{
                        try tlv(arena, 0x0c, &.{organization}),
                        try tlv(arena, 0x30, &.{try tlv(arena, 0x02, &.{&[_]u8{0xff}})}),
                    })}),
                    .user_notice_nonminimal_number => |organization| try tlv(arena, 0x30, &.{try tlv(arena, 0x30, &.{
                        try tlv(arena, 0x0c, &.{organization}),
                        try tlv(arena, 0x30, &.{try tlv(arena, 0x02, &.{&[_]u8{ 0xff, 0xff }})}),
                    })}),
                    .unsupported => try tlv(arena, 0x05, &.{}),
                };
                try qualifier_parts.append(arena, try tlv(arena, 0x30, &.{
                    try oidTlv(arena, qualifier_oid),
                    value,
                }));
            }
            try info_parts.append(arena, try tlv(arena, 0x30, qualifier_parts.items));
        }
        try policy_parts.append(arena, try tlv(arena, 0x30, info_parts.items));
    }
    return tlv(arena, 0x30, policy_parts.items);
}

const PolicyMappingSpec = struct {
    issuer: []const u32,
    subject: []const u32,
};

fn policyMappingsValue(arena: std.mem.Allocator, mappings: []const PolicyMappingSpec) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    for (mappings) |mapping| {
        try parts.append(arena, try tlv(arena, 0x30, &.{
            try oidTlv(arena, mapping.issuer),
            try oidTlv(arena, mapping.subject),
        }));
    }
    return tlv(arena, 0x30, parts.items);
}

const PolicyConstraintsSpec = struct {
    require_explicit_policy: ?u32 = null,
    inhibit_policy_mapping: ?u32 = null,
    critical: bool = true,
};

fn nonNegativeIntegerContent(arena: std.mem.Allocator, value: u32) ![]const u8 {
    var encoded: [5]u8 = undefined;
    std.mem.writeInt(u32, encoded[1..5], value, .big);
    var first: usize = 1;
    while (first < 4 and encoded[first] == 0) first += 1;
    if (encoded[first] & 0x80 != 0) {
        first -= 1;
        encoded[first] = 0;
    }
    return arena.dupe(u8, encoded[first..]);
}

fn policyConstraintsValue(arena: std.mem.Allocator, constraints: PolicyConstraintsSpec) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (constraints.require_explicit_policy) |value| {
        try parts.append(arena, try tlv(arena, 0x80, &.{try nonNegativeIntegerContent(arena, value)}));
    }
    if (constraints.inhibit_policy_mapping) |value| {
        try parts.append(arena, try tlv(arena, 0x81, &.{try nonNegativeIntegerContent(arena, value)}));
    }
    return tlv(arena, 0x30, parts.items);
}

fn nameConstraintsValue(arena: std.mem.Allocator, spec: NameConstraintsSpec) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (spec.permitted.len != 0) {
        var subtrees: std.ArrayList([]const u8) = .empty;
        defer subtrees.deinit(arena);
        for (spec.permitted) |name| {
            try subtrees.append(arena, try tlv(arena, 0x30, &.{try generalNameValue(arena, name)}));
        }
        try parts.append(arena, try tlv(arena, 0xa0, subtrees.items));
    }
    if (spec.excluded.len != 0) {
        var subtrees: std.ArrayList([]const u8) = .empty;
        defer subtrees.deinit(arena);
        for (spec.excluded) |name| {
            try subtrees.append(arena, try tlv(arena, 0x30, &.{try generalNameValue(arena, name)}));
        }
        try parts.append(arena, try tlv(arena, 0xa1, subtrees.items));
    }
    return tlv(arena, 0x30, parts.items);
}

const Spec = struct {
    subject: []const u8,
    issuer: []const u8,
    subject_key: u8,
    issuer_key: u8,
    not_before: []const u8 = "260101000000Z",
    not_after: []const u8 = "270101000000Z",
    ca: ?bool = null,
    path_len: ?u8 = null,
    /// First Key Usage content octet: digitalSignature=0x80,
    /// keyEncipherment=0x20, keyCertSign=0x04.
    key_usage: ?u8 = null,
    eku: Eku = .absent,
    subject_email: ?[]const u8 = null,
    san: ?[]const u8 = null,
    san_names: []const GeneralNameSpec = &.{},
    san_critical: bool = false,
    name_constraints: ?NameConstraintsSpec = null,
    certificate_policies: ?[]const PolicySpec = null,
    raw_certificate_policies: ?[]const u8 = null,
    certificate_policies_critical: bool = false,
    policy_mappings: ?[]const PolicyMappingSpec = null,
    raw_policy_mappings: ?[]const u8 = null,
    policy_mappings_critical: bool = true,
    policy_constraints: ?PolicyConstraintsSpec = null,
    raw_policy_constraints: ?[]const u8 = null,
    inhibit_any_policy: ?u32 = null,
    raw_inhibit_any_policy: ?[]const u8 = null,
    inhibit_any_policy_critical: bool = true,
    unknown_critical: bool = false,
    unknown_noncritical: bool = false,
    /// RFC 7633 TLS Feature values; `status_request` is must-staple.
    tls_features: ?[]const u16 = null,
    tls_features_critical: bool = false,
};

const Fixtures = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    certs: std.ArrayList(x509.Certificate) = .empty,

    fn init(allocator: std.mem.Allocator) Fixtures {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *Fixtures) void {
        for (self.certs.items) |*certificate| certificate.deinit(self.allocator);
        self.certs.deinit(self.allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    fn add(self: *Fixtures, spec: Spec) !void {
        const arena = self.arena.allocator();
        var extensions: std.ArrayList([]const u8) = .empty;
        defer extensions.deinit(arena);

        if (spec.ca) |is_ca| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.basic_constraints,
                true,
                try basicConstraintsValue(arena, is_ca, spec.path_len),
            ));
        }
        if (spec.key_usage) |usage| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.key_usage,
                true,
                try keyUsageValue(arena, usage),
            ));
        }
        if (spec.eku != .absent) {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.ext_key_usage,
                false,
                try ekuValue(arena, spec.eku),
            ));
        }
        if (spec.san) |dns_name| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.subject_alt_name,
                spec.san_critical,
                try sanValue(arena, &.{.{ .dns = dns_name }}),
            ));
        }
        if (spec.san_names.len != 0) {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.subject_alt_name,
                spec.san_critical,
                try sanValue(arena, spec.san_names),
            ));
        }
        if (spec.name_constraints) |constraints| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.name_constraints,
                constraints.critical,
                try nameConstraintsValue(arena, constraints),
            ));
        }
        if (spec.certificate_policies) |policies| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.certificate_policies,
                spec.certificate_policies_critical,
                try certificatePoliciesValue(arena, policies),
            ));
        }
        if (spec.raw_certificate_policies) |value| {
            try extensions.append(arena, try extensionTlv(arena, &oid.well_known.certificate_policies, spec.certificate_policies_critical, value));
        }
        if (spec.policy_mappings) |mappings| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.policy_mappings,
                spec.policy_mappings_critical,
                try policyMappingsValue(arena, mappings),
            ));
        }
        if (spec.raw_policy_mappings) |value| {
            try extensions.append(arena, try extensionTlv(arena, &oid.well_known.policy_mappings, spec.policy_mappings_critical, value));
        }
        if (spec.policy_constraints) |constraints| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.policy_constraints,
                constraints.critical,
                try policyConstraintsValue(arena, constraints),
            ));
        }
        if (spec.raw_policy_constraints) |value| {
            try extensions.append(arena, try extensionTlv(arena, &oid.well_known.policy_constraints, true, value));
        }
        if (spec.inhibit_any_policy) |count| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.inhibit_any_policy,
                spec.inhibit_any_policy_critical,
                try tlv(arena, 0x02, &.{try nonNegativeIntegerContent(arena, count)}),
            ));
        }
        if (spec.raw_inhibit_any_policy) |value| {
            try extensions.append(arena, try extensionTlv(arena, &oid.well_known.inhibit_any_policy, true, value));
        }
        if (spec.tls_features) |features| {
            var feature_parts: std.ArrayList([]const u8) = .empty;
            defer feature_parts.deinit(arena);
            for (features) |feature| {
                try feature_parts.append(arena, try tlv(arena, 0x02, &.{
                    try nonNegativeIntegerContent(arena, feature),
                }));
            }
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.tls_feature,
                spec.tls_features_critical,
                try tlv(arena, 0x30, feature_parts.items),
            ));
        }
        const unknown_oid = [_]u32{ 1, 2, 3, 4 };
        if (spec.unknown_critical) {
            try extensions.append(arena, try extensionTlv(arena, &unknown_oid, true, &.{ 0x05, 0x00 }));
        }
        if (spec.unknown_noncritical) {
            try extensions.append(arena, try extensionTlv(arena, &unknown_oid, false, &.{ 0x05, 0x00 }));
        }

        var tbs_parts: std.ArrayList([]const u8) = .empty;
        defer tbs_parts.deinit(arena);
        try tbs_parts.append(arena, try tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{2}})}));
        const serial: u8 = @intCast(self.certs.items.len + 1);
        try tbs_parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{serial}}));
        try tbs_parts.append(arena, try algorithmEd25519(arena));
        try tbs_parts.append(arena, try nameWithCn(arena, spec.issuer));
        try tbs_parts.append(arena, try validity(arena, spec.not_before, spec.not_after));
        const subject_name = if (spec.subject_email) |email|
            try nameWithCnAndEmail(arena, spec.subject, email)
        else if (spec.subject.len == 0)
            try tlv(arena, 0x30, &.{})
        else
            try nameWithCn(arena, spec.subject);
        try tbs_parts.append(arena, subject_name);
        try tbs_parts.append(arena, try spkiEd25519(arena, spec.subject_key));
        if (extensions.items.len > 0) {
            try tbs_parts.append(arena, try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions.items)}));
        }
        const tbs = try tlv(arena, 0x30, tbs_parts.items);

        var entropy = crypto.pure_zig.DeterministicEntropy.init(0x345);
        var signing_key = try crypto.pure_zig.SoftwareSigningKey.fromSeed(seed(spec.issuer_key));
        defer signing_key.deinit();
        var signature: [64]u8 = undefined;
        const signature_len = try signing_key.signingKey().sign(tbs, entropy.entropy(), &signature);
        const signature_bits = [_]u8{0} ++ signature;
        const certificate_der = try tlv(arena, 0x30, &.{
            tbs,
            try algorithmEd25519(arena),
            try tlv(arena, 0x03, &.{signature_bits[0 .. signature_len + 1]}),
        });

        const certificate = try x509.Certificate.parse(self.allocator, certificate_der, .{});
        errdefer {
            var owned = certificate;
            owned.deinit(self.allocator);
        }
        try self.certs.append(self.allocator, certificate);
    }
};

fn cryptoProvider(
    entropy: *crypto.pure_zig.DeterministicEntropy,
    provider: *crypto.pure_zig.Provider,
) crypto.provider.CryptoProvider {
    entropy.* = crypto.pure_zig.DeterministicEntropy.init(0x345);
    provider.* = crypto.pure_zig.Provider.init(entropy.entropy());
    return provider.cryptoProvider();
}

fn policy(anchors: []const x509.Certificate) validator.ValidationPolicy {
    return .{ .validation_time = validation_time, .trust_anchors = anchors };
}

fn validateBuilt(
    allocator: std.mem.Allocator,
    leaf: *const x509.Certificate,
    intermediates: []const x509.Certificate,
    anchors: []const x509.Certificate,
    validation_policy: validator.ValidationPolicy,
    provider: crypto.provider.CryptoProvider,
) !validator.ValidationResult {
    var candidates = try path_builder.build(allocator, leaf, intermediates, anchors, .{});
    defer candidates.deinit(allocator);
    return validator.validateCandidates(allocator, candidates, validation_policy, provider);
}

fn expectAccepted(result: *validator.ValidationResult, expected_len: usize) !void {
    switch (result.*) {
        .accepted => |accepted| try testing.expectEqual(expected_len, accepted.accepted_path.len),
        .rejected => |rejected| {
            std.debug.print("unexpected validation rejection: {s} at {?}\n", .{ @tagName(rejected.reason), rejected.certificate_index });
            return error.TestUnexpectedResult;
        },
    }
}

fn expectRejected(result: *validator.ValidationResult, reason: validator.FailureReason, index: ?usize) !void {
    switch (result.*) {
        .accepted => return error.TestUnexpectedResult,
        .rejected => |rejected| {
            try testing.expectEqual(reason, rejected.reason);
            try testing.expectEqual(index, rejected.certificate_index);
        },
    }
}

fn addValidChain(fx: *Fixtures, root_path_len: ?u8) !void {
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .eku = .server,
        .san = "leaf.example.com",
    });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .path_len = 0,
        .key_usage = 0x04,
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .path_len = root_path_len,
        .key_usage = 0x04,
    });
}

test "valid three-certificate and direct-anchor paths pass" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);
    try fx.add(.{
        .subject = "direct",
        .issuer = "Root",
        .subject_key = 4,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var chain = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer chain.deinit(testing.allocator);
    try expectAccepted(&chain, 3);

    var direct = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer direct.deinit(testing.allocator);
    try expectAccepted(&direct, 2);
}

test "OpenSSL-generated Ed25519 leaf and anchor validate independently" {
    var root_pem = try pem.loadCertificatePem(testing.allocator, openssl_root_pem, .{});
    defer root_pem.deinit(testing.allocator);
    var leaf_pem = try pem.loadCertificatePem(testing.allocator, openssl_leaf_pem, .{});
    defer leaf_pem.deinit(testing.allocator);
    var root = try x509.Certificate.parse(testing.allocator, root_pem.der, .{});
    defer root.deinit(testing.allocator);
    var leaf = try x509.Certificate.parse(testing.allocator, leaf_pem.der, .{});
    defer leaf.deinit(testing.allocator);

    const elements = [_]path_builder.Element{
        .{ .certificate = &leaf, .source = .leaf, .input_index = 0 },
        .{ .certificate = &root, .source = .anchor, .input_index = 0 },
    };
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var validation_policy = policy((&root)[0..1]);
    validation_policy.validation_time = 1_784_332_800; // 2026-07-18T00:00:00Z
    validation_policy.expected_dns_name = "openssl.example.com";
    var result = validator.validatePath(testing.allocator, .{ .elements = &elements }, validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 2);
}

test "TLS 1.3 RSA leaf requires digitalSignature rather than keyEncipherment" {
    var root_pem = try pem.loadCertificatePem(testing.allocator, rsa_root_pem, .{});
    defer root_pem.deinit(testing.allocator);
    var key_encipherment_pem = try pem.loadCertificatePem(testing.allocator, rsa_key_encipherment_leaf_pem, .{});
    defer key_encipherment_pem.deinit(testing.allocator);
    var digital_signature_pem = try pem.loadCertificatePem(testing.allocator, rsa_digital_signature_leaf_pem, .{});
    defer digital_signature_pem.deinit(testing.allocator);
    var root = try x509.Certificate.parse(testing.allocator, root_pem.der, .{});
    defer root.deinit(testing.allocator);
    var key_encipherment_leaf = try x509.Certificate.parse(testing.allocator, key_encipherment_pem.der, .{});
    defer key_encipherment_leaf.deinit(testing.allocator);
    var digital_signature_leaf = try x509.Certificate.parse(testing.allocator, digital_signature_pem.der, .{});
    defer digital_signature_leaf.deinit(testing.allocator);

    try testing.expectEqual(x509.PublicKeyType.rsa, key_encipherment_leaf.subject_public_key_info.key_type);
    try testing.expect(key_encipherment_leaf.keyUsage().?.key_encipherment);
    try testing.expect(!key_encipherment_leaf.keyUsage().?.digital_signature);
    try testing.expectEqual(x509.PublicKeyType.rsa, digital_signature_leaf.subject_public_key_info.key_type);
    try testing.expect(digital_signature_leaf.keyUsage().?.digital_signature);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var validation_policy = policy((&root)[0..1]);
    validation_policy.validation_time = 1_784_332_800; // 2026-07-18T00:00:00Z

    const key_encipherment_elements = [_]path_builder.Element{
        .{ .certificate = &key_encipherment_leaf, .source = .leaf, .input_index = 0 },
        .{ .certificate = &root, .source = .anchor, .input_index = 0 },
    };
    var key_encipherment_result = validator.validatePath(testing.allocator, .{ .elements = &key_encipherment_elements }, validation_policy, cp);
    defer key_encipherment_result.deinit(testing.allocator);
    try expectRejected(&key_encipherment_result, .key_usage_violation, 0);

    const digital_signature_elements = [_]path_builder.Element{
        .{ .certificate = &digital_signature_leaf, .source = .leaf, .input_index = 0 },
        .{ .certificate = &root, .source = .anchor, .input_index = 0 },
    };
    var digital_signature_result = validator.validatePath(testing.allocator, .{ .elements = &digital_signature_elements }, validation_policy, cp);
    defer digital_signature_result.deinit(testing.allocator);
    try expectAccepted(&digital_signature_result, 2);
}

test "validity windows reject early and late certificates and include exact boundaries" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[0], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .anchor, .input_index = 0 },
    };
    const path = path_builder.Path{ .elements = &elements };

    var at_not_before = validator.validatePath(testing.allocator, path, .{
        .validation_time = 1_767_225_600,
        .trust_anchors = fx.certs.items[2..3],
    }, cp);
    defer at_not_before.deinit(testing.allocator);
    try expectAccepted(&at_not_before, 3);

    var at_not_after = validator.validatePath(testing.allocator, path, .{
        .validation_time = 1_798_761_600,
        .trust_anchors = fx.certs.items[2..3],
    }, cp);
    defer at_not_after.deinit(testing.allocator);
    try expectAccepted(&at_not_after, 3);

    var early = validator.validatePath(testing.allocator, path, .{
        .validation_time = 1_767_225_599,
        .trust_anchors = fx.certs.items[2..3],
    }, cp);
    defer early.deinit(testing.allocator);
    try expectRejected(&early, .certificate_not_yet_valid, 0);

    var late = validator.validatePath(testing.allocator, path, .{
        .validation_time = 1_798_761_601,
        .trust_anchors = fx.certs.items[2..3],
    }, cp);
    defer late.deinit(testing.allocator);
    try expectRejected(&late, .certificate_expired, 0);
}

test "expired intermediate is identified and anchor validity is configurable" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = true, .key_usage = 0x04, .not_after = "260630235959Z" });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04, .not_after = "260630235959Z" });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var expired_intermediate = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer expired_intermediate.deinit(testing.allocator);
    try expectRejected(&expired_intermediate, .certificate_expired, 1);

    // A direct path isolates the expired anchor policy.
    try fx.add(.{ .subject = "direct", .issuer = "Root", .subject_key = 4, .issuer_key = 3, .ca = false, .key_usage = 0x80 });
    var ignored = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer ignored.deinit(testing.allocator);
    try expectAccepted(&ignored, 2);

    var strict_policy = policy(fx.certs.items[2..3]);
    strict_policy.enforce_anchor_validity = true;
    var enforced = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[2..3], strict_policy, cp);
    defer enforced.deinit(testing.allocator);
    try expectRejected(&enforced, .certificate_expired, 1);
}

test "tampered signature, wrong issuer key, and typed signature defects stay distinct" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    var tampered = fx.certs.items[0];
    var bad_signature = tampered.signature_value.data[0..64].*;
    bad_signature[0] ^= 1;
    tampered.signature_value = .{ .unused_bits = 0, .data = &bad_signature };
    const tampered_elements = [_]path_builder.Element{
        .{ .certificate = &tampered, .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .anchor, .input_index = 0 },
    };
    var invalid = validator.validatePath(testing.allocator, .{ .elements = &tampered_elements }, policy(fx.certs.items[2..3]), cp);
    defer invalid.deinit(testing.allocator);
    try expectRejected(&invalid, .signature_invalid, 0);

    var malformed = fx.certs.items[0];
    malformed.signature_value.unused_bits = 1;
    const malformed_elements = [_]path_builder.Element{
        .{ .certificate = &malformed, .source = .leaf, .input_index = 0 },
        tampered_elements[1],
        tampered_elements[2],
    };
    var malformed_result = validator.validatePath(testing.allocator, .{ .elements = &malformed_elements }, policy(fx.certs.items[2..3]), cp);
    defer malformed_result.deinit(testing.allocator);
    try expectRejected(&malformed_result, .signature_malformed, 0);

    var unsupported = fx.certs.items[0];
    // sha512WithRSAEncryption remains outside the matrix even after #645
    // added rsa_pkcs1_sha256/384: `resolveScheme` (src/pki/verify.zig)
    // classifies it as `.rsa_pkcs1_sha512`, which still falls through to the
    // `else => error.UnsupportedSignatureAlgorithm` arm regardless of issuer
    // key type — unlike sha256_with_rsa, which #645 made supported and whose
    // key-type mismatch is exercised as its own distinct case below.
    unsupported.signature_algorithm.oid = try oid.ObjectIdentifier.fromComponents(&oid.well_known.sha512_with_rsa);
    const unsupported_elements = [_]path_builder.Element{
        .{ .certificate = &unsupported, .source = .leaf, .input_index = 0 },
        tampered_elements[1],
        tampered_elements[2],
    };
    var unsupported_result = validator.validatePath(testing.allocator, .{ .elements = &unsupported_elements }, policy(fx.certs.items[2..3]), cp);
    defer unsupported_result.deinit(testing.allocator);
    try expectRejected(&unsupported_result, .signature_algorithm_unsupported, 0);

    var mismatched = fx.certs.items[0];
    mismatched.signature_algorithm.oid = try oid.ObjectIdentifier.fromComponents(&oid.well_known.ecdsa_with_sha256);
    mismatched.signature_algorithm.parameters_raw = null;
    const mismatch_elements = [_]path_builder.Element{
        .{ .certificate = &mismatched, .source = .leaf, .input_index = 0 },
        tampered_elements[1],
        tampered_elements[2],
    };
    var mismatch_result = validator.validatePath(testing.allocator, .{ .elements = &mismatch_elements }, policy(fx.certs.items[2..3]), cp);
    defer mismatch_result.deinit(testing.allocator);
    try expectRejected(&mismatch_result, .signature_key_mismatch, 0);

    var malformed_issuer = fx.certs.items[1];
    malformed_issuer.subject_public_key_info.subject_public_key.data = malformed_issuer.subject_public_key_info.subject_public_key.data[0..12];
    const bad_key_elements = [_]path_builder.Element{
        tampered_elements[0],
        .{ .certificate = &malformed_issuer, .source = .intermediate, .input_index = 0 },
        tampered_elements[2],
    };
    var bad_key_result = validator.validatePath(testing.allocator, .{ .elements = &bad_key_elements }, policy(fx.certs.items[2..3]), cp);
    defer bad_key_result.deinit(testing.allocator);
    try expectRejected(&bad_key_result, .issuer_public_key_malformed, 0);

    // The leaf is well-formed and chains by name, but was signed by key 9.
    try fx.add(.{ .subject = "wrong-key leaf", .issuer = "Root", .subject_key = 5, .issuer_key = 9, .ca = false, .key_usage = 0x80 });
    var wrong_key = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer wrong_key.deinit(testing.allocator);
    try expectRejected(&wrong_key, .signature_invalid, 0);
}

test "non-CA and missing keyCertSign issuers fail at the issuing certificate" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Issuer", .subject_key = 1, .issuer_key = 2, .ca = true, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Issuer", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var not_ca = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer not_ca.deinit(testing.allocator);
    try expectRejected(&not_ca, .issuer_is_not_ca, 1);

    try fx.add(.{ .subject = "leaf2", .issuer = "KU Issuer", .subject_key = 4, .issuer_key = 5, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "KU Issuer", .issuer = "Root2", .subject_key = 5, .issuer_key = 6, .ca = true, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Root2", .issuer = "Root2", .subject_key = 6, .issuer_key = 6, .ca = true, .key_usage = 0x04 });
    var bad_ku = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[4..5], fx.certs.items[5..6], policy(fx.certs.items[5..6]), cp);
    defer bad_ku.deinit(testing.allocator);
    try expectRejected(&bad_ku, .key_usage_violation, 1);

    // Missing Basic Constraints never grants intermediate issuing authority.
    try fx.add(.{ .subject = "leaf3", .issuer = "No BC", .subject_key = 7, .issuer_key = 8, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "No BC", .issuer = "Root3", .subject_key = 8, .issuer_key = 9 });
    try fx.add(.{ .subject = "Root3", .issuer = "Root3", .subject_key = 9, .issuer_key = 9, .ca = true, .key_usage = 0x04 });
    var missing_bc = try validateBuilt(testing.allocator, &fx.certs.items[6], fx.certs.items[7..8], fx.certs.items[8..9], policy(fx.certs.items[8..9]), cp);
    defer missing_bc.deinit(testing.allocator);
    try expectRejected(&missing_bc, .issuer_is_not_ca, 1);

    // A configured legacy anchor needs no certificate Basic Constraints or
    // KU, both for direct and intermediate paths.
    try fx.add(.{ .subject = "Legacy Root", .issuer = "Legacy Root", .subject_key = 10, .issuer_key = 10 });
    try fx.add(.{ .subject = "direct legacy", .issuer = "Legacy Root", .subject_key = 11, .issuer_key = 10, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Legacy Intermediate", .issuer = "Legacy Root", .subject_key = 12, .issuer_key = 10, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "legacy chain leaf", .issuer = "Legacy Intermediate", .subject_key = 13, .issuer_key = 12, .ca = false, .key_usage = 0x80 });
    var direct_legacy = try validateBuilt(testing.allocator, &fx.certs.items[10], &.{}, fx.certs.items[9..10], policy(fx.certs.items[9..10]), cp);
    defer direct_legacy.deinit(testing.allocator);
    try expectAccepted(&direct_legacy, 2);
    var chained_legacy = try validateBuilt(testing.allocator, &fx.certs.items[12], fx.certs.items[11..12], fx.certs.items[9..10], policy(fx.certs.items[9..10]), cp);
    defer chained_legacy.deinit(testing.allocator);
    try expectAccepted(&chained_legacy, 3);

    // Absent intermediate KU is unrestricted; only a present KU must assert
    // keyCertSign.
    try fx.add(.{ .subject = "leaf4", .issuer = "No KU", .subject_key = 14, .issuer_key = 15, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "No KU", .issuer = "Root4", .subject_key = 15, .issuer_key = 16, .ca = true });
    try fx.add(.{ .subject = "Root4", .issuer = "Root4", .subject_key = 16, .issuer_key = 16 });
    var absent_ku = try validateBuilt(testing.allocator, &fx.certs.items[13], fx.certs.items[14..15], fx.certs.items[15..16], policy(fx.certs.items[15..16]), cp);
    defer absent_ku.deinit(testing.allocator);
    try expectAccepted(&absent_ku, 3);
}

test "pathLenConstraint handles zero, exact limits, and self-issued CAs" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 0);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var exact = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer exact.deinit(testing.allocator);
    try expectAccepted(&exact, 3);

    // A constrained intermediate with one non-self-issued CA below exceeds
    // pathLen=0. Anchor pathLen is deliberately not trust policy.
    try fx.add(.{ .subject = "over leaf", .issuer = "Lower CA", .subject_key = 4, .issuer_key = 5, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Lower CA", .issuer = "Constrained CA", .subject_key = 5, .issuer_key = 6, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Constrained CA", .issuer = "Root2", .subject_key = 6, .issuer_key = 7, .ca = true, .path_len = 0, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Root2", .issuer = "Root2", .subject_key = 7, .issuer_key = 7 });
    var over = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[4..6], fx.certs.items[6..7], policy(fx.certs.items[6..7]), cp);
    defer over.deinit(testing.allocator);
    try expectRejected(&over, .path_length_exceeded, 2);

    // The configured anchor's certificate pathLen is not inherited as trust
    // policy, so a direct leaf also passes.
    try fx.add(.{ .subject = "direct", .issuer = "Root", .subject_key = 8, .issuer_key = 3, .ca = false, .key_usage = 0x80 });
    var zero = try validateBuilt(testing.allocator, &fx.certs.items[7], &.{}, fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer zero.deinit(testing.allocator);
    try expectAccepted(&zero, 2);

    // A self-issued rollover CA does not consume the constrained
    // intermediate's pathLen budget.
    try fx.add(.{ .subject = "Self CA", .issuer = "Self CA", .subject_key = 9, .issuer_key = 10, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Self CA", .issuer = "Root3", .subject_key = 10, .issuer_key = 11, .ca = true, .path_len = 0, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Root3", .issuer = "Root3", .subject_key = 11, .issuer_key = 11 });
    try fx.add(.{ .subject = "self leaf", .issuer = "Self CA", .subject_key = 12, .issuer_key = 9, .ca = false, .key_usage = 0x80 });
    const self_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[11], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[8], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[9], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[10], .source = .anchor, .input_index = 0 },
    };
    var self_issued = validator.validatePath(testing.allocator, .{ .elements = &self_elements }, policy(fx.certs.items[10..11]), cp);
    defer self_issued.deinit(testing.allocator);
    try expectAccepted(&self_issued, 4);
}

test "leaf KU and EKU server-auth policy accept absent or compatible values" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "server", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .server });
    try fx.add(.{ .subject = "client", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .client });
    try fx.add(.{ .subject = "absent", .issuer = "Root", .subject_key = 4, .issuer_key = 3, .ca = false });
    try fx.add(.{ .subject = "any", .issuer = "Root", .subject_key = 5, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .any });
    try fx.add(.{ .subject = "bad ku", .issuer = "Root", .subject_key = 6, .issuer_key = 3, .ca = false, .key_usage = 0x04 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    inline for (.{ @as(usize, 1), 3, 4 }) |index| {
        var result = try validateBuilt(testing.allocator, &fx.certs.items[index], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer result.deinit(testing.allocator);
        try expectAccepted(&result, 2);
    }
    var client = try validateBuilt(testing.allocator, &fx.certs.items[2], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer client.deinit(testing.allocator);
    try expectRejected(&client, .extended_key_usage_violation, 0);

    var eku_disabled_policy = policy(fx.certs.items[0..1]);
    eku_disabled_policy.require_server_auth_eku = false;
    var eku_disabled = try validateBuilt(testing.allocator, &fx.certs.items[2], &.{}, fx.certs.items[0..1], eku_disabled_policy, cp);
    defer eku_disabled.deinit(testing.allocator);
    try expectAccepted(&eku_disabled, 2);

    var bad_ku = try validateBuilt(testing.allocator, &fx.certs.items[5], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer bad_ku.deinit(testing.allocator);
    try expectRejected(&bad_ku, .key_usage_violation, 0);
}

test "client-auth EKU policy accepts clientAuth/any/absent and rejects serverAuth-only (#763)" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "server", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .server });
    try fx.add(.{ .subject = "client", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .client });
    try fx.add(.{ .subject = "absent", .issuer = "Root", .subject_key = 4, .issuer_key = 3, .ca = false });
    try fx.add(.{ .subject = "any", .issuer = "Root", .subject_key = 5, .issuer_key = 3, .ca = false, .key_usage = 0x80, .eku = .any });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var client_policy = policy(fx.certs.items[0..1]);
    client_policy.require_client_auth_eku = true;
    inline for (.{ @as(usize, 2), 3, 4 }) |index| {
        var result = try validateBuilt(testing.allocator, &fx.certs.items[index], &.{}, fx.certs.items[0..1], client_policy, cp);
        defer result.deinit(testing.allocator);
        try expectAccepted(&result, 2);
    }
    var server_only = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], client_policy, cp);
    defer server_only.deinit(testing.allocator);
    try expectRejected(&server_only, .extended_key_usage_violation, 0);
}

test "critical and duplicate extensions fail closed while unknown noncritical passes" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "critical", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80, .unknown_critical = true });
    try fx.add(.{ .subject = "noncritical", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = false, .key_usage = 0x80, .unknown_noncritical = true });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var critical = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer critical.deinit(testing.allocator);
    try expectRejected(&critical, .unknown_critical_extension, 0);
    try testing.expect(critical.rejected.extension_oid.?.eqlComponents(&.{ 1, 2, 3, 4 }));

    var noncritical = try validateBuilt(testing.allocator, &fx.certs.items[2], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer noncritical.deinit(testing.allocator);
    try expectAccepted(&noncritical, 2);

    var duplicate_leaf = fx.certs.items[1];
    const duplicated = [_]x509.Extension{
        duplicate_leaf.extensions[2],
        duplicate_leaf.extensions[2],
    };
    duplicate_leaf.extensions = &duplicated;
    const duplicate_elements = [_]path_builder.Element{
        .{ .certificate = &duplicate_leaf, .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    var duplicate = validator.validatePath(testing.allocator, .{ .elements = &duplicate_elements }, policy(fx.certs.items[0..1]), cp);
    defer duplicate.deinit(testing.allocator);
    try expectRejected(&duplicate, .duplicate_extension, 0);
}

test "noncritical Name Constraints fail closed while anchor extensions stay local policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Constrained", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{.{ .dns = ".example.com" }}, .critical = false },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .name_constraints_unsupported, 1);
    try testing.expect(result.rejected.extension_oid.?.eqlComponents(&oid.well_known.name_constraints));

    // The same extension on configured trust input is not inherited as local
    // policy by default.
    try fx.add(.{
        .subject = "NC Anchor",
        .issuer = "NC Anchor",
        .subject_key = 4,
        .issuer_key = 4,
        .name_constraints = .{ .permitted = &.{.{ .dns = ".example.com" }} },
        .unknown_critical = true,
    });
    try fx.add(.{ .subject = "anchor leaf", .issuer = "NC Anchor", .subject_key = 5, .issuer_key = 4, .ca = false, .key_usage = 0x80 });
    var anchor_extensions_ignored = try validateBuilt(testing.allocator, &fx.certs.items[4], &.{}, fx.certs.items[3..4], policy(fx.certs.items[3..4]), cp);
    defer anchor_extensions_ignored.deinit(testing.allocator);
    try expectAccepted(&anchor_extensions_ignored, 2);
}

test "Name Constraints propagate permitted and excluded DNS subtrees to every SAN" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{
            .permitted = &.{.{ .dns = "example.com" }},
            .excluded = &.{.{ .dns = "blocked.example.com" }},
        },
    });
    try fx.add(.{ .subject = "good", .issuer = "Constrained", .subject_key = 4, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com" });
    try fx.add(.{ .subject = "blocked", .issuer = "Constrained", .subject_key = 5, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "blocked.example.com" });
    try fx.add(.{
        .subject = "mixed",
        .issuer = "Constrained",
        .subject_key = 6,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{ .{ .dns = "api.example.com" }, .{ .dns = "blocked.example.com" } },
    });
    try fx.add(.{ .subject = "", .issuer = "Constrained", .subject_key = 7, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com", .san_critical = true });
    try fx.add(.{ .subject = "", .issuer = "Constrained", .subject_key = 8, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "blocked.example.com", .san_critical = true });
    try fx.add(.{ .subject = "blocked.example.com", .issuer = "Constrained", .subject_key = 9, .issuer_key = 2, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var good = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer good.deinit(testing.allocator);
    try expectAccepted(&good, 3);

    var empty_subject = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer empty_subject.deinit(testing.allocator);
    try expectAccepted(&empty_subject, 3);

    // A constrained form that is absent is acceptable, and subject CN is not
    // synthesized into a dNSName.
    var absent_dns = try validateBuilt(testing.allocator, &fx.certs.items[7], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer absent_dns.deinit(testing.allocator);
    try expectAccepted(&absent_dns, 3);

    inline for (.{ @as(usize, 3), 4, 6 }) |index| {
        var rejected = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer rejected.deinit(testing.allocator);
        try expectRejected(&rejected, .name_constraints_violation, 0);
        try testing.expectEqual(name_constraints.ConstraintKind.excluded, rejected.rejected.name_constraint_kind.?);
        try testing.expectEqual(name_constraints.Form.dns_name, rejected.rejected.name_form.?);
        try testing.expectEqual(@as(?usize, 1), rejected.rejected.constraint_certificate_index);
    }
}

test "permitted groups from successive CAs intersect and excluded sets accumulate" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4 });
    try fx.add(.{
        .subject = "Upper",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{
            .permitted = &.{ .{ .dns = "example.com" }, .{ .dns = "example.net" } },
            .excluded = &.{.{ .dns = "blocked.example.com" }},
        },
    });
    try fx.add(.{
        .subject = "Lower",
        .issuer = "Upper",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{
            .permitted = &.{.{ .dns = "service.example.com" }},
            .excluded = &.{.{ .dns = "private.service.example.com" }},
        },
    });
    try fx.add(.{ .subject = "good", .issuer = "Lower", .subject_key = 5, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.service.example.com" });
    try fx.add(.{ .subject = "outside lower", .issuer = "Lower", .subject_key = 6, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com" });
    try fx.add(.{ .subject = "excluded upper", .issuer = "Lower", .subject_key = 7, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "blocked.example.com" });
    try fx.add(.{ .subject = "excluded lower", .issuer = "Lower", .subject_key = 8, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "private.service.example.com" });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var good = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..3], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer good.deinit(testing.allocator);
    try expectAccepted(&good, 4);

    inline for (.{ @as(usize, 4), 5, 6 }) |index| {
        var rejected = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..3], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer rejected.deinit(testing.allocator);
        try expectRejected(&rejected, .name_constraints_violation, 0);
    }
}

test "self-issued rollover skips inherited checking but contributes constraints" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4 });
    try fx.add(.{
        .subject = "Rollover",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{.{ .dns = "example.com" }} },
    });
    try fx.add(.{
        .subject = "Rollover",
        .issuer = "Rollover",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .san = "outside.invalid",
        .name_constraints = .{ .permitted = &.{.{ .dns = "service.example.com" }} },
    });
    try fx.add(.{ .subject = "leaf", .issuer = "Rollover", .subject_key = 5, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.service.example.com" });
    try fx.add(.{ .subject = "Rollover", .issuer = "Rollover", .subject_key = 6, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "outside.invalid" });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var rollover = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..3], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer rollover.deinit(testing.allocator);
    try expectAccepted(&rollover, 4);

    const final_self_issued_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[4], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    var final_self_issued = validator.validatePath(testing.allocator, .{ .elements = &final_self_issued_elements }, policy(fx.certs.items[0..1]), cp);
    defer final_self_issued.deinit(testing.allocator);
    try expectRejected(&final_self_issued, .name_constraints_violation, 0);
}

test "directory, email, URI, IPv4, and IPv6 constraints validate through signed paths" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    const v4_network = [_]u8{ 192, 0, 2, 0, 255, 255, 255, 0 };
    const v6_network = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12 ++ [_]u8{0xff} ** 4 ++ [_]u8{0} ** 12;
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{
            .{ .directory_cn = "Allowed" },
            .{ .email = ".example.com" },
            .{ .uri = ".example.com" },
            .{ .ip = &v4_network },
            .{ .ip = &v6_network },
        } },
    });
    const v4_good = [_]u8{ 192, 0, 2, 255 };
    const v6_good = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0xaa} ** 12;
    try fx.add(.{
        .subject = "Allowed",
        .issuer = "Constrained",
        .subject_key = 4,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{
            .{ .email = "user@sub.example.com" },
            .{ .uri = "https://api.example.com:8443/path" },
            .{ .ip = &v4_good },
            .{ .ip = &v6_good },
            .{ .directory_cn = "Allowed" },
        },
    });
    const v4_bad = [_]u8{ 192, 0, 3, 1 };
    try fx.add(.{
        .subject = "Allowed",
        .issuer = "Constrained",
        .subject_key = 5,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{.{ .ip = &v4_bad }},
    });
    try fx.add(.{
        .subject = "Allowed",
        .subject_email = "legacy@sub.example.com",
        .issuer = "Constrained",
        .subject_key = 6,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
    });
    try fx.add(.{
        .subject = "Allowed",
        .subject_email = "legacy@example.com",
        .issuer = "Constrained",
        .subject_key = 7,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var good = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer good.deinit(testing.allocator);
    try expectAccepted(&good, 3);

    var bad = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer bad.deinit(testing.allocator);
    try expectRejected(&bad, .name_constraints_violation, 0);
    try testing.expectEqual(name_constraints.Form.ip_address, bad.rejected.name_form.?);

    var legacy_good = try validateBuilt(testing.allocator, &fx.certs.items[4], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer legacy_good.deinit(testing.allocator);
    try expectAccepted(&legacy_good, 3);

    var legacy_bad = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer legacy_bad.deinit(testing.allocator);
    try expectRejected(&legacy_bad, .name_constraints_violation, 0);
    try testing.expectEqual(name_constraints.Form.rfc822_name, legacy_bad.rejected.name_form.?);

    var uri_bound_policy = policy(fx.certs.items[0..1]);
    uri_bound_policy.name_constraints.maximum_uri_length = 8;
    var uri_bound = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], uri_bound_policy, cp);
    defer uri_bound.deinit(testing.allocator);
    try expectRejected(&uri_bound, .name_constraints_resource_limit_exceeded, 0);
}

test "wildcard DNS names apply set semantics through signed paths" {
    const Case = struct {
        constraint: []const u8,
        excluded: bool,
        accepted: bool,
    };
    inline for ([_]Case{
        .{ .constraint = "example.com", .excluded = false, .accepted = true },
        .{ .constraint = ".example.com", .excluded = false, .accepted = true },
        .{ .constraint = "foo.example.com", .excluded = false, .accepted = false },
        .{ .constraint = "foo.example.com", .excluded = true, .accepted = false },
        .{ .constraint = ".foo.example.com", .excluded = true, .accepted = true },
        .{ .constraint = ".example.com", .excluded = true, .accepted = false },
    }) |case| {
        var fx = Fixtures.init(testing.allocator);
        defer fx.deinit();
        try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
        try fx.add(.{
            .subject = "Constrained",
            .issuer = "Root",
            .subject_key = 2,
            .issuer_key = 3,
            .ca = true,
            .key_usage = 0x04,
            .name_constraints = if (case.excluded)
                .{ .excluded = &.{.{ .dns = case.constraint }} }
            else
                .{ .permitted = &.{.{ .dns = case.constraint }} },
        });
        try fx.add(.{
            .subject = "wildcard leaf",
            .issuer = "Constrained",
            .subject_key = 4,
            .issuer_key = 2,
            .ca = false,
            .key_usage = 0x80,
            .san = "*.example.com",
        });

        var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
        var provider: crypto.pure_zig.Provider = undefined;
        const cp = cryptoProvider(&entropy, &provider);
        var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer result.deinit(testing.allocator);
        if (case.accepted) {
            try expectAccepted(&result, 3);
        } else {
            try expectRejected(&result, .name_constraints_violation, 0);
            try testing.expectEqual(name_constraints.Form.dns_name, result.rejected.name_form.?);
        }
    }

    inline for ([_][]const u8{ "*", "a.*.example.com", "f*o.example.com", "*.com" }) |malformed| {
        var fx = Fixtures.init(testing.allocator);
        defer fx.deinit();
        try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
        try fx.add(.{
            .subject = "Constrained",
            .issuer = "Root",
            .subject_key = 2,
            .issuer_key = 3,
            .ca = true,
            .key_usage = 0x04,
            .name_constraints = .{ .permitted = &.{.{ .dns = "example.com" }} },
        });
        try fx.add(.{
            .subject = "malformed wildcard leaf",
            .issuer = "Constrained",
            .subject_key = 4,
            .issuer_key = 2,
            .ca = false,
            .key_usage = 0x80,
            .san = malformed,
        });

        var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
        var provider: crypto.pure_zig.Provider = undefined;
        const cp = cryptoProvider(&entropy, &provider);
        var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer result.deinit(testing.allocator);
        try expectRejected(&result, .name_constraints_violation, 0);
        try testing.expectEqual(name_constraints.Form.dns_name, result.rejected.name_form.?);
    }
}

test "mailbox and URI syntax is enforced through signed paths" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{
            .{ .email = "root@example.com" },
            .{ .email = ".example.com" },
            .{ .uri = ".example.com" },
        } },
    });
    try fx.add(.{
        .subject = "quoted forms",
        .issuer = "Constrained",
        .subject_key = 4,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{
            .{ .email = "\"root\"@example.com" },
            .{ .email = "\"a@b\"@sub.example.com" },
            .{ .uri = "https://user:pa%73s@api.example.com/path" },
        },
    });
    try fx.add(.{
        .subject = "legacy ignored",
        .subject_email = "legacy@outside.invalid",
        .issuer = "Constrained",
        .subject_key = 5,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{.{ .dns = "outside.invalid" }},
    });
    try fx.add(.{
        .subject = "legacy constrained",
        .subject_email = "legacy@outside.invalid",
        .issuer = "Constrained",
        .subject_key = 6,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
    });
    try fx.add(.{
        .subject = "SAN email constrained",
        .subject_email = "legacy@sub.example.com",
        .issuer = "Constrained",
        .subject_key = 7,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san_names = &.{.{ .email = "legacy@outside.invalid" }},
    });

    const malformed_mailboxes = [_][]const u8{
        ".a@sub.example.com",
        "a..b@sub.example.com",
        "a.@sub.example.com",
        "a(b)@sub.example.com",
    };
    inline for (malformed_mailboxes, 0..) |mailbox, offset| {
        try fx.add(.{
            .subject = "malformed mailbox",
            .issuer = "Constrained",
            .subject_key = 8 + offset,
            .issuer_key = 2,
            .ca = false,
            .key_usage = 0x80,
            .san_names = &.{.{ .email = mailbox }},
        });
    }
    const malformed_uris = [_][]const u8{
        "https://bad@@api.example.com/",
        "https://bad user@api.example.com/",
        "https://bad%ZZ@api.example.com/",
    };
    inline for (malformed_uris, 0..) |uri, offset| {
        try fx.add(.{
            .subject = "malformed URI",
            .issuer = "Constrained",
            .subject_key = 12 + offset,
            .issuer_key = 2,
            .ca = false,
            .key_usage = 0x80,
            .san_names = &.{.{ .uri = uri }},
        });
    }

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    inline for (.{ @as(usize, 2), 3 }) |index| {
        var accepted = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer accepted.deinit(testing.allocator);
        try expectAccepted(&accepted, 3);
    }
    inline for (.{ @as(usize, 4), 5 }) |index| {
        var rejected = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer rejected.deinit(testing.allocator);
        try expectRejected(&rejected, .name_constraints_violation, 0);
        try testing.expectEqual(name_constraints.Form.rfc822_name, rejected.rejected.name_form.?);
    }
    inline for (6..10) |index| {
        var rejected = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer rejected.deinit(testing.allocator);
        try expectRejected(&rejected, .name_constraints_violation, 0);
        try testing.expectEqual(name_constraints.Form.rfc822_name, rejected.rejected.name_form.?);
    }
    inline for (10..13) |index| {
        var rejected = try validateBuilt(testing.allocator, &fx.certs.items[index], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
        defer rejected.deinit(testing.allocator);
        try expectRejected(&rejected, .name_constraints_violation, 0);
        try testing.expectEqual(name_constraints.Form.uri, rejected.rejected.name_form.?);
    }
}

test "leaf, noncritical, unsupported-form, and resource-limit policies fail closed" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{
            .permitted = &.{ .{ .directory_cn = "leaf" }, .{ .dns = "example.com" } },
            .excluded = &.{.{ .dns = "invalid.example.com" }},
        },
    });
    try fx.add(.{ .subject = "leaf", .issuer = "Constrained", .subject_key = 4, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com" });
    try fx.add(.{
        .subject = "leaf nc",
        .issuer = "Root",
        .subject_key = 5,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .name_constraints = .{ .permitted = &.{.{ .dns = "example.com" }} },
    });
    try fx.add(.{
        .subject = "Unsupported",
        .issuer = "Root",
        .subject_key = 6,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{.{ .registered_id = &.{ 1, 2, 3, 4 } }} },
    });
    try fx.add(.{ .subject = "unsupported leaf", .issuer = "Unsupported", .subject_key = 7, .issuer_key = 6, .ca = false, .key_usage = 0x80 });
    const malformed_mask = [_]u8{ 192, 0, 2, 0, 255, 0, 255, 0 };
    try fx.add(.{
        .subject = "Malformed mask",
        .issuer = "Root",
        .subject_key = 8,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .permitted = &.{.{ .ip = &malformed_mask }} },
    });
    try fx.add(.{ .subject = "malformed mask leaf", .issuer = "Malformed mask", .subject_key = 9, .issuer_key = 8, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var resource_policy = policy(fx.certs.items[0..1]);
    resource_policy.name_constraints.maximum_comparisons = 0;
    var exhausted = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], resource_policy, cp);
    defer exhausted.deinit(testing.allocator);
    try expectRejected(&exhausted, .name_constraints_resource_limit_exceeded, 0);

    var groups_policy = policy(fx.certs.items[0..1]);
    groups_policy.name_constraints.maximum_permitted_groups_per_form = 0;
    var groups = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], groups_policy, cp);
    defer groups.deinit(testing.allocator);
    try expectRejected(&groups, .name_constraints_resource_limit_exceeded, 1);

    var permitted_policy = policy(fx.certs.items[0..1]);
    permitted_policy.name_constraints.maximum_permitted_subtrees = 1;
    var permitted = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], permitted_policy, cp);
    defer permitted.deinit(testing.allocator);
    try expectRejected(&permitted, .name_constraints_resource_limit_exceeded, 1);

    var excluded_policy = policy(fx.certs.items[0..1]);
    excluded_policy.name_constraints.maximum_excluded_subtrees = 0;
    var excluded = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], excluded_policy, cp);
    defer excluded.deinit(testing.allocator);
    try expectRejected(&excluded, .name_constraints_resource_limit_exceeded, 1);

    var names_policy = policy(fx.certs.items[0..1]);
    names_policy.name_constraints.maximum_names_per_certificate = 0;
    var names = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], names_policy, cp);
    defer names.deinit(testing.allocator);
    try expectRejected(&names, .name_constraints_resource_limit_exceeded, 0);

    var directory_policy = policy(fx.certs.items[0..1]);
    directory_policy.name_constraints.maximum_directory_name_parses = 0;
    var directory = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], directory_policy, cp);
    defer directory.deinit(testing.allocator);
    try expectRejected(&directory, .name_constraints_resource_limit_exceeded, 1);

    var rdn_policy = policy(fx.certs.items[0..1]);
    rdn_policy.name_constraints.maximum_directory_name_rdns = 0;
    var rdns = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], rdn_policy, cp);
    defer rdns.deinit(testing.allocator);
    try expectRejected(&rdns, .name_constraints_resource_limit_exceeded, 1);

    var attribute_policy = policy(fx.certs.items[0..1]);
    attribute_policy.name_constraints.maximum_directory_name_attributes_per_rdn = 0;
    var attributes = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], attribute_policy, cp);
    defer attributes.deinit(testing.allocator);
    try expectRejected(&attributes, .name_constraints_resource_limit_exceeded, 1);

    var path_policy = policy(fx.certs.items[0..1]);
    path_policy.name_constraints.maximum_path_length = 2;
    var path_bound = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], path_policy, cp);
    defer path_bound.deinit(testing.allocator);
    try expectRejected(&path_bound, .name_constraints_resource_limit_exceeded, null);

    var leaf_nc = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer leaf_nc.deinit(testing.allocator);
    try expectRejected(&leaf_nc, .name_constraints_unsupported, 0);

    var unsupported = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[4..5], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer unsupported.deinit(testing.allocator);
    try expectRejected(&unsupported, .name_constraints_unsupported, 1);

    var malformed = try validateBuilt(testing.allocator, &fx.certs.items[7], fx.certs.items[6..7], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer malformed.deinit(testing.allocator);
    try expectRejected(&malformed, .name_constraints_unsupported, 1);
}

test "Name Constraints allocation failures clean up every partial state" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Constrained",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{
            .permitted = &.{ .{ .directory_cn = "leaf" }, .{ .dns = "example.com" } },
            .excluded = &.{.{ .dns = "blocked.example.com" }},
        },
    });
    try fx.add(.{ .subject = "leaf", .issuer = "Constrained", .subject_key = 4, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com" });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[2], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    const Context = struct {
        path: path_builder.Path,
        validation_policy: validator.ValidationPolicy,
        crypto_provider: crypto.provider.CryptoProvider,

        fn run(allocator: std.mem.Allocator, context: @This()) !void {
            var result = validator.validatePath(allocator, context.path, context.validation_policy, context.crypto_provider);
            defer result.deinit(allocator);
            switch (result) {
                .accepted => {},
                .rejected => |rejected| {
                    if (rejected.reason == .out_of_memory) return error.OutOfMemory;
                    std.debug.print("unexpected allocation sweep rejection: {s}\n", .{@tagName(rejected.reason)});
                    return error.TestUnexpectedResult;
                },
            }
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Context.run, .{Context{
        .path = .{ .elements = &elements },
        .validation_policy = policy(fx.certs.items[0..1]),
        .crypto_provider = cp,
    }});
}

test "alternate candidate validation continues after a Name Constraints violation" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Shared", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80, .san = "api.example.com" });
    try fx.add(.{
        .subject = "Shared",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .name_constraints = .{ .excluded = &.{.{ .dns = "example.com" }} },
    });
    try fx.add(.{ .subject = "Shared", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], fx.certs.items[1..3], fx.certs.items[3..4], .{});
    defer candidates.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), candidates.paths.len);
    var result = validator.validateCandidates(testing.allocator, candidates, policy(fx.certs.items[3..4]), cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 1), result.accepted.accepted_path[1].input_index);
}

test "hostname verification is delegated and runs after path authentication" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80, .san = "api.example.com" });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var good_policy = policy(fx.certs.items[0..1]);
    good_policy.expected_dns_name = "api.example.com";
    var good = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], good_policy, cp);
    defer good.deinit(testing.allocator);
    try expectAccepted(&good, 2);

    var bad_policy = good_policy;
    bad_policy.expected_dns_name = "other.example.com";
    var mismatch = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], bad_policy, cp);
    defer mismatch.deinit(testing.allocator);
    try expectRejected(&mismatch, .identity_mismatch, 0);
}

test "alternate candidate paths continue after a bad signature" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80 });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..3], .{});
    defer candidates.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), candidates.paths.len);
    var result = validator.validateCandidates(testing.allocator, candidates, policy(fx.certs.items[1..3]), cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 2);
    try testing.expectEqual(@as(usize, 1), result.accepted.accepted_path[1].input_index);
}

test "path structure, configured anchors, resource bounds, and allocation failure are structured" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const valid_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[1], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };

    var too_short = validator.validatePath(testing.allocator, .{ .elements = valid_elements[0..1] }, policy(fx.certs.items[0..1]), cp);
    defer too_short.deinit(testing.allocator);
    try expectRejected(&too_short, .malformed_path, 0);

    const no_anchors_policy = policy(&.{});
    var untrusted = validator.validatePath(testing.allocator, .{ .elements = &valid_elements }, no_anchors_policy, cp);
    defer untrusted.deinit(testing.allocator);
    try expectRejected(&untrusted, .untrusted_anchor, 1);

    var copied_anchor = fx.certs.items[0];
    var copied_anchor_elements = valid_elements;
    copied_anchor_elements[1].certificate = &copied_anchor;
    var forged_provenance = validator.validatePath(testing.allocator, .{ .elements = &copied_anchor_elements }, policy(fx.certs.items[0..1]), cp);
    defer forged_provenance.deinit(testing.allocator);
    try expectRejected(&forged_provenance, .untrusted_anchor, 1);

    var bad_termination_elements = valid_elements;
    bad_termination_elements[1].source = .intermediate;
    var bad_termination = validator.validatePath(testing.allocator, .{ .elements = &bad_termination_elements }, policy(fx.certs.items[0..1]), cp);
    defer bad_termination.deinit(testing.allocator);
    try expectRejected(&bad_termination, .invalid_anchor_termination, 1);

    var bounded_policy = policy(fx.certs.items[0..1]);
    bounded_policy.maximum_path_length = 1;
    var bounded = validator.validatePath(testing.allocator, .{ .elements = &valid_elements }, bounded_policy, cp);
    defer bounded.deinit(testing.allocator);
    try expectRejected(&bounded, .validation_resource_limit_exceeded, null);

    var too_many_extensions_leaf = fx.certs.items[1];
    var too_many_extensions: [65]x509.Extension = undefined;
    for (&too_many_extensions) |*extension| extension.* = too_many_extensions_leaf.extensions[0];
    too_many_extensions_leaf.extensions = &too_many_extensions;
    const too_many_extension_elements = [_]path_builder.Element{
        .{ .certificate = &too_many_extensions_leaf, .source = .leaf, .input_index = 0 },
        valid_elements[1],
    };
    var extension_bound = validator.validatePath(testing.allocator, .{ .elements = &too_many_extension_elements }, policy(fx.certs.items[0..1]), cp);
    defer extension_bound.deinit(testing.allocator);
    try expectRejected(&extension_bound, .validation_resource_limit_exceeded, 0);

    var empty_buffer: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&empty_buffer);
    var oom = validator.validatePath(fixed.allocator(), .{ .elements = &valid_elements }, policy(fx.certs.items[0..1]), cp);
    defer oom.deinit(fixed.allocator());
    try expectRejected(&oom, .out_of_memory, null);
}

test "maximum supported path length accepts the boundary and rejects one-lower policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();

    // leaf + six intermediates + anchor = the default maximum of eight.
    try fx.add(.{ .subject = "leaf", .issuer = "CA1", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    inline for (1..7) |number| {
        var subject_buffer: [8]u8 = undefined;
        var issuer_buffer: [8]u8 = undefined;
        const subject = try std.fmt.bufPrint(&subject_buffer, "CA{d}", .{number});
        const issuer = try std.fmt.bufPrint(&issuer_buffer, "CA{d}", .{number + 1});
        try fx.add(.{
            .subject = subject,
            .issuer = issuer,
            .subject_key = @intCast(number + 1),
            .issuer_key = @intCast(number + 2),
            .ca = true,
            .key_usage = 0x04,
        });
    }
    try fx.add(.{ .subject = "CA7", .issuer = "CA7", .subject_key = 8, .issuer_key = 8, .ca = true, .key_usage = 0x04 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var accepted = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..7], fx.certs.items[7..8], policy(fx.certs.items[7..8]), cp);
    defer accepted.deinit(testing.allocator);
    try expectAccepted(&accepted, 8);

    var limited = policy(fx.certs.items[7..8]);
    limited.maximum_path_length = 7;
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], fx.certs.items[1..7], fx.certs.items[7..8], .{});
    defer candidates.deinit(testing.allocator);
    var rejected = validator.validateCandidates(testing.allocator, candidates, limited, cp);
    defer rejected.deinit(testing.allocator);
    try expectRejected(&rejected, .validation_resource_limit_exceeded, null);
}

const policy_a = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 1 };
const policy_b = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 2 };
const policy_c = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 3 };
const policy_d = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 4 };

fn policyObject(components: []const u32) !oid.ObjectIdentifier {
    return oid.ObjectIdentifier.fromComponents(components);
}

test "certificate policy intersection and user policy inputs validate through signed paths" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        // Anchor extensions are trust metadata only and must not constrain
        // the prospective path.
        .certificate_policies = &.{.{ .policy = &policy_d }},
    });
    try fx.add(.{
        .subject = "Policy CA",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{ .{ .policy = &policy_a }, .{ .policy = &policy_b } },
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Policy CA",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{ .{ .policy = &policy_a }, .{ .policy = &policy_c } },
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    var any_result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer any_result.deinit(testing.allocator);
    try expectAccepted(&any_result, 3);
    try testing.expectEqual(@as(usize, 1), any_result.accepted.policies.authority_constrained.len);
    try testing.expect(any_result.accepted.policies.authority_constrained[0].eqlComponents(&policy_a));
    try testing.expectEqual(@as(usize, 1), any_result.accepted.policies.user_constrained.len);
    try testing.expect(any_result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_b)};
    var requested_policy = policy(fx.certs.items[0..1]);
    requested_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    var absent = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], requested_policy, cp);
    defer absent.deinit(testing.allocator);
    try expectAccepted(&absent, 3);
    try testing.expectEqual(@as(usize, 1), absent.accepted.policies.authority_constrained.len);
    try testing.expectEqual(@as(usize, 0), absent.accepted.policies.user_constrained.len);

    requested_policy.certificate_policy.initial_explicit_policy = true;
    var required = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], requested_policy, cp);
    defer required.deinit(testing.allocator);
    try expectRejected(&required, .certificate_policy_required, 0);
}

test "missing policies null the graph while explicit policy controls rejection" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Policy CA",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{ .subject = "leaf", .issuer = "Policy CA", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var permissive = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer permissive.deinit(testing.allocator);
    try expectAccepted(&permissive, 3);
    try testing.expectEqual(@as(usize, 0), permissive.accepted.policies.authority_constrained.len);

    var strict_policy = policy(fx.certs.items[0..1]);
    strict_policy.certificate_policy.initial_explicit_policy = true;
    var strict = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], strict_policy, cp);
    defer strict.deinit(testing.allocator);
    try expectRejected(&strict, .certificate_policy_required, 0);
}

test "anyPolicy propagates and expands the requested user set deterministically" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try fx.add(.{
        .subject = "Any CA",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Any CA",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });

    const requested = [_]oid.ObjectIdentifier{ try policyObject(&policy_b), try policyObject(&policy_a) };
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 1), result.accepted.policies.authority_constrained.len);
    try testing.expect(result.accepted.policies.authority_constrained[0].eqlComponents(&oid.well_known.any_policy));
    try testing.expectEqual(@as(usize, 2), result.accepted.policies.user_constrained.len);
    try testing.expect(result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));
    try testing.expect(result.accepted.policies.user_constrained[1].eqlComponents(&policy_b));
}

test "critical policy qualifiers are supported or rejected safely" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    const supported = [_]PolicyQualifierSpec{
        .{ .cps = "https://ca.example/cps" },
        .{ .user_notice = "appliance policy" },
        .{ .user_notice_negative_number = "legacy notice numbers" },
    };
    try fx.add(.{
        .subject = "Supported",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a, .qualifiers = &supported }},
        .certificate_policies_critical = true,
    });
    const unsupported_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 99 };
    const unsupported = [_]PolicyQualifierSpec{.{ .unsupported = &unsupported_oid }};
    try fx.add(.{
        .subject = "Unsupported",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a, .qualifiers = &unsupported }},
        .certificate_policies_critical = true,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var accepted = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer accepted.deinit(testing.allocator);
    try expectAccepted(&accepted, 2);

    var rejected = try validateBuilt(testing.allocator, &fx.certs.items[2], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer rejected.deinit(testing.allocator);
    try expectRejected(&rejected, .certificate_policy_unsupported_qualifier, 0);
}

test "duplicate user and certificate policy OIDs fail deterministically" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3 });
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "duplicate policies",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{ .{ .policy = &policy_a }, .{ .policy = &policy_a } },
    }));
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });

    const duplicate = try policyObject(&policy_a);
    const requested = [_]oid.ObjectIdentifier{ duplicate, duplicate };
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .certificate_policy_invalid, null);
}

test "policy graph merges one-to-many and many-to-one mappings without duplicate outputs" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4 });
    try fx.add(.{
        .subject = "Mapping CA",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{ .{ .policy = &policy_a }, .{ .policy = &policy_d } },
        .policy_mappings = &.{
            .{ .issuer = &policy_a, .subject = &policy_b },
            .{ .issuer = &policy_a, .subject = &policy_c },
            .{ .issuer = &policy_d, .subject = &policy_b },
        },
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Mapping CA",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{ .{ .policy = &policy_b }, .{ .policy = &policy_c } },
    });

    const requested = [_]oid.ObjectIdentifier{ try policyObject(&policy_d), try policyObject(&policy_a) };
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 2), result.accepted.policies.authority_constrained.len);
    try testing.expect(result.accepted.policies.authority_constrained[0].eqlComponents(&policy_a));
    try testing.expect(result.accepted.policies.authority_constrained[1].eqlComponents(&policy_d));
    try testing.expectEqual(@as(usize, 5), result.accepted.policies.resource_usage.graph_nodes);
    try testing.expectEqual(@as(usize, 5), result.accepted.policies.resource_usage.graph_edges);
    try testing.expectEqual(
        result.accepted.policies.resource_usage.graph_edges,
        result.accepted.policies.resource_usage.parent_references,
    );
    try testing.expectEqual(@as(usize, 2), result.accepted.policies.user_constrained.len);

    validation_policy.certificate_policy.initial_policy_mapping_inhibit = true;
    var inhibited = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], validation_policy, cp);
    defer inhibited.deinit(testing.allocator);
    try expectRejected(&inhibited, .certificate_policy_required, 0);
}

test "multi-level mappings process from anchor toward target" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 5, .issuer_key = 5 });
    try fx.add(.{
        .subject = "Upper",
        .issuer = "Root",
        .subject_key = 4,
        .issuer_key = 5,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "Lower",
        .issuer = "Upper",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_b }},
        .policy_mappings = &.{.{ .issuer = &policy_b, .subject = &policy_c }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Lower",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_c }},
    });

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..3], fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 4);
    try testing.expectEqual(@as(usize, 1), result.accepted.policies.user_constrained.len);
    try testing.expect(result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));
}

test "policy mapping counters apply after the issuing certificate" {
    inline for (.{ @as(u8, 0), 1 }) |inhibit_count| {
        var fx = Fixtures.init(testing.allocator);
        defer fx.deinit();
        try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 5, .issuer_key = 5 });
        try fx.add(.{
            .subject = "Upper",
            .issuer = "Root",
            .subject_key = 4,
            .issuer_key = 5,
            .ca = true,
            .key_usage = 0x04,
            .certificate_policies = &.{.{ .policy = &policy_a }},
            .policy_constraints = .{ .inhibit_policy_mapping = inhibit_count },
        });
        try fx.add(.{
            .subject = "Lower",
            .issuer = "Upper",
            .subject_key = 3,
            .issuer_key = 4,
            .ca = true,
            .key_usage = 0x04,
            .certificate_policies = &.{.{ .policy = &policy_a }},
            .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &policy_b }},
        });
        try fx.add(.{
            .subject = "leaf",
            .issuer = "Lower",
            .subject_key = 2,
            .issuer_key = 3,
            .ca = false,
            .key_usage = 0x80,
            .certificate_policies = &.{.{ .policy = &policy_b }},
        });

        const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
        var validation_policy = policy(fx.certs.items[0..1]);
        validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
        validation_policy.certificate_policy.initial_explicit_policy = true;
        var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
        var provider: crypto.pure_zig.Provider = undefined;
        const cp = cryptoProvider(&entropy, &provider);
        var result = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..3], fx.certs.items[0..1], validation_policy, cp);
        defer result.deinit(testing.allocator);
        if (inhibit_count == 0) {
            try expectRejected(&result, .certificate_policy_required, 0);
        } else {
            try expectAccepted(&result, 4);
        }
    }
}

test "invalid anyPolicy mappings and target mappings fail closed" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4 });
    try fx.add(.{
        .subject = "Bad CA",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &oid.well_known.any_policy, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Bad CA",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_b }},
    });
    try fx.add(.{
        .subject = "mapped leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 4,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "Bad To CA",
        .issuer = "Root",
        .subject_key = 6,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "bad to leaf",
        .issuer = "Bad To CA",
        .subject_key = 5,
        .issuer_key = 6,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var any_mapping = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer any_mapping.deinit(testing.allocator);
    try expectRejected(&any_mapping, .policy_mapping_invalid, 1);

    var leaf_mapping = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer leaf_mapping.deinit(testing.allocator);
    try expectRejected(&leaf_mapping, .policy_mapping_invalid, 0);

    var to_any = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[4..5], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer to_any.deinit(testing.allocator);
    try expectRejected(&to_any, .policy_mapping_invalid, 1);
}

test "policy constraint and inhibit-any counters honor zero and one boundaries" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 12, .issuer_key = 12, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Upper0",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 12,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_constraints = .{ .require_explicit_policy = 0 },
    });
    try fx.add(.{
        .subject = "Lower0",
        .issuer = "Upper0",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{ .subject = "leaf0", .issuer = "Lower0", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    try fx.add(.{
        .subject = "Upper1",
        .issuer = "Root",
        .subject_key = 7,
        .issuer_key = 12,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_constraints = .{ .require_explicit_policy = 1 },
    });
    try fx.add(.{ .subject = "Lower1", .issuer = "Upper1", .subject_key = 6, .issuer_key = 7, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "leaf1",
        .issuer = "Lower1",
        .subject_key = 5,
        .issuer_key = 6,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{
        .subject = "Any0",
        .issuer = "Root",
        .subject_key = 9,
        .issuer_key = 12,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .inhibit_any_policy = 0,
    });
    try fx.add(.{
        .subject = "any leaf 0",
        .issuer = "Any0",
        .subject_key = 8,
        .issuer_key = 9,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "Any1",
        .issuer = "Root",
        .subject_key = 11,
        .issuer_key = 12,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .inhibit_any_policy = 1,
    });
    try fx.add(.{
        .subject = "any leaf 1",
        .issuer = "Any1",
        .subject_key = 10,
        .issuer_key = 11,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var require_zero = try validateBuilt(testing.allocator, &fx.certs.items[3], fx.certs.items[1..3], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer require_zero.deinit(testing.allocator);
    try expectRejected(&require_zero, .certificate_policy_required, 0);
    var require_one = try validateBuilt(testing.allocator, &fx.certs.items[6], fx.certs.items[4..6], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer require_one.deinit(testing.allocator);
    try expectRejected(&require_one, .certificate_policy_required, 0);

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var strict = policy(fx.certs.items[0..1]);
    strict.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    strict.certificate_policy.initial_explicit_policy = true;
    var inhibit_zero = try validateBuilt(testing.allocator, &fx.certs.items[8], fx.certs.items[7..8], fx.certs.items[0..1], strict, cp);
    defer inhibit_zero.deinit(testing.allocator);
    try expectRejected(&inhibit_zero, .certificate_policy_required, 0);
    var inhibit_one = try validateBuilt(testing.allocator, &fx.certs.items[10], fx.certs.items[9..10], fx.certs.items[0..1], strict, cp);
    defer inhibit_one.deinit(testing.allocator);
    try expectAccepted(&inhibit_one, 3);
    try testing.expect(inhibit_one.accepted.policies.user_constrained[0].eqlComponents(&policy_a));

    strict.certificate_policy.initial_any_policy_inhibit = true;
    var initially_inhibited = try validateBuilt(testing.allocator, &fx.certs.items[10], fx.certs.items[9..10], fx.certs.items[0..1], strict, cp);
    defer initially_inhibited.deinit(testing.allocator);
    try expectRejected(&initially_inhibited, .certificate_policy_required, 1);
}

test "self-issued rollover certificates do not decrement policy counters" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Issuer",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .inhibit_any_policy = 1,
    });
    try fx.add(.{
        .subject = "Issuer",
        .issuer = "Issuer",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Issuer",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    const elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[3], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = validator.validatePath(testing.allocator, .{ .elements = &elements }, validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 4);
    try testing.expect(result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));
}

test "policy extension profiles require critical CA-only constraints" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 4, .issuer_key = 4, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Noncritical constraints",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .policy_constraints = .{ .require_explicit_policy = 0, .critical = false },
    });
    try fx.add(.{ .subject = "leaf c", .issuer = "Noncritical constraints", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    try fx.add(.{
        .subject = "Noncritical inhibit",
        .issuer = "Root",
        .subject_key = 6,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .inhibit_any_policy = std.math.maxInt(u32),
        .inhibit_any_policy_critical = false,
    });
    try fx.add(.{ .subject = "leaf i", .issuer = "Noncritical inhibit", .subject_key = 5, .issuer_key = 6, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var constraints = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer constraints.deinit(testing.allocator);
    try expectRejected(&constraints, .policy_constraints_invalid, 1);
    var inhibit = try validateBuilt(testing.allocator, &fx.certs.items[4], fx.certs.items[3..4], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer inhibit.deinit(testing.allocator);
    try expectRejected(&inhibit, .inhibit_any_policy_invalid, 1);
}

test "policy graph resource accounting and limits are deterministic" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 2, .issuer_key = 2, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var first = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer first.deinit(testing.allocator);
    var second = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer second.deinit(testing.allocator);
    try expectAccepted(&first, 2);
    try expectAccepted(&second, 2);
    try testing.expectEqualDeep(first.accepted.policies.resource_usage, second.accepted.policies.resource_usage);
    try testing.expectEqual(@as(usize, 2), first.accepted.policies.resource_usage.graph_nodes);
    try testing.expectEqual(@as(usize, 1), first.accepted.policies.resource_usage.graph_edges);

    var limited = policy(fx.certs.items[0..1]);
    limited.certificate_policy.limits.maximum_total_nodes = 1;
    var nodes = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], limited, cp);
    defer nodes.deinit(testing.allocator);
    try expectRejected(&nodes, .certificate_policy_resource_limit_exceeded, 0);
    limited = policy(fx.certs.items[0..1]);
    limited.certificate_policy.limits.maximum_parent_references = 0;
    var parents = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], limited, cp);
    defer parents.deinit(testing.allocator);
    try expectRejected(&parents, .certificate_policy_resource_limit_exceeded, 0);
    limited = policy(fx.certs.items[0..1]);
    limited.certificate_policy.limits.maximum_operations = 0;
    var operations = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], limited, cp);
    defer operations.deinit(testing.allocator);
    try expectRejected(&operations, .certificate_policy_resource_limit_exceeded, 0);
    limited = policy(fx.certs.items[0..1]);
    limited.certificate_policy.limits.maximum_output_policies = 0;
    var outputs = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], limited, cp);
    defer outputs.deinit(testing.allocator);
    try expectRejected(&outputs, .certificate_policy_resource_limit_exceeded, 0);
}

test "alternate candidates continue after a policy-profile rejection" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Shared",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{
        .subject = "Shared",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &oid.well_known.any_policy, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "Shared",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], fx.certs.items[1..3], fx.certs.items[3..4], .{});
    defer candidates.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), candidates.paths.len);
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = validator.validateCandidates(testing.allocator, candidates, policy(fx.certs.items[3..4]), cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 1), result.accepted.accepted_path[1].input_index);
}

test "alternate candidates continue after explicit policy eliminates a graph" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Shared explicit",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{ .subject = "Shared explicit", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Shared explicit",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], fx.certs.items[1..3], fx.certs.items[3..4], .{});
    defer candidates.deinit(testing.allocator);
    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var validation_policy = policy(fx.certs.items[3..4]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = validator.validateCandidates(testing.allocator, candidates, validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 1), result.accepted.accepted_path[1].input_index);
    try testing.expect(result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));
}

test "policy parser rejects empty extension sequences" {
    var policies = Fixtures.init(testing.allocator);
    defer policies.deinit();
    try testing.expectError(error.MalformedExtension, policies.add(.{
        .subject = "empty policies",
        .issuer = "empty policies",
        .subject_key = 1,
        .issuer_key = 1,
        .certificate_policies = &.{},
    }));
    var mappings = Fixtures.init(testing.allocator);
    defer mappings.deinit();
    try testing.expectError(error.MalformedExtension, mappings.add(.{
        .subject = "empty mappings",
        .issuer = "empty mappings",
        .subject_key = 2,
        .issuer_key = 2,
        .policy_mappings = &.{},
    }));
    var constraints = Fixtures.init(testing.allocator);
    defer constraints.deinit();
    try testing.expectError(error.MalformedExtension, constraints.add(.{
        .subject = "empty constraints",
        .issuer = "empty constraints",
        .subject_key = 3,
        .issuer_key = 3,
        .policy_constraints = .{},
    }));
}

test "policy parser rejects malformed qualifiers mappings and counter integers" {
    const malformed_values = [_]struct { constraints: ?[]const u8 = null, inhibit: ?[]const u8 = null }{
        .{ .constraints = &.{ 0x30, 0x03, 0x80, 0x01, 0xff } },
        .{ .constraints = &.{ 0x30, 0x04, 0x80, 0x02, 0x00, 0x01 } },
        .{ .constraints = &.{ 0x30, 0x06, 0x80, 0x01, 0x00, 0x80, 0x01, 0x00 } },
        .{ .constraints = &.{ 0x30, 0x06, 0x81, 0x01, 0x01, 0x80, 0x01, 0x01 } },
        .{ .inhibit = &.{ 0x02, 0x01, 0xff } },
        .{ .inhibit = &.{ 0x02, 0x02, 0x00, 0x01 } },
    };
    for (malformed_values, 0..) |value, index| {
        var fx = Fixtures.init(testing.allocator);
        defer fx.deinit();
        try testing.expectError(error.MalformedExtension, fx.add(.{
            .subject = "malformed counter",
            .issuer = "malformed counter",
            .subject_key = @intCast(index + 1),
            .issuer_key = @intCast(index + 1),
            .raw_policy_constraints = value.constraints,
            .raw_inhibit_any_policy = value.inhibit,
        }));
    }

    var mappings = Fixtures.init(testing.allocator);
    defer mappings.deinit();
    try testing.expectError(error.MalformedExtension, mappings.add(.{
        .subject = "duplicate mapping",
        .issuer = "duplicate mapping",
        .subject_key = 20,
        .issuer_key = 20,
        .policy_mappings = &.{
            .{ .issuer = &policy_a, .subject = &policy_b },
            .{ .issuer = &policy_a, .subject = &policy_b },
        },
    }));

    var qualifiers = Fixtures.init(testing.allocator);
    defer qualifiers.deinit();
    const arena = qualifiers.arena.allocator();
    const empty_qualifiers = try tlv(arena, 0x30, &.{try tlv(arena, 0x30, &.{
        try oidTlv(arena, &policy_a),
        try tlv(arena, 0x30, &.{}),
    })});
    try testing.expectError(error.MalformedExtension, qualifiers.add(.{
        .subject = "empty qualifiers",
        .issuer = "empty qualifiers",
        .subject_key = 21,
        .issuer_key = 21,
        .raw_certificate_policies = empty_qualifiers,
    }));

    var notice = Fixtures.init(testing.allocator);
    defer notice.deinit();
    const nonminimal_notice = [_]PolicyQualifierSpec{.{ .user_notice_nonminimal_number = "nonminimal" }};
    try testing.expectError(error.MalformedExtension, notice.add(.{
        .subject = "nonminimal notice number",
        .issuer = "nonminimal notice number",
        .subject_key = 22,
        .issuer_key = 22,
        .certificate_policies = &.{.{ .policy = &policy_a, .qualifiers = &nonminimal_notice }},
        .certificate_policies_critical = true,
    }));
}

test "SkipCerts values above u32 saturate without inhibiting bounded paths" {
    const require_large = [_]u8{ 0x30, 0x07, 0x80, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const mapping_large = [_]u8{ 0x30, 0x07, 0x81, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const any_large = [_]u8{ 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 8, .issuer_key = 8, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Require large",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 8,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .raw_policy_constraints = &require_large,
    });
    try fx.add(.{ .subject = "missing leaf", .issuer = "Require large", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80 });
    try fx.add(.{
        .subject = "Mapping upper",
        .issuer = "Root",
        .subject_key = 5,
        .issuer_key = 8,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .raw_policy_constraints = &mapping_large,
    });
    try fx.add(.{
        .subject = "Mapping lower",
        .issuer = "Mapping upper",
        .subject_key = 4,
        .issuer_key = 5,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "mapped leaf",
        .issuer = "Mapping lower",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_b }},
    });
    try fx.add(.{
        .subject = "Any large",
        .issuer = "Root",
        .subject_key = 7,
        .issuer_key = 8,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .raw_inhibit_any_policy = &any_large,
    });
    try fx.add(.{
        .subject = "any leaf",
        .issuer = "Any large",
        .subject_key = 6,
        .issuer_key = 7,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });

    try testing.expect(fx.certs.items[1].policyConstraints().?.require_explicit_policy.? > 3);
    try testing.expect(fx.certs.items[3].policyConstraints().?.inhibit_policy_mapping.? > 3);
    try testing.expect(fx.certs.items[6].inhibitAnyPolicy().? > 3);
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var require_result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer require_result.deinit(testing.allocator);
    try expectAccepted(&require_result, 3);

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var strict = policy(fx.certs.items[0..1]);
    strict.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    strict.certificate_policy.initial_explicit_policy = true;
    var mapping_result = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[3..5], fx.certs.items[0..1], strict, cp);
    defer mapping_result.deinit(testing.allocator);
    try expectAccepted(&mapping_result, 4);
    var any_result = try validateBuilt(testing.allocator, &fx.certs.items[7], fx.certs.items[6..7], fx.certs.items[0..1], strict, cp);
    defer any_result.deinit(testing.allocator);
    try expectAccepted(&any_result, 3);
}

test "empty user policy sets and target wrap-up constraints are explicit" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "any leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "target CA",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x84,
        .certificate_policies = &.{.{ .policy = &policy_a }},
        .policy_constraints = .{ .require_explicit_policy = 0 },
    });
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var empty_policy = policy(fx.certs.items[0..1]);
    empty_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &.{} };
    var permissive = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], empty_policy, cp);
    defer permissive.deinit(testing.allocator);
    try expectAccepted(&permissive, 2);
    try testing.expectEqual(@as(usize, 0), permissive.accepted.policies.user_constrained.len);
    empty_policy.certificate_policy.initial_explicit_policy = true;
    var required = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], empty_policy, cp);
    defer required.deinit(testing.allocator);
    try expectRejected(&required, .certificate_policy_required, 0);

    const requested_b = [_]oid.ObjectIdentifier{try policyObject(&policy_b)};
    var wrap_policy = policy(fx.certs.items[0..1]);
    wrap_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested_b };
    var target = try validateBuilt(testing.allocator, &fx.certs.items[2], &.{}, fx.certs.items[0..1], wrap_policy, cp);
    defer target.deinit(testing.allocator);
    try expectRejected(&target, .certificate_policy_required, 0);
}

test "policy validation allocation failures are structured and leak-free" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 2, .issuer_key = 2, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{ .{ .policy = &policy_a }, .{ .policy = &policy_b } },
    });
    const elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[1], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const Context = struct {
        path: path_builder.Path,
        validation_policy: validator.ValidationPolicy,
        crypto_provider: crypto.provider.CryptoProvider,

        fn run(allocator: std.mem.Allocator, context: @This()) !void {
            var result = validator.validatePath(allocator, context.path, context.validation_policy, context.crypto_provider);
            defer result.deinit(allocator);
            switch (result) {
                .accepted => {},
                .rejected => |rejected| {
                    if (rejected.reason == .out_of_memory) return error.OutOfMemory;
                    return error.TestUnexpectedResult;
                },
            }
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Context.run, .{Context{
        .path = .{ .elements = &elements },
        .validation_policy = policy(fx.certs.items[0..1]),
        .crypto_provider = cp,
    }});
}

test "a DNS identity match cannot accept a path whose policy processing failed" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .subject_key = 2, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.expected_dns_name = "leaf.example.com";
    validation_policy.certificate_policy.initial_explicit_policy = true;
    // The SAN matches exactly, but the policy-free intermediate nulls the
    // graph while explicit policy is required: identity runs after policy
    // processing and must not resurrect the path.
    var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .certificate_policy_required, 1);
}

test "the RFC 9618 Cartesian mapping chain stays linear across depths" {
    // The attack that motivated RFC 9618 (§3.2): every CA asserts two
    // policies and maps their full Cartesian product, doubling the RFC 5280
    // valid_policy_tree at each level.  The policy graph must instead keep
    // exactly one node per policy per depth, and repeated validation must
    // produce identical resource accounting.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    const both = [_]PolicySpec{ .{ .policy = &policy_a }, .{ .policy = &policy_b } };
    const cartesian = [_]PolicyMappingSpec{
        .{ .issuer = &policy_a, .subject = &policy_a },
        .{ .issuer = &policy_a, .subject = &policy_b },
        .{ .issuer = &policy_b, .subject = &policy_a },
        .{ .issuer = &policy_b, .subject = &policy_b },
    };
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 6, .issuer_key = 6, .ca = true, .key_usage = 0x04 });
    try fx.add(.{ .subject = "CA1", .issuer = "Root", .subject_key = 5, .issuer_key = 6, .ca = true, .key_usage = 0x04, .certificate_policies = &both, .policy_mappings = &cartesian });
    try fx.add(.{ .subject = "CA2", .issuer = "CA1", .subject_key = 4, .issuer_key = 5, .ca = true, .key_usage = 0x04, .certificate_policies = &both, .policy_mappings = &cartesian });
    try fx.add(.{ .subject = "CA3", .issuer = "CA2", .subject_key = 3, .issuer_key = 4, .ca = true, .key_usage = 0x04, .certificate_policies = &both, .policy_mappings = &cartesian });
    try fx.add(.{ .subject = "CA4", .issuer = "CA3", .subject_key = 2, .issuer_key = 3, .ca = true, .key_usage = 0x04, .certificate_policies = &both, .policy_mappings = &cartesian });
    try fx.add(.{ .subject = "leaf", .issuer = "CA4", .subject_key = 1, .issuer_key = 2, .ca = false, .key_usage = 0x80, .certificate_policies = &both });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var first = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[1..5], fx.certs.items[0..1], validation_policy, cp);
    defer first.deinit(testing.allocator);
    try expectAccepted(&first, 6);
    try testing.expectEqual(@as(usize, 2), first.accepted.policies.authority_constrained.len);
    try testing.expect(first.accepted.policies.authority_constrained[0].eqlComponents(&policy_a));
    try testing.expect(first.accepted.policies.authority_constrained[1].eqlComponents(&policy_b));
    // Linear, not exponential: the anyPolicy root plus two nodes per
    // certificate depth (a 2^5-leaf policy tree would need 63 nodes).
    try testing.expectEqual(@as(usize, 11), first.accepted.policies.resource_usage.graph_nodes);
    try testing.expectEqual(@as(usize, 18), first.accepted.policies.resource_usage.graph_edges);

    var second = try validateBuilt(testing.allocator, &fx.certs.items[5], fx.certs.items[1..5], fx.certs.items[0..1], validation_policy, cp);
    defer second.deinit(testing.allocator);
    try expectAccepted(&second, 6);
    try testing.expectEqualDeep(first.accepted.policies.resource_usage, second.accepted.policies.resource_usage);
}

test "self-issued certificates may assert anyPolicy while inhibit-anyPolicy is exhausted" {
    // RFC 5280 §6.1.3 (d)(2): anyPolicy is processed when inhibit_anyPolicy
    // is zero if the certificate is self-issued and not the target.  A
    // non-self-issued certificate in the same position is inhibited.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 5, .issuer_key = 5, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Issuer",
        .issuer = "Root",
        .subject_key = 4,
        .issuer_key = 5,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .inhibit_any_policy = 0,
    });
    try fx.add(.{
        .subject = "Issuer",
        .issuer = "Issuer",
        .subject_key = 3,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Issuer",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });
    try fx.add(.{
        .subject = "Other",
        .issuer = "Issuer",
        .subject_key = 2,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
    });
    try fx.add(.{
        .subject = "other leaf",
        .issuer = "Other",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_a }},
    });

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    const self_issued_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[3], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    var accepted = validator.validatePath(testing.allocator, .{ .elements = &self_issued_elements }, validation_policy, cp);
    defer accepted.deinit(testing.allocator);
    try expectAccepted(&accepted, 4);
    try testing.expect(accepted.accepted.policies.user_constrained[0].eqlComponents(&policy_a));

    const renamed_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[5], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[4], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[1], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[0], .source = .anchor, .input_index = 0 },
    };
    var rejected = validator.validatePath(testing.allocator, .{ .elements = &renamed_elements }, validation_policy, cp);
    defer rejected.deinit(testing.allocator);
    try expectRejected(&rejected, .certificate_policy_required, 1);
}

test "policy mappings apply through an asserted anyPolicy" {
    // RFC 9618 §5.4 (b)(2): when a CA maps an issuerDomainPolicy it does not
    // assert directly but anyPolicy is present, the mapping materializes a
    // node under the previous depth's anyPolicy node.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04 });
    try fx.add(.{
        .subject = "Mapping CA",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .certificate_policies = &.{.{ .policy = &oid.well_known.any_policy }},
        .policy_mappings = &.{.{ .issuer = &policy_a, .subject = &policy_b }},
    });
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Mapping CA",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .certificate_policies = &.{.{ .policy = &policy_b }},
    });

    const requested = [_]oid.ObjectIdentifier{try policyObject(&policy_a)};
    var validation_policy = policy(fx.certs.items[0..1]);
    validation_policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    validation_policy.certificate_policy.initial_explicit_policy = true;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[2], fx.certs.items[1..2], fx.certs.items[0..1], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    try testing.expectEqual(@as(usize, 1), result.accepted.policies.user_constrained.len);
    try testing.expect(result.accepted.policies.user_constrained[0].eqlComponents(&policy_a));
}

// --- #492 adversarial path-validation targets -------------------------------
//
// Validation is the last PKI stage and the one whose *output* is a security
// decision, so these oracles are about determinism, boundedness, and the
// shape of the verdict: identical inputs must produce an identical verdict,
// an accepted path must be one of the candidates the builder actually
// emitted, and a rejection must carry nothing but reason/stage metadata.
// No target here performs AIA/OCSP/CRL fetching, because the modules under
// test contain no network code at all — `validatePath` takes an already-built
// path and an injected clock.

fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .optional => |info| containsPointer(info.child),
        .array => |info| containsPointer(info.child),
        .@"struct" => |info| blk: {
            inline for (info.fields) |field| {
                if (containsPointer(field.type)) break :blk true;
            }
            break :blk false;
        },
        .@"union" => |info| blk: {
            inline for (info.fields) |field| {
                if (containsPointer(field.type)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

test "a validation failure carries only reason and stage metadata, never borrowed memory" {
    // Structural proof of the sanitized-diagnostics rule: a `ValidationFailure`
    // has no pointer-shaped field anywhere in its transitive layout, so it
    // cannot carry certificate bytes, key material, or any other borrowed
    // attacker-controlled slice out of the validator.
    try testing.expect(!containsPointer(validator.ValidationFailure));
    try testing.expect(!containsPointer(validator.FailureReason));
}

const fuzz_builder_limits: path_builder.Limits = .{ .max_path_len = 6, .max_paths = 4 };

// --- Algorithm / signature failure classes ----------------------------------
//
// #492 lists "algorithm/signature failure classes" among the cases this
// target must exercise. `path_validator.signatureFailure` maps `verify.zig`'s
// five outcomes onto five distinct `FailureReason`s, and varying only *which
// key signed* reaches exactly one of them (`signature_invalid`). The rest are
// driven by mutating the already-parsed views just enough to hit the
// classification seam.
//
// This is deliberately not a re-run of #376's provider-primitive
// malformed-key/signature fuzzing: nothing here hands hostile bytes to a
// crypto primitive. It mutates a *parsed* `AlgorithmIdentifier`,
// `BitStringView`, or SPKI so `verify.verifyCertificateSignature` must
// classify the mismatch, which is the seam this story owns. `raw`/`tbs_raw`
// are intentionally left alone, so path structure still validates and the
// signature layer is the only thing under test.
//
// Signature verification runs before validity, Basic Constraints, Key Usage,
// EKU, Name Constraints, policy, and identity, so once path structure and the
// critical-extension scan pass, the classification is the *first* rejection —
// which is what lets these cases carry an exact reason oracle even while the
// surrounding chain, policy, and time state stay adversarial.
const SignatureCase = enum {
    valid,
    /// Construction-time: signed by a key nobody in the chain holds.
    forged_leaf,
    forged_intermediate,
    /// Ed25519 signatures are exactly 64 bytes.
    signature_truncated,
    /// A signature BIT STRING must be octet-aligned.
    signature_unaligned,
    /// An OID outside the supported matrix.
    algorithm_unknown_oid,
    /// RFC 8410 §3: Ed25519 signatureAlgorithm parameters MUST be absent.
    algorithm_ed25519_with_parameters,
    /// Supported algorithm, supported key, inconsistent pairing.
    algorithm_key_type_mismatch,
    /// Ed25519 public keys are exactly 32 bytes.
    issuer_key_truncated,
    /// A public-key BIT STRING must be octet-aligned.
    issuer_key_unaligned,
    /// RFC 8410 §3: Ed25519 SPKI parameters MUST be absent.
    issuer_key_with_parameters,
};

const signature_cases = std.enums.values(SignatureCase);

/// An explicit ASN.1 NULL, used where a parameters field must be absent.
const explicit_null_parameters = [_]u8{ 0x05, 0x00 };

const SignatureExpectation = struct {
    reason: validator.FailureReason,
    certificate_index: usize,
};

/// Applies `signature_case`'s post-parse view mutation, if it has one, and
/// returns the exact classification the validator owes it. The two `forged_*`
/// cases are applied at construction time instead (see `.issuer_key` in the
/// specs), so this only reports their expectation.
fn applySignatureCase(
    certificates: []x509.Certificate,
    intermediate_count: usize,
    signature_case: SignatureCase,
) ?SignatureExpectation {
    const leaf = &certificates[0];
    // The leaf's issuer is always the next element: the first intermediate
    // when there is one, otherwise the anchor itself.
    const issuer = &certificates[1];
    return switch (signature_case) {
        .valid => null,
        .forged_leaf => .{ .reason = .signature_invalid, .certificate_index = 0 },
        .forged_intermediate => if (intermediate_count >= 1)
            .{ .reason = .signature_invalid, .certificate_index = 1 }
        else
            // Nothing was forged: there is no intermediate to forge.
            null,
        .signature_truncated => blk: {
            const signature = leaf.signature_value.data;
            leaf.signature_value.data = signature[0 .. signature.len - 1];
            break :blk .{ .reason = .signature_malformed, .certificate_index = 0 };
        },
        .signature_unaligned => blk: {
            leaf.signature_value.unused_bits = 1;
            break :blk .{ .reason = .signature_malformed, .certificate_index = 0 };
        },
        .algorithm_unknown_oid => blk: {
            leaf.signature_algorithm.oid = oid.ObjectIdentifier.fromComponents(&[_]u32{ 1, 2, 3, 4, 5 }) catch unreachable;
            break :blk .{ .reason = .signature_algorithm_unsupported, .certificate_index = 0 };
        },
        .algorithm_ed25519_with_parameters => blk: {
            leaf.signature_algorithm.parameters_raw = &explicit_null_parameters;
            break :blk .{ .reason = .signature_algorithm_unsupported, .certificate_index = 0 };
        },
        .algorithm_key_type_mismatch => blk: {
            // An ECDSA-P256 signature algorithm against an Ed25519 issuer key:
            // both are individually supported, the pairing is not.
            leaf.signature_algorithm.oid = oid.ObjectIdentifier.fromComponents(&oid.well_known.ecdsa_with_sha256) catch unreachable;
            leaf.signature_algorithm.parameters_raw = null;
            break :blk .{ .reason = .signature_key_mismatch, .certificate_index = 0 };
        },
        .issuer_key_truncated => blk: {
            const key = issuer.subject_public_key_info.subject_public_key.data;
            issuer.subject_public_key_info.subject_public_key.data = key[0 .. key.len - 1];
            break :blk .{ .reason = .issuer_public_key_malformed, .certificate_index = 0 };
        },
        .issuer_key_unaligned => blk: {
            issuer.subject_public_key_info.subject_public_key.unused_bits = 1;
            break :blk .{ .reason = .issuer_public_key_malformed, .certificate_index = 0 };
        },
        .issuer_key_with_parameters => blk: {
            issuer.subject_public_key_info.algorithm.parameters_raw = &explicit_null_parameters;
            break :blk .{ .reason = .issuer_public_key_malformed, .certificate_index = 0 };
        },
    };
}

/// A `leaf -> Intermediate -> Root` chain that is known-good except for
/// `signature_case`'s construction-time forging, so a classification oracle
/// over it has nothing else that could reject first.
fn addSignatureCaseChain(fx: *Fixtures, signature_case: SignatureCase) !void {
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = if (signature_case == .forged_leaf) 9 else 2,
        .ca = false,
        .key_usage = 0x80,
        .eku = .server,
    });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = if (signature_case == .forged_intermediate) 9 else 3,
        .ca = true,
        .key_usage = 0x04,
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });
}

/// 2026-01-01T00:00:00Z and 2027-01-01T00:00:00Z, the exact Unix seconds of
/// the `260101000000Z`/`270101000000Z` window `addValidChain` uses.
const chain_not_before_unix: i64 = 1_767_225_600;
const chain_not_after_unix: i64 = 1_798_761_600;

fn expectAcceptedPathWellFormed(
    accepted: []const path_builder.Element,
    candidates: path_builder.CandidatePaths,
    validation_policy: validator.ValidationPolicy,
) !void {
    try testing.expect(accepted.len >= 2);
    try testing.expect(accepted.len <= validation_policy.maximum_path_length);
    try testing.expectEqual(path_builder.Source.leaf, accepted[0].source);
    try testing.expectEqual(path_builder.Source.anchor, accepted[accepted.len - 1].source);
    for (accepted[1 .. accepted.len - 1]) |element| {
        try testing.expectEqual(path_builder.Source.intermediate, element.source);
    }

    // The anchor is the configured one, by index and by exact DER.
    const anchor = accepted[accepted.len - 1];
    try testing.expect(anchor.input_index < validation_policy.trust_anchors.len);
    try testing.expectEqualSlices(
        u8,
        validation_policy.trust_anchors[anchor.input_index].raw,
        anchor.certificate.raw,
    );

    // An accepted path is one of the candidates, never a synthesized one.
    var matched = false;
    for (candidates.paths) |candidate| {
        if (candidate.elements.len != accepted.len) continue;
        var same = true;
        for (candidate.elements, accepted) |a, b| {
            if (a.certificate != b.certificate or a.source != b.source or a.input_index != b.input_index) {
                same = false;
                break;
            }
        }
        if (same) {
            matched = true;
            break;
        }
    }
    try testing.expect(matched);
}

fn expectSameOptionalOid(expected: ?oid.ObjectIdentifier, actual: ?oid.ObjectIdentifier) !void {
    if (expected) |lhs| {
        const rhs = actual orelse return error.TestUnexpectedResult;
        try testing.expect(lhs.eql(&rhs));
    } else {
        try testing.expect(actual == null);
    }
}

fn expectSameOidSlice(expected: []const oid.ObjectIdentifier, actual: []const oid.ObjectIdentifier) !void {
    try testing.expectEqual(expected.len, actual.len);
    // Both slices are documented as unique and lexicographically ordered, so
    // position-wise comparison is the right equality here: a run that emitted
    // the same set in a different order is still non-deterministic output.
    for (expected, actual) |lhs, rhs| try testing.expect(lhs.eql(&rhs));
}

fn expectSameVerdict(first: validator.ValidationResult, second: validator.ValidationResult) !void {
    switch (first) {
        .accepted => |mine| switch (second) {
            .accepted => |other| {
                try testing.expectEqual(mine.accepted_path.len, other.accepted_path.len);
                for (mine.accepted_path, other.accepted_path) |a, b| {
                    try testing.expectEqual(a.certificate, b.certificate);
                    try testing.expectEqual(a.source, b.source);
                    try testing.expectEqual(a.input_index, b.input_index);
                }
                // The accepted *result* is the path plus its RFC 9618 policy
                // output, so determinism has to cover the policy output too:
                // two runs agreeing on the path but disagreeing on the
                // constrained policy sets, or on the bounded graph accounting,
                // would still be a non-deterministic result.
                try expectSameOidSlice(mine.policies.authority_constrained, other.policies.authority_constrained);
                try expectSameOidSlice(mine.policies.user_constrained, other.policies.user_constrained);
                try testing.expectEqual(mine.policies.resource_usage, other.policies.resource_usage);
                // The certificate-status record is part of the accepted result
                // for the same reason: two runs that agreed on the path but
                // disagreed on what evidence was checked are not deterministic.
                try testing.expectEqual(mine.revocation.mode, other.revocation.mode);
                try testing.expectEqual(mine.revocation.must_staple, other.revocation.must_staple);
                try testing.expectEqual(mine.revocation.entries.len, other.revocation.entries.len);
                for (mine.revocation.entries, other.revocation.entries) |a, b| {
                    try testing.expectEqual(a, b);
                }
            },
            .rejected => return error.TestUnexpectedResult,
        },
        .rejected => |mine| switch (second) {
            .accepted => return error.TestUnexpectedResult,
            .rejected => |other| {
                // Every field of the failure value participates: the #492
                // criterion is deterministic *failure output*, so a run that
                // agreed on the reason but disagreed on which OID it named
                // would still be non-deterministic output.
                try testing.expectEqual(mine.reason, other.reason);
                try testing.expectEqual(mine.certificate_index, other.certificate_index);
                try testing.expectEqual(mine.constraint_certificate_index, other.constraint_certificate_index);
                try testing.expectEqual(mine.name_constraint_kind, other.name_constraint_kind);
                try testing.expectEqual(mine.name_form, other.name_form);
                try testing.expectEqual(mine.policy_stage, other.policy_stage);
                try testing.expectEqual(mine.policy_graph_depth, other.policy_graph_depth);
                try testing.expectEqual(mine.revocation_source, other.revocation_source);
                try testing.expectEqual(mine.revocation_defect, other.revocation_defect);
                try testing.expectEqual(mine.revocation_reason, other.revocation_reason);
                try expectSameOptionalOid(mine.extension_oid, other.extension_oid);
                try expectSameOptionalOid(mine.policy_oid, other.policy_oid);
            },
        },
    }
}

test "validation classifies every algorithm and signature failure class" {
    // `path_validator.signatureFailure` maps `verify.zig`'s five outcomes onto
    // five distinct `FailureReason`s. Each is pinned here on a chain that is
    // otherwise known-good, so the classification is the only thing that can
    // reject: this proves every class is reachable and correctly mapped, which
    // is what makes the fuzz target's exact reason oracle meaningful. The fuzz
    // target then explores the same seam against generated path, policy, and
    // time state, where one Smith draw only ever samples a single class.
    const allocator = testing.allocator;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    var seen_reasons = std.EnumSet(validator.FailureReason).initEmpty();
    for (signature_cases) |signature_case| {
        var fx = Fixtures.init(allocator);
        defer fx.deinit();
        try addSignatureCaseChain(&fx, signature_case);
        const expectation = applySignatureCase(fx.certs.items, 1, signature_case);
        const anchors = fx.certs.items[2..3];
        var result = try validateBuilt(
            allocator,
            &fx.certs.items[0],
            fx.certs.items[1..2],
            anchors,
            policy(anchors),
            cp,
        );
        defer result.deinit(allocator);
        if (expectation) |expected| {
            try expectRejected(&result, expected.reason, expected.certificate_index);
            seen_reasons.insert(expected.reason);
        } else {
            try expectAccepted(&result, 3);
        }
    }

    // All five classes really were exercised, so a future edit that quietly
    // stops reaching one of them fails here instead of passing vacuously.
    for ([_]validator.FailureReason{
        .signature_invalid,
        .signature_malformed,
        .signature_algorithm_unsupported,
        .signature_key_mismatch,
        .issuer_public_key_malformed,
    }) |reason| {
        try testing.expect(seen_reasons.contains(reason));
    }
}

test "validation pins the validity window and pathLenConstraint boundaries" {
    const allocator = testing.allocator;
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    // Everything else about this chain is known-good, so the verdict is a pure
    // function of where `validation_time` sits relative to the window.
    {
        var fx = Fixtures.init(allocator);
        defer fx.deinit();
        try addValidChain(&fx, 1);
        const anchors = fx.certs.items[2..3];
        const cases = [_]struct { time: i64, expected: ?validator.FailureReason }{
            .{ .time = chain_not_before_unix - 1, .expected = .certificate_not_yet_valid },
            .{ .time = chain_not_before_unix, .expected = null },
            .{ .time = chain_not_after_unix, .expected = null },
            .{ .time = chain_not_after_unix + 1, .expected = .certificate_expired },
        };
        for (cases) |case| {
            var boundary_policy = policy(anchors);
            boundary_policy.validation_time = case.time;
            var result = try validateBuilt(
                allocator,
                &fx.certs.items[0],
                fx.certs.items[1..2],
                anchors,
                boundary_policy,
                cp,
            );
            defer result.deinit(allocator);
            if (case.expected) |reason| {
                try expectRejected(&result, reason, 0);
            } else {
                try expectAccepted(&result, 3);
            }
        }
    }

    // RFC 5280 path length needs a `leaf -> I1 -> I2 -> root` shape to be
    // reachable at all: with a single intermediate the validator counts CA
    // certificates in the empty slice `path.elements[1..1]`, so its
    // `pathLenConstraint` can never be exceeded, and the anchor's own
    // constraint is not a validation input. At leaf-first index 2, `I2` counts
    // exactly one non-self-issued CA below it, so 0 must be exceeded and 1
    // must accept.
    //
    // Every non-anchor certificate also asserts the same policy, so the
    // accepted result carries a non-empty RFC 9618 constrained set. That is
    // what makes the per-OID half of `expectSameVerdict`'s accepted branch
    // live: against a chain with no policies extension both constrained
    // slices are empty and only their lengths get compared.
    for ([_]u8{ 0, 1 }) |path_len| {
        var fx = Fixtures.init(allocator);
        defer fx.deinit();
        const chain_policies: []const PolicySpec = &.{.{ .policy = &[_]u32{ 1, 3, 6, 1, 4, 1, 4242, 7 } }};
        try fx.add(.{
            .subject = "leaf",
            .issuer = "Intermediate 1",
            .subject_key = 1,
            .issuer_key = 2,
            .ca = false,
            .key_usage = 0x80,
            .eku = .server,
            .certificate_policies = chain_policies,
        });
        try fx.add(.{
            .subject = "Intermediate 1",
            .issuer = "Intermediate 2",
            .subject_key = 2,
            .issuer_key = 4,
            .ca = true,
            .key_usage = 0x04,
            .certificate_policies = chain_policies,
        });
        try fx.add(.{
            .subject = "Intermediate 2",
            .issuer = "Root",
            .subject_key = 4,
            .issuer_key = 3,
            .ca = true,
            .path_len = path_len,
            .key_usage = 0x04,
            .certificate_policies = chain_policies,
        });
        try fx.add(.{
            .subject = "Root",
            .issuer = "Root",
            .subject_key = 3,
            .issuer_key = 3,
            .ca = true,
            .key_usage = 0x04,
        });
        const anchors = fx.certs.items[3..4];
        var result = try validateBuilt(
            allocator,
            &fx.certs.items[0],
            fx.certs.items[1..3],
            anchors,
            policy(anchors),
            cp,
        );
        defer result.deinit(allocator);
        if (path_len == 0) {
            try expectRejected(&result, .path_length_exceeded, 2);
        } else {
            try expectAccepted(&result, 4);
        }

        // Replaying a known-good chain is what gives `expectSameVerdict`'s
        // accepted branch -- including the RFC 9618 policy output -- coverage
        // under plain `zig build test`. The randomized chain in the fuzz
        // target reaches an accepted verdict readily under `--fuzz`, but
        // essentially never during seed-corpus replay.
        var replay = try validateBuilt(
            allocator,
            &fx.certs.items[0],
            fx.certs.items[1..3],
            anchors,
            policy(anchors),
            cp,
        );
        defer replay.deinit(allocator);
        try expectSameVerdict(result, replay);
    }
}

test "fuzz: PKI: path validation is deterministic, bounded, and sanitized on adversarial chains" {
    try testing.fuzz({}, fuzzPathValidation, .{ .corpus = &.{
        "",
        &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        &[_]u8{ 1, 0, 2, 1, 0, 3, 1, 1 },
        &[_]u8{ 0, 2, 0, 0, 1, 0, 0, 0, 1 },
        &([_]u8{1} ** 24),
        &([_]u8{0xff} ** 32),
    } });
}

fn fuzzPathValidation(_: void, smith: *testing.Smith) !void {
    const allocator = testing.allocator;

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    // Deterministic boundary and classification oracles for this surface are
    // named tests below (`validation pins ...`, `validation classifies ...`),
    // not inline here: each of them builds and Ed25519-signs several chains,
    // which inside the fuzz callback would be rebuilt on every iteration and
    // throttle coverage-guided exploration by orders of magnitude for no
    // additional coverage. As separate `test` blocks they still run under
    // `zig build test`.

    var fx = Fixtures.init(allocator);
    defer fx.deinit();

    const windows = [_][2][]const u8{
        .{ "260101000000Z", "270101000000Z" }, // Contains the validation time.
        .{ "200101000000Z", "210101000000Z" }, // Wholly in the past.
        .{ "400101000000Z", "410101000000Z" }, // Wholly in the future.
        .{ "260701000000Z", "260701000000Z" }, // Zero-width, exactly on it.
    };
    // 0x00 is deliberately absent: an all-zero Key Usage is rejected by the
    // #341 parser (RFC 5280 §4.2.1.3 requires at least one bit), so it would
    // build an unparsable fixture rather than reach validation at all.
    const key_usages = [_]?u8{ null, 0x80, 0x20, 0x04, 0xa0, 0xff };
    const ekus = [_]Eku{ .absent, .server, .client, .any };
    // Certificate policies drive the RFC 9618 graph, so varying them is what
    // makes the accepted result's policy output (and the
    // `certificate_policy_*` rejection reasons) non-trivial rather than an
    // always-empty set.
    const policy_sets = [_]?[]const PolicySpec{
        null,
        &.{.{ .policy = &[_]u32{ 2, 5, 29, 32, 0 } }},
        &.{.{ .policy = &[_]u32{ 1, 3, 6, 1, 4, 1, 4242, 1 } }},
        &.{
            .{ .policy = &[_]u32{ 1, 3, 6, 1, 4, 1, 4242, 1 } },
            .{ .policy = &[_]u32{ 1, 3, 6, 1, 4, 1, 4242, 2 } },
        },
    };

    // Zero, one, or *two* intermediates. Two is not decoration: with a single
    // intermediate at leaf-first index 1, `validatePath` counts CA
    // certificates in the empty slice `path.elements[1..1]`, so a
    // pathLenConstraint on it can never be exceeded and RFC 5280 path-length
    // enforcement is unreachable. The anchor's own constraint does not help
    // either, since trust-anchor extensions are deliberately not validation
    // inputs. Only a `leaf -> I1 -> I2 -> root` shape reaches the rule.
    const intermediate_count = smith.index(3);
    const leaf_window = windows[smith.index(windows.len)];
    const intermediate_window = windows[smith.index(windows.len)];
    const root_window = windows[smith.index(windows.len)];
    // A signature forged with a key nobody in the chain holds.
    // One mutually-exclusive signature/algorithm case per run, so the
    // resulting classification is unambiguous and can carry an exact oracle.
    const signature_case = signature_cases[smith.index(signature_cases.len)];
    const forged_leaf = signature_case == .forged_leaf;
    const forged_intermediate = signature_case == .forged_intermediate;
    // An unknown *critical* extension is rejected during the extension scan,
    // which runs before signature verification, so it would mask the
    // classification under test. The non-critical variant is harmless and
    // stays available in every case.
    const leaf_unknown = if (signature_case == .valid) smith.index(6) else 2 * smith.index(2);
    const intermediate_ca: ?bool = if (smith.index(6) == 0) null else smith.index(6) != 0;

    // Subject names and signing keys per shape, leaf-first. `nearest` is the
    // leaf's issuer; the intermediates chain up to "Root".
    const nearest_name: []const u8 = switch (intermediate_count) {
        0 => "Root",
        else => "Intermediate 1",
    };
    const nearest_key: u8 = switch (intermediate_count) {
        0 => 3,
        else => 2,
    };

    try fx.add(.{
        .subject = "leaf",
        .issuer = nearest_name,
        .subject_key = 1,
        .issuer_key = if (forged_leaf) 9 else nearest_key,
        .not_before = leaf_window[0],
        .not_after = leaf_window[1],
        .ca = if (smith.index(4) == 0) null else smith.index(4) == 0,
        .key_usage = key_usages[smith.index(key_usages.len)],
        .eku = ekus[smith.index(ekus.len)],
        .san = if (smith.index(2) == 0) "leaf.example.com" else null,
        .certificate_policies = policy_sets[smith.index(policy_sets.len)],
        // Both flags emit the same OID, so asking for both would build a
        // duplicate-extension fixture the parser rejects before validation
        // ever runs. Duplicate extensions are #492's X.509 target's job.
        .unknown_critical = leaf_unknown == 1,
        .unknown_noncritical = leaf_unknown == 2,
    });
    if (intermediate_count >= 1) {
        const issuer_name: []const u8 = if (intermediate_count == 2) "Intermediate 2" else "Root";
        const issuer_key: u8 = if (intermediate_count == 2) 4 else 3;
        try fx.add(.{
            .subject = "Intermediate 1",
            .issuer = issuer_name,
            .subject_key = 2,
            .issuer_key = if (forged_intermediate) 9 else issuer_key,
            .not_before = intermediate_window[0],
            .not_after = intermediate_window[1],
            .ca = intermediate_ca,
            // RFC 5280 §4.2.1.9 only permits pathLenConstraint alongside
            // cA TRUE, and the #341 parser enforces that, so pairing it with
            // a non-CA here would build an unparsable fixture instead of an
            // interesting validation case.
            .path_len = if (intermediate_ca == true and smith.index(3) == 0) @intCast(smith.index(3)) else null,
            .key_usage = key_usages[smith.index(key_usages.len)],
            .eku = ekus[smith.index(ekus.len)],
            .name_constraints = if (smith.index(4) == 0) .{
                .permitted = &.{.{ .dns = "example.com" }},
                .critical = smith.index(2) == 0,
            } else null,
            .certificate_policies = policy_sets[smith.index(policy_sets.len)],
            .unknown_critical = signature_case == .valid and smith.index(8) == 0,
        });
    }
    if (intermediate_count == 2) {
        // The certificate whose pathLenConstraint the validator can actually
        // exceed: at leaf-first index 2 it counts the non-self-issued CAs
        // below it, which is exactly "Intermediate 1".
        const second_ca: ?bool = if (smith.index(8) == 0) null else smith.index(8) != 0;
        try fx.add(.{
            .subject = "Intermediate 2",
            .issuer = "Root",
            .subject_key = 4,
            .issuer_key = 3,
            .not_before = intermediate_window[0],
            .not_after = intermediate_window[1],
            .ca = second_ca,
            .path_len = if (second_ca == true and smith.index(2) == 0) @intCast(smith.index(3)) else null,
            .key_usage = key_usages[smith.index(key_usages.len)],
            .eku = ekus[smith.index(ekus.len)],
            .certificate_policies = policy_sets[smith.index(policy_sets.len)],
        });
    }
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .not_before = root_window[0],
        .not_after = root_window[1],
        .ca = true,
        .path_len = if (smith.index(3) == 0) @intCast(smith.index(3)) else null,
        .key_usage = 0x04,
    });

    const certs = fx.certs.items;
    // Mutate the parsed views before validating. Path discovery consumes
    // names and key identifiers only, so this cannot perturb which candidates
    // the builder finds -- just how the validator classifies them.
    const expected_signature = applySignatureCase(certs, intermediate_count, signature_case);
    const leaf = &certs[0];
    const intermediates = certs[1 .. 1 + intermediate_count];
    const anchors = certs[certs.len - 1 ..];

    const validation_policy: validator.ValidationPolicy = .{
        .validation_time = validation_time,
        .expected_dns_name = if (smith.index(3) == 0) "leaf.example.com" else null,
        .require_server_auth_eku = smith.index(2) == 0,
        // A path longer than this bound is refused by the structure check,
        // before signature verification, so when a classification is under
        // test the bound must admit the whole candidate.
        .maximum_path_length = if (signature_case == .valid)
            2 + smith.index(5)
        else
            fuzz_builder_limits.max_path_len,
        .enforce_anchor_validity = smith.index(4) == 0,
        .trust_anchors = anchors,
    };

    var candidates = path_builder.build(allocator, leaf, intermediates, anchors, fuzz_builder_limits) catch |err| switch (err) {
        error.OutOfMemory => return err,
        // Nothing to validate; the builder's own invariants are #492's
        // path-building target.
        else => return,
    };
    defer candidates.deinit(allocator);

    var result = validator.validateCandidates(allocator, candidates, validation_policy, cp);
    defer result.deinit(allocator);

    switch (result) {
        .accepted => |accepted| {
            try expectAcceptedPathWellFormed(accepted.accepted_path, candidates, validation_policy);
            // A signature or algorithm defect is never accepted, whatever the
            // rest of the generated chain, policy, and time state says.
            try testing.expect(expected_signature == null);
        },
        .rejected => |failure| {
            if (failure.certificate_index) |index| {
                try testing.expect(index < fuzz_builder_limits.max_path_len);
            }
            if (failure.constraint_certificate_index) |index| {
                try testing.expect(index < fuzz_builder_limits.max_path_len);
            }
            if (failure.extension_oid) |extension_oid| {
                try testing.expect(extension_oid.components().len >= 2);
                try testing.expect(extension_oid.components().len <= oid.max_components);
            }
            if (failure.policy_oid) |policy_oid| {
                try testing.expect(policy_oid.components().len <= oid.max_components);
            }
            if (expected_signature) |expected| {
                // Signature verification precedes validity, Basic
                // Constraints, Key Usage, EKU, Name Constraints, policy, and
                // identity, and the generator above keeps the two checks that
                // *do* run earlier (path structure and the critical-extension
                // scan) from rejecting, so this classification is the first
                // rejection and the reason is exact.
                if (candidates.truncated) {
                    // The one documented exception: a truncated bounded
                    // search reports the resource limit for the whole
                    // candidate set instead of any single path's reason.
                    try testing.expect(failure.reason == .validation_resource_limit_exceeded or
                        failure.reason == expected.reason);
                } else {
                    try testing.expectEqual(expected.reason, failure.reason);
                    try testing.expectEqual(@as(?usize, expected.certificate_index), failure.certificate_index);
                }
            }
        },
    }

    // Identical bytes, policy, and time must produce an identical verdict.
    var replay = validator.validateCandidates(allocator, candidates, validation_policy, cp);
    defer replay.deinit(allocator);
    try expectSameVerdict(result, replay);

    // Allocation failure at every reachable point: the verdict degrades to a
    // structured rejection and every byte allocated on the failing path is
    // released, so no partially owned accepted path escapes.
    // Runs until the first attempt whose fail index is past the last
    // allocation the validator makes, so the sweep provably covers *every*
    // reachable allocation point rather than stopping at an arbitrary cap.
    // The generated path and policy dimensions are already bounded, so this
    // terminates.
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var attempt = validator.validateCandidates(failing.allocator(), candidates, validation_policy, cp);
        attempt.deinit(failing.allocator());
        if (!failing.has_induced_failure) break;
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

// --- Certificate-status policy through the validator (#349) -----------------

const revocation = @import("revocation.zig");

fn statusAssertion(
    certificate: *const x509.Certificate,
    source: revocation.Source,
    status: revocation.Status,
) revocation.StatusAssertion {
    return .{
        .certificate = revocation.CertificateIdentity.of(certificate),
        .source = source,
        .status = status,
        .signature_verified = true,
        .this_update = validation_time - 3600,
        .next_update = validation_time + 3600,
    };
}

test "an accepted path records that revocation was not checked by default" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);

    // The acceptance is explicit about having checked nothing, rather than
    // leaving a caller to assume revocation was verified.
    const report = result.accepted.revocation;
    try testing.expectEqual(revocation.Mode.disabled, report.mode);
    try testing.expectEqual(@as(usize, 2), report.entries.len);
    for (report.entries) |entry| {
        try testing.expectEqual(revocation.Determination.not_checked_policy_disabled, entry.determination);
    }
    try testing.expect(!report.allChecked());
}

test "stapled status evidence is carried onto the accepted path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    const assertions = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
        statusAssertion(&fx.certs.items[1], .cached_ocsp, .good),
    };
    var validation_policy = policy(fx.certs.items[2..3]);
    validation_policy.revocation = .{ .mode = .strict };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);

    const report = result.accepted.revocation;
    try testing.expect(report.allChecked());
    try testing.expectEqual(revocation.Source.stapled_ocsp, report.entryFor(0).?.source.?);
    try testing.expectEqual(revocation.Source.cached_ocsp, report.entryFor(1).?.source.?);
}

test "a revoked certificate is rejected with its CRL reason" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    var revoked = statusAssertion(&fx.certs.items[0], .stapled_ocsp, .revoked);
    revoked.revocation_reason = .key_compromise;
    const assertions = [_]revocation.StatusAssertion{revoked};
    var validation_policy = policy(fx.certs.items[2..3]);
    validation_policy.revocation = .{ .mode = .soft_fail };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .certificate_revoked, 0);
    try testing.expectEqual(revocation.CrlReason.key_compromise, result.rejected.revocation_reason.?);
}

test "a must-staple leaf is rejected without a stapled good status" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .tls_features = &.{x509.TlsFeatures.status_request},
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);

    var validation_policy = policy(fx.certs.items[1..2]);
    // The certificate's demand only binds because this connection offered
    // `status_request` (RFC 7633 §4.3.3).
    validation_policy.revocation = .{ .mode = .soft_fail, .offered_status_request = true };
    var missing = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], validation_policy, cp);
    defer missing.deinit(testing.allocator);
    try expectRejected(&missing, .revocation_must_staple_not_satisfied, 0);

    const assertions = [_]revocation.StatusAssertion{statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good)};
    validation_policy.revocation_evidence = .{ .assertions = &assertions };
    var stapled = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], validation_policy, cp);
    defer stapled.deinit(testing.allocator);
    try expectAccepted(&stapled, 2);
    try testing.expect(stapled.accepted.revocation.entries[0].must_staple);

    // With status checking off, the assertion is unenforceable — and the
    // result says so instead of implying it was honored.
    var disabled_policy = policy(fx.certs.items[1..2]);
    disabled_policy.revocation = .{ .offered_status_request = true };
    var disabled = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], disabled_policy, cp);
    defer disabled.deinit(testing.allocator);
    try expectAccepted(&disabled, 2);
    try testing.expectEqual(
        revocation.MustStapleOutcome.unenforced_status_disabled,
        disabled.accepted.revocation.must_staple,
    );

    // And with the extension never offered, the certificate makes no demand of
    // this handshake at all.
    var not_offered = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], policy(fx.certs.items[1..2]), cp);
    defer not_offered.deinit(testing.allocator);
    try expectAccepted(&not_offered, 2);
    try testing.expectEqual(
        revocation.MustStapleOutcome.not_offered_by_client,
        not_offered.accepted.revocation.must_staple,
    );
}

test "a critical TLS Feature extension is a handled critical extension" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .tls_features = &.{x509.TlsFeatures.status_request},
        .tls_features_critical = true,
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], policy(fx.certs.items[1..2]), cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 2);
}

test "status evidence cannot rescue a path that fails RFC 5280 validation" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .subject_key = 1,
        .issuer_key = 3,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .not_before = "200101000000Z",
        .not_after = "210101000000Z",
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    const assertions = [_]revocation.StatusAssertion{statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good)};
    var validation_policy = policy(fx.certs.items[1..2]);
    validation_policy.revocation = .{ .mode = .strict };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], &.{}, fx.certs.items[1..2], validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .certificate_expired, 0);
}

test "status policy allocation failures stay structured and leak-free" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 1);

    const assertions = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
        statusAssertion(&fx.certs.items[1], .cached_ocsp, .good),
    };
    var validation_policy = policy(fx.certs.items[2..3]);
    validation_policy.revocation = .{ .mode = .strict };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };
    validation_policy.expected_dns_name = "leaf.example.com";

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var candidates = try path_builder.build(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], .{});
    defer candidates.deinit(testing.allocator);

    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var attempt = validator.validateCandidates(failing.allocator(), candidates, validation_policy, cp);
        attempt.deinit(failing.allocator());
        if (!failing.has_induced_failure) break;
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "an issuer's TLS Feature set constrains what its children must assert" {
    // RFC 7633 §4.2.2: a certificate-signing certificate carrying TLS Feature
    // requires every certificate it signs to assert the same set or a superset.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // 0: leaf with no TLS Feature under a must-staple-asserting intermediate.
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
    });
    // 1: leaf asserting exactly the issuer's set.
    try fx.add(.{
        .subject = "matching",
        .issuer = "Intermediate",
        .subject_key = 4,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .tls_features = &.{x509.TlsFeatures.status_request},
    });
    // 2: leaf asserting a superset.
    try fx.add(.{
        .subject = "superset",
        .issuer = "Intermediate",
        .subject_key = 5,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .tls_features = &.{ x509.TlsFeatures.status_request, x509.TlsFeatures.status_request_v2 },
    });
    // 3: leaf asserting a *different* feature than the issuer requires.
    try fx.add(.{
        .subject = "disjoint",
        .issuer = "Intermediate",
        .subject_key = 6,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
        .tls_features = &.{x509.TlsFeatures.status_request_v2},
    });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .tls_features = &.{x509.TlsFeatures.status_request},
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const intermediates = fx.certs.items[4..5];
    const anchors = fx.certs.items[5..6];

    // A staple cannot rescue a chain that breaks the issuer's constraint: the
    // constraint is checked during path validation, before any status policy.
    const assertions = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
    };
    var validation_policy = policy(anchors);
    validation_policy.revocation = .{ .mode = .stapled_only, .offered_status_request = true };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };
    var missing = try validateBuilt(testing.allocator, &fx.certs.items[0], intermediates, anchors, validation_policy, cp);
    defer missing.deinit(testing.allocator);
    try expectRejected(&missing, .tls_feature_constraint_violation, 0);
    // The failure names the issuer that imposed the constraint.
    try testing.expectEqual(@as(?usize, 1), missing.rejected.constraint_certificate_index);

    // A child asserting a different feature does not satisfy "same or superset".
    var disjoint = try validateBuilt(testing.allocator, &fx.certs.items[3], intermediates, anchors, policy(anchors), cp);
    defer disjoint.deinit(testing.allocator);
    try expectRejected(&disjoint, .tls_feature_constraint_violation, 0);

    // Same set and superset both satisfy the constraint, and then normal leaf
    // must-staple processing applies. The superset leaf also declares feature
    // 17; the §4.2.2 constraint covers every advertised feature, while the
    // end-entity obligation stays scoped to feature 5 — and here to a hello
    // that never offered `status_request`.
    for (fx.certs.items[1..3], 1..) |_, index| {
        var accepted = try validateBuilt(testing.allocator, &fx.certs.items[index], intermediates, anchors, policy(anchors), cp);
        defer accepted.deinit(testing.allocator);
        try expectAccepted(&accepted, 3);
        try testing.expectEqual(
            revocation.MustStapleOutcome.not_offered_by_client,
            accepted.accepted.revocation.must_staple,
        );
    }
}

test "an alternate candidate cannot inherit another candidate's status evidence" {
    // Two intermediates issue the same leaf name from the same key, so both
    // candidates are structurally valid and carry a *different* certificate at
    // index 1. Evidence gathered for the first must not decide the second.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
    });
    // Candidate A's intermediate expires before the validation time, so the
    // path fails a later RFC 5280 rule and the validator moves on to B.
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .not_before = "200101000000Z",
        .not_after = "210101000000Z",
    });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const intermediates = fx.certs.items[1..3];
    const anchors = fx.certs.items[3..4];

    // Evidence covers the leaf and the *expired* intermediate only.
    const assertions = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
        statusAssertion(&fx.certs.items[1], .cached_ocsp, .good),
    };
    var validation_policy = policy(anchors);
    validation_policy.revocation = .{ .mode = .strict };
    validation_policy.revocation_evidence = .{ .assertions = &assertions };

    // Candidate B on its own: same index 1, different certificate, no evidence
    // of its own. Strict mode must not let it consume candidate A's `good`.
    const candidate_b = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[0], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[2], .source = .intermediate, .input_index = 1 },
        .{ .certificate = &fx.certs.items[3], .source = .anchor, .input_index = 0 },
    };
    var isolated = validator.validatePath(testing.allocator, .{ .elements = &candidate_b }, validation_policy, cp);
    defer isolated.deinit(testing.allocator);
    // These fixtures publish no AIA or CRL distribution point, so "no usable
    // evidence for this certificate" surfaces as the unsupported-source
    // verdict rather than a plain unavailable one. Either way the point holds:
    // index 1 did not inherit the other candidate's `good`.
    try expectRejected(&isolated, .revocation_source_unsupported, 1);

    // End to end, no candidate can be accepted on that evidence: A fails its
    // validity window and B has no status of its own.
    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], intermediates, anchors, validation_policy, cp);
    defer result.deinit(testing.allocator);
    switch (result) {
        .accepted => return error.TestUnexpectedResult,
        .rejected => {},
    }

    // Binding the same evidence to the certificate that actually validates
    // accepts, which proves the rejection above was the identity check and not
    // an unrelated failure.
    const bound = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
        statusAssertion(&fx.certs.items[2], .cached_ocsp, .good),
    };
    validation_policy.revocation_evidence = .{ .assertions = &bound };
    var accepted = try validateBuilt(testing.allocator, &fx.certs.items[0], intermediates, anchors, validation_policy, cp);
    defer accepted.deinit(testing.allocator);
    try expectAccepted(&accepted, 3);
    try testing.expect(accepted.accepted.revocation.allChecked());
}

test "a longer candidate's evidence cannot reject a shorter candidate end to end" {
    // The union evidence set covers both candidates. Candidate A is one
    // certificate longer and fails an unrelated rule; candidate B has complete
    // evidence of its own and must be accepted, with A's extra assertions
    // neither applied to B nor treated as an error against it.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // 0: leaf, issued by "Intermediate".
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .subject_key = 1,
        .issuer_key = 2,
        .ca = false,
        .key_usage = 0x80,
        .san = "leaf.example.com",
    });
    // 1: candidate A's intermediate, under an expired sub-root.
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "SubRoot",
        .subject_key = 2,
        .issuer_key = 4,
        .ca = true,
        .key_usage = 0x04,
    });
    // 2: the expired sub-root, which makes candidate A fail on validity.
    try fx.add(.{
        .subject = "SubRoot",
        .issuer = "Root",
        .subject_key = 4,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
        .not_before = "200101000000Z",
        .not_after = "210101000000Z",
    });
    // 3: candidate B's intermediate, chaining straight to the anchor.
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .subject_key = 2,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });
    try fx.add(.{
        .subject = "Root",
        .issuer = "Root",
        .subject_key = 3,
        .issuer_key = 3,
        .ca = true,
        .key_usage = 0x04,
    });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    const intermediates = fx.certs.items[1..4];
    const anchors = fx.certs.items[4..5];

    const union_evidence = [_]revocation.StatusAssertion{
        statusAssertion(&fx.certs.items[0], .stapled_ocsp, .good),
        statusAssertion(&fx.certs.items[1], .cached_ocsp, .good),
        // Only candidate A has a certificate at this depth.
        statusAssertion(&fx.certs.items[2], .cached_ocsp, .good),
        statusAssertion(&fx.certs.items[3], .cached_ocsp, .good),
    };
    var validation_policy = policy(anchors);
    validation_policy.revocation = .{ .mode = .strict };
    validation_policy.revocation_evidence = .{ .assertions = &union_evidence };

    var result = try validateBuilt(testing.allocator, &fx.certs.items[0], intermediates, anchors, validation_policy, cp);
    defer result.deinit(testing.allocator);
    try expectAccepted(&result, 3);
    const report = result.accepted.revocation;
    try testing.expect(report.allChecked());
    try testing.expectEqual(@as(usize, 2), report.entries.len);
}
