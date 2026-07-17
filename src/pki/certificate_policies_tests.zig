//! Deterministic, offline RFC 9618 certificate-policy fixtures (#345).
//!
//! The policy engine never verifies signatures, so these fixtures carry a
//! placeholder signature BIT STRING: they are parseable #341 views, which is
//! exactly the engine's input contract.  End-to-end integration through
//! `path_validator` (with real signatures) is covered in
//! `path_validator_tests.zig`.

const std = @import("std");
const cert_policies = @import("certificate_policies.zig");
const der = @import("der.zig");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const x509 = @import("x509.zig");

const testing = std.testing;
const wk = oid.well_known;

const test_oid_1 = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 1 };
const test_oid_2 = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 2 };
const test_oid_3 = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 3 };
const test_oid_4 = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 4 };
const unknown_qualifier_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 99 };

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

fn nameWithCn(arena: std.mem.Allocator, common_name: []const u8) ![]u8 {
    const attribute = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &wk.common_name),
        try tlv(arena, 0x0c, &.{common_name}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{attribute})});
}

fn extensionTlv(arena: std.mem.Allocator, components: []const u32, critical: bool, value: []const u8) ![]u8 {
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

const QualifierSpec = union(enum) {
    cps: []const u8,
    user_notice_text: []const u8,
    user_notice_full: void,
    unknown: void,
};

const PolicySpec = struct {
    components: []const u32,
    qualifiers: []const QualifierSpec = &.{},
};

const PolicyExt = struct {
    critical: bool = false,
    policies: []const PolicySpec,
};

const MappingSpec = struct {
    issuer: []const u32,
    subject: []const u32,
};

const ConstraintsSpec = struct {
    require_explicit_policy: ?u32 = null,
    inhibit_policy_mapping: ?u32 = null,
    critical: bool = true,
};

const InhibitSpec = struct {
    skip_certs: u32,
    critical: bool = true,
};

const RawExtension = struct {
    components: []const u32,
    critical: bool,
    value: []const u8,
};

const Spec = struct {
    subject: []const u8,
    issuer: []const u8,
    ca: bool = true,
    policies: ?PolicyExt = null,
    mappings: ?[]const MappingSpec = null,
    mappings_critical: bool = false,
    constraints: ?ConstraintsSpec = null,
    inhibit_any: ?InhibitSpec = null,
    raw_extensions: []const RawExtension = &.{},
};

fn smallInteger(arena: std.mem.Allocator, value: u32) ![]u8 {
    var content: [5]u8 = undefined;
    var len: usize = 0;
    if (value == 0) {
        content[0] = 0;
        len = 1;
    } else {
        var scratch: [5]u8 = undefined;
        var remaining = value;
        var count: usize = 0;
        while (remaining > 0) : (count += 1) {
            scratch[count] = @intCast(remaining & 0xff);
            remaining >>= 8;
        }
        // Minimal two's-complement: prepend 0x00 when the top bit is set.
        if (scratch[count - 1] & 0x80 != 0) {
            content[0] = 0;
            len = 1;
        }
        var index: usize = count;
        while (index > 0) : (index -= 1) {
            content[len] = scratch[index - 1];
            len += 1;
        }
    }
    const out = try arena.alloc(u8, len);
    @memcpy(out, content[0..len]);
    return out;
}

fn qualifierTlv(arena: std.mem.Allocator, spec: QualifierSpec) ![]u8 {
    return switch (spec) {
        .cps => |uri| tlv(arena, 0x30, &.{
            try oidTlv(arena, &wk.qualifier_cps),
            try tlv(arena, 0x16, &.{uri}),
        }),
        .user_notice_text => |text| tlv(arena, 0x30, &.{
            try oidTlv(arena, &wk.qualifier_user_notice),
            try tlv(arena, 0x30, &.{try tlv(arena, 0x0c, &.{text})}),
        }),
        .user_notice_full => tlv(arena, 0x30, &.{
            try oidTlv(arena, &wk.qualifier_user_notice),
            try tlv(arena, 0x30, &.{
                // noticeRef: organization + noticeNumbers {1, 2}
                try tlv(arena, 0x30, &.{
                    try tlv(arena, 0x16, &.{"Bare Systems"}),
                    try tlv(arena, 0x30, &.{
                        try tlv(arena, 0x02, &.{&[_]u8{1}}),
                        try tlv(arena, 0x02, &.{&[_]u8{2}}),
                    }),
                }),
                try tlv(arena, 0x0c, &.{"policy notice"}),
            }),
        }),
        .unknown => tlv(arena, 0x30, &.{
            try oidTlv(arena, &unknown_qualifier_oid),
            try tlv(arena, 0x05, &.{}),
        }),
    };
}

fn policiesValue(arena: std.mem.Allocator, ext: PolicyExt) ![]u8 {
    var infos: std.ArrayList([]const u8) = .empty;
    defer infos.deinit(arena);
    for (ext.policies) |policy| {
        var parts: std.ArrayList([]const u8) = .empty;
        defer parts.deinit(arena);
        try parts.append(arena, try oidTlv(arena, policy.components));
        if (policy.qualifiers.len != 0) {
            var qualifiers: std.ArrayList([]const u8) = .empty;
            defer qualifiers.deinit(arena);
            for (policy.qualifiers) |qualifier| {
                try qualifiers.append(arena, try qualifierTlv(arena, qualifier));
            }
            try parts.append(arena, try tlv(arena, 0x30, qualifiers.items));
        }
        try infos.append(arena, try tlv(arena, 0x30, parts.items));
    }
    return tlv(arena, 0x30, infos.items);
}

fn mappingsValue(arena: std.mem.Allocator, mappings: []const MappingSpec) ![]u8 {
    var pairs: std.ArrayList([]const u8) = .empty;
    defer pairs.deinit(arena);
    for (mappings) |mapping| {
        try pairs.append(arena, try tlv(arena, 0x30, &.{
            try oidTlv(arena, mapping.issuer),
            try oidTlv(arena, mapping.subject),
        }));
    }
    return tlv(arena, 0x30, pairs.items);
}

fn constraintsValue(arena: std.mem.Allocator, spec: ConstraintsSpec) ![]u8 {
    var fields: std.ArrayList([]const u8) = .empty;
    defer fields.deinit(arena);
    if (spec.require_explicit_policy) |value| {
        try fields.append(arena, try tlv(arena, 0x80, &.{try smallInteger(arena, value)}));
    }
    if (spec.inhibit_policy_mapping) |value| {
        try fields.append(arena, try tlv(arena, 0x81, &.{try smallInteger(arena, value)}));
    }
    return tlv(arena, 0x30, fields.items);
}

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

    /// Add one certificate, leaf first, anchor last.
    fn add(self: *Fixtures, spec: Spec) !void {
        const arena = self.arena.allocator();
        var extensions: std.ArrayList([]const u8) = .empty;
        defer extensions.deinit(arena);

        if (spec.ca) {
            try extensions.append(arena, try extensionTlv(
                arena,
                &wk.basic_constraints,
                true,
                try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0xff}})}),
            ));
        }
        if (spec.policies) |policy_ext| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &wk.certificate_policies,
                policy_ext.critical,
                try policiesValue(arena, policy_ext),
            ));
        }
        if (spec.mappings) |mappings| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &wk.policy_mappings,
                spec.mappings_critical,
                try mappingsValue(arena, mappings),
            ));
        }
        if (spec.constraints) |constraints| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &wk.policy_constraints,
                constraints.critical,
                try constraintsValue(arena, constraints),
            ));
        }
        if (spec.inhibit_any) |inhibit| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &wk.inhibit_any_policy,
                inhibit.critical,
                try tlv(arena, 0x02, &.{try smallInteger(arena, inhibit.skip_certs)}),
            ));
        }
        for (spec.raw_extensions) |raw| {
            try extensions.append(arena, try extensionTlv(arena, raw.components, raw.critical, raw.value));
        }

        var tbs_parts: std.ArrayList([]const u8) = .empty;
        defer tbs_parts.deinit(arena);
        try tbs_parts.append(arena, try tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{2}})}));
        const serial: u8 = @intCast(self.certs.items.len + 1);
        try tbs_parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{serial}}));
        const algorithm = try tlv(arena, 0x30, &.{try oidTlv(arena, &wk.ed25519)});
        try tbs_parts.append(arena, algorithm);
        try tbs_parts.append(arena, try nameWithCn(arena, spec.issuer));
        try tbs_parts.append(arena, try tlv(arena, 0x30, &.{
            try tlv(arena, 0x17, &.{"260101000000Z"}),
            try tlv(arena, 0x17, &.{"270101000000Z"}),
        }));
        try tbs_parts.append(arena, try nameWithCn(arena, spec.subject));
        const key_bits = [_]u8{0} ++ ([_]u8{0xab} ** 32);
        try tbs_parts.append(arena, try tlv(arena, 0x30, &.{
            algorithm,
            try tlv(arena, 0x03, &.{&key_bits}),
        }));
        if (extensions.items.len > 0) {
            try tbs_parts.append(arena, try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions.items)}));
        }
        const tbs = try tlv(arena, 0x30, tbs_parts.items);

        // Placeholder signature: the policy engine never verifies it.
        const signature_bits = [_]u8{0} ++ ([_]u8{0x5a} ** 64);
        const certificate_der = try tlv(arena, 0x30, &.{
            tbs,
            algorithm,
            try tlv(arena, 0x03, &.{&signature_bits}),
        });

        const certificate = try x509.Certificate.parse(self.allocator, certificate_der, .{});
        errdefer {
            var owned = certificate;
            owned.deinit(self.allocator);
        }
        try self.certs.append(self.allocator, certificate);
    }

    /// Leaf-first, anchor-last elements over every added certificate.
    fn elements(self: *const Fixtures, buffer: []path_builder.Element) []const path_builder.Element {
        const count = self.certs.items.len;
        for (self.certs.items, 0..) |*certificate, index| {
            buffer[index] = .{
                .certificate = certificate,
                .source = if (index == 0) .leaf else if (index == count - 1) .anchor else .intermediate,
                .input_index = if (index == 0) 0 else if (index == count - 1) 0 else index - 1,
            };
        }
        return buffer[0..count];
    }
};

fn runPolicy(fx: *const Fixtures, config: cert_policies.Config) cert_policies.Result {
    var buffer: [8]path_builder.Element = undefined;
    const path_elements = fx.elements(&buffer);
    return cert_policies.validatePath(testing.allocator, .{ .elements = path_elements }, config);
}

fn runPolicyWithStats(fx: *const Fixtures, config: cert_policies.Config, stats: *cert_policies.Stats) cert_policies.Result {
    var buffer: [8]path_builder.Element = undefined;
    const path_elements = fx.elements(&buffer);
    return cert_policies.validatePathWithStats(testing.allocator, .{ .elements = path_elements }, config, stats);
}

fn expectPolicySets(
    result: *cert_policies.Result,
    expected_authority: []const []const u32,
    expected_user: []const []const u32,
) !void {
    switch (result.*) {
        .accepted => |*accepted| {
            defer accepted.deinit(testing.allocator);
            errdefer std.debug.print(
                "authority len {} user len {}\n",
                .{ accepted.authority_constrained.len, accepted.user_constrained.len },
            );
            try testing.expectEqual(expected_authority.len, accepted.authority_constrained.len);
            for (expected_authority, accepted.authority_constrained) |expected, actual| {
                try testing.expect(actual.eqlComponents(expected));
            }
            try testing.expectEqual(expected_user.len, accepted.user_constrained.len);
            for (expected_user, accepted.user_constrained) |expected, actual| {
                try testing.expect(actual.eqlComponents(expected));
            }
        },
        .rejected => |rejected| {
            std.debug.print("unexpected policy rejection: {s} at {?} stage {s}\n", .{
                @tagName(rejected.reason), rejected.certificate_index, @tagName(rejected.stage),
            });
            return error.TestUnexpectedResult;
        },
    }
}

fn expectPolicyRejected(
    result: *cert_policies.Result,
    reason: cert_policies.FailureReason,
    certificate_index: ?usize,
) !void {
    switch (result.*) {
        .accepted => |*accepted| {
            accepted.deinit(testing.allocator);
            return error.TestUnexpectedResult;
        },
        .rejected => |rejected| {
            errdefer std.debug.print("policy rejection: {s} at {?} stage {s}\n", .{
                @tagName(rejected.reason), rejected.certificate_index, @tagName(rejected.stage),
            });
            try testing.expectEqual(reason, rejected.reason);
            try testing.expectEqual(certificate_index, rejected.certificate_index);
        },
    }
}

const explicit_config = cert_policies.Config{ .initial_explicit_policy = true };

fn userConfig(user_policies: []const oid.ObjectIdentifier) cert_policies.Config {
    return .{
        .user_initial_policy_set = .{ .explicit = user_policies },
        .initial_explicit_policy = true,
    };
}

fn oidOf(components: []const u32) oid.ObjectIdentifier {
    return oid.ObjectIdentifier.fromComponents(components) catch unreachable;
}

// ---------------------------------------------------------------------------
// Basic policy behavior
// ---------------------------------------------------------------------------

test "path without certificatePolicies accepts under the default policy with empty outputs" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root" });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicySets(&result, &.{}, &.{});
}

test "one explicit policy asserted by every certificate satisfies a required user policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{oidOf(&test_oid_1)};
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "two policies with one surviving intersection" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
    } } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "no surviving policy accepts with empty outputs when explicit policy is not required" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicySets(&result, &.{}, &.{});
}

test "no surviving policy rejects when explicit policy is required" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // The graph empties while processing the leaf (depth 2): OID2 matches no
    // expected policy and no anyPolicy node exists.
    var result = runPolicy(&fx, explicit_config);
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
}

test "anyPolicy in an intermediate propagates the leaf policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "an all-anyPolicy chain constrains to anyPolicy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&wk.any_policy}, &.{&wk.any_policy});
}

test "initial anyPolicy inhibition kills anyPolicy at the first depth" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var config = explicit_config;
    config.initial_any_policy_inhibit = true;
    // The intermediate (leaf-first index 1, RFC depth 1) has only anyPolicy,
    // which is inhibited, so the graph empties there — a traversal running
    // leaf-first would instead fail at index 0 / depth 2.
    var result = runPolicy(&fx, config);
    try expectPolicyRejected(&result, .certificate_policy_required, 1);
    switch (result) {
        .rejected => |rejected| try testing.expectEqual(@as(?usize, 1), rejected.graph_depth),
        .accepted => return error.TestUnexpectedResult,
    }
}

test "inhibitAnyPolicy zero on an intermediate inhibits deeper certificates only" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "B", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} },
        .inhibit_any = .{ .skip_certs = 0 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // A's own anyPolicy is processed (the extension constrains subsequent
    // certificates), then B's anyPolicy is inhibited: the graph dies at RFC
    // depth 2 (leaf-first index 1).  Reversed traversal would report the
    // failure at a different certificate.
    var result = runPolicy(&fx, explicit_config);
    try expectPolicyRejected(&result, .certificate_policy_required, 1);

    // Without the inhibition the same chain accepts.
    var fx_ok = Fixtures.init(testing.allocator);
    defer fx_ok.deinit();
    try fx_ok.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx_ok.add(.{ .subject = "B", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx_ok.add(.{ .subject = "A", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx_ok.add(.{ .subject = "Root", .issuer = "Root" });
    var ok = runPolicy(&fx_ok, explicit_config);
    try expectPolicySets(&ok, &.{&test_oid_1}, &.{&test_oid_1});
}

test "inhibitAnyPolicy one permits exactly one further certificate" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "B", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} },
        .inhibit_any = .{ .skip_certs = 1 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // B (one certificate after A) still processes anyPolicy; the leaf does
    // not, so its anyPolicy contributes nothing and the graph dies at the
    // target depth.
    var result = runPolicy(&fx, explicit_config);
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
}

test "missing certificatePolicies nulls the graph permanently" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root" });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // Accepted with empty outputs by default; the leaf's later policies
    // cannot resurrect the graph.
    var result = runPolicy(&fx, .{});
    try expectPolicySets(&result, &.{}, &.{});

    // With explicit policy required from the start, the intermediate's
    // missing extension is the rejection point (leaf-first index 1).
    var rejected = runPolicy(&fx, explicit_config);
    try expectPolicyRejected(&rejected, .certificate_policy_required, 1);
}

test "critical certificatePolicies with supported qualifiers is accepted" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{
        .critical = true,
        .policies = &.{.{ .components = &test_oid_1, .qualifiers = &.{
            .{ .cps = "https://example.com/cps" },
            .{ .user_notice_text = "example notice" },
            .user_notice_full,
        } }},
    } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "critical certificatePolicies with an unsupported qualifier rejects" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{
        .critical = true,
        .policies = &.{.{ .components = &test_oid_1, .qualifiers = &.{.unknown} }},
    } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .certificate_policy_unsupported_qualifier, 0);
    switch (result) {
        .rejected => |rejected| {
            try testing.expect(rejected.policy_oid.?.eqlComponents(&test_oid_1));
            try testing.expect(rejected.extension_oid.?.eqlComponents(&wk.certificate_policies));
        },
        .accepted => return error.TestUnexpectedResult,
    }
}

test "noncritical certificatePolicies tolerates an unrecognized qualifier form" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{
        .policies = &.{.{ .components = &test_oid_1, .qualifiers = &.{.unknown} }},
    } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "duplicate policy OIDs in one extension fail at parse time" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .ca = false,
        .policies = .{ .policies = &.{
            .{ .components = &test_oid_1 },
            .{ .components = &test_oid_1 },
        } },
    }));
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .ca = false,
        .policies = .{ .policies = &.{
            .{ .components = &wk.any_policy },
            .{ .components = &wk.any_policy },
        } },
    }));
}

// ---------------------------------------------------------------------------
// User policy inputs
// ---------------------------------------------------------------------------

test "several requested policies intersect with the authority set" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
    } } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
    } } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{ oidOf(&test_oid_2), oidOf(&test_oid_1) };
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicySets(&result, &.{ &test_oid_1, &test_oid_2 }, &.{ &test_oid_1, &test_oid_2 });
}

test "an absent requested policy empties the user-constrained set" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{oidOf(&test_oid_3)};
    var rejected = runPolicy(&fx, userConfig(&user));
    try expectPolicyRejected(&rejected, .certificate_policy_required, 0);

    // Without required explicit policy the path is accepted; the authority
    // set is reported and the user set is empty.
    var config = userConfig(&user);
    config.initial_explicit_policy = false;
    var accepted = runPolicy(&fx, config);
    try expectPolicySets(&accepted, &.{&test_oid_1}, &.{});
}

test "duplicate user policy OIDs are a configuration error" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .ca = false });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{ oidOf(&test_oid_1), oidOf(&test_oid_1) };
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicyRejected(&result, .invalid_policy_configuration, null);
}

test "anyPolicy inside an explicit user set is a configuration error" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .ca = false });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{ oidOf(&test_oid_1), oidOf(&wk.any_policy) };
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicyRejected(&result, .invalid_policy_configuration, null);
}

test "an empty explicit user set accepts without explicit policy and rejects with it" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var accepted = runPolicy(&fx, .{ .user_initial_policy_set = .{ .explicit = &.{} } });
    try expectPolicySets(&accepted, &.{&test_oid_1}, &.{});

    var rejected = runPolicy(&fx, userConfig(&.{}));
    try expectPolicyRejected(&rejected, .certificate_policy_required, 0);
}

test "a final anyPolicy expands into every requested user policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{ oidOf(&test_oid_2), oidOf(&test_oid_1) };
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicySets(&result, &.{&wk.any_policy}, &.{ &test_oid_1, &test_oid_2 });
}

// ---------------------------------------------------------------------------
// Policy mappings
// ---------------------------------------------------------------------------

test "one-to-one policy mapping carries the issuer-domain policy" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{oidOf(&test_oid_1)};
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "one-to-many mapping accepts any mapped leaf policy without node duplication" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{
        .{ .components = &test_oid_2 },
        .{ .components = &test_oid_3 },
    } } });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{
            .{ .issuer = &test_oid_1, .subject = &test_oid_2 },
            .{ .issuer = &test_oid_1, .subject = &test_oid_3 },
        },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var stats: cert_policies.Stats = .{};
    var result = runPolicyWithStats(&fx, explicit_config, &stats);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
    // Root + OID1@1 + OID2@2 + OID3@2.
    try testing.expectEqual(@as(usize, 4), stats.total_nodes);
}

test "several issuer policies mapping to one subject policy converge on one node" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_3 }} } });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{
            .{ .components = &test_oid_1 },
            .{ .components = &test_oid_2 },
        } },
        .mappings = &.{
            .{ .issuer = &test_oid_1, .subject = &test_oid_3 },
            .{ .issuer = &test_oid_2, .subject = &test_oid_3 },
        },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var stats: cert_policies.Stats = .{};
    var result = runPolicyWithStats(&fx, explicit_config, &stats);
    // Both issuer-domain policies enter from anyPolicy, so both are
    // authority-constrained; the leaf node is shared, not duplicated.
    try expectPolicySets(&result, &.{ &test_oid_1, &test_oid_2 }, &.{ &test_oid_1, &test_oid_2 });
    // Root + OID1@1 + OID2@1 + OID3@2 (one node, two parents).
    try testing.expectEqual(@as(usize, 4), stats.total_nodes);
}

test "multi-level mappings resolve across three CAs" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_3 }} } });
    try fx.add(.{
        .subject = "B",
        .issuer = "A",
        .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} },
        .mappings = &.{.{ .issuer = &test_oid_2, .subject = &test_oid_3 }},
    });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const user = [_]oid.ObjectIdentifier{oidOf(&test_oid_1)};
    var result = runPolicy(&fx, userConfig(&user));
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "initial policy-mapping inhibition deletes mapped policies" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var config = explicit_config;
    config.initial_policy_mapping_inhibit = true;
    var result = runPolicy(&fx, config);
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
}

test "an intermediate inhibitPolicyMapping constraint inhibits later mappings" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx.add(.{
        .subject = "B",
        .issuer = "A",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .inhibit_policy_mapping = 0 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // A's constraint inhibits B's mappings (not A's own), so B's mapped
    // node is deleted and the leaf's OID2 finds no parent.
    var result = runPolicy(&fx, explicit_config);
    try expectPolicyRejected(&result, .certificate_policy_required, 0);

    // inhibitPolicyMapping = 1 skips one certificate: B's mappings remain
    // permitted and the same chain accepts.
    var fx_ok = Fixtures.init(testing.allocator);
    defer fx_ok.deinit();
    try fx_ok.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_2 }} } });
    try fx_ok.add(.{
        .subject = "B",
        .issuer = "A",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx_ok.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .inhibit_policy_mapping = 1 },
    });
    try fx_ok.add(.{ .subject = "Root", .issuer = "Root" });
    var ok = runPolicy(&fx_ok, explicit_config);
    try expectPolicySets(&ok, &.{&test_oid_1}, &.{&test_oid_1});
}

test "mappings to or from anyPolicy fail at parse time" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .mappings = &.{.{ .issuer = &wk.any_policy, .subject = &test_oid_1 }},
    }));
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &wk.any_policy }},
    }));
}

test "policy mappings on the target certificate reject" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .ca = false,
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .mappings = &.{.{ .issuer = &test_oid_1, .subject = &test_oid_2 }},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .policy_mapping_invalid, 0);
}

test "a Cartesian mapping chain stays linear in the policy graph" {
    // The RFC 9618 motivating attack: every CA asserts OID1 and OID2 and
    // maps the full Cartesian product.  The policy tree would double per
    // level; the graph must stay at two nodes per depth.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    const both = [_]PolicySpec{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
    };
    const cartesian = [_]MappingSpec{
        .{ .issuer = &test_oid_1, .subject = &test_oid_1 },
        .{ .issuer = &test_oid_1, .subject = &test_oid_2 },
        .{ .issuer = &test_oid_2, .subject = &test_oid_1 },
        .{ .issuer = &test_oid_2, .subject = &test_oid_2 },
    };
    try fx.add(.{ .subject = "leaf", .issuer = "CA4", .ca = false, .policies = .{ .policies = &both } });
    try fx.add(.{ .subject = "CA4", .issuer = "CA3", .policies = .{ .policies = &both }, .mappings = &cartesian });
    try fx.add(.{ .subject = "CA3", .issuer = "CA2", .policies = .{ .policies = &both }, .mappings = &cartesian });
    try fx.add(.{ .subject = "CA2", .issuer = "CA1", .policies = .{ .policies = &both }, .mappings = &cartesian });
    try fx.add(.{ .subject = "CA1", .issuer = "Root", .policies = .{ .policies = &both }, .mappings = &cartesian });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var first_stats: cert_policies.Stats = .{};
    var result = runPolicyWithStats(&fx, explicit_config, &first_stats);
    try expectPolicySets(&result, &.{ &test_oid_1, &test_oid_2 }, &.{ &test_oid_1, &test_oid_2 });

    // Two nodes per certificate depth plus the root: linear, not 2^depth.
    try testing.expectEqual(@as(usize, 11), first_stats.total_nodes);
    try testing.expect(first_stats.total_edges <= 2 * 2 * 5 + 2);

    // Node counts, operation counts, and outputs are identical on repeat
    // runs: processing is deterministic.
    var repeat: usize = 0;
    while (repeat < 3) : (repeat += 1) {
        var stats: cert_policies.Stats = .{};
        var again = runPolicyWithStats(&fx, explicit_config, &stats);
        try expectPolicySets(&again, &.{ &test_oid_1, &test_oid_2 }, &.{ &test_oid_1, &test_oid_2 });
        try testing.expectEqual(first_stats, stats);
    }
}

// ---------------------------------------------------------------------------
// Constraints and counters
// ---------------------------------------------------------------------------

test "requireExplicitPolicy zero on an intermediate demands policies from there on" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .require_explicit_policy = 0 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // The leaf carries no policies: the graph nulls at RFC depth 2 while
    // explicit_policy is already zero.
    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
}

test "requireExplicitPolicy one reaches zero exactly at the target" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .require_explicit_policy = 1 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // explicit_policy becomes 1 after the intermediate and 0 in wrap-up
    // step (a); the policy-free leaf leaves the user set empty.
    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
    switch (result) {
        .rejected => |rejected| try testing.expectEqual(cert_policies.Stage.wrap_up, rejected.stage),
        .accepted => return error.TestUnexpectedResult,
    }
}

test "requireExplicitPolicy zero on the target applies in wrap-up" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .ca = false,
        .constraints = .{ .require_explicit_policy = 0 },
    });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
    switch (result) {
        .rejected => |rejected| try testing.expectEqual(cert_policies.Stage.wrap_up, rejected.stage),
        .accepted => return error.TestUnexpectedResult,
    }

    // The same chain with a policy-bearing leaf accepts.
    var fx_ok = Fixtures.init(testing.allocator);
    defer fx_ok.deinit();
    try fx_ok.add(.{
        .subject = "leaf",
        .issuer = "Intermediate",
        .ca = false,
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .require_explicit_policy = 0 },
    });
    try fx_ok.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx_ok.add(.{ .subject = "Root", .issuer = "Root" });
    var ok = runPolicy(&fx_ok, .{});
    try expectPolicySets(&ok, &.{&test_oid_1}, &.{&test_oid_1});
}

test "noncritical policyConstraints and inhibitAnyPolicy fail closed" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .constraints = .{ .require_explicit_policy = 0, .critical = false },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });
    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .policy_constraints_invalid, 1);

    var fx2 = Fixtures.init(testing.allocator);
    defer fx2.deinit();
    try fx2.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx2.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .inhibit_any = .{ .skip_certs = 0, .critical = false },
    });
    try fx2.add(.{ .subject = "Root", .issuer = "Root" });
    var result2 = runPolicy(&fx2, .{});
    try expectPolicyRejected(&result2, .inhibit_any_policy_invalid, 1);
}

test "inhibitAnyPolicy on a non-CA target rejects" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .ca = false,
        .inhibit_any = .{ .skip_certs = 0 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .inhibit_any_policy_invalid, 0);
}

test "self-issued certificates do not consume counters and may assert anyPolicy" {
    // A self-issued intermediate below an inhibitAnyPolicy=0 CA still
    // processes anyPolicy (RFC 5280 §6.1.3 (d)(2)(b)); an otherwise
    // identical non-self-issued intermediate does not.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "A", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "A", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} },
        .inhibit_any = .{ .skip_certs = 0 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});

    var fx_bad = Fixtures.init(testing.allocator);
    defer fx_bad.deinit();
    try fx_bad.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx_bad.add(.{ .subject = "B", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx_bad.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} },
        .inhibit_any = .{ .skip_certs = 0 },
    });
    try fx_bad.add(.{ .subject = "Root", .issuer = "Root" });

    var bad = runPolicy(&fx_bad, explicit_config);
    try expectPolicyRejected(&bad, .certificate_policy_required, 1);
}

test "self-issued certificates do not decrement requireExplicitPolicy" {
    // requireExplicitPolicy=1 on A skips exactly one non-self-issued
    // certificate.  With a self-issued certificate in between, the counter
    // still reaches zero exactly at the target, which carries a policy, so
    // the path accepts; without the leaf policy it rejects.
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "A", .ca = false });
    try fx.add(.{ .subject = "A", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} },
        .constraints = .{ .require_explicit_policy = 1 },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var result = runPolicy(&fx, .{});
    try expectPolicyRejected(&result, .certificate_policy_required, 0);
}

test "malformed policy extension encodings fail at parse time" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();

    // Negative SkipCerts.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.inhibit_any_policy,
            .critical = true,
            .value = &.{ 0x02, 0x01, 0xff },
        }},
    }));
    // Non-minimal SkipCerts encoding.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.inhibit_any_policy,
            .critical = true,
            .value = &.{ 0x02, 0x02, 0x00, 0x05 },
        }},
    }));
    // SkipCerts larger than u32.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.inhibit_any_policy,
            .critical = true,
            .value = &.{ 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 },
        }},
    }));
    // Empty policyConstraints SEQUENCE.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.policy_constraints,
            .critical = true,
            .value = &.{ 0x30, 0x00 },
        }},
    }));
    // Duplicate requireExplicitPolicy fields.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.policy_constraints,
            .critical = true,
            .value = &.{ 0x30, 0x06, 0x80, 0x01, 0x00, 0x80, 0x01, 0x01 },
        }},
    }));
    // Fields out of ascending tag order.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.policy_constraints,
            .critical = true,
            .value = &.{ 0x30, 0x06, 0x81, 0x01, 0x00, 0x80, 0x01, 0x00 },
        }},
    }));
    // Empty certificatePolicies SEQUENCE.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.certificate_policies,
            .critical = false,
            .value = &.{ 0x30, 0x00 },
        }},
    }));
    // Empty policyQualifiers SEQUENCE: 06 03 55 1d 20 is a stand-in OID.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.certificate_policies,
            .critical = false,
            .value = &.{ 0x30, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x30, 0x00 },
        }},
    }));
    // Empty policyMappings SEQUENCE.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.policy_mappings,
            .critical = false,
            .value = &.{ 0x30, 0x00 },
        }},
    }));
    // A mapping pair with trailing garbage is not fully consumed.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .raw_extensions = &.{.{
            .components = &wk.policy_mappings,
            .critical = false,
            .value = &.{
                0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d,
                0x21, 0x06, 0x03, 0x55, 0x1d, 0x22, 0x05, 0x00,
            },
        }},
    }));
    // CPS qualifier with a non-IA5String value.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "A",
        .issuer = "Root",
        .policies = null,
        .raw_extensions = &.{.{
            .components = &wk.certificate_policies,
            .critical = false,
            // PolicyInformation { OID 2.5.29.32.1, qualifiers { { id-qt-cps, UTF8String "x" } } }
            .value = &.{
                0x30, 0x18, 0x30, 0x16, 0x06, 0x04, 0x55, 0x1d,
                0x20, 0x01, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
                0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
                0x0c, 0x00,
            },
        }},
    }));
}

// ---------------------------------------------------------------------------
// Graph safety
// ---------------------------------------------------------------------------

test "pruning removes ancestors that no longer reach the frontier" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "B", .ca = false, .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "B", .issuer = "A", .policies = .{ .policies = &.{.{ .components = &test_oid_1 }} } });
    try fx.add(.{ .subject = "A", .issuer = "Root", .policies = .{ .policies = &.{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
    } } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    // OID2's depth-1 node dies when B contributes no child for it; only
    // OID1 remains authority-constrained.
    var result = runPolicy(&fx, explicit_config);
    try expectPolicySets(&result, &.{&test_oid_1}, &.{&test_oid_1});
}

test "node, edge, and operation budgets reject structurally" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{
        .{ .components = &test_oid_1 },
        .{ .components = &test_oid_2 },
        .{ .components = &test_oid_3 },
    } } });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .policies = .{ .policies = &.{.{ .components = &wk.any_policy }} } });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var node_config = cert_policies.Config{};
    node_config.limits.maximum_nodes_per_depth = 2;
    var node_result = runPolicy(&fx, node_config);
    try expectPolicyRejected(&node_result, .resource_limit_exceeded, 0);

    var total_config = cert_policies.Config{};
    total_config.limits.maximum_total_nodes = 3;
    var total_result = runPolicy(&fx, total_config);
    try expectPolicyRejected(&total_result, .resource_limit_exceeded, 0);

    var ops_config = cert_policies.Config{};
    ops_config.limits.maximum_operations = 4;
    var ops_result = runPolicy(&fx, ops_config);
    switch (ops_result) {
        .rejected => |rejected| try testing.expectEqual(cert_policies.FailureReason.resource_limit_exceeded, rejected.reason),
        .accepted => |*accepted| {
            accepted.deinit(testing.allocator);
            return error.TestUnexpectedResult;
        },
    }

    var edge_config = cert_policies.Config{};
    edge_config.limits.maximum_total_edges = 2;
    var edge_result = runPolicy(&fx, edge_config);
    try expectPolicyRejected(&edge_result, .resource_limit_exceeded, 0);
}

test "paths beyond the configured maximum length reject" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root" });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    var config = cert_policies.Config{};
    config.limits.maximum_path_length = 2;
    var result = runPolicy(&fx, config);
    try expectPolicyRejected(&result, .resource_limit_exceeded, null);
}

test "policy processing survives allocation failure without leaks" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate", .ca = false, .policies = .{ .policies = &.{
        .{ .components = &test_oid_2 },
        .{ .components = &test_oid_3 },
    } } });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .policies = .{ .policies = &.{
            .{ .components = &test_oid_1 },
            .{ .components = &wk.any_policy },
        } },
        .mappings = &.{
            .{ .issuer = &test_oid_1, .subject = &test_oid_2 },
            .{ .issuer = &test_oid_4, .subject = &test_oid_3 },
        },
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root" });

    const Context = struct {
        fn run(allocator: std.mem.Allocator, context: *const Fixtures) !void {
            var buffer: [8]path_builder.Element = undefined;
            const path_elements = context.elements(&buffer);
            var result = cert_policies.validatePath(allocator, .{ .elements = path_elements }, .{
                .user_initial_policy_set = .{ .explicit = &.{ oidOf(&test_oid_1), oidOf(&test_oid_4) } },
                .initial_explicit_policy = true,
            });
            switch (result) {
                .accepted => |*accepted| accepted.deinit(allocator),
                .rejected => |rejected| {
                    if (rejected.reason == .out_of_memory) return error.OutOfMemory;
                },
            }
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Context.run, .{&fx});
}

test {
    testing.refAllDecls(@This());
}
