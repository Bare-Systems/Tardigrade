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
    unknown_critical: bool = false,
    unknown_noncritical: bool = false,
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
    unsupported.signature_algorithm.oid = try oid.ObjectIdentifier.fromComponents(&oid.well_known.sha256_with_rsa);
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
