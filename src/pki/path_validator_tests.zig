//! Deterministic, offline certification-path validation fixtures (#345).

const std = @import("std");
const crypto = @import("crypto");
const der = @import("der.zig");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const pem = @import("pem.zig");
const validator = @import("path_validator.zig");
const x509 = @import("x509.zig");

const testing = std.testing;
const validation_time: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z
const openssl_root_pem = @embedFile("testdata/path_validator_ed25519_root.crt");
const openssl_leaf_pem = @embedFile("testdata/path_validator_ed25519_leaf.crt");

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

fn sanValue(arena: std.mem.Allocator, dns_name: []const u8) ![]u8 {
    return tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{dns_name})});
}

fn nameConstraintsValue(arena: std.mem.Allocator) ![]u8 {
    const subtree = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{".example.com"})});
    return tlv(arena, 0x30, &.{try tlv(arena, 0xa0, &.{subtree})});
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
    san: ?[]const u8 = null,
    name_constraints: bool = false,
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
                false,
                try sanValue(arena, dns_name),
            ));
        }
        if (spec.name_constraints) {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.name_constraints,
                false,
                try nameConstraintsValue(arena),
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
        try tbs_parts.append(arena, try nameWithCn(arena, spec.subject));
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

    try fx.add(.{ .subject = "KU Issuer", .issuer = "KU Issuer", .subject_key = 4, .issuer_key = 4, .ca = true, .key_usage = 0x80 });
    try fx.add(.{ .subject = "leaf2", .issuer = "KU Issuer", .subject_key = 5, .issuer_key = 4, .ca = false, .key_usage = 0x80 });
    var bad_ku = try validateBuilt(testing.allocator, &fx.certs.items[4], &.{}, fx.certs.items[3..4], policy(fx.certs.items[3..4]), cp);
    defer bad_ku.deinit(testing.allocator);
    try expectRejected(&bad_ku, .key_usage_violation, 1);

    // Missing Basic Constraints never grants issuing authority.
    try fx.add(.{ .subject = "No BC", .issuer = "No BC", .subject_key = 6, .issuer_key = 6 });
    try fx.add(.{ .subject = "leaf3", .issuer = "No BC", .subject_key = 7, .issuer_key = 6, .ca = false, .key_usage = 0x80 });
    var missing_bc = try validateBuilt(testing.allocator, &fx.certs.items[6], &.{}, fx.certs.items[5..6], policy(fx.certs.items[5..6]), cp);
    defer missing_bc.deinit(testing.allocator);
    try expectRejected(&missing_bc, .issuer_is_not_ca, 1);

    // Absent issuer KU is unrestricted; only a present KU must assert
    // keyCertSign.
    try fx.add(.{ .subject = "No KU", .issuer = "No KU", .subject_key = 8, .issuer_key = 8, .ca = true });
    try fx.add(.{ .subject = "leaf4", .issuer = "No KU", .subject_key = 9, .issuer_key = 8, .ca = false, .key_usage = 0x80 });
    var absent_ku = try validateBuilt(testing.allocator, &fx.certs.items[8], &.{}, fx.certs.items[7..8], policy(fx.certs.items[7..8]), cp);
    defer absent_ku.deinit(testing.allocator);
    try expectAccepted(&absent_ku, 2);
}

test "pathLenConstraint handles zero, exact limits, and self-issued CAs" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try addValidChain(&fx, 0);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var over = try validateBuilt(testing.allocator, &fx.certs.items[0], fx.certs.items[1..2], fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer over.deinit(testing.allocator);
    try expectRejected(&over, .path_length_exceeded, 2);

    // Direct leaf -> pathLen=0 anchor has no subordinate CA and passes.
    try fx.add(.{ .subject = "direct", .issuer = "Root", .subject_key = 4, .issuer_key = 3, .ca = false, .key_usage = 0x80 });
    var zero = try validateBuilt(testing.allocator, &fx.certs.items[3], &.{}, fx.certs.items[2..3], policy(fx.certs.items[2..3]), cp);
    defer zero.deinit(testing.allocator);
    try expectAccepted(&zero, 2);

    // A self-issued rollover CA does not consume the anchor's pathLen budget.
    try fx.add(.{ .subject = "Self CA", .issuer = "Self CA", .subject_key = 5, .issuer_key = 6, .ca = true, .path_len = 0, .key_usage = 0x04 });
    try fx.add(.{ .subject = "Self CA", .issuer = "Self CA", .subject_key = 6, .issuer_key = 6, .ca = true, .path_len = 0, .key_usage = 0x04 });
    try fx.add(.{ .subject = "self leaf", .issuer = "Self CA", .subject_key = 7, .issuer_key = 5, .ca = false, .key_usage = 0x80 });
    const self_elements = [_]path_builder.Element{
        .{ .certificate = &fx.certs.items[6], .source = .leaf, .input_index = 0 },
        .{ .certificate = &fx.certs.items[4], .source = .intermediate, .input_index = 0 },
        .{ .certificate = &fx.certs.items[5], .source = .anchor, .input_index = 0 },
    };
    var self_issued = validator.validatePath(testing.allocator, .{ .elements = &self_elements }, policy(fx.certs.items[5..6]), cp);
    defer self_issued.deinit(testing.allocator);
    try expectAccepted(&self_issued, 3);
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

test "deferred Name Constraints fail closed even when noncritical" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "Root", .issuer = "Root", .subject_key = 3, .issuer_key = 3, .ca = true, .key_usage = 0x04, .name_constraints = true });
    try fx.add(.{ .subject = "leaf", .issuer = "Root", .subject_key = 1, .issuer_key = 3, .ca = false, .key_usage = 0x80 });

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    const cp = cryptoProvider(&entropy, &provider);
    var result = try validateBuilt(testing.allocator, &fx.certs.items[1], &.{}, fx.certs.items[0..1], policy(fx.certs.items[0..1]), cp);
    defer result.deinit(testing.allocator);
    try expectRejected(&result, .name_constraints_unsupported, 1);
    try testing.expect(result.rejected.extension_oid.?.eqlComponents(&oid.well_known.name_constraints));
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
