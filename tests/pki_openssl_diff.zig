//! Opt-in OpenSSL differential checks for fixed RFC 5280 fixtures.
//!
//! The checked-in certificates are the immutable input.  OpenSSL is invoked
//! out of process and never linked into the PKI package or normal unit tests.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const pki = @import("pki");

const testing = std.testing;
const fixture_dir = "src/pki/testdata/name_constraints";
const policy_fixture_dir = "src/pki/testdata/policy";
const validation_time: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z
const validation_time_argument = std.fmt.comptimePrint("{d}", .{validation_time});
const policy_a = [_]u32{ 1, 3, 6, 1, 4, 1, 55555, 1 };

const Case = struct {
    leaf_file: []const u8,
    intermediate_file: []const u8,
    accepted: bool,
};

const cases = [_]Case{
    .{ .leaf_file = "dns-good.crt", .intermediate_file = "intermediate.crt", .accepted = true },
    .{ .leaf_file = "dns-excluded.crt", .intermediate_file = "intermediate.crt", .accepted = false },
    .{ .leaf_file = "ip-good.crt", .intermediate_file = "intermediate.crt", .accepted = true },
    .{ .leaf_file = "ip-bad.crt", .intermediate_file = "intermediate.crt", .accepted = false },
    .{ .leaf_file = "directory-bad.crt", .intermediate_file = "intermediate.crt", .accepted = false },
    .{ .leaf_file = "leading-dot-subdomain.crt", .intermediate_file = "leading-dot-intermediate.crt", .accepted = true },
    .{ .leaf_file = "leading-dot-exact.crt", .intermediate_file = "leading-dot-intermediate.crt", .accepted = false },
};

fn loadCertificate(allocator: std.mem.Allocator, path: []const u8) !struct {
    pem_certificate: pki.pem.Certificate,
    certificate: pki.x509.Certificate,
} {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(compat.io(), path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    var pem_certificate = try pki.pem.loadCertificatePem(allocator, bytes, .{});
    errdefer pem_certificate.deinit(allocator);
    const certificate = try pki.x509.Certificate.parse(allocator, pem_certificate.der, .{});
    return .{ .pem_certificate = pem_certificate, .certificate = certificate };
}

fn opensslDecision(allocator: std.mem.Allocator, case: Case) !bool {
    const root_path = try std.fmt.allocPrint(allocator, "{s}/root.crt", .{fixture_dir});
    defer allocator.free(root_path);
    const intermediate_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture_dir, case.intermediate_file });
    defer allocator.free(intermediate_path);
    const leaf_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture_dir, case.leaf_file });
    defer allocator.free(leaf_path);

    const openssl = compat.getEnvVarOwned(allocator, "OPENSSL_BIN") catch try allocator.dupe(u8, "openssl");
    defer allocator.free(openssl);
    const result = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ openssl, "verify", "-attime", validation_time_argument, "-trusted", root_path, "-untrusted", intermediate_path, leaf_path },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn tardigradeDecision(allocator: std.mem.Allocator, case: Case) !bool {
    const root_path = try std.fmt.allocPrint(allocator, "{s}/root.crt", .{fixture_dir});
    defer allocator.free(root_path);
    const intermediate_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture_dir, case.intermediate_file });
    defer allocator.free(intermediate_path);
    const leaf_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture_dir, case.leaf_file });
    defer allocator.free(leaf_path);

    var root = try loadCertificate(allocator, root_path);
    defer root.certificate.deinit(allocator);
    defer root.pem_certificate.deinit(allocator);
    var intermediate = try loadCertificate(allocator, intermediate_path);
    defer intermediate.certificate.deinit(allocator);
    defer intermediate.pem_certificate.deinit(allocator);
    var leaf = try loadCertificate(allocator, leaf_path);
    defer leaf.certificate.deinit(allocator);
    defer leaf.pem_certificate.deinit(allocator);

    const elements = [_]pki.path_builder.Element{
        .{ .certificate = &leaf.certificate, .source = .leaf, .input_index = 0 },
        .{ .certificate = &intermediate.certificate, .source = .intermediate, .input_index = 0 },
        .{ .certificate = &root.certificate, .source = .anchor, .input_index = 0 },
    };
    var entropy = crypto.pure_zig.DeterministicEntropy.init(0x345);
    var provider = crypto.pure_zig.Provider.init(entropy.entropy());
    var result = pki.path_validator.validatePath(allocator, .{ .elements = &elements }, .{
        .validation_time = validation_time,
        .trust_anchors = (&root.certificate)[0..1],
    }, provider.cryptoProvider());
    defer result.deinit(allocator);
    return result == .accepted;
}

test "Tardigrade Name Constraints decisions match OpenSSL fixtures" {
    for (cases) |case| {
        const expected = case.accepted;
        const openssl = try opensslDecision(testing.allocator, case);
        const tardigrade = try tardigradeDecision(testing.allocator, case);
        errdefer std.debug.print(
            "Name Constraints differential mismatch: leaf={s} expected={} openssl={} tardigrade={}\n",
            .{ case.leaf_file, expected, openssl, tardigrade },
        );
        try testing.expectEqual(expected, openssl);
        try testing.expectEqual(expected, tardigrade);
    }
}

const PolicyCase = struct {
    leaf_file: []const u8,
    intermediate_file: []const u8,
    upper_file: ?[]const u8 = null,
    untrusted_file: ?[]const u8 = null,
    accepted: bool,
    explicit_policy: bool = true,
    inhibit_any: bool = false,
    inhibit_mapping: bool = false,
};

const policy_cases = [_]PolicyCase{
    .{ .leaf_file = "direct-leaf.crt", .intermediate_file = "direct-intermediate.crt", .accepted = true },
    .{ .leaf_file = "missing-leaf.crt", .intermediate_file = "direct-intermediate.crt", .accepted = false },
    .{ .leaf_file = "any-leaf.crt", .intermediate_file = "direct-intermediate.crt", .accepted = true },
    .{ .leaf_file = "any-leaf.crt", .intermediate_file = "direct-intermediate.crt", .accepted = false, .inhibit_any = true },
    .{ .leaf_file = "mapped-leaf.crt", .intermediate_file = "mapping-intermediate.crt", .accepted = true },
    .{ .leaf_file = "mapped-leaf.crt", .intermediate_file = "mapping-intermediate.crt", .accepted = false, .inhibit_mapping = true },
    .{ .leaf_file = "explicit-missing-leaf.crt", .intermediate_file = "explicit-intermediate.crt", .accepted = false, .explicit_policy = false },
    .{
        .leaf_file = "constrained-mapped-leaf.crt",
        .intermediate_file = "mapping-constraint-lower.crt",
        .upper_file = "mapping-constraint-upper.crt",
        .untrusted_file = "mapping-constraint-chain.crt",
        .accepted = false,
    },
    .{ .leaf_file = "extension-inhibited-any-leaf.crt", .intermediate_file = "inhibit-any-intermediate.crt", .accepted = false },
};

fn policyPaths(allocator: std.mem.Allocator, case: PolicyCase) !struct {
    root: []u8,
    intermediate: []u8,
    untrusted: []u8,
    leaf: []u8,
} {
    const root = try std.fmt.allocPrint(allocator, "{s}/root.crt", .{policy_fixture_dir});
    errdefer allocator.free(root);
    const intermediate = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ policy_fixture_dir, case.intermediate_file });
    errdefer allocator.free(intermediate);
    const untrusted = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ policy_fixture_dir, case.untrusted_file orelse case.intermediate_file });
    errdefer allocator.free(untrusted);
    const leaf = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ policy_fixture_dir, case.leaf_file });
    return .{
        .root = root,
        .intermediate = intermediate,
        .untrusted = untrusted,
        .leaf = leaf,
    };
}

fn opensslPolicyDecision(allocator: std.mem.Allocator, case: PolicyCase) !bool {
    const paths = try policyPaths(allocator, case);
    defer allocator.free(paths.root);
    defer allocator.free(paths.intermediate);
    defer allocator.free(paths.untrusted);
    defer allocator.free(paths.leaf);
    const openssl = compat.getEnvVarOwned(allocator, "OPENSSL_BIN") catch try allocator.dupe(u8, "openssl");
    defer allocator.free(openssl);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ openssl, "verify", "-attime", validation_time_argument, "-trusted", paths.root, "-untrusted", paths.untrusted, "-policy", "1.3.6.1.4.1.55555.1", "-policy_check" });
    if (case.explicit_policy) try argv.append(allocator, "-explicit_policy");
    if (case.inhibit_any) try argv.append(allocator, "-inhibit_any");
    if (case.inhibit_mapping) try argv.append(allocator, "-inhibit_map");
    try argv.append(allocator, paths.leaf);
    const result = try std.process.run(allocator, compat.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn tardigradePolicyDecision(allocator: std.mem.Allocator, case: PolicyCase) !bool {
    const paths = try policyPaths(allocator, case);
    defer allocator.free(paths.root);
    defer allocator.free(paths.intermediate);
    defer allocator.free(paths.untrusted);
    defer allocator.free(paths.leaf);
    var root = try loadCertificate(allocator, paths.root);
    defer root.certificate.deinit(allocator);
    defer root.pem_certificate.deinit(allocator);
    var intermediate = try loadCertificate(allocator, paths.intermediate);
    defer intermediate.certificate.deinit(allocator);
    defer intermediate.pem_certificate.deinit(allocator);
    var leaf = try loadCertificate(allocator, paths.leaf);
    defer leaf.certificate.deinit(allocator);
    defer leaf.pem_certificate.deinit(allocator);
    var upper: ?@TypeOf(root) = null;
    if (case.upper_file) |file| {
        const upper_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ policy_fixture_dir, file });
        defer allocator.free(upper_path);
        upper = try loadCertificate(allocator, upper_path);
    }
    defer if (upper) |*loaded| {
        loaded.certificate.deinit(allocator);
        loaded.pem_certificate.deinit(allocator);
    };
    var elements: std.ArrayList(pki.path_builder.Element) = .empty;
    defer elements.deinit(allocator);
    try elements.append(allocator, .{ .certificate = &leaf.certificate, .source = .leaf, .input_index = 0 });
    try elements.append(allocator, .{ .certificate = &intermediate.certificate, .source = .intermediate, .input_index = 0 });
    if (upper) |*loaded| try elements.append(allocator, .{ .certificate = &loaded.certificate, .source = .intermediate, .input_index = 1 });
    try elements.append(allocator, .{ .certificate = &root.certificate, .source = .anchor, .input_index = 0 });
    const requested = [_]pki.oid.ObjectIdentifier{try pki.oid.ObjectIdentifier.fromComponents(&policy_a)};
    var policy: pki.path_validator.ValidationPolicy = .{
        .validation_time = validation_time,
        .trust_anchors = (&root.certificate)[0..1],
    };
    policy.certificate_policy.user_initial_policy_set = .{ .explicit = &requested };
    policy.certificate_policy.initial_explicit_policy = case.explicit_policy;
    policy.certificate_policy.initial_any_policy_inhibit = case.inhibit_any;
    policy.certificate_policy.initial_policy_mapping_inhibit = case.inhibit_mapping;
    var entropy = crypto.pure_zig.DeterministicEntropy.init(0x345);
    var provider = crypto.pure_zig.Provider.init(entropy.entropy());
    var result = pki.path_validator.validatePath(allocator, .{ .elements = elements.items }, policy, provider.cryptoProvider());
    defer result.deinit(allocator);
    return result == .accepted;
}

test "Tardigrade certificate policy decisions match OpenSSL fixtures" {
    for (policy_cases) |case| {
        const openssl = try opensslPolicyDecision(testing.allocator, case);
        const tardigrade = try tardigradePolicyDecision(testing.allocator, case);
        errdefer std.debug.print(
            "policy differential mismatch: leaf={s} explicit={} inhibit_any={} inhibit_map={} expected={} openssl={} tardigrade={}\n",
            .{ case.leaf_file, case.explicit_policy, case.inhibit_any, case.inhibit_mapping, case.accepted, openssl, tardigrade },
        );
        try testing.expectEqual(case.accepted, openssl);
        try testing.expectEqual(case.accepted, tardigrade);
    }
}
