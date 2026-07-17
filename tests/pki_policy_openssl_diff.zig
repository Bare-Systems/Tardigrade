//! Opt-in OpenSSL differential checks for the fixed certificate-policy
//! fixtures (#345).
//!
//! The checked-in certificates are the immutable input.  OpenSSL is invoked
//! out of process and never linked into the PKI package or normal unit
//! tests.  Flags map one-to-one onto RFC 5280 §6.1.1 initial inputs:
//! `-policy` → user-initial-policy-set, `-explicit_policy` →
//! initial-explicit-policy, `-inhibit_any` → initial-any-policy-inhibit,
//! `-inhibit_map` → initial-policy-mapping-inhibit.
//!
//! Intentional difference: Tardigrade always processes policy extensions,
//! while OpenSSL skips them (including requireExplicitPolicy) unless
//! `-policy_check` or a `-policy` argument enables processing.  The harness
//! always enables OpenSSL policy checking, so decisions are comparable.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const pki = @import("pki");

const testing = std.testing;
const fixture_dir = "src/pki/testdata/certificate_policies";
const validation_time: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z

const test_policy_1 = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 1 };
const test_policy_1_text = "1.3.6.1.4.1.99999.1";

const Case = struct {
    name: []const u8,
    leaf_file: []const u8,
    intermediate_files: []const []const u8,
    /// Request test_policy_1 as the user-initial-policy-set.
    request_policy_1: bool = true,
    explicit_policy: bool = true,
    inhibit_any: bool = false,
    inhibit_map: bool = false,
    accepted: bool,
};

const cases = [_]Case{
    .{
        .name = "direct explicit-policy success",
        .leaf_file = "leaf-policy1.crt",
        .intermediate_files = &.{"policy-intermediate.crt"},
        .accepted = true,
    },
    .{
        .name = "missing required policy",
        .leaf_file = "leaf-policy2.crt",
        .intermediate_files = &.{"policy-intermediate.crt"},
        .accepted = false,
    },
    .{
        .name = "anyPolicy propagation success",
        .leaf_file = "any-leaf.crt",
        .intermediate_files = &.{"any-intermediate.crt"},
        .accepted = true,
    },
    .{
        .name = "anyPolicy inhibited by initial input",
        .leaf_file = "any-leaf.crt",
        .intermediate_files = &.{"any-intermediate.crt"},
        .inhibit_any = true,
        .accepted = false,
    },
    .{
        .name = "anyPolicy inhibited by extension",
        .leaf_file = "inhibit-leaf.crt",
        .intermediate_files = &.{ "inhibit-ca2.crt", "inhibit-ca1.crt" },
        .accepted = false,
    },
    .{
        .name = "simple policy mapping",
        .leaf_file = "mapping-leaf.crt",
        .intermediate_files = &.{"mapping-intermediate.crt"},
        .accepted = true,
    },
    .{
        .name = "mapping inhibited by initial input",
        .leaf_file = "mapping-leaf.crt",
        .intermediate_files = &.{"mapping-intermediate.crt"},
        .inhibit_map = true,
        .accepted = false,
    },
    .{
        .name = "mapping inhibited by policyConstraints",
        .leaf_file = "mapinhibit-leaf.crt",
        .intermediate_files = &.{ "mapinhibit-ca2.crt", "mapinhibit-ca1.crt" },
        .accepted = false,
    },
    .{
        .name = "requireExplicitPolicy without leaf policy",
        .leaf_file = "rep-leaf.crt",
        .intermediate_files = &.{"rep-intermediate.crt"},
        .request_policy_1 = false,
        .explicit_policy = false,
        .accepted = false,
    },
};

fn fixturePath(allocator: std.mem.Allocator, file: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture_dir, file });
}

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
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const openssl = compat.getEnvVarOwned(arena, "OPENSSL_BIN") catch try arena.dupe(u8, "openssl");

    // OpenSSL accepts one -untrusted file with every intermediate.
    const untrusted_path = try std.fmt.allocPrint(arena, "{s}/policy-diff-untrusted-{s}.pem", .{
        compat.getEnvVarOwned(arena, "TMPDIR") catch try arena.dupe(u8, "/tmp"),
        case.leaf_file,
    });
    {
        var untrusted: std.ArrayList(u8) = .empty;
        for (case.intermediate_files) |file| {
            const path = try fixturePath(arena, file);
            const bytes = try std.Io.Dir.cwd().readFileAlloc(compat.io(), path, arena, .limited(1024 * 1024));
            try untrusted.appendSlice(arena, bytes);
        }
        try std.Io.Dir.cwd().writeFile(compat.io(), .{ .sub_path = untrusted_path, .data = untrusted.items });
    }

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ openssl, "verify", "-attime", "1784332800" });
    try argv.appendSlice(arena, &.{ "-policy_check", "-policy_print" });
    if (case.request_policy_1) try argv.appendSlice(arena, &.{ "-policy", test_policy_1_text });
    if (case.explicit_policy) try argv.append(arena, "-explicit_policy");
    if (case.inhibit_any) try argv.append(arena, "-inhibit_any");
    if (case.inhibit_map) try argv.append(arena, "-inhibit_map");
    const root_path = try fixturePath(arena, "root.crt");
    try argv.appendSlice(arena, &.{ "-CAfile", root_path, "-untrusted", untrusted_path });
    try argv.append(arena, try fixturePath(arena, case.leaf_file));

    const result = try std.process.run(arena, compat.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn tardigradeDecision(allocator: std.mem.Allocator, case: Case) !bool {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var loaded: std.ArrayList(pki.x509.Certificate) = .empty;
    var elements: std.ArrayList(pki.path_builder.Element) = .empty;

    const leaf_path = try fixturePath(arena, case.leaf_file);
    const leaf = try loadCertificate(arena, leaf_path);
    try loaded.append(arena, leaf.certificate);
    for (case.intermediate_files, 0..) |file, index| {
        const loaded_intermediate = try loadCertificate(arena, try fixturePath(arena, file));
        try loaded.append(arena, loaded_intermediate.certificate);
        _ = index;
    }
    const root = try loadCertificate(arena, try fixturePath(arena, "root.crt"));
    try loaded.append(arena, root.certificate);

    const count = loaded.items.len;
    for (loaded.items, 0..) |*certificate, index| {
        try elements.append(arena, .{
            .certificate = certificate,
            .source = if (index == 0) .leaf else if (index == count - 1) .anchor else .intermediate,
            .input_index = if (index == 0) 0 else if (index == count - 1) 0 else index - 1,
        });
    }

    const user_policies = [_]pki.oid.ObjectIdentifier{
        pki.oid.ObjectIdentifier.fromComponents(&test_policy_1) catch unreachable,
    };
    const policy_config = pki.certificate_policies.Config{
        .user_initial_policy_set = if (case.request_policy_1)
            .{ .explicit = &user_policies }
        else
            .any_policy,
        .initial_explicit_policy = case.explicit_policy,
        .initial_any_policy_inhibit = case.inhibit_any,
        .initial_policy_mapping_inhibit = case.inhibit_map,
    };

    var entropy = crypto.pure_zig.DeterministicEntropy.init(0x345);
    var provider = crypto.pure_zig.Provider.init(entropy.entropy());
    var result = pki.path_validator.validatePath(allocator, .{ .elements = elements.items }, .{
        .validation_time = validation_time,
        .trust_anchors = loaded.items[count - 1 .. count],
        .certificate_policies = policy_config,
    }, provider.cryptoProvider());
    defer result.deinit(allocator);
    return result == .accepted;
}

test "Tardigrade certificate-policy decisions match OpenSSL fixtures" {
    for (cases) |case| {
        const expected = case.accepted;
        const openssl = try opensslDecision(testing.allocator, case);
        const tardigrade = try tardigradeDecision(testing.allocator, case);
        errdefer std.debug.print(
            "certificate-policy differential mismatch: case=\"{s}\" expected={} openssl={} tardigrade={}\n",
            .{ case.name, expected, openssl, tardigrade },
        );
        try testing.expectEqual(expected, openssl);
        try testing.expectEqual(expected, tardigrade);
    }
}
