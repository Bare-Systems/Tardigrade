//! Opt-in OpenSSL differential checks for fixed Name Constraints fixtures.
//!
//! The checked-in certificates are the immutable input.  OpenSSL is invoked
//! out of process and never linked into the PKI package or normal unit tests.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const pki = @import("pki");

const testing = std.testing;
const fixture_dir = "src/pki/testdata/name_constraints";
const validation_time: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z

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
        .argv = &.{ openssl, "verify", "-attime", "1784332800", "-CAfile", root_path, "-untrusted", intermediate_path, leaf_path },
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
