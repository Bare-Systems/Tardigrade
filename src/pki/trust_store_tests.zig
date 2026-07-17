//! Trust-store ownership, reload, and bundle-loading tests (#346).

const std = @import("std");
const crypto = @import("crypto");
const path_builder = @import("path_builder.zig");
const path_validator = @import("path_validator.zig");
const pem = @import("pem.zig");
const trust_store = @import("trust_store.zig");
const x509 = @import("x509.zig");

const testing = std.testing;
const name_constraints_root_pem = @embedFile("testdata/name_constraints/root.crt");
const name_constraints_intermediate_pem = @embedFile("testdata/name_constraints/intermediate.crt");
const name_constraints_leaf_pem = @embedFile("testdata/name_constraints/dns-good.crt");
const openssl_root_pem = @embedFile("testdata/path_validator_ed25519_root.crt");
const openssl_leaf_pem = @embedFile("testdata/path_validator_ed25519_leaf.crt");
const validation_time_name_constraints: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z

const LoadedCertificate = struct {
    pem_certificate: pem.Certificate,
    certificate: x509.Certificate,

    fn deinit(self: *LoadedCertificate, allocator: std.mem.Allocator) void {
        self.certificate.deinit(allocator);
        self.pem_certificate.deinit(allocator);
        self.* = undefined;
    }
};

fn loadFixture(allocator: std.mem.Allocator, pem_text: []const u8) !LoadedCertificate {
    var pem_certificate = try pem.loadCertificatePem(allocator, pem_text, .{});
    errdefer pem_certificate.deinit(allocator);
    const certificate = try x509.Certificate.parse(allocator, pem_certificate.der, .{});
    return .{ .pem_certificate = pem_certificate, .certificate = certificate };
}

fn cryptoProvider(
    entropy: *crypto.pure_zig.DeterministicEntropy,
    provider: *crypto.pure_zig.Provider,
) crypto.provider.CryptoProvider {
    entropy.* = crypto.pure_zig.DeterministicEntropy.init(0x346);
    provider.* = crypto.pure_zig.Provider.init(entropy.entropy());
    return provider.cryptoProvider();
}

fn expectAccepted(
    allocator: std.mem.Allocator,
    leaf: *const x509.Certificate,
    intermediates: []const x509.Certificate,
    anchors: []const x509.Certificate,
    validation_time: i64,
) !void {
    var candidates = try path_builder.build(allocator, leaf, intermediates, anchors, .{});
    defer candidates.deinit(allocator);

    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    var result = path_validator.validateCandidates(
        allocator,
        candidates,
        .{
            .validation_time = validation_time,
            .trust_anchors = anchors,
        },
        cryptoProvider(&entropy, &provider),
    );
    defer result.deinit(allocator);
    try testing.expect(result == .accepted);
}

fn expectDirectAnchorAccepted(
    allocator: std.mem.Allocator,
    leaf: *const x509.Certificate,
    anchors: []const x509.Certificate,
    validation_time: i64,
    expected_dns_name: []const u8,
) !void {
    const elements = [_]path_builder.Element{
        .{ .certificate = leaf, .source = .leaf, .input_index = 0 },
        .{ .certificate = &anchors[0], .source = .anchor, .input_index = 0 },
    };
    var entropy: crypto.pure_zig.DeterministicEntropy = undefined;
    var provider: crypto.pure_zig.Provider = undefined;
    var result = path_validator.validatePath(
        allocator,
        .{ .elements = &elements },
        .{
            .validation_time = validation_time,
            .expected_dns_name = expected_dns_name,
            .trust_anchors = anchors,
        },
        cryptoProvider(&entropy, &provider),
    );
    defer result.deinit(allocator);
    try testing.expect(result == .accepted);
}

fn minimalCertDer(n: u8) [5]u8 {
    return .{ 0x30, 0x03, 0x02, 0x01, n };
}

fn concatPemBundle(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.mem.concat(allocator, u8, parts);
}

test "snapshot loads mixed PEM and DER bundles with exact-DER dedup" {
    var primary_root = try loadFixture(testing.allocator, name_constraints_root_pem);
    defer primary_root.deinit(testing.allocator);
    var alternate_root = try loadFixture(testing.allocator, openssl_root_pem);
    defer alternate_root.deinit(testing.allocator);

    const inputs = [_]trust_store.BufferInput{
        .{ .pem = name_constraints_root_pem },
        .{ .der = alternate_root.pem_certificate.der },
        .{ .pem = name_constraints_root_pem },
    };
    var snapshot = try trust_store.Snapshot.loadBuffers(testing.allocator, &inputs, .{});
    defer snapshot.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), snapshot.anchors().len);
    try testing.expectEqualSlices(u8, primary_root.pem_certificate.der, snapshot.anchors()[0].raw);
    try testing.expectEqualSlices(u8, alternate_root.pem_certificate.der, snapshot.anchors()[1].raw);
}

test "snapshot rejects malformed, non-CA, and empty anchor sets typed" {
    const malformed = minimalCertDer(1);
    const malformed_inputs = [_]trust_store.BufferInput{
        .{ .der = &malformed },
    };
    try testing.expectError(error.MalformedCertificate, trust_store.Snapshot.loadBuffers(
        testing.allocator,
        &malformed_inputs,
        .{},
    ));

    const non_ca_inputs = [_]trust_store.BufferInput{
        .{ .pem = openssl_leaf_pem },
    };
    try testing.expectError(error.NonCaAnchor, trust_store.Snapshot.loadBuffers(
        testing.allocator,
        &non_ca_inputs,
        .{},
    ));

    const empty_inputs = [_]trust_store.BufferInput{};
    try testing.expectError(error.NoTrustAnchors, trust_store.Snapshot.loadBuffers(
        testing.allocator,
        &empty_inputs,
        .{},
    ));
}

test "multi-certificate PEM bundle returns NonCaAnchor without leaking trailing entries" {
    const bundle = try concatPemBundle(testing.allocator, &.{
        name_constraints_root_pem,
        openssl_leaf_pem,
        openssl_root_pem,
    });
    defer testing.allocator.free(bundle);

    const inputs = [_]trust_store.BufferInput{
        .{ .pem = bundle },
    };
    try testing.expectError(error.NonCaAnchor, trust_store.Snapshot.loadBuffers(
        testing.allocator,
        &inputs,
        .{},
    ));
}

test "multi-certificate PEM bundle returns TooManyAnchors without leaking trailing entries" {
    const bundle = try concatPemBundle(testing.allocator, &.{
        name_constraints_root_pem,
        openssl_root_pem,
        name_constraints_root_pem,
    });
    defer testing.allocator.free(bundle);

    const inputs = [_]trust_store.BufferInput{
        .{ .pem = bundle },
    };
    try testing.expectError(error.TooManyAnchors, trust_store.Snapshot.loadBuffers(
        testing.allocator,
        &inputs,
        .{ .max_anchors = 1 },
    ));
}

test "file-backed bundle loader indexes PEM and DER trust anchors" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var alternate_root = try loadFixture(testing.allocator, openssl_root_pem);
    defer alternate_root.deinit(testing.allocator);

    try tmp.dir.writeFile(io, .{ .sub_path = "roots.pem", .data = name_constraints_root_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "alt-root.der", .data = alternate_root.pem_certificate.der });

    const inputs = [_]trust_store.FileInput{
        .{ .pem = "roots.pem" },
        .{ .der = "alt-root.der" },
    };
    var snapshot = try trust_store.Snapshot.loadFiles(testing.allocator, io, tmp.dir, &inputs, .{});
    defer snapshot.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), snapshot.anchors().len);
}

test "bundle store snapshots survive reload and validate the matching chains" {
    var nc_intermediate = try loadFixture(testing.allocator, name_constraints_intermediate_pem);
    defer nc_intermediate.deinit(testing.allocator);
    var nc_leaf = try loadFixture(testing.allocator, name_constraints_leaf_pem);
    defer nc_leaf.deinit(testing.allocator);
    var direct_leaf = try loadFixture(testing.allocator, openssl_leaf_pem);
    defer direct_leaf.deinit(testing.allocator);

    const initial_inputs = [_]trust_store.BufferInput{
        .{ .pem = name_constraints_root_pem },
    };
    var store = try trust_store.BundleStore.initBuffers(testing.allocator, &initial_inputs, .{});
    defer store.deinit(testing.allocator);

    const provider = store.provider();
    var first_snapshot = try provider.snapshot(testing.allocator);
    defer first_snapshot.deinit(testing.allocator);

    const name_constraints_intermediates = [_]x509.Certificate{nc_intermediate.certificate};
    try expectAccepted(
        testing.allocator,
        &nc_leaf.certificate,
        &name_constraints_intermediates,
        first_snapshot.anchors(),
        validation_time_name_constraints,
    );

    const reloaded_inputs = [_]trust_store.BufferInput{
        .{ .pem = openssl_root_pem },
    };
    try store.reloadBuffers(testing.allocator, &reloaded_inputs, .{});

    var second_snapshot = try provider.snapshot(testing.allocator);
    defer second_snapshot.deinit(testing.allocator);

    try expectAccepted(
        testing.allocator,
        &nc_leaf.certificate,
        &name_constraints_intermediates,
        first_snapshot.anchors(),
        validation_time_name_constraints,
    );
    try expectDirectAnchorAccepted(
        testing.allocator,
        &direct_leaf.certificate,
        second_snapshot.anchors(),
        validation_time_name_constraints,
        "openssl.example.com",
    );
    try testing.expectEqual(@as(usize, 1), first_snapshot.anchors().len);
    try testing.expectEqual(@as(usize, 1), second_snapshot.anchors().len);
    try testing.expect(!std.mem.eql(u8, first_snapshot.anchors()[0].raw, second_snapshot.anchors()[0].raw));
}
