//! PEM and certificate-chain loader regression and adversarial tests (#340).

const std = @import("std");
const der = @import("der.zig");
const pem = @import("pem.zig");

const testing = std.testing;

/// Minimal valid "certificate" DER for structural tests: SEQUENCE { INTEGER n }.
/// The loader only enforces the outer SEQUENCE shape; interior is #341.
fn minimalCertDer(n: u8) [5]u8 {
    return .{ 0x30, 0x03, 0x02, 0x01, n };
}

fn appendPemBlock(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, der_bytes: []const u8, line_ending: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der_bytes.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, der_bytes);

    try out.appendSlice(allocator, "-----BEGIN ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----");
    try out.appendSlice(allocator, line_ending);
    var rest: []const u8 = encoded;
    while (rest.len > 0) {
        const take = @min(rest.len, 64);
        try out.appendSlice(allocator, rest[0..take]);
        try out.appendSlice(allocator, line_ending);
        rest = rest[take..];
    }
    try out.appendSlice(allocator, "-----END ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----");
    try out.appendSlice(allocator, line_ending);
}

fn certPem(allocator: std.mem.Allocator, der_bytes: []const u8, line_ending: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendPemBlock(&out, allocator, "CERTIFICATE", der_bytes, line_ending);
    return out.toOwnedSlice(allocator);
}

test "single certificate loads and preserves exact DER bytes" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);

    var chain = try pem.loadChainPem(allocator, text, .{});
    defer chain.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert, chain.certificates[0].der);
}

test "multi-certificate chain preserves input order" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const leaf = minimalCertDer(1);
    const intermediate = minimalCertDer(2);
    const root = minimalCertDer(3);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &leaf, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &intermediate, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &root, "\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), chain.certificates.len);
    try testing.expectEqualSlices(u8, &leaf, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &intermediate, chain.certificates[1].der);
    try testing.expectEqualSlices(u8, &root, chain.certificates[2].der);
}

test "mixed surrounding text and OpenSSL-style annotations are ignored" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    try out.appendSlice(allocator, "# Root bundle exported 2026-07-12\n\n");
    try out.appendSlice(allocator, "subject=CN = Test Leaf\nissuer=CN = Test CA\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try out.appendSlice(allocator, "\nsubject=CN = Test CA\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");
    try out.appendSlice(allocator, "trailing commentary, no dashes\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert_a, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &cert_b, chain.certificates[1].der);
}

test "CRLF and mixed line endings load identically to LF" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(7);

    const crlf_text = try certPem(allocator, &cert, "\r\n");
    defer allocator.free(crlf_text);
    var crlf_chain = try pem.loadChainPem(allocator, crlf_text, .{});
    defer crlf_chain.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, crlf_chain.certificates[0].der);

    var mixed: std.ArrayList(u8) = .empty;
    defer mixed.deinit(allocator);
    const cert_b = minimalCertDer(8);
    try appendPemBlock(&mixed, allocator, "CERTIFICATE", &cert, "\r\n");
    try appendPemBlock(&mixed, allocator, "CERTIFICATE", &cert_b, "\n");
    var mixed_chain = try pem.loadChainPem(allocator, mixed.items, .{});
    defer mixed_chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), mixed_chain.certificates.len);
}

test "missing final newline after END boundary still loads" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);
    const trimmed = std.mem.trimEnd(u8, text, "\n");

    var chain = try pem.loadChainPem(allocator, trimmed, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
}

test "non-certificate blocks are skipped but must be well-formed" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert = minimalCertDer(1);
    const key_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try appendPemBlock(&out, allocator, "PRIVATE KEY", &key_bytes, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert, "\n");
    try appendPemBlock(&out, allocator, "EC PARAMETERS", &key_bytes, "\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert, chain.certificates[0].der);
}

test "input with no certificate blocks fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, "just some text\n", .{}));
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, "", .{}));

    // A lone skipped block is well-formed but yields an empty chain.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const key_bytes = [_]u8{ 0x01, 0x02 };
    try appendPemBlock(&out, allocator, "PRIVATE KEY", &key_bytes, "\n");
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, out.items, .{}));
}

test "malformed boundaries fail typed" {
    const allocator = testing.allocator;
    const cases = [_][]const u8{
        // Dashes but not a boundary.
        "-----GARBAGE-----\n",
        // Truncated BEGIN keyword.
        "-----BEGIN CERTIFICATE\n",
        // Missing closing dashes.
        "-----BEGIN CERTIFICATE---\nMTIz\n-----END CERTIFICATE-----\n",
        // Empty label.
        "-----BEGIN -----\n-----END -----\n",
        // Label with control character.
        "-----BEGIN CERT\tIFICATE-----\nMTIz\n-----END CERT\tIFICATE-----\n",
        // Label with doubled separator.
        "-----BEGIN NEW  CERTIFICATE-----\n-----END NEW  CERTIFICATE-----\n",
        // Label with trailing separator.
        "-----BEGIN CERTIFICATE- -----\n",
        // Trailing junk after the closing dashes.
        "-----BEGIN CERTIFICATE----- junk\nMTIz\n-----END CERTIFICATE-----\n",
        // END with no open block.
        "-----END CERTIFICATE-----\n",
        // Nested BEGIN inside an open block.
        "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
    };
    for (cases) |case| {
        try testing.expectError(error.MalformedPemBoundary, pem.loadChainPem(allocator, case, .{}));
    }
}

test "mismatched END label fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.MismatchedPemLabel, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END PRIVATE KEY-----\n",
        .{},
    ));
    try testing.expectError(error.MismatchedPemLabel, pem.loadChainPem(
        allocator,
        "-----BEGIN PRIVATE KEY-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
        .{},
    ));
}

test "unterminated block fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnterminatedPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n",
        .{},
    ));
    try testing.expectError(error.UnterminatedPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n",
        .{},
    ));
}

test "strict base64 rejects malformed data" {
    const allocator = testing.allocator;
    const prefix = "-----BEGIN CERTIFICATE-----\n";
    const suffix = "-----END CERTIFICATE-----\n";
    const cases = [_][]const u8{
        // Invalid character.
        "MAMCAQ!=\n",
        // Interior space.
        "MAMC AQE=\n",
        // Blank line inside the block.
        "MAMC\n\nAQE=\n",
        // Length not a multiple of four (missing padding).
        "MAMCAQE\n",
        // Data after padding within the block.
        "MAMCAQE=\nAAAA\n",
        // Nonzero trailing bits (non-canonical final symbol).
        "MAMCAQF=\n",
        // Padding only.
        "====\n",
        // Bare CR inside a base64 line is not a line terminator.
        "MAMC\rAQE=\n",
    };
    for (cases) |body| {
        const text = try std.mem.concat(allocator, u8, &.{ prefix, body, suffix });
        defer allocator.free(text);
        try testing.expectError(error.InvalidPemBase64, pem.loadChainPem(allocator, text, .{}));
    }
}

test "empty certificate block fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.EmptyPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        .{},
    ));
}

test "decoded bytes that are not one DER SEQUENCE fail typed" {
    const allocator = testing.allocator;

    // INTEGER at top level instead of SEQUENCE.
    const not_sequence = [_]u8{ 0x02, 0x01, 0x01 };
    // Valid SEQUENCE followed by trailing bytes.
    const trailing = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01, 0x00 };
    // Truncated SEQUENCE (length beyond content).
    const truncated = [_]u8{ 0x30, 0x10, 0x02, 0x01 };
    // BER indefinite length.
    const indefinite = [_]u8{ 0x30, 0x80, 0x00, 0x00 };

    for ([_][]const u8{ &not_sequence, &trailing, &truncated, &indefinite }) |bytes| {
        const text = try certPem(allocator, bytes, "\n");
        defer allocator.free(text);
        try testing.expectError(error.MalformedCertificateDer, pem.loadChainPem(allocator, text, .{}));
        try testing.expectError(error.MalformedCertificateDer, pem.loadCertificateDer(allocator, bytes, .{}));
    }
}

test "certificate count limit fails typed" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");

    try testing.expectError(error.TooManyCertificates, pem.loadChainPem(allocator, out.items, .{ .max_certificates = 1 }));

    var chain = try pem.loadChainPem(allocator, out.items, .{ .max_certificates = 2 });
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
}

test "hostile oversized input fails before unbounded allocation" {
    const allocator = testing.allocator;

    // Input larger than max_input_len is rejected up front.
    const big = try allocator.alloc(u8, 1024);
    defer allocator.free(big);
    @memset(big, 'A');
    try testing.expectError(error.InputTooLarge, pem.loadChainPem(allocator, big, .{ .max_input_len = 512 }));
    try testing.expectError(error.InputTooLarge, pem.loadCertificateDer(allocator, big, .{ .max_input_len = 512 }));

    // A block whose base64 exceeds the per-certificate bound is rejected
    // during accumulation, before base64 decoding or DER validation.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        try out.appendSlice(allocator, "QUFB" ** 16);
        try out.appendSlice(allocator, "\n");
    }
    try out.appendSlice(allocator, "-----END CERTIFICATE-----\n");
    try testing.expectError(error.CertificateTooLarge, pem.loadChainPem(allocator, out.items, .{ .max_certificate_len = 1024 }));

    // Same bound applies to the decoded size of a DER buffer.
    const cert = minimalCertDer(1);
    try testing.expectError(error.CertificateTooLarge, pem.loadCertificateDer(allocator, &cert, .{ .max_certificate_len = 4 }));
}

test "loadCertificatePem accepts exactly one block" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(5);
    const single = try certPem(allocator, &cert, "\n");
    defer allocator.free(single);

    var loaded = try pem.loadCertificatePem(allocator, single, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, loaded.der);

    var two: std.ArrayList(u8) = .empty;
    defer two.deinit(allocator);
    try appendPemBlock(&two, allocator, "CERTIFICATE", &cert, "\n");
    try appendPemBlock(&two, allocator, "CERTIFICATE", &cert, "\n");
    try testing.expectError(error.TooManyCertificates, pem.loadCertificatePem(allocator, two.items, .{}));
}

test "loadCertificateDer copies exact bytes and rejects empty input" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(9);

    var loaded = try pem.loadCertificateDer(allocator, &cert, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, loaded.der);
    // Owned copy, not a view into the input.
    try testing.expect(loaded.der.ptr != @as([]const u8, &cert).ptr);

    try testing.expectError(error.NoCertificates, pem.loadCertificateDer(allocator, &.{}, .{}));
}

test "file helpers load PEM chains and DER certificates" {
    const allocator = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");

    try tmp.dir.writeFile(io, .{ .sub_path = "chain.pem", .data = out.items });
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.der", .data = &cert_a });

    var chain = try pem.loadChainPemFile(allocator, io, tmp.dir, "chain.pem", .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert_a, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &cert_b, chain.certificates[1].der);

    var single = try pem.loadCertificateDerFile(allocator, io, tmp.dir, "cert.der", .{});
    defer single.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert_a, single.der);

    try testing.expectError(error.FileNotFound, pem.loadChainPemFile(allocator, io, tmp.dir, "missing.pem", .{}));
    try testing.expectError(error.InputTooLarge, pem.loadChainPemFile(allocator, io, tmp.dir, "chain.pem", .{ .max_input_len = 8 }));
}

test "loader is leak-free across allocation failure points" {
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try appendPemBlock(&out, testing.allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, testing.allocator, "CERTIFICATE", &cert_b, "\n");

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, text: []const u8) !void {
            var chain = try pem.loadChainPem(allocator, text, .{});
            chain.deinit(allocator);
        }
    }.run, .{out.items});
}

test "fuzz entrypoint tolerates arbitrary input" {
    const allocator = testing.allocator;
    pem.fuzzLoadChainPem(allocator, "");
    pem.fuzzLoadChainPem(allocator, "-----BEGIN CERTIFICATE-----");
    pem.fuzzLoadChainPem(allocator, "-----BEGIN CERTIFICATE-----\n\x00\xff\n-----END CERTIFICATE-----\n");
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);
    pem.fuzzLoadChainPem(allocator, text);
}
