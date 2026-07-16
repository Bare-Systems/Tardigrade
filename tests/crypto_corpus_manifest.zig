//! Shared manifest for checked-in Wycheproof-style crypto corpus suites.

const crypto_pkg = @import("crypto");
const profile = crypto_pkg.profile;

pub const Suite = struct {
    id: []const u8,
    algorithm: profile.Algorithm,
    source_file: []const u8,
    case_count: usize,
};

pub const SkippedSuite = struct {
    algorithm: []const u8,
    reason: []const u8,
    tracking_issue: []const u8,
};

pub const suites = [_]Suite{
    .{ .id = "wycheproof-aes-128-gcm-reduced", .algorithm = .{ .aead = .aes_128_gcm }, .source_file = "testvectors_v1/aes_gcm_test.json", .case_count = 2 },
    .{ .id = "wycheproof-aes-256-gcm-reduced", .algorithm = .{ .aead = .aes_256_gcm }, .source_file = "testvectors_v1/aes_gcm_test.json", .case_count = 2 },
    .{ .id = "wycheproof-chacha20-poly1305-reduced", .algorithm = .{ .aead = .chacha20_poly1305 }, .source_file = "testvectors_v1/chacha20_poly1305_test.json", .case_count = 3 },
    .{ .id = "wycheproof-x25519-reduced", .algorithm = .{ .group = .x25519 }, .source_file = "testvectors_v1/x25519_test.json", .case_count = 2 },
    .{ .id = "wycheproof-ed25519-verify-reduced", .algorithm = .{ .signature = .ed25519 }, .source_file = "testvectors_v1/ed25519_test.json", .case_count = 2 },
};

pub const skipped_suites = [_]SkippedSuite{
    .{ .algorithm = "RSA-PSS", .reason = "Provider capability remains deferred for issue #374 follow-up; pure-Zig provider currently returns UnsupportedCapability.", .tracking_issue = "#374" },
    .{ .algorithm = "ECDSA-P256-SHA256", .reason = "Supported provider operation, but outside this first merge-sized #374 corpus slice.", .tracking_issue = "#374" },
    .{ .algorithm = "X448", .reason = "Unsupported by the current provider capability matrix.", .tracking_issue = "#374" },
};
