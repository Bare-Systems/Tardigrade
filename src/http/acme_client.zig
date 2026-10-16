//! Native ACME client surface for every shipping profile (#379, #649).
//!
//! Imported directly by the gateway and TLS termination code. Contains no
//! `@cImport` and no OpenSSL in any profile. The issuance/renewal workflow,
//! which needs EC key generation, CSR building, and signing, is not yet
//! available on the native path and fails closed rather than silently
//! doing nothing. Automated ACME is tracked alongside the native TLS
//! matrix (#391). (Historically this file's OpenSSL-backed implementation
//! lived under this name and this native surface was `acme_client_stub.zig`;
//! #649 retired the OpenSSL implementation and promoted this surface to
//! the file's name.)

const std = @import("std");

pub const AcmeError = error{
    OutOfMemory,
    KeyGenFailed,
    KeyLoadFailed,
    KeySaveFailed,
    JsonParseFailed,
    NetworkError,
    AcmeProtocolError,
    ChallengeFailed,
    CsrFailed,
    CertDownloadFailed,
    CertSaveFailed,
    CertNotYetDue,
};

/// Shared pure-Zig challenge token store (identical to the general profile).
pub const ChallengeStore = @import("acme_challenge_store.zig").ChallengeStore;
/// Host-scopes a request Host header against the managed-hostname set
/// before a challenge lookup (#877).
pub const matchManagedHost = @import("acme_challenge_store.zig").matchManagedHost;

pub const AcmeOptions = struct {
    allocator: std.mem.Allocator,
    directory_url: []const u8,
    domains: []const []const u8,
    email: []const u8,
    account_key_path: []const u8,
    cert_dir: []const u8,
    renew_days_before_expiry: u32,
    challenge_store: *ChallengeStore,
    challenge_timeout_s: u32 = 120,
};

/// Certificate expiry inspection needs X.509 parsing that the native path does
/// not yet expose here; report "unknown" so callers treat it as not-due rather
/// than forcing a renewal that cannot run.
pub fn daysUntilExpiry(cert_path: []const u8) ?i64 {
    _ = cert_path;
    return null;
}

/// The ACME issuance/renewal workflow is unavailable in every profile
/// (#649: no OpenSSL-backed implementation remains). Fail closed with an
/// inspectable error instead of a hidden no-op.
pub fn runOnce(opts: AcmeOptions) AcmeError!void {
    _ = opts;
    return error.AcmeProtocolError;
}

test "stub ACME runOnce fails closed and shares the challenge store" {
    var store = ChallengeStore.init(std.testing.allocator);
    defer store.deinit();
    try store.put(0, "example.com", "tokislongenoughxx", "tok.key", 600);
    const copy = store.getCopy(std.testing.allocator, 0, "example.com", "tokislongenoughxx").?;
    defer std.testing.allocator.free(copy);
    try std.testing.expectEqualStrings("tok.key", copy);

    try std.testing.expectEqual(@as(?i64, null), daysUntilExpiry("whatever.crt"));
    try std.testing.expectError(error.AcmeProtocolError, runOnce(.{
        .allocator = std.testing.allocator,
        .directory_url = "",
        .domains = &.{"example.com"},
        .email = "",
        .account_key_path = "",
        .cert_dir = "",
        .renew_days_before_expiry = 30,
        .challenge_store = &store,
    }));
}
