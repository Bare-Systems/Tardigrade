//! Native TLS-ALPN-01 credential selection (#939, A6-3 of #759).
//!
//! `Provider` wraps a production `credentials.CredentialProvider` (the
//! native TCP listener's `NativeCredentialStore`/`sni_provider` selection) so
//! that a ClientHello offering **exclusively** `acme-tls/1` for a host with a
//! live #932 registry authorization receives the ephemeral RFC 8737 identity
//! (#938) instead of the committed managed/manual identity. Every other
//! ClientHello -- ordinary `h2`/`http/1.1`, any ALPN offer the registry does
//! not vouch for, or an unauthorized/expired/cancelled challenge -- falls
//! through to (or fails exactly like) the wrapped provider.
//!
//! ## Fail-closed, never fall-through, once committed
//!
//! `selectCredential` only ever delegates to the wrapped provider when the
//! ClientHello's complete offered ALPN list is NOT exclusively `acme-tls/1`
//! (see `tls_alpn_challenges.isChallengeAlpnOffer`) -- i.e. this is clearly an
//! ordinary connection, or one that intentionally offered extra protocols
//! alongside `acme-tls/1` and therefore does not get the exclusive validation
//! identity, by design (#939 requirement 1). Once a ClientHello *has*
//! committed to the exclusive offer, every outcome below is terminal: a
//! missing/invalid SNI, no live registry entry, or an authorization/identity
//! build failure (NotAuthorized/Expired/TooManyIdentities/EntropyFailure/...)
//! all fail the handshake closed via `error.NoCredentialAvailable` or
//! `error.ProviderInternalFailure` -- never the wrapped provider's ordinary
//! production certificate, and never plaintext.
//!
//! ## Lifecycle
//!
//! A successful selection pins exactly one `tls_alpn_identity.ChallengeIdentity`
//! (which itself pins one `tls_alpn_challenges.IdentityGate` slot) for the
//! life of the returned `SelectedCredential`; `ChallengeHandle.release` --
//! called by the engine exactly once, on success, failure, or timeout --
//! wipes the ephemeral key, frees the certificate DER, and releases the gate
//! slot. The registry lookup and the gate acquisition happen under the
//! registry's own lock (`Registry.confirmAndAcquire`), so a cancellation,
//! replacement, reload, or expiry racing this selection either happens
//! strictly before (the lease is refused) or strictly after (this handshake's
//! already-admitted build drains normally) -- never mid-build.

const std = @import("std");
const credentials = @import("tls_core").credentials;
const crypto_provider = @import("crypto").provider;
const challenges = @import("tls_alpn_challenges.zig");
const identity_mod = @import("tls_alpn_identity.zig");
const orders = @import("orders.zig");
const dns_name = @import("tls_core").dns_name;

/// Bounded upper case->lower case ASCII fold, matching the registry's own
/// canonical (lowercase) host requirement (`names.validateName`). Returns
/// null for an empty or oversized host rather than silently truncating.
fn canonicalizeHost(raw: []const u8, buf: *[dns_name.max_name_len]u8) ?[]const u8 {
    if (raw.len == 0 or raw.len > buf.len) return null;
    for (raw, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..raw.len];
}

fn mapIdentityError(err: identity_mod.Error) credentials.SelectError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidHost,
        error.InvalidKeyAuthorization,
        error.InvalidValidity,
        error.NotAuthorized,
        error.Expired,
        error.TooManyIdentities,
        => error.NoCredentialAvailable,
        error.EntropyFailure, error.KeyGenFailed, error.SignFailed => error.ProviderInternalFailure,
    };
}

/// A `credentials.CredentialProvider` decorator; see the module doc. `inner`,
/// `registry`, and the clock are borrowed for the life of `Provider` and must
/// outlive it. `entropy` is used only to build fresh ephemeral challenge keys
/// and to sign with them -- never to touch any other identity.
pub const Provider = struct {
    inner: credentials.CredentialProvider,
    registry: *challenges.Registry,
    allocator: std.mem.Allocator,
    entropy: crypto_provider.Entropy,
    clock: orders.UnixClock = .{},

    pub fn init(
        inner: credentials.CredentialProvider,
        registry: *challenges.Registry,
        allocator: std.mem.Allocator,
        entropy: crypto_provider.Entropy,
    ) Provider {
        return .{ .inner = inner, .registry = registry, .allocator = allocator, .entropy = entropy };
    }

    pub fn credentialProvider(self: *Provider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &provider_vtable };
    }

    const provider_vtable = credentials.CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const self: *Provider = @ptrCast(@alignCast(ctx));
        if (try self.decide(selection)) |outcome| return outcome;
        return self.inner.selectCredential(selection);
    }

    /// `null` means "not an exclusive acme-tls/1 offer" -- the caller must
    /// fall through to `inner` unchanged. A non-null return (success or
    /// error) is always terminal; see the module doc.
    fn decide(
        self: *Provider,
        selection: *const credentials.SelectionContext,
    ) credentials.SelectError!?credentials.Progress(credentials.SelectedCredential) {
        if (selection.role != .server) return null;
        if (!challenges.isChallengeAlpnOffer(selection.offered_alpn_protocols)) return null;
        return try self.selectChallenge(selection);
    }

    fn selectChallenge(
        self: *Provider,
        selection: *const credentials.SelectionContext,
    ) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const raw_host = selection.server_name orelse return error.NoCredentialAvailable;
        var host_buf: [dns_name.max_name_len]u8 = undefined;
        const host = canonicalizeHost(raw_host, &host_buf) orelse return error.NoCredentialAvailable;
        const now = self.clock.now();

        const maybe_lease = self.registry.lookup(self.allocator, now, host, selection.offered_alpn_protocols) catch
            return error.OutOfMemory;
        const lease = maybe_lease orelse return error.NoCredentialAvailable;

        var identity = identity_mod.build(self.registry, self.allocator, self.entropy, lease, host, lease.binding, now) catch |err|
            return mapIdentityError(err);
        errdefer identity.deinit();

        const handle = self.allocator.create(ChallengeHandle) catch return error.OutOfMemory;
        handle.* = .{
            .identity = identity,
            .entropy = self.entropy,
            .allocator = self.allocator,
            .chain_entry = .{identity.certificate_der},
        };
        return .{ .complete = .{ .handle = handle, .scheme = .ecdsa_secp256r1_sha256, .vtable = &ChallengeHandle.vtable } };
    }
};

/// The `SelectedCredential` handle for one pinned `ChallengeIdentity`.
const ChallengeHandle = struct {
    identity: identity_mod.ChallengeIdentity,
    entropy: crypto_provider.Entropy,
    allocator: std.mem.Allocator,
    /// `identity.certificate_der` is self-signed (#938): no intermediate
    /// chain, exactly one entry.
    chain_entry: [1][]const u8,

    const vtable = credentials.SelectedCredential.VTable{ .chain = chain, .sign = sign, .release = release };

    fn chain(handle: *anyopaque) credentials.CertificateChain {
        const self: *ChallengeHandle = @ptrCast(@alignCast(handle));
        return .{ .entries = self.chain_entry[0..] };
    }

    fn sign(handle: *anyopaque, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!credentials.Progress(usize) {
        const self: *ChallengeHandle = @ptrCast(@alignCast(handle));
        if (scheme != .ecdsa_secp256r1_sha256) return error.InvalidCallbackBehavior;
        const written = self.identity.key.key.signingKey().sign(input, self.entropy, out) catch |err| return switch (err) {
            error.InvalidInput => error.SignatureOutputOverflow,
            error.UnsupportedCapability, error.EntropyFailure, error.ProviderFailure => error.SigningProviderFailure,
        };
        return .{ .complete = written };
    }

    fn release(handle: *anyopaque) void {
        const self: *ChallengeHandle = @ptrCast(@alignCast(handle));
        const allocator = self.allocator;
        self.identity.deinit();
        allocator.destroy(self);
    }
};

const testing = std.testing;
const pki = @import("pki");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const test_entropy: crypto_provider.Entropy = .{ .context = @constCast(&test_entropy_ctx), .fillFn = testFill };
const test_entropy_ctx: u8 = 0;
fn testFill(_: *anyopaque, buffer: []u8) crypto_provider.EntropyError!void {
    zig_compat.randomBytes(buffer);
}

const binding_a: challenges.Binding = [_]u8{0xAB} ** 32;
const valid_token = "a" ** 32;
fn canonicalThumbprint(comptime fill: u8) [account_mod.thumbprint_len]u8 {
    var out: [account_mod.thumbprint_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &([_]u8{fill} ** 32));
    return out;
}
const valid_thumbprint = canonicalThumbprint(0x42);
const valid_key_authorization = valid_token ++ "." ++ valid_thumbprint;

const exclusive_alpn = [_][]const u8{challenges.protocol};
const mixed_alpn = [_][]const u8{ "h2", challenges.protocol };
const h2_alpn = [_][]const u8{"h2"};

fn fixedNow1000(_: ?*anyopaque) i64 {
    return 1000;
}

fn readCtxNow(ctx: ?*anyopaque) i64 {
    const ptr: *const i64 = @ptrCast(@alignCast(ctx.?));
    return ptr.*;
}

fn testInnerIdentity() credentials.Identity {
    return credentials.testdata.identity();
}

fn syncSelect(provider: credentials.CredentialProvider, selection: *const credentials.SelectionContext) !credentials.SelectedCredential {
    return switch (try provider.selectCredential(selection)) {
        .complete => |credential| credential,
        .pending => error.TestUnexpectedPending,
    };
}

fn baseSelection(host: ?[]const u8, offered_alpn: []const []const u8) credentials.SelectionContext {
    return .{
        .role = .server,
        .server_name = host,
        .peer_signature_schemes = &.{ 0x0403, 0x0807 }, // ecdsa_secp256r1_sha256, ed25519
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
        .offered_alpn_protocols = offered_alpn,
    };
}

test "selects exactly the registry's RFC 8737 identity for an exact SNI and exclusive acme-tls/1 offer" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);
    provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };

    const selection = baseSelection("a.example.test", &exclusive_alpn);
    const credential = try syncSelect(provider.credentialProvider(), &selection);
    defer credential.release();
    try testing.expectEqual(credentials.SignatureScheme.ecdsa_secp256r1_sha256, credential.scheme);

    const chain = credential.certificateChain();
    try testing.expectEqual(@as(usize, 1), chain.count());
    var cert = try pki.x509.Certificate.parse(testing.allocator, chain.leaf().?, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);
    const san = cert.subjectAltName().?;
    try testing.expectEqual(@as(usize, 1), san.len);
    try testing.expectEqualStrings("a.example.test", san[0].dns_name);
    try testing.expect(cert.findExtension(&pki.oid.well_known.acme_identifier) != null);

    var out: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const written = switch (try credential.sign("test transcript", &out)) {
        .complete => |n| n,
        .pending => return error.TestUnexpectedPending,
    };
    var sec1: [65]u8 = undefined;
    @memcpy(&sec1, cert.subject_public_key_info.subject_public_key.data);
    try (try Ecdsa.Signature.fromDer(out[0..written])).verify("test transcript", try Ecdsa.PublicKey.fromSec1(&sec1));

    // Never fell through to the wrapped (ordinary production) provider.
    try testing.expectEqual(@as(usize, 0), inner.select_count);
}

test "falls through to the wrapped provider whenever the offered ALPN is not exclusively acme-tls/1" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);
    provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };

    const empty_alpn: []const []const u8 = &.{};
    for ([_][]const []const u8{ &mixed_alpn, &h2_alpn, empty_alpn }) |offer| {
        inner.select_count = 0;
        const selection = baseSelection("a.example.test", offer);
        const credential = try syncSelect(provider.credentialProvider(), &selection);
        defer credential.release();
        try testing.expectEqual(@as(usize, 1), inner.select_count);
        try testing.expectEqualSlices(u8, credentials.testdata.certificate_der, credential.certificateChain().leaf().?);
    }
}

test "canonicalizes SNI case before matching the registry's lowercase-only host" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);
    provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };

    const selection = baseSelection("A.Example.Test", &exclusive_alpn);
    const credential = try syncSelect(provider.credentialProvider(), &selection);
    defer credential.release();
    var cert = try pki.x509.Certificate.parse(testing.allocator, credential.certificateChain().leaf().?, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);
    try testing.expectEqualStrings("a.example.test", cert.subjectAltName().?[0].dns_name);
    try testing.expectEqual(@as(usize, 0), inner.select_count);
}

test "fails closed, never falling through, for an exclusive offer with no live authorized entry" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1005);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);

    const long_host = "x" ** 300;
    const cases = [_]struct { host: ?[]const u8, now: i64 }{
        .{ .host = null, .now = 1000 }, // absent SNI
        .{ .host = "b.example.test", .now = 1000 }, // unregistered host
        .{ .host = "a.example.test", .now = 1006 }, // expired lease
        .{ .host = long_host, .now = 1000 }, // oversized host
    };
    for (cases) |case| {
        var now = case.now;
        provider.clock = .{ .ctx = @ptrCast(&now), .nowFn = readCtxNow };
        const selection = baseSelection(case.host, &exclusive_alpn);
        try testing.expectError(error.NoCredentialAvailable, provider.credentialProvider().selectCredential(&selection));
    }
    try testing.expectEqual(@as(usize, 0), inner.select_count);
}

test "never attempts challenge selection for the client role, regardless of the offered ALPN" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);
    provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };

    var selection = baseSelection("a.example.test", &exclusive_alpn);
    selection.role = .client;
    const credential = try syncSelect(provider.credentialProvider(), &selection);
    defer credential.release();
    try testing.expectEqual(@as(usize, 1), inner.select_count);
}

test "release wipes the identity and returns exactly one registry slot" {
    var registry = challenges.Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);

    var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
    var provider = Provider.init(inner.provider(), &registry, testing.allocator, test_entropy);
    provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };

    const selection = baseSelection("a.example.test", &exclusive_alpn);
    const credential = try syncSelect(provider.credentialProvider(), &selection);
    try testing.expectEqual(@as(u32, 1), registry.liveIdentities());
    credential.release();
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}

test "allocation failure sweep through registry lookup, identity build, and handle creation leaks nothing" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var registry = challenges.Registry.init(allocator);
            defer registry.deinit();
            try registry.put(1000, "a.example.test", binding_a, valid_key_authorization, 1100);
            var inner = credentials.MockCredentialProvider.init(testInnerIdentity());
            var provider = Provider.init(inner.provider(), &registry, allocator, test_entropy);
            provider.clock = .{ .ctx = null, .nowFn = fixedNow1000 };
            const selection = baseSelection("a.example.test", &exclusive_alpn);
            const credential = try syncSelect(provider.credentialProvider(), &selection);
            credential.release();
        }
    }.run, .{});
}
