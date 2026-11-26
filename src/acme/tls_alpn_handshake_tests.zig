//! #939: the real ACME TLS-ALPN-01 credential provider + the real challenge
//! registry composed with the production TLS 1.3 engine, driven through a
//! deterministic two-sided handshake that is paused at the boundary the pin
//! exists for: after the server flight, before the peer's Finished.
//!
//! Registry-only and provider-only tests cannot prove the *engine's*
//! ownership of the registry gate; these do, for every way a handshake can
//! end (valid Finished, invalid Finished, stalled teardown, registry
//! shutdown) and for every authorization mutation racing it (revoke/replace
//! before selection, complete/revoke/replace while pinned, expiry).

const std = @import("std");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const tls_core = @import("tls_core");
const credentials = tls_core.credentials;
const tls_backend = tls_core.tls13_backend;
const DirectSink = tls_core.tls13_transport.EventSink;
const challenges = @import("tls_alpn_challenges.zig");
const credential_provider = @import("tls_alpn_credential.zig");
const account_mod = @import("account.zig");

const testing = std.testing;

const host = "a.example.test";
const binding_a: challenges.Binding = [_]u8{0xA1} ** 32;
const binding_b: challenges.Binding = [_]u8{0xB2} ** 32;

fn canonicalThumbprint(comptime fill: u8) [account_mod.thumbprint_len]u8 {
    var out: [account_mod.thumbprint_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &([_]u8{fill} ** 32));
    return out;
}
const key_auth_a = ("a" ** 32) ++ "." ++ canonicalThumbprint(0x42);
const key_auth_b = ("b" ** 32) ++ "." ++ canonicalThumbprint(0x43);

const acme_only = [_]tls_core.algorithms.ProtocolName{tls_core.algorithms.alpn.acme_tls_1};
const server_alpns = [_]tls_core.algorithms.ProtocolName{
    tls_core.algorithms.alpn.h2,
    tls_core.algorithms.alpn.http_1_1,
    tls_core.algorithms.alpn.acme_tls_1,
};

fn entropyFill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
    zig_compat.randomBytes(buffer);
}
var entropy_ctx: u8 = 0;
fn challengeEntropy() crypto.provider.Entropy {
    return .{ .context = &entropy_ctx, .fillFn = entropyFill };
}

/// Mutable wall clock the provider reads, so expiry is a controlled seam.
const Clock = struct {
    now: i64 = 1000,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *const Clock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
};

const CryptoStorage = struct {
    entropy: crypto.pure_zig.DeterministicEntropy = crypto.pure_zig.DeterministicEntropy.init(0),
    provider: crypto.pure_zig.Provider = undefined,

    fn init(self: *CryptoStorage, seed: u64) crypto.provider.CryptoProvider {
        self.entropy = crypto.pure_zig.DeterministicEntropy.init(seed);
        self.provider = crypto.pure_zig.Provider.init(self.entropy.entropy());
        return self.provider.cryptoProvider();
    }
};

/// Real registry + real ACME provider wrapping a mock "ordinary" provider.
const Fixture = struct {
    registry: challenges.Registry,
    inner: credentials.MockCredentialProvider,
    clock: Clock = .{},
    provider: credential_provider.Provider = undefined,

    fn init(self: *Fixture) void {
        self.* = .{
            .registry = challenges.Registry.init(testing.allocator),
            .inner = credentials.MockCredentialProvider.init(credentials.testdata.identity()),
        };
        self.provider = credential_provider.Provider.init(self.inner.provider(), &self.registry, testing.allocator, challengeEntropy());
        self.provider.clock = .{ .ctx = &self.clock, .nowFn = Clock.read };
    }

    fn deinit(self: *Fixture) void {
        self.registry.deinit();
    }

    fn activate(self: *Fixture, binding: challenges.Binding, key_auth: []const u8) !void {
        try self.registry.put(self.clock.now, host, binding, key_auth, self.clock.now + 100);
    }
};

/// One two-sided handshake between a real exclusive-`acme-tls/1` client and a
/// server engine whose credential provider is the ACME decorator.
const Handshake = struct {
    client_store: CryptoStorage = .{},
    server_store: CryptoStorage = .{},
    client: tls_backend.Tls13Backend = undefined,
    server: tls_backend.Tls13Backend = undefined,
    client_sink: DirectSink = .{},
    server_sink: DirectSink = .{},
    server_live: bool = false,

    fn init(self: *Handshake, provider: credentials.CredentialProvider, seed: u64) void {
        const client_policy = tls_core.policy.Policy.fromCapabilities(.record, tls_backend.native_capabilities, &acme_only);
        self.client = tls_backend.Tls13Backend.initClientConfigured(
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            self.client_store.init(seed),
            .insecure_no_verification,
            tls_backend.recordConfig(client_policy),
            .{ .server_name = host },
        );
        var server_policy = tls_core.policy.Policy.recordDefault();
        server_policy.alpn_protocols = &server_alpns;
        server_policy.exclusive_only_alpn_protocols = &acme_only;
        self.server = tls_backend.Tls13Backend.initServerWithProviderConfigured(
            .{ .hello_random = [_]u8{0x51} ** 32 },
            self.server_store.init(seed + 1),
            provider,
            tls_backend.recordConfig(server_policy),
        );
        self.server_live = true;
    }

    fn deinit(self: *Handshake) void {
        self.client.deinit();
        self.server.deinit();
        self.client_sink.deinit();
        self.server_sink.deinit();
    }

    /// Deliver ClientHello to the server (credential selection happens here)
    /// and the whole server flight to the client.  Stops right after the
    /// server flight, with the client's Finished still unsent.
    fn serverFlight(self: *Handshake) !void {
        try self.client.backend().start(.client, {}, &self.client_sink);
        var ch_buf: [1024]u8 = undefined;
        const client_hello = firstInitialCrypto(&self.client_sink, &ch_buf);

        try self.server.backend().start(.server, {}, &self.server_sink);
        try self.server.backend().receive(.initial, client_hello, &self.server_sink);

        var sh_buf: [512]u8 = undefined;
        const server_hello = firstInitialCrypto(&self.server_sink, &sh_buf);
        var flight_buf: [16384]u8 = undefined;
        const flight = collectHandshakeCrypto(&self.server_sink, &flight_buf);

        self.client_sink.reset();
        try self.client.backend().receive(.initial, server_hello, &self.client_sink);
        try self.client.backend().receive(.handshake, flight, &self.client_sink);
    }

    /// The certificate the server actually presented (client's view).
    fn presentedLeaf(self: *const Handshake) []const u8 {
        const entry = self.client.peer_chain_entries[0];
        return self.client.peer_chain[entry.start..][0..entry.len];
    }

    /// Deliver the client's Finished to the server, optionally corrupted.
    fn clientFinished(self: *Handshake, corrupt: bool) !void {
        var flight_buf: [16384]u8 = undefined;
        const flight = collectHandshakeCrypto(&self.client_sink, &flight_buf);
        if (corrupt) flight_buf[flight.len - 1] ^= 0xff;
        self.server_sink.reset();
        try self.server.backend().receive(.handshake, flight_buf[0..flight.len], &self.server_sink);
    }
};

fn collectHandshakeCrypto(sink: *const DirectSink, out: []u8) []const u8 {
    var len: usize = 0;
    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .handshake_bytes => |hb| if (hb.epoch == .handshake) {
                @memcpy(out[len..][0..hb.data.len], hb.data);
                len += hb.data.len;
            },
            else => {},
        }
    }
    return out[0..len];
}

fn firstInitialCrypto(sink: *const DirectSink, out: []u8) []const u8 {
    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .handshake_bytes => |hb| if (hb.epoch == .initial) {
                @memcpy(out[0..hb.data.len], hb.data);
                return out[0..hb.data.len];
            },
            else => {},
        }
    }
    return out[0..0];
}

fn expectAcmeIdentifier(leaf: []const u8, key_authorization: []const u8) !void {
    // RFC 8737 S3: the critical id-pe-acmeIdentifier extension carries exactly
    // SHA-256(keyAuthorization); checked as a raw byte pattern.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_authorization, &digest, .{});
    const prefix = [_]u8{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f, 0x01, 0x01, 0xff, 0x04, 0x22, 0x04, 0x20 };
    var pattern: [prefix.len + 32]u8 = undefined;
    @memcpy(pattern[0..prefix.len], &prefix);
    @memcpy(pattern[prefix.len..], &digest);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, leaf, &pattern));
}

test "#939 engine+registry: revoked or expired authorization is refused before any selection" {
    var fixture: Fixture = undefined;
    fixture.init();
    defer fixture.deinit();
    try fixture.activate(binding_a, key_auth_a);
    try testing.expectEqual(challenges.CloseOutcome.closed, fixture.registry.revoke(host, binding_a));

    var hs: Handshake = .{};
    hs.init(fixture.provider.credentialProvider(), 100);
    defer hs.deinit();
    try testing.expectError(error.NoApplicableCredential, hs.serverFlight());
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
    try testing.expectEqual(@as(usize, 0), fixture.inner.select_count);

    // Expiry is the same fail-closed seam.
    try fixture.activate(binding_b, key_auth_b);
    fixture.clock.now += 1000;
    var expired: Handshake = .{};
    expired.init(fixture.provider.credentialProvider(), 200);
    defer expired.deinit();
    try testing.expectError(error.NoApplicableCredential, expired.serverFlight());
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
    try testing.expectEqual(@as(usize, 0), fixture.inner.select_count);
}

test "#939 engine+registry: complete/replace while pinned drains the old identity and a valid Finished releases exactly once" {
    var fixture: Fixture = undefined;
    fixture.init();
    defer fixture.deinit();
    try fixture.activate(binding_a, key_auth_a);

    var hs_a: Handshake = .{};
    hs_a.init(fixture.provider.credentialProvider(), 300);
    defer hs_a.deinit();
    try hs_a.serverFlight();
    // Paused after the server flight, before client Finished: the gate slot
    // is held by the engine, not merely by the signature step.
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());
    try expectAcmeIdentifier(hs_a.presentedLeaf(), key_auth_a);
    var leaf_a_buf: [2048]u8 = undefined;
    const leaf_a = leaf_a_buf[0..hs_a.presentedLeaf().len];
    @memcpy(leaf_a, hs_a.presentedLeaf());

    // The order completes and a replacement authorization is published for
    // the same host while A's handshake is still stalled.
    try testing.expectEqual(challenges.CloseOutcome.closed, fixture.registry.complete(host, binding_a));
    try fixture.activate(binding_b, key_auth_b);
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());

    // A stale (completed) binding can never revoke the replacement.
    try testing.expectEqual(challenges.CloseOutcome.not_found, fixture.registry.revoke(host, binding_a));

    // A new selection uses B, never A, while A drains.
    var hs_b: Handshake = .{};
    hs_b.init(fixture.provider.credentialProvider(), 400);
    defer hs_b.deinit();
    try hs_b.serverFlight();
    try testing.expectEqual(@as(u32, 2), fixture.registry.liveIdentities());
    try expectAcmeIdentifier(hs_b.presentedLeaf(), key_auth_b);
    try testing.expect(!std.mem.eql(u8, leaf_a, hs_b.presentedLeaf()));

    // A already-selected identity keeps presenting A (no switch to B) and
    // completes; its single pin is released exactly once.
    try hs_a.clientFinished(false);
    try testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, hs_a.server.core.handshake_lifecycle);
    try expectAcmeIdentifier(hs_a.presentedLeaf(), key_auth_a);
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());
    hs_a.server.deinit(); // idempotent teardown fallback
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());

    try hs_b.clientFinished(false);
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
    try testing.expectEqual(@as(usize, 0), fixture.inner.select_count);
}

test "#939 engine+registry: an invalid Finished releases the pin immediately, before teardown" {
    var fixture: Fixture = undefined;
    fixture.init();
    defer fixture.deinit();
    try fixture.activate(binding_a, key_auth_a);

    var hs: Handshake = .{};
    hs.init(fixture.provider.credentialProvider(), 500);
    defer hs.deinit();
    try hs.serverFlight();
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());
    // Revoke while pinned: the stalled handshake still holds its slot.
    try testing.expectEqual(challenges.CloseOutcome.closed, fixture.registry.revoke(host, binding_a));
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());

    try testing.expectError(error.DecryptError, hs.clientFinished(true));
    // Terminal failure itself returns the slot -- not deinit's fallback.
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
    hs.server.deinit();
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
}

test "#939 engine+registry: stalled teardown (timeout) releases the pin exactly once" {
    var fixture: Fixture = undefined;
    fixture.init();
    defer fixture.deinit();
    try fixture.activate(binding_a, key_auth_a);

    var hs: Handshake = .{};
    hs.init(fixture.provider.credentialProvider(), 600);
    defer hs.deinit();
    try hs.serverFlight();
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());
    // The peer never sends Finished; the listener's handshake timeout tears
    // the engine down.
    hs.server.deinit();
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
    hs.server.deinit();
    try testing.expectEqual(@as(u32, 0), fixture.registry.liveIdentities());
}

test "#939 engine+registry: registry shutdown/reload while pinned lets the in-flight handshake drain safely" {
    var fixture: Fixture = undefined;
    fixture.init();
    // `fixture.deinit()` is the shutdown under test; it runs mid-handshake.
    try fixture.activate(binding_a, key_auth_a);

    var hs: Handshake = .{};
    hs.init(fixture.provider.credentialProvider(), 700);
    defer hs.deinit();
    try hs.serverFlight();
    try testing.expectEqual(@as(u32, 1), fixture.registry.liveIdentities());

    // Shutdown: no new identity may be issued, but the outstanding gate must
    // stay valid for the in-flight release (the testing allocator proves
    // there is no leak or use-after-free).
    fixture.registry.deinit();
    try hs.clientFinished(false);
    try testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, hs.server.core.handshake_lifecycle);
}
