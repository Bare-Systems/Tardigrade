//! Process-shared native TLS 1.3 resumption runtime (#365).
//!
//! This module composes the transport-neutral cache, stateless ticket
//! protection, and resolver contracts. TCP record and QUIC/H3 adapters should
//! borrow one `Runtime` for the process and install only the resolver/consumer
//! handles exposed here; PSK parsing, binder verification, and key scheduling
//! stay in `tls13_backend.zig`.

const std = @import("std");
const crypto = @import("crypto");
const new_session_ticket = @import("new_session_ticket.zig");
const pre_shared_key = @import("pre_shared_key.zig");
const session = @import("session.zig");
const session_cache = @import("session_cache.zig");
const ticket_protection = @import("ticket_protection.zig");

const provider = crypto.provider;

pub const Mode = enum { disabled, stateful, stateless, hybrid };
pub const TicketUsage = enum { reusable, single_use };

pub const Clock = struct {
    ctx: *anyopaque,
    nowUnixMsFn: *const fn (*anyopaque) i64,

    pub fn nowUnixMs(self: Clock) i64 {
        return self.nowUnixMsFn(self.ctx);
    }
};

pub const Config = struct {
    mode: Mode = .disabled,
    ticket_lifetime_seconds: u32 = 86_400,
    usage: TicketUsage = .reusable,
    session_limits: session.Limits = .default,
    client_cache_limits: session_cache.Limits = .client_default,
    server_cache_limits: session_cache.Limits = .stateful_server_default,

    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.usage == .single_use) return error.InvalidConfig;
        if (self.ticket_lifetime_seconds == 0 or self.ticket_lifetime_seconds > session.max_lifetime_seconds)
            return error.InvalidConfig;
        if (self.mode != .disabled) {
            self.session_limits.validate() catch return error.InvalidConfig;
            self.client_cache_limits.validate() catch return error.InvalidConfig;
        }
        if (self.mode == .stateful or self.mode == .hybrid)
            self.server_cache_limits.validate() catch return error.InvalidConfig;
    }
};

pub const InitError = error{ InvalidConfig, EntropyFailure, ProviderUnsupported, OutOfMemory };

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    config: Config,
    clock: Clock,
    provider: provider.CryptoProvider,
    client_cache: ?session_cache.ClientSessionCache = null,
    server_cache: ?session_cache.StatefulServerCache = null,
    keyring: ?ticket_protection.ReloadableKeyRing = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        clock: Clock,
        crypto_provider: provider.CryptoProvider,
    ) InitError!Runtime {
        try config.validate();
        if ((config.mode == .stateless or config.mode == .hybrid) and
            !crypto_provider.capabilities().supportsAead(.aes_128_gcm))
            return error.ProviderUnsupported;

        var runtime = Runtime{
            .allocator = allocator,
            .config = config,
            .clock = clock,
            .provider = crypto_provider,
        };
        errdefer runtime.deinit();

        if (config.mode != .disabled)
            runtime.client_cache = session_cache.ClientSessionCache.init(allocator, config.client_cache_limits) catch return error.InvalidConfig;

        if (config.mode == .stateful or config.mode == .hybrid)
            runtime.server_cache = session_cache.StatefulServerCache.init(
                allocator,
                config.server_cache_limits,
                session_cache.system_random_source,
            ) catch return error.InvalidConfig;

        if (config.mode == .stateless or config.mode == .hybrid) {
            runtime.keyring = ticket_protection.ReloadableKeyRing.init(allocator);
            try runtime.installEphemeralStatelessKey();
        }

        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        if (self.keyring) |*keyring| keyring.deinit();
        if (self.server_cache) |*server_cache| server_cache.deinit();
        if (self.client_cache) |*client_cache| client_cache.deinit();
        self.* = undefined;
    }

    pub fn nowUnixMs(self: *Runtime) i64 {
        return self.clock.nowUnixMs();
    }

    pub fn serverResolver(self: *Runtime) ?pre_shared_key.ServerPskResolver {
        if (self.config.mode == .disabled) return null;
        return .{
            .ctx = self,
            .nowUnixMsFn = resolverNow,
            .resolveFn = resolverResolve,
        };
    }

    pub fn lookupClientOffers(self: *Runtime, candidate: session.CandidateContext) session_cache.ClientLookupResult {
        if (self.client_cache) |*cache|
            return cache.lookupOffers(candidate, self.nowUnixMs());
        return .miss;
    }

    pub fn storeClientTicket(self: *Runtime, ticket: *const session.ClientTicketState) session_cache.StoreResult {
        if (self.client_cache) |*cache|
            return cache.storeClone(ticket, self.nowUnixMs(), usagePolicy(self.config.usage));
        return .rejected_capacity;
    }

    fn resolverNow(ctx: *anyopaque) i64 {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        return self.nowUnixMs();
    }

    fn resolverResolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        const now = self.nowUnixMs();

        if (session_cache.isValidStatefulHandleShape(identity)) {
            if (self.server_cache) |*cache|
                return session_cache.resolveStatefulServerPsk(cache, self.allocator, identity, now);
            return .miss;
        }

        if (isStatelessIdentity(identity)) {
            const keyring = if (self.keyring) |*keyring| keyring else return .miss;
            var protector = ticket_protection.Protector{
                .provider = self.provider,
                .keyring = keyring,
                .limits = self.config.session_limits,
            };
            var state: session.ServerRecoverableState = .{};
            const found = protector.resolve(self.allocator, identity, now, &state) catch return error.ResolverFailed;
            if (!found) return .miss;
            return .{ .hit = .{ .state = state, .lease = pre_shared_key.ServerPskLease.initNoop() } };
        }

        return .miss;
    }

    fn installEphemeralStatelessKey(self: *Runtime) InitError!void {
        const keyring = if (self.keyring) |*keyring| keyring else return error.InvalidConfig;
        var key_id: ticket_protection.KeyId = undefined;
        var key: [16]u8 = undefined;
        var nonce_prefix: [4]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        self.provider.randomBytes(&key_id) catch return error.EntropyFailure;
        self.provider.randomBytes(&key) catch return error.EntropyFailure;
        self.provider.randomBytes(&nonce_prefix) catch return error.EntropyFailure;

        const now = self.nowUnixMs();
        const config = ticket_protection.KeyConfig{
            .id = key_id,
            .aead = .aes_128_gcm,
            .key_bytes = &key,
            .not_before_unix_ms = now,
            .encrypt_until_unix_ms = std.math.maxInt(i64),
            .decrypt_until_unix_ms = std.math.maxInt(i64),
            .nonce_lease = .{ .prefix = nonce_prefix, .start = 0, .end_exclusive = std.math.maxInt(u64) },
        };
        const snapshot = keyring.buildSnapshot(&.{config}, self.provider.capabilities()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfig,
        };
        keyring.install(snapshot) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfig,
        };
    }
};

fn usagePolicy(usage: TicketUsage) session_cache.UsagePolicy {
    return switch (usage) {
        .reusable => .reusable,
        .single_use => .single_use,
    };
}

fn isStatelessIdentity(identity: []const u8) bool {
    return identity.len >= ticket_protection.fixed_header_len + ticket_protection.tag_len and
        std.mem.eql(u8, identity[0..4], &ticket_protection.magic) and
        identity[4] == ticket_protection.format_version;
}

test "config validates ticket lifetime ceiling" {
    try std.testing.expectError(error.InvalidConfig, (Config{ .ticket_lifetime_seconds = 0 }).validate());
    try std.testing.expectError(error.InvalidConfig, (Config{ .ticket_lifetime_seconds = session.max_lifetime_seconds + 1 }).validate());
    try (Config{ .ticket_lifetime_seconds = session.max_lifetime_seconds }).validate();
    try std.testing.expectError(error.InvalidConfig, (Config{ .mode = .stateful, .usage = .single_use }).validate());
}

const TestClock = struct {
    now_ms: i64 = 0,

    fn clock(self: *TestClock) Clock {
        return .{ .ctx = self, .nowUnixMsFn = now };
    }

    fn now(ctx: *anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx));
        return self.now_ms;
    }
};

const TestEntropy = struct {
    byte: u8 = 0x44,
    calls: usize = 0,
    fail: bool = false,

    fn entropy(self: *TestEntropy) provider.Entropy {
        return .{ .context = self, .fillFn = fill };
    }

    fn fill(ctx: *anyopaque, buffer: []u8) provider.EntropyError!void {
        const self: *TestEntropy = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.fail) return error.EntropyFailure;
        @memset(buffer, self.byte);
        self.byte +%= 1;
    }
};

fn sampleServerState(allocator: std.mem.Allocator, sni: []const u8) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x42} ** 32),
        .server_name = sni,
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 86_400,
    });
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 7);
    return state;
}

test "disabled runtime exposes no server resolver and no client offers" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{},
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();
    try std.testing.expect(runtime.serverResolver() == null);
    var result = runtime.lookupClientOffers(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
    });
    defer result.deinit();
    try std.testing.expect(result == .miss);
    try std.testing.expect(runtime.client_cache == null);
    try std.testing.expect(runtime.server_cache == null);
    try std.testing.expect(runtime.keyring == null);
    try std.testing.expectEqual(@as(usize, 0), entropy_ctx.calls);
}

test "stateful runtime resolves TDSH handles and misses TDTK/unknown prefixes" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateful },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();
    try std.testing.expect(runtime.client_cache != null);
    try std.testing.expect(runtime.server_cache != null);
    try std.testing.expect(runtime.keyring == null);

    var state = try sampleServerState(std.testing.allocator, "stateful.test");
    defer state.deinit();
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(.stored, runtime.server_cache.?.insertMove(&state, clock.now_ms, .reusable, &handle));

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(&handle);
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
    try std.testing.expect(hit.hit.lease == .owned);

    var unknown = try resolver.resolve("not-a-ticket");
    defer unknown.deinit();
    try std.testing.expect(unknown == .miss);

    var tdkt_like = [_]u8{0} ** (ticket_protection.fixed_header_len + ticket_protection.tag_len);
    @memcpy(tdkt_like[0..4], &ticket_protection.magic);
    tdkt_like[4] = ticket_protection.format_version;
    var wrong_mode = try resolver.resolve(&tdkt_like);
    defer wrong_mode.deinit();
    try std.testing.expect(wrong_mode == .miss);
}

test "stateless runtime resolves TDTK identities with a no-op lease across long-lived process time" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();
    try std.testing.expect(runtime.client_cache != null);
    try std.testing.expect(runtime.server_cache == null);
    try std.testing.expect(runtime.keyring != null);

    clock.now_ms = @as(i64, session.max_lifetime_seconds) * 1000 + 1234;
    var state = try sampleServerState(std.testing.allocator, "stateless.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    var protector = ticket_protection.Protector{
        .provider = runtime.provider,
        .keyring = &runtime.keyring.?,
        .limits = runtime.config.session_limits,
    };
    var ticket_buf = [_]u8{0} ** 1024;
    const ticket = try protector.seal(std.testing.allocator, &state, clock.now_ms, &ticket_buf);

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(ticket);
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
    try std.testing.expect(hit.hit.lease == .noop);

    var tampered_buf: [1024]u8 = undefined;
    @memcpy(tampered_buf[0..ticket.len], ticket);
    tampered_buf[ticket.len - 1] ^= 0x01;
    var tampered = try resolver.resolve(tampered_buf[0..ticket.len]);
    defer tampered.deinit();
    try std.testing.expect(tampered == .miss);
}

test "hybrid runtime dispatches TDSH and TDTK by prefix only" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .hybrid },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();
    try std.testing.expect(runtime.server_cache != null);
    try std.testing.expect(runtime.keyring != null);

    var stateful_state = try sampleServerState(std.testing.allocator, "hybrid-stateful.test");
    defer stateful_state.deinit();
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(.stored, runtime.server_cache.?.insertMove(&stateful_state, clock.now_ms, .reusable, &handle));

    var stateless_state = try sampleServerState(std.testing.allocator, "hybrid-stateless.test");
    defer stateless_state.deinit();
    var protector = ticket_protection.Protector{
        .provider = runtime.provider,
        .keyring = &runtime.keyring.?,
        .limits = runtime.config.session_limits,
    };
    var ticket_buf = [_]u8{0} ** 1024;
    const ticket = try protector.seal(std.testing.allocator, &stateless_state, clock.now_ms, &ticket_buf);

    const resolver = runtime.serverResolver().?;
    var stateful_hit = try resolver.resolve(&handle);
    defer stateful_hit.deinit();
    try std.testing.expect(stateful_hit == .hit);

    var stateless_hit = try resolver.resolve(ticket);
    defer stateless_hit.deinit();
    try std.testing.expect(stateless_hit == .hit);

    var malformed_tdsh = handle;
    malformed_tdsh[6] = 1; // reserved field must be zero, so this must not enter the cache path.
    var malformed = try resolver.resolve(&malformed_tdsh);
    defer malformed.deinit();
    try std.testing.expect(malformed == .miss);
}

test "stateless runtime initialization fails deterministically on entropy failure" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{ .fail = true };
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    try std.testing.expectError(error.EntropyFailure, Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless },
        clock.clock(),
        provider_impl.cryptoProvider(),
    ));
}

test "stateless runtime initialization fails without AES-128-GCM capability" {
    const UnsupportedProvider = struct {
        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }

        fn cryptoProvider(self: *@This()) provider.CryptoProvider {
            return .{ .context = self, .vtable = &vtable, .entropy = self.entropy() };
        }

        fn fill(_: *anyopaque, buffer: []u8) provider.EntropyError!void {
            @memset(buffer, 0x00);
        }

        fn capabilities(_: *anyopaque) provider.Capabilities {
            return .{};
        }

        fn hkdfExtract(_: *anyopaque, _: provider.Hash, _: []const u8, _: []const u8, _: []u8) provider.HkdfError!void {
            return error.UnsupportedCapability;
        }

        fn hkdfExpandLabel(_: *anyopaque, _: provider.Hash, _: []const u8, _: []const u8, _: []const u8, _: []u8) provider.HkdfError!void {
            return error.UnsupportedCapability;
        }

        fn aeadSeal(_: *anyopaque, _: provider.Aead, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: []u8, _: []u8) provider.SealError!void {
            return error.UnsupportedCapability;
        }

        fn aeadOpen(_: *anyopaque, _: provider.Aead, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: []u8) provider.OpenError!void {
            return error.UnsupportedCapability;
        }

        fn generateKeyShare(_: *anyopaque, _: provider.Group, _: []u8, _: []u8) provider.KeyShareError!void {
            return error.UnsupportedCapability;
        }

        fn deriveSharedSecret(_: *anyopaque, _: provider.Group, _: []const u8, _: []const u8, _: []u8) provider.DeriveError!void {
            return error.UnsupportedCapability;
        }

        fn verify(_: *anyopaque, _: provider.SignatureScheme, _: []const u8, _: []const u8, _: []const u8) provider.VerifyError!void {
            return error.UnsupportedCapability;
        }

        const vtable = provider.CryptoProvider.VTable{
            .capabilities = capabilities,
            .hkdfExtract = hkdfExtract,
            .hkdfExpandLabel = hkdfExpandLabel,
            .aeadSeal = aeadSeal,
            .aeadOpen = aeadOpen,
            .generateKeyShare = generateKeyShare,
            .deriveSharedSecret = deriveSharedSecret,
            .verify = verify,
        };
    };

    var clock = TestClock{};
    var unsupported = UnsupportedProvider{};
    try std.testing.expectError(error.ProviderUnsupported, Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless },
        clock.clock(),
        unsupported.cryptoProvider(),
    ));
}
