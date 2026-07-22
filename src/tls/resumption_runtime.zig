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
const secrets = crypto.secrets;

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
        if (self.ticket_lifetime_seconds == 0 or self.ticket_lifetime_seconds > session.max_lifetime_seconds)
            return error.InvalidConfig;
        self.session_limits.validate() catch return error.InvalidConfig;
        self.client_cache_limits.validate() catch return error.InvalidConfig;
        self.server_cache_limits.validate() catch return error.InvalidConfig;
    }
};

pub const InitError = error{ InvalidConfig, EntropyFailure, ProviderUnsupported, OutOfMemory };

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    config: Config,
    clock: Clock,
    provider: provider.CryptoProvider,
    client_cache: session_cache.ClientSessionCache,
    server_cache: session_cache.StatefulServerCache,
    keyring: ticket_protection.ReloadableKeyRing,
    stateless_key: [16]u8 = [_]u8{0} ** 16,

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
            .client_cache = session_cache.ClientSessionCache.init(allocator, config.client_cache_limits) catch return error.InvalidConfig,
            .server_cache = session_cache.StatefulServerCache.init(
                allocator,
                config.server_cache_limits,
                session_cache.system_random_source,
            ) catch return error.InvalidConfig,
            .keyring = ticket_protection.ReloadableKeyRing.init(allocator),
        };
        errdefer runtime.deinit();

        if (config.mode == .stateless or config.mode == .hybrid)
            try runtime.installEphemeralStatelessKey();

        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        self.keyring.deinit();
        self.server_cache.deinit();
        self.client_cache.deinit();
        secrets.secureZero(&self.stateless_key);
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
        if (self.config.mode == .disabled) return .miss;
        return self.client_cache.lookupOffers(candidate, self.nowUnixMs());
    }

    pub fn storeClientTicket(self: *Runtime, ticket: *const session.ClientTicketState) session_cache.StoreResult {
        if (self.config.mode == .disabled) return .rejected_capacity;
        return self.client_cache.storeClone(ticket, self.nowUnixMs(), usagePolicy(self.config.usage));
    }

    fn resolverNow(ctx: *anyopaque) i64 {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        return self.nowUnixMs();
    }

    fn resolverResolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        const now = self.nowUnixMs();

        if ((self.config.mode == .stateful or self.config.mode == .hybrid) and
            session_cache.isValidStatefulHandleShape(identity))
            return session_cache.resolveStatefulServerPsk(&self.server_cache, self.allocator, identity, now);

        if ((self.config.mode == .stateless or self.config.mode == .hybrid) and
            isStatelessIdentity(identity))
        {
            var protector = ticket_protection.Protector{
                .provider = self.provider,
                .keyring = &self.keyring,
                .limits = self.config.session_limits,
            };
            var state: session.ServerRecoverableState = .{};
            const found = protector.resolve(self.allocator, identity, now, &state) catch return error.ResolverFailed;
            if (!found) return .miss;
            return .{ .hit = .{ .state = state, .lease = pre_shared_key.ServerPskLease.noop() } };
        }

        return .miss;
    }

    fn installEphemeralStatelessKey(self: *Runtime) InitError!void {
        var key_id: ticket_protection.KeyId = undefined;
        var nonce_prefix: [4]u8 = undefined;
        self.provider.randomBytes(&key_id) catch return error.EntropyFailure;
        self.provider.randomBytes(&self.stateless_key) catch return error.EntropyFailure;
        self.provider.randomBytes(&nonce_prefix) catch return error.EntropyFailure;

        const now = self.nowUnixMs();
        const decrypt_until = checkedAddMs(now, @as(i64, session.max_lifetime_seconds) * 1000) orelse std.math.maxInt(i64);
        const config = ticket_protection.KeyConfig{
            .id = key_id,
            .aead = .aes_128_gcm,
            .key_bytes = &self.stateless_key,
            .not_before_unix_ms = now,
            .encrypt_until_unix_ms = decrypt_until,
            .decrypt_until_unix_ms = decrypt_until,
            .nonce_lease = .{ .prefix = nonce_prefix, .start = 0, .end_exclusive = std.math.maxInt(u64) },
        };
        const snapshot = self.keyring.buildSnapshot(&.{config}, self.provider.capabilities()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfig,
        };
        self.keyring.install(snapshot) catch |err| switch (err) {
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

fn checkedAddMs(a: i64, b: i64) ?i64 {
    return std.math.add(i64, a, b) catch null;
}

test "config validates ticket lifetime ceiling" {
    try std.testing.expectError(error.InvalidConfig, (Config{ .ticket_lifetime_seconds = 0 }).validate());
    try std.testing.expectError(error.InvalidConfig, (Config{ .ticket_lifetime_seconds = session.max_lifetime_seconds + 1 }).validate());
    try (Config{ .ticket_lifetime_seconds = session.max_lifetime_seconds }).validate();
}

test "disabled runtime exposes no server resolver and no client offers" {
    const TestClock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    const TestEntropy = struct {
        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
        fn fill(_: *anyopaque, buffer: []u8) provider.EntropyError!void {
            @memset(buffer, 0x44);
        }
    };
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{},
        .{ .ctx = &entropy_ctx, .nowUnixMsFn = TestClock.now },
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
}
