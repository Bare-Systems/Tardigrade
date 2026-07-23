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
const tls13_backend = @import("tls13_backend.zig");

const provider = crypto.provider;

pub const Mode = enum { disabled, stateful, stateless, hybrid };
pub const TicketUsage = enum { reusable, single_use };
pub const Transport = enum { record, quic };
pub const TicketResult = enum { success, rejected, failed };
pub const ResumptionOutcome = enum { accepted, full_handshake, incompatible, miss, fatal };

pub const Observer = struct {
    ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
    onTicketIssueFn: ?*const fn (*anyopaque, Transport, Mode, TicketResult) void = null,
    onTicketStoreFn: ?*const fn (*anyopaque, TicketResult) void = null,
    onTicketResolveFn: ?*const fn (*anyopaque, Mode, TicketResult) void = null,
    onResumptionAttemptFn: ?*const fn (*anyopaque, Transport) void = null,
    onResumptionOutcomeFn: ?*const fn (*anyopaque, Transport, ResumptionOutcome) void = null,

    pub fn ticketIssue(self: Observer, transport: Transport, mode: Mode, result: TicketResult) void {
        if (self.onTicketIssueFn) |f| f(self.ctx, transport, mode, result);
    }

    pub fn ticketStore(self: Observer, result: TicketResult) void {
        if (self.onTicketStoreFn) |f| f(self.ctx, result);
    }

    pub fn ticketResolve(self: Observer, mode: Mode, result: TicketResult) void {
        if (self.onTicketResolveFn) |f| f(self.ctx, mode, result);
    }

    pub fn resumptionAttempt(self: Observer, transport: Transport) void {
        if (self.onResumptionAttemptFn) |f| f(self.ctx, transport);
    }

    pub fn resumptionOutcome(self: Observer, transport: Transport, outcome: ResumptionOutcome) void {
        if (self.onResumptionOutcomeFn) |f| f(self.ctx, transport, outcome);
    }
};

var empty_observer_dummy: u8 = 0;

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
    observer: Observer = .{},

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
        const result = if (self.client_cache) |*cache|
            cache.storeClone(ticket, self.nowUnixMs(), usagePolicy(self.config.usage))
        else
            .rejected_capacity;
        self.observer.ticketStore(storeResultToTicketResult(result));
        return result;
    }

    pub fn setObserver(self: *Runtime, observer: Observer) void {
        self.observer = observer;
    }

    pub fn backendDecisionObserver(self: *Runtime, transport: Transport) tls13_backend.Tls13Backend.ResumptionDecisionObserver {
        return switch (transport) {
            .record => .{ .ctx = self, .onDecisionFn = backendRecordDecision },
            .quic => .{ .ctx = self, .onDecisionFn = backendQuicDecision },
        };
    }

    /// Safe upper bound on the wire length of an identity this runtime can
    /// produce (stateful handle or stateless envelope), for callers that
    /// need to size a scratch buffer before `createIdentity`. `0` while
    /// disabled.
    pub fn maxIdentityLen(self: *const Runtime) usize {
        var max: usize = 0;
        if (self.config.mode == .stateful or self.config.mode == .hybrid)
            max = @max(max, session_cache.stateful_identity_len);
        if (self.config.mode == .stateless or self.config.mode == .hybrid)
            max = @max(max, @min(
                self.config.session_limits.max_serialized_len + ticket_protection.envelope_overhead,
                self.config.session_limits.max_ticket_len,
            ));
        return max;
    }

    pub const IdentityMode = enum { stateful, stateless };

    /// The opaque bearer identity produced by `createIdentity`. `stateless`
    /// borrows the caller-supplied `scratch` buffer passed to
    /// `createIdentity`; `stateful` owns its bytes inline. Either way,
    /// `slice()` stays valid exactly as long as the `Identity` value (and,
    /// for `stateless`, its backing `scratch` buffer) does.
    pub const Identity = union(IdentityMode) {
        stateful: [session_cache.stateful_identity_len]u8,
        stateless: struct { buf: []u8, len: usize },

        pub fn slice(self: *const Identity) []const u8 {
            return switch (self.*) {
                .stateful => |*handle| handle[0..],
                .stateless => |s| s.buf[0..s.len],
            };
        }

        pub fn deinit(self: *Identity) void {
            switch (self.*) {
                .stateful => |*handle| crypto.secrets.secureZero(handle[0..]),
                .stateless => |s| crypto.secrets.secureZero(s.buf[0..s.len]),
            }
            self.* = undefined;
        }
    };

    pub const CreateIdentityError = error{
        StatefulCapacityRefused,
        StatefulStorageFailed,
        HandleGenerationFailed,
        SealFailed,
    };

    /// Consumes `state` — the exact prepared `ServerRecoverableState` from
    /// `Tls13Backend.prepareNewSessionTicket` — into this runtime's
    /// configured issuance storage and returns the resulting bearer
    /// identity. Stateful mode moves `state` into the server cache
    /// (`state.*` becomes zero-valued on success, so the caller's later
    /// unconditional `deinit` is then a no-op); stateless mode only reads
    /// `state` to seal it into `scratch` and leaves it fully owned by the
    /// caller either way. Hybrid prefers stateful issuance and falls back
    /// to stateless only for ordinary stateful capacity/storage refusal —
    /// never for a hard internal error.
    ///
    /// On any failure, `state.*` is left completely unchanged (never
    /// partially consumed), and no identity is left resolvable: the caller
    /// need not roll anything back.
    pub fn createIdentity(
        self: *Runtime,
        state: *session.ServerRecoverableState,
        now_unix_ms: i64,
        scratch: []u8,
    ) CreateIdentityError!Identity {
        return switch (self.config.mode) {
            .disabled => error.StatefulCapacityRefused,
            .stateful => self.createStatefulIdentity(state, now_unix_ms),
            .stateless => self.createStatelessIdentity(state, now_unix_ms, scratch),
            .hybrid => self.createStatefulIdentity(state, now_unix_ms) catch |err| switch (err) {
                error.StatefulCapacityRefused => self.createStatelessIdentity(state, now_unix_ms, scratch),
                else => err,
            },
        };
    }

    fn createStatefulIdentity(
        self: *Runtime,
        state: *session.ServerRecoverableState,
        now_unix_ms: i64,
    ) CreateIdentityError!Identity {
        const cache = if (self.server_cache) |*cache| cache else return error.StatefulCapacityRefused;
        var handle: [session_cache.stateful_identity_len]u8 = undefined;
        defer crypto.secrets.secureZero(handle[0..]);
        const result = cache.insertMove(state, now_unix_ms, usagePolicy(self.config.usage), &handle);
        return switch (result) {
            .stored => .{ .stateful = handle },
            .rejected_capacity => error.StatefulCapacityRefused,
            .storage_failed => error.StatefulStorageFailed,
            .rejected_handle_generation_failed => error.HandleGenerationFailed,
            .replaced, .rejected_unsupported_usage => unreachable,
        };
    }

    fn createStatelessIdentity(
        self: *Runtime,
        state: *const session.ServerRecoverableState,
        now_unix_ms: i64,
        scratch: []u8,
    ) CreateIdentityError!Identity {
        const keyring = if (self.keyring) |*keyring| keyring else return error.StatefulCapacityRefused;
        var protector = ticket_protection.Protector{
            .provider = self.provider,
            .keyring = keyring,
            .limits = self.config.session_limits,
        };
        const sealed = protector.seal(self.allocator, state, now_unix_ms, scratch) catch return error.SealFailed;
        return .{ .stateless = .{ .buf = scratch, .len = sealed.len } };
    }

    /// Rolls back an identity `createIdentity` produced but that never
    /// actually reached the peer (e.g. `NewSessionTicket` emission or
    /// queueing failed afterward): revokes a stateful handle from storage
    /// so it can never be offered back; a no-op for a stateless envelope
    /// (nothing was stored — the caller's own `scratch`/message buffers are
    /// the only copies, and wiping those remains the caller's concern).
    pub fn rollbackIdentity(self: *Runtime, identity: *const Identity) void {
        switch (identity.*) {
            .stateful => |*handle| if (self.server_cache) |*cache| cache.revokeHandle(handle),
            .stateless => {},
        }
    }

    fn resolverNow(ctx: *anyopaque) i64 {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        return self.nowUnixMs();
    }

    fn resolverResolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        const now = self.nowUnixMs();

        if (session_cache.isValidStatefulHandleShape(identity)) {
            if (self.server_cache) |*cache| {
                const result = session_cache.resolveStatefulServerPsk(cache, self.allocator, identity, now) catch |err| {
                    self.observer.ticketResolve(.stateful, .failed);
                    return err;
                };
                self.observer.ticketResolve(.stateful, if (result == .hit) .success else .rejected);
                return result;
            }
            self.observer.ticketResolve(.stateful, .rejected);
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
            const found = protector.resolve(self.allocator, identity, now, &state) catch {
                self.observer.ticketResolve(.stateless, .failed);
                return error.ResolverFailed;
            };
            if (!found) {
                self.observer.ticketResolve(.stateless, .rejected);
                return .miss;
            }
            self.observer.ticketResolve(.stateless, .success);
            return .{ .hit = .{ .state = state, .lease = pre_shared_key.ServerPskLease.initNoop() } };
        }

        self.observer.ticketResolve(self.config.mode, .rejected);
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

    fn backendRecordDecision(ctx: *anyopaque, decision: tls13_backend.Tls13Backend.ResumptionDecision) void {
        backendDecision(ctx, .record, decision);
    }

    fn backendQuicDecision(ctx: *anyopaque, decision: tls13_backend.Tls13Backend.ResumptionDecision) void {
        backendDecision(ctx, .quic, decision);
    }

    fn backendDecision(ctx: *anyopaque, transport: Transport, decision: tls13_backend.Tls13Backend.ResumptionDecision) void {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        self.observer.resumptionAttempt(transport);
        self.observer.resumptionOutcome(transport, switch (decision) {
            .accepted => .accepted,
            .miss => .miss,
            .incompatible => .incompatible,
            .full_handshake => .full_handshake,
            .fatal => .fatal,
        });
    }
};

fn usagePolicy(usage: TicketUsage) session_cache.UsagePolicy {
    return switch (usage) {
        .reusable => .reusable,
        .single_use => .single_use,
    };
}

pub fn storeResultToTicketResult(result: session_cache.StoreResult) TicketResult {
    return switch (result) {
        .stored, .replaced => .success,
        .rejected_capacity, .rejected_unsupported_usage => .rejected,
        .storage_failed, .rejected_handle_generation_failed => .failed,
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
    try (Config{ .mode = .stateful, .usage = .single_use }).validate();
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

const FailingHandleRandom = struct {
    fn source() session_cache.RandomSource {
        return .{ .ctx = @ptrCast(@constCast(&empty_observer_dummy)), .fillFn = fill };
    }

    fn fill(_: *anyopaque, _: []u8) error{EntropyFailure}!void {
        return error.EntropyFailure;
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

fn sampleClientTicket(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8) !session.ClientTicketState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xab} ** 32),
        .server_name = sni,
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 86_400,
    });
    var state: session.ClientTicketState = .{};
    try state.init(allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 1,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
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

test "stateful runtime accepts and offers single_use client tickets" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateful, .usage = .single_use },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    var ticket = try sampleClientTicket(std.testing.allocator, "single-runtime", "runtime.test");
    defer ticket.deinit();
    try std.testing.expectEqual(session_cache.StoreResult.stored, runtime.storeClientTicket(&ticket));

    var lookup = runtime.lookupClientOffers(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "runtime.test",
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
    });
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);
    try std.testing.expect(lookup.hit.active);
    try std.testing.expectEqual(@as(usize, 1), lookup.hit.offers.len);
    try std.testing.expectEqualStrings("single-runtime", lookup.hit.offers.constSlice()[0].ticket.slice());
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
    try std.testing.expect(hit.hit.lease == .noop);

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

test "createIdentity stateful issues a resolvable handle and consumes state" {
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

    var state = try sampleServerState(std.testing.allocator, "createidentity.test");
    var identity = try runtime.createIdentity(&state, clock.now_ms, &.{});
    // Successful stateful issuance moves `state` away; the caller's later
    // unconditional `deinit` must be a safe no-op rather than a double-free.
    state.deinit();

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(identity.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
    try std.testing.expectEqualStrings("createidentity.test", hit.hit.state.common.server_name.?.slice());
}

test "createIdentity stateless seals into caller scratch and does not consume state" {
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

    var state = try sampleServerState(std.testing.allocator, "stateless-identity.test");
    defer state.deinit();
    var scratch: [1024]u8 = undefined;
    var identity = try runtime.createIdentity(&state, clock.now_ms, &scratch);

    // Stateless issuance only reads `state` to seal it: it must remain
    // fully owned (and independently deinit-able) by the caller.
    try std.testing.expect(!std.mem.allEqual(u8, state.common.resumption_psk.slice(), 0));

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(identity.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
}

test "createIdentity hybrid falls back to stateless on ordinary stateful capacity refusal" {
    var clock = TestClock{};
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .hybrid, .server_cache_limits = .{
            .max_entries = 4,
            .max_origins = 4,
            .max_entries_per_origin = 4,
            .max_entry_bytes = 1,
            .max_total_bytes = 1024,
        } },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    var state = try sampleServerState(std.testing.allocator, "hybrid-fallback.test");
    defer state.deinit();
    var scratch: [1024]u8 = undefined;
    var identity = try runtime.createIdentity(&state, clock.now_ms, &scratch);
    try std.testing.expect(identity == .stateless);

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(identity.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
}

test "createIdentity hybrid does not fall back on stateful storage failure" {
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

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const original_allocator = runtime.server_cache.?.allocator;
    runtime.server_cache.?.allocator = failing.allocator();
    defer {
        runtime.server_cache.?.allocator = original_allocator;
    }

    var state = try sampleServerState(std.testing.allocator, "hybrid-storage-failed.test");
    defer state.deinit();
    var scratch = [_]u8{0} ** 1024;
    try std.testing.expectError(error.StatefulStorageFailed, runtime.createIdentity(&state, clock.now_ms, &scratch));
    try std.testing.expect(!std.mem.startsWith(u8, &scratch, &ticket_protection.magic));
}

test "createIdentity hybrid does not fall back on stateful handle generation failure" {
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

    runtime.server_cache.?.random = FailingHandleRandom.source();

    var state = try sampleServerState(std.testing.allocator, "hybrid-handle-failed.test");
    defer state.deinit();
    var scratch = [_]u8{0} ** 1024;
    try std.testing.expectError(error.HandleGenerationFailed, runtime.createIdentity(&state, clock.now_ms, &scratch));
    try std.testing.expect(!std.mem.startsWith(u8, &scratch, &ticket_protection.magic));
}

test "rollbackIdentity revokes a stateful handle so it no longer resolves" {
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

    var state = try sampleServerState(std.testing.allocator, "rollback.test");
    var identity = try runtime.createIdentity(&state, clock.now_ms, &.{});
    state.deinit();

    runtime.rollbackIdentity(&identity);

    const resolver = runtime.serverResolver().?;
    var miss = try resolver.resolve(identity.slice());
    defer miss.deinit();
    try std.testing.expect(miss == .miss);
}

test "rollbackIdentity is a no-op for a stateless envelope" {
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

    var state = try sampleServerState(std.testing.allocator, "stateless-rollback.test");
    defer state.deinit();
    var scratch: [1024]u8 = undefined;
    var identity = try runtime.createIdentity(&state, clock.now_ms, &scratch);
    runtime.rollbackIdentity(&identity);

    // Stateless issuance never stored anything server-side, so the exact
    // same envelope must still resolve after "rollback".
    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(identity.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
}

test "createIdentity disabled runtime reports typed stateful refusal" {
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

    var state = try sampleServerState(std.testing.allocator, "disabled.test");
    defer state.deinit();
    try std.testing.expectError(error.StatefulCapacityRefused, runtime.createIdentity(&state, clock.now_ms, &.{}));
}
