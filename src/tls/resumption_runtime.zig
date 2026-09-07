//! Process-shared native TLS 1.3 resumption runtime (#365).
//!
//! This module composes the transport-neutral cache, stateless ticket
//! protection, and resolver contracts. TCP record and QUIC/H3 adapters should
//! borrow one `Runtime` for the process and install only the resolver/consumer
//! handles exposed here; PSK parsing, binder verification, and key scheduling
//! stay in `tls13_backend.zig`.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const new_session_ticket = @import("new_session_ticket.zig");
const pre_shared_key = @import("pre_shared_key.zig");
const session = @import("session.zig");
const session_cache = @import("session_cache.zig");
const ticket_key_snapshot = @import("ticket_key_snapshot.zig");
const ticket_protection = @import("ticket_protection.zig");
const tls13_backend = @import("tls13_backend.zig");

const provider = crypto.provider;

pub const Mode = enum { disabled, stateful, stateless, hybrid };
pub const TicketUsage = enum { reusable, single_use };
pub const Transport = enum { record, quic };
pub const TicketResult = enum { success, rejected, failed };
pub const ResumptionOutcome = enum { accepted, full_handshake, incompatible, miss, fatal };
pub const StatelessTicketKeySource = enum { ephemeral, persistent };

pub const Observer = struct {
    ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
    onTicketIssueFn: ?*const fn (*anyopaque, Transport, Mode, TicketResult) void = null,
    onTicketStoreFn: ?*const fn (*anyopaque, TicketResult) void = null,
    onTicketResolveFn: ?*const fn (*anyopaque, Mode, TicketResult) void = null,
    onResumptionAttemptFn: ?*const fn (*anyopaque, Transport) void = null,
    onResumptionOutcomeFn: ?*const fn (*anyopaque, Transport, ResumptionOutcome) void = null,
    // #520: fires immediately before `loadPersistentTicketKeysFromFile`
    // calls `ticket_key_snapshot.reserveNonceLeasesInFile` -- whose very
    // first action is acquiring `${path}.lock` -- so an external observer
    // (a secret-free log line, in production) can mark the exact instant
    // this process is about to attempt that lock. Used by
    // `tests/integration.zig`'s multi-process startup-reservation soak to
    // wait for a real per-process arrival signal, on both processes,
    // before releasing a barrier lock it holds -- not a fixed delay that
    // could still let a slower process reach the attempt only after an
    // early release.
    onTicketKeyReservationAttemptFn: ?*const fn (*anyopaque) void = null,

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

    pub fn ticketKeyReservationAttempt(self: Observer) void {
        if (self.onTicketKeyReservationAttemptFn) |f| f(self.ctx);
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
    stateless_ticket_key_source: StatelessTicketKeySource = .ephemeral,

    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.ticket_lifetime_seconds == 0 or self.ticket_lifetime_seconds > session.max_lifetime_seconds)
            return error.InvalidConfig;
        if (self.mode != .disabled) {
            self.session_limits.validate() catch return error.InvalidConfig;
            self.client_cache_limits.validate() catch return error.InvalidConfig;
        }
        if (self.mode == .stateful or self.mode == .hybrid)
            self.server_cache_limits.validate() catch return error.InvalidConfig;
        if (self.stateless_ticket_key_source == .persistent and !(self.mode == .stateless or self.mode == .hybrid))
            return error.InvalidConfig;
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
    persistent_snapshot_fingerprint: ?[32]u8 = null,
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
            if (config.stateless_ticket_key_source == .ephemeral)
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

    pub fn installPersistentTicketKeys(
        self: *Runtime,
        generation: u64,
        configs: []const ticket_protection.KeyConfig,
    ) ticket_protection.SnapshotError!void {
        if (self.config.stateless_ticket_key_source != .persistent) return error.StaleSnapshotGeneration;
        const keyring = if (self.keyring) |*keyring| keyring else return error.TooManyKeys;
        const fingerprint = fingerprintPersistentTicketKeys(generation, configs);
        if (self.persistent_snapshot_fingerprint) |accepted| {
            if (std.mem.eql(u8, &accepted, &fingerprint)) return;
        }
        const snapshot = try ticket_protection.Snapshot.build(self.allocator, configs, generation, self.provider.capabilities());
        try keyring.install(snapshot);
        self.persistent_snapshot_fingerprint = fingerprint;
    }

    fn validatePersistentTicketKeys(
        self: *Runtime,
        generation: u64,
        configs: []const ticket_protection.KeyConfig,
    ) ticket_protection.SnapshotError!void {
        if (self.config.stateless_ticket_key_source != .persistent) return error.StaleSnapshotGeneration;
        const keyring = if (self.keyring) |*keyring| keyring else return error.TooManyKeys;
        const snapshot = try ticket_protection.Snapshot.build(self.allocator, configs, generation, self.provider.capabilities());
        defer snapshot.release();
        try keyring.validateInstallCandidate(snapshot);
    }

    pub fn loadPersistentTicketKeysFromFile(self: *Runtime, path: []const u8) (ticket_key_snapshot.LoadError || ticket_protection.SnapshotError)!void {
        var loaded = try ticket_key_snapshot.loadFromFile(self.allocator, path);
        defer loaded.deinit();
        const loaded_fingerprint = fingerprintPersistentTicketKeys(loaded.generation, loaded.configs);
        if (self.persistent_snapshot_fingerprint) |accepted| {
            if (std.mem.eql(u8, &accepted, &loaded_fingerprint)) return;
        }
        try self.validatePersistentTicketKeys(loaded.generation, loaded.configs);
        self.observer.ticketKeyReservationAttempt();
        try ticket_key_snapshot.reserveNonceLeasesInFile(self.allocator, path, &loaded, .{
            .ctx = self,
            .validateFn = validatePersistentTicketKeysForReservation,
        });
        try self.installPersistentTicketKeys(loaded.generation, loaded.configs);
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
        // Canonical helper, not `std.crypto.secureZero`: since #675 the two
        // are no longer the same primitive (see `crypto.secrets.secureZero`).
        defer crypto.secrets.secureZero(&key);
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

fn sampleEarlyDataServerState(allocator: std.mem.Allocator, sni: []const u8) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x43} ** 32),
        .server_name = sni,
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 86_400,
        .early_data = .{ .early_data_capable = 32 },
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = "ordinary-transport" },
        .early_data_transport_compat = .{ .format_id = 57, .format_version = 1, .bytes = "remembered-server-transport" },
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

fn validatePersistentTicketKeysForReservation(
    ctx: *anyopaque,
    generation: u64,
    configs: []const ticket_protection.KeyConfig,
) ticket_protection.SnapshotError!void {
    const runtime: *Runtime = @ptrCast(@alignCast(ctx));
    try runtime.validatePersistentTicketKeys(generation, configs);
}

fn fingerprintPersistentTicketKeys(generation: u64, configs: []const ticket_protection.KeyConfig) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    defer crypto.secrets.secureZero(std.mem.asBytes(&hasher));
    hasher.update("tardigrade/tls-persistent-ticket-snapshot/v1\x00");

    var int_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &int_buf, generation, .big);
    hasher.update(&int_buf);
    std.mem.writeInt(u64, &int_buf, configs.len, .big);
    hasher.update(&int_buf);

    for (configs) |cfg| {
        hasher.update(&cfg.id);
        hasher.update(&[_]u8{@intFromEnum(cfg.aead)});
        std.mem.writeInt(u64, &int_buf, cfg.key_bytes.len, .big);
        hasher.update(&int_buf);
        hasher.update(cfg.key_bytes);
        std.mem.writeInt(i64, &int_buf, cfg.not_before_unix_ms, .big);
        hasher.update(&int_buf);
        std.mem.writeInt(i64, &int_buf, cfg.encrypt_until_unix_ms, .big);
        hasher.update(&int_buf);
        std.mem.writeInt(i64, &int_buf, cfg.decrypt_until_unix_ms, .big);
        hasher.update(&int_buf);
        if (cfg.nonce_lease) |lease| {
            hasher.update(&[_]u8{1});
            hasher.update(&lease.prefix);
        } else {
            hasher.update(&[_]u8{0});
        }
    }

    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

const TestTicketKey = struct {
    id: ticket_protection.KeyId,
    key: [16]u8,
};

fn testTicketKey(id_byte: u8, key_byte: u8) TestTicketKey {
    return .{
        .id = [_]u8{id_byte} ** ticket_protection.key_id_len,
        .key = [_]u8{key_byte} ** 16,
    };
}

fn persistentKeyConfig(key: *const TestTicketKey, not_before: i64, encrypt_until: i64, decrypt_until: i64, lease: ?ticket_protection.NonceLeaseConfig) ticket_protection.KeyConfig {
    return .{
        .id = key.id,
        .aead = .aes_128_gcm,
        .key_bytes = &key.key,
        .not_before_unix_ms = not_before,
        .encrypt_until_unix_ms = encrypt_until,
        .decrypt_until_unix_ms = decrypt_until,
        .nonce_lease = lease,
    };
}

fn expectTicketKeyId(identity: []const u8, expected: *const ticket_protection.KeyId) !void {
    try std.testing.expect(std.mem.eql(u8, identity[0..4], &ticket_protection.magic));
    try std.testing.expectEqualSlices(u8, expected, identity[8..24]);
}

fn expectTicketNonceCounter(identity: []const u8, expected: u64) !void {
    try std.testing.expectEqual(expected, ticketNonceCounter(identity));
}

fn ticketNonceCounter(identity: []const u8) u64 {
    return std.mem.readInt(u64, identity[28..36], .big);
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
    try std.testing.expect(hit.hit.current_process_stateful);

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
    try std.testing.expect(!hit.hit.current_process_stateful);

    var tampered_buf: [1024]u8 = undefined;
    @memcpy(tampered_buf[0..ticket.len], ticket);
    tampered_buf[ticket.len - 1] ^= 0x01;
    var tampered = try resolver.resolve(tampered_buf[0..ticket.len]);
    defer tampered.deinit();
    try std.testing.expect(tampered == .miss);
}

test "#512 persistent stateless runtime loads configured keys, rotates, and retires old tickets" {
    var clock = TestClock{ .now_ms = 1_000 };
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();
    try std.testing.expect(runtime.keyring != null);
    try std.testing.expect(runtime.keyring.?.current == null);

    const key_n = testTicketKey(0x10, 0xa0);
    const key_np1 = testTicketKey(0x11, 0xb0);
    try runtime.installPersistentTicketKeys(1, &.{
        persistentKeyConfig(&key_n, 1_000, 2_000, 5_000, .{ .prefix = .{ 1, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }),
    });

    var n_state = try sampleServerState(std.testing.allocator, "persistent-n.test");
    defer n_state.deinit();
    n_state.common.issued_at_unix_ms = clock.now_ms;
    n_state.common.lifetime_seconds = 3;
    var n_scratch: [1024]u8 = undefined;
    var n_identity = try runtime.createIdentity(&n_state, clock.now_ms, &n_scratch);
    try expectTicketKeyId(n_identity.slice(), &key_n.id);
    try expectTicketNonceCounter(n_identity.slice(), 0);

    clock.now_ms = 2_000;
    try runtime.installPersistentTicketKeys(2, &.{
        persistentKeyConfig(&key_n, 1_000, 2_000, 5_000, null),
        persistentKeyConfig(&key_np1, 2_000, 9_000, 12_000, .{ .prefix = .{ 2, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }),
    });

    var np1_state = try sampleServerState(std.testing.allocator, "persistent-np1.test");
    defer np1_state.deinit();
    np1_state.common.issued_at_unix_ms = clock.now_ms;
    np1_state.common.lifetime_seconds = 3;
    var np1_scratch: [1024]u8 = undefined;
    var np1_identity = try runtime.createIdentity(&np1_state, clock.now_ms, &np1_scratch);
    try expectTicketKeyId(np1_identity.slice(), &key_np1.id);
    try expectTicketNonceCounter(np1_identity.slice(), 0);

    const resolver = runtime.serverResolver().?;
    var old_grace_hit = try resolver.resolve(n_identity.slice());
    defer old_grace_hit.deinit();
    try std.testing.expect(old_grace_hit == .hit);

    clock.now_ms = 5_000;
    var old_retired = try resolver.resolve(n_identity.slice());
    defer old_retired.deinit();
    try std.testing.expect(old_retired == .miss);

    clock.now_ms = 9_000;
    try std.testing.expectError(error.SealFailed, runtime.createIdentity(&np1_state, clock.now_ms, &np1_scratch));
}

test "#512 failed persistent ticket-key reload leaves previous production runtime snapshot active" {
    var clock = TestClock{ .now_ms = 1_000 };
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    const key = testTicketKey(0x20, 0xc0);
    try runtime.installPersistentTicketKeys(1, &.{
        persistentKeyConfig(&key, 1_000, 5_000, 10_000, .{ .prefix = .{ 3, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }),
    });

    var state = try sampleServerState(std.testing.allocator, "failed-reload.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    state.common.lifetime_seconds = 3;
    var scratch: [1024]u8 = undefined;
    var before = try runtime.createIdentity(&state, clock.now_ms, &scratch);
    try expectTicketNonceCounter(before.slice(), 0);

    try std.testing.expectError(error.OverlappingNonceLease, runtime.installPersistentTicketKeys(2, &.{
        persistentKeyConfig(&key, 1_000, 5_000, 10_000, .{ .prefix = .{ 3, 0, 0, 0 }, .start = 5, .end_exclusive = 15 }),
    }));

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(before.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);

    var after_scratch: [1024]u8 = undefined;
    var after = try runtime.createIdentity(&state, clock.now_ms, &after_scratch);
    try expectTicketKeyId(after.slice(), &key.id);
    try expectTicketNonceCounter(after.slice(), 1);
}

test "#512 unchanged persistent ticket-key reload preserves live nonce cursor" {
    var clock = TestClock{ .now_ms = 1_000 };
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    const key = testTicketKey(0x28, 0xc8);
    const configs = [_]ticket_protection.KeyConfig{
        persistentKeyConfig(&key, 1_000, 5_000, 10_000, .{ .prefix = .{ 8, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }),
    };
    try runtime.installPersistentTicketKeys(1, &configs);

    var state = try sampleServerState(std.testing.allocator, "unchanged-reload.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    state.common.lifetime_seconds = 3;
    var scratch: [1024]u8 = undefined;
    var first = try runtime.createIdentity(&state, clock.now_ms, &scratch);
    try expectTicketNonceCounter(first.slice(), 0);

    try runtime.installPersistentTicketKeys(1, &configs);

    var after_scratch: [1024]u8 = undefined;
    var second = try runtime.createIdentity(&state, clock.now_ms, &after_scratch);
    try expectTicketKeyId(second.slice(), &key.id);
    try expectTicketNonceCounter(second.slice(), 1);
}

test "#512 persistent stateless restart resumes old tickets and advances nonce lease" {
    var clock = TestClock{ .now_ms = 1_000 };
    const key = testTicketKey(0x30, 0xd0);

    var entropy_a = TestEntropy{};
    var provider_a = crypto.pure_zig.Provider.init(entropy_a.entropy());
    var runtime_a = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_a.cryptoProvider(),
    );
    defer runtime_a.deinit();
    try runtime_a.installPersistentTicketKeys(1, &.{
        persistentKeyConfig(&key, 1_000, 5_000, 20_000, .{ .prefix = .{ 4, 0, 0, 0 }, .start = 0, .end_exclusive = 1 }),
    });

    var state = try sampleServerState(std.testing.allocator, "persistent-restart.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    state.common.lifetime_seconds = 3;
    var scratch_a: [1024]u8 = undefined;
    var identity_a = try runtime_a.createIdentity(&state, clock.now_ms, &scratch_a);
    try expectTicketNonceCounter(identity_a.slice(), 0);

    var entropy_b = TestEntropy{};
    var provider_b = crypto.pure_zig.Provider.init(entropy_b.entropy());
    var runtime_b = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_b.cryptoProvider(),
    );
    defer runtime_b.deinit();
    try runtime_b.installPersistentTicketKeys(1, &.{
        persistentKeyConfig(&key, 1_000, 5_000, 20_000, .{ .prefix = .{ 4, 0, 0, 0 }, .start = 1, .end_exclusive = 2 }),
    });

    const resolver_b = runtime_b.serverResolver().?;
    var resumed = try resolver_b.resolve(identity_a.slice());
    defer resumed.deinit();
    try std.testing.expect(resumed == .hit);

    var scratch_b: [1024]u8 = undefined;
    var identity_b = try runtime_b.createIdentity(&state, clock.now_ms, &scratch_b);
    try expectTicketNonceCounter(identity_b.slice(), 1);
}

test "#512 persistent file load durably advances nonce lease across sequential runtimes" {
    var clock = TestClock{ .now_ms = 1_000 };
    const path = ".zig-cache/persistent-ticket-lease-reservation-test.json";
    const json =
        \\{"version":1,"generation":1,"keys":[{"id":"30303030303030303030303030303030","aead":"aes_128_gcm","key":"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":20000,"nonce_lease":{"prefix":"09000000","start":0,"end_exclusive":1}}]}
    ;
    try compat.cwd().writeFile(.{ .sub_path = path, .data = json });
    if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
        var file = try compat.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        if (std.c.fchmod(file.file.handle, 0o600) != 0) return error.PermissionDenied;
    }
    defer compat.cwd().deleteFile(path) catch {};
    defer compat.cwd().deleteFile(".zig-cache/persistent-ticket-lease-reservation-test.json.lock") catch {};

    const key = testTicketKey(0x30, 0xd0);
    var state = try sampleServerState(std.testing.allocator, "persistent-file-restart.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    state.common.lifetime_seconds = 3;

    var entropy_a = TestEntropy{};
    var provider_a = crypto.pure_zig.Provider.init(entropy_a.entropy());
    var runtime_a = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_a.cryptoProvider(),
    );
    defer runtime_a.deinit();
    try runtime_a.loadPersistentTicketKeysFromFile(path);
    var scratch_a: [1024]u8 = undefined;
    var identity_a = try runtime_a.createIdentity(&state, clock.now_ms, &scratch_a);
    try expectTicketKeyId(identity_a.slice(), &key.id);
    try expectTicketNonceCounter(identity_a.slice(), 1);

    var entropy_b = TestEntropy{};
    var provider_b = crypto.pure_zig.Provider.init(entropy_b.entropy());
    var runtime_b = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_b.cryptoProvider(),
    );
    defer runtime_b.deinit();
    try runtime_b.loadPersistentTicketKeysFromFile(path);
    const resolver_b = runtime_b.serverResolver().?;
    var resumed = try resolver_b.resolve(identity_a.slice());
    defer resumed.deinit();
    try std.testing.expect(resumed == .hit);

    var scratch_b: [1024]u8 = undefined;
    var identity_b = try runtime_b.createIdentity(&state, clock.now_ms, &scratch_b);
    try expectTicketKeyId(identity_b.slice(), &key.id);
    try expectTicketNonceCounter(identity_b.slice(), 2);
    if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
        const stat = try compat.cwd().statFile(path);
        try std.testing.expectEqual(@as(std.posix.mode_t, 0), stat.permissions.toMode() & 0o077);
    }
}

test "#512 invalid persistent ticket-key candidate does not mutate durable lease state" {
    var clock = TestClock{ .now_ms = 1_000 };
    const path = ".zig-cache/persistent-ticket-invalid-reservation-test.json";
    const json =
        \\{"version":1,"generation":1,"keys":[{"id":"31313131313131313131313131313131","aead":"aes_128_gcm","key":"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":20000,"nonce_lease":{"prefix":"0a000000","start":0,"end_exclusive":1}},{"id":"31313131313131313131313131313131","aead":"aes_128_gcm","key":"d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":20000,"nonce_lease":{"prefix":"0b000000","start":0,"end_exclusive":1}}]}
    ;
    try compat.cwd().writeFile(.{ .sub_path = path, .data = json });
    if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
        var file = try compat.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        if (std.c.fchmod(file.file.handle, 0o600) != 0) return error.PermissionDenied;
    }
    defer compat.cwd().deleteFile(path) catch {};
    defer compat.cwd().deleteFile(".zig-cache/persistent-ticket-invalid-reservation-test.json.lock") catch {};

    const before = try compat.cwd().readFileAlloc(std.testing.allocator, path, ticket_key_snapshot.max_snapshot_bytes);
    defer std.testing.allocator.free(before);

    var entropy = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    try std.testing.expectError(error.DuplicateKeyId, runtime.loadPersistentTicketKeysFromFile(path));

    const after = try compat.cwd().readFileAlloc(std.testing.allocator, path, ticket_key_snapshot.max_snapshot_bytes);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "#512 competing persistent file reservations issue disjoint nonce counters" {
    var clock = TestClock{ .now_ms = 1_000 };
    const path = ".zig-cache/persistent-ticket-competing-reservation-test.json";
    const json =
        \\{"version":1,"generation":1,"keys":[{"id":"32323232323232323232323232323232","aead":"aes_128_gcm","key":"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":20000,"nonce_lease":{"prefix":"0c000000","start":0,"end_exclusive":1}}]}
    ;
    try compat.cwd().writeFile(.{ .sub_path = path, .data = json });
    if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
        var file = try compat.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        if (std.c.fchmod(file.file.handle, 0o600) != 0) return error.PermissionDenied;
    }
    defer compat.cwd().deleteFile(path) catch {};
    defer compat.cwd().deleteFile(".zig-cache/persistent-ticket-competing-reservation-test.json.lock") catch {};

    var entropy_a = TestEntropy{};
    var provider_a = crypto.pure_zig.Provider.init(entropy_a.entropy());
    var runtime_a = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_a.cryptoProvider(),
    );
    defer runtime_a.deinit();
    var entropy_b = TestEntropy{};
    var provider_b = crypto.pure_zig.Provider.init(entropy_b.entropy());
    var runtime_b = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_b.cryptoProvider(),
    );
    defer runtime_b.deinit();

    var state_a = try sampleServerState(std.testing.allocator, "persistent-competing-a.test");
    defer state_a.deinit();
    state_a.common.issued_at_unix_ms = clock.now_ms;
    state_a.common.lifetime_seconds = 3;
    var state_b = try sampleServerState(std.testing.allocator, "persistent-competing-b.test");
    defer state_b.deinit();
    state_b.common.issued_at_unix_ms = clock.now_ms;
    state_b.common.lifetime_seconds = 3;

    const Worker = struct {
        runtime: *Runtime,
        state: *session.ServerRecoverableState,
        path: []const u8,
        start: *std.atomic.Value(bool),
        failed: *std.atomic.Value(bool),
        counter: *std.atomic.Value(u64),

        fn run(self: *@This()) void {
            while (!self.start.load(.acquire)) std.Thread.yield() catch {};
            self.runtime.loadPersistentTicketKeysFromFile(self.path) catch {
                self.failed.store(true, .release);
                return;
            };
            var scratch: [1024]u8 = undefined;
            var identity = self.runtime.createIdentity(self.state, 1_000, &scratch) catch {
                self.failed.store(true, .release);
                return;
            };
            self.counter.store(ticketNonceCounter(identity.slice()), .release);
        }
    };

    var start = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    var counter_a = std.atomic.Value(u64).init(std.math.maxInt(u64));
    var counter_b = std.atomic.Value(u64).init(std.math.maxInt(u64));
    var worker_a = Worker{ .runtime = &runtime_a, .state = &state_a, .path = path, .start = &start, .failed = &failed, .counter = &counter_a };
    var worker_b = Worker{ .runtime = &runtime_b, .state = &state_b, .path = path, .start = &start, .failed = &failed, .counter = &counter_b };
    const thread_a = try std.Thread.spawn(.{}, Worker.run, .{&worker_a});
    const thread_b = try std.Thread.spawn(.{}, Worker.run, .{&worker_b});
    start.store(true, .release);
    thread_a.join();
    thread_b.join();

    try std.testing.expect(!failed.load(.acquire));
    const a = counter_a.load(.acquire);
    const b = counter_b.load(.acquire);
    try std.testing.expect(a == 1 or a == 2);
    try std.testing.expect(b == 1 or b == 2);
    try std.testing.expect(a != b);

    var reserved = try ticket_key_snapshot.loadFromFile(std.testing.allocator, path);
    defer reserved.deinit();
    try std.testing.expectEqual(@as(u64, 2), reserved.configs[0].nonce_lease.?.start);
    try std.testing.expectEqual(@as(u64, 3), reserved.configs[0].nonce_lease.?.end_exclusive);
}

test "#512 persistent stateless runtime issues while publishing adjacent rotations concurrently" {
    var clock = TestClock{ .now_ms = 1_000 };
    var entropy_ctx = TestEntropy{};
    var provider_impl = crypto.pure_zig.Provider.init(entropy_ctx.entropy());
    var runtime = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless, .stateless_ticket_key_source = .persistent },
        clock.clock(),
        provider_impl.cryptoProvider(),
    );
    defer runtime.deinit();

    const key = testTicketKey(0x40, 0xe0);
    try runtime.installPersistentTicketKeys(1, &.{
        persistentKeyConfig(&key, 1_000, 10_000, 20_000, .{ .prefix = .{ 5, 0, 0, 0 }, .start = 0, .end_exclusive = 1_000 }),
    });
    var state = try sampleServerState(std.testing.allocator, "persistent-concurrent.test");
    defer state.deinit();
    state.common.issued_at_unix_ms = clock.now_ms;
    state.common.lifetime_seconds = 3;

    const Issuer = struct {
        runtime: *Runtime,
        state: *session.ServerRecoverableState,
        successes: *std.atomic.Value(usize),

        fn run(self: *@This()) void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                var scratch: [1024]u8 = undefined;
                var identity = self.runtime.createIdentity(self.state, 1_000, &scratch) catch continue;
                if (std.mem.eql(u8, identity.slice()[0..4], &ticket_protection.magic))
                    _ = self.successes.fetchAdd(1, .acq_rel);
            }
        }
    };
    const Rotator = struct {
        runtime: *Runtime,
        key: *const TestTicketKey,
        failures: *std.atomic.Value(usize),

        fn run(self: *@This()) void {
            var generation: u64 = 2;
            while (generation < 20) : (generation += 1) {
                const start = (generation - 1) * 1_000;
                self.runtime.installPersistentTicketKeys(generation, &.{
                    persistentKeyConfig(self.key, 1_000, 10_000, 20_000, .{ .prefix = .{ 5, 0, 0, 0 }, .start = start, .end_exclusive = start + 1_000 }),
                }) catch {
                    _ = self.failures.fetchAdd(1, .acq_rel);
                };
            }
        }
    };

    var successes = std.atomic.Value(usize).init(0);
    var failures = std.atomic.Value(usize).init(0);
    var issuers: [4]Issuer = undefined;
    var issuer_threads: [4]std.Thread = undefined;
    for (&issuers, 0..) |*issuer, i| {
        issuer.* = .{ .runtime = &runtime, .state = &state, .successes = &successes };
        issuer_threads[i] = try std.Thread.spawn(.{}, Issuer.run, .{issuer});
    }
    var rotator = Rotator{ .runtime = &runtime, .key = &key, .failures = &failures };
    const rotator_thread = try std.Thread.spawn(.{}, Rotator.run, .{&rotator});
    for (&issuer_threads) |thread| thread.join();
    rotator_thread.join();

    try std.testing.expectEqual(@as(usize, 0), failures.load(.acquire));
    try std.testing.expect(successes.load(.acquire) > 0);
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

        fn quicHeaderProtectionMask(_: *anyopaque, _: provider.QuicHeaderProtection, _: []const u8, _: []const u8, _: []u8) provider.QuicHeaderProtectionError!void {
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
            .quicHeaderProtectionMask = quicHeaderProtectionMask,
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

test "createIdentity stateless preserves early-data transport compatibility" {
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

    var state = try sampleEarlyDataServerState(std.testing.allocator, "early-stateless.test");
    defer state.deinit();
    var scratch: [2048]u8 = undefined;
    var identity = try runtime.createIdentity(&state, clock.now_ms, &scratch);

    const resolver = runtime.serverResolver().?;
    var hit = try resolver.resolve(identity.slice());
    defer hit.deinit();
    try std.testing.expect(hit == .hit);
    try std.testing.expectEqualStrings("ordinary-transport", hit.hit.state.common.transport_compat.?.slice());
    const early_transport = hit.hit.state.common.early_data_transport_compat orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u16, 57), early_transport.format_id);
    try std.testing.expectEqual(@as(u16, 1), early_transport.format_version);
    try std.testing.expectEqualStrings("remembered-server-transport", early_transport.slice());
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

test "restart: a stateless identity issued by one process is unresolvable by a fresh process with no shared state (#369)" {
    var clock = TestClock{};

    var entropy_a = TestEntropy{ .byte = 0x10 };
    var provider_a = crypto.pure_zig.Provider.init(entropy_a.entropy());
    var runtime_a = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless },
        clock.clock(),
        provider_a.cryptoProvider(),
    );
    defer runtime_a.deinit();

    var state = try sampleServerState(std.testing.allocator, "restart-stateless.test");
    defer state.deinit();
    var scratch: [1024]u8 = undefined;
    const identity = try runtime_a.createIdentity(&state, clock.now_ms, &scratch);

    // A fresh process: an independent entropy source feeding an independent
    // `Runtime.init` call, so its ephemeral stateless key
    // (`installEphemeralStatelessKey`) shares no key material with
    // `runtime_a`'s — exactly what a real restart looks like.
    var entropy_b = TestEntropy{ .byte = 0x99 };
    var provider_b = crypto.pure_zig.Provider.init(entropy_b.entropy());
    var runtime_b = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateless },
        clock.clock(),
        provider_b.cryptoProvider(),
    );
    defer runtime_b.deinit();

    const resolver = runtime_b.serverResolver().?;
    var miss = try resolver.resolve(identity.slice());
    defer miss.deinit();
    try std.testing.expect(miss == .miss);
}

test "restart: a stateful handle issued by one process is unresolvable by a fresh process with an empty cache (#369)" {
    var clock = TestClock{};

    var entropy_a = TestEntropy{ .byte = 0x21 };
    var provider_a = crypto.pure_zig.Provider.init(entropy_a.entropy());
    var runtime_a = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateful },
        clock.clock(),
        provider_a.cryptoProvider(),
    );
    defer runtime_a.deinit();

    var state = try sampleServerState(std.testing.allocator, "restart-stateful.test");
    const identity = try runtime_a.createIdentity(&state, clock.now_ms, &.{});
    state.deinit();

    // A fresh process with its own empty stateful cache — no knowledge of
    // any handle `runtime_a` ever issued.
    var entropy_b = TestEntropy{ .byte = 0x88 };
    var provider_b = crypto.pure_zig.Provider.init(entropy_b.entropy());
    var runtime_b = try Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateful },
        clock.clock(),
        provider_b.cryptoProvider(),
    );
    defer runtime_b.deinit();

    const resolver = runtime_b.serverResolver().?;
    var miss = try resolver.resolve(identity.slice());
    defer miss.deinit();
    try std.testing.expect(miss == .miss);
}
