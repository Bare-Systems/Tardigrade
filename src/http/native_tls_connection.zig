const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");
const tls = @import("tls_core");
const encrypted_stream_connection = @import("encrypted_stream_connection.zig");
const event_loop = @import("event_loop.zig");
const negotiated_dispatch = @import("negotiated_dispatch.zig");

const encrypted_stream = tls.encrypted_stream;
const production_crypto = tls.production_crypto;
const tls_backend = tls.tls13_backend;
const sni_provider = tls.sni_provider;
const credentials = tls.credentials;
const webpki_verifier = tls.webpki_verifier;
const client_identity = tls.client_identity;

pub const ListenerProtocolPolicy = negotiated_dispatch.ListenerProtocolPolicy;
pub const NegotiatedProtocol = negotiated_dispatch.NegotiatedProtocol;

pub const SniCertSpec = struct {
    server_name: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
};

/// One ACME-managed group's already-verified chain and leaf key, owned by
/// the caller as in-memory bytes rather than files (#880). The A4
/// persistence ticket (`acme.activate.verifyChain`/`verifyAndPersist`) is
/// the intended source: `chain_pem` is the exact leaf-first PEM chain it
/// verified, and `key_pem` is the matching leaf key re-encoded via
/// `LeafKey.toPkcs8Pem`. Neither is re-verified here -- this store only
/// parses and publishes what has already been judged safe to activate.
/// `hostnames` must be the group's exact managed names (no wildcards;
/// HTTP-01 never issues for one) and must exactly match the hostnames of
/// any later call for the same group, otherwise the two are treated as
/// unrelated groups, not a rotation.
pub const ManagedBundleSpec = struct {
    hostnames: []const []const u8,
    chain_pem: []const u8,
    key_pem: []const u8,
};

/// Downstream client-certificate trust anchors (#763); shared with HTTP/3.
pub const ClientTrustStore = tls.client_trust.ClientTrustStore;
pub const ClientPolicySet = tls.client_trust.PolicySet;
pub const ClientPolicySnapshot = tls.client_trust.PolicySnapshot;

pub const NativeCredentialStore = struct {
    allocator: std.mem.Allocator,
    provider_state: sni_provider.ReloadableProvider,
    entropy_source: production_crypto.OsEntropy = .{},
    /// Whether the currently-installed generation carries any managed (ACME)
    /// bundle, set from `PreparedReload.has_managed_bundles` on every
    /// successful `commitPreparedReload`. Exists so a file-only reload can
    /// refuse to silently replace an active managed generation with a
    /// manual-only one -- `gateway_shutdown.hotReloadConfig` (#884) rebuilds
    /// the complete persisted managed set and calls
    /// `prepareReloadFromBundles` instead of `prepareReloadFromFiles`
    /// whenever ACME is enabled, precisely so a routine file-only reload
    /// never looks like every managed group vanished (#880).
    ///
    /// The authoritative check lives in `commitPreparedReload`'s critical
    /// section below, guarded by `commit_mutex` alongside the `install()`
    /// call and this flag's update, so a file-only `PreparedReload` can
    /// never publish over a managed generation that activated after it was
    /// prepared (a time-of-check/time-of-use gap a prepare-time-only check
    /// would leave open). `prepareReloadFromFiles` still reads this
    /// atomically for a cheap, non-authoritative fail-fast.
    has_managed_bundles: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// The config generation whose manual default/SNI inputs were used to
    /// build the installed snapshot.  An ACME worker may finish long after a
    /// SIGHUP has rotated those inputs; it must not install its old view over
    /// that newer generation.
    manual_config_generation: u64 = 0,
    /// Serializes the commit critical section (the managed-active check,
    /// `provider_state.install`, and the `has_managed_bundles` update) so
    /// the three happen as one atomic step from the perspective of any
    /// other committer. File parsing, CA I/O, and snapshot building all
    /// happen in `prepareReload*` before this mutex is ever touched.
    commit_mutex: compat.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) NativeCredentialStore {
        return .{
            .allocator = allocator,
            .provider_state = sni_provider.ReloadableProvider.init(allocator),
            .entropy_source = .{},
        };
    }

    pub fn provider(self: *NativeCredentialStore) credentials.CredentialProvider {
        return self.provider_state.provider();
    }

    pub fn deinit(self: *NativeCredentialStore) void {
        self.provider_state.deinit();
        self.* = undefined;
    }

    pub fn reloadFromFiles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
    ) !void {
        var prepared = try self.prepareReloadFromFiles(default_cert_path, default_key_path, sni_certs);
        defer prepared.deinit();
        try self.commitPreparedReload(&prepared);
    }

    pub const PreparedReload = struct {
        snapshot: ?*sni_provider.Snapshot,
        has_managed_bundles: bool = false,
        /// Zero is for callers not associated with a reloadable gateway
        /// configuration (unit tests and one-shot stores).
        manual_config_generation: u64 = 0,
        /// Set only by `prepareReloadFromFiles`. A deliberate empty managed
        /// set published through `prepareReloadFromBundles` (`&.{}`) is NOT
        /// file-only: it is the caller's explicit declaration that the
        /// managed set has legitimately gone empty, and must still clear
        /// `has_managed_bundles` on commit.
        file_only: bool = false,

        pub fn deinit(self: *PreparedReload) void {
            if (self.snapshot) |snapshot| snapshot.release();
            self.* = undefined;
        }
    };

    /// File-only reload: never carries a managed bundle, so it must refuse
    /// to replace a generation that currently has one -- otherwise an
    /// ordinary config-file SIGHUP (routed here by
    /// `gateway_shutdown.hotReloadConfig`, which knows nothing about managed
    /// bundles) would silently drop every ACME-issued identity the moment it
    /// ran. Callers that manage ACME credentials must publish through
    /// `prepareReloadFromBundles`/`reloadFromBundles` instead, re-passing the
    /// complete current managed set every time (see that function's doc
    /// comment).
    ///
    /// This early check is a cheap, non-authoritative fail-fast only -- it
    /// cannot see a managed reload that activates *after* this call returns
    /// but *before* the resulting `PreparedReload` is committed. The
    /// authoritative check that closes that race lives in
    /// `commitPreparedReload`.
    pub fn prepareReloadFromFiles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
    ) !PreparedReload {
        if (self.has_managed_bundles.load(.acquire)) return error.ManagedCredentialsActive;
        var prepared = try self.prepareReloadFromFilesAndBundles(default_cert_path, default_key_path, sni_certs, &.{});
        prepared.file_only = true;
        return prepared;
    }

    /// Bytes-based sibling of `prepareReloadFromFiles` (#880): builds the
    /// same default/manual-SNI bundles from files, plus one bundle per
    /// `managed_bundles` entry loaded from owned in-memory bytes, into a
    /// single `Snapshot` committed through the same `commitPreparedReload`.
    /// There is no separate managed-credential store or selector -- this
    /// composes exactly the `sni_provider.ReloadableProvider` every other
    /// native TLS/H3 credential already shares.
    ///
    /// Per design doc §7.1, the managed set is rebuilt from **every**
    /// currently-managed group on each call (not just the one being
    /// renewed) -- the caller, not this function, is responsible for
    /// re-passing every group's current verified bundle alongside any
    /// newly issued one, so an unrelated group is never dropped by a
    /// publish for a different one. `managed_bundles` entries may not
    /// share a hostname with each other; they are not checked against
    /// `sni_certs`/the default bundle, which keep their existing
    /// first-match-by-array-order precedence (needed by the legitimate
    /// same-hostname-different-key-type case, #565).
    pub fn prepareReloadFromBundles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
        managed_bundles: []const ManagedBundleSpec,
    ) !PreparedReload {
        try validateManagedBundles(sni_certs.len, managed_bundles);
        return self.prepareReloadFromFilesAndBundles(default_cert_path, default_key_path, sni_certs, managed_bundles);
    }

    pub fn reloadFromBundles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
        managed_bundles: []const ManagedBundleSpec,
    ) !void {
        var prepared = try self.prepareReloadFromBundles(default_cert_path, default_key_path, sni_certs, managed_bundles);
        defer prepared.deinit();
        try self.commitPreparedReload(&prepared);
    }

    fn prepareReloadFromFilesAndBundles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
        managed_bundles: []const ManagedBundleSpec,
    ) !PreparedReload {
        // #884 (G11): the automatic-HTTPS bootstrap topology publishes a
        // snapshot before any manual cert/key is configured at all (an
        // ACME-only first boot) and again once a managed bundle is ready,
        // so "no default identity" must be a legal input, not just "empty
        // paths that happen to load" -- `default_cert_path`/`_key_path`
        // empty means the caller never has a default to offer, never a
        // file it still expects to open.
        const has_default = default_cert_path.len > 0 and default_key_path.len > 0;
        var loaded = try self.allocator.alloc(LoadedBundle, (if (has_default) @as(usize, 1) else 0) + sni_certs.len + managed_bundles.len);
        defer self.allocator.free(loaded);
        var loaded_len: usize = 0;
        defer {
            for (loaded[0..loaded_len]) |*bundle| bundle.deinit();
        }

        // One entropy view, used both for private-key import (RSA's
        // primality check) below and for signing via `config()` further
        // down — `OsEntropy.entropy()` is a stateless wrapper over the OS
        // CSPRNG, so reusing/re-deriving it across calls is the established
        // pattern (see its doc comment), not a per-call resource.
        const load_entropy = self.entropy_source.entropy();
        if (has_default) {
            try loaded[loaded_len].initDefault(self.allocator, default_cert_path, default_key_path, load_entropy);
            loaded_len += 1;
        }
        for (sni_certs) |spec| {
            try loaded[loaded_len].initNamed(self.allocator, spec, load_entropy);
            loaded_len += 1;
        }
        for (managed_bundles) |spec| {
            try loaded[loaded_len].initManaged(self.allocator, spec, load_entropy);
            loaded_len += 1;
        }

        var configs = try self.allocator.alloc(sni_provider.CredentialBundleConfig, loaded_len);
        defer {
            for (configs) |*config| config.signer.release();
            self.allocator.free(configs);
        }
        const signer_entropy = self.entropy_source.entropy();
        for (loaded[0..loaded_len], 0..) |*bundle, i| configs[i] = bundle.config(signer_entropy);

        const snapshot = try self.provider_state.buildSnapshot(configs, .{
            // #884 (G11): with no default identity at all (ACME-only, no
            // manual cert/key configured), there is nothing to fall back
            // to for an absent or unmatched SNI, so both policies must fail
            // closed rather than ask `Snapshot.build` to require a default
            // bundle that was never requested (`error.NoUsableDefaultBundle`).
            .absent_sni_policy = if (has_default) .use_default else .fail_handshake,
            // #634: the default identity may satisfy a requested SNI that
            // has no explicit `TARDIGRADE_TLS_SNI_CERTS` mapping when its own
            // certificate's SAN actually covers that hostname, checked via
            // `sni_provider.Snapshot.defaultIdentitySatisfiesSni` (RFC 9525
            // matching, not blind fallback) -- an explicit mapping still
            // always wins, and a non-covering or unparsable default
            // identity still fails closed exactly like before.
            .unknown_sni_policy = if (has_default) .use_default_when_identity_matches else .fail_handshake,
        });
        return .{ .snapshot = snapshot, .has_managed_bundles = managed_bundles.len > 0 };
    }

    /// The managed-active check, `provider_state.install`, and the
    /// `has_managed_bundles` update below all happen under `commit_mutex`
    /// as one step, so a file-only `prepared` can never publish over a
    /// managed generation that activated after it was built: this is the
    /// only authoritative check (see `prepareReloadFromFiles`'s doc
    /// comment), and nothing else may install a snapshot or observe/update
    /// the flag in between. On the `ManagedCredentialsActive` rejection
    /// below, `prepared.snapshot` is left owned by the caller -- every
    /// caller (`reloadFromFiles`/`reloadFromBundles`) defers
    /// `prepared.deinit()` to release it in that case.
    pub fn commitPreparedReload(self: *NativeCredentialStore, prepared: *PreparedReload) !void {
        const snapshot = prepared.snapshot orelse return;
        const has_managed_bundles = prepared.has_managed_bundles;
        const file_only = prepared.file_only;
        const manual_config_generation = prepared.manual_config_generation;

        self.commit_mutex.lock();
        defer self.commit_mutex.unlock();

        if (file_only and self.has_managed_bundles.load(.acquire)) {
            return error.ManagedCredentialsActive;
        }
        if (manual_config_generation != 0 and manual_config_generation < self.manual_config_generation) {
            return error.StaleManualCredentialConfig;
        }
        prepared.snapshot = null;
        try self.provider_state.install(snapshot);
        self.has_managed_bundles.store(has_managed_bundles, .release);
        if (manual_config_generation != 0) self.manual_config_generation = manual_config_generation;
    }
};

/// Rejects a managed set before any PEM/key parsing: an empty or wildcard
/// hostname is never a valid HTTP-01 managed name, and two different
/// managed groups may never claim the same hostname -- unlike the
/// manual-bundle case (#565), there is no legitimate reason for two ACME
/// groups to compete for one name, so this fails closed instead of letting
/// bundle array order decide (#880).
///
/// The aggregate `1 (default) + sni_certs_len + managed_bundles.len` and
/// per-group `hostnames.len` budget checks below run before any PEM/key is
/// parsed and before `prepareReloadFromFilesAndBundles` allocates its
/// per-bundle arrays, so an oversize caller-supplied set is rejected in
/// O(managed_bundles.len) rather than paying for `max_bundles`-many RSA/EC
/// imports (and the unbounded `loaded`/`configs` allocations they'd need)
/// only to have `sni_provider.Snapshot.build` reject it afterward. The
/// `sni_certs_len >= max_bundles` short-circuit keeps the following
/// subtraction from underflowing.
fn validateManagedBundles(sni_certs_len: usize, managed_bundles: []const ManagedBundleSpec) !void {
    if (sni_certs_len >= sni_provider.max_bundles or managed_bundles.len > sni_provider.max_bundles - 1 - sni_certs_len) {
        return error.EmptyCredentialSet;
    }
    for (managed_bundles, 0..) |spec, i| {
        if (spec.hostnames.len == 0 or spec.hostnames.len > sni_provider.max_patterns_per_bundle) return error.EmptyHostPattern;
        for (spec.hostnames) |host| {
            if (host.len == 0 or std.mem.indexOfScalar(u8, host, '*') != null) return error.InvalidHostPattern;
        }
        for (managed_bundles[0..i]) |prior| {
            for (spec.hostnames) |host| {
                for (prior.hostnames) |prior_host| {
                    if (sni_provider.asciiEqlIgnoreCase(host, prior_host)) return error.DuplicateManagedHostname;
                }
            }
        }
    }
}

const LoadedBundle = struct {
    loaded: tls.identity_loader.LoadedIdentity = undefined,
    chain: []const []const u8 = &.{},
    /// Owned copy (allocated with `loaded.allocator`), freed in `deinit`.
    /// A slice rather than a fixed single-entry array because a managed
    /// (ACME) bundle may cover several hostnames at once (#880).
    patterns: []const []const u8 = &.{},
    supported_schemes: [1]credentials.SignatureScheme = undefined,
    is_default: bool = false,

    fn initDefault(
        self: *LoadedBundle,
        allocator: std.mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
        entropy: @import("crypto").provider.Entropy,
    ) !void {
        try self.initFromFiles(allocator, cert_path, key_path, &.{"default.invalid"}, true, entropy);
    }

    fn initNamed(self: *LoadedBundle, allocator: std.mem.Allocator, spec: SniCertSpec, entropy: @import("crypto").provider.Entropy) !void {
        try self.initFromFiles(allocator, spec.cert_path, spec.key_path, &.{spec.server_name}, false, entropy);
    }

    fn initFromFiles(
        self: *LoadedBundle,
        allocator: std.mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
        patterns: []const []const u8,
        is_default: bool,
        entropy: @import("crypto").provider.Entropy,
    ) !void {
        self.* = .{};
        self.loaded = try tls.identity_loader.loadIdentity(allocator, cert_path, key_path, entropy);
        errdefer self.loaded.deinit();
        self.chain = self.loaded.cert_chain;
        self.patterns = try allocator.dupe([]const u8, patterns);
        self.supported_schemes = .{self.loaded.identity.signatureScheme()};
        self.is_default = is_default;
    }

    /// Loads a managed bundle's identity from owned in-memory PEM/DER bytes
    /// rather than file paths (#880) -- the entry point an A4 persistence
    /// ticket uses to publish an already-verified (`activate.verifyChain`)
    /// ACME chain and leaf key without ever touching disk through this
    /// store. Never a default identity: a managed bundle is only ever
    /// selected by its own exact hostnames.
    fn initManaged(
        self: *LoadedBundle,
        allocator: std.mem.Allocator,
        spec: ManagedBundleSpec,
        entropy: @import("crypto").provider.Entropy,
    ) !void {
        self.* = .{};
        self.loaded = try tls.identity_loader.loadIdentityFromBytes(allocator, spec.chain_pem, spec.key_pem, entropy);
        errdefer self.loaded.deinit();
        self.chain = self.loaded.cert_chain;
        self.patterns = try allocator.dupe([]const u8, spec.hostnames);
        self.supported_schemes = .{self.loaded.identity.signatureScheme()};
        self.is_default = false;
    }

    fn config(self: *const LoadedBundle, entropy: @import("crypto").provider.Entropy) sni_provider.CredentialBundleConfig {
        return .{
            .chain = self.chain,
            .patterns = self.patterns,
            .signer = sni_provider.SignAdapter.fromIdentity(self.loaded.identity, entropy),
            .key_kind = keyKindForScheme(self.supported_schemes[0]),
            .supported_schemes = self.supported_schemes[0..],
            .is_default = self.is_default,
        };
    }

    fn deinit(self: *LoadedBundle) void {
        const allocator = self.loaded.allocator;
        allocator.free(self.patterns);
        self.loaded.deinit();
        self.* = undefined;
    }
};

fn keyKindForScheme(scheme: credentials.SignatureScheme) sni_provider.KeyKind {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_p256,
        .rsa_pss_rsae_sha256 => .rsa,
        else => unreachable,
    };
}

pub const NativeTlsConnection = struct {
    pub const Options = struct {
        buffer_limits: encrypted_stream.BufferLimits = encrypted_stream.BufferLimits.defaults(),
        /// #488: process-shared native resumption runtime, borrowed for the
        /// lifetime of this connection. `null` (the default) leaves
        /// resumption fully disabled: no resolver is installed and no
        /// ticket is ever issued.
        resumption_runtime: ?*tls.resumption_runtime.Runtime = null,
        /// #368 Slice 2: process-shared anti-replay gate, borrowed for the
        /// lifetime of this connection and installed independently of
        /// `resumption_runtime` — without a PSK resolver early data can
        /// never be attempted anyway, but installing this gate does not
        /// itself depend on that. `null` (the default) leaves the backend's
        /// own default gate in place, which fails closed (`.unavailable`)
        /// for any 0-RTT attempt.
        early_data_replay_gate: ?tls_backend.EarlyDataReplayGate = null,
        /// Enables native TCP 0-RTT only when the production composition has
        /// also installed replay protection. Default disabled keeps tickets
        /// resume-only and causes attempted early data to be rejected.
        server_early_data_policy: tls_backend.ServerEarlyDataPolicy = .{},
        /// Downstream client-certificate authentication (#763). Anything but
        /// `.disabled` requires `client_trust` with a published generation;
        /// creation fails closed otherwise.
        client_auth: tls_backend.ClientAuthMode = .disabled,
        client_trust: ?*ClientTrustStore = null,
        /// SNI-keyed client-auth policies (#763) of the configuration
        /// generation this connection is admitted under. The policy (mode and
        /// trust generation) is chosen from the ClientHello server_name and
        /// takes precedence over `client_auth`/`client_trust`. Retained for
        /// the connection's lifetime, so handshake policy and Host admission
        /// can never observe a later reload.
        client_policies: ?*ClientPolicySnapshot = null,
    };

    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    backend: *tls_backend.Tls13Backend,
    record: *encrypted_stream.PureZigRecordStream,
    policy: ListenerProtocolPolicy,
    negotiated: ?NegotiatedProtocol = null,
    entropy_source: production_crypto.OsEntropy = .{},
    crypto_provider_state: production_crypto.Provider = undefined,
    resumption_runtime: ?*tls.resumption_runtime.Runtime = null,
    server_early_data_policy: tls_backend.ServerEarlyDataPolicy = .{},
    /// Set exactly once this connection has attempted post-handshake ticket
    /// issuance (successfully or not) — issuance is best-effort and must
    /// never be retried on the same connection (#488).
    ticket_issue_attempted: bool = false,
    /// Client-auth state (#763). `client_verifier` is borrowed by the backend
    /// for the handshake, so it lives here (heap-stable) beside the pinned
    /// trust generation it reads.
    client_trust_generation: ?*ClientTrustStore.Generation = null,
    client_verifier: webpki_verifier.WebPkiVerifier = undefined,
    client_identity: client_identity.ClientIdentity = .{},
    client_identity_present: bool = false,
    client_policies: ?*ClientPolicySnapshot = null,
    /// Fingerprint of the SNI-selected policy this connection was admitted
    /// under (0 = no client auth); see `tls.client_trust.hostAdmitted`.
    client_policy_fingerprint: u64 = 0,

    pub fn create(
        allocator: std.mem.Allocator,
        fd: std.posix.fd_t,
        policy: ListenerProtocolPolicy,
        provider: credentials.CredentialProvider,
    ) !*NativeTlsConnection {
        return createWithOptions(allocator, fd, policy, provider, .{});
    }

    pub fn createWithOptions(
        allocator: std.mem.Allocator,
        fd: std.posix.fd_t,
        policy: ListenerProtocolPolicy,
        provider: credentials.CredentialProvider,
        options: Options,
    ) !*NativeTlsConnection {
        if (!policy.http1_enabled and !policy.http2_enabled) return error.ProtocolConfigFailed;
        try options.buffer_limits.validate();
        try setNonBlocking(fd);
        const handshake_entropy = try production_crypto.freshHandshakeEntropy();

        // Fail closed before anything is allocated: a listener that demands
        // client certificates must never degrade to unauthenticated.
        var trust_generation: ?*ClientTrustStore.Generation = null;
        if (options.client_auth != .disabled) {
            const store = options.client_trust orelse return error.ClientTrustUnavailable;
            trust_generation = store.acquire() orelse return error.ClientTrustUnavailable;
        }
        errdefer if (trust_generation) |g| g.release();

        const self = try allocator.create(NativeTlsConnection);
        errdefer allocator.destroy(self);
        // #490: the shared `CryptoProvider` must exist before the TLS
        // handshake engine is constructed (it now takes one explicitly, for
        // its own HKDF key schedule, X25519 key-share generation, and
        // CertificateVerify signature verification) — built directly into
        // `self`'s already-allocated storage here, ahead of the `self.* =
        // .{...}` below, which re-threads this same value through
        // explicitly so it is not reset to `undefined`.
        self.entropy_source = .{};
        self.crypto_provider_state = production_crypto.Provider.init(self.entropy_source.entropy());
        const crypto_provider = self.crypto_provider_state.cryptoProvider();

        const backend = try allocator.create(tls_backend.Tls13Backend);
        var backend_owned_by_record = false;
        errdefer if (!backend_owned_by_record) {
            backend.deinit();
            allocator.destroy(backend);
        };
        backend.* = tls_backend.Tls13Backend.initServerWithProviderConfigured(
            handshake_entropy,
            crypto_provider,
            provider,
            .{
                .policy = policy.nativeTlsPolicy(),
                .transport = .record,
            },
        );
        // #488: install the process-shared server resolver before the
        // handshake can start — `setServerPskResolver` itself refuses once
        // the backend has left `.idle`.
        if (options.resumption_runtime) |runtime| {
            backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore }) catch unreachable;
            backend.setResumptionDecisionObserver(runtime.backendDecisionObserver(.record)) catch unreachable;
            if (runtime.serverResolver()) |resolver| {
                backend.setServerPskResolver(resolver) catch unreachable;
            }
        }
        // #368 Slice 2: independent of `resumption_runtime` above — this is
        // the same process-scoped store shared with every other native TCP
        // worker and QUIC/H3, not a per-connection concern.
        if (options.early_data_replay_gate) |gate| {
            backend.setEarlyDataReplayGate(gate) catch unreachable;
            if (options.resumption_runtime != null and options.server_early_data_policy.enabled) {
                backend.setServerEarlyDataPolicy(options.server_early_data_policy) catch unreachable;
            }
        }

        const record = try allocator.create(encrypted_stream.PureZigRecordStream);
        errdefer allocator.destroy(record);

        self.* = .{
            .allocator = allocator,
            .fd = fd,
            .backend = backend,
            .record = record,
            .policy = policy,
            .entropy_source = self.entropy_source,
            .crypto_provider_state = self.crypto_provider_state,
            .resumption_runtime = options.resumption_runtime,
            .server_early_data_policy = if (options.early_data_replay_gate != null and options.resumption_runtime != null) options.server_early_data_policy else .{},
            .client_trust_generation = trust_generation,
            .client_policies = null,
        };
        if (options.client_policies != null) {
            backend.setClientAuthSelector(.{ .ctx = self, .selectFn = selectClientAuth });
        }
        if (trust_generation) |g| {
            self.client_verifier = webpki_verifier.WebPkiVerifier.initClientAuth(
                allocator,
                g.anchors.anchors(),
                crypto_provider,
                g.max_path_length,
            );
            backend.requestClientAuthentication(options.client_auth, self.client_verifier.verifier());
        }
        record.* = try encrypted_stream.PureZigRecordStream.initWithCarrierBackendAndLimits(
            allocator,
            .server,
            crypto_provider,
            .tls_aes_128_gcm_sha256,
            self.socketCarrier(),
            backend.backend(),
            options.buffer_limits,
        );
        backend_owned_by_record = true;
        // Last, so no failure above can leak the reference.
        if (options.client_policies) |snap| self.client_policies = snap.retain();
        return self;
    }

    /// Backend hook: pick the client-auth policy for the ClientHello's SNI and
    /// pin its trust generation for this handshake.
    fn selectClientAuth(ptr: *anyopaque, server_name: ?[]const u8) error{ClientAuthUnavailable}!tls_backend.ClientAuthSelection {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        const snapshot = self.client_policies orelse return error.ClientAuthUnavailable;
        const selection = snapshot.select(server_name);
        if (self.client_trust_generation) |g| g.release();
        self.client_trust_generation = selection.generation;
        self.client_policy_fingerprint = selection.fingerprint;
        const g = selection.generation orelse return .{ .mode = .disabled };
        self.client_verifier = webpki_verifier.WebPkiVerifier.initClientAuth(
            self.allocator,
            g.anchors.anchors(),
            self.crypto_provider_state.cryptoProvider(),
            g.max_path_length,
        );
        return .{ .mode = selection.mode, .verifier = self.client_verifier.verifier() };
    }

    /// Whether a request for `host` may be served on this connection: its
    /// client-auth policy must not differ from the SNI-selected one the
    /// handshake enforced (otherwise the caller answers 421).
    pub fn clientPolicyAdmitsHost(self: *const NativeTlsConnection, host: []const u8) bool {
        const snapshot = self.client_policies orelse return true;
        return tls.client_trust.hostAdmitted(self.client_policy_fingerprint, snapshot.fingerprintForHost(host));
    }

    fn nativeClientPolicyAdmitsHost(ptr: *anyopaque, host: []const u8) bool {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        return self.clientPolicyAdmitsHost(host);
    }

    pub fn destroy(self: *NativeTlsConnection) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    pub fn deinit(self: *NativeTlsConnection) void {
        const trust_generation = self.client_trust_generation;
        defer if (trust_generation) |g| g.release();
        const policies = self.client_policies;
        defer if (policies) |snap| snap.release();
        self.record.deinit();
        self.allocator.destroy(self.record);
        self.allocator.destroy(self.backend);
        self.* = undefined;
    }

    pub fn stream(self: *NativeTlsConnection) encrypted_stream.EncryptedStream {
        return self.record.stream();
    }

    pub fn httpConnection(self: *NativeTlsConnection) encrypted_stream_connection.EncryptedStreamHttpConnection {
        var conn = encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFdAndProvenance(
            self.stream(),
            self.fd,
            self,
            nativeReadTransportEarly,
            nativeReadEarlyPrefixLen,
            nativeHandshakeComplete,
        );
        conn.client_cert_fn = nativeClientIdentity;
        conn.client_policy_admits_host_fn = nativeClientPolicyAdmitsHost;
        return conn;
    }

    /// Capture the verified client identity once the handshake is complete
    /// (#763). A no-op without client auth or when the client presented no
    /// certificate. Returns an error only when a *verified* certificate cannot
    /// be rendered, which the caller must treat as a failed connection rather
    /// than serve the request unauthenticated.
    pub fn finalizeClientIdentity(self: *NativeTlsConnection) !void {
        if (self.client_identity_present) return;
        const der = self.backend.verifiedPeerCertificate() orelse return;
        self.client_identity = try client_identity.ClientIdentity.fromVerifiedDer(self.allocator, der);
        self.client_identity_present = true;
    }

    /// The verified client identity, borrowing this connection's storage.
    /// Null when no client certificate was verified.
    pub fn clientIdentity(self: *const NativeTlsConnection) ?*const client_identity.ClientIdentity {
        if (!self.client_identity_present) return null;
        return &self.client_identity;
    }

    fn nativeClientIdentity(ptr: *anyopaque) ?*const client_identity.ClientIdentity {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        return self.clientIdentity();
    }

    pub fn readTransportEarly(self: *const NativeTlsConnection) bool {
        return self.record.currentReadTransportEarly();
    }

    pub fn readEarlyPrefixLen(self: *const NativeTlsConnection) usize {
        return self.record.currentReadEarlyPrefixLen();
    }

    pub fn downstreamHandshakeComplete(self: *const NativeTlsConnection) bool {
        return self.record.applicationDataOpen();
    }

    pub fn rawFd(self: *const NativeTlsConnection) std.posix.fd_t {
        return self.fd;
    }

    pub fn readiness(self: *const NativeTlsConnection) encrypted_stream.Readiness {
        return self.record.readiness();
    }

    pub fn interest(self: *const NativeTlsConnection) event_loop.Interest {
        return interestForReadiness(self.readiness());
    }

    pub fn drive(self: *NativeTlsConnection) encrypted_stream.Error!encrypted_stream.DriveResult {
        const result = try self.record.drive();
        self.maybeIssueSessionTicket();
        return result;
    }

    /// #488: best-effort, exactly-once post-handshake ticket issuance. Only
    /// attempted once authenticated application data has actually opened,
    /// and never retried on this connection regardless of outcome — a
    /// failure here is swallowed rather than tearing down an otherwise
    /// usable connection.
    fn maybeIssueSessionTicket(self: *NativeTlsConnection) void {
        if (self.ticket_issue_attempted) return;
        const runtime = self.resumption_runtime orelse return;
        if (self.backend.role != .server) return;
        if (!self.record.applicationDataOpen()) return;
        self.ticket_issue_attempted = true;
        self.issueSessionTicket(runtime) catch |err| {
            runtime.observer.ticketIssue(.record, runtime.config.mode, switch (err) {
                error.StatefulCapacityRefused => .rejected,
                else => .failed,
            });
            return;
        };
        runtime.observer.ticketIssue(.record, runtime.config.mode, .success);
    }

    fn issueSessionTicket(self: *NativeTlsConnection, runtime: *tls.resumption_runtime.Runtime) !void {
        const now_unix_ms = runtime.nowUnixMs();
        const crypto_provider = self.crypto_provider_state.cryptoProvider();

        var ticket_nonce: [8]u8 = undefined;
        try crypto_provider.randomBytes(&ticket_nonce);
        var age_add_bytes: [4]u8 = undefined;
        try crypto_provider.randomBytes(&age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &age_add_bytes, .big);

        const limits = runtime.config.session_limits;
        var prepared = try self.backend.prepareNewSessionTicket(self.allocator, .{
            .ticket_lifetime = runtime.config.ticket_lifetime_seconds,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = &ticket_nonce,
            .issued_at_unix_ms = now_unix_ms,
            .max_early_data_size = if (self.server_early_data_policy.enabled) self.server_early_data_policy.max_early_data_size else null,
        }, limits);
        defer prepared.deinit();

        // The scratch buffer receives the serialized ticket identity (sealed
        // stateless envelope or stateful handle). Release it through the
        // canonical wipe-and-free (#783): an ordinary `allocator.free` would
        // re-scribble the wiped bytes with `undefined` before the backing
        // allocator sees them, and in ReleaseFast that scribble — and a
        // preceding wipe of now-dead memory — carries no guarantee.
        const scratch = try self.allocator.alloc(u8, runtime.maxIdentityLen());
        defer @import("crypto").secrets.secureZeroAndFree(self.allocator, scratch);
        var identity = try runtime.createIdentity(&prepared.state, now_unix_ms, scratch);
        defer identity.deinit();

        var sink = tls.tls13_transport.EventSink{};
        defer sink.deinit();
        self.backend.emitPreparedNewSessionTicket(self.allocator, &sink, &prepared, identity.slice(), limits) catch |err| {
            runtime.rollbackIdentity(&identity);
            return err;
        };

        for (sink.items[0..sink.len]) |event| switch (event) {
            .handshake_bytes => |hb| self.record.tryQueuePostHandshake(.{ .handshake_bytes = .{ .epoch = hb.epoch, .data = hb.data } }) catch |err| {
                runtime.rollbackIdentity(&identity);
                return err;
            },
            else => {},
        };
    }

    pub fn validatedNegotiatedProtocol(self: *NativeTlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        if (self.negotiated) |protocol| return protocol;
        if (!self.record.applicationDataOpen()) return error.HandshakeNotComplete;
        const protocol = try negotiated_dispatch.selectNegotiatedProtocol(
            self.record.negotiatedAlpn(),
            self.policy,
        );
        self.negotiated = protocol;
        return protocol;
    }

    fn socketCarrier(self: *NativeTlsConnection) encrypted_stream.Carrier {
        return .{
            .ptr = self,
            .readFn = carrierRead,
            .writeFn = carrierWrite,
            .closeFn = carrierClose,
            .owns_handle = true,
        };
    }

    fn nativeReadTransportEarly(ptr: *anyopaque) bool {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        return self.readTransportEarly();
    }

    fn nativeReadEarlyPrefixLen(ptr: *anyopaque) usize {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        return self.readEarlyPrefixLen();
    }

    fn nativeHandshakeComplete(ptr: *anyopaque) bool {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        return self.downstreamHandshakeComplete();
    }

    fn carrierRead(ptr: *anyopaque, out: []u8) encrypted_stream.Error!usize {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return error.StreamClosed;
        return readFd(self.fd, out);
    }

    fn carrierWrite(ptr: *anyopaque, bytes: []const u8) encrypted_stream.Error!usize {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return error.StreamClosed;
        return writeFd(self.fd, bytes);
    }

    fn carrierClose(ptr: *anyopaque) void {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return;
        closeFd(self.fd);
        self.fd = -1;
    }
};

pub fn interestForReadiness(readiness: encrypted_stream.Readiness) event_loop.Interest {
    return .{
        .read = readiness.wants_read,
        .write = readiness.wants_write,
    };
}

fn readFd(fd: std.posix.fd_t, out: []u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

test "native TLS policy follows listener preference and fallback" {
    const dual = (ListenerProtocolPolicy{
        .http1_enabled = true,
        .http2_enabled = true,
        .allow_http1_without_alpn = true,
    }).nativeTlsPolicy();
    try std.testing.expectEqual(@as(usize, 2), dual.alpn_protocols.len);
    try std.testing.expect(dual.alpn_protocols[0].eql(tls.algorithms.alpn.h2));
    try std.testing.expect(dual.alpn_protocols[1].eql(tls.algorithms.alpn.http_1_1));
    try std.testing.expect(dual.allow_absent_alpn);

    const h2_only = (ListenerProtocolPolicy{
        .http1_enabled = false,
        .http2_enabled = true,
        .allow_http1_without_alpn = true,
    }).nativeTlsPolicy();
    try std.testing.expectEqual(@as(usize, 1), h2_only.alpn_protocols.len);
    try std.testing.expect(h2_only.alpn_protocols[0].eql(tls.algorithms.alpn.h2));
    try std.testing.expect(!h2_only.allow_absent_alpn);

    const disabled = (ListenerProtocolPolicy{
        .http1_enabled = false,
        .http2_enabled = false,
        .allow_http1_without_alpn = true,
    }).nativeTlsPolicy();
    try std.testing.expectEqual(@as(usize, 0), disabled.alpn_protocols.len);
    try std.testing.expect(!disabled.allow_absent_alpn);
}

test "native readiness maps directly to event-loop interest" {
    try std.testing.expectEqual(
        event_loop.Interest{ .read = true, .write = false },
        interestForReadiness(.{ .wants_read = true }),
    );
    try std.testing.expectEqual(
        event_loop.Interest{ .read = false, .write = true },
        interestForReadiness(.{ .wants_write = true }),
    );
    try std.testing.expectEqual(
        event_loop.Interest{ .read = true, .write = true },
        interestForReadiness(.{ .wants_read = true, .wants_write = true }),
    );
}

test "prepared native credential reload does not publish same-path cert changes before commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/server.crt", .{tmp_abs});
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/server.key", .{tmp_abs});
    defer allocator.free(key_path);

    const cert_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(cert_a);
    const key_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(key_a);
    const cert_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.crt", 256 * 1024);
    defer allocator.free(cert_b);
    const key_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.key", 256 * 1024);
    defer allocator.free(key_b);
    const chain_a = try tls.identity_loader.certChainFromPemOrDer(allocator, cert_a);
    defer freeTestCertChain(allocator, chain_a);
    const chain_b = try tls.identity_loader.certChainFromPemOrDer(allocator, cert_b);
    defer freeTestCertChain(allocator, chain_b);

    try compat.cwd().writeFile(.{ .sub_path = cert_path, .data = cert_a });
    try compat.cwd().writeFile(.{ .sub_path = key_path, .data = key_a });
    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(cert_path, key_path, &.{});
    try expectSelectedLeaf(store.provider(), chain_a[0]);

    try compat.cwd().writeFile(.{ .sub_path = cert_path, .data = cert_b });
    try compat.cwd().writeFile(.{ .sub_path = key_path, .data = key_b });
    var prepared = try store.prepareReloadFromFiles(cert_path, key_path, &.{});
    defer prepared.deinit();

    try expectSelectedLeaf(store.provider(), chain_a[0]);
    try store.commitPreparedReload(&prepared);
    try expectSelectedLeaf(store.provider(), chain_b[0]);
}

test "prepareReloadFromBundles publishes an in-memory managed bundle alongside an untouched manual/default bundle, pinning the old generation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);
    const manual_cert_path = try std.fmt.allocPrint(allocator, "{s}/manual.crt", .{tmp_abs});
    defer allocator.free(manual_cert_path);
    const manual_key_path = try std.fmt.allocPrint(allocator, "{s}/manual.key", .{tmp_abs});
    defer allocator.free(manual_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const manual_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.crt", 256 * 1024);
    defer allocator.free(manual_cert);
    const manual_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.key", 256 * 1024);
    defer allocator.free(manual_key);
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);

    const default_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, default_cert);
    defer freeTestCertChain(allocator, default_chain);
    const manual_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, manual_cert);
    defer freeTestCertChain(allocator, manual_chain);
    const managed_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, managed_cert);
    defer freeTestCertChain(allocator, managed_chain);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });
    try compat.cwd().writeFile(.{ .sub_path = manual_cert_path, .data = manual_cert });
    try compat.cwd().writeFile(.{ .sub_path = manual_key_path, .data = manual_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    const sni_certs = [_]SniCertSpec{.{ .server_name = "manual.example.test", .cert_path = manual_cert_path, .key_path = manual_key_path }};
    try store.reloadFromFiles(default_cert_path, default_key_path, &sni_certs);
    try expectSelectedLeafFor(store.provider(), "manual.example.test", manual_chain[0]);

    // Held across the managed-bundle publish, as an in-flight handshake
    // would hold its selection across a later reload.
    const pinned = try selectFor(store.provider(), null);
    defer pinned.release();

    const managed_specs = [_]ManagedBundleSpec{.{
        .hostnames = &.{"managed.example.test"},
        .chain_pem = managed_cert,
        .key_pem = managed_key,
    }};
    try store.reloadFromBundles(default_cert_path, default_key_path, &sni_certs, &managed_specs);

    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);
    try expectSelectedLeafFor(store.provider(), "manual.example.test", manual_chain[0]);
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    // The handle selected before the managed publish still serves (and can
    // still sign for) generation 1's default identity.
    try std.testing.expectEqualSlices(u8, default_chain[0], pinned.certificateChain().leaf().?);
    var sig: [128]u8 = undefined;
    const progress = try pinned.sign("pinned generation stays reachable after managed publish", &sig);
    _ = switch (progress) {
        .complete => |written| written,
        .pending => return error.TestUnexpectedPending,
    };
}

test "a store that never reloaded (no default, no managed bundle) fails every selection closed (#884 G11 bootstrap)" {
    const allocator = std.testing.allocator;
    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();

    try std.testing.expectError(error.NoCredentialAvailable, selectFor(store.provider(), null));
    try std.testing.expectError(error.NoCredentialAvailable, selectFor(store.provider(), "managed.example.test"));
}

test "prepareReloadFromBundles publishes a managed bundle with no default identity at all, failing closed for an absent or unmanaged SNI (#884 G11 ACME-only bootstrap)" {
    const allocator = std.testing.allocator;
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);
    const managed_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, managed_cert);
    defer freeTestCertChain(allocator, managed_chain);

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();

    // No manual cert/key configured: an ACME-only first boot's TLS listener
    // binds and starts failing handshakes closed before any generation is
    // ever installed.
    try std.testing.expectError(error.NoCredentialAvailable, selectFor(store.provider(), "managed.example.test"));

    const managed_specs = [_]ManagedBundleSpec{.{
        .hostnames = &.{"managed.example.test"},
        .chain_pem = managed_cert,
        .key_pem = managed_key,
    }};
    try store.reloadFromBundles("", "", &.{}, &managed_specs);

    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);
    // No default identity exists to fall back to, so both the absent-SNI
    // and unknown-SNI cases fail closed rather than serving anything.
    try std.testing.expectError(error.NoCredentialAvailable, selectFor(store.provider(), null));
    try std.testing.expectError(error.NoCredentialAvailable, selectFor(store.provider(), "other.example.test"));
}

test "prepareReloadFromBundles rejects two managed bundles claiming the same hostname, or a key/cert type mismatch, without touching the active generation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);
    const default_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, default_cert);
    defer freeTestCertChain(allocator, default_chain);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    const duplicate_hostname = [_]ManagedBundleSpec{
        .{ .hostnames = &.{"shared.example.test"}, .chain_pem = managed_cert, .key_pem = managed_key },
        .{ .hostnames = &.{"shared.example.test"}, .chain_pem = managed_cert, .key_pem = managed_key },
    };
    try std.testing.expectError(
        error.DuplicateManagedHostname,
        store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &duplicate_hostname),
    );
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    const wildcard_hostname = [_]ManagedBundleSpec{.{ .hostnames = &.{"*.example.test"}, .chain_pem = managed_cert, .key_pem = managed_key }};
    try std.testing.expectError(
        error.InvalidHostPattern,
        store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &wildcard_hostname),
    );
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    // An RSA leaf certificate paired with an Ed25519 key: both parse
    // independently, but the leaf's own SPKI key kind disagrees with the
    // signer's -- #880 relies on `buildBundle`'s existing `KeySignerMismatch`
    // check here, not a second check of its own.
    const mismatched_key = [_]ManagedBundleSpec{.{ .hostnames = &.{"mismatched.example.test"}, .chain_pem = managed_cert, .key_pem = default_key }};
    try std.testing.expectError(
        error.KeySignerMismatch,
        store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &mismatched_key),
    );
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    var oversize_hostnames: [sni_provider.max_patterns_per_bundle + 1][]const u8 = undefined;
    var oversize_bufs: [sni_provider.max_patterns_per_bundle + 1][32]u8 = undefined;
    for (0..oversize_hostnames.len) |i| {
        oversize_hostnames[i] = std.fmt.bufPrint(&oversize_bufs[i], "h{d}.example.test", .{i}) catch unreachable;
    }
    const oversize = [_]ManagedBundleSpec{.{ .hostnames = oversize_hostnames[0..], .chain_pem = managed_cert, .key_pem = managed_key }};
    try std.testing.expectError(
        error.EmptyHostPattern,
        store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &oversize),
    );
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);
}

test "prepareReloadFromBundles repeated managed-bundle rotation settles owned signer and buffer state without leaks" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const cert_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(cert_a);
    const key_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(key_a);
    const cert_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.crt", 256 * 1024);
    defer allocator.free(cert_b);
    const key_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.key", 256 * 1024);
    defer allocator.free(key_b);
    const chain_a = try tls.identity_loader.certChainFromPemOrDer(allocator, cert_a);
    defer freeTestCertChain(allocator, chain_a);
    const chain_b = try tls.identity_loader.certChainFromPemOrDer(allocator, cert_b);
    defer freeTestCertChain(allocator, chain_b);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});

    const rotations = [_]struct { cert: []const u8, key: []const u8, chain: [][]u8 }{
        .{ .cert = cert_a, .key = key_a, .chain = chain_a },
        .{ .cert = cert_b, .key = key_b, .chain = chain_b },
        .{ .cert = cert_a, .key = key_a, .chain = chain_a },
        .{ .cert = cert_b, .key = key_b, .chain = chain_b },
    };
    for (rotations) |rotation| {
        const specs = [_]ManagedBundleSpec{.{ .hostnames = &.{"rotating.example.test"}, .chain_pem = rotation.cert, .key_pem = rotation.key }};
        try store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &specs);
        try expectSelectedLeafFor(store.provider(), "rotating.example.test", rotation.chain[0]);
    }
}

test "prepareReloadFromFiles rejects a routine file-only reload while a managed bundle is active, without touching the active generation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);
    const managed_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, managed_cert);
    defer freeTestCertChain(allocator, managed_chain);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});

    const managed_specs = [_]ManagedBundleSpec{.{ .hostnames = &.{"managed.example.test"}, .chain_pem = managed_cert, .key_pem = managed_key }};
    try store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &managed_specs);
    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);

    // An ordinary file-only reload -- the shape `gateway_shutdown.hotReloadConfig`
    // issues on every routine SIGHUP -- must refuse outright rather than
    // silently publishing a snapshot missing the managed bundle above (#880).
    try std.testing.expectError(error.ManagedCredentialsActive, store.prepareReloadFromFiles(default_cert_path, default_key_path, &.{}));
    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);

    // Publishing the complete managed set again through the bundles-aware
    // API still works -- the guard only blocks the file-only entry point.
    try store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &managed_specs);
    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);

    // And explicitly publishing zero managed bundles through the
    // bundles-aware API clears the guard, since that is this store's only
    // way to learn the managed set has legitimately gone empty.
    try store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &.{});
    var prepared = try store.prepareReloadFromFiles(default_cert_path, default_key_path, &.{});
    prepared.deinit();
}

test "commitPreparedReload rejects a file-only reload prepared before a racing managed reload activated, even though the file-only snapshot is newer" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);
    const managed_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, managed_cert);
    defer freeTestCertChain(allocator, managed_chain);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});

    // Both prepared while `has_managed_bundles` is still false, so the
    // prepare-time fast-fail in `prepareReloadFromFiles` cannot see the
    // managed reload below -- exactly the race the commit-time guard
    // exists to close. `managed` is prepared (and generation-stamped)
    // first, but `file_only` is prepared, and so stamped with a *higher*
    // generation, before either one commits.
    const managed_specs = [_]ManagedBundleSpec{.{ .hostnames = &.{"managed.example.test"}, .chain_pem = managed_cert, .key_pem = managed_key }};
    var managed = try store.prepareReloadFromBundles(default_cert_path, default_key_path, &.{}, &managed_specs);
    defer managed.deinit();
    var file_only = try store.prepareReloadFromFiles(default_cert_path, default_key_path, &.{});
    defer file_only.deinit();

    try store.commitPreparedReload(&managed);
    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);

    // `file_only`'s snapshot generation is newer, so a prepare-time-only
    // guard (or a naive generation comparison) would let it win and
    // silently drop the managed identity just committed. The commit-time
    // check must reject it instead, and ownership of its (unpublished)
    // snapshot must still land back with the caller via `deinit()` above.
    try std.testing.expectError(error.ManagedCredentialsActive, store.commitPreparedReload(&file_only));
    try expectSelectedLeafFor(store.provider(), "managed.example.test", managed_chain[0]);
}

test "prepareReloadFromBundles rejects an oversize managed set before parsing any key material" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const default_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, default_cert);
    defer freeTestCertChain(allocator, default_chain);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);

    // One more managed bundle than the default identity leaves room for.
    // Every entry below is deliberately unparsable, so the only way this
    // can fail with `EmptyCredentialSet` rather than a PEM/key parse error
    // is if the aggregate budget is checked before any parsing starts.
    var oversize_hosts: [sni_provider.max_bundles][32]u8 = undefined;
    var oversize_host_slices: [sni_provider.max_bundles][]const u8 = undefined;
    var oversize_specs: [sni_provider.max_bundles]ManagedBundleSpec = undefined;
    for (0..oversize_specs.len) |i| {
        oversize_host_slices[i] = std.fmt.bufPrint(&oversize_hosts[i], "budget{d}.example.test", .{i}) catch unreachable;
        oversize_specs[i] = .{
            .hostnames = oversize_host_slices[i .. i + 1],
            .chain_pem = "not a certificate",
            .key_pem = "not a key",
        };
    }
    try std.testing.expectError(
        error.EmptyCredentialSet,
        store.reloadFromBundles(default_cert_path, default_key_path, &.{}, &oversize_specs),
    );
    try expectSelectedLeafFor(store.provider(), null, default_chain[0]);
}

test "commitPreparedReload rejects a stale prepared reload once a newer one has already published, while the newer generation serves and a handle pinned to the prior generation keeps signing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const cert_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(cert_a);
    const key_a = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(key_a);
    const cert_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.crt", 256 * 1024);
    defer allocator.free(cert_b);
    const key_b = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_p256.key", 256 * 1024);
    defer allocator.free(key_b);
    const default_chain = try tls.identity_loader.certChainFromPemOrDer(allocator, default_cert);
    defer freeTestCertChain(allocator, default_chain);
    const chain_b = try tls.identity_loader.certChainFromPemOrDer(allocator, cert_b);
    defer freeTestCertChain(allocator, chain_b);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(default_cert_path, default_key_path, &.{});

    // Held across both prepared reloads below, as an in-flight handshake
    // would hold its selection across a later rotation attempt.
    const pinned = try selectFor(store.provider(), null);
    defer pinned.release();

    const specs_a = [_]ManagedBundleSpec{.{ .hostnames = &.{"rotating.example.test"}, .chain_pem = cert_a, .key_pem = key_a }};
    var older = try store.prepareReloadFromBundles(default_cert_path, default_key_path, &.{}, &specs_a);
    defer older.deinit();

    const specs_b = [_]ManagedBundleSpec{.{ .hostnames = &.{"rotating.example.test"}, .chain_pem = cert_b, .key_pem = key_b }};
    var newer = try store.prepareReloadFromBundles(default_cert_path, default_key_path, &.{}, &specs_b);
    defer newer.deinit();

    try store.commitPreparedReload(&newer);
    try expectSelectedLeafFor(store.provider(), "rotating.example.test", chain_b[0]);

    try std.testing.expectError(error.StaleSnapshotGeneration, store.commitPreparedReload(&older));
    try expectSelectedLeafFor(store.provider(), "rotating.example.test", chain_b[0]);

    // The handle selected before either prepared reload still serves (and
    // can still sign for) the original generation's default identity.
    try std.testing.expectEqualSlices(u8, default_chain[0], pinned.certificateChain().leaf().?);
    var sig: [128]u8 = undefined;
    const progress = try pinned.sign("pinned generation stays reachable after stale commit rejection", &sig);
    _ = switch (progress) {
        .complete => |written| written,
        .pending => return error.TestUnexpectedPending,
    };
}

test "allocator-fault sweep over bytes-based multi-bundle preparation leaves every owned buffer and signer freed on every induced failure" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const default_cert_path = try std.fmt.allocPrint(allocator, "{s}/default.crt", .{tmp_abs});
    defer allocator.free(default_cert_path);
    const default_key_path = try std.fmt.allocPrint(allocator, "{s}/default.key", .{tmp_abs});
    defer allocator.free(default_key_path);

    const default_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.crt", 256 * 1024);
    defer allocator.free(default_cert);
    const default_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_ed25519.key", 256 * 1024);
    defer allocator.free(default_key);
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(managed_key);

    try compat.cwd().writeFile(.{ .sub_path = default_cert_path, .data = default_cert });
    try compat.cwd().writeFile(.{ .sub_path = default_key_path, .data = default_key });

    // Covers the full bytes-based reload path end to end -- default-bundle
    // file load, then a managed-bundle publish on top of it -- so the sweep
    // also exercises induced failures after the default and one managed key
    // have already loaded, not just failures during the very first
    // allocation.
    const Fixture = struct {
        default_cert_path: []const u8,
        default_key_path: []const u8,
        managed_cert: []const u8,
        managed_key: []const u8,
    };
    const fixture = Fixture{
        .default_cert_path = default_cert_path,
        .default_key_path = default_key_path,
        .managed_cert = managed_cert,
        .managed_key = managed_key,
    };

    try std.testing.checkAllAllocationFailures(allocator, struct {
        fn run(failing_allocator: std.mem.Allocator, fx: Fixture) !void {
            var store = NativeCredentialStore.init(failing_allocator);
            defer store.deinit();
            try store.reloadFromFiles(fx.default_cert_path, fx.default_key_path, &.{});
            const specs = [_]ManagedBundleSpec{.{ .hostnames = &.{"managed.example.test"}, .chain_pem = fx.managed_cert, .key_pem = fx.managed_key }};
            try store.reloadFromBundles(fx.default_cert_path, fx.default_key_path, &.{}, &specs);
        }
    }.run, .{fixture});
}

// #565 review: the production file-loading composition
// (`NativeCredentialStore.reloadFromFiles` -> `LoadedBundle.init` ->
// `identity_loader.loadIdentity`) could not construct an RSA identity at
// all — `loadIdentity` called the no-entropy `Identity.initPkcs8`, which
// this PR deliberately makes reject RSA, and `keyKindForScheme` had no RSA
// arm (would have hit its `unreachable` the first time a real RSA
// credential reached selection). This exercises the exact reload-from-files
// path a real deployment uses, not a lower-level direct-construction
// shortcut, so both gaps are covered together.
test "native credential store loads an RSA identity through the real reload-from-files path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/server.crt", .{tmp_abs});
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/server.key", .{tmp_abs});
    defer allocator.free(key_path);

    const cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(cert);
    const key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer allocator.free(key);
    const chain = try tls.identity_loader.certChainFromPemOrDer(allocator, cert);
    defer freeTestCertChain(allocator, chain);

    try compat.cwd().writeFile(.{ .sub_path = cert_path, .data = cert });
    try compat.cwd().writeFile(.{ .sub_path = key_path, .data = key });

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    try store.reloadFromFiles(cert_path, key_path, &.{});

    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = null,
        .peer_signature_schemes = &.{0x0804}, // rsa_pss_rsae_sha256 only
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const progress = try store.provider().selectCredential(&selection);
    const credential = switch (progress) {
        .complete => |c| c,
        .pending => return error.TestUnexpectedPending,
    };
    defer credential.release();
    try std.testing.expectEqual(credentials.SignatureScheme.rsa_pss_rsae_sha256, credential.scheme);
    const selected_chain = credential.certificateChain();
    try std.testing.expectEqual(@as(usize, 1), selected_chain.count());
    try std.testing.expectEqualSlices(u8, chain[0], selected_chain.leaf().?);

    // Prove the selected credential can actually sign, not merely that
    // selection returned an RSA-tagged handle.
    var signature: [512]u8 = undefined;
    const progress2 = try credential.sign("reload-from-files RSA smoke signature", &signature);
    const written = switch (progress2) {
        .complete => |len| len,
        .pending => return error.TestUnexpectedPending,
    };
    try std.testing.expectEqual(@as(usize, 256), written);
}

test "native TLS owner heap-stabilizes backend record and owns fd close" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    const conn = try NativeTlsConnection.create(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
    );
    const original_fd = conn.rawFd();
    try std.testing.expect(original_fd >= 0);
    try std.testing.expectEqual(@intFromPtr(conn.backend), @intFromPtr(conn.backend.backend().ptr));
    try std.testing.expectEqual(encrypted_stream.BackendKind.pure_zig_record, conn.stream().backend());
    conn.destroy();

    try std.testing.expectError(error.SocketWriteFailed, writeFd(original_fd, "x"));
}

test "native TLS createWithOptions applies validated buffer limits" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var limits = encrypted_stream.BufferLimits.defaults();
    limits.outbound_ciphertext.high = limits.outbound_ciphertext.low + 16;
    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .buffer_limits = limits },
    );
    defer conn.destroy();

    const snapshot = conn.stream().bufferSnapshot();
    try std.testing.expect(snapshot.limits_enforced);
    try std.testing.expectEqual(limits.outbound_ciphertext.high, snapshot.limits.?.outbound_ciphertext.high);
}

fn fixedNowUnixMs(_: *anyopaque) i64 {
    return 1000;
}

fn expectSelectedLeaf(provider: credentials.CredentialProvider, expected_leaf: []const u8) !void {
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = null,
        .peer_signature_schemes = &.{ 0x0807, 0x0403 },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const progress = try provider.selectCredential(&selection);
    const credential = switch (progress) {
        .complete => |credential| credential,
        .pending => return error.TestUnexpectedPending,
    };
    defer credential.release();
    const chain = credential.certificateChain();
    try std.testing.expectEqual(@as(usize, 1), chain.count());
    try std.testing.expectEqualSlices(u8, expected_leaf, chain.leaf().?);
}

fn freeTestCertChain(allocator: std.mem.Allocator, chain: [][]u8) void {
    for (chain) |entry| allocator.free(entry);
    allocator.free(chain);
}

/// Like `expectSelectedLeaf`, but for a specific SNI (or `null` for the
/// absent-SNI/default case) and offering ed25519/ecdsa/rsa schemes so a
/// managed (RSA) bundle is selectable too (#880).
fn selectFor(provider: credentials.CredentialProvider, server_name: ?[]const u8) !credentials.SelectedCredential {
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = server_name,
        .peer_signature_schemes = &.{ 0x0807, 0x0403, 0x0804 },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    return switch (try provider.selectCredential(&selection)) {
        .complete => |credential| credential,
        .pending => error.TestUnexpectedPending,
    };
}

fn expectSelectedLeafFor(provider: credentials.CredentialProvider, server_name: ?[]const u8, expected_leaf: []const u8) !void {
    const credential = try selectFor(provider, server_name);
    defer credential.release();
    try std.testing.expectEqualSlices(u8, expected_leaf, credential.certificateChain().leaf().?);
}

fn testResumptionRuntime(allocator: std.mem.Allocator) !tls.resumption_runtime.Runtime {
    var entropy = production_crypto.OsEntropy{};
    var provider_state = production_crypto.Provider.init(entropy.entropy());
    return tls.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMs },
        provider_state.cryptoProvider(),
    );
}

const TicketIssueProbe = struct {
    count: usize = 0,
    transport: tls.resumption_runtime.Transport = undefined,
    mode: tls.resumption_runtime.Mode = undefined,
    result: tls.resumption_runtime.TicketResult = undefined,

    fn observer(self: *TicketIssueProbe) tls.resumption_runtime.Observer {
        return .{
            .ctx = self,
            .onTicketIssueFn = onTicketIssue,
        };
    }

    fn onTicketIssue(
        ctx: *anyopaque,
        transport: tls.resumption_runtime.Transport,
        mode: tls.resumption_runtime.Mode,
        result: tls.resumption_runtime.TicketResult,
    ) void {
        const self: *TicketIssueProbe = @ptrCast(@alignCast(ctx));
        self.count += 1;
        self.transport = transport;
        self.mode = mode;
        self.result = result;
    }
};

fn armNativeTicketIssuer(conn: *NativeTlsConnection) !void {
    const hs_read = [_]u8{0x21} ** 32;
    const hs_write = [_]u8{0x22} ** 32;
    const app_read = [_]u8{0x23} ** 32;
    const app_write = [_]u8{0x24} ** 32;
    try conn.record.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &hs_read } });
    try conn.record.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &hs_write } });
    try conn.record.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &app_read } });
    try conn.record.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &app_write } });
    try conn.record.applyEvent(.{ .discard_epoch = .initial });
    try conn.record.applyEvent(.{ .discard_epoch = .handshake });
    try conn.record.applyEvent(.handshake_complete);
    conn.backend.core.handshake_lifecycle = .complete;
    try conn.backend.resumption_master_secret.replace(&([_]u8{0x42} ** tls.tls13_backend.hash_len));
}

fn expectOnlyStatefulTicketEarlyData(runtime: *tls.resumption_runtime.Runtime, expected: tls.session.EarlyDataPolicy) !void {
    const cache = &runtime.server_cache.?;
    cache.mutex.lock();
    defer cache.mutex.unlock();
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());
    var it = cache.entries.valueIterator();
    const entry = it.next().?.*;
    try std.testing.expectEqual(expected, entry.state.common.early_data);
}

const CacheEventProbe = struct {
    stored: usize = 0,

    fn observer(self: *CacheEventProbe) tls.session_cache.Observer {
        return .{ .ctx = self, .onEventFn = onEvent };
    }

    fn onEvent(ctx: *anyopaque, event: tls.session_cache.CacheEvent) void {
        const self: *CacheEventProbe = @ptrCast(@alignCast(ctx));
        if (event == .stored) self.stored += 1;
    }
};

test "native TLS createWithOptions installs the shared server resolver when configured" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var runtime = try testResumptionRuntime(std.testing.allocator);
    defer runtime.deinit();

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .resumption_runtime = &runtime },
    );
    defer conn.destroy();

    try std.testing.expect(conn.backend.psk_resolver != null);
    try std.testing.expectEqual(@as(?*tls.resumption_runtime.Runtime, &runtime), conn.resumption_runtime);
}

test "native TLS createWithOptions installs the shared early-data replay gate independently of the resumption runtime" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var store = try tls.early_data_replay.LocalStore.init(std.testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var adapter = tls.early_data_replay.GateAdapter.init(store.store());
    const gate = adapter.gate();

    // No `resumption_runtime` supplied: the replay gate must still install,
    // proving it is not gated on resumption plumbing.
    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .early_data_replay_gate = gate },
    );
    defer conn.destroy();

    try std.testing.expectEqual(gate.ctx, conn.backend.early_data_replay_gate.ctx);
    try std.testing.expectEqual(gate.decideFn, conn.backend.early_data_replay_gate.decideFn);
}

test "native TLS server early data policy is disabled unless resumption and replay gate are both configured" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();

    var runtime = try testResumptionRuntime(std.testing.allocator);
    defer runtime.deinit();

    var store = try tls.early_data_replay.LocalStore.init(std.testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var adapter = tls.early_data_replay.GateAdapter.init(store.store());
    const gate = adapter.gate();

    {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{
                .resumption_runtime = &runtime,
                .server_early_data_policy = .{ .enabled = true, .max_early_data_size = 4096 },
            },
        );
        defer conn.destroy();
        try std.testing.expect(!conn.backend.server_early_data_policy.enabled);
    }

    {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{
                .early_data_replay_gate = gate,
                .server_early_data_policy = .{ .enabled = true, .max_early_data_size = 4096 },
            },
        );
        defer conn.destroy();
        try std.testing.expect(!conn.backend.server_early_data_policy.enabled);
    }

    {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{
                .resumption_runtime = &runtime,
                .early_data_replay_gate = gate,
                .server_early_data_policy = .{ .enabled = true, .max_early_data_size = 4096 },
            },
        );
        defer conn.destroy();
        try std.testing.expect(conn.backend.server_early_data_policy.enabled);
        try std.testing.expectEqual(@as(u32, 4096), conn.backend.server_early_data_policy.max_early_data_size);
    }
}

test "native TLS production ticket issuance advertises early data only when policy is enabled" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();

    {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        var runtime = try testResumptionRuntime(std.testing.allocator);
        defer runtime.deinit();
        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{ .resumption_runtime = &runtime },
        );
        defer conn.destroy();
        try armNativeTicketIssuer(conn);
        conn.maybeIssueSessionTicket();
        try std.testing.expect(conn.ticket_issue_attempted);
        try expectOnlyStatefulTicketEarlyData(&runtime, .resume_only);
    }

    {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        var runtime = try testResumptionRuntime(std.testing.allocator);
        defer runtime.deinit();
        var store = try tls.early_data_replay.LocalStore.init(std.testing.allocator, .{}, 0, 0);
        defer store.deinit();
        var adapter = tls.early_data_replay.GateAdapter.init(store.store());
        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{
                .resumption_runtime = &runtime,
                .early_data_replay_gate = adapter.gate(),
                .server_early_data_policy = .{ .enabled = true, .max_early_data_size = 8192 },
            },
        );
        defer conn.destroy();
        try armNativeTicketIssuer(conn);
        conn.maybeIssueSessionTicket();
        try std.testing.expect(conn.ticket_issue_attempted);
        try expectOnlyStatefulTicketEarlyData(&runtime, .{ .early_data_capable = 8192 });
    }
}

test "native TLS without a resumption runtime never attempts ticket issuance" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    const conn = try NativeTlsConnection.create(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
    );
    defer conn.destroy();

    try std.testing.expect(conn.backend.psk_resolver == null);
    conn.maybeIssueSessionTicket();
    try std.testing.expect(!conn.ticket_issue_attempted);
}

test "native TLS failed post-handshake issuance notifies the runtime observer once" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var runtime = try testResumptionRuntime(std.testing.allocator);
    defer runtime.deinit();
    var probe = TicketIssueProbe{};
    runtime.setObserver(probe.observer());

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .resumption_runtime = &runtime },
    );
    defer conn.destroy();

    conn.record.lifecycle = .open;
    conn.record.bridge.handshake_complete = true;
    runtime.config.ticket_lifetime_seconds = 0;

    conn.maybeIssueSessionTicket();
    try std.testing.expect(conn.ticket_issue_attempted);
    try std.testing.expectEqual(@as(usize, 1), probe.count);
    try std.testing.expectEqual(tls.resumption_runtime.Transport.record, probe.transport);
    try std.testing.expectEqual(tls.resumption_runtime.Mode.stateful, probe.mode);
    try std.testing.expectEqual(tls.resumption_runtime.TicketResult.failed, probe.result);

    conn.maybeIssueSessionTicket();
    try std.testing.expectEqual(@as(usize, 1), probe.count);
}

test "native TLS post-handshake queue pressure rolls back inserted stateful handle and keeps stream open" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var runtime = try testResumptionRuntime(std.testing.allocator);
    defer runtime.deinit();
    var issue_probe = TicketIssueProbe{};
    runtime.setObserver(issue_probe.observer());
    var cache_probe = CacheEventProbe{};
    runtime.server_cache.?.setObserver(cache_probe.observer());

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .resumption_runtime = &runtime },
    );
    defer conn.destroy();

    try armNativeTicketIssuer(conn);

    try std.testing.expectEqual(@as(usize, 0), runtime.server_cache.?.count());
    conn.record.outbound_ciphertext.len = encrypted_stream.PureZigRecordStream.max_ciphertext_queue - 1;
    conn.maybeIssueSessionTicket();

    try std.testing.expect(conn.ticket_issue_attempted);
    try std.testing.expectEqual(@as(usize, 1), cache_probe.stored);
    try std.testing.expectEqual(@as(usize, 0), runtime.server_cache.?.count());
    try std.testing.expectEqual(@as(usize, 1), issue_probe.count);
    try std.testing.expectEqual(tls.resumption_runtime.TicketResult.failed, issue_probe.result);
    try std.testing.expect(conn.record.lifecycle == .open);
    try std.testing.expect(conn.record.failed == null);

    conn.record.outbound_ciphertext.len = 0;
    const written = try conn.record.stream().write("still-open");
    try std.testing.expectEqual(@as(usize, "still-open".len), written);
    try std.testing.expect(conn.record.queuedCiphertextLen() > 0);
}

/// Test allocator that observes every release of a buffer with exactly
/// `target_len` bytes and records whether it was all-zero at that moment.
/// `Allocator.free` scribbles `undefined` (0xaa in safe builds) before the
/// backing allocator sees the bytes, so only a release through
/// `secureZeroAndFree` (which calls `rawFree`) arrives zeroed (#783).
const ScratchReleaseProbe = struct {
    backing: std.mem.Allocator,
    target_len: usize,
    released: usize = 0,
    released_nonzero: usize = 0,

    fn allocator(self: *ScratchReleaseProbe) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ScratchReleaseProbe = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ScratchReleaseProbe = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *ScratchReleaseProbe = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ScratchReleaseProbe = @ptrCast(@alignCast(ctx));
        if (memory.len == self.target_len) {
            self.released += 1;
            if (!std.mem.allEqual(u8, memory, 0)) self.released_nonzero += 1;
        }
        self.backing.rawFree(memory, alignment, ret_addr);
    }
};

test "native TLS ticket issuance releases identity scratch zeroed on success and on queue-pressure failure (#783)" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();

    for ([_]bool{ false, true }) |force_queue_failure| {
        const fds = try testSocketPair();
        defer closeFd(fds[1]);
        var runtime = try testResumptionRuntime(std.testing.allocator);
        defer runtime.deinit();
        var issue_probe = TicketIssueProbe{};
        runtime.setObserver(issue_probe.observer());

        const conn = try NativeTlsConnection.createWithOptions(
            std.testing.allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            fixed.provider(),
            .{ .resumption_runtime = &runtime },
        );
        defer conn.destroy();
        try armNativeTicketIssuer(conn);

        // Route only the issuance call through the probe; it forwards to the
        // same backing allocator, so ownership is unchanged either side.
        var probe = ScratchReleaseProbe{ .backing = conn.allocator, .target_len = runtime.maxIdentityLen() };
        const saved_allocator = conn.allocator;
        conn.allocator = probe.allocator();
        defer conn.allocator = saved_allocator;

        if (force_queue_failure)
            conn.record.outbound_ciphertext.len = encrypted_stream.PureZigRecordStream.max_ciphertext_queue - 1;
        conn.maybeIssueSessionTicket();
        conn.allocator = saved_allocator;
        if (force_queue_failure) conn.record.outbound_ciphertext.len = 0;

        try std.testing.expect(conn.ticket_issue_attempted);
        try std.testing.expectEqual(@as(usize, 1), issue_probe.count);
        try std.testing.expectEqual(
            if (force_queue_failure) tls.resumption_runtime.TicketResult.failed else tls.resumption_runtime.TicketResult.success,
            issue_probe.result,
        );
        try std.testing.expect(probe.released >= 1);
        try std.testing.expectEqual(@as(usize, 0), probe.released_nonzero);
    }
}

test "native TLS never attempts ticket issuance before application data opens" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var runtime = try testResumptionRuntime(std.testing.allocator);
    defer runtime.deinit();

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .resumption_runtime = &runtime },
    );
    defer conn.destroy();

    try std.testing.expect(!conn.record.applicationDataOpen());
    conn.maybeIssueSessionTicket();
    try std.testing.expect(!conn.ticket_issue_attempted);
}

test "native TLS negotiated protocol is unavailable before application data opens" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    const conn = try NativeTlsConnection.create(
        std.testing.allocator,
        fds[0],
        .{
            .http1_enabled = true,
            .http2_enabled = true,
            .allow_http1_without_alpn = true,
        },
        fixed.provider(),
    );
    defer conn.destroy();

    try std.testing.expectError(error.HandshakeNotComplete, conn.validatedNegotiatedProtocol());
    try std.testing.expect(conn.negotiated == null);
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    return fds;
}

// ---------------------------------------------------------------------------
// #763: downstream client-certificate authentication.
// ---------------------------------------------------------------------------

fn testClientVerdict(
    allocator: std.mem.Allocator,
    trust: *const webpki_verifier.TrustAnchors,
    leaf_pem_path: []const u8,
    depth: usize,
) !credentials.Verdict {
    const leaf_pem = try compat.cwd().readFileAlloc(allocator, leaf_pem_path, 256 * 1024);
    defer allocator.free(leaf_pem);
    const chain = try tls.identity_loader.certChainFromPemOrDer(allocator, leaf_pem);
    defer freeTestCertChain(allocator, chain);
    const views = try allocator.alloc([]const u8, chain.len);
    defer allocator.free(views);
    for (chain, 0..) |entry, i| views[i] = entry;

    var entropy = production_crypto.OsEntropy{};
    var provider_state = production_crypto.Provider.init(entropy.entropy());
    var verifier = webpki_verifier.WebPkiVerifier.initClientAuth(allocator, trust.anchors(), provider_state.cryptoProvider(), depth);
    const context = credentials.VerificationContext{
        .role = .server,
        // The SNI the client asked for names *this server*; it must never
        // become a hostname policy on the client certificate.
        .server_name = "unrelated.example",
        .chain = .{ .entries = views },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{ .require_peer_authentication = true },
    };
    return switch (try verifier.verifier().verifyPeer(&context)) {
        .complete => |verdict| verdict,
        .pending => error.UnexpectedPending,
    };
}

test "client-auth verifier accepts a CA-issued clientAuth cert and rejects wrong CA, wrong EKU, and garbage" {
    const allocator = std.testing.allocator;
    var anchors = try webpki_verifier.loadTrustAnchors(allocator, "tests/fixtures/tls/ca.crt");
    defer anchors.deinit(allocator);

    try std.testing.expectEqual(credentials.Verdict.accepted, try testClientVerdict(allocator, &anchors, "tests/fixtures/tls/client.crt", 3));
    // Issued by a different CA than the configured trust anchor.
    try std.testing.expectEqual(credentials.Verdict.rejected, try testClientVerdict(allocator, &anchors, "tests/fixtures/tls/rogue_client.crt", 3));
    // Right CA, but a serverAuth-only certificate is not a client identity.
    try std.testing.expectEqual(credentials.Verdict.rejected, try testClientVerdict(allocator, &anchors, "tests/fixtures/tls/server.crt", 3));
    // Self-signed leaf that is not itself a configured anchor.
    try std.testing.expectEqual(credentials.Verdict.rejected, try testClientVerdict(allocator, &anchors, "tests/fixtures/tls/native_ed25519.crt", 3));
}

test "client trust store rotates atomically and a failed prepare keeps the serving generation" {
    const allocator = std.testing.allocator;
    var store = ClientTrustStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.acquire() == null);
    try std.testing.expectError(error.ClientTrustPathRequired, store.prepare("", 3));

    var first = try store.prepare("tests/fixtures/tls/ca.crt", 3);
    store.commit(&first);
    // A handshake pins generation one, then a reload publishes generation two.
    const pinned = store.acquire().?;
    defer pinned.release();

    try std.testing.expectError(error.FileNotFound, store.prepare("tests/fixtures/tls/does-not-exist.pem", 3));
    const still_serving = store.acquire().?;
    defer still_serving.release();
    try std.testing.expectEqual(pinned, still_serving);

    var second = try store.prepare("tests/fixtures/tls/native_ed25519_ca.crt", 5);
    store.commit(&second);
    const current = store.acquire().?;
    defer current.release();
    try std.testing.expect(current != pinned);
    try std.testing.expectEqual(@as(usize, 5), current.max_path_length);
    // The pinned generation keeps verifying against the *old* anchors.
    try std.testing.expectEqual(@as(usize, 3), pinned.max_path_length);
    try std.testing.expectEqual(credentials.Verdict.accepted, try testClientVerdict(allocator, &pinned.anchors, "tests/fixtures/tls/client.crt", 3));
    try std.testing.expectEqual(credentials.Verdict.rejected, try testClientVerdict(allocator, &current.anchors, "tests/fixtures/tls/client.crt", 3));
    // A CA bundle must be made of real CAs: a non-CA "anchor" fails the load.
    try std.testing.expectError(error.NonCaAnchor, store.prepare("tests/fixtures/tls/rogue_ca.crt", 3));
}

test "native TLS client auth fails closed without a published trust generation" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try std.testing.expectError(error.ClientTrustUnavailable, NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_auth = .required },
    ));

    var store = ClientTrustStore.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.ClientTrustUnavailable, NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_auth = .optional, .client_trust = &store },
    ));
}

test "native TLS client auth pins a trust generation for the connection lifetime" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var store = ClientTrustStore.init(std.testing.allocator);
    defer store.deinit();
    var prepared = try store.prepare("tests/fixtures/tls/ca.crt", 3);
    store.commit(&prepared);

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_auth = .required, .client_trust = &store },
    );
    try std.testing.expect(conn.client_trust_generation != null);
    try std.testing.expect(conn.backend.client_auth == .required);
    // No handshake has run: no identity may exist.
    try conn.finalizeClientIdentity();
    try std.testing.expect(conn.clientIdentity() == null);
    // Rotating trust while the connection is alive must not free its anchors.
    var rotated = try store.prepare("tests/fixtures/tls/native_ed25519_ca.crt", 3);
    store.commit(&rotated);
    conn.destroy();
}

fn testPolicySnapshot(set: *ClientPolicySet, comptime api_mode: tls_backend.ClientAuthMode) !void {
    const specs = [_]tls.client_trust.PolicySpec{
        .{ .names = &.{"api.example.test"}, .mode = api_mode, .ca_path = "tests/fixtures/tls/ca.crt" },
        .{ .names = &.{"admin.example.test"}, .mode = .required, .ca_path = "tests/fixtures/tls/native_ed25519_ca.crt" },
        .{ .names = &.{"open.example.test"}, .mode = .disabled },
    };
    var prepared = try set.prepare(.{}, &specs, tls.client_trust.exactNameMatcher);
    set.commit(&prepared);
}

test "native TLS per-SNI policy: the connection installs the selector and only admits hosts whose policy matches its SNI-selected one (#763)" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    var set = ClientPolicySet.init(std.testing.allocator);
    defer set.deinit();
    try testPolicySnapshot(&set, .required);
    const snapshot = set.acquire().?;
    defer snapshot.release();

    const conn = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_policies = snapshot },
    );
    defer conn.destroy();
    try std.testing.expect(conn.backend.client_auth_selector != null);
    try std.testing.expect(conn.client_trust_generation == null);

    const decision = try NativeTlsConnection.selectClientAuth(conn, "api.example.test");
    try std.testing.expectEqual(tls_backend.ClientAuthMode.required, decision.mode);
    try std.testing.expect(decision.verifier != null);
    try std.testing.expect(conn.client_trust_generation != null);

    try std.testing.expect(conn.clientPolicyAdmitsHost("api.example.test"));
    try std.testing.expect(conn.clientPolicyAdmitsHost("api.example.test:8443"));
    try std.testing.expect(conn.clientPolicyAdmitsHost("open.example.test")); // needs no client auth
    try std.testing.expect(!conn.clientPolicyAdmitsHost("admin.example.test")); // different CA
    try std.testing.expect(conn.clientPolicyAdmitsHost("unknown.example.test")); // fallback is "no client auth"

    // A second ClientHello (after HelloRetryRequest) re-selects and releases the first pin.
    const open = try NativeTlsConnection.selectClientAuth(conn, "open.example.test");
    try std.testing.expectEqual(tls_backend.ClientAuthMode.disabled, open.mode);
    try std.testing.expect(conn.client_trust_generation == null);
    try std.testing.expect(!conn.clientPolicyAdmitsHost("api.example.test")); // anonymous connection, host demands mTLS
}

test "native TLS per-SNI policy: a delayed ClientHello and later requests stay on the generation the connection was admitted under (#763)" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity(), credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);
    const fds2 = try testSocketPair();
    defer closeFd(fds2[1]);

    var set = ClientPolicySet.init(std.testing.allocator);
    defer set.deinit();
    // Generation N: api requires a client certificate.
    try testPolicySnapshot(&set, .required);
    const gen_n = set.acquire().?;
    defer gen_n.release();
    const strict = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_policies = gen_n },
    );
    defer strict.destroy();

    // Reload to N+1 (api disabled) BEFORE the ClientHello arrives.
    try testPolicySnapshot(&set, .disabled);
    const gen_n1 = set.acquire().?;
    defer gen_n1.release();
    try std.testing.expect(gen_n1 != gen_n);

    // required -> disabled must NOT fail open: the late ClientHello still
    // gets generation N's required policy, and Host admission agrees.
    const late = try NativeTlsConnection.selectClientAuth(strict, "api.example.test");
    try std.testing.expectEqual(tls_backend.ClientAuthMode.required, late.mode);
    try std.testing.expect(strict.clientPolicyAdmitsHost("api.example.test"));
    try std.testing.expect(!strict.clientPolicyAdmitsHost("admin.example.test"));

    // The reverse transition (disabled -> required) also stays on its own
    // generation: a connection admitted under N+1 is anonymous and must not
    // reach the host N+2 now protects.
    const loose = try NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds2[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .client_policies = gen_n1 },
    );
    defer loose.destroy();
    try testPolicySnapshot(&set, .required);
    const anon = try NativeTlsConnection.selectClientAuth(loose, "api.example.test");
    try std.testing.expectEqual(tls_backend.ClientAuthMode.disabled, anon.mode);
    try std.testing.expect(loose.clientPolicyAdmitsHost("api.example.test")); // N+1 says api is open
    try std.testing.expect(!loose.clientPolicyAdmitsHost("admin.example.test")); // required host, anonymous connection
}

test "client verify depth counts non-anchor certificates: N accepts exactly N, N-1 rejects (#763)" {
    const allocator = std.testing.allocator;
    // leaf -> anchor: one non-anchor certificate.
    var direct = try webpki_verifier.loadTrustAnchors(allocator, "tests/fixtures/tls/ca.crt");
    defer direct.deinit(allocator);
    try std.testing.expectEqual(credentials.Verdict.accepted, try testClientVerdict(allocator, &direct, "tests/fixtures/tls/client.crt", 1));

    // leaf -> intermediate -> anchor: two non-anchor certificates.
    var rooted = try webpki_verifier.loadTrustAnchors(allocator, "tests/fixtures/tls/client_depth_root.crt");
    defer rooted.deinit(allocator);
    const chain = "tests/fixtures/tls/client_depth_chain.crt";
    try std.testing.expectEqual(credentials.Verdict.rejected, try testClientVerdict(allocator, &rooted, chain, 1));
    try std.testing.expectEqual(credentials.Verdict.accepted, try testClientVerdict(allocator, &rooted, chain, 2));
    // The same bound feeds both the path builder and the validator.
    try std.testing.expectEqual(credentials.Verdict.accepted, try testClientVerdict(allocator, &rooted, chain, 8));
}
