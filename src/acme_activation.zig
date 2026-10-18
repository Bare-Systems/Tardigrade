//! A4 product integration for automatic HTTPS (#884, epic #759, design
//! `docs/ACME_AUTOMATIC_HTTPS.md` §7, §8.3, §9.2). This is the glue none of
//! #879 (verification/persistence), #880 (bytes-based publish) or #883
//! (orders/HTTP-01) provide alone: deciding what a freshly started process
//! should serve, driving one issuance attempt per managed group against the
//! real CA, and republishing/tracking the result.
//!
//! Not the renewal worker (#835/A5): there is no scheduler, no periodic
//! wake-up, no cross-restart backoff here. `runBootstrapOnce` makes exactly
//! one attempt per group that still needs a certificate, on a background
//! thread started once at startup; a failure is logged and leaves whatever
//! was already being served (possibly nothing) untouched, exactly as every
//! other phase in this design documents.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const crypto = @import("crypto");

const acme = http.acme;
const secrets = crypto.secrets;

pub const ManagedBundleSpec = http.native_tls_connection.ManagedBundleSpec;
pub const NativeCredentialStore = http.native_tls_connection.NativeCredentialStore;
pub const SniCertSpec = http.native_tls_connection.SniCertSpec;
pub const ChallengeStore = http.acme_http01_listener.ChallengeStore;

/// Tracks which managed hostnames currently have a published generation, so
/// the HTTP-01 listener's optional `https_redirect` (design §8.3) can skip
/// redirecting a first-run deployment to a door that is still closed.
/// Deliberately independent of `sni_provider`: this answers "has A4 ever
/// published this host", not "would a handshake succeed right now", and
/// never needs to inspect a `Snapshot`.
pub const PublishedHosts = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    hosts: std.StringHashMapUnmanaged(void) = .{},

    pub fn init(allocator: std.mem.Allocator) PublishedHosts {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PublishedHosts) void {
        var it = self.hosts.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.hosts.deinit(self.allocator);
        self.* = undefined;
    }

    /// Idempotent per name; a name already marked published is left alone.
    pub fn markGroup(self: *PublishedHosts, names: []const []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (names) |name| {
            if (self.hosts.contains(name)) continue;
            const owned = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(owned);
            try self.hosts.put(self.allocator, owned, {});
        }
    }

    pub fn isPublished(self: *PublishedHosts, host: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.hosts.contains(host);
    }
};

const OwnedBundle = struct {
    chain_pem: []u8,
    key_pem: []u8,

    fn deinit(self: *OwnedBundle, allocator: std.mem.Allocator) void {
        allocator.free(self.chain_pem);
        secrets.secureZeroAndFree(allocator, self.key_pem);
    }
};

/// The complete current managed bundle set for every group that has a valid
/// committed generation, loaded fresh from disk. Design §7.1: "the managed
/// bundle set is rebuilt from **all** groups every publish" -- this is the
/// one place that rebuild happens, shared by the startup bootstrap and by
/// `gateway_shutdown.hotReloadConfig`'s file-only reload path.
///
/// `specs[i].hostnames` borrows from the `acme.groups.GroupList` the caller
/// passed to `load`; the caller must keep that `GroupList` (and the
/// `domains_spec` string it was parsed from) alive for at least as long as
/// this `ManagedBundleSet`.
pub const ManagedBundleSet = struct {
    allocator: std.mem.Allocator,
    owned: []OwnedBundle,
    specs: []ManagedBundleSpec,

    pub fn deinit(self: *ManagedBundleSet) void {
        self.allocator.free(self.specs);
        for (self.owned) |*bundle| bundle.deinit(self.allocator);
        self.allocator.free(self.owned);
        self.* = undefined;
    }

    pub fn slice(self: *const ManagedBundleSet) []const ManagedBundleSpec {
        return self.specs;
    }
};

/// Loads every group's committed generation (`acme.activate.loadCommitted`,
/// restart recovery, no network) and returns it as a bytes-based managed
/// bundle set ready for `NativeCredentialStore.prepareReloadFromBundles`. A
/// group with no valid generation yet is simply absent from the result,
/// never an error.
pub fn loadManagedBundleSet(
    allocator: std.mem.Allocator,
    state: *acme.state.StateDir,
    group_list: *const acme.groups.GroupList,
    now: i64,
) !ManagedBundleSet {
    var owned_list = std.ArrayList(OwnedBundle).empty;
    errdefer {
        for (owned_list.items) |*bundle| bundle.deinit(allocator);
        owned_list.deinit(allocator);
    }
    var specs_list = std.ArrayList(ManagedBundleSpec).empty;
    errdefer specs_list.deinit(allocator);

    // Pointer capture, not a by-value copy: `ManagedBundleSpec.hostnames`
    // below borrows `group.slice()`, which is a slice of `group`'s *own*
    // embedded array -- it must point into `group_list`'s actual backing
    // storage (stable for the caller-owned `GroupList`'s lifetime), not a
    // per-iteration stack temporary that goes out of scope.
    for (group_list.groups[0..group_list.len]) |*group| {
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, group.slice());
        const loaded_opt = try acme.activate.loadCommitted(allocator, state, group_id, group.slice(), now);
        var loaded = loaded_opt orelse continue;
        const key_pem = loaded.leaf_key.toPkcs8Pem(allocator) catch |err| {
            loaded.deinit(allocator);
            return err;
        };
        const chain_pem = loaded.chain_pem;
        // Ownership of `chain_pem` transfers to `owned_list` below; release
        // only the other two fields here instead of calling
        // `loaded.deinit(allocator)`.
        loaded.leaf_key.deinit();
        loaded.meta.deinit();

        // `loaded` no longer owns either PEM after the detach above, but the
        // list does not own them until this append succeeds.  In particular,
        // preserve the private-key wipe on an OOM here.
        var transferred = false;
        errdefer if (!transferred) {
            allocator.free(chain_pem);
            secrets.secureZeroAndFree(allocator, key_pem);
        };
        try owned_list.append(allocator, .{ .chain_pem = chain_pem, .key_pem = key_pem });
        transferred = true;
        try specs_list.append(allocator, .{ .hostnames = group.slice(), .chain_pem = chain_pem, .key_pem = key_pem });
    }

    const owned = try owned_list.toOwnedSlice(allocator);
    errdefer {
        for (owned) |*bundle| bundle.deinit(allocator);
        allocator.free(owned);
    }
    const specs = try specs_list.toOwnedSlice(allocator);
    return .{ .allocator = allocator, .owned = owned, .specs = specs };
}

fn sameNameSet(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a) |name_a| {
        for (b) |name_b| {
            if (std.ascii.eqlIgnoreCase(name_a, name_b)) break;
        } else return false;
    }
    return true;
}

pub const RecoverResult = struct {
    group_list: acme.groups.GroupList,
    /// Parallel to `group_list.slice()`: whether that group still needs a
    /// fresh issuance attempt (no valid committed generation was found on
    /// disk).
    needs_issuance: [acme.groups.max_groups]bool = @splat(true),
};

/// Design §5.5 "Restart": load whatever is already committed on disk and
/// publish it *before any network access*, so a restart during a CA outage
/// still serves the certificate it already has. Runs synchronously (local,
/// bounded disk I/O only) at startup, before the background issuance
/// attempt below. A hard error here (bad state-dir ownership/permissions,
/// corrupt lock) is a startup failure, not a soft "serve nothing" outcome:
/// an operator-visible, deterministic failure beats silently ignoring a
/// tampered-with state directory.
pub fn recoverFromDisk(
    allocator: std.mem.Allocator,
    domains_spec: []const u8,
    state_dir_path: []const u8,
    default_cert_path: []const u8,
    default_key_path: []const u8,
    sni_certs: []const SniCertSpec,
    store: *NativeCredentialStore,
    published: *PublishedHosts,
    now: i64,
) !RecoverResult {
    const group_list = acme.groups.parse(domains_spec) catch return error.InvalidAcmeDomains;
    var result = RecoverResult{ .group_list = group_list };

    var state = try acme.state.StateDir.open(state_dir_path);
    defer state.close();

    var bundles = try loadManagedBundleSet(allocator, &state, &group_list, now);
    defer bundles.deinit();

    for (group_list.slice(), 0..) |group, i| {
        for (bundles.slice()) |spec| {
            if (sameNameSet(spec.hostnames, group.slice())) {
                result.needs_issuance[i] = false;
                break;
            }
        }
    }

    if (default_cert_path.len > 0 or sni_certs.len > 0 or bundles.slice().len > 0) {
        var prepared = try store.prepareReloadFromBundles(default_cert_path, default_key_path, sni_certs, bundles.slice());
        defer prepared.deinit();
        try store.commitPreparedReload(&prepared);
        for (bundles.slice()) |spec| try published.markGroup(spec.hostnames);
    }

    return result;
}

/// Everything `runBootstrapOnce` needs to drive one issuance attempt per
/// managed group and republish the result. Owned by the caller (typically a
/// stack variable in `edge_gateway.run()`) with a stable address for the
/// lifetime of the background thread `start` spawns.
pub const IssueOptions = struct {
    directory_url: []const u8,
    contact_email: []const u8 = "",
    terms_of_service_agreed: bool = false,
    account_key_path: []const u8 = "",
    /// Borrowed; already loaded by the caller (design §9.3: before any
    /// privilege drop/chroot). `BootstrapCtx`'s own `TlsDialer` retains its
    /// own reference, so the caller may release its copy any time after
    /// `BootstrapCtx.stopAndJoin()` returns.
    trust_anchors: *acme.transport.TrustAnchorSnapshot,
};

pub const BootstrapCtx = struct {
    allocator: std.mem.Allocator,
    state_dir_path: []const u8,
    default_cert_path: []const u8,
    default_key_path: []const u8,
    sni_certs: []const SniCertSpec,
    issue: IssueOptions,
    store: *NativeCredentialStore,
    challenge_store: *ChallengeStore,
    published: *PublishedHosts,
    /// Builds a publication snapshot from the currently live config rather
    /// than the startup-only manual cert/SNI mapping.  The gateway supplies
    /// this so an issuance completing after SIGHUP cannot resurrect stale
    /// manual credentials.  Kept optional for focused unit tests.
    prepare_current_credentials: ?*const fn (
        ?*anyopaque,
        std.mem.Allocator,
        *NativeCredentialStore,
        []const ManagedBundleSpec,
    ) anyerror!NativeCredentialStore.PreparedReload = null,
    credential_config_ctx: ?*anyopaque = null,
    group_list: acme.groups.GroupList,
    needs_issuance: [acme.groups.max_groups]bool,
    logger: http.logger.Logger,
    cancel: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    pub fn start(self: *BootstrapCtx) !void {
        self.thread = try std.Thread.spawn(.{}, runThread, .{self});
    }

    /// Idempotent; safe to call even if `start` was never called or the
    /// thread already finished on its own.
    pub fn stopAndJoin(self: *BootstrapCtx) void {
        self.cancel.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
    }
};

fn runThread(ctx: *BootstrapCtx) void {
    runBootstrapOnce(ctx) catch |err| {
        ctx.logger.warn(null, "ACME bootstrap issuance attempt failed (class={s}, error={s})", .{ @tagName(acme.client.classify(err)), @errorName(err) });
    };
}

fn cancelCheck(ctx: ?*anyopaque) bool {
    const flag: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
    return flag.load(.acquire);
}

/// One pass over every group still missing a valid generation: open the ACME
/// session (account), attempt `obtain()` + `verifyAndPersist()` once per
/// group, then -- if anything succeeded -- rebuild and republish the
/// complete managed set (design §7.1: a publish for one group must never
/// drop another). A group's own failure never aborts the others; this
/// function itself never returns an error for a per-group failure, only for
/// a setup failure (trust anchors, account) that makes every attempt moot.
fn runBootstrapOnce(ctx: *BootstrapCtx) !void {
    var dialer = http.acme_tls_dialer.TlsDialer.init(ctx.issue.trust_anchors);
    defer dialer.deinit();
    try runBootstrapWithDialer(ctx, dialer.dialer());
}

/// The CA-reachable half of `runBootstrapOnce`, taking an already-built
/// `Dialer` rather than constructing the production TLS one -- the seam a
/// test substitutes `fake_ca.FakeCa.dialer()` through, exactly like
/// `acme_account_cmd.openAccount` does for the account-only phase.
fn runBootstrapWithDialer(ctx: *BootstrapCtx, dialer: acme.transport.Dialer) !void {
    var any_needed = false;
    for (ctx.group_list.slice(), 0..) |_, i| {
        if (ctx.needs_issuance[i]) any_needed = true;
    }
    if (!any_needed) return;

    var transport_inst = acme.transport.Transport{ .allocator = ctx.allocator, .dialer = dialer };
    // StateDir's advisory lock protects short durable-state transitions, not
    // the potentially minutes-long HTTP-01 order/polling loop.  The session
    // retains its key/client after this scope, so routine SIGHUP reloads can
    // read the last committed managed set while issuance is in flight.
    const session = try acme.client.Session.openUnlocked(ctx.allocator, &transport_inst, ctx.state_dir_path, .{
        .directory_url = ctx.issue.directory_url,
        .contact_email = ctx.issue.contact_email,
        .terms_of_service_agreed = ctx.issue.terms_of_service_agreed,
        .account_key_path = ctx.issue.account_key_path,
    }, compat.unixTimestamp());
    defer session.close();

    var issued_any = false;
    for (ctx.group_list.slice(), 0..) |group, i| {
        if (ctx.cancel.load(.acquire)) break;
        if (!ctx.needs_issuance[i]) continue;
        issueGroup(ctx, &session.client, group) catch |err| {
            ctx.logger.warn(null, "ACME issuance failed for a managed group (class={s}, error={s})", .{ @tagName(acme.client.classify(err)), @errorName(err) });
            continue;
        };
        issued_any = true;
    }
    if (!issued_any) return;

    var bundles = blk: {
        var state = try acme.state.StateDir.open(ctx.state_dir_path);
        defer state.close();
        break :blk try loadManagedBundleSet(ctx.allocator, &state, &ctx.group_list, compat.unixTimestamp());
    };
    defer bundles.deinit();
    if (bundles.slice().len == 0) return;
    // The state-directory lock was released after the durable generation was
    // fully loaded above; all later work is in memory.
    try publishManagedBundles(ctx, bundles.slice());
    for (bundles.slice()) |spec| try ctx.published.markGroup(spec.hostnames);
}

fn publishManagedBundles(ctx: *BootstrapCtx, bundles: []const ManagedBundleSpec) !void {
    var attempts: u8 = 0;
    while (attempts < 3) : (attempts += 1) {
        var prepared = if (ctx.prepare_current_credentials) |prepare|
            try prepare(ctx.credential_config_ctx, ctx.allocator, ctx.store, bundles)
        else
            try ctx.store.prepareReloadFromBundles(ctx.default_cert_path, ctx.default_key_path, ctx.sni_certs, bundles);
        defer prepared.deinit();
        ctx.store.commitPreparedReload(&prepared) catch |err| {
            if (err == error.StaleManualCredentialConfig) continue;
            return err;
        };
        return;
    }
    return error.StaleManualCredentialConfig;
}

const PublishRetryTestContext = struct {
    calls: u8 = 0,
    stale_sni: []const SniCertSpec,
    current_sni: []const SniCertSpec,

    fn prepare(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        store: *NativeCredentialStore,
        bundles: []const ManagedBundleSpec,
    ) anyerror!NativeCredentialStore.PreparedReload {
        const self: *PublishRetryTestContext = @ptrCast(@alignCast(raw.?));
        if (self.calls == 0) {
            self.calls += 1;
            var stale = try store.prepareReloadFromBundles("", "", self.stale_sni, bundles);
            stale.manual_config_generation = 1;

            // Model the SIGHUP commit in the narrow window after bootstrap
            // preparation but before its commit. The returned snapshot must
            // therefore hit publishManagedBundles' real retry branch.
            var current = try store.prepareReloadFromFiles("", "", self.current_sni);
            defer current.deinit();
            current.manual_config_generation = 2;
            try store.commitPreparedReload(&current);
            return stale;
        }
        self.calls += 1;
        var current = try store.prepareReloadFromBundles("", "", self.current_sni, bundles);
        current.manual_config_generation = 2;
        return current;
    }
};

fn issueGroup(ctx: *BootstrapCtx, client: *acme.client.Client, group: acme.groups.Group) !void {
    var issued = try acme.orders.obtain(ctx.allocator, client, ctx.challenge_store, group.slice(), .{
        .cancel = .{ .ctx = &ctx.cancel, .checkFn = cancelCheck },
    });
    defer issued.deinit(ctx.allocator);

    // Hold the filesystem lock only for the atomic verify/persist step.
    var state = try acme.state.StateDir.open(ctx.state_dir_path);
    defer state.close();
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, group.slice());
    _ = try acme.activate.verifyAndPersist(ctx.allocator, &state, group_id, &issued.key, issued.chain_pem, .{
        .hostnames = group.slice(),
        .now = compat.unixTimestamp(),
    });
}

// ---------------------------------------------------------------------------

const testing = std.testing;

fn issueTestLeafForCsr(_: ?*anyopaque, allocator: std.mem.Allocator, csr_der: []const u8, hostnames: []const []const u8) anyerror![]u8 {
    const now = compat.unixTimestamp();
    return acme.test_cert_builder.leafForCsr(allocator, csr_der, hostnames, now - 3600, now + 365 * 24 * 3600);
}

test "PublishedHosts.markGroup is idempotent and isPublished only reflects marked names" {
    var published = PublishedHosts.init(testing.allocator);
    defer published.deinit();

    try testing.expect(!published.isPublished("a.example.com"));
    try published.markGroup(&.{ "a.example.com", "b.example.com" });
    try testing.expect(published.isPublished("a.example.com"));
    try testing.expect(published.isPublished("b.example.com"));
    try testing.expect(!published.isPublished("c.example.com"));

    // Idempotent: marking again does not duplicate or error.
    try published.markGroup(&.{"a.example.com"});
    try testing.expect(published.isPublished("a.example.com"));
}

test "recoverFromDisk publishes nothing and reports every group as needing issuance when the state dir is empty" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();

    const result = try recoverFromDisk(allocator, "a.example.com;b.example.com", state_dir, "", "", &.{}, &store, &published, 1_700_000_000);
    try testing.expectEqual(@as(usize, 2), result.group_list.len);
    try testing.expect(result.needs_issuance[0]);
    try testing.expect(result.needs_issuance[1]);
    try testing.expect(!published.isPublished("a.example.com"));

    // Nothing was ever installed: every selection fails closed, not with a
    // plaintext/self-signed stand-in (design §7.4.1).
    const credentials = @import("tls_core").credentials;
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "a.example.com",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    try testing.expectError(error.NoCredentialAvailable, store.provider().selectCredential(&selection));
}

test "recoverFromDisk publishes a manual SNI-only identity before ACME issuance (#929 review)" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const sni = [_]SniCertSpec{.{
        .server_name = "manual.example.test",
        .cert_path = "tests/fixtures/tls/native_p256.crt",
        .key_path = "tests/fixtures/tls/native_p256.key",
    }};

    const result = try recoverFromDisk(allocator, "managed.example.test", state_dir, "", "", &sni, &store, &published, 1_700_000_000);
    try testing.expect(result.needs_issuance[0]);

    const credentials = @import("tls_core").credentials;
    const manual = credentials.SelectionContext{
        .role = .server,
        .server_name = "manual.example.test",
        .peer_signature_schemes = &.{ 0x0403, 0x0804 },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const selection = try store.provider().selectCredential(&manual);
    const selected = switch (selection) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    selected.release();

    const unmanaged = credentials.SelectionContext{
        .role = .server,
        .server_name = "unmanaged.example.test",
        .peer_signature_schemes = &.{ 0x0403, 0x0804 },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    try testing.expectError(error.NoCredentialAvailable, store.provider().selectCredential(&unmanaged));
}

test "publishManagedBundles retries a stale manual generation using the current credential callback (#929 review)" {
    const allocator = testing.allocator;
    const managed_cert = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.crt", 256 * 1024);
    defer allocator.free(managed_cert);
    const managed_key = try compat.cwd().readFileAlloc(allocator, "tests/fixtures/tls/native_rsa.key", 256 * 1024);
    defer secrets.secureZeroAndFree(allocator, managed_key);

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    const manual_a = [_]SniCertSpec{.{
        .server_name = "manual.example.test",
        .cert_path = "tests/fixtures/tls/native_ed25519.crt",
        .key_path = "tests/fixtures/tls/native_ed25519.key",
    }};
    const manual_b = [_]SniCertSpec{.{
        .server_name = "manual.example.test",
        .cert_path = "tests/fixtures/tls/native_p256.crt",
        .key_path = "tests/fixtures/tls/native_p256.key",
    }};
    try store.reloadFromFiles("", "", &manual_a);

    const credentials = @import("tls_core").credentials;
    var manual_selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "manual.example.test",
        .peer_signature_schemes = &.{ 0x0403, 0x0804 },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const pinned = switch (try store.provider().selectCredential(&manual_selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer pinned.release();
    const pinned_leaf = pinned.certificateChain().leaf().?;

    const managed = [_]ManagedBundleSpec{.{
        .hostnames = &.{"managed.example.test"},
        .chain_pem = managed_cert,
        .key_pem = managed_key,
    }};
    var retry_ctx = PublishRetryTestContext{ .stale_sni = &manual_a, .current_sni = &manual_b };
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try acme.transport.TrustAnchorSnapshot.load(allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    defer trust_anchors.release();
    var ctx = BootstrapCtx{
        .allocator = allocator,
        .state_dir_path = "unused-by-publication-test",
        .default_cert_path = "",
        .default_key_path = "",
        .sni_certs = &manual_a,
        .issue = .{ .directory_url = "https://ca.test/directory", .terms_of_service_agreed = true, .trust_anchors = trust_anchors },
        .store = &store,
        .challenge_store = &challenge_store,
        .published = &published,
        .prepare_current_credentials = PublishRetryTestContext.prepare,
        .credential_config_ctx = &retry_ctx,
        .group_list = .{},
        .needs_issuance = @splat(false),
        .logger = http.logger.Logger.init(.warn, "test"),
    };
    try publishManagedBundles(&ctx, &managed);
    try testing.expectEqual(@as(u8, 2), retry_ctx.calls);

    const current_manual = switch (try store.provider().selectCredential(&manual_selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer current_manual.release();
    try testing.expect(!std.mem.eql(u8, pinned_leaf, current_manual.certificateChain().leaf().?));

    var managed_selection = manual_selection;
    managed_selection.server_name = "managed.example.test";
    const managed_credential = switch (try store.provider().selectCredential(&managed_selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    managed_credential.release();
    managed_selection.server_name = "unknown.example.test";
    try testing.expectError(error.NoCredentialAvailable, store.provider().selectCredential(&managed_selection));
    // The old selection remains pinned even after the production retry
    // publishes the B+managed snapshot.
    try testing.expect(std.mem.eql(u8, pinned_leaf, pinned.certificateChain().leaf().?));
}

test "runBootstrapWithDialer obtains a CSR-matched certificate and activates it for native TLS (#929 review)" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
    ca.issued_chain_factory = .{ .makeFn = issueTestLeafForCsr };
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try acme.transport.TrustAnchorSnapshot.load(allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    defer trust_anchors.release();
    var ctx = BootstrapCtx{
        .allocator = allocator,
        .state_dir_path = state_dir,
        .default_cert_path = "",
        .default_key_path = "",
        .sni_certs = &.{},
        .issue = .{ .directory_url = "https://ca.test/directory", .terms_of_service_agreed = true, .trust_anchors = trust_anchors },
        .store = &store,
        .challenge_store = &challenge_store,
        .published = &published,
        .group_list = try acme.groups.parse("issued.example.test"),
        .needs_issuance = @splat(false),
        .logger = http.logger.Logger.init(.warn, "test"),
    };
    ctx.needs_issuance[0] = true;
    try runBootstrapWithDialer(&ctx, ca.dialer());
    try testing.expect(published.isPublished("issued.example.test"));

    const credentials = @import("tls_core").credentials;
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "issued.example.test",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const selected = switch (try store.provider().selectCredential(&selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer selected.release();
    try testing.expect(selected.certificateChain().leaf() != null);
}

test "issueGroup never persists or publishes a CA-issued chain that fails §6.4 verification" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    // The test drives `orders.obtain` with the production (real-clock)
    // default `Options`, unlike `orders_tests.zig`'s fake-clock `Env`, so
    // the fake CA's default fixed-2023 order `expires` would already be in
    // the past; pin it far in the future instead (same fix
    // `live_http01_tests.zig`'s `Env.start` applies for the same reason).
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";

    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var transport_inst = acme.transport.Transport{ .allocator = allocator, .dialer = ca.dialer() };
    const session = blk: {
        var state = try acme.state.StateDir.open(state_dir);
        defer state.close();
        break :blk try acme.client.Session.open(allocator, &transport_inst, &state, .{
            .directory_url = "https://ca.test/directory",
            .terms_of_service_agreed = true,
        }, 1_700_000_000);
    };
    defer session.close();

    // `issueGroup` never reads `ctx.issue.trust_anchors` itself (only
    // `runBootstrapWithDialer`'s caller-supplied `Dialer` does, and this
    // test calls `issueGroup` directly), but the field is required, so any
    // loaded snapshot satisfies the type.
    const trust_anchors = try acme.transport.TrustAnchorSnapshot.load(allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    defer trust_anchors.release();

    var ctx = BootstrapCtx{
        .allocator = allocator,
        .state_dir_path = state_dir,
        .default_cert_path = "",
        .default_key_path = "",
        .sni_certs = &.{},
        .issue = .{ .directory_url = "https://ca.test/directory", .terms_of_service_agreed = true, .trust_anchors = trust_anchors },
        .store = undefined,
        .challenge_store = &challenge_store,
        .published = undefined,
        .group_list = .{},
        .needs_issuance = @splat(true),
        .logger = http.logger.Logger.init(.warn, "test"),
    };
    const group_list = try acme.groups.parse("a.example.test");
    const group = group_list.groups[0];

    // `fake_ca.zig`'s default certificate is a scripted placeholder, not a
    // real, verifiable X.509 chain (#883's own tests only ever assert its
    // PEM header, never parse it) -- exactly the untrusted-CA-response case
    // §6.4 exists for. `issueGroup` must surface that failure, not swallow
    // it or persist/publish anything.
    try testing.expectError(error.MalformedChain, issueGroup(&ctx, &session.client, group));

    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, group.slice());
    var state = try acme.state.StateDir.open(state_dir);
    defer state.close();
    const loaded = try acme.activate.loadCommitted(allocator, &state, group_id, group.slice(), 1_700_000_100);
    try testing.expect(loaded == null);
}

test "verifyAndPersist + loadManagedBundleSet + prepareReloadFromBundles publish a real issued chain, and a restart recovers it with no CA contact at all" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    const hostnames = [_][]const u8{"a.example.test"};
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, 1_700_000_000 - 3600, 1_700_000_000 + 365 * 24 * 3600);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();

    // This is exactly `issueGroup`'s own sequence, minus the CA round trip
    // that produced `leaf` above (already proven against the fake CA, as a
    // CA-returns-garbage *rejection*, in the previous test; #883's own
    // suites prove the live network leg).
    {
        var state = try acme.state.StateDir.open(state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{
            .hostnames = &hostnames,
            .now = 1_700_000_000,
        });

        const group_list = try acme.groups.parse("a.example.test");
        var bundles = try loadManagedBundleSet(allocator, &state, &group_list, 1_700_000_000);
        defer bundles.deinit();
        try testing.expectEqual(@as(usize, 1), bundles.slice().len);

        var prepared = try store.prepareReloadFromBundles("", "", &.{}, bundles.slice());
        defer prepared.deinit();
        try store.commitPreparedReload(&prepared);
        for (bundles.slice()) |spec| try published.markGroup(spec.hostnames);
    }

    try testing.expect(published.isPublished("a.example.test"));

    const credentials = @import("tls_core").credentials;
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "a.example.test",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const progress = try store.provider().selectCredential(&selection);
    const credential = switch (progress) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer credential.release();

    // Restart: `recoverFromDisk` finds and republishes the same generation
    // from disk alone (design §5.5 "Restart"), with no need for a CA at
    // all -- there is nothing left for this group to issue.
    var restarted_store = NativeCredentialStore.init(allocator);
    defer restarted_store.deinit();
    var restarted_published = PublishedHosts.init(allocator);
    defer restarted_published.deinit();
    const restart_result = try recoverFromDisk(allocator, "a.example.test", state_dir, "", "", &.{}, &restarted_store, &restarted_published, 1_700_000_100);
    try testing.expect(!restart_result.needs_issuance[0]);
    try testing.expect(restarted_published.isPublished("a.example.test"));
}

test {
    std.testing.refAllDecls(@This());
}
