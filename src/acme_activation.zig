//! A4 product integration for automatic HTTPS (#884, epic #759, design
//! `docs/ACME_AUTOMATIC_HTTPS.md` §7, §8.3, §9.2). This is the glue none of
//! #879 (verification/persistence), #880 (bytes-based publish) or #883
//! (orders/HTTP-01) provide alone: deciding what a freshly started process
//! should serve, and rebuilding/republishing the complete managed bundle
//! set from whatever is durably committed on disk.
//!
//! Not the renewal worker (#835/A5): there is no scheduler, no periodic
//! wake-up, no cross-restart backoff, and nothing here ever talks to a CA.
//! `recoverFromDisk` runs once at startup, before any network access, and
//! `loadManagedBundleSet` is the shared read-only primitive both that
//! startup path and `acme_renewal.Worker`'s ongoing issuance/renewal
//! passes use to turn "whatever is committed right now" into a publishable
//! bundle set. `acme_renewal.zig` owns every CA attempt (initial and
//! renewal alike) and reuses these primitives rather than duplicating them.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const crypto = @import("crypto");

const acme = http.acme;
const secrets = crypto.secrets;

pub const ManagedBundleSpec = http.native_tls_connection.ManagedBundleSpec;
pub const NativeCredentialStore = http.native_tls_connection.NativeCredentialStore;
pub const SniCertSpec = http.native_tls_connection.SniCertSpec;

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

// ---------------------------------------------------------------------------

const testing = std.testing;

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
