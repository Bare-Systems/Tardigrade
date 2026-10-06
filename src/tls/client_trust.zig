//! Downstream client-certificate trust anchors for native TLS and QUIC (#763).
//!
//! Shared by the TCP (H1/H2) and QUIC (H3) accept paths so one CA bundle, one
//! reload and one generation counter govern every protocol.

const std = @import("std");
const compat = @import("zig_compat");
const webpki_verifier = @import("webpki_verifier.zig");
const sni_provider = @import("sni_provider.zig");
const tls13_backend = @import("tls13_backend.zig");

/// Client-certificate trust anchors, published as immutable
/// refcounted generations so a reload swaps the whole set atomically: a
/// handshake pins one generation for its whole lifetime (the verifier borrows
/// its anchors) and never observes a half-rotated bundle. A failed
/// `prepare` leaves the serving generation untouched.
pub const ClientTrustStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: ?*Generation = null,

    pub const Generation = struct {
        allocator: std.mem.Allocator,
        refs: std.atomic.Value(u32),
        anchors: webpki_verifier.TrustAnchors,
        max_path_length: usize,

        pub fn release(self: *Generation) void {
            if (self.refs.fetchSub(1, .acq_rel) == 1) {
                const allocator = self.allocator;
                self.anchors.deinit(allocator);
                allocator.destroy(self);
            }
        }
    };

    pub const Prepared = struct {
        generation: ?*Generation,

        pub fn deinit(self: *Prepared) void {
            if (self.generation) |g| g.release();
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) ClientTrustStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ClientTrustStore) void {
        if (self.current) |g| g.release();
        self.* = undefined;
    }

    /// Load and parse `ca_bundle_path` without publishing it. `ca_bundle_path`
    /// must be non-empty: client trust never falls back to the system store.
    pub fn prepare(self: *ClientTrustStore, ca_bundle_path: []const u8, max_path_length: usize) !Prepared {
        return .{ .generation = try loadGeneration(self.allocator, ca_bundle_path, max_path_length) };
    }

    pub fn commit(self: *ClientTrustStore, prepared: *Prepared) void {
        const generation = prepared.generation orelse return;
        prepared.generation = null;
        self.mutex.lock();
        const previous = self.current;
        self.current = generation;
        self.mutex.unlock();
        if (previous) |g| g.release();
    }

    /// Pin the serving generation; the caller must `release` it.
    pub fn acquire(self: *ClientTrustStore) ?*Generation {
        self.mutex.lock();
        defer self.mutex.unlock();
        const g = self.current orelse return null;
        _ = g.refs.fetchAdd(1, .monotonic);
        return g;
    }
};

fn loadGeneration(allocator: std.mem.Allocator, ca_bundle_path: []const u8, max_path_length: usize) !*ClientTrustStore.Generation {
    if (ca_bundle_path.len == 0) return error.ClientTrustPathRequired;
    var anchors = try webpki_verifier.loadTrustAnchors(allocator, ca_bundle_path);
    errdefer anchors.deinit(allocator);
    if (anchors.anchors().len == 0) return error.NoClientTrustAnchors;
    const generation = try allocator.create(ClientTrustStore.Generation);
    generation.* = .{
        .allocator = allocator,
        .refs = std.atomic.Value(u32).init(1),
        .anchors = anchors,
        .max_path_length = max_path_length,
    };
    return generation;
}

pub const Mode = tls13_backend.ClientAuthMode;

/// One client-authentication policy: the server names it governs (exact
/// `host`, or `*.suffix`; empty for the fallback policy), whether client
/// certificates are requested, and which CA bundle anchors them.
pub const PolicySpec = struct {
    names: []const []const u8 = &.{},
    mode: Mode = .disabled,
    ca_path: []const u8 = "",
    max_path_length: usize = 3,
};

/// Stable identity of a policy's *semantics* (mode, depth, CA path). Zero
/// means "no client authentication". Used to detect a request whose Host maps
/// to a different policy than the one its TLS handshake was admitted under.
pub fn policyFingerprint(spec: PolicySpec) u64 {
    if (spec.mode == .disabled) return 0;
    var h = std.hash.Wyhash.init(0x6d544c53);
    h.update(&.{@intFromEnum(spec.mode)});
    h.update(std.mem.asBytes(&spec.max_path_length));
    h.update(spec.ca_path);
    const v = h.final();
    return if (v == 0) 1 else v;
}

/// Server-name matcher injected by the owner of the server-block routing
/// contract (`edge_config.hostMatchesPatterns`): `true` when `host` belongs to
/// a block with these `names` (an empty list matches everything). Policy
/// selection must use the *same* matcher as virtual-host routing, so the two
/// can never pick different server blocks for one name.
pub const NameMatcher = *const fn (names: []const []const u8, host: ?[]const u8) bool;

/// Case-insensitive exact-name matcher (empty list matches everything), for
/// callers with no routing contract to mirror (tests, simple embeddings).
pub fn exactNameMatcher(names: []const []const u8, host: ?[]const u8) bool {
    if (names.len == 0) return true;
    const h = host orelse return false;
    for (names) |n| if (sni_provider.asciiEqlIgnoreCase(n, h)) return true;
    return false;
}

/// One immutable, refcounted client-authentication policy table. A policy is
/// chosen from the ClientHello server_name *before* CertificateRequest is
/// emitted; selection is "first entry, in configuration order, whose names
/// match" (exactly server-block routing), else `fallback`. Each distinct CA
/// bundle is its own refcounted trust generation. A snapshot is owned by one
/// configuration generation (and by every connection admitted under it), so
/// handshake policy, Host admission and routing all resolve from one
/// generation.
pub const PolicySnapshot = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(u32),
    entries: []Entry,
    fallback: Entry,
    matcher: NameMatcher,

    const Entry = struct {
        names: [][]const u8,
        mode: Mode,
        generation: ?*ClientTrustStore.Generation,
        fingerprint: u64,

        fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
            for (self.names) |n| allocator.free(n);
            allocator.free(self.names);
            if (self.generation) |g| g.release();
        }
    };

    /// A pinned policy decision. `generation` (non-null iff `mode` is not
    /// disabled) is retained; the caller must `release` it.
    pub const Selection = struct {
        mode: Mode,
        generation: ?*ClientTrustStore.Generation,
        fingerprint: u64,
    };

    pub fn retain(self: *PolicySnapshot) *PolicySnapshot {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }

    pub fn release(self: *PolicySnapshot) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const allocator = self.allocator;
        for (self.entries) |*e| e.deinit(allocator);
        allocator.free(self.entries);
        self.fallback.deinit(allocator);
        allocator.destroy(self);
    }

    fn lookup(self: *const PolicySnapshot, host: ?[]const u8) *const Entry {
        for (self.entries) |*e| {
            if (self.matcher(e.names, host)) return e;
        }
        return &self.fallback;
    }

    pub fn select(self: *const PolicySnapshot, server_name: ?[]const u8) Selection {
        const e = self.lookup(server_name);
        if (e.generation) |g| _ = g.refs.fetchAdd(1, .monotonic);
        return .{ .mode = e.mode, .generation = e.generation, .fingerprint = e.fingerprint };
    }

    /// Fingerprint of the policy `host` (Host/authority, port allowed) maps to.
    pub fn fingerprintForHost(self: *const PolicySnapshot, host: []const u8) u64 {
        return self.lookup(host).fingerprint;
    }
};

/// Prepared-but-unpublished snapshot; `deinit` drops its reference.
pub const PolicyPrepared = struct {
    snapshot: ?*PolicySnapshot,

    pub fn deinit(self: *PolicyPrepared) void {
        if (self.snapshot) |s| s.release();
        self.* = undefined;
    }
};

/// Builds policy snapshots and holds the one new connections without a
/// configuration lease (QUIC) start from. TCP connections take their snapshot
/// from the configuration generation they are admitted under instead.
pub const PolicySet = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: ?*PolicySnapshot = null,

    pub const Prepared = PolicyPrepared;
    pub const Selection = PolicySnapshot.Selection;

    pub fn init(allocator: std.mem.Allocator) PolicySet {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PolicySet) void {
        if (self.current) |s| s.release();
        self.* = undefined;
    }

    /// Load every enabled policy's CA bundle without publishing. Any failing
    /// bundle fails the whole prepare. `specs` are in routing order.
    pub fn prepare(self: *PolicySet, fallback: PolicySpec, specs: []const PolicySpec, matcher: NameMatcher) !Prepared {
        const allocator = self.allocator;
        const snapshot = try allocator.create(PolicySnapshot);
        errdefer allocator.destroy(snapshot);
        const entries = try allocator.alloc(PolicySnapshot.Entry, specs.len);
        var built: usize = 0;
        errdefer {
            for (entries[0..built]) |*e| e.deinit(allocator);
            allocator.free(entries);
        }
        for (specs, 0..) |spec, i| {
            entries[i] = try buildEntry(allocator, spec, specs[0..i], entries[0..i]);
            built += 1;
        }
        var fb = try buildEntry(allocator, fallback, specs, entries);
        errdefer fb.deinit(allocator);
        snapshot.* = .{ .allocator = allocator, .refs = std.atomic.Value(u32).init(1), .entries = entries, .fallback = fb, .matcher = matcher };
        return .{ .snapshot = snapshot };
    }

    fn buildEntry(allocator: std.mem.Allocator, spec: PolicySpec, prior_specs: []const PolicySpec, prior: []const PolicySnapshot.Entry) !PolicySnapshot.Entry {
        const names = try allocator.alloc([]const u8, spec.names.len);
        var n_built: usize = 0;
        errdefer {
            for (names[0..n_built]) |n| allocator.free(n);
            allocator.free(names);
        }
        for (spec.names) |raw| {
            names[n_built] = try allocator.dupe(u8, raw);
            n_built += 1;
        }
        var generation: ?*ClientTrustStore.Generation = null;
        if (spec.mode != .disabled) {
            // Identical (CA, depth) policies share one generation.
            for (prior_specs, prior) |ps, pe| {
                if (pe.generation) |g| if (ps.mode != .disabled and ps.max_path_length == spec.max_path_length and std.mem.eql(u8, ps.ca_path, spec.ca_path)) {
                    _ = g.refs.fetchAdd(1, .monotonic);
                    generation = g;
                    break;
                };
            }
            if (generation == null) generation = try loadGeneration(allocator, spec.ca_path, spec.max_path_length);
        }
        return .{ .names = names, .mode = spec.mode, .generation = generation, .fingerprint = policyFingerprint(spec) };
    }

    /// Publish `prepared` as the snapshot new QUIC connections start from.
    /// Consumes the prepared reference.
    pub fn commit(self: *PolicySet, prepared: *Prepared) void {
        const snapshot = prepared.snapshot orelse return;
        prepared.snapshot = null;
        self.mutex.lock();
        const previous = self.current;
        self.current = snapshot;
        self.mutex.unlock();
        if (previous) |s| s.release();
    }

    /// Retain the serving snapshot; the caller must `release` it.
    pub fn acquire(self: *PolicySet) ?*PolicySnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const s = self.current orelse return null;
        return s.retain();
    }
};

/// A request whose Host maps to a different client-auth policy than the one
/// its connection was admitted under must not be served on that connection
/// (RFC 9110 §15.5.20 → 421). A host with no client auth is always admissible.
pub fn hostAdmitted(pinned_fingerprint: u64, host_fingerprint: ?u64) bool {
    const fp = host_fingerprint orelse return false;
    return fp == 0 or fp == pinned_fingerprint;
}

const test_ca_a = "tests/fixtures/tls/h3mtls/ca.crt";
const test_ca_b = "tests/fixtures/tls/h3mtls/rogue_ca.crt";

test "policy snapshot selects the first matching entry in order, else the fallback" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    try std.testing.expect(set.acquire() == null);

    const specs = [_]PolicySpec{
        .{ .names = &.{"api.example.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"open.example.test"}, .mode = .disabled },
        // A nameless block matches everything after it, like server-block routing.
        .{ .mode = .optional, .ca_path = test_ca_b },
        .{ .names = &.{"never.example.test"}, .mode = .required, .ca_path = test_ca_a },
    };
    var prepared = try set.prepare(.{ .mode = .disabled }, &specs, exactNameMatcher);
    set.commit(&prepared);
    const snap = set.acquire().?;
    defer snap.release();

    const api = snap.select("API.example.test");
    defer api.generation.?.release();
    try std.testing.expectEqual(Mode.required, api.mode);
    const open = snap.select("open.example.test");
    try std.testing.expectEqual(Mode.disabled, open.mode);
    try std.testing.expect(open.generation == null and open.fingerprint == 0);
    // Order wins: the catch-all precedes `never`, which is therefore unreachable.
    const other = snap.select("never.example.test");
    defer other.generation.?.release();
    try std.testing.expectEqual(Mode.optional, other.mode);
    const none = snap.select(null);
    defer none.generation.?.release();
    try std.testing.expectEqual(Mode.optional, none.mode);
}

test "policy snapshot without a catch-all uses the fallback; identical CAs share a generation" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    const specs = [_]PolicySpec{
        .{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"b.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"c.test"}, .mode = .required, .ca_path = test_ca_b },
    };
    var prepared = try set.prepare(.{ .mode = .required, .ca_path = test_ca_b }, &specs, exactNameMatcher);
    set.commit(&prepared);
    const snap = set.acquire().?;
    defer snap.release();
    const a = snap.select("a.test");
    defer a.generation.?.release();
    const b = snap.select("b.test");
    defer b.generation.?.release();
    const c = snap.select("c.test");
    defer c.generation.?.release();
    const fb = snap.select("zzz.test");
    defer fb.generation.?.release();
    try std.testing.expect(a.generation.? == b.generation.?);
    try std.testing.expect(a.generation.? != c.generation.?);
    try std.testing.expect(fb.generation.? != a.generation.?);
    try std.testing.expectEqual(c.fingerprint, fb.fingerprint); // same mode/CA/depth
}

test "policy set: reload publishes atomically, pinned snapshots and generations are unaffected, a bad bundle changes nothing" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    const v1 = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_a }};
    var p1 = try set.prepare(.{}, &v1, exactNameMatcher);
    set.commit(&p1);

    const pinned_snapshot = set.acquire().?; // e.g. a connection admitted under N
    defer pinned_snapshot.release();
    const pinned = pinned_snapshot.select("a.test");
    defer pinned.generation.?.release();

    const bad = [_]PolicySpec{
        .{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_b },
        .{ .names = &.{"b.test"}, .mode = .required, .ca_path = "tests/fixtures/tls/h3mtls/does-not-exist.crt" },
    };
    try std.testing.expectError(error.FileNotFound, set.prepare(.{}, &bad, exactNameMatcher));
    const still = set.acquire().?;
    defer still.release();
    try std.testing.expect(still == pinned_snapshot);
    // An enabled policy with no CA never falls back to a system store.
    const nocafg = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .required }};
    try std.testing.expectError(error.ClientTrustPathRequired, set.prepare(.{}, &nocafg, exactNameMatcher));

    // Reload required(CA-A) -> disabled: new acquirers see N+1, the pinned
    // snapshot (and so its handshake policy) keeps N.
    const v2 = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .disabled }};
    var p2 = try set.prepare(.{}, &v2, exactNameMatcher);
    set.commit(&p2);
    const fresh = set.acquire().?;
    defer fresh.release();
    try std.testing.expect(fresh != pinned_snapshot);
    try std.testing.expectEqual(Mode.disabled, fresh.select("a.test").mode);
    const old_policy = pinned_snapshot.select("a.test");
    defer old_policy.generation.?.release();
    try std.testing.expectEqual(Mode.required, old_policy.mode);
    // Pinned generation is still alive after the set dropped its snapshot.
    const again = pinned_snapshot.select("a.test");
    defer again.generation.?.release();
    try std.testing.expect(again.generation.? == pinned.generation.?);
}

test "hostAdmitted and fingerprints" {
    try std.testing.expect(hostAdmitted(7, 7));
    try std.testing.expect(hostAdmitted(7, 0)); // host needs no client auth
    try std.testing.expect(!hostAdmitted(7, 9)); // different policy
    try std.testing.expect(!hostAdmitted(0, 9)); // admitted anonymously, host demands mTLS
    try std.testing.expect(!hostAdmitted(7, null));
    try std.testing.expectEqual(@as(u64, 0), policyFingerprint(.{ .mode = .disabled, .ca_path = "x" }));
    try std.testing.expect(policyFingerprint(.{ .mode = .required, .ca_path = "x" }) != policyFingerprint(.{ .mode = .optional, .ca_path = "x" }));
}
