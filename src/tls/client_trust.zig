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

/// Strip an optional `:port` (and IPv6 brackets) from a Host/authority value.
pub fn stripPort(host: []const u8) []const u8 {
    if (host.len > 0 and host[0] == '[') {
        const end = std.mem.indexOfScalar(u8, host, ']') orelse return host;
        return host[1..end];
    }
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |i| {
        if (std.mem.indexOfScalar(u8, host[0..i], ':') == null) return host[0..i];
    }
    return host;
}

/// SNI-keyed client-authentication policies. A policy is chosen from the
/// ClientHello server_name *before* CertificateRequest is emitted; each policy
/// owns its own refcounted trust generation, and a reload swaps the whole set
/// atomically (prepare-then-commit) while in-flight handshakes keep the
/// generation they pinned at selection time.
pub const PolicySet = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: ?*Snapshot = null,

    const Entry = struct {
        /// Lowercase: exact names, or ".suffix" for wildcard patterns.
        names: [][]u8,
        mode: Mode,
        generation: ?*ClientTrustStore.Generation,
        fingerprint: u64,

        fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
            for (self.names) |n| allocator.free(n);
            allocator.free(self.names);
            if (self.generation) |g| g.release();
        }
    };

    const Snapshot = struct {
        entries: []Entry,
        fallback: Entry,

        fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
            for (self.entries) |*e| e.deinit(allocator);
            allocator.free(self.entries);
            self.fallback.deinit(allocator);
            allocator.destroy(self);
        }

        fn lookup(self: *const Snapshot, raw: ?[]const u8) *const Entry {
            var buf: [sni_provider.max_host_pattern_len]u8 = undefined;
            const name = normalizeHost(raw orelse return &self.fallback, &buf) orelse return &self.fallback;
            for (self.entries) |*e| {
                for (e.names) |n| {
                    if (n.len > 0 and n[0] != '.' and std.mem.eql(u8, n, name)) return e;
                }
            }
            var best: ?*const Entry = null;
            var best_len: usize = 0;
            for (self.entries) |*e| {
                for (e.names) |n| {
                    if (n.len > 0 and n[0] == '.' and sni_provider.wildcardMatchesSuffix(name, n) and n.len > best_len) {
                        best = e;
                        best_len = n.len;
                    }
                }
            }
            return best orelse &self.fallback;
        }
    };

    pub const Prepared = struct {
        allocator: std.mem.Allocator,
        snapshot: ?*Snapshot,

        pub fn deinit(self: *Prepared) void {
            if (self.snapshot) |s| s.deinit(self.allocator);
            self.* = undefined;
        }
    };

    /// A pinned policy decision. `generation` (non-null iff `mode` is not
    /// disabled) is retained; the caller must `release` it.
    pub const Selection = struct {
        mode: Mode,
        generation: ?*ClientTrustStore.Generation,
        fingerprint: u64,
    };

    pub fn init(allocator: std.mem.Allocator) PolicySet {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PolicySet) void {
        if (self.current) |s| s.deinit(self.allocator);
        self.* = undefined;
    }

    /// Load every enabled policy's CA bundle without publishing. Any failing
    /// bundle fails the whole prepare, leaving the serving set untouched.
    pub fn prepare(self: *PolicySet, fallback: PolicySpec, specs: []const PolicySpec) !Prepared {
        const allocator = self.allocator;
        const snapshot = try allocator.create(Snapshot);
        errdefer allocator.destroy(snapshot);
        const entries = try allocator.alloc(Entry, specs.len);
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
        snapshot.* = .{ .entries = entries, .fallback = fb };
        return .{ .allocator = allocator, .snapshot = snapshot };
    }

    fn buildEntry(allocator: std.mem.Allocator, spec: PolicySpec, prior_specs: []const PolicySpec, prior: []const Entry) !Entry {
        var names = try allocator.alloc([]u8, spec.names.len);
        var n_built: usize = 0;
        errdefer {
            for (names[0..n_built]) |n| allocator.free(n);
            allocator.free(names);
        }
        for (spec.names) |raw| {
            names[n_built] = try normalizePattern(allocator, raw);
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

    pub fn commit(self: *PolicySet, prepared: *Prepared) void {
        const snapshot = prepared.snapshot orelse return;
        prepared.snapshot = null;
        self.mutex.lock();
        const previous = self.current;
        self.current = snapshot;
        self.mutex.unlock();
        if (previous) |s| s.deinit(self.allocator);
    }

    /// Resolve the policy for `server_name` (null/unmatched → fallback) and pin
    /// its trust generation.
    pub fn select(self: *PolicySet, server_name: ?[]const u8) error{ClientTrustUnavailable}!Selection {
        self.mutex.lock();
        defer self.mutex.unlock();
        const snap = self.current orelse return error.ClientTrustUnavailable;
        const e = snap.lookup(server_name);
        if (e.generation) |g| _ = g.refs.fetchAdd(1, .monotonic);
        return .{ .mode = e.mode, .generation = e.generation, .fingerprint = e.fingerprint };
    }

    /// Fingerprint of the policy `host` (a Host/authority value, port allowed)
    /// maps to in the serving set.
    pub fn fingerprintForHost(self: *PolicySet, host: []const u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const snap = self.current orelse return null;
        return snap.lookup(stripPort(host)).fingerprint;
    }
};

/// A request whose Host maps to a different client-auth policy than the one
/// its connection was admitted under must not be served on that connection
/// (RFC 9110 §15.5.20 → 421). A host with no client auth is always admissible.
pub fn hostAdmitted(pinned_fingerprint: u64, host_fingerprint: ?u64) bool {
    const fp = host_fingerprint orelse return false;
    return fp == 0 or fp == pinned_fingerprint;
}

fn normalizeHost(raw: []const u8, buf: *[sni_provider.max_host_pattern_len]u8) ?[]const u8 {
    var r = raw;
    if (r.len > 0 and r[r.len - 1] == '.') r = r[0 .. r.len - 1];
    if (r.len == 0 or r.len > buf.len) return null;
    for (r, 0..) |c, i| buf[i] = sni_provider.asciiLower(c);
    return buf[0..r.len];
}

fn normalizePattern(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var r = raw;
    if (r.len > 0 and r[r.len - 1] == '.') r = r[0 .. r.len - 1];
    if (std.mem.startsWith(u8, r, "*.")) r = r[1..];
    if (r.len == 0 or r.len > sni_provider.max_host_pattern_len) return error.InvalidServerName;
    const out = try allocator.alloc(u8, r.len);
    for (r, 0..) |c, i| out[i] = sni_provider.asciiLower(c);
    return out;
}

const test_ca_a = "tests/fixtures/tls/h3mtls/ca.crt";
const test_ca_b = "tests/fixtures/tls/h3mtls/rogue_ca.crt";

test "policy set selects by exact name, longest wildcard, then fallback; names are case-insensitive" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    try std.testing.expectError(error.ClientTrustUnavailable, set.select("a.example.test"));

    const specs = [_]PolicySpec{
        .{ .names = &.{"API.example.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"*.example.test"}, .mode = .optional, .ca_path = test_ca_b },
        .{ .names = &.{"open.example.test"}, .mode = .disabled },
    };
    var prepared = try set.prepare(.{ .mode = .required, .ca_path = test_ca_b }, &specs);
    set.commit(&prepared);

    const exact = try set.select("api.EXAMPLE.test.");
    defer exact.generation.?.release();
    try std.testing.expectEqual(Mode.required, exact.mode);

    const wild = try set.select("x.example.test");
    defer wild.generation.?.release();
    try std.testing.expectEqual(Mode.optional, wild.mode);
    try std.testing.expect(wild.generation.? != exact.generation.?);
    // A wildcard covers exactly one label.
    const deep = try set.select("a.b.example.test");
    defer deep.generation.?.release();
    try std.testing.expectEqual(Mode.required, deep.mode); // fallback

    const open = try set.select("open.example.test");
    try std.testing.expectEqual(Mode.disabled, open.mode);
    try std.testing.expect(open.generation == null);
    try std.testing.expectEqual(@as(u64, 0), open.fingerprint);

    const none = try set.select(null);
    defer none.generation.?.release();
    try std.testing.expectEqual(Mode.required, none.mode);
    try std.testing.expect(none.fingerprint != exact.fingerprint); // different CA
}

test "policy set: identical CA policies share one generation; distinct CAs do not" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    const specs = [_]PolicySpec{
        .{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"b.test"}, .mode = .required, .ca_path = test_ca_a },
        .{ .names = &.{"c.test"}, .mode = .required, .ca_path = test_ca_b },
    };
    var prepared = try set.prepare(.{}, &specs);
    set.commit(&prepared);
    const a = try set.select("a.test");
    defer a.generation.?.release();
    const b = try set.select("b.test");
    defer b.generation.?.release();
    const c = try set.select("c.test");
    defer c.generation.?.release();
    try std.testing.expect(a.generation.? == b.generation.?);
    try std.testing.expect(a.generation.? != c.generation.?);
}

test "policy set: reload is atomic, pins in-flight generations, and a bad bundle leaves the serving set untouched" {
    const allocator = std.testing.allocator;
    var set = PolicySet.init(allocator);
    defer set.deinit();
    const v1 = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_a }};
    var p1 = try set.prepare(.{}, &v1);
    set.commit(&p1);

    const pinned = try set.select("a.test"); // an in-flight handshake
    defer pinned.generation.?.release();

    // A missing bundle in ANY policy rejects the whole prepare.
    const bad = [_]PolicySpec{
        .{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_b },
        .{ .names = &.{"b.test"}, .mode = .required, .ca_path = "tests/fixtures/tls/h3mtls/does-not-exist.crt" },
    };
    try std.testing.expectError(error.FileNotFound, set.prepare(.{}, &bad));
    const still = try set.select("a.test");
    defer still.generation.?.release();
    try std.testing.expect(still.generation.? == pinned.generation.?);

    // An enabled policy with no CA never falls back to a system store.
    const nocafg = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .required }};
    try std.testing.expectError(error.ClientTrustPathRequired, set.prepare(.{}, &nocafg));

    const v2 = [_]PolicySpec{.{ .names = &.{"a.test"}, .mode = .required, .ca_path = test_ca_b }};
    var p2 = try set.prepare(.{}, &v2);
    set.commit(&p2);
    const fresh = try set.select("a.test");
    defer fresh.generation.?.release();
    try std.testing.expect(fresh.generation.? != pinned.generation.?);
    // The pinned generation is still alive and unchanged.
    try std.testing.expect(pinned.generation.?.anchors.anchors().len > 0);
}

test "hostAdmitted and stripPort" {
    try std.testing.expectEqualStrings("a.test", stripPort("a.test:8443"));
    try std.testing.expectEqualStrings("::1", stripPort("[::1]:443"));
    try std.testing.expectEqualStrings("a.test", stripPort("a.test"));
    try std.testing.expect(hostAdmitted(7, 7));
    try std.testing.expect(hostAdmitted(7, 0)); // host needs no client auth
    try std.testing.expect(!hostAdmitted(7, 9)); // different policy
    try std.testing.expect(!hostAdmitted(0, 9)); // admitted anonymously, host demands mTLS
    try std.testing.expect(!hostAdmitted(7, null));
    try std.testing.expectEqual(@as(u64, 0), policyFingerprint(.{ .mode = .disabled, .ca_path = "x" }));
    try std.testing.expect(policyFingerprint(.{ .mode = .required, .ca_path = "x" }) != policyFingerprint(.{ .mode = .optional, .ca_path = "x" }));
}
