//! Live end-to-end proof that the A3 order engine, the real #877
//! `ChallengeStore` and the real #881 `Listener` compose into one working
//! native HTTP-01 issuance path (#883, epic #759 phase A3).
//!
//! `orders_tests.zig` deliberately drives the order engine against
//! `fake_ca.zig` entirely over an in-memory `Connection`, so that suite makes
//! no live network call at all. Every test here instead starts a real
//! `acme_http01_listener.Listener` bound to a real loopback TCP port and
//! wires `fake_ca.zig`'s `live_validate` hook to perform a genuine TCP
//! HTTP-01 GET against it -- the same request shape an independent CA
//! (Pebble or any other RFC 8555 peer) would send -- instead of trusting a
//! scripted outcome. The ACME directory/account/order/finalize protocol
//! itself still runs through `fake_ca.zig`'s in-memory `Connection` (the
//! already-reviewed A2/A3 CA-transport fake, §11 "deterministic local CA");
//! only the HTTP-01 validation leg, which is what #883 exists to prove,
//! crosses the real network to the real listener against the real,
//! order-engine-populated store.

const std = @import("std");
const zig_compat = @import("zig_compat");
const client_mod = @import("client.zig");
const state_mod = @import("state.zig");
const transport_mod = @import("transport.zig");
const orders_mod = @import("orders.zig");
const fake = @import("fake_ca.zig");
const live_ca_server = @import("live_ca_server.zig");
const tls_dialer_mod = @import("../http/acme_tls_dialer.zig");
const challenge_store_mod = @import("../http/acme_challenge_store.zig");
const listener_mod = @import("../http/acme_http01_listener.zig");

const testing = std.testing;
const Session = client_mod.Session;
const StateDir = state_mod.StateDir;
const ChallengeStore = challenge_store_mod.ChallengeStore;
const Listener = listener_mod.Listener;

const directory_url = "https://ca.test/directory";

/// One real HTTP-01 response read off a live listener connection, parsed
/// just enough to assert on. The listener answers one response per
/// connection with `Connection: close` (design §8.0), so reading to EOF is
/// always a complete response.
const LiveResponse = struct {
    status: u16,
    body: []const u8,
    raw: []u8,

    fn deinit(self: *LiveResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
    }
};

/// Per-phase bound on the real socket connect/write/read below: a hung or
/// deliberately stalling listener must fail the test closed, not block the
/// whole suite.
const live_fetch_timeout_ms: u32 = 2_000;
/// A real HTTP-01 challenge response is a handful of bytes; a peer that
/// keeps sending past this is misbehaving, not slow (reviewer #883 P2).
const live_fetch_max_response_bytes: usize = 8 * 1024;

fn liveFetch(allocator: std.mem.Allocator, port: u16, host: []const u8, token: []const u8) !LiveResponse {
    const fd = try zig_compat.connectBoundedTcp("127.0.0.1", port, live_fetch_timeout_ms);
    const stream = zig_compat.netStreamFromFd(fd);
    defer stream.close();
    try zig_compat.setSocketTimeoutsMsChecked(fd, live_fetch_timeout_ms, live_fetch_timeout_ms);

    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET {s}{s} HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ listener_mod.challenge_prefix, token, host });
    try stream.writeAll(req);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        // A timed-out or reset read surfaces as an error instead of being
        // folded into a silent EOF, so a stalled/misbehaving peer fails the
        // test closed rather than passing on a truncated response.
        const n = try stream.read(&buf);
        if (n == 0) break;
        if (out.items.len + n > live_fetch_max_response_bytes) return error.LiveResponseTooLarge;
        try out.appendSlice(allocator, buf[0..n]);
    }
    const raw = try out.toOwnedSlice(allocator);
    errdefer allocator.free(raw);

    if (raw.len < 12 or !std.mem.startsWith(u8, raw, "HTTP/1.1 ")) return error.MalformedLiveResponse;
    const status = std.fmt.parseInt(u16, raw[9..12], 10) catch return error.MalformedLiveResponse;
    const body_at = (std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.MalformedLiveResponse) + 4;
    return .{ .status = status, .body = raw[body_at..], .raw = raw };
}

const Env = struct {
    tmp: testing.TmpDir = undefined,
    path: []u8 = undefined,
    ca: fake.FakeCa = undefined,
    store: ChallengeStore = undefined,
    listener: Listener = undefined,
    managed_hosts: []const []const u8 = &.{},
    /// A field (not a local), so the pointer `Client.transport` borrows from
    /// `openSession` stays valid for the whole test, matching the `Client`
    /// contract (`transport: *const Transport`, no owned copy).
    t: transport_mod.Transport = undefined,

    /// A mutating in-place starter, not a by-value `init` returning `Env`:
    /// `listener.start` captures `&self.listener`/`&self.store`, so `self`
    /// must already be at its final, stable address (the caller's own `var
    /// env: Env = .{};` local) before this runs, exactly like `Listener`'s
    /// own doc comment requires of every caller.
    fn start(self: *Env, managed_hosts: []const []const u8) !void {
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try self.tmp.dir.realPath(zig_compat.io(), &buf);
        self.path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        errdefer testing.allocator.free(self.path);
        self.ca = fake.FakeCa.init(testing.allocator);
        // Every clock here is real wall-clock time (§883: a genuine live
        // run, not `orders_tests.zig`'s injected fake clock), so the fake
        // CA's default scripted order `expires` (a fixed 2023 date, sized
        // for that fake clock) would already be in the past; pin it far in
        // the future instead.
        self.ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
        self.store = ChallengeStore.init(testing.allocator);
        self.managed_hosts = managed_hosts;
        try self.listener.start(testing.allocator, "127.0.0.1", 0, .{
            .managed_hosts = self.managed_hosts,
            .store = &self.store,
        });
    }

    fn deinit(self: *Env) void {
        self.listener.deinit();
        self.store.deinit();
        self.ca.deinit();
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn openSession(self: *Env) !*Session {
        self.t = .{
            .allocator = testing.allocator,
            .dialer = self.ca.dialer(),
        };
        var state = try StateDir.open(self.path);
        defer state.close();
        return Session.open(testing.allocator, &self.t, &state, .{
            .directory_url = directory_url,
            .terms_of_service_agreed = true,
        }, zig_compat.unixTimestamp());
    }

    fn expectStoreEmpty(self: *Env) !void {
        try testing.expectEqual(@as(usize, 0), self.store.slots.items.len);
    }
};

fn fastPoll(opts: *orders_mod.Options) void {
    opts.limits.poll_interval_min_s = 1;
    opts.limits.poll_interval_max_s = 1;
}

/// Correct host, correct token: the exact body the order engine published.
const ValidateCtx = struct {
    allocator: std.mem.Allocator,
    listener_port: u16,
    /// A second managed host the test asserts can never retrieve this
    /// host's token (host-scoped storage, not just unmanaged-Host 404).
    other_managed_host: ?[]const u8 = null,
    /// When set, the live fetch's body is compared against this instead of
    /// the real key authorization the order engine computed, so the
    /// validator reports a mismatch exactly like a CA that fetched garbage
    /// would (hostile/negative path).
    expect_override: ?[]const u8 = null,
    fetched: bool = false,
    cross_host_checked: bool = false,

    fn validate(ctx: ?*anyopaque, host: []const u8, token: []const u8, key_authorization: []const u8) bool {
        const self: *ValidateCtx = @ptrCast(@alignCast(ctx.?));
        self.fetched = true;

        if (self.other_managed_host) |other| {
            // A live GET claiming a *different* managed host must never
            // hand back this host's token: storage is keyed by (host,
            // token), not token alone (#877).
            var cross = liveFetch(self.allocator, self.listener_port, other, token) catch return false;
            defer cross.deinit(self.allocator);
            if (cross.status == 200) return false;
            self.cross_host_checked = true;
        }

        var resp = liveFetch(self.allocator, self.listener_port, host, token) catch return false;
        defer resp.deinit(self.allocator);
        if (resp.status != 200) return false;
        const expected = self.expect_override orelse key_authorization;
        return std.mem.eql(u8, resp.body, expected);
    }
};

test "ACME A3 (#883): live HTTP-01 issuance through the real gateway listener succeeds end to end" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var ctx = ValidateCtx{ .allocator = testing.allocator, .listener_port = env.listener.port() };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = ValidateCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);

    try testing.expect(ctx.fetched);
    try testing.expect(std.mem.startsWith(u8, issued.chain_pem, "-----BEGIN CERTIFICATE-----"));
    try env.expectStoreEmpty();
    // The token the order engine published is gone from the *live* listener
    // too, not merely from the in-memory store struct's bookkeeping.
    var token_gone = try liveFetch(testing.allocator, env.listener.port(), "a.example.com", "any-token-shape-no-longer-matters");
    defer token_gone.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 404), token_gone.status);
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

test "ACME A3 (#883): a live token never cross-serves to a sibling managed host" {
    const hosts = [_][]const u8{ "a.example.com", "b.example.com" };
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var ctx = ValidateCtx{
        .allocator = testing.allocator,
        .listener_port = env.listener.port(),
        .other_managed_host = "b.example.com",
    };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = ValidateCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);

    try testing.expect(ctx.cross_host_checked);
    try env.expectStoreEmpty();
}

test "ACME A3 (#883): a key authorization mismatch on the live listener fails the authorization closed and leaves no residue" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var ctx = ValidateCtx{
        .allocator = testing.allocator,
        .listener_port = env.listener.port(),
        .expect_override = "attacker-controlled-value",
    };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = ValidateCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationInvalid, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    try testing.expect(ctx.fetched);
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

// -- #883 P2: lifecycle and failure matrix -----------------------------

/// Fires `flag` after a short, fixed real-wall-clock delay, well inside the
/// window a "pending"-forever authorization (`polls_before_final` set high
/// enough to never invoke live validation) keeps polling. Tied to real time
/// rather than to any CA response, so this proves cooperative cancellation
/// -- not a scripted CA outcome -- is what ends an in-flight order.
const DelayedCancel = struct {
    flag: std.atomic.Value(bool) = .init(false),

    fn fire(self: *DelayedCancel) void {
        zig_compat.sleepNs(700 * std.time.ns_per_ms);
        self.flag.store(true, .release);
    }

    fn check(ctx: ?*anyopaque) bool {
        const self: *DelayedCancel = @ptrCast(@alignCast(ctx.?));
        return self.flag.load(.acquire);
    }
};

test "ACME A3 (#883): cancelling mid-order while authorization polling is outstanding leaves no residue" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    // Published (the real listener's store gets the token on the first
    // authorization fetch, before any poll) but never finalized: this
    // proves cancellation, not a terminal CA response, ends the order.
    env.ca.script.authz.polls_before_final = 1_000;

    var delayed = DelayedCancel{};
    const timer = try std.Thread.spawn(.{}, DelayedCancel.fire, .{&delayed});
    defer timer.join();

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    opts.cancel = .{ .ctx = &delayed, .checkFn = DelayedCancel.check };

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Cancelled, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

test "ACME A3 (#883): a CA that never finalizes an authorization times the order out and leaves no residue" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    // An unresponsive/stalled CA: every authorization poll answers
    // "pending" forever (live validation is never even reached), so the
    // authorization's own bounded deadline -- not a CA response -- is what
    // has to end this closed.
    env.ca.script.authz.polls_before_final = 1_000;

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    // Long enough that `store.put`'s own `expires_at > now` floor never
    // rejects the publish outright (truncating a 1s budget to whole
    // seconds can round down to exactly `now`), short enough that this
    // test still finishes in a couple of real seconds.
    opts.limits.authz_deadline_s = 2;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    // The real listener published this host's token (the first
    // authorization fetch always does, before any poll) and the CA really
    // did receive the live trigger POST that publishes it -- the timeout
    // path must still have cleaned the store up (same `errdefer
    // store.remove` as every other failure path), not merely left it to
    // decay on its own.
    try testing.expect(env.ca.countRequests(.POST, "/authz/1/http-01") >= 1);
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

test "ACME A3 (#883): the real listener serves issuance again after a stop/restart with no residue carried over" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};

    var ctx1 = ValidateCtx{ .allocator = testing.allocator, .listener_port = env.listener.port() };
    env.ca.live_validate = .{ .ctx = &ctx1, .validateFn = ValidateCtx.validate };
    var issued1 = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued1.deinit(testing.allocator);
    try testing.expect(ctx1.fetched);
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());

    // Stop the real listener and bring up a fresh one on a new ephemeral
    // port, bound to the same store and managed-host configuration (owned by
    // `Env`, not the listener) -- the thing #883 P2 asks to prove is that a
    // listener restart does not wedge the next issuance or leak anything
    // from the one before it.
    env.listener.deinit();
    try env.listener.start(testing.allocator, "127.0.0.1", 0, .{
        .managed_hosts = env.managed_hosts,
        .store = &env.store,
    });

    var ctx2 = ValidateCtx{ .allocator = testing.allocator, .listener_port = env.listener.port() };
    env.ca.live_validate = .{ .ctx = &ctx2, .validateFn = ValidateCtx.validate };
    var issued2 = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued2.deinit(testing.allocator);
    try testing.expect(ctx2.fetched);
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

/// Shared, independently advanceable Unix-seconds clock the order engine's
/// own `ChallengeStore` admission (`orders_mod.Options.unix_clock`) and this
/// real listener's own TTL check (`listener_mod.Options.unix_now`) are both
/// pointed at, instead of each reading the real wall clock on its own. A
/// published challenge's live window is then bounded purely by when the test
/// itself jumps this clock forward, never by how much real CI-scheduling
/// delay elapses between publish and the first live fetch (#883 P2 review:
/// a real-time race here could expire the entry before that first fetch).
const FakeUnixClock = struct {
    now_s: std.atomic.Value(i64),

    fn init(start: i64) FakeUnixClock {
        return .{ .now_s = .init(start) };
    }

    fn tick(ctx: ?*anyopaque) i64 {
        const self: *FakeUnixClock = @ptrCast(@alignCast(ctx.?));
        return self.now_s.load(.acquire);
    }

    fn advance(self: *FakeUnixClock, delta_s: i64) void {
        _ = self.now_s.fetchAdd(delta_s, .release);
    }
};

/// Live-fetches `host`/`token` on the real listener before and after jumping
/// the shared `FakeUnixClock` well past the published challenge's TTL, so a
/// single hook invocation (itself a blocking read inside the production
/// authorization *poll* call) can observe the published challenge both live
/// and -- purely through `ChallengeStore`'s own TTL enforcement, never an
/// explicit `store.remove` -- expired, while the order engine itself is
/// still blocked in that very call, not yet past any deadline/cleanup check
/// of its own (#883 P2 review).
const ExpiryCtx = struct {
    allocator: std.mem.Allocator,
    listener_port: u16,
    clock: *FakeUnixClock,
    before_status: u16 = 0,
    before_body_matched: bool = false,
    after_status: u16 = 0,

    fn validate(ctx: ?*anyopaque, host: []const u8, token: []const u8, key_authorization: []const u8) bool {
        const self: *ExpiryCtx = @ptrCast(@alignCast(ctx.?));

        var before = liveFetch(self.allocator, self.listener_port, host, token) catch return false;
        defer before.deinit(self.allocator);
        self.before_status = before.status;
        self.before_body_matched = std.mem.eql(u8, before.body, key_authorization);

        // Comfortably past the short TTL this test's `authz_deadline_s`
        // bounds the published challenge to (design §8.2): the store must
        // expire this entry on its own, independent of the order engine
        // (which is blocked right here, inside this very poll call, and has
        // not reached any deadline check since publishing it). An instant
        // clock jump, not a real sleep, so this can never race the "before"
        // fetch above.
        self.clock.advance(10);

        var after = liveFetch(self.allocator, self.listener_port, host, token) catch return false;
        defer after.deinit(self.allocator);
        self.after_status = after.status;

        // A real, bounded wall-clock sleep -- unrelated to the TTL check
        // above, which the fake clock jump already settled -- so the
        // transport's own real-time read deadline for this very poll
        // request trips for real, converting it into the order engine's
        // ordinary `AuthorizationTimedOut` back in `orders.zig` (the same
        // path a genuinely slow CA peer would hit).
        zig_compat.sleepNs(3 * std.time.ns_per_s);

        // Report a validation failure either way: the point of this test is
        // the two live fetches above, not a successful issuance.
        return false;
    }
};

test "ACME A3 (#883 P2): the live listener serves a published challenge before its TTL and 404s after it expires while the authorization is still in flight" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: Env = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var fake_unix = FakeUnixClock.init(zig_compat.unixTimestamp());
    // Restart the real listener bound to the same store, this time handing
    // it the same fake clock the order engine's own `unix_clock` below uses,
    // so both sides of the TTL check share one controlled time source
    // (#883 P2 review).
    env.listener.deinit();
    try env.listener.start(testing.allocator, "127.0.0.1", 0, .{
        .managed_hosts = env.managed_hosts,
        .store = &env.store,
        .unix_now = .{ .ctx = &fake_unix, .nowFn = FakeUnixClock.tick },
    });

    var ctx = ExpiryCtx{ .allocator = testing.allocator, .listener_port = env.listener.port(), .clock = &fake_unix };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = ExpiryCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    opts.unix_clock = .{ .ctx = &fake_unix, .nowFn = FakeUnixClock.tick };
    // Short enough that `store.put`'s TTL (bounded by this deadline, design
    // §8.2/§9.1) is already crossed by `ExpiryCtx.validate`'s clock jump
    // above; the order engine's own read of that same poll response then
    // times out too via its own real clock and the real sleep above, so
    // `obtain` itself still fails closed on a bounded, ordinary deadline
    // error.
    opts.limits.authz_deadline_s = 2;
    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    try testing.expectEqual(@as(u16, 200), ctx.before_status);
    try testing.expect(ctx.before_body_matched);
    try testing.expectEqual(@as(u16, 404), ctx.after_status);
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

// -- #883 P1: a genuinely independent CA, over real TLS and real wire bytes --

/// Records every host this hook actually live-fetched and validated, so a
/// multi-identifier test can assert every requested name -- not just one --
/// crossed the real socket with its own correct key authorization.
const MultiValidateCtx = struct {
    allocator: std.mem.Allocator,
    listener_port: u16,
    seen: [4][]const u8 = undefined,
    seen_len: usize = 0,

    fn validate(ctx: ?*anyopaque, host: []const u8, token: []const u8, key_authorization: []const u8) bool {
        const self: *MultiValidateCtx = @ptrCast(@alignCast(ctx.?));
        if (self.seen_len < self.seen.len) {
            self.seen[self.seen_len] = host;
            self.seen_len += 1;
        }
        var resp = liveFetch(self.allocator, self.listener_port, host, token) catch return false;
        defer resp.deinit(self.allocator);
        if (resp.status != 200) return false;
        return std.mem.eql(u8, resp.body, key_authorization);
    }

    fn saw(self: *const MultiValidateCtx, host: []const u8) bool {
        for (self.seen[0..self.seen_len]) |h| {
            if (std.mem.eql(u8, h, host)) return true;
        }
        return false;
    }
};

/// Like `Env`, but every ACME directory/account/order/authorization/
/// finalize/certificate exchange crosses a real loopback TCP socket and a
/// real server-role TLS 1.3 handshake into `live_ca_server.Server` -- the
/// production A2 client dials through the real `acme_tls_dialer.zig`
/// (`UpstreamTlsConn`, real hostname/chain verification against a real
/// trust anchor), not the in-memory fake `Connection`. Only the HTTP-01
/// validation leg was already real before this (`Env` above); this harness
/// makes the CA leg real too, closing the #883 P1 gap.
const RealCaEnv = struct {
    tmp: testing.TmpDir = undefined,
    path: []u8 = undefined,
    ca: fake.FakeCa = undefined,
    ca_server: live_ca_server.Server = .{},
    /// `fake.FakeCa.base` (every CA-issued `Location`/`newNonce`/`finalize`
    /// URL) defaults to the fixed `https://ca.test`; #832's SSRF-pinning
    /// `requireCaOrigin` would reject every one of those against this
    /// harness's real, dynamically-ported `https://127.0.0.1:<port>`
    /// directory origin, so this owns the real origin string and points
    /// `self.ca.base` at it instead.
    ca_base: []u8 = undefined,
    ca_trust: *transport_mod.TrustAnchorSnapshot = undefined,
    ca_dialer: tls_dialer_mod.TlsDialer = undefined,
    store: ChallengeStore = undefined,
    listener: Listener = undefined,
    managed_hosts: []const []const u8 = &.{},
    t: transport_mod.Transport = undefined,

    fn start(self: *RealCaEnv, managed_hosts: []const []const u8) !void {
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try self.tmp.dir.realPath(zig_compat.io(), &buf);
        self.path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        errdefer testing.allocator.free(self.path);
        self.ca = fake.FakeCa.init(testing.allocator);
        self.ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
        errdefer self.ca.deinit();
        try self.ca_server.start(testing.allocator, &self.ca);
        errdefer self.ca_server.deinit();
        self.ca_base = try std.fmt.allocPrint(testing.allocator, "https://127.0.0.1:{d}", .{self.ca_server.port()});
        errdefer testing.allocator.free(self.ca_base);
        self.ca.base = self.ca_base;
        self.ca_trust = try transport_mod.TrustAnchorSnapshot.load(testing.allocator, live_ca_server.default_ca_bundle_path);
        errdefer self.ca_trust.release();
        self.ca_dialer = tls_dialer_mod.TlsDialer.init(self.ca_trust);
        self.store = ChallengeStore.init(testing.allocator);
        self.managed_hosts = managed_hosts;
        try self.listener.start(testing.allocator, "127.0.0.1", 0, .{
            .managed_hosts = self.managed_hosts,
            .store = &self.store,
        });
    }

    fn deinit(self: *RealCaEnv) void {
        self.listener.deinit();
        self.store.deinit();
        self.ca_dialer.deinit();
        self.ca_trust.release();
        self.ca_server.deinit();
        self.ca.deinit();
        testing.allocator.free(self.ca_base);
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn openSession(self: *RealCaEnv) !*Session {
        self.t = .{ .allocator = testing.allocator, .dialer = self.ca_dialer.dialer() };
        var state = try StateDir.open(self.path);
        defer state.close();
        var url_buf: [96]u8 = undefined;
        const url_text = try std.fmt.bufPrint(&url_buf, "{s}/directory", .{self.ca_base});
        return Session.open(testing.allocator, &self.t, &state, .{
            .directory_url = url_text,
            .terms_of_service_agreed = true,
        }, zig_compat.unixTimestamp());
    }

    fn expectStoreEmpty(self: *RealCaEnv) !void {
        try testing.expectEqual(@as(usize, 0), self.store.slots.items.len);
    }
};

test "ACME A3 (#883 P1): live issuance through a real independent TLS CA and the real gateway listener succeeds end to end" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: RealCaEnv = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var ctx = ValidateCtx{ .allocator = testing.allocator, .listener_port = env.listener.port() };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = ValidateCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);

    try testing.expect(ctx.fetched);
    try testing.expect(std.mem.startsWith(u8, issued.chain_pem, "-----BEGIN CERTIFICATE-----"));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

test "ACME A3 (#883 P1/P2): a real independent TLS CA issues a multi-identifier order with every name live-validated" {
    const hosts = [_][]const u8{ "a.example.com", "b.example.com" };
    var env: RealCaEnv = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var ctx = MultiValidateCtx{ .allocator = testing.allocator, .listener_port = env.listener.port() };
    env.ca.live_validate = .{ .ctx = &ctx, .validateFn = MultiValidateCtx.validate };

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);

    try testing.expect(ctx.saw("a.example.com"));
    try testing.expect(ctx.saw("b.example.com"));
    try testing.expect(std.mem.startsWith(u8, issued.chain_pem, "-----BEGIN CERTIFICATE-----"));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

// -- #883 P2: hostile CA responses over the real TLS wire, not only the
// in-memory fake `Connection` `orders_tests.zig` already covers --

test "ACME A3 (#883 P2): malformed JSON from the real independent TLS CA's new-order response fails closed with no residue" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: RealCaEnv = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    env.ca.script.new_order.malformed_json = true;

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    // No authorization was ever reached, so there is nothing for the live
    // listener's store to have admitted in the first place.
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}

test "ACME A3 (#883 P2): a cross-origin authorization URL from the real independent TLS CA is rejected closed with no residue" {
    const hosts = [_][]const u8{"a.example.com"};
    var env: RealCaEnv = .{};
    try env.start(&hosts);
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    // The new-order response's first `authorizations[]` entry points at
    // `https://evil.test/authz/1` instead of this harness's own real CA
    // origin: #832's SSRF-pinning `requireCaOrigin` must reject this before
    // ever dialing that origin, over the real TLS transport exactly as it
    // would over the in-memory fake.
    env.ca.script.new_order.cross_host_authorization = true;

    var opts = orders_mod.Options{};
    fastPoll(&opts);
    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CrossHostUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));

    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.listener.activeConnections());
}
