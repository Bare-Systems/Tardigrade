//! End-to-end tests for the A3 order engine (#882) against the fake CA.
//! Every request is driven through the real A2 `Client`/`Session`
//! (`client_tests.zig`'s fake CA extended with order/authz/finalize/
//! download endpoints, see `fake_ca.zig`); every wait is an injected
//! `orders.Waiter` that advances a shared fake clock synchronously instead
//! of blocking, so polling/backoff/timeout/cancellation are deterministic
//! and these tests make no live network call.

const std = @import("std");
const client_mod = @import("client.zig");
const state_mod = @import("state.zig");
const transport_mod = @import("transport.zig");
const orders_mod = @import("orders.zig");
const fake = @import("fake_ca.zig");
const challenge_store_mod = @import("../http/acme_challenge_store.zig");
const zig_compat = @import("zig_compat");

const testing = std.testing;
const Session = client_mod.Session;
const StateDir = state_mod.StateDir;
const ChallengeStore = challenge_store_mod.ChallengeStore;

const directory_url = "https://ca.test/directory";

/// Shared fake time: `ms` backs both the transport's per-request deadline
/// clock and the order engine's monotonic `Clock`; `unix` backs the
/// `ChallengeStore`'s Unix-seconds admission clock. `Waiter.wait` advances
/// both together so a test never actually sleeps.
const TestTime = struct {
    ms: i64 = 10_000,
    unix: i64 = 1_700_000_000,
};

fn tickMs(ctx: ?*anyopaque) i64 {
    const t: *TestTime = @ptrCast(@alignCast(ctx.?));
    return t.ms;
}

fn tickUnix(ctx: ?*anyopaque) i64 {
    const t: *TestTime = @ptrCast(@alignCast(ctx.?));
    return t.unix;
}

fn advanceOnWait(ctx: ?*anyopaque, ms: u32) void {
    const t: *TestTime = @ptrCast(@alignCast(ctx.?));
    t.ms += ms;
    t.unix += @divTrunc(ms, 1000) + 1;
}

const Env = struct {
    tmp: testing.TmpDir,
    path: []u8,
    ca: fake.FakeCa,
    store: ChallengeStore,
    time: TestTime = .{},
    t: transport_mod.Transport = undefined,

    fn init() !Env {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(zig_compat.io(), &buf);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        return .{
            .tmp = tmp,
            .path = path,
            .ca = fake.FakeCa.init(testing.allocator),
            .store = ChallengeStore.init(testing.allocator),
        };
    }

    fn deinit(self: *Env) void {
        self.store.deinit();
        self.ca.deinit();
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn transport(self: *Env) *const transport_mod.Transport {
        self.t = .{
            .allocator = testing.allocator,
            .dialer = self.ca.dialer(),
            .clock = .{ .ctx = &self.time, .nowFn = tickMs },
        };
        return &self.t;
    }

    fn openSession(self: *Env) !*Session {
        const t = self.transport();
        var state = try StateDir.open(self.path);
        defer state.close();
        return Session.open(testing.allocator, t, &state, .{
            .directory_url = directory_url,
            .terms_of_service_agreed = true,
        }, 1_700_000_000);
    }

    fn options(self: *Env) orders_mod.Options {
        return .{
            .clock = .{ .ctx = &self.time, .nowFn = tickMs },
            .unix_clock = .{ .ctx = &self.time, .nowFn = tickUnix },
            .waiter = .{ .ctx = &self.time, .sleepFn = advanceOnWait },
        };
    }

    fn expectStoreEmpty(self: *Env) !void {
        try testing.expectEqual(@as(usize, 0), self.store.slots.items.len);
    }
};

fn fastPoll(opts: *orders_mod.Options) void {
    opts.limits.poll_interval_min_s = 1;
    opts.limits.poll_interval_max_s = 1;
}

test "ACME orders: single-identifier HTTP-01 issuance succeeds end to end" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);

    try testing.expect(std.mem.startsWith(u8, issued.chain_pem, "-----BEGIN CERTIFICATE-----"));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.POST, "/new-order"));
    try testing.expect(env.ca.allPostsVerified());
}

test "ACME orders: multi-identifier order issues one chain covering every name" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);

    try testing.expect(std.mem.startsWith(u8, issued.chain_pem, "-----BEGIN CERTIFICATE-----"));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 2), env.ca.countRequests(.POST, "/authz/1"));
    try testing.expectEqual(@as(usize, 2), env.ca.countRequests(.POST, "/authz/2"));
}

test "ACME orders: finite polling before an authorization settles valid" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.polls_before_final = 3;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);
    try env.expectStoreEmpty();
    // 1 initial fetch + 3 pending polls + 1 terminal poll = 5.
    try testing.expectEqual(@as(usize, 5), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: an invalid authorization fails closed and clears the challenge store" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.final_status = .invalid;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationInvalid, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: authorization polling times out and clears the challenge store" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.polls_before_final = 1_000_000;
    var opts = env.options();
    fastPoll(&opts);
    opts.limits.authz_deadline_s = 5;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
}

test "ACME orders: cancellation during authorization polling aborts and clears the challenge store" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.polls_before_final = 1_000_000;
    var opts = env.options();
    fastPoll(&opts);

    const Counter = struct { remaining: u32 };
    var counter = Counter{ .remaining = 2 };
    opts.cancel = .{ .ctx = &counter, .checkFn = struct {
        fn check(ctx: ?*anyopaque) bool {
            const c: *Counter = @ptrCast(@alignCast(ctx.?));
            if (c.remaining == 0) return true;
            c.remaining -= 1;
            return false;
        }
    }.check };

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Cancelled, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
}

test "ACME orders: rate-limited authorization polling honors Retry-After then succeeds" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.rate_limited_polls = 2;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);
    try env.expectStoreEmpty();
}

test "ACME orders: a CA identifier outside the requested group fails closed (new-order)" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.extra_identifier = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a dropped identifier fails closed (new-order)" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.missing_identifier = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: an authorization identifier outside the requested group fails closed (confused deputy)" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.wrong_identifier = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a cross-host authorization URL is rejected before it is ever requested" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.cross_host_authorization = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CrossHostUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a cross-host finalize URL is rejected" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.cross_host_finalize = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CrossHostUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a duplicate authorization URL in the order response fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.duplicate_authorization = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    try testing.expectError(error.DuplicateAuthorizationUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: no http-01 challenge offered fails closed without publishing anything" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.no_http01 = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.NoHttp01Challenge, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a cross-host http-01 challenge URL is rejected" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.cross_host_challenge = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CrossHostUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a rejected CSR (badCSR) fails the attempt and clears the challenge store" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.finalize.rejected = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CaRejected, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: an invalid order after finalize fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.final_status = .invalid;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderInvalid, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: finite polling before the order settles valid after finalize" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.polls_before_final = 3;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);
}

test "ACME orders: order polling times out after finalize" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.polls_before_final = 1_000_000;
    var opts = env.options();
    fastPoll(&opts);
    opts.limits.order_deadline_s = 5;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
}

test "ACME orders: rate-limited order polling honors Retry-After then succeeds" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.rate_limited_polls = 2;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);
}

test "ACME orders: a cross-host certificate URL is rejected before download" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.cross_host_certificate = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CrossHostUrl, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}

test "ACME orders: a malformed authorization response fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.malformed_json = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}

test "ACME orders: a malformed new-order response fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.malformed_json = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}

test "ACME orders: an oversized certificate response is rejected" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.cert.huge_body = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.ResponseTooLarge, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}

test "ACME orders: an empty certificate response is rejected" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.cert.empty_body = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadCertificateResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}
