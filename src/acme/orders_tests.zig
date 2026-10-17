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

fn advanceOnWait(ctx: ?*anyopaque, ms: u32, cancel: orders_mod.Cancel) bool {
    const t: *TestTime = @ptrCast(@alignCast(ctx.?));
    t.ms += ms;
    t.unix += @divTrunc(ms, 1000) + 1;
    return cancel.isCancelled();
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
        // Lets `script.stall_ms_per_read` (a simulated slow peer) advance
        // the same shared `TestTime.ms` that `options().clock` reads, so a
        // test can make a single CA response read consume real budget from
        // the order/authorization deadlines (#898).
        self.ca.clock_sink = .{ .ctx = &self.time, .advanceFn = struct {
            fn advance(ctx: ?*anyopaque, ms: i64) void {
                const t: *TestTime = @ptrCast(@alignCast(ctx.?));
                t.ms += ms;
            }
        }.advance };
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
            .waiter = .{ .ctx = &self.time, .waitFn = advanceOnWait },
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

test "ACME orders: a malformed new-order expiry fails closed before authorization work" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.expires_override = "not-a-timestamp";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1"));
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

test "ACME orders: a preauthorized name may have no authorization URL" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.missing_authorization = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), env.ca.countRequests(.POST, "/authz/1"));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/2"));
}

test "ACME orders: distinct authorization URLs may cover the same requested name" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.collapse_identifier = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
    try env.expectStoreEmpty();
}

test "ACME orders: a ready order may have no authorization URLs" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.ready_without_authorizations = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: a ready new-order response may omit expires" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.ready_without_authorizations = true;
    env.ca.script.new_order.omit_expires = true;

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
}

test "ACME orders: an authorization identifier that changes mid-poll fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.swap_identifier_on_poll = true;

    const names = [_][]const u8{ "a.example.com", "b.example.com" };
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a duplicate http-01 challenge fails closed without publishing anything" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.duplicate_http01 = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: a surprising new-order status fails closed before any authorization request" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.status_override = "bogus";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: a premature valid new-order status fails closed before any authorization request" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.status_override = "valid";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: an invalid new-order status fails closed before any authorization request" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.status_override = "invalid";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderInvalid, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: an already-cancelled attempt makes no CA request" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    var opts = env.options();
    opts.cancel = .{ .checkFn = struct {
        fn check(_: ?*anyopaque) bool {
            return true;
        }
    }.check };

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Cancelled, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/new-order"));
}

test "ACME orders: an already-expired order deadline makes no CA request" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    var opts = env.options();
    opts.limits.order_deadline_s = 0;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/new-order"));
}

test "ACME orders: cancellation after the final order poll aborts before certificate download" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    var opts = env.options();
    opts.cancel = .{
        .ctx = &env.ca,
        .checkFn = struct {
            fn check(ctx: ?*anyopaque) bool {
                const ca: *fake.FakeCa = @ptrCast(@alignCast(ctx.?));
                // True only once the final order-status poll (not the
                // `/finalize` submission, a different path) has actually been
                // sent, so this fires right as `obtain` is about to download
                // the certificate -- not any earlier.
                return ca.countRequests(.POST, "/order/1") >= 1;
            }
        }.check,
    };

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Cancelled, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/cert/1"));
}

// ---------------------------------------------------------------------------
// #898 follow-up: finalize response validation, absolute deadlines across
// authorization fetch/publish, bounded transient-failure retry, and
// CA-bounded authorization expiry.
// ---------------------------------------------------------------------------

test "ACME orders: a malformed finalize response fails closed before any order poll" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.finalize.malformed_json = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/order/1"));
}

test "ACME orders: an invalid-status finalize response fails closed before any order poll" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.finalize.status_override = "invalid";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderInvalid, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/order/1"));
}

test "ACME orders: a finalize response naming identifiers outside the requested group fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.finalize.mismatched_identifiers = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/order/1"));
}

test "ACME orders: an authorization deadline consumed during its own fetch publishes nothing" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    // Every CA response read advances the shared clock by 300ms; the
    // authorization's own 2s budget cannot survive reading even one
    // authorization response, but the generous order budget means this is
    // specifically the authorization deadline firing, not the order one.
    env.ca.script.stall_ms_per_read = 300;
    var opts = env.options();
    opts.limits.order_deadline_s = 600;
    opts.limits.authz_deadline_s = 2;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: transient 5xx authorization polls retry with bounded backoff then succeed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.transient_failures = 2;

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
    try env.expectStoreEmpty();
}

test "ACME orders: perpetual 5xx on the very first authorization fetch exhausts the bounded retry budget" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.status_500 = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CaRejected, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: perpetual 5xx on authorization polling (after publication) exhausts the bounded retry budget" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.status_500_after_first_get = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CaRejected, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.POST, "/authz/1/http-01"));
    try testing.expect(env.ca.countRequests(.POST, "/authz/1") <= 5);
}

test "ACME orders: transient 5xx order polls retry with bounded backoff then succeed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.transient_failures = 2;

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
}

test "ACME orders: perpetual 5xx on order polling exhausts the bounded retry budget" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.status_500 = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.CaRejected, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
}

test "ACME orders: an already-expired CA authorization expiry rejects before publishing anything" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    // One second before `TestTime.unix`'s starting value (1_700_000_000 =
    // 2023-11-14T22:13:20Z).
    env.ca.script.authz.expires_override = "2023-11-14T22:13:19Z";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: a near-future CA authorization expiry caps polling even while pending" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    // 3 seconds after `TestTime.unix`'s starting value (1_700_000_000 =
    // 2023-11-14T22:13:20Z): short enough that the CA's own `expires` --
    // not the ordinary 120s authorization deadline -- is what must stop
    // polling, even though the CA keeps answering `processing` forever.
    env.ca.script.authz.expires_override = "2023-11-14T22:13:23Z";
    env.ca.script.authz.polls_before_final = 1_000_000;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
    try testing.expect(env.ca.countRequests(.POST, "/authz/1") <= 5);
}

test "ACME orders: a stalled cold directory GET cannot outrun the order deadline before newOrder" {
    var env = try Env.init();
    defer env.deinit();
    const first_session = try env.openSession();
    first_session.close();

    // Reopening against the now-persisted account record reuses the stored
    // `kid` with no network call at all (`client.zig`'s `Session.open`), so
    // this fresh `Client` starts with an uncached directory -- unlike every
    // other test here, where `openSession`'s account registration already
    // warmed it. This is the only way to exercise `client.newOrderUrl`'s own
    // deadline cap on a genuinely cold directory GET (#898).
    const session = try env.openSession();
    defer session.close();

    env.ca.script.stall_ms_per_read = 2_000;
    var opts = env.options();
    opts.limits.order_deadline_s = 1;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Timeout, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/new-order"));
}

test "ACME orders: a malformed CA authorization expiry fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.expires_override = "not-a-timestamp";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
}

test "ACME orders: a malformed challenge acknowledgement stops before polling and clears the store" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.challenge.malformed_ack = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: a mismatched challenge acknowledgement stops before polling" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.challenge.mismatched_ack_token = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: an invalid challenge acknowledgement status stops before polling" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.challenge.invalid_ack_status = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadAuthorizationResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: a rate-limited initial authorization GET retries before publishing" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.rate_limited_first_gets = 1;

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), env.ca.countRequests(.POST, "/authz/1"));
}

test "ACME orders: cancellation during initial authorization Retry-After returns promptly" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.rate_limited_first_gets = 1;
    var opts = env.options();
    opts.cancel = .{ .ctx = &env.ca, .checkFn = struct {
        fn check(ctx: ?*anyopaque) bool {
            const ca: *fake.FakeCa = @ptrCast(@alignCast(ctx.?));
            return ca.countRequests(.POST, "/authz/1") >= 1;
        }
    }.check };

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.Cancelled, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: initial authorization Retry-After obeys the absolute deadline" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.authz.rate_limited_first_gets = 1;
    var opts = env.options();
    opts.limits.order_deadline_s = 1;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.AuthorizationTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try env.expectStoreEmpty();
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/authz/1/http-01"));
}

test "ACME orders: a polled order with changed identifiers is rejected before certificate download" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.mismatched_identifiers = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.UnexpectedIdentifier, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/cert/1"));
}

test "ACME orders: a polled order with changed authorization URLs is rejected before certificate download" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.mismatched_authorizations = true;

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/cert/1"));
}

test "ACME orders: a near-future CA order expiry caps polling before download" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.new_order.expires_override = "2023-11-14T22:13:23Z";
    env.ca.script.order_poll.polls_before_final = 1_000_000;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.OrderTimedOut, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/cert/1"));
}

test "ACME orders: a processing order poll may omit expires" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.polls_before_final = 1;
    env.ca.script.order_poll.omit_expires_while_processing = true;
    var opts = env.options();
    fastPoll(&opts);

    const names = [_][]const u8{"a.example.com"};
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, opts);
    defer issued.deinit(testing.allocator);
}

test "ACME orders: a malformed supplied order-poll expiry fails closed" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();
    env.ca.script.order_poll.expires_override = "not-a-timestamp";

    const names = [_][]const u8{"a.example.com"};
    try testing.expectError(error.BadOrderResponse, orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options()));
    try testing.expectEqual(@as(usize, 0), env.ca.countRequests(.POST, "/cert/1"));
}

test "ACME orders: the issued chain owns a durable copy of the requested order group" {
    var env = try Env.init();
    defer env.deinit();
    const session = try env.openSession();
    defer session.close();

    var names = [_][]const u8{ "a.example.com", "b.example.com" };
    var issued = try orders_mod.obtain(testing.allocator, &session.client, &env.store, &names, env.options());
    defer issued.deinit(testing.allocator);

    // The caller's slice is mutated after `obtain` returns: the result must
    // not alias it.
    names[0] = "mutated.example.com";

    try testing.expectEqual(@as(usize, 2), issued.hostnames.len);
    try testing.expectEqualStrings("a.example.com", issued.hostnames[0]);
    try testing.expectEqualStrings("b.example.com", issued.hostnames[1]);
}
