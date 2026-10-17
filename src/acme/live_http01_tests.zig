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

fn liveFetch(allocator: std.mem.Allocator, port: u16, host: []const u8, token: []const u8) !LiveResponse {
    const stream = try zig_compat.tcpConnectToHost(allocator, "127.0.0.1", port);
    defer stream.close();
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET {s}{s} HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ listener_mod.challenge_prefix, token, host });
    try stream.writeAll(req);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) catch break;
        if (n == 0) break;
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
