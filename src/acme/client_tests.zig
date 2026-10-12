//! End-to-end tests for the A2 account protocol against the fake CA (#832).
//! Every request the client makes is a real signed JWS that the fake CA
//! verifies; see `fake_ca.zig` for the hostile behaviors it can script.

const std = @import("std");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const client_mod = @import("client.zig");
const account_mod = @import("account.zig");
const state_mod = @import("state.zig");
const transport_mod = @import("transport.zig");
const fake = @import("fake_ca.zig");

const testing = std.testing;
const Client = client_mod.Client;
const Session = client_mod.Session;
const FakeCa = fake.FakeCa;
const StateDir = state_mod.StateDir;

const directory_url = "https://ca.test/directory";

const Env = struct {
    tmp: testing.TmpDir,
    path: []u8,
    ca: FakeCa,
    clock: fake.FakeClock = .{},
    /// Owned here so a returned `Session` never points at a dead stack frame.
    t: transport_mod.Transport = undefined,

    fn init() !Env {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(zig_compat.io(), &buf);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        return .{ .tmp = tmp, .path = path, .ca = FakeCa.init(testing.allocator) };
    }

    fn deinit(self: *Env) void {
        self.ca.deinit();
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn transport(self: *Env) *const transport_mod.Transport {
        self.ca.clock = &self.clock;
        self.t = .{ .allocator = testing.allocator, .dialer = self.ca.dialer(), .clock = self.clock.clock() };
        return &self.t;
    }

    fn config(self: *Env) client_mod.Config {
        _ = self;
        return .{ .directory_url = directory_url, .terms_of_service_agreed = true };
    }

    fn recordExists(self: *Env) !bool {
        var state = try StateDir.open(self.path);
        defer state.close();
        if (state.readFileAlloc(testing.allocator, state_mod.account_record_name, 4096, true)) |bytes| {
            testing.allocator.free(bytes);
            return true;
        } else |err| switch (err) {
            error.NotFound => return false,
            else => return err,
        }
    }
};

fn openSession(env: *Env, cfg: client_mod.Config) !*Session {
    const t = env.transport();
    var state = try StateDir.open(env.path);
    defer state.close();
    return Session.open(testing.allocator, t, &state, cfg, 1_700_000_000);
}

fn expectOpenFails(env: *Env, cfg: client_mod.Config, expected: anyerror) !void {
    const t = env.transport();
    var state = try StateDir.open(env.path);
    defer state.close();
    if (Session.open(testing.allocator, t, &state, cfg, 1_700_000_000)) |session| {
        session.close();
        return error.ExpectedFailure;
    } else |err| try testing.expectEqual(expected, err);
}

test "ACME client: creates an account with signed requests and persists it" {
    var env = try Env.init();
    defer env.deinit();
    var cfg = env.config();
    cfg.contact_email = "ops@example.com";

    const session = try openSession(&env, cfg);
    defer session.close();

    try testing.expect(session.created);
    try testing.expectEqualStrings("https://ca.test/acct/1", session.accountUrl());
    try testing.expectEqual(@as(usize, 1), env.ca.accounts.items.len);
    try testing.expectEqual(@as(usize, 1), env.ca.countPosts());
    try testing.expect(env.ca.allPostsVerified());
    try testing.expect(!env.ca.nonce_reuse_detected);
    // GET directory, HEAD new-nonce, POST new-acct: no more.
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.GET, "/directory"));
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.HEAD, "/new-nonce"));
    try testing.expect(std.mem.indexOf(u8, env.ca.last_payload.?, "\"termsOfServiceAgreed\":true") != null);
    try testing.expect(std.mem.indexOf(u8, env.ca.last_payload.?, "mailto:ops@example.com") != null);
    try testing.expect(try env.recordExists());

    const diag = session.client.status();
    try testing.expectEqual(@as(u32, 1), diag.accounts_created);
    try testing.expectEqual(@as(u32, 1), diag.signed_requests);
    try testing.expectEqual(@as(u32, 1), diag.directory_fetches);
    try testing.expectEqual(@as(?client_mod.FailureClass, null), diag.last_failure);
}

test "ACME client: restart reuses the persisted account without any network I/O" {
    var env = try Env.init();
    defer env.deinit();
    const cfg = env.config();
    {
        const first = try openSession(&env, cfg);
        first.close();
    }
    const requests_before = env.ca.log.items.len;
    // The CA is now unreachable; a persisted account must still open.
    env.ca.script.refuse_dial = true;
    const second = try openSession(&env, cfg);
    defer second.close();
    try testing.expect(!second.created);
    try testing.expectEqualStrings("https://ca.test/acct/1", second.accountUrl());
    try testing.expectEqual(requests_before, env.ca.log.items.len);
    try testing.expectEqual(@as(u32, 1), second.client.status().accounts_reused);
}

test "ACME client: kid-authenticated requests verify against the registered key" {
    var env = try Env.init();
    defer env.deinit();
    const session = try openSession(&env, env.config());
    defer session.close();

    var resp = try session.client.signedPostAsGet("https://ca.test/acct/1");
    resp.deinit();
    try testing.expect(env.ca.log.items[env.ca.log.items.len - 1].used_kid);
    try testing.expect(env.ca.allPostsVerified());
    // The nonce came from the previous response: no extra HEAD.
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.HEAD, "/new-nonce"));

    // A kid for an account the CA never created is refused, signature or not.
    try session.client.setKid("https://ca.test/acct/999");
    try testing.expectError(error.CaRejected, session.client.signedPostAsGet("https://ca.test/acct/999"));
    try testing.expectEqual(client_mod.ProblemType.account_does_not_exist, session.client.status().last_problem);
}

test "ACME client: badNonce is retried with the fresh nonce within a finite budget" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.bad_nonce_remaining = 1;
    const session = try openSession(&env, env.config());
    defer session.close();

    try testing.expectEqual(@as(usize, 2), env.ca.countPosts());
    // The retry used the nonce carried by the badNonce response.
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.HEAD, "/new-nonce"));
    try testing.expectEqual(@as(u32, 1), session.client.status().bad_nonce_retries);
    try testing.expect(!env.ca.nonce_reuse_detected);
}

test "ACME client: persistent badNonce fails after exactly the retry budget" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.bad_nonce_remaining = 100;
    try expectOpenFails(&env, env.config(), error.BadNonceExhausted);
    // 1 attempt + 1 retry (A1 contract §5.3).
    try testing.expectEqual(@as(usize, 2), env.ca.countPosts());
    try testing.expect(!(try env.recordExists()));
    try testing.expectEqual(client_mod.FailureClass.protocol, client_mod.classify(error.BadNonceExhausted));
}

test "ACME client: a zero retry budget makes one attempt" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.bad_nonce_remaining = 100;
    var cfg = env.config();
    cfg.max_bad_nonce_retries = 0;
    try expectOpenFails(&env, cfg, error.BadNonceExhausted);
    try testing.expectEqual(@as(usize, 1), env.ca.countPosts());
    // The default is one retry.
    try testing.expectEqual(@as(u8, 1), (client_mod.Config{ .directory_url = directory_url }).max_bad_nonce_retries);
}

test "ACME client: a nonce is never reused across sequential and failing requests" {
    var env = try Env.init();
    defer env.deinit();
    const session = try openSession(&env, env.config());
    defer session.close();
    for (0..5) |_| {
        var resp = try session.client.signedPostAsGet("https://ca.test/acct/1");
        resp.deinit();
    }
    // Interleave failures (unknown kid) with successes.
    try session.client.setKid("https://ca.test/acct/77");
    try testing.expectError(error.CaRejected, session.client.signedPostAsGet("https://ca.test/acct/77"));
    try session.client.setKid("https://ca.test/acct/1");
    var resp = try session.client.signedPostAsGet("https://ca.test/acct/1");
    resp.deinit();
    try testing.expect(!env.ca.nonce_reuse_detected);
}

test "ACME client: missing Replay-Nonce on responses falls back to newNonce each time" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.omit_nonce_on_post = true;
    const session = try openSession(&env, env.config());
    defer session.close();
    try testing.expectEqual(@as(usize, 1), env.ca.countRequests(.HEAD, "/new-nonce"));

    // The newAccount response carried no nonce, so the next request must HEAD.
    var resp = try session.client.signedPostAsGet("https://ca.test/acct/1");
    resp.deinit();
    try testing.expectEqual(@as(usize, 2), env.ca.countRequests(.HEAD, "/new-nonce"));
    try testing.expect(env.ca.allPostsVerified());
}

test "ACME client: newNonce without a usable nonce fails closed" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.omit_nonce_on_head = true;
    try expectOpenFails(&env, env.config(), error.MissingNonce);
    try testing.expectEqual(@as(usize, 0), env.ca.countPosts());

    env.ca.script.omit_nonce_on_head = false;
    env.ca.script.bad_nonce_value_on_head = true;
    try expectOpenFails(&env, env.config(), error.MissingNonce);
    try testing.expectEqual(@as(usize, 0), env.ca.countPosts());
}

test "ACME client: hostile directories fail closed and never dial another host" {
    const cases = [_]struct { mode: fake.DirectoryMode, err: anyerror }{
        .{ .mode = .malformed_json, .err = error.BadDirectory },
        .{ .mode = .deep_json, .err = error.BadDirectory },
        .{ .mode = .missing_field, .err = error.BadDirectory },
        .{ .mode = .wrong_field_type, .err = error.BadDirectory },
        .{ .mode = .huge_body, .err = error.ResponseTooLarge },
        .{ .mode = .redirect, .err = error.RedirectRejected },
        .{ .mode = .not_json_content_type, .err = error.NotJson },
        .{ .mode = .cross_host_new_account, .err = error.CrossHostUrl },
        .{ .mode = .cross_host_new_nonce, .err = error.CrossHostUrl },
        .{ .mode = .http_scheme_url, .err = error.NotHttps },
        .{ .mode = .userinfo_url, .err = error.UserInfo },
        .{ .mode = .status_500, .err = error.CaRejected },
    };
    for (cases) |case| {
        var env = try Env.init();
        defer env.deinit();
        env.ca.script.directory = case.mode;
        try expectOpenFails(&env, env.config(), case.err);
        for (env.ca.dialed.items) |host| try testing.expectEqualStrings("ca.test", host);
        try testing.expectEqual(@as(usize, 0), env.ca.countPosts());
        try testing.expect(!(try env.recordExists()));
    }
}

test "ACME client: cross-host URLs are reachable only with the explicit opt-in" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.directory = .cross_host_new_account;
    var cfg = env.config();
    cfg.allow_cross_host_urls = true;
    // Allowed by policy, so the client tries to dial the other host (which
    // does not exist in this world) instead of refusing the URL.
    try expectOpenFails(&env, cfg, error.DialFailed);
    try testing.expect(env.ca.dialed.items.len >= 2);
    try testing.expectEqualStrings("internal.test", env.ca.dialed.items[env.ca.dialed.items.len - 1]);
}

test "ACME client: hostile account responses fail closed without persisting" {
    const cases = [_]struct { mode: fake.AccountMode, err: anyerror }{
        .{ .mode = .missing_location, .err = error.BadAccountResponse },
        .{ .mode = .cross_host_location, .err = error.CrossHostUrl },
        .{ .mode = .http_location, .err = error.NotHttps },
        .{ .mode = .status_500, .err = error.CaRejected },
        .{ .mode = .status_202, .err = error.UnexpectedStatus },
        .{ .mode = .rate_limited, .err = error.RateLimited },
        .{ .mode = .invalid_status_body, .err = error.BadAccountResponse },
        .{ .mode = .text_plain_content_type, .err = error.BadAccountResponse },
        .{ .mode = .garbage_body, .err = error.BadAccountResponse },
        .{ .mode = .empty_body, .err = error.BadAccountResponse },
        .{ .mode = .huge_body, .err = error.ResponseTooLarge },
        .{ .mode = .server_error_problem, .err = error.CaRejected },
    };
    for (cases) |case| {
        var env = try Env.init();
        defer env.deinit();
        env.ca.script.account = case.mode;
        try expectOpenFails(&env, env.config(), case.err);
        try testing.expect(!(try env.recordExists()));
        try testing.expect(env.ca.allPostsVerified());
    }
}

test "ACME client: rate limits and unknown problems surface only closed enums" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.account = .rate_limited;
    const t = env.transport();
    var state = try StateDir.open(env.path);
    defer state.close();
    var key = try account_mod.AccountKey.generate();
    defer key.deinit();
    var client = try Client.init(testing.allocator, t, &key, env.config());
    defer client.deinit();
    try testing.expectError(error.RateLimited, client.signedPost("https://ca.test/new-acct", "{\"termsOfServiceAgreed\":true}", .jwk));
    var diag = client.status();
    try testing.expectEqual(client_mod.ProblemType.rate_limited, diag.last_problem);
    try testing.expectEqual(@as(?u32, 60), diag.last_retry_after_s);
    try testing.expectEqual(@as(u16, 429), diag.last_http_status);

    env.ca.script.account = .server_error_problem;
    try testing.expectError(error.CaRejected, client.signedPost("https://ca.test/new-acct", "{\"termsOfServiceAgreed\":true}", .jwk));
    diag = client.status();
    try testing.expectEqual(client_mod.ProblemType.other, diag.last_problem);
}

test "ACME client: terms must be agreed and contacts must be safe, before any request" {
    var env = try Env.init();
    defer env.deinit();
    var cfg = env.config();
    cfg.terms_of_service_agreed = false;
    try expectOpenFails(&env, cfg, error.TermsNotAgreed);
    try testing.expectEqual(@as(usize, 0), env.ca.log.items.len);

    cfg.terms_of_service_agreed = true;
    for ([_][]const u8{ "no-at-sign", "a\"b@x.test", "a@b@x.test", "a b@x.test", "a@x.test\n", "@x.test", "a@", "a\\b@x.test", "a@x.test,b@y.test" }) |bad| {
        cfg.contact_email = bad;
        try expectOpenFails(&env, cfg, error.InvalidContact);
    }
    try testing.expectEqual(@as(usize, 0), env.ca.countPosts());
}

test "ACME client: failed persistence after registration converges on the next open" {
    var env = try Env.init();
    defer env.deinit();
    const cfg = env.config();
    const t = env.transport();
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        var seeded = try state_mod.loadOrCreateAccountKey(&state, testing.allocator);
        seeded.key.deinit();
        state.fault = .rename; // fails the account.json write, not the key
        try testing.expectError(error.InjectedFault, Session.open(testing.allocator, t, &state, cfg, 1));
    }
    try testing.expectEqual(@as(usize, 1), env.ca.accounts.items.len);
    try testing.expect(!(try env.recordExists()));

    const session = try openSession(&env, cfg);
    defer session.close();
    // newAccount is idempotent per key: same account, no duplicate.
    try testing.expectEqual(@as(usize, 1), env.ca.accounts.items.len);
    try testing.expect(!session.created);
    try testing.expectEqualStrings("https://ca.test/acct/1", session.accountUrl());
    try testing.expect(try env.recordExists());
    try testing.expectEqual(client_mod.FailureClass.persistence, client_mod.classify(error.InjectedFault));
}

test "ACME client: a record for a different directory is fatal, never silently reused" {
    var env = try Env.init();
    defer env.deinit();
    {
        const first = try openSession(&env, env.config());
        first.close();
    }
    const requests_before = env.ca.log.items.len;
    var cfg = env.config();
    cfg.directory_url = "https://staging.ca.test/directory";
    try expectOpenFails(&env, cfg, error.DirectoryMismatch);
    try testing.expectEqual(requests_before, env.ca.log.items.len);
}

test "ACME client: corrupt or missing state is reported, never papered over" {
    var env = try Env.init();
    defer env.deinit();
    {
        const first = try openSession(&env, env.config());
        first.close();
    }
    var original_x: [32]u8 = undefined;
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        var k = try state_mod.loadOrCreateAccountKey(&state, testing.allocator);
        defer k.key.deinit();
        original_x = k.key.jwk().x;
        try state.writeFileAtomic(state_mod.account_record_name, "{\"version\":1", 0o600);
    }
    const before = env.ca.log.items.len;
    try expectOpenFails(&env, env.config(), error.CorruptState);
    try testing.expectEqual(before, env.ca.log.items.len);
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        var k = try state_mod.loadOrCreateAccountKey(&state, testing.allocator);
        defer k.key.deinit();
        try testing.expectEqualSlices(u8, &original_x, &k.key.jwk().x);
    }

    // Record whose kid points off-origin: tampering, not a reason to trust it.
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        const hash = state_mod.contactHash("");
        try state_mod.saveAccountRecord(&state, testing.allocator, .{ .directory = directory_url, .kid = "https://evil.test/acct/1", .key_thumbprint = &(account_mod.AccountKey.generate() catch unreachable).jwk().thumbprint(), .created_at = 1, .contact_hash = &hash });
    }
    try expectOpenFails(&env, env.config(), error.CorruptState);
}

test "ACME client: a missing key beside an existing account is inconsistent, not regenerated" {
    var env = try Env.init();
    defer env.deinit();
    {
        const first = try openSession(&env, env.config());
        first.close();
    }
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const joined = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ env.path, state_mod.account_key_name });
        zig_compat.unlinkPath(joined);
    }
    try expectOpenFails(&env, env.config(), error.InconsistentState);
}

test "ACME client: loosened key permissions refuse to start" {
    var env = try Env.init();
    defer env.deinit();
    {
        const first = try openSession(&env, env.config());
        first.close();
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const joined = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ env.path, state_mod.account_key_name });
    try zig_compat.chmodPath(joined, 0o644);
    try expectOpenFails(&env, env.config(), error.InsecurePermissions);
}

test "ACME client: untrusted URLs never reach the transport" {
    var env = try Env.init();
    defer env.deinit();
    const session = try openSession(&env, env.config());
    defer session.close();
    const before = env.ca.dialed.items.len;
    try testing.expectError(error.CrossHostUrl, session.client.signedPost("https://evil.test/x", null, .{ .kid = "https://ca.test/acct/1" }));
    try testing.expectError(error.NotHttps, session.client.signedPost("http://ca.test/x", null, .{ .kid = "https://ca.test/acct/1" }));
    try testing.expectError(error.CrossHostUrl, session.client.signedPost("https://ca.test:8443/x", null, .{ .kid = "https://ca.test/acct/1" }));
    try testing.expectEqual(before, env.ca.dialed.items.len);
    try testing.expectError(error.CrossHostUrl, session.client.setKid("https://evil.test/acct/1"));
}

test "ACME client: slow CA hits the request deadline as a transport failure" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.stall_ms_per_read = 20_000;
    try expectOpenFails(&env, env.config(), error.Timeout);
    try testing.expectEqual(client_mod.FailureClass.transport, client_mod.classify(error.Timeout));
}

test "ACME client: chunked responses delivered one byte at a time work end to end" {
    var env = try Env.init();
    defer env.deinit();
    env.ca.script.chunked = true;
    env.ca.script.read_chunk = 1;
    const session = try openSession(&env, env.config());
    defer session.close();
    try testing.expect(session.created);
    try testing.expect(env.ca.allPostsVerified());
}

test "ACME client: failure classes distinguish transport, protocol, persistence and resource" {
    const C = client_mod.FailureClass;
    for ([_]anyerror{ error.DialFailed, error.Timeout, error.ConnectionFailed, error.MalformedResponse, error.HeadersTooLarge, error.ResponseTooLarge, error.RedirectRejected }) |e| {
        try testing.expectEqual(C.transport, client_mod.classify(e));
    }
    for ([_]anyerror{ error.BadDirectory, error.NotJson, error.MissingNonce, error.CaRejected, error.RateLimited, error.CrossHostUrl, error.NotHttps, error.BadAccountResponse, error.UnexpectedStatus, error.TermsNotAgreed }) |e| {
        try testing.expectEqual(C.protocol, client_mod.classify(e));
    }
    for ([_]anyerror{ error.InsecurePermissions, error.CorruptState, error.Locked, error.InconsistentState, error.DirectoryMismatch, error.IoFailure, error.UnsafeFileType }) |e| {
        try testing.expectEqual(C.persistence, client_mod.classify(e));
    }
    try testing.expectEqual(C.resource, client_mod.classify(error.OutOfMemory));

    var env = try Env.init();
    defer env.deinit();
    env.ca.script.directory = .malformed_json;
    const t = env.transport();
    var key = try account_mod.AccountKey.generate();
    defer key.deinit();
    var client = try Client.init(testing.allocator, t, &key, env.config());
    defer client.deinit();
    try testing.expectError(error.BadDirectory, client.fetchDirectory());
    env.ca.script.refuse_dial = true;
    try testing.expectError(error.DialFailed, client.fetchDirectory());
    const diag = client.status();
    try testing.expectEqual(@as(u32, 1), diag.failureCount(.protocol));
    try testing.expectEqual(@as(u32, 1), diag.failureCount(.transport));
    try testing.expectEqual(@as(u32, 0), diag.failureCount(.persistence));
    try testing.expectEqual(@as(?C, .transport), diag.last_failure);
    try testing.expectEqualStrings("DialFailed", diag.last_error.?);
}

test "ACME client: concurrent signed requests are serialized and never reuse a nonce" {
    var env = try Env.init();
    defer env.deinit();
    const session = try openSession(&env, env.config());
    defer session.close();

    const Worker = struct {
        fn run(s: *Session, failures: *std.atomic.Value(u32)) void {
            for (0..6) |_| {
                var resp = s.client.signedPostAsGet("https://ca.test/acct/1") catch {
                    _ = failures.fetchAdd(1, .monotonic);
                    continue;
                };
                resp.deinit();
            }
        }
    };
    var failures = std.atomic.Value(u32).init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ session, &failures });
    for (threads) |t| t.join();

    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try testing.expect(!env.ca.nonce_reuse_detected);
    try testing.expect(env.ca.allPostsVerified());
    // 1 newAccount + 24 account fetches.
    try testing.expectEqual(@as(usize, 25), env.ca.countPosts());
}

test "ACME client: secrets and CA text never appear in state files or diagnostics" {
    var env = try Env.init();
    defer env.deinit();
    var cfg = env.config();
    cfg.contact_email = "ops@example.com";
    env.ca.script.account = .server_error_problem;
    try expectOpenFails(&env, cfg, error.CaRejected);
    env.ca.script.account = .normal;
    const session = try openSession(&env, cfg);
    defer session.close();

    var state = try StateDir.open(env.path);
    defer state.close();
    const record = try state.readFileAlloc(testing.allocator, state_mod.account_record_name, 4096, true);
    defer testing.allocator.free(record);
    try testing.expect(std.mem.indexOf(u8, record, "BEGIN") == null);
    try testing.expect(std.mem.indexOf(u8, record, "ops@example.com") == null);
    try testing.expect(std.mem.indexOf(u8, record, "secret-looking") == null);

    const pem = try state.readFileAlloc(testing.allocator, state_mod.account_key_name, 512, true);
    defer crypto.secrets.secureZeroAndFree(testing.allocator, pem);
    try testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN PRIVATE KEY-----"));

    // The only strings diagnostics can carry are static error names.
    const diag = session.client.status();
    try testing.expect(diag.last_error == null or std.mem.indexOf(u8, diag.last_error.?, "secret") == null);
    const fp = session.client.kidFingerprint().?;
    try testing.expectEqual(@as(usize, 8), fp.len);
}

fn fuzzCaDocuments(_: void, smith: *testing.Smith) !void {
    var dir_buf: [768]u8 = undefined;
    var acct_buf: [256]u8 = undefined;
    const dir_len = smith.slice(&dir_buf);
    const acct_len = smith.slice(&acct_buf);

    var env = try Env.init();
    defer env.deinit();
    env.ca.script.directory_body = dir_buf[0..dir_len];
    env.ca.script.account_body = acct_buf[0..acct_len];
    const t = env.transport();
    var key = try account_mod.AccountKey.generate();
    defer key.deinit();
    var client = try Client.init(testing.allocator, t, &key, env.config());
    defer client.deinit();
    client.fetchDirectory() catch return;
    // Whatever was admitted must be https, same-origin, and re-parseable.
    const dir = client.directory.?;
    for ([_][]const u8{ dir.new_nonce, dir.new_account, dir.new_order }) |u| {
        const parsed = try @import("url.zig").requireCaOrigin(u, client.directory_origin, false);
        try testing.expectEqualStrings("ca.test", parsed.host);
    }
}

test "fuzz: ACME: untrusted directory documents are admitted only as same-origin https URLs" {
    try testing.fuzz({}, fuzzCaDocuments, .{ .corpus = &.{
        "",
        "{}",
        "{\"newNonce\":\"https://ca.test/n\",\"newAccount\":\"https://ca.test/a\",\"newOrder\":\"https://ca.test/o\"}",
        "{\"newNonce\":\"https://ca.test/n\",\"newAccount\":\"https://evil.test/a\",\"newOrder\":\"https://ca.test/o\"}",
        "{\"newNonce\":\"http://ca.test/n\",\"newAccount\":\"https://ca.test/a\",\"newOrder\":\"https://ca.test/o\"}",
        "{\"newNonce\":\"https://ca.test/n\",\"newAccount\":\"https://ca.test/a\",\"newOrder\":\"https://ca.test/o\",\"revokeCert\":\"https://169.254.169.254/\"}",
        "{\"newNonce\":[[[[[[[[[[1]]]]]]]]]]}",
        "{\"newNonce\":\"https://ca.test/n\",\"newNonce\":\"https://ca.test/n\"}",
    } });
}

fn fuzzAccountResponse(_: void, smith: *testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);

    var env = try Env.init();
    defer env.deinit();
    env.ca.script.account_body = buf[0..len];
    const t = env.transport();
    var key = try account_mod.AccountKey.generate();
    defer key.deinit();
    var client = try Client.init(testing.allocator, t, &key, env.config());
    defer client.deinit();
    var resp = client.signedPost("https://ca.test/new-acct", "{\"termsOfServiceAgreed\":true}", .jwk) catch return;
    resp.deinit();
}

test "fuzz: ACME: arbitrary account response bodies never crash or leak" {
    try testing.fuzz({}, fuzzAccountResponse, .{ .corpus = &.{
        "",
        "{\"status\":\"valid\"}",
        "{\"status\":5}",
        "[]",
        "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}",
        &([_]u8{'{'} ** 40),
    } });
}

test "ACME client: a pre-provisioned account key is used and never created" {
    var env = try Env.init();
    defer env.deinit();
    var key = try account_mod.AccountKey.generate();
    defer key.deinit();
    const pem = try key.toPkcs8Pem(testing.allocator);
    defer crypto.secrets.secureZeroAndFree(testing.allocator, pem);
    const key_path = try std.fmt.allocPrint(testing.allocator, "{s}-provisioned.pem", .{env.path});
    defer testing.allocator.free(key_path);
    defer zig_compat.unlinkPath(key_path);
    {
        var state = try StateDir.open(env.path);
        defer state.close();
        // Written next to (not inside) the state dir, as an operator would.
        var parent = try std.Io.Dir.cwd().openDir(zig_compat.io(), std.fs.path.dirname(env.path).?, .{});
        defer parent.close(zig_compat.io());
        var file = try parent.createFile(zig_compat.io(), std.fs.path.basename(key_path), .{ .permissions = .fromMode(0o600) });
        defer file.close(zig_compat.io());
        try file.writePositionalAll(zig_compat.io(), pem, 0);
    }

    var cfg = env.config();
    cfg.account_key_path = key_path;
    const session = try openSession(&env, cfg);
    defer session.close();
    try testing.expectEqualSlices(u8, &key.jwk().x, &session.key.jwk().x);
    try testing.expect(env.ca.allPostsVerified());
    // The state directory did not mint its own key.
    var state = try StateDir.open(env.path);
    defer state.close();
    try testing.expectError(error.NotFound, state.readFileAlloc(testing.allocator, state_mod.account_key_name, 512, true));

    cfg.account_key_path = "/nonexistent/key.pem";
    try testing.expectError(error.NotFound, Session.open(testing.allocator, env.transport(), &state, cfg, 1));
}

test "ACME client: replacing the pre-provisioned key invalidates the stored account (#832)" {
    var env = try Env.init();
    defer env.deinit();
    const key_path = try std.fmt.allocPrint(testing.allocator, "{s}-provisioned.pem", .{env.path});
    defer testing.allocator.free(key_path);
    defer zig_compat.unlinkPath(key_path);

    const writeKey = struct {
        fn run(path: []const u8, key: *const account_mod.AccountKey) !void {
            const pem = try key.toPkcs8Pem(testing.allocator);
            defer crypto.secrets.secureZeroAndFree(testing.allocator, pem);
            var parent = try std.Io.Dir.cwd().openDir(zig_compat.io(), std.fs.path.dirname(path).?, .{});
            defer parent.close(zig_compat.io());
            var file = try parent.createFile(zig_compat.io(), std.fs.path.basename(path), .{ .permissions = .fromMode(0o600), .truncate = true });
            defer file.close(zig_compat.io());
            try file.writePositionalAll(zig_compat.io(), pem, 0);
        }
    }.run;

    var key_a = try account_mod.AccountKey.generate();
    defer key_a.deinit();
    var key_b = try account_mod.AccountKey.generate();
    defer key_b.deinit();
    {
        var state = try StateDir.open(env.path);
        state.close();
    }
    try writeKey(key_path, &key_a);
    var cfg = env.config();
    cfg.account_key_path = key_path;

    {
        const first = try openSession(&env, cfg);
        first.close();
    }
    // Same key: loads from the record with no network traffic.
    env.ca.script.refuse_dial = true;
    {
        const again = try openSession(&env, cfg);
        try testing.expect(!again.created);
        again.close();
    }
    // A different key behind the same path must not inherit account A.
    try writeKey(key_path, &key_b);
    const before = env.ca.log.items.len;
    try expectOpenFails(&env, cfg, error.InconsistentState);
    try testing.expectEqual(before, env.ca.log.items.len);
}
