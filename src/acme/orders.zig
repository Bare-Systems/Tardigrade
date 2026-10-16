//! Native ACME order/authorization/finalize/download engine (#882, A3 of
//! epic #759, design `docs/ACME_AUTOMATIC_HTTPS.md` §5).
//!
//! `obtain` drives one order group (RFC 8555 §7.1–7.4.2) end to end: newOrder
//! -> per-authorization HTTP-01 challenge ack/poll -> finalize(CSR) -> poll
//! order -> download, using A2's `client.Client` for every CA request (so
//! nonce handling, JWS framing, CA-URL origin pinning and bounded JSON
//! parsing are never duplicated here) and #878's `csr.issue` for the leaf
//! key and CSR. It returns an owned, **unactivated** `IssuedChain`; nothing
//! here verifies the chain against `pki.x509` (that is A4's `activate.zig`
//! §6.4) or publishes it to `sni_provider.ReloadableProvider` (A4/A5). It
//! also never touches the gateway's HTTP-01 listener (#881) or the TLS
//! provider.
//!
//! Every CA-controlled value — order/authorization status, identifiers,
//! challenge tokens and URLs, the certificate body — is treated as hostile:
//! URLs are re-validated by `client.signedPost*`'s own CA-origin pinning on
//! every use, JSON is parsed through `json_limits.parseBounded`, identifiers
//! are matched against the exact requested order group (never trusted from
//! the CA alone), and an unrecognized or terminal-failure status fails
//! closed rather than being retried forever. Deadlines (design §9.1: 300 s
//! per order, 120 s per authorization) and a hard poll-count ceiling bound
//! every loop; `Options.clock`/`waiter`/`cancel` make that fully
//! deterministic under test (`orders_tests.zig`) with no live CA contact.
//!
//! Challenge-store ownership: a token is published to the `ChallengeStore`
//! only immediately before the challenge-ready POST, and is removed on
//! every exit from that authorization's processing -- success, CA-reported
//! failure, timeout or cancellation -- via `errdefer` plus an explicit
//! remove on each terminal branch, so no path leaves a stale entry behind.

const std = @import("std");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const client_mod = @import("client.zig");
const csr_mod = @import("csr.zig");
const json_limits = @import("json_limits.zig");
const names_mod = @import("names.zig");
const challenge_store_mod = @import("../http/acme_challenge_store.zig");

pub const ChallengeStore = challenge_store_mod.ChallengeStore;

pub const Error = client_mod.Error || csr_mod.Error || challenge_store_mod.PutError || error{
    TooManyAuthorizations,
    DuplicateAuthorizationUrl,
    UnexpectedIdentifier,
    NoHttp01Challenge,
    AuthorizationInvalid,
    AuthorizationTimedOut,
    OrderInvalid,
    OrderTimedOut,
    BadOrderResponse,
    BadAuthorizationResponse,
    BadCertificateResponse,
    Cancelled,
};

/// Design §9.1 limits plus the engine's own bounded-polling parameters.
pub const Limits = struct {
    order_deadline_s: i64 = 300,
    authz_deadline_s: i64 = 120,
    poll_interval_min_s: u32 = 2,
    poll_interval_max_s: u32 = 10,
    retry_after_min_s: u32 = 1,
    retry_after_max_s: u32 = 30,
    max_certificate_bytes: usize = 128 * 1024,
    /// Defense in depth against a misconfigured clock/waiter in a caller:
    /// the deadline checks already bound every loop given a clock that
    /// actually advances, but a hard ceiling means a frozen clock fails
    /// closed instead of spinning forever.
    max_polls: u32 = 1000,
};

/// Monotonic millisecond clock; the same shape as `transport.Clock` so a
/// caller can hand the order engine the identical clock it gave the
/// transport, keeping request deadlines and order/authorization deadlines
/// on one time base in tests.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i64 = realNow,

    fn realNow(_: ?*anyopaque) i64 {
        return @intCast(@divTrunc(zig_compat.monotonicNanoTimestamp(), std.time.ns_per_ms));
    }

    pub fn now(self: Clock) i64 {
        return self.nowFn(self.ctx);
    }
};

/// Unix-seconds wall clock for `ChallengeStore` admission (`now`/`expires_at`
/// are Unix seconds, never the monotonic `Clock` above).
pub const UnixClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i64 = realNow,

    fn realNow(_: ?*anyopaque) i64 {
        return zig_compat.unixTimestamp();
    }

    pub fn now(self: UnixClock) i64 {
        return self.nowFn(self.ctx);
    }
};

/// Injectable backoff/poll-interval wait. Production uses a real sleep;
/// tests substitute one that advances a fake clock instead of blocking, so
/// polling/backoff/timeout behavior is deterministic (design: "fake clock or
/// injected waits").
pub const Waiter = struct {
    ctx: ?*anyopaque = null,
    sleepFn: *const fn (ctx: ?*anyopaque, ms: u32) void = defaultSleep,

    fn defaultSleep(_: ?*anyopaque, ms: u32) void {
        zig_compat.sleepNs(@as(u64, ms) * std.time.ns_per_ms);
    }

    pub fn wait(self: Waiter, ms: u32) void {
        self.sleepFn(self.ctx, ms);
    }
};

/// Cooperative cancellation, checked between every network call and every
/// poll wait (design §5.5): "the worker waits on an interruptible
/// condition, not an uninterruptible sleep."
pub const Cancel = struct {
    ctx: ?*anyopaque = null,
    checkFn: *const fn (ctx: ?*anyopaque) bool = alwaysFalse,

    fn alwaysFalse(_: ?*anyopaque) bool {
        return false;
    }

    pub fn isCancelled(self: Cancel) bool {
        return self.checkFn(self.ctx);
    }
};

pub const Options = struct {
    limits: Limits = .{},
    clock: Clock = .{},
    unix_clock: UnixClock = .{},
    waiter: Waiter = .{},
    cancel: Cancel = .{},
};

/// Owned result: a fresh, distinct leaf key and the issued chain, never
/// activated or published. Caller (A4) must call `deinit` exactly once.
pub const IssuedChain = struct {
    key: csr_mod.LeafKey,
    /// Leaf-first PEM chain exactly as downloaded; not yet parsed or
    /// verified (that is `activate.verifyChain`, §6.4).
    chain_pem: []u8,

    pub fn deinit(self: *IssuedChain, allocator: std.mem.Allocator) void {
        self.key.deinit();
        allocator.free(self.chain_pem);
    }
};

const key_authorization_buf_len = challenge_store_mod.max_token_len + 1 + account_mod.thumbprint_len;

/// Obtain a certificate for `order_group` (one order, one SAN list) via
/// `client`, publishing HTTP-01 key authorizations into `store` as each
/// authorization is processed. Fails closed and leaves `store` with no
/// residual entries for this call on every exit path.
pub fn obtain(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    store: *ChallengeStore,
    order_group: []const []const u8,
    options: Options,
) Error!IssuedChain {
    try csr_mod.validateGroup(order_group);

    const order_deadline_ms = options.clock.now() + options.limits.order_deadline_s * 1000;

    var order = try newOrder(allocator, client, order_group);
    defer order.deinit(allocator);

    if (order.authorizations.len > order_group.len) return error.TooManyAuthorizations;
    for (order.authorizations, 0..) |url, i| {
        for (order.authorizations[0..i]) |earlier| {
            if (std.mem.eql(u8, earlier, url)) return error.DuplicateAuthorizationUrl;
        }
    }

    for (order.authorizations) |authz_url| {
        if (options.cancel.isCancelled()) return error.Cancelled;
        if (options.clock.now() >= order_deadline_ms) return error.OrderTimedOut;
        try authorizeOne(allocator, client, store, order_group, authz_url, options, order_deadline_ms);
    }

    if (options.clock.now() >= order_deadline_ms) return error.OrderTimedOut;
    var issued_csr = try csr_mod.issue(allocator, order_group);
    errdefer issued_csr.key.deinit();
    defer allocator.free(issued_csr.csr_der);

    const certificate_url = try finalizeAndPoll(allocator, client, &order, issued_csr.csr_der, options, order_deadline_ms);
    defer allocator.free(certificate_url);

    const chain_pem = try downloadCertificate(allocator, client, certificate_url, options);

    return .{ .key = issued_csr.key, .chain_pem = chain_pem };
}

// ---------------------------------------------------------------------------
// newOrder (RFC 8555 §7.4)
// ---------------------------------------------------------------------------

const IdentifierJson = struct {
    type: []const u8,
    value: []const u8,
};

const NewOrderResponseJson = struct {
    status: []const u8,
    identifiers: []const IdentifierJson,
    authorizations: []const []const u8,
    finalize: []const u8,
};

const Order = struct {
    /// The order resource's own URL (`Location`), polled again after
    /// finalize (RFC 8555 §7.4).
    order_url: []u8,
    finalize_url: []u8,
    authorizations: [][]u8,

    fn deinit(self: *Order, allocator: std.mem.Allocator) void {
        allocator.free(self.order_url);
        allocator.free(self.finalize_url);
        for (self.authorizations) |url| allocator.free(url);
        allocator.free(self.authorizations);
    }
};

fn identifiersMatchGroup(identifiers: []const IdentifierJson, order_group: []const []const u8) bool {
    if (identifiers.len != order_group.len or identifiers.len > names_mod.max_names_per_group) return false;
    var matched = [_]bool{false} ** names_mod.max_names_per_group;
    for (identifiers) |id| {
        if (!std.mem.eql(u8, id.type, "dns")) return false;
        var found: ?usize = null;
        for (order_group, 0..) |name, i| {
            if (matched[i]) continue;
            if (std.mem.eql(u8, id.value, name)) {
                found = i;
                break;
            }
        }
        const index = found orelse return false;
        matched[index] = true;
    }
    return true;
}

fn newOrder(allocator: std.mem.Allocator, client: *client_mod.Client, order_group: []const []const u8) Error!Order {
    const new_order_url = try client.newOrderUrl();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, "{\"identifiers\":[");
    for (order_group, 0..) |name, i| {
        if (i > 0) try payload.append(allocator, ',');
        // `name` is already validated DNS-label charset (alnum/hyphen/dot
        // only) by `csr_mod.validateGroup` above, so no JSON escaping is
        // needed to embed it as a bare string value.
        try payload.print(allocator, "{{\"type\":\"dns\",\"value\":\"{s}\"}}", .{name});
    }
    try payload.appendSlice(allocator, "]}");

    const kid = client.kid orelse return error.BadAccountResponse;
    var resp = try client.signedPost(new_order_url, payload.items, .{ .kid = kid });
    defer resp.deinit();
    if (resp.status != 201) return error.BadOrderResponse;
    const location = resp.location() orelse return error.BadOrderResponse;
    if (!resp.content_type_json) return error.BadOrderResponse;

    var parsed = json_limits.parseBounded(NewOrderResponseJson, allocator, resp.body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadOrderResponse,
    };
    defer parsed.deinit();
    const v = parsed.value;
    if (std.mem.eql(u8, v.status, "invalid")) return error.OrderInvalid;
    if (!identifiersMatchGroup(v.identifiers, order_group)) return error.UnexpectedIdentifier;
    if (v.authorizations.len == 0 or v.authorizations.len > order_group.len) return error.TooManyAuthorizations;

    const order_url = try allocator.dupe(u8, location);
    errdefer allocator.free(order_url);
    const finalize_url = try allocator.dupe(u8, v.finalize);
    errdefer allocator.free(finalize_url);

    const authorizations = try allocator.alloc([]u8, v.authorizations.len);
    var filled: usize = 0;
    errdefer {
        for (authorizations[0..filled]) |url| allocator.free(url);
        allocator.free(authorizations);
    }
    for (v.authorizations, 0..) |url, i| {
        authorizations[i] = try allocator.dupe(u8, url);
        filled += 1;
    }

    return .{ .order_url = order_url, .finalize_url = finalize_url, .authorizations = authorizations };
}

// ---------------------------------------------------------------------------
// Authorization / HTTP-01 challenge (RFC 8555 §7.5)
// ---------------------------------------------------------------------------

const ChallengeJson = struct {
    type: []const u8,
    url: []const u8,
    token: []const u8,
};

const AuthorizationJson = struct {
    status: []const u8,
    identifier: IdentifierJson,
    challenges: []const ChallengeJson,
};

const Terminal = enum { pending, valid, invalid };

const Http01Challenge = struct {
    url: []const u8,
    token: []const u8,
};

const FetchedAuthz = struct {
    parsed: std.json.Parsed(AuthorizationJson),
    terminal: Terminal,
    http01: ?Http01Challenge,
    identifier_value: []const u8,

    fn deinit(self: *FetchedAuthz) void {
        self.parsed.deinit();
    }
};

fn fetchAuthorization(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    url: []const u8,
    order_group: []const []const u8,
) Error!FetchedAuthz {
    var resp = try client.signedPostAsGet(url);
    defer resp.deinit();
    if (!resp.content_type_json) return error.BadAuthorizationResponse;

    var parsed = json_limits.parseBounded(AuthorizationJson, allocator, resp.body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadAuthorizationResponse,
    };
    errdefer parsed.deinit();
    const v = parsed.value;
    if (!std.mem.eql(u8, v.identifier.type, "dns")) return error.BadAuthorizationResponse;
    if (!identifierInGroup(order_group, v.identifier.value)) return error.UnexpectedIdentifier;

    const terminal: Terminal = if (std.mem.eql(u8, v.status, "valid"))
        .valid
    else if (std.mem.eql(u8, v.status, "pending") or std.mem.eql(u8, v.status, "processing"))
        .pending
    else
        // `deactivated`/`expired`/`revoked`/anything unrecognized: fail
        // closed rather than poll forever on a status that will never
        // become `valid`.
        .invalid;

    var http01: ?Http01Challenge = null;
    for (v.challenges) |c| {
        if (std.mem.eql(u8, c.type, "http-01")) {
            http01 = .{ .url = c.url, .token = c.token };
            break;
        }
    }

    return .{ .parsed = parsed, .terminal = terminal, .http01 = http01, .identifier_value = v.identifier.value };
}

fn identifierInGroup(order_group: []const []const u8, value: []const u8) bool {
    for (order_group) |name| {
        if (std.mem.eql(u8, name, value)) return true;
    }
    return false;
}

fn buildKeyAuthorization(client: *client_mod.Client, token: []const u8, out: *[key_authorization_buf_len]u8) Error![]const u8 {
    const thumbprint = client.key.jwk().thumbprint();
    return std.fmt.bufPrint(out, "{s}.{s}", .{ token, thumbprint }) catch error.BadAuthorizationResponse;
}

fn authorizeOne(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    store: *ChallengeStore,
    order_group: []const []const u8,
    authz_url: []const u8,
    options: Options,
    order_deadline_ms: i64,
) Error!void {
    const authz_deadline_ms = @min(order_deadline_ms, options.clock.now() + options.limits.authz_deadline_s * 1000);

    // `first`'s backing JSON (and therefore `host`/`token`/`challenge_url`,
    // which point into it) stays valid for the whole function: `deinit` only
    // runs when this function returns, via the `defer` below.
    var first = try fetchAuthorization(allocator, client, authz_url, order_group);
    defer first.deinit();
    switch (first.terminal) {
        .valid => return,
        .invalid => return error.AuthorizationInvalid,
        .pending => {},
    }
    const challenge = first.http01 orelse return error.NoHttp01Challenge;
    const host = first.identifier_value;
    const token = challenge.token;
    const challenge_url = challenge.url;

    var key_auth_buf: [key_authorization_buf_len]u8 = undefined;
    const key_authorization = try buildKeyAuthorization(client, token, &key_auth_buf);

    const now_unix = options.unix_clock.now();
    const expires_at = std.math.add(i64, now_unix, options.limits.authz_deadline_s) catch std.math.maxInt(i64);
    try store.put(now_unix, host, token, key_authorization, expires_at);
    errdefer _ = store.remove(host, token);

    {
        const kid = client.kid orelse return error.BadAccountResponse;
        var trigger = try client.signedPost(challenge_url, "{}", .{ .kid = kid });
        trigger.deinit();
    }

    var poll_attempt: u32 = 0;
    while (true) {
        if (options.cancel.isCancelled()) return error.Cancelled;
        const now_ms = options.clock.now();
        if (now_ms >= authz_deadline_ms or now_ms >= order_deadline_ms) return error.AuthorizationTimedOut;
        if (poll_attempt >= options.limits.max_polls) return error.AuthorizationTimedOut;

        var polled = fetchAuthorization(allocator, client, authz_url, order_group) catch |err| {
            if (err == error.RateLimited) {
                waitForRetry(client, options);
                poll_attempt +|= 1;
                continue;
            }
            return err;
        };
        defer polled.deinit();

        switch (polled.terminal) {
            .valid => {
                _ = store.remove(host, token);
                return;
            },
            .invalid => {
                _ = store.remove(host, token);
                return error.AuthorizationInvalid;
            },
            .pending => {
                const wait_ms = retryAfterOrPollInterval(client, poll_attempt, options.limits);
                options.waiter.wait(wait_ms);
                poll_attempt +|= 1;
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Finalize / download (RFC 8555 §7.4.2)
// ---------------------------------------------------------------------------

const OrderStatusJson = struct {
    status: []const u8,
    certificate: ?[]const u8 = null,
};

fn finalizeAndPoll(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    order: *const Order,
    csr_der: []const u8,
    options: Options,
    order_deadline_ms: i64,
) Error![]u8 {
    const b64url = std.base64.url_safe_no_pad;
    const csr_b64 = try allocator.alloc(u8, b64url.Encoder.calcSize(csr_der.len));
    defer allocator.free(csr_b64);
    _ = b64url.Encoder.encode(csr_b64, csr_der);
    const payload = try std.fmt.allocPrint(allocator, "{{\"csr\":\"{s}\"}}", .{csr_b64});
    defer allocator.free(payload);

    {
        const kid = client.kid orelse return error.BadAccountResponse;
        var resp = try client.signedPost(order.finalize_url, payload, .{ .kid = kid });
        resp.deinit();
    }

    var poll_attempt: u32 = 0;
    while (true) {
        if (options.cancel.isCancelled()) return error.Cancelled;
        if (options.clock.now() >= order_deadline_ms) return error.OrderTimedOut;
        if (poll_attempt >= options.limits.max_polls) return error.OrderTimedOut;

        var resp = client.signedPostAsGet(order.order_url) catch |err| {
            if (err == error.RateLimited) {
                waitForRetry(client, options);
                poll_attempt +|= 1;
                continue;
            }
            return err;
        };
        defer resp.deinit();
        if (!resp.content_type_json) return error.BadOrderResponse;

        var parsed = json_limits.parseBounded(OrderStatusJson, allocator, resp.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadOrderResponse,
        };
        defer parsed.deinit();
        const v = parsed.value;

        if (std.mem.eql(u8, v.status, "valid")) {
            const certificate_url = v.certificate orelse return error.BadOrderResponse;
            return allocator.dupe(u8, certificate_url);
        }
        if (std.mem.eql(u8, v.status, "pending") or std.mem.eql(u8, v.status, "ready") or std.mem.eql(u8, v.status, "processing")) {
            const wait_ms = retryAfterOrPollInterval(client, poll_attempt, options.limits);
            options.waiter.wait(wait_ms);
            poll_attempt +|= 1;
            continue;
        }
        // `invalid` or any unrecognized status: fail closed.
        return error.OrderInvalid;
    }
}

fn downloadCertificate(allocator: std.mem.Allocator, client: *client_mod.Client, certificate_url: []const u8, options: Options) Error![]u8 {
    var resp = try client.signedPostAsGetMaxBody(certificate_url, options.limits.max_certificate_bytes);
    defer resp.deinit();
    if (!std.mem.startsWith(u8, resp.body, "-----BEGIN CERTIFICATE-----")) return error.BadCertificateResponse;
    return allocator.dupe(u8, resp.body);
}

// ---------------------------------------------------------------------------
// Backoff helpers (design §5.4)
// ---------------------------------------------------------------------------

fn clampRetryAfter(seconds: u32, limits: Limits) u32 {
    return std.math.clamp(seconds, limits.retry_after_min_s, limits.retry_after_max_s);
}

/// `Retry-After` from the most recent response if present (clamped),
/// otherwise a doubling poll interval capped at `poll_interval_max_s`
/// (design §5.4: "`Retry-After` if present ... else 2s -> 10s").
fn retryAfterOrPollInterval(client: *client_mod.Client, attempt: u32, limits: Limits) u32 {
    if (client.diagnostics.last_retry_after_s) |s| return clampRetryAfter(s, limits) * 1000;
    const shift: u5 = @intCast(@min(attempt, 8));
    const scaled = limits.poll_interval_min_s *| (@as(u32, 1) << shift);
    return @min(scaled, limits.poll_interval_max_s) * 1000;
}

fn waitForRetry(client: *client_mod.Client, options: Options) void {
    const seconds = clampRetryAfter(client.diagnostics.last_retry_after_s orelse options.limits.retry_after_max_s, options.limits);
    options.waiter.wait(seconds * 1000);
}

// ---------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
