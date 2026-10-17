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
const pki = @import("pki");
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
    /// Independent finite ceiling on `order.authorizations.len` (RFC 8555
    /// §7.1.3: a CA's authorization count need not match the requested
    /// identifier count -- fewer when identities are preauthorized, more
    /// when a CA hands back distinct authorizations for the same name).
    /// This bounds worst-case work per order without assuming any
    /// particular CA authorization policy (#898).
    max_authz_urls: u32 = 64,
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

/// Injectable backoff/poll-interval wait. A production wait can be up to
/// `retry_after_max_s` (30s); design §5.5 requires that wait be interruptible
/// rather than an uninterruptible sleep, so the default implementation sleeps
/// in small slices and checks `cancel` between each one, returning as soon as
/// cancellation fires instead of blocking for the full duration. Tests
/// substitute a waiter that advances a fake clock instead of sleeping at all,
/// so polling/backoff/timeout behavior stays deterministic (design: "fake
/// clock or injected waits").
pub const Waiter = struct {
    ctx: ?*anyopaque = null,
    waitFn: *const fn (ctx: ?*anyopaque, ms: u32, cancel: Cancel) bool = defaultWait,

    const slice_ms: u32 = 200;

    fn defaultWait(_: ?*anyopaque, ms: u32, cancel: Cancel) bool {
        var remaining = ms;
        while (remaining > 0) {
            if (cancel.isCancelled()) return true;
            const this_slice = @min(remaining, slice_ms);
            zig_compat.sleepNs(@as(u64, this_slice) * std.time.ns_per_ms);
            remaining -= this_slice;
        }
        return cancel.isCancelled();
    }

    /// Returns `true` if `cancel` fired during (or before) the wait.
    pub fn wait(self: Waiter, ms: u32, cancel: Cancel) bool {
        return self.waitFn(self.ctx, ms, cancel);
    }
};

pub const Options = struct {
    limits: Limits = .{},
    clock: Clock = .{},
    unix_clock: UnixClock = .{},
    waiter: Waiter = .{},
    cancel: Cancel = .{},
};

test "ACME orders: the production Waiter returns promptly when cancelled mid-wait" {
    var flag = std.atomic.Value(bool).init(false);
    const cancel: Cancel = .{ .ctx = &flag, .checkFn = struct {
        fn check(ctx: ?*anyopaque) bool {
            const f: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
            return f.load(.acquire);
        }
    }.check };

    const Setter = struct {
        fn run(f: *std.atomic.Value(bool)) void {
            zig_compat.sleepNs(50 * std.time.ns_per_ms);
            f.store(true, .release);
        }
    };
    const setter = try std.Thread.spawn(.{}, Setter.run, .{&flag});
    defer setter.join();

    const start_ns = zig_compat.monotonicNanoTimestamp();
    // A real production wait with the same 30s ceiling `retryAfterWaitMs`
    // allows for a `Retry-After: 30` response; cancellation a few slices in
    // must return almost immediately rather than blocking for the full 30s.
    const cancelled = (Waiter{}).wait(30_000, cancel);
    const elapsed_ms = @divTrunc(zig_compat.monotonicNanoTimestamp() - start_ns, std.time.ns_per_ms);

    try std.testing.expect(cancelled);
    try std.testing.expect(elapsed_ms < 2_000);
}

/// Owned result: a fresh, distinct leaf key and the issued chain, never
/// activated or published. Caller (A4) must call `deinit` exactly once.
pub const IssuedChain = struct {
    key: csr_mod.LeafKey,
    /// Leaf-first PEM chain exactly as downloaded; not yet parsed or
    /// verified (that is `activate.verifyChain`, §6.4).
    chain_pem: []u8,
    /// Owned copy of the exact requested order-group identity (RFC 8555
    /// SAN set) this key/chain was issued for. A4's `activate.verifyChain`
    /// needs the precise group this call processed; copying it here means
    /// the caller's `order_group` slice can be mutated or freed after
    /// `obtain` returns without any ad hoc correlation channel back to it.
    hostnames: [][]u8,

    pub fn deinit(self: *IssuedChain, allocator: std.mem.Allocator) void {
        self.key.deinit();
        allocator.free(self.chain_pem);
        for (self.hostnames) |h| allocator.free(h);
        allocator.free(self.hostnames);
    }
};

fn dupeGroup(allocator: std.mem.Allocator, order_group: []const []const u8) Error![][]u8 {
    const out = try allocator.alloc([]u8, order_group.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |h| allocator.free(h);
        allocator.free(out);
    }
    for (order_group, 0..) |name, i| {
        out[i] = try allocator.dupe(u8, name);
        filled += 1;
    }
    return out;
}

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
    try checkLive(options, order_deadline_ms);

    var order = try newOrder(allocator, client, order_group, options, order_deadline_ms);
    defer order.deinit(allocator);
    // The CA's own order `expires` (RFC 8555 §7.1.3), when given, bounds
    // every request/wait for this order from here on, the same way an
    // authorization's own `expires` bounds `authorizeOne` (design §8.2,
    // #898): the local 300s default must never outlive a CA-promised
    // shorter lifetime.
    const effective_order_deadline_ms = order.effective_deadline_ms;

    // RFC 8555 §7.1.3: the number of authorizations a CA returns need not
    // match the number of requested identifiers -- fewer when an identity
    // is already preauthorized, more when the CA hands back distinct
    // authorizations for the same name. Only an independent, finite
    // ceiling and URL deduplication are enforced here; the actual security
    // boundary is each URL's identifier staying inside the requested group
    // (checked per-fetch below) and A4's exact SAN verification of the
    // issued certificate.
    if (order.authorizations.len > options.limits.max_authz_urls) return error.TooManyAuthorizations;
    for (order.authorizations, 0..) |url, i| {
        for (order.authorizations[0..i]) |earlier| {
            if (std.mem.eql(u8, earlier, url)) return error.DuplicateAuthorizationUrl;
        }
    }

    for (order.authorizations) |authz_url| {
        try checkLive(options, effective_order_deadline_ms);
        try authorizeOne(allocator, client, store, order_group, authz_url, options, effective_order_deadline_ms);
    }

    try checkLive(options, effective_order_deadline_ms);
    var issued_csr = try csr_mod.issue(allocator, order_group);
    errdefer issued_csr.key.deinit();
    defer allocator.free(issued_csr.csr_der);

    const certificate_url = try finalizeAndPoll(allocator, client, &order, order_group, issued_csr.csr_der, options, effective_order_deadline_ms);
    defer allocator.free(certificate_url);

    const chain_pem = try downloadCertificate(allocator, client, certificate_url, options, effective_order_deadline_ms);
    errdefer allocator.free(chain_pem);
    try checkLive(options, effective_order_deadline_ms);

    const hostnames = try dupeGroup(allocator, order_group);

    return .{ .key = issued_csr.key, .chain_pem = chain_pem, .hostnames = hostnames };
}

/// Fails closed on cancellation or an expired order deadline. Called before
/// every CA-affecting step (design §9.1/§5.5) -- not just between polls --
/// so an attempt that is already cancelled or out of budget never issues a
/// fresh request (new-order, finalize, download) and never returns a
/// key/certificate once the deadline has passed, even if the triggering CA
/// response itself was fast.
fn checkLive(options: Options, order_deadline_ms: i64) Error!void {
    if (options.cancel.isCancelled()) return error.Cancelled;
    if (options.clock.now() >= order_deadline_ms) return error.OrderTimedOut;
}

/// Remaining budget until `order_deadline_ms`, clamped into `u32` for the
/// transport's per-request deadline cap. `checkLive` must already have
/// passed, so the remainder here is always positive.
fn remainingOrderMs(options: Options, order_deadline_ms: i64) u32 {
    const remaining = order_deadline_ms - options.clock.now();
    return @intCast(@min(@max(remaining, 1), @as(i64, std.math.maxInt(u32))));
}

/// Clamp a poll/backoff wait to whatever remains of `deadline_ms`, and fail
/// closed with `timeout_err` the instant that deadline is reached -- before
/// waiting at all, or immediately after -- rather than handing the full
/// CA-requested `Retry-After`/backoff duration to `options.waiter.wait`.
/// Without this, a 30s `Retry-After` (or an 8s transient backoff) can
/// overrun an order/authorization/CA-expiry deadline that has only a second
/// or two left, in violation of #882's finite deadline contract (#898).
fn waitWithinDeadline(options: Options, requested_ms: u32, deadline_ms: i64, timeout_err: Error) Error!void {
    const remaining = deadline_ms - options.clock.now();
    if (remaining <= 0) return timeout_err;
    const capped: u32 = @intCast(@min(@as(i64, requested_ms), remaining));
    if (options.waiter.wait(capped, options.cancel)) return error.Cancelled;
    if (options.clock.now() >= deadline_ms) return timeout_err;
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
    /// RFC 8555 §7.1.3 requires this on a pending or ready order object.
    expires: []const u8,
};

const Order = struct {
    /// The order resource's own URL (`Location`), polled again after
    /// finalize (RFC 8555 §7.4).
    order_url: []u8,
    finalize_url: []u8,
    authorizations: [][]u8,
    /// The earlier of the local 300s default and the CA's own order
    /// `expires` (RFC 8555 §7.1.3), computed once from the initial
    /// `newOrder` response; every later request/wait for this order must
    /// respect it (#898).
    effective_deadline_ms: i64,

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

fn newOrder(allocator: std.mem.Allocator, client: *client_mod.Client, order_group: []const []const u8, options: Options, order_deadline_ms: i64) Error!Order {
    // A cold directory fetch is itself capped by the remaining order budget
    // (#898); recheck liveness immediately after, since that GET can consume
    // an arbitrary slice of it before the signed `newOrder` POST below ever
    // runs.
    const new_order_url = try client.newOrderUrl(remainingOrderMs(options, order_deadline_ms));
    try checkLive(options, order_deadline_ms);

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
    var resp = try client.signedPostOptions(new_order_url, payload.items, .{ .kid = kid }, client.transport.limits.max_body_bytes, .json, remainingOrderMs(options, order_deadline_ms));
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
    // Only `pending` (the ordinary case) and `ready` (every requested
    // identifier already has a valid authorization from an earlier order)
    // are sane statuses for a response this engine has never finalized yet;
    // anything else -- `valid`, `deactivated`, `expired`, an unrecognized
    // string -- fails closed rather than walking into challenge issuance on
    // a status the CA could not legitimately have produced here.
    if (!std.mem.eql(u8, v.status, "pending") and !std.mem.eql(u8, v.status, "ready")) return error.BadOrderResponse;
    if (!identifiersMatchGroup(v.identifiers, order_group)) return error.UnexpectedIdentifier;
    if (v.authorizations.len > options.limits.max_authz_urls) return error.TooManyAuthorizations;

    const now_unix = options.unix_clock.now();
    const parsed_expiry = parseRfc3339ToUnix(v.expires) orelse return error.BadOrderResponse;
    if (parsed_expiry <= now_unix) return error.OrderTimedOut;
    const ca_remaining_s = parsed_expiry - now_unix;
    const ca_remaining_ms = std.math.mul(i64, ca_remaining_s, 1000) catch std.math.maxInt(i64);
    const ca_deadline_ms = std.math.add(i64, options.clock.now(), ca_remaining_ms) catch std.math.maxInt(i64);
    const effective_deadline_ms = @min(order_deadline_ms, ca_deadline_ms);

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

    return .{ .order_url = order_url, .finalize_url = finalize_url, .authorizations = authorizations, .effective_deadline_ms = effective_deadline_ms };
}

// ---------------------------------------------------------------------------
// Authorization / HTTP-01 challenge (RFC 8555 §7.5)
// ---------------------------------------------------------------------------

const ChallengeJson = struct {
    type: []const u8,
    url: []const u8,
    token: []const u8,
};

/// RFC 8555 §7.5.1 requires the response to a challenge acknowledgement to
/// be the updated challenge object. Keep every identity-binding field
/// mandatory so malformed acknowledgements fail closed.
const ChallengeAckJson = struct {
    type: []const u8,
    url: []const u8,
    token: []const u8,
    status: []const u8,
};

const AuthorizationJson = struct {
    status: []const u8,
    identifier: IdentifierJson,
    challenges: []const ChallengeJson,
    /// RFC 8555 §7.1.4: when present, the CA's own authorization lifetime.
    /// The published key authorization must never outlive it (design §8.2).
    expires: ?[]const u8 = null,
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
    expires: ?[]const u8,

    fn deinit(self: *FetchedAuthz) void {
        self.parsed.deinit();
    }
};

fn fetchAuthorization(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    url: []const u8,
    order_group: []const []const u8,
    cap_ms: u32,
) Error!FetchedAuthz {
    var resp = try client.signedPostAsGetOptions(url, client.transport.limits.max_body_bytes, .json, cap_ms);
    defer resp.deinit();
    if (!resp.content_type_json) return error.BadAuthorizationResponse;

    var parsed = json_limits.parseBounded(AuthorizationJson, allocator, resp.body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadAuthorizationResponse,
    };
    errdefer parsed.deinit();
    const v = parsed.value;
    if (!std.mem.eql(u8, v.identifier.type, "dns")) return error.BadAuthorizationResponse;
    if (identifierIndexInGroup(order_group, v.identifier.value) == null) return error.UnexpectedIdentifier;

    const terminal: Terminal = if (std.mem.eql(u8, v.status, "valid"))
        .valid
    else if (std.mem.eql(u8, v.status, "pending") or std.mem.eql(u8, v.status, "processing"))
        .pending
    else
        // `deactivated`/`expired`/`revoked`/anything unrecognized: fail
        // closed rather than poll forever on a status that will never
        // become `valid`.
        .invalid;

    // Exactly one http-01 entry is accepted: a second one would leave it
    // ambiguous which challenge is actually bound to this authorization, and
    // #882 requires this duplicate shape to fail closed rather than silently
    // picking the first.
    var http01: ?Http01Challenge = null;
    for (v.challenges) |c| {
        if (std.mem.eql(u8, c.type, "http-01")) {
            if (http01 != null) return error.BadAuthorizationResponse;
            http01 = .{ .url = c.url, .token = c.token };
        }
    }

    return .{ .parsed = parsed, .terminal = terminal, .http01 = http01, .identifier_value = v.identifier.value, .expires = v.expires };
}

/// Up to `max_transient_retries` retries for a single transient CA failure
/// on an idempotent POST-as-GET read (design §5.2/§5.4): a dial/timeout/
/// connection failure, or any 5xx, retries the same read with bounded
/// backoff. Never applied to `newOrder`, the challenge-ready trigger or
/// `finalize`: those are not idempotent, and a blind retry after an
/// ambiguous network failure risks a second CA-side effect.
const max_transient_retries: u32 = 3;

fn isTransientFailure(client: *client_mod.Client, err: anyerror) bool {
    return switch (err) {
        error.Timeout, error.DialFailed, error.ConnectionFailed => true,
        error.CaRejected => client.diagnostics.last_http_status >= 500,
        else => false,
    };
}

/// 2s, 4s, 8s (design §5.4: "bounded exponential backoff, 2s -> 8s").
fn transientBackoffMs(attempt: u32) u32 {
    const shift: u5 = @intCast(@min(attempt, 2));
    return @as(u32, 2000) << shift;
}

/// Wraps the very first authorization fetch (before any challenge is
/// published) with the same bounded transient retry the poll loop below
/// uses, so a single dropped connection or 5xx on that fetch does not abort
/// the whole attempt.
fn fetchAuthorizationRetrying(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    url: []const u8,
    order_group: []const []const u8,
    options: Options,
    order_deadline_ms: i64,
    authz_deadline_ms: i64,
) Error!FetchedAuthz {
    var transient_attempt: u32 = 0;
    var rate_limit_attempt: u32 = 0;
    const deadline_ms = @min(order_deadline_ms, authz_deadline_ms);
    while (true) {
        if (options.cancel.isCancelled()) return error.Cancelled;
        if (options.clock.now() >= deadline_ms) return error.AuthorizationTimedOut;
        if (rate_limit_attempt >= options.limits.max_polls) return error.AuthorizationTimedOut;
        const cap = remainingOrderMs(options, deadline_ms);
        return fetchAuthorization(allocator, client, url, order_group, cap) catch |err| {
            // This POST-as-GET is idempotent, just like later authz polls.
            // A CA may rate-limit it before the challenge is published.
            if (err == error.RateLimited) {
                rate_limit_attempt +|= 1;
                try waitWithinDeadline(options, retryAfterWaitMs(client, options), deadline_ms, error.AuthorizationTimedOut);
                continue;
            }
            if (!isTransientFailure(client, err) or transient_attempt >= max_transient_retries) return err;
            transient_attempt += 1;
            try waitWithinDeadline(options, transientBackoffMs(transient_attempt - 1), deadline_ms, error.AuthorizationTimedOut);
            continue;
        };
    }
}

fn parseTwoDigits(s: []const u8) ?u8 {
    if (s[0] < '0' or s[0] > '9' or s[1] < '0' or s[1] > '9') return null;
    return (s[0] - '0') * 10 + (s[1] - '0');
}

/// Bounded RFC 3339 timestamp parser for the CA-supplied authorization
/// `expires` field (RFC 8555 §7.1.4). Accepts
/// `YYYY-MM-DDTHH:MM:SS[.fff...](Z|+HH:MM|-HH:MM)` -- RFC 3339 §5.6's full
/// set of timezone designators, not just `Z`: RFC 8555 only requires RFC
/// 3339, and a CA is free to emit a numeric offset instead. Rejects anything
/// else (trailing garbage, an out-of-range offset, an absurdly long value)
/// rather than guessing at it. Reformats the local date/time into ASN.1
/// GeneralizedTime so the actual calendar validation (leap years, days per
/// month) is `pki.time.parseGeneralizedTime`'s, not a second bespoke copy of
/// it here; the offset is then applied on top to land on the UTC instant.
fn parseRfc3339ToUnix(value: []const u8) ?i64 {
    if (value.len < 20 or value.len > 40) return null;
    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or value[13] != ':' or value[16] != ':') return null;

    const tz = value[value.len - 1];
    var offset_seconds: i64 = 0;
    var datetime_end: usize = undefined;
    if (tz == 'Z' or tz == 'z') {
        datetime_end = value.len - 1;
    } else {
        // `+HH:MM`/`-HH:MM`: a fixed 6-byte suffix (sign, 2-digit hours,
        // ':', 2-digit minutes).
        if (value.len < 25) return null;
        const off = value[value.len - 6 ..];
        if (off[3] != ':') return null;
        const sign: i64 = switch (off[0]) {
            '+' => 1,
            '-' => -1,
            else => return null,
        };
        const hh = parseTwoDigits(off[1..3]) orelse return null;
        const mm = parseTwoDigits(off[4..6]) orelse return null;
        if (hh > 23 or mm > 59) return null;
        offset_seconds = sign * (@as(i64, hh) * 3600 + @as(i64, mm) * 60);
        datetime_end = value.len - 6;
    }
    if (datetime_end < 19) return null;
    if (datetime_end > 19) {
        const frac = value[19..datetime_end];
        if (frac.len < 2 or frac[0] != '.') return null;
        for (frac[1..]) |c| if (c < '0' or c > '9') return null;
    }

    var compact: [15]u8 = undefined;
    compact[0..4].* = value[0..4].*;
    compact[4..6].* = value[5..7].*;
    compact[6..8].* = value[8..10].*;
    compact[8..10].* = value[11..13].*;
    compact[10..12].* = value[14..16].*;
    compact[12..14].* = value[17..19].*;
    compact[14] = 'Z';
    const parsed = pki.time.parseGeneralizedTime(&compact) catch return null;
    const t = pki.x509.Time{
        .year = parsed.year,
        .month = parsed.month,
        .day = parsed.day,
        .hour = parsed.hour,
        .minute = parsed.minute,
        .second = parsed.second,
        .encoding = .generalized,
    };
    // `+HH:MM` means local time is ahead of UTC by that much, so the UTC
    // instant is the local wall-clock time *minus* the offset (and
    // symmetrically for `-HH:MM`).
    return pki.path_validator.unixSeconds(t) - offset_seconds;
}

test "parseRfc3339ToUnix: Z and equivalent numeric offsets agree on the same instant" {
    const z = parseRfc3339ToUnix("2026-10-17T01:00:00Z") orelse return error.TestUnexpectedResult;
    const zero_offset = parseRfc3339ToUnix("2026-10-17T01:00:00+00:00") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(z, zero_offset);

    // 21:00 local at -04:00 is the same instant as 01:00Z the next day.
    const negative_offset = parseRfc3339ToUnix("2026-10-16T21:00:00-04:00") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(z, negative_offset);

    // A fractional-second value with a positive offset still lands on a
    // consistent, decodable instant (exact value not asserted here, only
    // that it parses and that the offset actually shifted it from the
    // naive, offset-ignored reading).
    const positive_offset = parseRfc3339ToUnix("2026-10-17T05:00:00.123+04:00") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(z, positive_offset);
}

test "parseRfc3339ToUnix: rejects out-of-range or malformed offsets" {
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-10-17T01:00:00+24:00"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-10-17T01:00:00+00:60"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-10-17T01:00:00+0000"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-10-17T01:00:00"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("not-a-timestamp"));
}

test "parseRfc3339ToUnix: still rejects a leap-date that the calendar validator catches" {
    // 2026 is not a leap year; Feb 29 must still fail closed regardless of
    // which timezone designator is used.
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-02-29T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339ToUnix("2026-02-29T00:00:00+01:00"));
}

fn identifierIndexInGroup(order_group: []const []const u8, value: []const u8) ?usize {
    for (order_group, 0..) |name, i| {
        if (std.mem.eql(u8, name, value)) return i;
    }
    return null;
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
    var first = try fetchAuthorizationRetrying(allocator, client, authz_url, order_group, options, order_deadline_ms, authz_deadline_ms);
    defer first.deinit();
    // RFC 8555 §7.1.3 does not guarantee a 1:1 count between requested
    // identifiers and authorizations, so this only checks group membership
    // -- never that the identifier is still "unclaimed" by an earlier
    // authorization URL -- leaving a later poll of this same `authz_url`
    // (below) to enforce the one invariant the RFC does promise: its
    // identifier never changes mid-poll.
    _ = identifierIndexInGroup(order_group, first.identifier_value) orelse return error.UnexpectedIdentifier;
    switch (first.terminal) {
        .valid => return,
        .invalid => return error.AuthorizationInvalid,
        .pending => {},
    }
    const challenge = first.http01 orelse return error.NoHttp01Challenge;
    const host = first.identifier_value;
    const token = challenge.token;
    const challenge_url = challenge.url;

    // The fetch above spent an unknown slice of this authorization's budget
    // on an independent transport request; re-check both deadlines (and
    // cancellation) before publishing a key authorization or acknowledging
    // the challenge, so an attempt that ran out of budget during that fetch
    // can never still produce these CA-visible side effects (#898).
    try checkLive(options, order_deadline_ms);
    if (options.clock.now() >= authz_deadline_ms) return error.AuthorizationTimedOut;

    var key_auth_buf: [key_authorization_buf_len]u8 = undefined;
    const key_authorization = try buildKeyAuthorization(client, token, &key_auth_buf);

    const now_unix = options.unix_clock.now();
    // The CA's own authorization lifetime (RFC 8555 §7.1.4), when given,
    // must bound not just the published challenge's store TTL but every
    // later poll/wait of this authorization too: a CA that promises
    // `expires` in 2 seconds and then keeps answering `pending` for 120
    // would otherwise let this worker poll (and potentially accept a late
    // `valid`) well past a lifetime the CA itself never promised (design
    // §8.2, #898).
    var effective_authz_deadline_ms = authz_deadline_ms;
    var ca_expiry_unix: ?i64 = null;
    if (first.expires) |expires_str| {
        const parsed_expiry = parseRfc3339ToUnix(expires_str) orelse return error.BadAuthorizationResponse;
        if (parsed_expiry <= now_unix) return error.AuthorizationTimedOut;
        ca_expiry_unix = parsed_expiry;
        const ca_remaining_s = parsed_expiry - now_unix;
        const ca_remaining_ms = std.math.mul(i64, ca_remaining_s, 1000) catch std.math.maxInt(i64);
        const ca_deadline_ms = std.math.add(i64, options.clock.now(), ca_remaining_ms) catch std.math.maxInt(i64);
        effective_authz_deadline_ms = @min(effective_authz_deadline_ms, ca_deadline_ms);
    }

    const remaining_s = @divTrunc(remainingOrderMs(options, effective_authz_deadline_ms), 1000);
    var expires_at = std.math.add(i64, now_unix, remaining_s) catch std.math.maxInt(i64);
    if (ca_expiry_unix) |ca_u| expires_at = @min(expires_at, ca_u);
    try store.put(now_unix, host, token, key_authorization, expires_at);
    errdefer _ = store.remove(host, token);

    {
        const kid = client.kid orelse return error.BadAccountResponse;
        var trigger = try client.signedPostOptions(challenge_url, "{}", .{ .kid = kid }, client.transport.limits.max_body_bytes, .json, remainingOrderMs(options, effective_authz_deadline_ms));
        defer trigger.deinit();
        // RFC 8555 §7.5.1: the response is the updated challenge object, not
        // an arbitrary 2xx. Checking it means a CA-controlled malformed
        // body, a mismatched url/token/type, or an unrecognized status
        // fails closed here instead of silently falling through to the
        // poll loop below on a challenge this client never actually
        // acknowledged (#898).
        if (trigger.status != 200 or !trigger.content_type_json) return error.BadAuthorizationResponse;
        var ack = json_limits.parseBounded(ChallengeAckJson, allocator, trigger.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadAuthorizationResponse,
        };
        defer ack.deinit();
        const av = ack.value;
        if (!std.mem.eql(u8, av.type, "http-01") or !std.mem.eql(u8, av.url, challenge_url) or !std.mem.eql(u8, av.token, token))
            return error.BadAuthorizationResponse;
        if (!std.mem.eql(u8, av.status, "processing") and !std.mem.eql(u8, av.status, "valid"))
            return error.BadAuthorizationResponse;
    }

    var poll_attempt: u32 = 0;
    var transient_attempt: u32 = 0;
    while (true) {
        if (options.cancel.isCancelled()) return error.Cancelled;
        if (options.clock.now() >= effective_authz_deadline_ms) {
            _ = store.remove(host, token);
            return error.AuthorizationTimedOut;
        }
        if (poll_attempt >= options.limits.max_polls) {
            _ = store.remove(host, token);
            return error.AuthorizationTimedOut;
        }

        const cap = remainingOrderMs(options, effective_authz_deadline_ms);
        var polled = fetchAuthorization(allocator, client, authz_url, order_group, cap) catch |err| {
            if (err == error.RateLimited) {
                waitWithinDeadline(options, retryAfterWaitMs(client, options), effective_authz_deadline_ms, error.AuthorizationTimedOut) catch |e| {
                    _ = store.remove(host, token);
                    return e;
                };
                poll_attempt +|= 1;
                continue;
            }
            if (isTransientFailure(client, err) and transient_attempt < max_transient_retries) {
                transient_attempt += 1;
                waitWithinDeadline(options, transientBackoffMs(transient_attempt - 1), effective_authz_deadline_ms, error.AuthorizationTimedOut) catch |e| {
                    _ = store.remove(host, token);
                    return e;
                };
                continue;
            }
            _ = store.remove(host, token);
            return err;
        };
        defer polled.deinit();
        transient_attempt = 0;
        // The same `authz_url` must keep reporting the identifier it
        // reported on its very first fetch; a CA that later swaps in a
        // different (still in-group) identifier would otherwise leave that
        // other name's authorization uncovered while this `seen` slot wrongly
        // reads as already satisfied.
        if (!std.mem.eql(u8, polled.identifier_value, host)) {
            _ = store.remove(host, token);
            return error.UnexpectedIdentifier;
        }

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
                waitWithinDeadline(options, wait_ms, effective_authz_deadline_ms, error.AuthorizationTimedOut) catch |e| {
                    _ = store.remove(host, token);
                    return e;
                };
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
    identifiers: []const IdentifierJson,
    authorizations: []const []const u8,
    finalize: []const u8,
    expires: []const u8,
    certificate: ?[]const u8 = null,
};

fn authorizationUrlsMatch(expected: []const []u8, actual: []const []const u8) bool {
    if (expected.len != actual.len) return false;
    for (actual, 0..) |url, i| {
        // `newOrder` already rejected duplicated URLs. Repeat that check on
        // the later representation before comparing the order-insensitive
        // set, without tying this helper to a compile-time policy limit.
        for (actual[0..i]) |earlier| {
            if (std.mem.eql(u8, earlier, url)) return false;
        }
        var found = false;
        for (expected) |known| {
            if (std.mem.eql(u8, known, url)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

/// The finalize response is the order object again (RFC 8555 §7.1.3); only
/// `identifiers` (when the CA echoes it) is checked here, not `certificate`
/// -- a synchronously-issued `valid` status still has to go through the
/// ordinary poll loop below to pick up the certificate URL.
const FinalizeOrderJson = struct {
    status: []const u8,
    identifiers: ?[]const IdentifierJson = null,
};

fn isAcceptablePostFinalizeStatus(status: []const u8) bool {
    return std.mem.eql(u8, status, "processing") or std.mem.eql(u8, status, "valid");
}

fn finalizeAndPoll(
    allocator: std.mem.Allocator,
    client: *client_mod.Client,
    order: *const Order,
    order_group: []const []const u8,
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

    try checkLive(options, order_deadline_ms);
    {
        const kid = client.kid orelse return error.BadAccountResponse;
        var resp = try client.signedPostOptions(order.finalize_url, payload, .{ .kid = kid }, client.transport.limits.max_body_bytes, .json, remainingOrderMs(options, order_deadline_ms));
        defer resp.deinit();
        // The 2xx status is already guaranteed by `signedPostOptions`
        // (anything else became an error above); what is not yet checked is
        // whether the body is actually the bounded order object this engine
        // expects, naming a sane post-finalize status and, if given, the
        // exact requested identifiers -- not just any 2xx JSON (#898).
        if (!resp.content_type_json) return error.BadOrderResponse;
        var parsed = json_limits.parseBounded(FinalizeOrderJson, allocator, resp.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadOrderResponse,
        };
        defer parsed.deinit();
        const v = parsed.value;
        if (v.identifiers) |ids| {
            if (!identifiersMatchGroup(ids, order_group)) return error.UnexpectedIdentifier;
        }
        if (!isAcceptablePostFinalizeStatus(v.status)) return error.OrderInvalid;
    }

    var poll_attempt: u32 = 0;
    var transient_attempt: u32 = 0;
    while (true) {
        try checkLive(options, order_deadline_ms);
        if (poll_attempt >= options.limits.max_polls) return error.OrderTimedOut;

        var resp = client.signedPostAsGetOptions(order.order_url, client.transport.limits.max_body_bytes, .json, remainingOrderMs(options, order_deadline_ms)) catch |err| {
            if (err == error.RateLimited) {
                try waitWithinDeadline(options, retryAfterWaitMs(client, options), order_deadline_ms, error.OrderTimedOut);
                poll_attempt +|= 1;
                continue;
            }
            if (isTransientFailure(client, err) and transient_attempt < max_transient_retries) {
                transient_attempt += 1;
                try waitWithinDeadline(options, transientBackoffMs(transient_attempt - 1), order_deadline_ms, error.OrderTimedOut);
                continue;
            }
            return err;
        };
        defer resp.deinit();
        transient_attempt = 0;
        if (!resp.content_type_json) return error.BadOrderResponse;

        var parsed = json_limits.parseBounded(OrderStatusJson, allocator, resp.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadOrderResponse,
        };
        defer parsed.deinit();
        const v = parsed.value;

        // RFC 8555 §7.1.3 makes these pieces of order identity immutable.
        // Reject a CA response that changes them before acting on `valid`.
        if (!identifiersMatchGroup(v.identifiers, order_group)) return error.UnexpectedIdentifier;
        if (!authorizationUrlsMatch(order.authorizations, v.authorizations)) return error.BadOrderResponse;
        if (!std.mem.eql(u8, v.finalize, order.finalize_url)) return error.BadOrderResponse;
        // The original expiry set the absolute deadline. A later malformed
        // expiry cannot be ignored merely because no deadline is extended.
        if (parseRfc3339ToUnix(v.expires) == null) return error.BadOrderResponse;

        if (std.mem.eql(u8, v.status, "valid")) {
            const certificate_url = v.certificate orelse return error.BadOrderResponse;
            return allocator.dupe(u8, certificate_url);
        }
        if (std.mem.eql(u8, v.status, "pending") or std.mem.eql(u8, v.status, "ready") or std.mem.eql(u8, v.status, "processing")) {
            const wait_ms = retryAfterOrPollInterval(client, poll_attempt, options.limits);
            try waitWithinDeadline(options, wait_ms, order_deadline_ms, error.OrderTimedOut);
            poll_attempt +|= 1;
            continue;
        }
        // `invalid` or any unrecognized status: fail closed.
        return error.OrderInvalid;
    }
}

fn downloadCertificate(allocator: std.mem.Allocator, client: *client_mod.Client, certificate_url: []const u8, options: Options, order_deadline_ms: i64) Error![]u8 {
    try checkLive(options, order_deadline_ms);
    // PEM, not JSON (design §5.1): the default `Accept: application/json`
    // would misrepresent what this engine can use, masking interop failures
    // with a CA that content-negotiates. The request is also capped to
    // whatever remains of the absolute order deadline, not just the
    // transport's own independent default, so a slow certificate endpoint
    // cannot push this single request past the 300s budget design §9.1
    // promises.
    var resp = try client.signedPostAsGetOptions(
        certificate_url,
        options.limits.max_certificate_bytes,
        .pem_certificate_chain,
        remainingOrderMs(options, order_deadline_ms),
    );
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

/// The clamped `Retry-After` wait (or the configured maximum, lacking one),
/// in milliseconds, for a 429 response -- the caller clamps this further to
/// whatever remains of its own deadline via `waitWithinDeadline` (#898).
fn retryAfterWaitMs(client: *client_mod.Client, options: Options) u32 {
    const seconds = clampRetryAfter(client.diagnostics.last_retry_after_s orelse options.limits.retry_after_max_s, options.limits);
    return seconds * 1000;
}

// ---------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
