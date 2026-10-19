//! ACME protocol client for accounts (#832, RFC 8555 §6–7; design §5.3, §6.3).
//!
//! Scope of this phase (A2): directory discovery, the replay-nonce protocol,
//! authenticated (JWS) POSTs with a finite `badNonce` retry budget, and
//! account creation/reuse with restart-persistent state. Orders,
//! authorizations and certificates belong to A3/A4; nothing here issues or
//! activates a certificate.
//!
//! Safety properties, each covered by a test:
//!   * A nonce is consumed by exactly one signed request: it is taken out of
//!     the one-slot cache *before* signing and is never put back, even when
//!     the request fails. Requests are serialized by `mutex`, so concurrent
//!     refreshes cannot interleave a nonce.
//!   * Every CA-supplied URL passes `url.requireCaOrigin` before it can be
//!     requested or persisted.
//!   * CA text (`detail`, `instance`, arbitrary headers) is never stored or
//!     surfaced; problem documents reduce to a closed `ProblemType` enum.
//!   * Diagnostics classify each failure as transport, protocol, persistence
//!     or resource, and carry only counters, enum values and static error
//!     names — no URLs, nonces, keys or response bytes.

const std = @import("std");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const contact = @import("contact.zig");
const json_limits = @import("json_limits.zig");
const state_mod = @import("state.zig");
const transport_mod = @import("transport.zig");
const url_mod = @import("url.zig");

const secrets = crypto.secrets;
const Transport = transport_mod.Transport;
const StateDir = state_mod.StateDir;

pub const ProtocolError = error{
    /// Non-2xx status with no better classification.
    CaRejected,
    /// The CA kept answering `badNonce` after the retry budget.
    BadNonceExhausted,
    /// CA answered 429 / rateLimited.
    RateLimited,
    /// A 2xx status that the call does not accept (e.g. 202 for newAccount).
    UnexpectedStatus,
    /// The body was not `application/json`.
    NotJson,
    BadDirectory,
    /// No usable `Replay-Nonce` could be obtained.
    MissingNonce,
    BadAccountResponse,
    /// Operator has not accepted the CA's terms (`terms_of_service_agreed`).
    TermsNotAgreed,
    InvalidContact,
    JwsFailed,
};

pub const Error = ProtocolError || transport_mod.Error || url_mod.Error || state_mod.Error || error{Cancelled};

/// Cooperative cancellation for `Session.openUnlocked`'s account-registration
/// network path. It is checked between the directory, nonce, signed POST and
/// bad-nonce retry steps; all of those steps share one absolute registration
/// deadline, so cancellation can never extend shutdown through a sequence of
/// independent request budgets. This deliberately duplicates the shape of
/// `acme.orders.Cancel`: importing it here would cycle because `orders.zig`
/// already imports this module for `Client`/`Session`.
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

pub const FailureClass = enum {
    /// Could not reach / talk to the CA at the byte level (dial, TLS, timeout,
    /// framing, size caps, redirects).
    transport,
    /// The CA answered, but not acceptably (problem documents, bad JSON,
    /// unsafe URLs, nonce failures).
    protocol,
    /// Local durable state failed (permissions, corruption, I/O, locks).
    persistence,
    /// Local resource exhaustion.
    resource,
};

pub fn classify(err: anyerror) FailureClass {
    if (err == error.OutOfMemory) return .resource;
    if (inSet(state_mod.Error, err)) return .persistence;
    if (inSet(ProtocolError, err) or inSet(url_mod.Error, err)) return .protocol;
    return .transport;
}

fn inSet(comptime Set: type, err: anyerror) bool {
    inline for (@typeInfo(Set).error_set.?) |member| {
        if (err == @field(Set, member.name)) return true;
    }
    return false;
}

/// Closed set of ACME problem types we act on (RFC 8555 §6.7). Anything else
/// is `other`; the CA's free text is dropped.
pub const ProblemType = enum {
    none,
    bad_nonce,
    malformed,
    rate_limited,
    unauthorized,
    account_does_not_exist,
    user_action_required,
    server_internal,
    other,
};

const problem_prefix = "urn:ietf:params:acme:error:";

fn problemFromType(value: []const u8) ProblemType {
    if (!std.mem.startsWith(u8, value, problem_prefix)) return .other;
    const name = value[problem_prefix.len..];
    const table = [_]struct { []const u8, ProblemType }{
        .{ "badNonce", .bad_nonce },
        .{ "malformed", .malformed },
        .{ "rateLimited", .rate_limited },
        .{ "unauthorized", .unauthorized },
        .{ "accountDoesNotExist", .account_does_not_exist },
        .{ "userActionRequired", .user_action_required },
        .{ "serverInternal", .server_internal },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return .other;
}

/// Non-sensitive status for operators. Copyable; contains no CA-controlled
/// strings.
pub const Diagnostics = struct {
    directory_fetches: u32 = 0,
    nonce_fetches: u32 = 0,
    signed_requests: u32 = 0,
    bad_nonce_retries: u32 = 0,
    accounts_created: u32 = 0,
    accounts_reused: u32 = 0,
    failures: [@typeInfo(FailureClass).@"enum".fields.len]u32 = [_]u32{0} ** @typeInfo(FailureClass).@"enum".fields.len,
    last_failure: ?FailureClass = null,
    /// `@errorName` of the last failure: a compile-time string, not CA data.
    last_error: ?[]const u8 = null,
    last_problem: ProblemType = .none,
    last_http_status: u16 = 0,
    last_retry_after_s: ?u32 = null,

    pub fn failureCount(self: *const Diagnostics, class: FailureClass) u32 {
        return self.failures[@intFromEnum(class)];
    }

    fn record(self: *Diagnostics, err: anyerror) void {
        const class = classify(err);
        self.failures[@intFromEnum(class)] +|= 1;
        self.last_failure = class;
        self.last_error = @errorName(err);
    }
};

pub const Config = struct {
    directory_url: []const u8,
    /// Optional account contact address; sent as `mailto:` and never stored
    /// on disk (only its hash is).
    contact_email: []const u8 = "",
    /// Operator accepts the CA's terms of service (design §4.1, `acme_agree_tos`).
    terms_of_service_agreed: bool = false,
    /// Pre-provisioned account key (design §4.1). Empty uses `account.key` in
    /// the state directory, created on first use. When set the file is only
    /// read, never created.
    account_key_path: []const u8 = "",
    /// Off by default (design §6.3): CA URLs must share the directory origin.
    allow_cross_host_urls: bool = false,
    /// Extra attempts after a `badNonce`; total POSTs is this plus one. The
    /// A1 contract (§5.3) is a single retry.
    max_bad_nonce_retries: u8 = 1,
};

const DirectoryJson = struct {
    newNonce: []const u8,
    newAccount: []const u8,
    newOrder: []const u8,
    revokeCert: ?[]const u8 = null,
    keyChange: ?[]const u8 = null,
};

const ProblemJson = struct {
    type: ?[]const u8 = null,
};

const AccountJson = struct {
    status: ?[]const u8 = null,
};

pub const Directory = struct {
    new_nonce: []u8,
    new_account: []u8,
    new_order: []u8,

    fn deinit(self: *Directory, allocator: std.mem.Allocator) void {
        allocator.free(self.new_nonce);
        allocator.free(self.new_account);
        allocator.free(self.new_order);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    transport: *const Transport,
    key: *const account_mod.AccountKey,
    config: Config,
    /// Owned copy of `config.directory_url`; `config.directory_url` is
    /// re-pointed at it so callers' buffers need not outlive the client.
    directory_url: []u8,
    directory_origin: url_mod.Url,
    directory: ?Directory = null,
    nonce_buf: [account_mod.max_nonce_len]u8 = undefined,
    nonce_len: usize = 0,
    kid: ?[]u8 = null,
    mutex: zig_compat.Mutex = .{},
    diagnostics: Diagnostics = .{},

    pub fn init(allocator: std.mem.Allocator, transport: *const Transport, key: *const account_mod.AccountKey, config: Config) Error!Client {
        const owned = try allocator.dupe(u8, config.directory_url);
        errdefer allocator.free(owned);
        const origin = try url_mod.parse(owned);
        var cfg = config;
        cfg.directory_url = owned;
        return .{
            .allocator = allocator,
            .transport = transport,
            .key = key,
            .config = cfg,
            .directory_url = owned,
            .directory_origin = origin,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.directory) |*d| d.deinit(self.allocator);
        if (self.kid) |kid| self.allocator.free(kid);
        self.allocator.free(self.directory_url);
        self.* = undefined;
    }

    pub fn status(self: *Client) Diagnostics {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.diagnostics;
    }

    /// Four-byte hex fingerprint of the account URL, for logs (design §6.2:
    /// account URLs are never logged in full).
    pub fn kidFingerprint(self: *Client) ?[8]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const kid = self.kid orelse return null;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(kid, &digest, .{});
        return std.fmt.bytesToHex(digest[0..4].*, .lower);
    }

    pub fn accountUrlLen(self: *Client) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return if (self.kid) |kid| kid.len else null;
    }

    // -- directory ------------------------------------------------------

    pub fn fetchDirectory(self: *Client) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.fetchDirectoryLocked(null) catch |err| return self.fail(err);
    }

    /// `deadline`, if given, is an absolute point on `self.transport`'s own
    /// clock: the remaining budget shrinks across every request a single
    /// logical call makes (directory, nonce, the signed POST), rather than
    /// each getting its own fresh `request_deadline_ms` (#898).
    fn ensureDirectoryLocked(self: *Client, deadline: ?i64) Error!void {
        if (self.directory == null) try self.fetchDirectoryLocked(deadline);
    }

    fn fetchDirectoryLocked(self: *Client, deadline: ?i64) Error!void {
        self.diagnostics.directory_fetches +|= 1;
        const cap = try self.remainingCapMs(deadline);
        var resp = try self.transport.requestWithBodyLimit(.GET, self.directory_origin, null, null, self.transport.limits.max_body_bytes, .json, cap);
        defer resp.deinit();
        self.noteResponse(&resp);
        if (resp.status != 200) return error.CaRejected;
        if (!resp.content_type_json) return error.NotJson;

        var parsed = json_limits.parseBounded(DirectoryJson, self.allocator, resp.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadDirectory,
        };
        defer parsed.deinit();
        const v = parsed.value;

        // Every advertised endpoint must be an https URL on the directory's
        // origin before it is stored; optional ones too, so a later phase can
        // not trip over an unvetted URL.
        _ = try url_mod.requireCaOrigin(v.newNonce, self.directory_origin, self.config.allow_cross_host_urls);
        _ = try url_mod.requireCaOrigin(v.newAccount, self.directory_origin, self.config.allow_cross_host_urls);
        _ = try url_mod.requireCaOrigin(v.newOrder, self.directory_origin, self.config.allow_cross_host_urls);
        if (v.revokeCert) |u| _ = try url_mod.requireCaOrigin(u, self.directory_origin, self.config.allow_cross_host_urls);
        if (v.keyChange) |u| _ = try url_mod.requireCaOrigin(u, self.directory_origin, self.config.allow_cross_host_urls);

        var fresh = Directory{
            .new_nonce = try self.allocator.dupe(u8, v.newNonce),
            .new_account = undefined,
            .new_order = undefined,
        };
        errdefer self.allocator.free(fresh.new_nonce);
        fresh.new_account = try self.allocator.dupe(u8, v.newAccount);
        errdefer self.allocator.free(fresh.new_account);
        fresh.new_order = try self.allocator.dupe(u8, v.newOrder);
        errdefer self.allocator.free(fresh.new_order);

        if (self.directory) |*old| old.deinit(self.allocator);
        self.directory = fresh;
    }

    // -- nonces ---------------------------------------------------------

    /// Remember the response's nonce for the next request, or forget the cache
    /// when it is absent or malformed. Never logged.
    fn noteResponse(self: *Client, resp: *const transport_mod.Response) void {
        self.diagnostics.last_http_status = resp.status;
        self.diagnostics.last_retry_after_s = resp.retry_after_s;
        self.nonce_len = 0;
        if (resp.replayNonce()) |nonce| {
            if (account_mod.isValidNonce(nonce)) {
                @memcpy(self.nonce_buf[0..nonce.len], nonce);
                self.nonce_len = nonce.len;
            }
        }
    }

    fn fetchNonceLocked(self: *Client, deadline: ?i64) Error!void {
        try self.ensureDirectoryLocked(deadline);
        const target = try url_mod.requireCaOrigin(self.directory.?.new_nonce, self.directory_origin, self.config.allow_cross_host_urls);
        self.diagnostics.nonce_fetches +|= 1;
        const cap = try self.remainingCapMs(deadline);
        var resp = try self.transport.requestWithBodyLimit(.HEAD, target, null, null, self.transport.limits.max_body_bytes, .json, cap);
        defer resp.deinit();
        self.noteResponse(&resp);
        if (resp.status != 200 and resp.status != 204) return error.CaRejected;
        if (self.nonce_len == 0) return error.MissingNonce;
    }

    /// Take the cached nonce (fetching one if needed) and clear the slot: the
    /// caller now owns it for exactly one request.
    fn takeNonceLocked(self: *Client, out: *[account_mod.max_nonce_len]u8, deadline: ?i64) Error![]const u8 {
        if (self.nonce_len == 0) try self.fetchNonceLocked(deadline);
        const len = self.nonce_len;
        @memcpy(out[0..len], self.nonce_buf[0..len]);
        self.nonce_len = 0;
        return out[0..len];
    }

    /// Remaining budget until `deadline` (an absolute point on
    /// `self.transport`'s clock), or `null` when the caller gave no cap.
    /// Fails closed with `error.Timeout` rather than handing a sub-request a
    /// nonsensical zero/negative budget once the deadline has already
    /// passed between two requests of the same logical call.
    fn remainingCapMs(self: *Client, deadline: ?i64) Error!?u32 {
        const d = deadline orelse return null;
        const remaining = d - self.transport.nowMs();
        if (remaining <= 0) return error.Timeout;
        return @intCast(@min(remaining, @as(i64, std.math.maxInt(u32))));
    }

    // -- signed requests --------------------------------------------------

    /// POST `payload` (null = POST-as-GET) to a CA URL as a signed JWS. On a
    /// `badNonce` problem the request is re-signed with the fresh nonce the
    /// CA returned, at most `max_bad_nonce_retries` times. Returns the 2xx
    /// response; any other status becomes an error and updates diagnostics.
    pub fn signedPost(self: *Client, url: []const u8, payload: ?[]const u8, auth: account_mod.Auth) Error!transport_mod.Response {
        return self.signedPostMaxBody(url, payload, auth, self.transport.limits.max_body_bytes);
    }

    /// Same as `signedPost`, but reads the response body under
    /// `max_body_bytes` instead of the transport's default JSON cap. The
    /// order engine (`orders.zig`, #882) needs this for certificate chain
    /// downloads, which design §9.1 caps at 128 KiB, well above the 64 KiB
    /// JSON default every other ACME response uses.
    pub fn signedPostMaxBody(self: *Client, url: []const u8, payload: ?[]const u8, auth: account_mod.Auth, max_body_bytes: usize) Error!transport_mod.Response {
        return self.signedPostOptions(url, payload, auth, max_body_bytes, .json, null);
    }

    /// Same as `signedPostMaxBody`, with the request's `Accept` header and a
    /// cap on the per-request deadline both overridable. The order engine's
    /// certificate download (`orders.zig`, #882) needs
    /// `Accept: application/pem-certificate-chain` (design §5.1) and a
    /// deadline bounded by its own remaining per-order budget rather than the
    /// transport's independent default.
    pub fn signedPostOptions(
        self: *Client,
        url: []const u8,
        payload: ?[]const u8,
        auth: account_mod.Auth,
        max_body_bytes: usize,
        accept: transport_mod.Accept,
        deadline_cap_ms: ?u32,
    ) Error!transport_mod.Response {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.signedPostLocked(url, payload, auth, max_body_bytes, accept, deadline_cap_ms) catch |err| return self.fail(err);
    }

    fn signedPostLocked(
        self: *Client,
        url: []const u8,
        payload: ?[]const u8,
        auth: account_mod.Auth,
        max_body_bytes: usize,
        accept: transport_mod.Accept,
        deadline_cap_ms: ?u32,
    ) Error!transport_mod.Response {
        const deadline: ?i64 = if (deadline_cap_ms) |cap| self.transport.nowMs() + @as(i64, cap) else null;
        return self.signedPostLockedUntil(url, payload, auth, max_body_bytes, accept, deadline, null);
    }

    /// The internal form accepts an already-established absolute deadline so
    /// account registration can share it with its preceding directory GET.
    /// `cancel` is optional because ordinary order calls have their own
    /// cancellation seam; registration needs one between every subrequest.
    fn signedPostLockedUntil(
        self: *Client,
        url: []const u8,
        payload: ?[]const u8,
        auth: account_mod.Auth,
        max_body_bytes: usize,
        accept: transport_mod.Accept,
        deadline: ?i64,
        cancel: ?Cancel,
    ) Error!transport_mod.Response {
        const target = try url_mod.requireCaOrigin(url, self.directory_origin, self.config.allow_cross_host_urls);
        if (if (cancel) |c| c.isCancelled() else false) return error.Cancelled;
        try self.ensureDirectoryLocked(deadline);

        var retries: u8 = 0;
        while (true) {
            if (if (cancel) |c| c.isCancelled() else false) return error.Cancelled;
            var nonce_storage: [account_mod.max_nonce_len]u8 = undefined;
            const nonce = try self.takeNonceLocked(&nonce_storage, deadline);
            if (if (cancel) |c| c.isCancelled() else false) return error.Cancelled;
            const jws = account_mod.signJws(self.allocator, self.key, .{ .url = url, .nonce = nonce, .auth = auth }, payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.JwsFailed,
            };
            defer self.allocator.free(jws);
            self.diagnostics.signed_requests +|= 1;

            // Every path below either returns `resp` to the caller or frees it
            // exactly once; nothing between here and there can fail.
            const cap = try self.remainingCapMs(deadline);
            var resp = try self.transport.requestWithBodyLimit(.POST, target, jws, "application/jose+json", max_body_bytes, accept, cap);
            self.noteResponse(&resp);
            if (resp.status >= 200 and resp.status < 300) {
                self.diagnostics.last_problem = .none;
                return resp;
            }

            const problem = self.parseProblem(&resp);
            self.diagnostics.last_problem = problem;
            if (problem == .bad_nonce and retries < self.config.max_bad_nonce_retries) {
                retries += 1;
                self.diagnostics.bad_nonce_retries +|= 1;
                resp.deinit();
                if (if (cancel) |c| c.isCancelled() else false) return error.Cancelled;
                continue;
            }
            const failure: Error = switch (problem) {
                .bad_nonce => error.BadNonceExhausted,
                .rate_limited => error.RateLimited,
                else => if (resp.status == 429) error.RateLimited else error.CaRejected,
            };
            resp.deinit();
            return failure;
        }
    }

    fn parseProblem(self: *Client, resp: *const transport_mod.Response) ProblemType {
        if (!resp.content_type_json) return .other;
        var parsed = json_limits.parseBounded(ProblemJson, self.allocator, resp.body, .{}) catch return .other;
        defer parsed.deinit();
        const t = parsed.value.type orelse return .other;
        return problemFromType(t);
    }

    fn fail(self: *Client, err: Error) Error {
        self.diagnostics.record(err);
        return err;
    }

    // -- accounts ---------------------------------------------------------

    pub fn setKid(self: *Client, kid: []const u8) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = try url_mod.requireCaOrigin(kid, self.directory_origin, self.config.allow_cross_host_urls);
        const owned = try self.allocator.dupe(u8, kid);
        if (self.kid) |old| self.allocator.free(old);
        self.kid = owned;
    }

    /// POST-as-GET against an account-bound URL using the stored `kid`.
    pub fn signedPostAsGet(self: *Client, url: []const u8) Error!transport_mod.Response {
        return self.signedPostAsGetMaxBody(url, self.transport.limits.max_body_bytes);
    }

    /// Same as `signedPostAsGet`, but reads the response body under
    /// `max_body_bytes` (see `signedPostMaxBody`).
    pub fn signedPostAsGetMaxBody(self: *Client, url: []const u8, max_body_bytes: usize) Error!transport_mod.Response {
        return self.signedPostAsGetOptions(url, max_body_bytes, .json, null);
    }

    /// Same as `signedPostAsGetMaxBody`, with the request's `Accept` header
    /// and a deadline cap both overridable (see `signedPostOptions`).
    pub fn signedPostAsGetOptions(
        self: *Client,
        url: []const u8,
        max_body_bytes: usize,
        accept: transport_mod.Accept,
        deadline_cap_ms: ?u32,
    ) Error!transport_mod.Response {
        const kid = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            break :blk self.kid orelse return error.BadAccountResponse;
        };
        // The slice stays valid: kid is only replaced via setKid/deinit, which
        // callers do not run concurrently with in-flight requests.
        return self.signedPostOptions(url, null, .{ .kid = kid }, max_body_bytes, accept, deadline_cap_ms);
    }

    /// `newOrder` endpoint URL (RFC 8555 §7.1.1), fetching the directory
    /// first if needed. The order engine (`orders.zig`, #882) uses this
    /// instead of reaching into `self.directory` directly, keeping the
    /// directory fetch/cache logic owned by this file. `deadline_cap_ms`
    /// bounds a cold directory GET by the caller's own remaining budget (the
    /// same contract as `signedPostOptions`'s `deadline_cap_ms`), so this can
    /// never itself consume more than what is left of the order's absolute
    /// deadline before the later signed `newOrder` POST even runs (#898).
    pub fn newOrderUrl(self: *Client, deadline_cap_ms: u32) Error![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const deadline = self.transport.nowMs() + @as(i64, deadline_cap_ms);
        self.ensureDirectoryLocked(deadline) catch |err| return self.fail(err);
        return self.directory.?.new_order;
    }

    /// newAccount (RFC 8555 §7.3). Idempotent per key: a CA that already knows
    /// the key answers 200 with the existing account URL, which is how a lost
    /// local record is rediscovered. Returns whether the account is new.
    /// Registration has one absolute deadline across directory discovery,
    /// nonce fetch, signed POST and any bad-nonce retry. `cancel` is checked
    /// before each of those discrete stages, so shutdown cannot accumulate a
    /// fresh transport deadline for every stage.
    fn registerAccount(self: *Client, cancel: Cancel) Error!bool {
        if (!self.config.terms_of_service_agreed) return self.failLocked(error.TermsNotAgreed);
        if (cancel.isCancelled()) return self.failLocked(error.Cancelled);
        var payload_buf: [512]u8 = undefined;
        const payload = self.buildNewAccountPayload(&payload_buf) catch |err| return self.failLocked(err);

        const deadline = self.transport.nowMs() + @as(i64, self.transport.limits.request_deadline_ms);
        self.mutex.lock();
        const url = blk: {
            defer self.mutex.unlock();
            self.ensureDirectoryLocked(deadline) catch |err| return self.fail(err);
            break :blk self.allocator.dupe(u8, self.directory.?.new_account) catch return self.fail(error.OutOfMemory);
        };
        defer self.allocator.free(url);

        if (cancel.isCancelled()) return self.failLocked(error.Cancelled);
        self.mutex.lock();
        var resp = self.signedPostLockedUntil(url, payload, .jwk, self.transport.limits.max_body_bytes, .json, deadline, cancel) catch |err| {
            const failure = self.fail(err);
            self.mutex.unlock();
            return failure;
        };
        self.mutex.unlock();
        defer resp.deinit();
        const created = switch (resp.status) {
            201 => true,
            200 => false,
            else => return self.failLocked(error.UnexpectedStatus),
        };
        const location = resp.location() orelse return self.failLocked(error.BadAccountResponse);
        // The account object is required to be bounded JSON: a 2xx with a
        // missing/odd content type or a garbage body fails closed instead of
        // being persisted.
        if (!resp.content_type_json) return self.failLocked(error.BadAccountResponse);
        var parsed = json_limits.parseBounded(AccountJson, self.allocator, resp.body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return self.failLocked(error.OutOfMemory),
            else => return self.failLocked(error.BadAccountResponse),
        };
        defer parsed.deinit();
        if (parsed.value.status) |s| {
            if (!std.mem.eql(u8, s, "valid")) return self.failLocked(error.BadAccountResponse);
        }
        self.setKid(location) catch |err| return self.failLocked(err);
        return created;
    }

    fn failLocked(self: *Client, err: Error) Error {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.fail(err);
    }

    fn buildNewAccountPayload(self: *Client, out: []u8) Error![]const u8 {
        const email = self.config.contact_email;
        if (email.len == 0) return std.fmt.bufPrint(out, "{{\"termsOfServiceAgreed\":true}}", .{}) catch error.InvalidContact;
        if (!isPlausibleEmail(email)) return error.InvalidContact;
        return std.fmt.bufPrint(out, "{{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:{s}\"]}}", .{email}) catch error.InvalidContact;
    }
};

pub const isPlausibleEmail = contact.isPlausibleEmail;

/// A ready account: key, protocol client, and the persisted account URL.
pub const Session = struct {
    allocator: std.mem.Allocator,
    key: account_mod.AccountKey,
    client: Client,
    /// Whether this `open` registered the account (false: reused or
    /// rediscovered from the CA).
    created: bool,

    /// Open `state`'s account for `config`.
    ///
    /// With a persisted record this performs **no network I/O**: the account
    /// URL comes from `account.json`, so a restart during a CA outage still
    /// has its identity. Without one it registers (or rediscovers) the
    /// account and then persists the record; a failure to persist leaves the
    /// key on disk and the account at the CA, and the next `open` converges
    /// through newAccount's idempotence.
    pub fn open(
        allocator: std.mem.Allocator,
        transport: *const Transport,
        state: *StateDir,
        config: Config,
        now_unix: i64,
    ) Error!*Session {
        const session = try allocator.create(Session);
        errdefer allocator.destroy(session);
        session.allocator = allocator;

        if (config.account_key_path.len > 0) {
            session.key = try state_mod.loadPreprovisionedKey(config.account_key_path);
        } else {
            const loaded = try state_mod.loadOrCreateAccountKey(state, allocator);
            session.key = loaded.key;
        }
        errdefer session.key.deinit();

        session.client = try Client.init(allocator, transport, &session.key, config);
        errdefer session.client.deinit();

        var record = state_mod.loadAccountRecord(state, allocator, config.directory_url) catch |err| switch (err) {
            error.NotFound => null,
            else => return session.client.fail(err),
        };
        if (record) |*r| {
            defer r.deinit();
            // A record we wrote must name an account on the directory's
            // origin; anything else is corruption or tampering.
            // A record we wrote must name an account on the directory's
            // origin; anything else is corruption or tampering.
            session.client.setKid(r.record().kid) catch return session.client.fail(error.CorruptState);
            // ...and it must belong to the key just loaded; otherwise every
            // request would sign with one key while claiming another's `kid`.
            const current = session.key.jwk().thumbprint();
            if (!std.mem.eql(u8, r.record().key_thumbprint, &current)) return session.client.fail(error.InconsistentState);
            session.client.diagnostics.accounts_reused +|= 1;
            session.created = false;
            return session;
        }

        const created = try session.client.registerAccount(.{});
        const hash = state_mod.contactHash(if (config.contact_email.len == 0) "" else config.contact_email);
        state_mod.saveAccountRecord(state, allocator, .{
            .directory = config.directory_url,
            .kid = session.client.kid.?,
            .key_thumbprint = &session.key.jwk().thumbprint(),
            .created_at = now_unix,
            .contact_hash = &hash,
        }) catch |err| return session.client.failLocked(err);
        if (created) session.client.diagnostics.accounts_created +|= 1 else session.client.diagnostics.accounts_reused +|= 1;
        session.created = created;
        return session;
    }

    /// Opens an account while holding the state-directory lock only around
    /// durable reads and writes.  In particular, first-account registration
    /// performs directory/nonce/new-account network I/O after the initial
    /// state transaction has closed.  Long-running gateway work must use
    /// this variant so a harmless config reload cannot be rejected merely
    /// because an ACME endpoint is slow to register a new account.
    ///
    /// A second short transaction before persisting reconciles a record that
    /// another process may have written while the CA request was in flight.
    /// `cancel` bounds first-registration shutdown latency to whichever of
    /// `registerAccount`'s own steps is currently in flight -- see its own
    /// and `Cancel`'s doc comments.
    pub fn openUnlocked(
        allocator: std.mem.Allocator,
        transport: *const Transport,
        state_dir_path: []const u8,
        config: Config,
        now_unix: i64,
        cancel: Cancel,
    ) Error!*Session {
        const session = try allocator.create(Session);
        errdefer allocator.destroy(session);
        session.allocator = allocator;
        var has_key = false;
        errdefer if (has_key) session.key.deinit();

        var initial_record = blk: {
            var state = try StateDir.open(state_dir_path);
            defer state.close();
            if (config.account_key_path.len > 0) {
                session.key = try state_mod.loadPreprovisionedKey(config.account_key_path);
            } else {
                const loaded = try state_mod.loadOrCreateAccountKey(&state, allocator);
                session.key = loaded.key;
            }
            has_key = true;
            break :blk state_mod.loadAccountRecord(&state, allocator, config.directory_url) catch |err| switch (err) {
                error.NotFound => null,
                else => return err,
            };
        };
        defer if (initial_record) |*record| record.deinit();

        session.client = try Client.init(allocator, transport, &session.key, config);
        errdefer session.client.deinit();

        if (initial_record) |*record| {
            try session.installPersistedRecord(record.record());
            return session;
        }

        if (cancel.isCancelled()) return session.client.failLocked(error.Cancelled);
        const created = try session.client.registerAccount(cancel);
        var state = try StateDir.open(state_dir_path);
        defer state.close();
        var record = state_mod.loadAccountRecord(&state, allocator, config.directory_url) catch |err| switch (err) {
            error.NotFound => null,
            else => return session.client.fail(err),
        };
        if (record) |*existing| {
            defer existing.deinit();
            // Another process registered the same key while we were doing
            // network I/O. Its durable record wins; never overwrite it.
            try session.installPersistedRecord(existing.record());
            return session;
        }

        const hash = state_mod.contactHash(if (config.contact_email.len == 0) "" else config.contact_email);
        state_mod.saveAccountRecord(&state, allocator, .{
            .directory = config.directory_url,
            .kid = session.client.kid.?,
            .key_thumbprint = &session.key.jwk().thumbprint(),
            .created_at = now_unix,
            .contact_hash = &hash,
        }) catch |err| return session.client.failLocked(err);
        if (created) session.client.diagnostics.accounts_created +|= 1 else session.client.diagnostics.accounts_reused +|= 1;
        session.created = created;
        return session;
    }

    fn installPersistedRecord(self: *Session, record: state_mod.AccountRecord) Error!void {
        self.client.setKid(record.kid) catch return self.client.fail(error.CorruptState);
        const current = self.key.jwk().thumbprint();
        if (!std.mem.eql(u8, record.key_thumbprint, &current)) return self.client.fail(error.InconsistentState);
        self.client.diagnostics.accounts_reused +|= 1;
        self.created = false;
    }

    pub fn close(self: *Session) void {
        const allocator = self.allocator;
        self.client.deinit();
        self.key.deinit();
        allocator.destroy(self);
    }

    pub fn accountUrl(self: *const Session) []const u8 {
        return self.client.kid.?;
    }
};

// Tests for the client live in `client_tests.zig`, next to the fake CA they
// need, to keep this file reviewable.
