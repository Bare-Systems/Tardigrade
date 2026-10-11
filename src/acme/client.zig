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

pub const Error = ProtocolError || transport_mod.Error || url_mod.Error || state_mod.Error;

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
        self.fetchDirectoryLocked() catch |err| return self.fail(err);
    }

    fn ensureDirectoryLocked(self: *Client) Error!void {
        if (self.directory == null) try self.fetchDirectoryLocked();
    }

    fn fetchDirectoryLocked(self: *Client) Error!void {
        self.diagnostics.directory_fetches +|= 1;
        var resp = try self.transport.request(.GET, self.directory_origin, null, null);
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

    fn fetchNonceLocked(self: *Client) Error!void {
        try self.ensureDirectoryLocked();
        const target = try url_mod.requireCaOrigin(self.directory.?.new_nonce, self.directory_origin, self.config.allow_cross_host_urls);
        self.diagnostics.nonce_fetches +|= 1;
        var resp = try self.transport.request(.HEAD, target, null, null);
        defer resp.deinit();
        self.noteResponse(&resp);
        if (resp.status != 200 and resp.status != 204) return error.CaRejected;
        if (self.nonce_len == 0) return error.MissingNonce;
    }

    /// Take the cached nonce (fetching one if needed) and clear the slot: the
    /// caller now owns it for exactly one request.
    fn takeNonceLocked(self: *Client, out: *[account_mod.max_nonce_len]u8) Error![]const u8 {
        if (self.nonce_len == 0) try self.fetchNonceLocked();
        const len = self.nonce_len;
        @memcpy(out[0..len], self.nonce_buf[0..len]);
        self.nonce_len = 0;
        return out[0..len];
    }

    // -- signed requests --------------------------------------------------

    /// POST `payload` (null = POST-as-GET) to a CA URL as a signed JWS. On a
    /// `badNonce` problem the request is re-signed with the fresh nonce the
    /// CA returned, at most `max_bad_nonce_retries` times. Returns the 2xx
    /// response; any other status becomes an error and updates diagnostics.
    pub fn signedPost(self: *Client, url: []const u8, payload: ?[]const u8, auth: account_mod.Auth) Error!transport_mod.Response {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.signedPostLocked(url, payload, auth) catch |err| return self.fail(err);
    }

    fn signedPostLocked(self: *Client, url: []const u8, payload: ?[]const u8, auth: account_mod.Auth) Error!transport_mod.Response {
        const target = try url_mod.requireCaOrigin(url, self.directory_origin, self.config.allow_cross_host_urls);
        try self.ensureDirectoryLocked();

        var retries: u8 = 0;
        while (true) {
            var nonce_storage: [account_mod.max_nonce_len]u8 = undefined;
            const nonce = try self.takeNonceLocked(&nonce_storage);
            const jws = account_mod.signJws(self.allocator, self.key, .{ .url = url, .nonce = nonce, .auth = auth }, payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.JwsFailed,
            };
            defer self.allocator.free(jws);
            self.diagnostics.signed_requests +|= 1;

            // Every path below either returns `resp` to the caller or frees it
            // exactly once; nothing between here and there can fail.
            var resp = try self.transport.request(.POST, target, jws, "application/jose+json");
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
        const kid = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            break :blk self.kid orelse return error.BadAccountResponse;
        };
        // The slice stays valid: kid is only replaced via setKid/deinit, which
        // callers do not run concurrently with in-flight requests.
        return self.signedPost(url, null, .{ .kid = kid });
    }

    /// newAccount (RFC 8555 §7.3). Idempotent per key: a CA that already knows
    /// the key answers 200 with the existing account URL, which is how a lost
    /// local record is rediscovered. Returns whether the account is new.
    fn registerAccount(self: *Client) Error!bool {
        if (!self.config.terms_of_service_agreed) return self.failLocked(error.TermsNotAgreed);
        var payload_buf: [512]u8 = undefined;
        const payload = self.buildNewAccountPayload(&payload_buf) catch |err| return self.failLocked(err);

        self.mutex.lock();
        const url = blk: {
            defer self.mutex.unlock();
            self.ensureDirectoryLocked() catch |err| return self.fail(err);
            break :blk self.allocator.dupe(u8, self.directory.?.new_account) catch return self.fail(error.OutOfMemory);
        };
        defer self.allocator.free(url);

        var resp = try self.signedPost(url, payload, .jwk);
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

        const loaded = try state_mod.loadOrCreateAccountKey(state, allocator);
        session.key = loaded.key;
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
            session.client.setKid(r.record().kid) catch return session.client.fail(error.CorruptState);
            session.client.diagnostics.accounts_reused +|= 1;
            session.created = false;
            return session;
        }

        const created = try session.client.registerAccount();
        const hash = state_mod.contactHash(if (config.contact_email.len == 0) "" else config.contact_email);
        state_mod.saveAccountRecord(state, allocator, .{
            .directory = config.directory_url,
            .kid = session.client.kid.?,
            .created_at = now_unix,
            .contact_hash = &hash,
        }) catch |err| return session.client.failLocked(err);
        if (created) session.client.diagnostics.accounts_created +|= 1 else session.client.diagnostics.accounts_reused +|= 1;
        session.created = created;
        return session;
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
