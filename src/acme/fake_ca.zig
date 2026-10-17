//! Deterministic in-process fake ACME CA for tests (#832, design §11).
//!
//! Test-only (`root.zig` exposes it only under `builtin.is_test`). It speaks
//! HTTP/1.1 through the transport's `Connection` seam and, crucially, does not
//! trust the client: every POST is a real flattened JWS whose protected header
//! (alg, nonce, url, jwk-xor-kid) and ES256 signature it verifies with the
//! account's public key, consuming nonces single-use exactly as RFC 8555 §6.5
//! requires. A scripted fault surface covers the hostile cases the client must
//! survive (badNonce, missing nonce, redirects, oversized/malformed/cross-host
//! directories, rate limits, slow responses, ...).
//!
//! What it does not cover: the TLS leg. `UpstreamTlsConn` and the
//! `webpki_verifier` path have their own suites; this fake replaces only the
//! byte stream beneath HTTP.

const std = @import("std");
const account = @import("account.zig");
const transport = @import("transport.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const b64url = std.base64.url_safe_no_pad;

pub const DirectoryMode = enum {
    normal,
    malformed_json,
    deep_json,
    huge_body,
    redirect,
    not_json_content_type,
    missing_field,
    wrong_field_type,
    cross_host_new_account,
    cross_host_new_nonce,
    http_scheme_url,
    userinfo_url,
    status_500,
};

pub const AccountMode = enum {
    normal,
    missing_location,
    cross_host_location,
    http_location,
    status_500,
    status_202,
    rate_limited,
    invalid_status_body,
    text_plain_content_type,
    garbage_body,
    empty_body,
    huge_body,
    server_error_problem,
};

pub const Script = struct {
    directory: DirectoryMode = .normal,
    account: AccountMode = .normal,
    /// Answer the next N signed POSTs with `badNonce` (and a fresh nonce).
    bad_nonce_remaining: u32 = 0,
    /// Never send `Replay-Nonce` on POST responses (the client must HEAD).
    omit_nonce_on_post: bool = false,
    /// Never send a usable nonce on HEAD newNonce.
    omit_nonce_on_head: bool = false,
    /// Send a malformed nonce on HEAD newNonce.
    bad_nonce_value_on_head: bool = false,
    chunked: bool = false,
    read_chunk: usize = 11,
    /// Advance the fake clock by this much on every read (slow peer).
    stall_ms_per_read: i64 = 0,
    /// Fail the connection outright on dial.
    refuse_dial: bool = false,
    /// Replace the directory / newAccount response bodies verbatim (fuzzing).
    directory_body: ?[]const u8 = null,
    account_body: ?[]const u8 = null,

    new_order: NewOrderBehavior = .{},
    authz: AuthzBehavior = .{},
    challenge: ChallengeBehavior = .{},
    finalize: FinalizeBehavior = .{},
    order_poll: OrderPollBehavior = .{},
    cert: CertBehavior = .{},
};

/// Scripted hostile behavior for `POST /new-order` (#882 order engine).
pub const NewOrderBehavior = struct {
    status_500: bool = false,
    rate_limited: bool = false,
    malformed_json: bool = false,
    /// The response lists one more `dns` identifier than was requested.
    extra_identifier: bool = false,
    /// The response drops the last requested identifier.
    missing_identifier: bool = false,
    /// `identifiers[]` lists every requested name, but `authorizations[]`
    /// drops the last entry, so one name is left without any authorization
    /// URL at all.
    missing_authorization: bool = false,
    /// One `authorizations[]` entry points at a different (non-CA) origin.
    cross_host_authorization: bool = false,
    /// The last `authorizations[]` entry is replaced with a repeat of the
    /// first one's URL (same count as identifiers, but a real duplicate).
    duplicate_authorization: bool = false,
    /// `finalize` points at a different (non-CA) origin.
    cross_host_finalize: bool = false,
    /// Replace the `status` field with an arbitrary scripted value (e.g. an
    /// unrecognized string, or `valid`), instead of the normal `pending`.
    status_override: ?[]const u8 = null,
};

/// Scripted hostile behavior for authorization GET polls.
pub const AuthzBehavior = struct {
    /// Reports an identifier the client never requested (confused-deputy
    /// check: `orders.zig` must reject this even though `new-order` was
    /// honest).
    wrong_identifier: bool = false,
    /// `challenges[]` contains no `http-01` entry.
    no_http01: bool = false,
    /// The `http-01` challenge's `url` points at a different origin.
    cross_host_challenge: bool = false,
    /// `challenges[]` contains two distinct `http-01` entries (different
    /// URLs/tokens), so the client cannot tell which one is actually bound.
    duplicate_http01: bool = false,
    /// Every authorization reports the identifier of the very first
    /// authorization ever created, simulating two distinct authorization
    /// URLs that both claim to cover the same requested name.
    collapse_identifier: bool = false,
    /// Authorization id 1 reports its own identifier on the first GET (so it
    /// claims the correct `seen` slot), then switches to authorization id
    /// 2's (still in-group) identifier on every later GET.
    swap_identifier_on_poll: bool = false,
    /// How many polls answer "pending" before the terminal status below.
    polls_before_final: u32 = 0,
    final_status: enum { valid, invalid } = .valid,
    /// 429 + Retry-After for this many polls before answering normally.
    rate_limited_polls: u32 = 0,
    malformed_json: bool = false,
    status_500: bool = false,
};

/// Scripted hostile behavior for `POST /authz/{id}/http-01` (challenge
/// ready-trigger).
pub const ChallengeBehavior = struct {
    /// The CA rejects the trigger itself (not validation).
    rejected: bool = false,
};

/// Scripted hostile behavior for `POST /order/{id}/finalize`.
pub const FinalizeBehavior = struct {
    /// badCSR problem.
    rejected: bool = false,
    status_500: bool = false,
    malformed_json: bool = false,
};

/// Scripted hostile behavior for order-status polls after finalize.
pub const OrderPollBehavior = struct {
    polls_before_final: u32 = 0,
    final_status: enum { valid, invalid } = .valid,
    rate_limited_polls: u32 = 0,
    cross_host_certificate: bool = false,
    malformed_json: bool = false,
};

/// Scripted hostile behavior for `POST /cert/{id}` (certificate download).
pub const CertBehavior = struct {
    status_500: bool = false,
    huge_body: bool = false,
    empty_body: bool = false,
};

pub const Logged = struct {
    method: transport.Method,
    path: []u8,
    /// POST only: the JWS verified (header, nonce, url, signature).
    signature_ok: bool = false,
    used_kid: bool = false,
    status: u16 = 0,
};

pub const FakeClock = struct {
    now: i64 = 10_000,

    pub fn clock(self: *FakeClock) transport.Clock {
        return .{ .ctx = self, .nowFn = tick };
    }

    fn tick(ctx: ?*anyopaque) i64 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
};

pub const FakeCa = struct {
    allocator: std.mem.Allocator,
    base: []const u8 = "https://ca.test",
    script: Script = .{},
    clock: ?*FakeClock = null,

    nonce_seq: u64 = 0,
    valid_nonces: std.StringHashMapUnmanaged(void) = .empty,
    accounts: std.ArrayList(Account) = .empty,
    log: std.ArrayList(Logged) = .empty,
    dialed: std.ArrayList([]u8) = .empty,
    /// Nonces already accepted once; seeing one again means client reuse.
    seen_nonce_uses: std.StringHashMapUnmanaged(u32) = .empty,
    nonce_reuse_detected: bool = false,
    /// Decoded payload of the last verified newAccount request.
    last_payload: ?[]u8 = null,

    orders: std.ArrayList(Order) = .empty,
    authorizations: std.ArrayList(Authz) = .empty,
    certificates: std.ArrayList([]u8) = .empty,

    const Account = struct { x: [32]u8, y: [32]u8 };

    const OrderStatus = enum { pending, processing, valid, invalid };
    const AuthzStatus = enum { pending, processing, valid, invalid };

    const Order = struct {
        identifiers: std.ArrayList([]u8) = .empty,
        authz_ids: std.ArrayList(usize) = .empty,
        status: OrderStatus = .pending,
        finalized: bool = false,
        polls_before_final: u32,
        poll_count: u32 = 0,
        rate_limited_remaining: u32,
        certificate_id: ?usize = null,

        fn deinit(self: *Order, allocator: std.mem.Allocator) void {
            for (self.identifiers.items) |id| allocator.free(id);
            self.identifiers.deinit(allocator);
            self.authz_ids.deinit(allocator);
        }
    };

    const Authz = struct {
        identifier: []u8,
        token: []u8,
        status: AuthzStatus = .pending,
        triggered: bool = false,
        polls_before_final: u32,
        poll_count: u32 = 0,
        rate_limited_remaining: u32,
        /// Every GET against this authorization, including the first fetch
        /// before the challenge is triggered; `swap_identifier_on_poll` uses
        /// this to report a different in-group identifier from the second
        /// GET onward.
        get_count: u32 = 0,

        fn deinit(self: *Authz, allocator: std.mem.Allocator) void {
            allocator.free(self.identifier);
            allocator.free(self.token);
        }
    };

    pub fn init(allocator: std.mem.Allocator) FakeCa {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FakeCa) void {
        var it = self.valid_nonces.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.valid_nonces.deinit(self.allocator);
        var it2 = self.seen_nonce_uses.keyIterator();
        while (it2.next()) |k| self.allocator.free(k.*);
        self.seen_nonce_uses.deinit(self.allocator);
        self.accounts.deinit(self.allocator);
        if (self.last_payload) |p| self.allocator.free(p);
        for (self.log.items) |entry| self.allocator.free(entry.path);
        self.log.deinit(self.allocator);
        for (self.dialed.items) |h| self.allocator.free(h);
        self.dialed.deinit(self.allocator);
        for (self.orders.items) |*o| o.deinit(self.allocator);
        self.orders.deinit(self.allocator);
        for (self.authorizations.items) |*a| a.deinit(self.allocator);
        self.authorizations.deinit(self.allocator);
        for (self.certificates.items) |c| self.allocator.free(c);
        self.certificates.deinit(self.allocator);
    }

    pub fn dialer(self: *FakeCa) transport.Dialer {
        return .{ .ptr = self, .dialFn = dial };
    }

    pub fn countPosts(self: *const FakeCa) usize {
        var n: usize = 0;
        for (self.log.items) |e| {
            if (e.method == .POST) n += 1;
        }
        return n;
    }

    pub fn countRequests(self: *const FakeCa, method: transport.Method, path: []const u8) usize {
        var n: usize = 0;
        for (self.log.items) |e| {
            if (e.method == method and std.mem.eql(u8, e.path, path)) n += 1;
        }
        return n;
    }

    pub fn allPostsVerified(self: *const FakeCa) bool {
        for (self.log.items) |e| {
            if (e.method == .POST and !e.signature_ok) return false;
        }
        return true;
    }

    // -- connection ------------------------------------------------------

    const Conn = struct {
        ca: *FakeCa,
        allocator: std.mem.Allocator,
        request: std.ArrayList(u8) = .empty,
        response: ?[]u8 = null,
        pos: usize = 0,
    };

    const vtable = transport.Connection.VTable{ .read = read, .writeAll = writeAll, .close = close };

    fn dial(ptr: *anyopaque, allocator: std.mem.Allocator, host: []const u8, _: u16, _: u32) transport.DialError!transport.Connection {
        const self: *FakeCa = @ptrCast(@alignCast(ptr));
        const copy = allocator.dupe(u8, host) catch return error.OutOfMemory;
        self.dialed.append(self.allocator, copy) catch {
            allocator.free(copy);
            return error.OutOfMemory;
        };
        if (self.script.refuse_dial) return error.DialFailed;
        // Only the CA's own host exists in this world.
        if (!std.mem.eql(u8, host, "ca.test")) return error.DialFailed;
        const conn = allocator.create(Conn) catch return error.OutOfMemory;
        conn.* = .{ .ca = self, .allocator = allocator };
        return .{ .ptr = conn, .vtable = &vtable };
    }

    fn writeAll(ptr: *anyopaque, data: []const u8) transport.IoError!void {
        const conn: *Conn = @ptrCast(@alignCast(ptr));
        conn.request.appendSlice(conn.allocator, data) catch return error.Failed;
    }

    fn read(ptr: *anyopaque, buf: []u8) transport.IoError!usize {
        const conn: *Conn = @ptrCast(@alignCast(ptr));
        if (conn.ca.clock) |c| c.now += conn.ca.script.stall_ms_per_read;
        if (conn.response == null) {
            conn.response = conn.ca.handle(conn.allocator, conn.request.items) catch return error.Failed;
        }
        const resp = conn.response.?;
        if (conn.pos >= resp.len) return 0;
        const n = @min(@min(conn.ca.script.read_chunk, buf.len), resp.len - conn.pos);
        @memcpy(buf[0..n], resp[conn.pos .. conn.pos + n]);
        conn.pos += n;
        return n;
    }

    fn close(ptr: *anyopaque) void {
        const conn: *Conn = @ptrCast(@alignCast(ptr));
        const allocator = conn.allocator;
        conn.request.deinit(allocator);
        if (conn.response) |r| allocator.free(r);
        allocator.destroy(conn);
    }

    // -- server ------------------------------------------------------------

    const HandleError = error{OutOfMemory};

    fn handle(self: *FakeCa, allocator: std.mem.Allocator, raw: []const u8) HandleError![]u8 {
        const head_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.OutOfMemory;
        const head = raw[0..head_end];
        const body = raw[head_end + 4 ..];
        var lines = std.mem.splitSequence(u8, head, "\r\n");
        const request_line = lines.next().?;
        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_s = parts.next().?;
        const path = parts.next().?;
        const method: transport.Method = if (std.mem.eql(u8, method_s, "GET")) .GET else if (std.mem.eql(u8, method_s, "HEAD")) .HEAD else .POST;

        var accept_header: ?[]const u8 = null;
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "accept")) {
                accept_header = std.mem.trim(u8, line[colon + 1 ..], " \t");
            }
        }

        const log_index = self.log.items.len;
        try self.log.append(self.allocator, .{ .method = method, .path = try self.allocator.dupe(u8, path) });

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        var resp = Reply{};
        defer resp.deinit(allocator);

        if (method == .GET and std.mem.eql(u8, path, "/directory")) {
            try self.directory(allocator, &resp);
        } else if ((method == .HEAD or method == .GET) and std.mem.eql(u8, path, "/new-nonce")) {
            resp.status = if (method == .HEAD) 200 else 204;
            if (!self.script.omit_nonce_on_head) {
                resp.nonce = if (self.script.bad_nonce_value_on_head) try allocator.dupe(u8, "bad nonce!") else try self.freshNonce(allocator);
            }
        } else if (method == .POST and std.mem.eql(u8, path, "/new-acct")) {
            try self.newAccount(allocator, body, log_index, &resp);
        } else if (method == .POST and std.mem.startsWith(u8, path, "/acct/")) {
            try self.accountGet(allocator, path, body, log_index, &resp);
        } else if (method == .POST and std.mem.eql(u8, path, "/new-order")) {
            try self.newOrder(allocator, body, log_index, &resp);
        } else if (method == .POST and std.mem.endsWith(u8, path, "/http-01")) {
            try self.challengeTrigger(allocator, path, body, log_index, &resp);
        } else if (method == .POST and std.mem.startsWith(u8, path, "/authz/")) {
            try self.authzGet(allocator, path, body, log_index, &resp);
        } else if (method == .POST and std.mem.endsWith(u8, path, "/finalize")) {
            try self.finalize(allocator, path, body, log_index, &resp);
        } else if (method == .POST and std.mem.startsWith(u8, path, "/order/")) {
            try self.orderGet(allocator, path, body, log_index, &resp);
        } else if (method == .POST and std.mem.startsWith(u8, path, "/cert/")) {
            try self.certGet(allocator, path, body, log_index, &resp, accept_header);
        } else {
            resp.status = 404;
            try resp.problem(allocator, "urn:ietf:params:acme:error:malformed");
        }
        self.log.items[log_index].status = resp.status;

        try self.serialize(allocator, &out, method, resp);
        return out.toOwnedSlice(allocator);
    }

    const Reply = struct {
        status: u16 = 200,
        content_type: []const u8 = "application/json",
        nonce: ?[]u8 = null,
        location: ?[]const u8 = null,
        retry_after: ?[]const u8 = null,
        body: []const u8 = "",
        body_owned: ?[]u8 = null,
        location_owned: ?[]u8 = null,

        fn deinit(self: *Reply, allocator: std.mem.Allocator) void {
            if (self.nonce) |n| allocator.free(n);
            if (self.body_owned) |b| allocator.free(b);
            if (self.location_owned) |l| allocator.free(l);
        }

        fn problem(self: *Reply, allocator: std.mem.Allocator, type_urn: []const u8) !void {
            self.content_type = "application/problem+json";
            self.body_owned = try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"detail\":\"secret-looking free text that must never be surfaced\",\"status\":{d}}}", .{ type_urn, self.status });
            self.body = self.body_owned.?;
        }
    };

    fn serialize(self: *FakeCa, allocator: std.mem.Allocator, out: *std.ArrayList(u8), method: transport.Method, resp: Reply) !void {
        const reason = switch (resp.status) {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            302 => "Found",
            else => "Status",
        };
        try out.print(allocator, "HTTP/1.1 {d} {s}\r\n", .{ resp.status, reason });
        try out.print(allocator, "Content-Type: {s}\r\n", .{resp.content_type});
        if (resp.nonce) |n| try out.print(allocator, "Replay-Nonce: {s}\r\n", .{n});
        if (resp.location) |l| try out.print(allocator, "Location: {s}\r\n", .{l});
        if (resp.retry_after) |r| try out.print(allocator, "Retry-After: {s}\r\n", .{r});
        try out.appendSlice(allocator, "Connection: close\r\n");
        if (method == .HEAD or resp.status == 204) {
            try out.appendSlice(allocator, "\r\n");
            return;
        }
        if (self.script.chunked) {
            try out.appendSlice(allocator, "Transfer-Encoding: chunked\r\n\r\n");
            var offset: usize = 0;
            while (offset < resp.body.len) {
                const n = @min(5, resp.body.len - offset);
                try out.print(allocator, "{x}\r\n", .{n});
                try out.appendSlice(allocator, resp.body[offset .. offset + n]);
                try out.appendSlice(allocator, "\r\n");
                offset += n;
            }
            try out.appendSlice(allocator, "0\r\n\r\n");
        } else {
            try out.print(allocator, "Content-Length: {d}\r\n\r\n", .{resp.body.len});
            try out.appendSlice(allocator, resp.body);
        }
    }

    fn freshNonce(self: *FakeCa, allocator: std.mem.Allocator) ![]u8 {
        self.nonce_seq += 1;
        const text = try std.fmt.allocPrint(allocator, "nonce-{d}-{x}", .{ self.nonce_seq, self.nonce_seq *% 0x9e3779b97f4a7c15 });
        errdefer allocator.free(text);
        const key = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(key);
        try self.valid_nonces.put(self.allocator, key, {});
        return text;
    }

    fn directory(self: *FakeCa, allocator: std.mem.Allocator, resp: *Reply) !void {
        if (self.script.directory_body) |override| {
            resp.body = override;
            return;
        }
        switch (self.script.directory) {
            .status_500 => {
                resp.status = 500;
                try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
                return;
            },
            .redirect => {
                resp.status = 302;
                resp.location = "https://169.254.169.254/latest/meta-data";
                return;
            },
            .not_json_content_type => resp.content_type = "text/html",
            else => {},
        }
        const body: []const u8 = switch (self.script.directory) {
            .malformed_json => "{\"newNonce\": ",
            .deep_json => "{\"newNonce\":[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]}",
            .missing_field => "{\"newNonce\":\"https://ca.test/new-nonce\",\"newAccount\":\"https://ca.test/new-acct\"}",
            .wrong_field_type => "{\"newNonce\":5,\"newAccount\":\"https://ca.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\"}",
            .cross_host_new_account => "{\"newNonce\":\"https://ca.test/new-nonce\",\"newAccount\":\"https://internal.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\"}",
            .cross_host_new_nonce => "{\"newNonce\":\"https://169.254.169.254/new-nonce\",\"newAccount\":\"https://ca.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\"}",
            .http_scheme_url => "{\"newNonce\":\"https://ca.test/new-nonce\",\"newAccount\":\"http://ca.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\"}",
            .userinfo_url => "{\"newNonce\":\"https://ca.test/new-nonce\",\"newAccount\":\"https://user@ca.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\"}",
            .huge_body => blk: {
                const big = try allocator.alloc(u8, 200 * 1024);
                @memset(big, ' ');
                resp.body_owned = big;
                break :blk big;
            },
            else => "{\"newNonce\":\"https://ca.test/new-nonce\",\"newAccount\":\"https://ca.test/new-acct\",\"newOrder\":\"https://ca.test/new-order\",\"meta\":{\"termsOfService\":\"https://ca.test/tos\",\"unknown\":[1,2,3]},\"extra\":\"ignored\"}",
        };
        resp.body = body;
    }

    const Verified = struct {
        ok: bool,
        problem: ?[]const u8 = null,
        used_kid: bool = false,
        account_index: ?usize = null,
        jwk: ?Account = null,
        payload: []u8 = &.{},
    };

    /// Verify a flattened JWS for `path`. `allocator` owns `payload`.
    fn verify(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8) !Verified {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return .{ .ok = false, .problem = "malformed" };
        defer parsed.deinit();
        if (parsed.value != .object) return .{ .ok = false, .problem = "malformed" };
        const obj = parsed.value.object;
        const protected_b64 = jsonStr(obj, "protected") orelse return .{ .ok = false, .problem = "malformed" };
        const payload_b64 = jsonStr(obj, "payload") orelse return .{ .ok = false, .problem = "malformed" };
        const sig_b64 = jsonStr(obj, "signature") orelse return .{ .ok = false, .problem = "malformed" };

        var header_buf: [1024]u8 = undefined;
        const header_len = b64url.Decoder.calcSizeForSlice(protected_b64) catch return .{ .ok = false, .problem = "malformed" };
        if (header_len > header_buf.len) return .{ .ok = false, .problem = "malformed" };
        b64url.Decoder.decode(header_buf[0..header_len], protected_b64) catch return .{ .ok = false, .problem = "malformed" };
        const header = std.json.parseFromSlice(std.json.Value, allocator, header_buf[0..header_len], .{}) catch return .{ .ok = false, .problem = "malformed" };
        defer header.deinit();
        if (header.value != .object) return .{ .ok = false, .problem = "malformed" };
        const h = header.value.object;

        const alg = jsonStr(h, "alg") orelse return .{ .ok = false, .problem = "malformed" };
        if (!std.mem.eql(u8, alg, "ES256")) return .{ .ok = false, .problem = "badSignatureAlgorithm" };

        // Nonce first (RFC 8555 §6.5): single-use.
        const nonce = jsonStr(h, "nonce") orelse return .{ .ok = false, .problem = "badNonce" };
        if (self.valid_nonces.fetchRemove(nonce)) |kv| {
            // Ownership of the key moves to the consumed set.
            try self.seen_nonce_uses.put(self.allocator, kv.key, 1);
        } else {
            // A nonce we issued and already accepted: the client reused it.
            if (self.seen_nonce_uses.contains(nonce)) self.nonce_reuse_detected = true;
            return .{ .ok = false, .problem = "badNonce" };
        }

        const url = jsonStr(h, "url") orelse return .{ .ok = false, .problem = "malformed" };
        const expected = try std.fmt.allocPrint(allocator, "{s}{s}", .{ self.base, path });
        defer allocator.free(expected);
        if (!std.mem.eql(u8, url, expected)) return .{ .ok = false, .problem = "unauthorized" };

        const has_jwk = h.get("jwk") != null;
        const has_kid = h.get("kid") != null;
        if (has_jwk == has_kid) return .{ .ok = false, .problem = "malformed" };

        var key = Account{ .x = undefined, .y = undefined };
        var account_index: ?usize = null;
        if (has_jwk) {
            const jwk = h.get("jwk").?;
            if (jwk != .object) return .{ .ok = false, .problem = "malformed" };
            const kty = jsonStr(jwk.object, "kty") orelse return .{ .ok = false, .problem = "malformed" };
            const crv = jsonStr(jwk.object, "crv") orelse return .{ .ok = false, .problem = "malformed" };
            if (!std.mem.eql(u8, kty, "EC") or !std.mem.eql(u8, crv, "P-256")) return .{ .ok = false, .problem = "badPublicKey" };
            const x = jsonStr(jwk.object, "x") orelse return .{ .ok = false, .problem = "malformed" };
            const y = jsonStr(jwk.object, "y") orelse return .{ .ok = false, .problem = "malformed" };
            if ((b64url.Decoder.calcSizeForSlice(x) catch 0) != 32 or (b64url.Decoder.calcSizeForSlice(y) catch 0) != 32) return .{ .ok = false, .problem = "malformed" };
            b64url.Decoder.decode(&key.x, x) catch return .{ .ok = false, .problem = "malformed" };
            b64url.Decoder.decode(&key.y, y) catch return .{ .ok = false, .problem = "malformed" };
        } else {
            const kid = jsonStr(h, "kid") orelse return .{ .ok = false, .problem = "malformed" };
            const prefix = try std.fmt.allocPrint(allocator, "{s}/acct/", .{self.base});
            defer allocator.free(prefix);
            if (!std.mem.startsWith(u8, kid, prefix)) return .{ .ok = false, .problem = "accountDoesNotExist" };
            const id = std.fmt.parseInt(usize, kid[prefix.len..], 10) catch return .{ .ok = false, .problem = "accountDoesNotExist" };
            if (id == 0 or id > self.accounts.items.len) return .{ .ok = false, .problem = "accountDoesNotExist" };
            account_index = id - 1;
            key = self.accounts.items[id - 1];
        }

        var sec1: [65]u8 = undefined;
        sec1[0] = 4;
        @memcpy(sec1[1..33], &key.x);
        @memcpy(sec1[33..65], &key.y);
        const public_key = Ecdsa.PublicKey.fromSec1(&sec1) catch return .{ .ok = false, .problem = "badPublicKey" };
        if ((b64url.Decoder.calcSizeForSlice(sig_b64) catch 0) != 64) return .{ .ok = false, .problem = "malformed" };
        var sig_bytes: [64]u8 = undefined;
        b64url.Decoder.decode(&sig_bytes, sig_b64) catch return .{ .ok = false, .problem = "malformed" };
        const input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_b64, payload_b64 });
        defer allocator.free(input);
        Ecdsa.Signature.fromBytes(sig_bytes).verify(input, public_key) catch return .{ .ok = false, .problem = "unauthorized" };

        const payload_len = b64url.Decoder.calcSizeForSlice(payload_b64) catch return .{ .ok = false, .problem = "malformed" };
        const payload = try allocator.alloc(u8, payload_len);
        errdefer allocator.free(payload);
        b64url.Decoder.decode(payload, payload_b64) catch return .{ .ok = false, .problem = "malformed" };
        return .{ .ok = true, .used_kid = has_kid, .account_index = account_index, .jwk = key, .payload = payload };
    }

    fn jsonStr(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
        const v = obj.get(name) orelse return null;
        return if (v == .string) v.string else null;
    }

    fn failPost(self: *FakeCa, allocator: std.mem.Allocator, v: Verified, resp: *Reply) !void {
        resp.status = 400;
        const problem = v.problem orelse "malformed";
        const urn = try std.fmt.allocPrint(allocator, "urn:ietf:params:acme:error:{s}", .{problem});
        defer allocator.free(urn);
        try resp.problem(allocator, urn);
        resp.nonce = try self.freshNonce(allocator);
    }

    fn newAccount(self: *FakeCa, allocator: std.mem.Allocator, body: []const u8, log_index: usize, resp: *Reply) !void {
        if (self.script.bad_nonce_remaining > 0) {
            self.script.bad_nonce_remaining -= 1;
            // Consume nothing: the client's nonce stays "issued" but the CA
            // rejects the request as stale, which is what a real CA does.
            resp.status = 400;
            try resp.problem(allocator, "urn:ietf:params:acme:error:badNonce");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        const v = try self.verify(allocator, "/new-acct", body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        switch (self.script.account) {
            .status_500 => {
                resp.status = 500;
                try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
                resp.nonce = try self.freshNonce(allocator);
                return;
            },
            .rate_limited => {
                resp.status = 429;
                resp.retry_after = "60";
                try resp.problem(allocator, "urn:ietf:params:acme:error:rateLimited");
                resp.nonce = try self.freshNonce(allocator);
                return;
            },
            .server_error_problem => {
                resp.status = 403;
                try resp.problem(allocator, "urn:ietf:params:acme:error:somethingNew");
                resp.nonce = try self.freshNonce(allocator);
                return;
            },
            else => {},
        }

        if (self.last_payload) |old| self.allocator.free(old);
        self.last_payload = try self.allocator.dupe(u8, v.payload);

        // Existing account for this key?
        var existing: ?usize = null;
        for (self.accounts.items, 0..) |a, i| {
            if (std.mem.eql(u8, &a.x, &v.jwk.?.x) and std.mem.eql(u8, &a.y, &v.jwk.?.y)) existing = i;
        }
        const created = existing == null;
        const index = existing orelse blk: {
            try self.accounts.append(self.allocator, v.jwk.?);
            break :blk self.accounts.items.len - 1;
        };

        resp.status = if (created) 201 else 200;
        if (self.script.account == .status_202) resp.status = 202;
        resp.body = if (self.script.account_body) |override| override else if (self.script.account == .invalid_status_body) "{\"status\":\"deactivated\"}" else "{\"status\":\"valid\"}";
        switch (self.script.account) {
            .text_plain_content_type => resp.content_type = "text/plain",
            .garbage_body => resp.body = "not json at all",
            .empty_body => resp.body = "",
            .huge_body => {
                const big = try allocator.alloc(u8, 200 * 1024);
                @memset(big, ' ');
                resp.body_owned = big;
                resp.body = big;
            },
            else => {},
        }
        if (!self.script.omit_nonce_on_post) resp.nonce = try self.freshNonce(allocator);
        const loc = try std.fmt.allocPrint(allocator, "{s}/acct/{d}", .{ self.base, index + 1 });
        switch (self.script.account) {
            .missing_location => allocator.free(loc),
            .cross_host_location => {
                allocator.free(loc);
                resp.location = "https://evil.test/acct/1";
            },
            .http_location => {
                allocator.free(loc);
                resp.location = "http://ca.test/acct/1";
            },
            else => {
                resp.location = loc;
                resp.location_owned = loc;
            },
        }
    }

    fn accountGet(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);
        resp.body = "{\"status\":\"valid\"}";
        resp.nonce = try self.freshNonce(allocator);
    }

    // -- orders / authorizations / finalize / download (#882) --------------

    fn trimSuffix(path: []const u8, suffix: []const u8) []const u8 {
        if (std.mem.endsWith(u8, path, suffix)) return path[0 .. path.len - suffix.len];
        return path;
    }

    fn parseTrailingId(path: []const u8, prefix: []const u8) ?usize {
        if (!std.mem.startsWith(u8, path, prefix)) return null;
        return std.fmt.parseInt(usize, path[prefix.len..], 10) catch null;
    }

    fn notFound(self: *FakeCa, allocator: std.mem.Allocator, resp: *Reply) !void {
        resp.status = 404;
        try resp.problem(allocator, "urn:ietf:params:acme:error:malformed");
        resp.nonce = try self.freshNonce(allocator);
    }

    fn buildFakeCertPem(allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "-----BEGIN CERTIFICATE-----\nZmFrZS1sZWFmLWNlcnRpZmljYXRlLWJ5dGVz\n-----END CERTIFICATE-----\n" ++
                "-----BEGIN CERTIFICATE-----\nZmFrZS1pbnRlcm1lZGlhdGUtY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
            .{},
        );
    }

    fn newOrder(self: *FakeCa, allocator: std.mem.Allocator, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, "/new-order", body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        const b = self.script.new_order;
        if (b.status_500) {
            resp.status = 500;
            try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (b.rate_limited) {
            resp.status = 429;
            resp.retry_after = "60";
            try resp.problem(allocator, "urn:ietf:params:acme:error:rateLimited");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (b.malformed_json) {
            resp.status = 201;
            resp.body = "{\"status\": ";
            const loc = try std.fmt.allocPrint(allocator, "{s}/order/1", .{self.base});
            resp.location = loc;
            resp.location_owned = loc;
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        const RequestIdentifier = struct { type: []const u8, value: []const u8 };
        const RequestJson = struct { identifiers: []const RequestIdentifier };
        const parsed = std.json.parseFromSlice(RequestJson, allocator, v.payload, .{}) catch {
            resp.status = 400;
            try resp.problem(allocator, "urn:ietf:params:acme:error:malformed");
            resp.nonce = try self.freshNonce(allocator);
            return;
        };
        defer parsed.deinit();

        // No `errdefer order.deinit(...)` here: once `order` is appended to
        // `self.orders` below, it is owned there and `FakeCa.deinit` frees
        // it; an errdefer spanning past that append would double-free on a
        // later allocation failure in this function (test-helper code, so a
        // leak on an injected OOM here -- never exercised by ordinary test
        // runs -- is an acceptable trade for not double-freeing).
        var order = Order{
            .polls_before_final = self.script.order_poll.polls_before_final,
            .rate_limited_remaining = self.script.order_poll.rate_limited_polls,
        };
        for (parsed.value.identifiers) |id| {
            try order.identifiers.append(self.allocator, try self.allocator.dupe(u8, id.value));
        }
        if (b.missing_identifier and order.identifiers.items.len > 0) {
            self.allocator.free(order.identifiers.pop().?);
        }
        if (b.extra_identifier) {
            try order.identifiers.append(self.allocator, try self.allocator.dupe(u8, "bogus-extra.example.com"));
        }

        for (order.identifiers.items) |id| {
            self.nonce_seq += 1;
            var token_buf: [22]u8 = undefined;
            const token = std.fmt.bufPrint(&token_buf, "token{d:0>17}", .{self.nonce_seq}) catch unreachable;
            try self.authorizations.append(self.allocator, .{
                .identifier = try self.allocator.dupe(u8, id),
                .token = try self.allocator.dupe(u8, token),
                .polls_before_final = self.script.authz.polls_before_final,
                .rate_limited_remaining = self.script.authz.rate_limited_polls,
            });
            try order.authz_ids.append(self.allocator, self.authorizations.items.len - 1);
        }

        try self.orders.append(self.allocator, order);
        const order_id = self.orders.items.len;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try buf.print(allocator, "{{\"status\":\"{s}\",\"identifiers\":[", .{b.status_override orelse "pending"});
        for (order.identifiers.items, 0..) |id, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.print(allocator, "{{\"type\":\"dns\",\"value\":\"{s}\"}}", .{id});
        }
        try buf.appendSlice(allocator, "],\"authorizations\":[");
        const authz_count = order.authz_ids.items.len;
        // `missing_authorization` drops the last entry while every
        // `identifiers[]` entry above stays intact, so the mismatch is in
        // the authorization count alone, not in which names were requested.
        const emitted_count = if (b.missing_authorization and authz_count > 0) authz_count - 1 else authz_count;
        for (order.authz_ids.items[0..emitted_count], 0..) |aid, i| {
            if (i > 0) try buf.append(allocator, ',');
            // `duplicate_authorization` replaces the *last* entry with the
            // first one's id (same count, a real repeated URL) rather than
            // appending an extra entry, so this scenario is distinguishable
            // from `authorizations.len > identifiers.len`.
            const effective_aid = if (b.duplicate_authorization and authz_count >= 2 and i == authz_count - 1)
                order.authz_ids.items[0]
            else
                aid;
            if (b.cross_host_authorization and i == 0) {
                try buf.print(allocator, "\"https://evil.test/authz/{d}\"", .{effective_aid + 1});
            } else {
                try buf.print(allocator, "\"{s}/authz/{d}\"", .{ self.base, effective_aid + 1 });
            }
        }
        try buf.appendSlice(allocator, "],\"finalize\":\"");
        if (b.cross_host_finalize) {
            try buf.appendSlice(allocator, "https://evil.test/order/1/finalize");
        } else {
            try buf.print(allocator, "{s}/order/{d}/finalize", .{ self.base, order_id });
        }
        try buf.appendSlice(allocator, "\"}");

        resp.status = 201;
        resp.body_owned = try buf.toOwnedSlice(allocator);
        resp.body = resp.body_owned.?;
        const loc = try std.fmt.allocPrint(allocator, "{s}/order/{d}", .{ self.base, order_id });
        resp.location = loc;
        resp.location_owned = loc;
        resp.nonce = try self.freshNonce(allocator);
    }

    fn authzGet(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        const id = parseTrailingId(path, "/authz/") orelse return self.notFound(allocator, resp);
        if (id == 0 or id > self.authorizations.items.len) return self.notFound(allocator, resp);
        const b = self.script.authz;
        if (b.status_500) {
            resp.status = 500;
            try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (b.malformed_json) {
            resp.body = "{\"status\": ";
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        var authz = &self.authorizations.items[id - 1];
        authz.get_count += 1;
        if (authz.triggered and authz.status == .pending) authz.status = .processing;
        if (authz.status == .processing) {
            if (authz.poll_count < authz.polls_before_final) {
                if (authz.rate_limited_remaining > 0) {
                    authz.rate_limited_remaining -= 1;
                    resp.status = 429;
                    resp.retry_after = "1";
                    try resp.problem(allocator, "urn:ietf:params:acme:error:rateLimited");
                    resp.nonce = try self.freshNonce(allocator);
                    return;
                }
                authz.poll_count += 1;
            } else {
                authz.status = if (b.final_status == .valid) .valid else .invalid;
            }
        }

        const status_str = @tagName(authz.status);
        const identifier_value = if (b.wrong_identifier)
            "attacker-controlled.example.net"
        else if (b.collapse_identifier and self.authorizations.items.len > 0)
            self.authorizations.items[0].identifier
        else if (b.swap_identifier_on_poll and id == 1 and authz.get_count > 1 and self.authorizations.items.len > 1)
            self.authorizations.items[1].identifier
        else
            authz.identifier;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try buf.print(allocator, "{{\"status\":\"{s}\",\"identifier\":{{\"type\":\"dns\",\"value\":\"{s}\"}},\"challenges\":[", .{ status_str, identifier_value });
        if (!b.no_http01) {
            if (b.cross_host_challenge) {
                try buf.print(allocator, "{{\"type\":\"http-01\",\"url\":\"https://evil.test/authz/{d}/http-01\",\"token\":\"{s}\"}}", .{ id, authz.token });
            } else {
                try buf.print(allocator, "{{\"type\":\"http-01\",\"url\":\"{s}/authz/{d}/http-01\",\"token\":\"{s}\"}}", .{ self.base, id, authz.token });
            }
            if (b.duplicate_http01) {
                // A second, distinct http-01 entry: different URL and token,
                // so a client that just takes "the first one" would trigger
                // and poll the wrong challenge without ever noticing.
                try buf.print(allocator, ",{{\"type\":\"http-01\",\"url\":\"{s}/authz/{d}/http-01-dup\",\"token\":\"{s}-dup\"}}", .{ self.base, id, authz.token });
            }
        }
        try buf.appendSlice(allocator, "]}");

        resp.body_owned = try buf.toOwnedSlice(allocator);
        resp.body = resp.body_owned.?;
        resp.nonce = try self.freshNonce(allocator);
    }

    fn challengeTrigger(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        const id = parseTrailingId(trimSuffix(path, "/http-01"), "/authz/") orelse return self.notFound(allocator, resp);
        if (id == 0 or id > self.authorizations.items.len) return self.notFound(allocator, resp);
        if (self.script.challenge.rejected) {
            resp.status = 403;
            try resp.problem(allocator, "urn:ietf:params:acme:error:unauthorized");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        var authz = &self.authorizations.items[id - 1];
        authz.triggered = true;
        if (authz.status == .pending) authz.status = .processing;
        resp.body = "{\"status\":\"processing\"}";
        resp.nonce = try self.freshNonce(allocator);
    }

    fn finalize(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        const id = parseTrailingId(trimSuffix(path, "/finalize"), "/order/") orelse return self.notFound(allocator, resp);
        if (id == 0 or id > self.orders.items.len) return self.notFound(allocator, resp);
        const b = self.script.finalize;
        if (b.status_500) {
            resp.status = 500;
            try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (b.rejected) {
            resp.status = 400;
            try resp.problem(allocator, "urn:ietf:params:acme:error:badCSR");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (b.malformed_json) {
            resp.body = "{\"status\": ";
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        var order = &self.orders.items[id - 1];
        order.finalized = true;
        order.status = .processing;
        resp.body = "{\"status\":\"processing\"}";
        resp.nonce = try self.freshNonce(allocator);
    }

    fn orderGet(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        const id = parseTrailingId(path, "/order/") orelse return self.notFound(allocator, resp);
        if (id == 0 or id > self.orders.items.len) return self.notFound(allocator, resp);
        const b = self.script.order_poll;
        if (b.malformed_json) {
            resp.body = "{\"status\": ";
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        var order = &self.orders.items[id - 1];
        if (order.finalized and order.status == .processing) {
            if (order.poll_count < order.polls_before_final) {
                if (order.rate_limited_remaining > 0) {
                    order.rate_limited_remaining -= 1;
                    resp.status = 429;
                    resp.retry_after = "1";
                    try resp.problem(allocator, "urn:ietf:params:acme:error:rateLimited");
                    resp.nonce = try self.freshNonce(allocator);
                    return;
                }
                order.poll_count += 1;
            } else {
                order.status = if (b.final_status == .valid) .valid else .invalid;
                if (order.status == .valid) {
                    const cert_pem = try buildFakeCertPem(self.allocator);
                    try self.certificates.append(self.allocator, cert_pem);
                    order.certificate_id = self.certificates.items.len;
                }
            }
        }

        const status_str = @tagName(order.status);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        if (order.status == .valid) {
            if (b.cross_host_certificate) {
                try buf.print(allocator, "{{\"status\":\"{s}\",\"certificate\":\"https://evil.test/cert/{d}\"}}", .{ status_str, order.certificate_id.? });
            } else {
                try buf.print(allocator, "{{\"status\":\"{s}\",\"certificate\":\"{s}/cert/{d}\"}}", .{ status_str, self.base, order.certificate_id.? });
            }
        } else {
            try buf.print(allocator, "{{\"status\":\"{s}\"}}", .{status_str});
        }

        resp.body_owned = try buf.toOwnedSlice(allocator);
        resp.body = resp.body_owned.?;
        resp.nonce = try self.freshNonce(allocator);
    }

    fn certGet(self: *FakeCa, allocator: std.mem.Allocator, path: []const u8, body: []const u8, log_index: usize, resp: *Reply, accept: ?[]const u8) !void {
        const v = try self.verify(allocator, path, body);
        defer allocator.free(v.payload);
        self.log.items[log_index].signature_ok = v.ok;
        self.log.items[log_index].used_kid = v.used_kid;
        if (!v.ok) return self.failPost(allocator, v, resp);

        // A real CA may content-negotiate; a client that still advertises
        // `Accept: application/json` for this POST-as-GET (design §5.1)
        // misrepresents what it can use, so this fake CA refuses it rather
        // than silently answering with PEM anyway.
        if (!std.mem.eql(u8, accept orelse "", "application/pem-certificate-chain")) {
            resp.status = 406;
            try resp.problem(allocator, "urn:ietf:params:acme:error:malformed");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }

        const id = parseTrailingId(path, "/cert/") orelse return self.notFound(allocator, resp);
        const b = self.script.cert;
        if (b.status_500) {
            resp.status = 500;
            try resp.problem(allocator, "urn:ietf:params:acme:error:serverInternal");
            resp.nonce = try self.freshNonce(allocator);
            return;
        }
        if (id == 0 or id > self.certificates.items.len) return self.notFound(allocator, resp);

        resp.content_type = "application/pem-certificate-chain";
        if (b.empty_body) {
            resp.body = "";
        } else if (b.huge_body) {
            const big = try allocator.alloc(u8, 200 * 1024);
            @memset(big, 'a');
            resp.body_owned = big;
            resp.body = big;
        } else {
            resp.body = self.certificates.items[id - 1];
        }
        resp.nonce = try self.freshNonce(allocator);
    }
};
