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

    const Account = struct { x: [32]u8, y: [32]u8 };

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
};
