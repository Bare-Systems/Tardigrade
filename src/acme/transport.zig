//! Bounded HTTPS transport for CA traffic (#832, design §6.3, §9.1, §9.3).
//!
//! One request per connection (`Connection: close`), serialized by the caller.
//! The wire is HTTP/1.1 over an abstract `Connection`; the production
//! `http/acme_tls_dialer.zig` implements it with the native `UpstreamTlsConn`
//! and a preloaded, refcounted trust-anchor snapshot (no filesystem access
//! after startup, so it keeps working after a privilege drop or chroot), and
//! tests implement it with an in-memory fake CA.
//!
//! Everything from the CA is hostile: the status line, every header, and the
//! body are parsed with hard caps (header count/bytes, body bytes, chunk
//! framing), redirects are failures, and the whole exchange runs under one
//! request deadline. Nothing here logs or returns a body to a log sink.

const std = @import("std");
const tls_core = @import("tls_core");
const zig_compat = @import("zig_compat");
const url_mod = @import("url.zig");

pub const Error = error{
    OutOfMemory,
    /// TCP connect or TLS handshake/verification failed.
    DialFailed,
    Timeout,
    /// The connection failed or closed before a complete response.
    ConnectionFailed,
    MalformedResponse,
    HeadersTooLarge,
    ResponseTooLarge,
    /// Any 3xx. CA traffic never follows redirects.
    RedirectRejected,
    RequestTooLarge,
    InvalidUrl,
};

pub const Method = enum {
    GET,
    HEAD,
    POST,

    fn name(self: Method) []const u8 {
        return @tagName(self);
    }
};

pub const Limits = struct {
    /// Connect + TLS + request + response, wall budget.
    request_deadline_ms: u32 = 15_000,
    /// JSON bodies (directory, account, order, ...). Certificate chains need
    /// the larger cap, passed per request by A3.
    max_body_bytes: usize = 64 * 1024,
    max_header_count: usize = 32,
    max_header_bytes: usize = 8 * 1024,
    max_request_body_bytes: usize = 16 * 1024,
};

// -- Abstract connection ------------------------------------------------------

pub const IoError = error{ Timeout, Closed, Failed };

pub const Connection = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ptr: *anyopaque, buf: []u8) IoError!usize,
        writeAll: *const fn (ptr: *anyopaque, data: []const u8) IoError!void,
        close: *const fn (ptr: *anyopaque) void,
    };

    fn read(self: Connection, buf: []u8) IoError!usize {
        return self.vtable.read(self.ptr, buf);
    }
    fn writeAll(self: Connection, data: []const u8) IoError!void {
        return self.vtable.writeAll(self.ptr, data);
    }
    fn close(self: Connection) void {
        self.vtable.close(self.ptr);
    }
};

pub const DialError = error{ OutOfMemory, DialFailed, Timeout };

pub const Dialer = struct {
    ptr: *anyopaque,
    /// `remaining_ms` is what is left of the request deadline; connect, TLS
    /// and all later I/O on the connection must complete within it.
    dialFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, host: []const u8, port: u16, remaining_ms: u32) DialError!Connection,
};

/// Monotonic millisecond clock; injectable so deadline tests are deterministic.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i64 = realNow,

    fn now(self: Clock) i64 {
        return self.nowFn(self.ctx);
    }

    fn realNow(_: ?*anyopaque) i64 {
        return @intCast(@divTrunc(zig_compat.monotonicNanoTimestamp(), std.time.ns_per_ms));
    }
};

// -- Response -----------------------------------------------------------------

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    /// Owned; empty for HEAD.
    body: []u8,
    nonce_buf: [256]u8 = undefined,
    nonce_len: usize = 0,
    location_buf: [url_mod.max_url_len]u8 = undefined,
    location_len: usize = 0,
    /// Delta-seconds form only; the HTTP-date form is ignored.
    retry_after_s: ?u32 = null,
    content_type_json: bool = false,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.body);
        self.* = undefined;
    }

    pub fn replayNonce(self: *const Response) ?[]const u8 {
        return if (self.nonce_len == 0) null else self.nonce_buf[0..self.nonce_len];
    }

    pub fn location(self: *const Response) ?[]const u8 {
        return if (self.location_len == 0) null else self.location_buf[0..self.location_len];
    }
};

// -- Transport ----------------------------------------------------------------

pub const Transport = struct {
    allocator: std.mem.Allocator,
    dialer: Dialer,
    limits: Limits = .{},
    clock: Clock = .{},

    pub fn request(
        self: *const Transport,
        method: Method,
        target: url_mod.Url,
        body: ?[]const u8,
        content_type: ?[]const u8,
    ) Error!Response {
        return self.requestWithBodyLimit(method, target, body, content_type, self.limits.max_body_bytes);
    }

    pub fn requestWithBodyLimit(
        self: *const Transport,
        method: Method,
        target: url_mod.Url,
        body: ?[]const u8,
        content_type: ?[]const u8,
        max_body_bytes: usize,
    ) Error!Response {
        if (body) |b| if (b.len > self.limits.max_request_body_bytes) return error.RequestTooLarge;
        const deadline = self.clock.now() + @as(i64, self.limits.request_deadline_ms);

        var host_buf: [url_mod.max_host_len + 8]u8 = undefined;
        const host_header = target.writeHostHeader(&host_buf) orelse return error.InvalidUrl;

        // The dialer gets the *remaining* budget, not a fresh one: connect and
        // TLS must fit in what is left of the single request deadline.
        const conn = self.dialer.dialFn(self.dialer.ptr, self.allocator, target.host, target.port, try self.remainingMs(deadline)) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Timeout => error.Timeout,
            error.DialFailed => error.DialFailed,
        };
        defer conn.close();

        // Request: head and body are assembled once so a failed write cannot
        // leave a half-sent, ambiguous message.
        var head_buf: [url_mod.max_url_len + 512]u8 = undefined;
        const head = std.fmt.bufPrint(
            &head_buf,
            "{s} {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: tardigrade-acme/1\r\nAccept: application/json\r\nConnection: close\r\n",
            .{ method.name(), target.target, host_header },
        ) catch return error.InvalidUrl;
        var tail_buf: [128]u8 = undefined;
        const tail = if (body) |b|
            std.fmt.bufPrint(&tail_buf, "Content-Type: {s}\r\nContent-Length: {d}\r\n\r\n", .{ content_type orelse "application/json", b.len }) catch unreachable
        else
            "\r\n";

        if (self.clock.now() > deadline) return error.Timeout;
        conn.writeAll(head) catch |err| return mapIo(err);
        conn.writeAll(tail) catch |err| return mapIo(err);
        if (body) |b| conn.writeAll(b) catch |err| return mapIo(err);

        var reader = Reader{ .conn = conn, .clock = self.clock, .deadline = deadline };
        return self.readResponse(&reader, method, max_body_bytes);
    }

    fn remainingMs(self: *const Transport, deadline: i64) Error!u32 {
        const remaining = deadline - self.clock.now();
        if (remaining <= 0) return error.Timeout;
        return @intCast(@min(remaining, @as(i64, std.math.maxInt(u32))));
    }

    fn readResponse(self: *const Transport, reader: *Reader, method: Method, max_body_bytes: usize) Error!Response {
        var line_buf: [8 * 1024]u8 = undefined;
        var header_bytes: usize = 0;

        const status_line = try reader.readLine(&line_buf);
        header_bytes += status_line.len + 2;
        const status = try parseStatusLine(status_line);
        if (status >= 300 and status < 400) return error.RedirectRejected;
        if (status < 200) return error.MalformedResponse;

        var resp = Response{ .allocator = self.allocator, .status = status, .body = &.{} };
        var content_length: ?usize = null;
        var chunked = false;
        var header_count: usize = 0;
        var seen_nonce = false;
        var seen_location = false;
        var seen_retry = false;
        var seen_content_type = false;

        while (true) {
            const line = try reader.readLine(&line_buf);
            header_bytes += line.len + 2;
            if (header_bytes > self.limits.max_header_bytes) return error.HeadersTooLarge;
            if (line.len == 0) break;
            header_count += 1;
            if (header_count > self.limits.max_header_count) return error.HeadersTooLarge;
            // No obs-fold, no stray control bytes.
            if (line[0] == ' ' or line[0] == '\t') return error.MalformedResponse;
            for (line) |c| if (c < 0x20 and c != '\t' or c == 0x7f) return error.MalformedResponse;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedResponse;
            const name = line[0..colon];
            if (name.len == 0 or std.mem.indexOfAny(u8, name, " \t") != null) return error.MalformedResponse;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                if (value.len == 0 or value.len > 12) return error.MalformedResponse;
                const parsed = std.fmt.parseInt(usize, value, 10) catch return error.MalformedResponse;
                if (content_length) |existing| {
                    if (existing != parsed) return error.MalformedResponse;
                }
                content_length = parsed;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.MalformedResponse;
                chunked = true;
            } else if (std.ascii.eqlIgnoreCase(name, "replay-nonce")) {
                // Two nonces would be ambiguous; refuse rather than pick one.
                if (seen_nonce) return error.MalformedResponse;
                seen_nonce = true;
                // Not validated here (the client decides what a bad nonce
                // means); only bounded so it cannot be stored unbounded.
                if (value.len > resp.nonce_buf.len) return error.MalformedResponse;
                @memcpy(resp.nonce_buf[0..value.len], value);
                resp.nonce_len = value.len;
            } else if (std.ascii.eqlIgnoreCase(name, "location")) {
                if (seen_location) return error.MalformedResponse;
                seen_location = true;
                if (value.len > resp.location_buf.len) return error.MalformedResponse;
                @memcpy(resp.location_buf[0..value.len], value);
                resp.location_len = value.len;
            } else if (std.ascii.eqlIgnoreCase(name, "retry-after")) {
                if (seen_retry) return error.MalformedResponse;
                seen_retry = true;
                resp.retry_after_s = parseDeltaSeconds(value);
            } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
                if (seen_content_type) return error.MalformedResponse;
                seen_content_type = true;
                resp.content_type_json = isJsonContentType(value);
            }
        }
        if (chunked and content_length != null) return error.MalformedResponse;

        const no_body = method == .HEAD or status == 204 or status == 304;
        if (no_body) return resp;

        if (chunked) {
            resp.body = try readChunked(self, reader, max_body_bytes);
        } else if (content_length) |len| {
            if (len > max_body_bytes) return error.ResponseTooLarge;
            const body = try self.allocator.alloc(u8, len);
            errdefer self.allocator.free(body);
            try reader.readExact(body);
            resp.body = body;
        } else {
            resp.body = try readToEof(self, reader, max_body_bytes);
        }
        return resp;
    }
};

fn mapIo(err: IoError) Error {
    return switch (err) {
        error.Timeout => error.Timeout,
        error.Closed, error.Failed => error.ConnectionFailed,
    };
}

fn parseStatusLine(line: []const u8) Error!u16 {
    // "HTTP/1.1 200 OK": exactly HTTP/1.1, a space, three digits, then a space
    // or end. HTTP/1.0 and anything else is not what an ACME CA speaks to us.
    const prefix = "HTTP/1.1 ";
    if (line.len < prefix.len + 3 or !std.mem.startsWith(u8, line, prefix)) return error.MalformedResponse;
    const digits = line[prefix.len .. prefix.len + 3];
    for (digits) |d| if (d < '0' or d > '9') return error.MalformedResponse;
    if (line.len > prefix.len + 3 and line[prefix.len + 3] != ' ') return error.MalformedResponse;
    return std.fmt.parseInt(u16, digits, 10) catch error.MalformedResponse;
}

fn parseDeltaSeconds(value: []const u8) ?u32 {
    if (value.len == 0 or value.len > 9) return null;
    for (value) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseInt(u32, value, 10) catch null;
}

fn isJsonContentType(value: []const u8) bool {
    const types = [_][]const u8{ "application/json", "application/problem+json" };
    for (types) |t| {
        if (value.len >= t.len and std.ascii.eqlIgnoreCase(value[0..t.len], t)) {
            if (value.len == t.len) return true;
            const next = value[t.len];
            if (next == ';' or next == ' ') return true;
        }
    }
    return false;
}

fn readToEof(self: *const Transport, reader: *Reader, max: usize) Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(self.allocator);
    var chunk: [2048]u8 = undefined;
    while (true) {
        const n = try reader.readSome(&chunk) orelse break;
        if (list.items.len + n > max) return error.ResponseTooLarge;
        try list.appendSlice(self.allocator, chunk[0..n]);
    }
    return list.toOwnedSlice(self.allocator);
}

fn readChunked(self: *const Transport, reader: *Reader, max: usize) Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(self.allocator);
    var line_buf: [128]u8 = undefined;
    while (true) {
        const size_line = try reader.readLine(&line_buf);
        // Chunk extensions are not used by ACME servers; refuse them rather
        // than parse attacker-controlled data we have no use for.
        if (size_line.len == 0 or size_line.len > 8) return error.MalformedResponse;
        for (size_line) |c| if (!std.ascii.isHex(c)) return error.MalformedResponse;
        const size = std.fmt.parseInt(usize, size_line, 16) catch return error.MalformedResponse;
        if (size == 0) break;
        if (size > max or list.items.len + size > max) return error.ResponseTooLarge;
        const start = list.items.len;
        try list.resize(self.allocator, start + size);
        try reader.readExact(list.items[start..]);
        const crlf = try reader.readLine(&line_buf);
        if (crlf.len != 0) return error.MalformedResponse;
    }
    // Trailers: consume and ignore, bounded.
    var trailer_lines: usize = 0;
    while (true) {
        const line = try reader.readLine(&line_buf);
        if (line.len == 0) break;
        trailer_lines += 1;
        if (trailer_lines > 8) return error.HeadersTooLarge;
    }
    return list.toOwnedSlice(self.allocator);
}

/// Small buffered reader enforcing the request deadline between reads.
const Reader = struct {
    conn: Connection,
    clock: Clock,
    deadline: i64,
    buf: [2048]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn fill(self: *Reader) Error!bool {
        if (self.clock.now() > self.deadline) return error.Timeout;
        self.start = 0;
        self.end = 0;
        const n = self.conn.read(&self.buf) catch |err| return mapIo(err);
        if (n == 0) return false;
        self.end = n;
        return true;
    }

    /// Up to `out.len` bytes; null at clean EOF.
    fn readSome(self: *Reader, out: []u8) Error!?usize {
        if (self.start == self.end and !try self.fill()) return null;
        const n = @min(out.len, self.end - self.start);
        @memcpy(out[0..n], self.buf[self.start .. self.start + n]);
        self.start += n;
        return n;
    }

    fn readExact(self: *Reader, out: []u8) Error!void {
        var filled: usize = 0;
        while (filled < out.len) {
            const n = try self.readSome(out[filled..]) orelse return error.ConnectionFailed;
            filled += n;
        }
    }

    /// One CRLF-terminated line (terminator stripped) into `out`. A bare LF,
    /// a line longer than `out`, or EOF mid-line is malformed.
    fn readLine(self: *Reader, out: []u8) Error![]u8 {
        var len: usize = 0;
        while (true) {
            if (self.start == self.end and !try self.fill()) return error.ConnectionFailed;
            const byte = self.buf[self.start];
            self.start += 1;
            if (byte == '\n') {
                if (len == 0 or out[len - 1] != '\r') return error.MalformedResponse;
                return out[0 .. len - 1];
            }
            if (len == out.len) return error.HeadersTooLarge;
            out[len] = byte;
            len += 1;
        }
    }
};

// -- Trust anchors (G10) ------------------------------------------------------

/// Refcounted preloaded CA trust-anchor snapshot. Loaded once at startup
/// (before any privilege drop/chroot); `release` frees it when the last holder
/// is done, so a reload can swap snapshots without freeing anchors under an
/// in-flight CA request.
pub const TrustAnchorSnapshot = struct {
    allocator: std.mem.Allocator,
    anchors: tls_core.webpki_verifier.TrustAnchors,
    refs: std.atomic.Value(u32),

    /// `ca_bundle_path` empty selects the first readable system bundle.
    pub fn load(allocator: std.mem.Allocator, ca_bundle_path: []const u8) !*TrustAnchorSnapshot {
        var anchors = try tls_core.webpki_verifier.loadTrustAnchors(allocator, ca_bundle_path);
        errdefer anchors.deinit(allocator);
        const snapshot = try allocator.create(TrustAnchorSnapshot);
        snapshot.* = .{ .allocator = allocator, .anchors = anchors, .refs = .init(1) };
        return snapshot;
    }

    pub fn retain(self: *TrustAnchorSnapshot) *TrustAnchorSnapshot {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous > 0);
        return self;
    }

    pub fn release(self: *TrustAnchorSnapshot) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            const allocator = self.allocator;
            self.anchors.deinit(allocator);
            allocator.destroy(self);
        }
    }
};

// ---------------------------------------------------------------------------

const testing = std.testing;

/// Scripted byte-level connection for parser tests: feeds `response` in
/// `chunk` byte slices and records what was written.
const ScriptConn = struct {
    allocator: std.mem.Allocator,
    response: []const u8,
    chunk: usize = 7,
    pos: usize = 0,
    written: std.ArrayList(u8) = .empty,
    clock: ?*TestClock = null,
    advance_per_read_ms: i64 = 0,
    fail_read_after: ?usize = null,

    fn vtable() *const Connection.VTable {
        return &.{ .read = read, .writeAll = writeAll, .close = close };
    }

    fn read(ptr: *anyopaque, buf: []u8) IoError!usize {
        const self: *ScriptConn = @ptrCast(@alignCast(ptr));
        if (self.clock) |c| c.now += self.advance_per_read_ms;
        if (self.fail_read_after) |limit| if (self.pos >= limit) return error.Failed;
        if (self.pos >= self.response.len) return 0;
        const n = @min(@min(self.chunk, buf.len), self.response.len - self.pos);
        @memcpy(buf[0..n], self.response[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }

    fn writeAll(ptr: *anyopaque, data: []const u8) IoError!void {
        const self: *ScriptConn = @ptrCast(@alignCast(ptr));
        self.written.appendSlice(self.allocator, data) catch return error.Failed;
    }

    fn close(_: *anyopaque) void {}

    fn dialer(self: *ScriptConn) Dialer {
        return .{ .ptr = self, .dialFn = dial };
    }

    fn dial(ptr: *anyopaque, _: std.mem.Allocator, _: []const u8, _: u16, _: u32) DialError!Connection {
        return .{ .ptr = ptr, .vtable = vtable() };
    }
};

const TestClock = struct {
    now: i64 = 1_000,

    fn clock(self: *TestClock) Clock {
        return .{ .ctx = self, .nowFn = tick };
    }

    fn tick(ctx: ?*anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
};

fn runScript(response: []const u8, limits: Limits, method: Method) (Error || url_mod.Error)!Response {
    var conn = ScriptConn{ .allocator = testing.allocator, .response = response };
    defer conn.written.deinit(testing.allocator);
    const transport = Transport{ .allocator = testing.allocator, .dialer = conn.dialer(), .limits = limits };
    const target = try url_mod.parse("https://ca.test/dir");
    return transport.request(method, target, null, null);
}

test "ACME transport: parses a normal response across tiny read chunks" {
    const wire = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nReplay-Nonce: abc_DEF-1\r\nLocation: https://ca.test/acct/1\r\nRetry-After: 7\r\nX-Other: ignored\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
    var resp = try runScript(wire, .{}, .GET);
    defer resp.deinit();
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expectEqualStrings("{\"ok\":true}", resp.body);
    try testing.expectEqualStrings("abc_DEF-1", resp.replayNonce().?);
    try testing.expectEqualStrings("https://ca.test/acct/1", resp.location().?);
    try testing.expectEqual(@as(?u32, 7), resp.retry_after_s);
    try testing.expect(resp.content_type_json);
}

test "ACME transport: request framing is exact and carries JOSE body" {
    var conn = ScriptConn{ .allocator = testing.allocator, .response = "HTTP/1.1 204 No Content\r\n\r\n" };
    defer conn.written.deinit(testing.allocator);
    const transport = Transport{ .allocator = testing.allocator, .dialer = conn.dialer() };
    const target = try url_mod.parse("https://ca.test:8443/new-acct?x=1");
    var resp = try transport.request(.POST, target, "{\"a\":1}", "application/jose+json");
    resp.deinit();
    try testing.expectEqualStrings(
        "POST /new-acct?x=1 HTTP/1.1\r\nHost: ca.test:8443\r\nUser-Agent: tardigrade-acme/1\r\nAccept: application/json\r\nConnection: close\r\nContent-Type: application/jose+json\r\nContent-Length: 7\r\n\r\n{\"a\":1}",
        conn.written.items,
    );
}

test "ACME transport: HEAD, 204 and 304 never read a body" {
    var head = try runScript("HTTP/1.1 200 OK\r\nReplay-Nonce: n1\r\nContent-Length: 500\r\n\r\n", .{}, .HEAD);
    defer head.deinit();
    try testing.expectEqual(@as(usize, 0), head.body.len);
    try testing.expectEqualStrings("n1", head.replayNonce().?);
    var none = try runScript("HTTP/1.1 204 No Content\r\n\r\n", .{}, .GET);
    none.deinit();
}

test "ACME transport: chunked bodies decode and are bounded" {
    var ok = try runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n", .{}, .GET);
    defer ok.deinit();
    try testing.expectEqualStrings("hello world", ok.body);

    const small = Limits{ .max_body_bytes = 8 };
    try testing.expectError(error.ResponseTooLarge, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", small, .GET));
    try testing.expectError(error.ResponseTooLarge, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n", small, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX\r\n0\r\n\r\n", .{}, .GET));
    try testing.expectError(error.ConnectionFailed, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", .{}, .GET));
}

test "ACME transport: body size caps are enforced before and during reads" {
    const limits = Limits{ .max_body_bytes = 16 };
    var at_limit = try runScript("HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n0123456789abcdef", limits, .GET);
    at_limit.deinit();
    try testing.expectError(error.ResponseTooLarge, runScript("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n0123456789abcdefg", limits, .GET));
    // Declared length absurdly large: rejected without allocating it.
    try testing.expectError(error.ResponseTooLarge, runScript("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n", .{}, .GET));
    // No framing at all: read-to-EOF is capped too.
    try testing.expectError(error.ResponseTooLarge, runScript("HTTP/1.1 200 OK\r\n\r\n0123456789abcdefg", limits, .GET));
    var eof = try runScript("HTTP/1.1 200 OK\r\n\r\n0123456789", limits, .GET);
    defer eof.deinit();
    try testing.expectEqualStrings("0123456789", eof.body);
    // Truncated: body shorter than declared.
    try testing.expectError(error.ConnectionFailed, runScript("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", .{}, .GET));
}

test "ACME transport: redirects and informational responses are failures" {
    for ([_]u16{ 301, 302, 303, 307, 308 }) |code| {
        var buf: [96]u8 = undefined;
        const wire = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} Moved\r\nLocation: https://127.0.0.1/\r\nContent-Length: 0\r\n\r\n", .{code});
        try testing.expectError(error.RedirectRejected, runScript(wire, .{}, .GET));
    }
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 100 Continue\r\n\r\n", .{}, .GET));
}

test "ACME transport: header limits and hostile headers fail closed" {
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.0 200 OK\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 2xx OK\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200OK\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("garbage\r\n\r\n", .{}, .GET));
    // Bare LF line endings.
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\nContent-Length: 0\n\n", .{}, .GET));
    // obs-fold, missing colon, control bytes, space in name.
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nA: b\r\n c\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nnocolon\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nA: b\x00c\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nA B: c\r\n\r\n", .{}, .GET));
    // Request-smuggling shapes.
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", .{}, .GET));
    // Ambiguous nonce / location.
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nReplay-Nonce: a\r\nReplay-Nonce: b\r\nContent-Length: 0\r\n\r\n", .{}, .GET));
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nLocation: a\r\nLocation: b\r\nContent-Length: 0\r\n\r\n", .{}, .GET));

    // Count and byte caps.
    const few = Limits{ .max_header_count = 3 };
    try testing.expectError(error.HeadersTooLarge, runScript("HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nContent-Length: 0\r\n\r\n", few, .GET));
    const tiny = Limits{ .max_header_bytes = 64 };
    try testing.expectError(error.HeadersTooLarge, runScript("HTTP/1.1 200 OK\r\nX: " ++ ("a" ** 80) ++ "\r\nContent-Length: 0\r\n\r\n", tiny, .GET));
    // A single endless line cannot exceed the line buffer.
    const endless = "HTTP/1.1 200 OK\r\nX: " ++ ("a" ** 9000) ++ "\r\n\r\n";
    try testing.expectError(error.HeadersTooLarge, runScript(endless, .{}, .GET));
    // Oversized Location / Replay-Nonce values are refused, not truncated.
    try testing.expectError(error.MalformedResponse, runScript("HTTP/1.1 200 OK\r\nReplay-Nonce: " ++ ("a" ** 257) ++ "\r\nContent-Length: 0\r\n\r\n", .{}, .GET));
}

test "ACME transport: Retry-After keeps only delta-seconds" {
    var a = try runScript("HTTP/1.1 429 Too Many\r\nRetry-After: 120\r\nContent-Length: 0\r\n\r\n", .{}, .GET);
    defer a.deinit();
    try testing.expectEqual(@as(?u32, 120), a.retry_after_s);
    var b = try runScript("HTTP/1.1 429 Too Many\r\nRetry-After: Wed, 21 Oct 2026 07:28:00 GMT\r\nContent-Length: 0\r\n\r\n", .{}, .GET);
    defer b.deinit();
    try testing.expectEqual(@as(?u32, null), b.retry_after_s);
    var c = try runScript("HTTP/1.1 429 Too Many\r\nRetry-After: 99999999999\r\nContent-Length: 0\r\n\r\n", .{}, .GET);
    defer c.deinit();
    try testing.expectEqual(@as(?u32, null), c.retry_after_s);
}

test "ACME transport: deadline expires on a slow peer" {
    var clock = TestClock{};
    var conn = ScriptConn{
        .allocator = testing.allocator,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd",
        .chunk = 1,
        .clock = &clock,
        .advance_per_read_ms = 1_000,
    };
    defer conn.written.deinit(testing.allocator);
    const transport = Transport{
        .allocator = testing.allocator,
        .dialer = conn.dialer(),
        .limits = .{ .request_deadline_ms = 5_000 },
        .clock = clock.clock(),
    };
    const target = try url_mod.parse("https://ca.test/dir");
    try testing.expectError(error.Timeout, transport.request(.GET, target, null, null));
}

test "ACME transport: connection failure mid-response is a transport error" {
    var conn = ScriptConn{
        .allocator = testing.allocator,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" ++ ("x" ** 100),
        .fail_read_after = 30,
    };
    defer conn.written.deinit(testing.allocator);
    const transport = Transport{ .allocator = testing.allocator, .dialer = conn.dialer() };
    const target = try url_mod.parse("https://ca.test/dir");
    try testing.expectError(error.ConnectionFailed, transport.request(.GET, target, null, null));
}

test "ACME transport: oversized request bodies are refused before dialing" {
    var conn = ScriptConn{ .allocator = testing.allocator, .response = "" };
    defer conn.written.deinit(testing.allocator);
    const transport = Transport{ .allocator = testing.allocator, .dialer = conn.dialer(), .limits = .{ .max_request_body_bytes = 4 } };
    const target = try url_mod.parse("https://ca.test/dir");
    try testing.expectError(error.RequestTooLarge, transport.request(.POST, target, "12345", null));
    try testing.expectEqual(@as(usize, 0), conn.written.items.len);
}

test "ACME transport: trust-anchor snapshot is refcounted" {
    const snapshot = try TrustAnchorSnapshot.load(testing.allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    const second = snapshot.retain();
    try testing.expect(snapshot.anchors.anchors().len > 0);
    snapshot.release();
    // Still usable: the second holder keeps it alive (testing allocator would
    // flag a use-after-free or a leak).
    try testing.expect(second.anchors.anchors().len > 0);
    second.release();
    if (TrustAnchorSnapshot.load(testing.allocator, "no/such/bundle.pem")) |loaded| {
        loaded.release();
        return error.TestUnexpectedResult;
    } else |_| {}
}

fn fuzzResponseParser(_: void, smith: *testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len = smith.slice(&buf);
    const chunk = smith.valueRangeAtMost(u8, 1, 64);
    var conn = ScriptConn{ .allocator = testing.allocator, .response = buf[0..len], .chunk = chunk };
    defer conn.written.deinit(testing.allocator);
    const limits = Limits{ .max_body_bytes = 256, .max_header_bytes = 512, .max_header_count = 8 };
    const transport = Transport{ .allocator = testing.allocator, .dialer = conn.dialer(), .limits = limits };
    const target = try url_mod.parse("https://ca.test/dir");
    var resp = transport.request(.GET, target, null, null) catch return;
    defer resp.deinit();
    try testing.expect(resp.body.len <= limits.max_body_bytes);
}

test "fuzz: ACME: HTTP response parser is bounded on hostile CA bytes" {
    try testing.fuzz({}, fuzzResponseParser, .{ .corpus = &.{
        "",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: https://169.254.169.254/\r\n\r\n",
        "HTTP/1.1 200 OK\r\nReplay-Nonce: a\r\nReplay-Nonce: b\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4294967296\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
        &([_]u8{'a'} ** 600),
    } });
}
