const std = @import("std");
const compat = @import("zig_compat");
const Allocator = std.mem.Allocator;
const Request = @import("request.zig").Request;
const RequestLifecycle = @import("request_lifecycle.zig").RequestLifecycle;
const access_control = @import("access_control.zig");

pub const EarlyDataContext = struct {
    transport_early: bool = false,
    inbound_marker: bool = false,
    downstream_handshake: ?DownstreamHandshakeBarrier = null,

    pub fn replayExposed(self: EarlyDataContext) bool {
        return self.transport_early or self.inbound_marker;
    }

    pub fn mayRetryUpstream425(self: EarlyDataContext) bool {
        return self.transport_early and !self.inbound_marker;
    }

    pub fn downstreamHandshakeComplete(self: EarlyDataContext) bool {
        const barrier = self.downstream_handshake orelse return true;
        return barrier.isComplete();
    }

    pub fn waitOrDriveDownstreamHandshake(self: EarlyDataContext) !void {
        const barrier = self.downstream_handshake orelse return;
        try barrier.waitOrDrive();
    }

    pub fn source(self: EarlyDataContext) EarlyDataSource {
        return if (self.transport_early and self.inbound_marker)
            .both
        else if (self.transport_early)
            .transport
        else if (self.inbound_marker)
            .header
        else
            .none;
    }
};

pub const EarlyDataSource = enum {
    none,
    transport,
    header,
    both,
};

pub const EarlyDataAction = enum {
    ordinary,
    accepted,
    too_early,
    forwarded,
    retried,
    deferred,
};

pub const EarlyDataRetryResult = enum {
    none,
    success,
    too_early,
    failure,
};

pub const DownstreamHandshakeBarrier = struct {
    ctx: *anyopaque,
    is_complete_fn: *const fn (*anyopaque) bool,
    wait_or_drive_fn: *const fn (*anyopaque) anyerror!void,

    pub fn isComplete(self: DownstreamHandshakeBarrier) bool {
        return self.is_complete_fn(self.ctx);
    }

    pub fn waitOrDrive(self: DownstreamHandshakeBarrier) !void {
        try self.wait_or_drive_fn(self.ctx);
    }
};

/// Per-request context propagated through the middleware pipeline.
///
/// Captures identity, timing, and metadata so downstream handlers
/// can make authorization and auditing decisions without re-parsing
/// headers.
pub const RequestContext = struct {
    allocator: Allocator,
    /// Unique request identifier (correlation ID).
    request_id: []const u8,
    /// Authenticated identity (bearer token hash, device id, etc.) or null.
    identity: ?[]const u8,
    /// Asserted upstream-facing user identifier when auth carries one.
    user_id: ?[]const u8,
    /// Asserted upstream-facing device identifier when auth carries one.
    device_id: ?[]const u8,
    /// Space-delimited scopes asserted for the authenticated request.
    scopes: ?[]const u8,
    /// Whether the request passed authentication.
    authenticated: bool,
    /// Monotonic start time for latency tracking (nanoseconds).
    started_ns: i128,
    /// Millisecond wall-clock start (for audit logs).
    started_ms: i64,
    /// Client IP address.
    client_ip: []const u8,
    /// API version extracted from the path (e.g. 1 for /v1/...).
    api_version: ?u16,
    /// Idempotency key if provided.
    idempotency_key: ?[]const u8,
    /// HTTP early-data provenance for this request hop and prior hops.
    early_data: EarlyDataContext,
    /// Bounded early-data action label for observability.
    early_data_action: EarlyDataAction,
    /// Bounded retry result label for upstream 425 retry observability.
    early_data_retry_result: EarlyDataRetryResult,
    /// Upstream address selected for proxied requests.
    upstream_addr: ?[]const u8,
    /// Final upstream status observed for proxied requests.
    upstream_status: ?u16,
    /// Response body bytes written back to the client when tracked.
    response_bytes: usize,
    /// Request lifecycle tracker (deadline, cancellation). Null for short-circuit paths
    /// that return before a full lifecycle is created (e.g. 400/405 early rejections).
    lifecycle: ?*RequestLifecycle,

    pub fn init(allocator: Allocator, request_id: []const u8, client_ip: []const u8) RequestContext {
        return .{
            .allocator = allocator,
            .request_id = request_id,
            .identity = null,
            .user_id = null,
            .device_id = null,
            .scopes = null,
            .authenticated = false,
            .started_ns = compat.nanoTimestamp(),
            .started_ms = compat.milliTimestamp(),
            .client_ip = client_ip,
            .api_version = null,
            .idempotency_key = null,
            .early_data = .{},
            .early_data_action = .ordinary,
            .early_data_retry_result = .none,
            .upstream_addr = null,
            .upstream_status = null,
            .response_bytes = 0,
            .lifecycle = null,
        };
    }

    /// Elapsed milliseconds since request started.
    pub fn elapsedMs(self: *const RequestContext) i64 {
        return compat.milliTimestamp() - self.started_ms;
    }

    /// Set authenticated identity.
    pub fn setIdentity(self: *RequestContext, id: []const u8) void {
        self.identity = id;
        self.authenticated = true;
    }

    /// Set the asserted auth context that will be forwarded upstream.
    pub fn setAuthContext(
        self: *RequestContext,
        identity: []const u8,
        user_id: ?[]const u8,
        device_id: ?[]const u8,
        scopes: ?[]const u8,
    ) void {
        self.identity = identity;
        self.user_id = user_id;
        self.device_id = device_id;
        self.scopes = scopes;
        self.authenticated = true;
    }

    /// Set API version.
    pub fn setApiVersion(self: *RequestContext, version: u16) void {
        self.api_version = version;
    }

    /// Set idempotency key.
    pub fn setIdempotencyKey(self: *RequestContext, key: []const u8) void {
        self.idempotency_key = key;
    }

    pub fn setUpstreamResult(self: *RequestContext, upstream_addr: []const u8, upstream_status: u16, response_bytes: usize) void {
        self.upstream_addr = self.allocator.dupe(u8, upstream_addr) catch upstream_addr;
        self.upstream_status = upstream_status;
        self.response_bytes = response_bytes;
    }

    /// Format a structured audit log line.
    pub fn auditLog(self: *const RequestContext, route: []const u8, status: u16) void {
        std.log.info(
            "audit route={s} status={d} auth={} identity={s} correlation_id={s} api_version={?d} client_ip={s} latency_ms={d}",
            .{
                route,
                status,
                self.authenticated,
                self.identity orelse "-",
                self.request_id,
                self.api_version,
                self.client_ip,
                self.elapsedMs(),
            },
        );
    }
};

/// `extractClientIp` trusted-proxy set for callers with no trusted hops:
/// every `X-Forwarded-For` entry is treated as untrusted, so the rightmost
/// one (the address the connecting peer itself observed) is the client.
pub const no_trusted_proxies = struct {
    pub fn isTrustedProxy(_: @This(), _: []const u8) bool {
        return false;
    }
}{};

/// Extract the client IP from request headers or connection info.
///
/// `trusted_forwarding_source` gates whether client-supplied forwarding
/// headers are honored at all. This value is resolved by the caller
/// (edge_gateway.zig) against `trusted_upstream_identities` /
/// `trust_require_upstream_identity` -- the SAME trust boundary
/// `docs/PROXY_SECURITY.md` §7 documents for the outbound `X-Forwarded-For`
/// Tardigrade sends to its own upstream (#673). When it is false, `default`
/// (the real connection IP) is always returned, exactly as if no forwarding
/// headers were present.
///
/// For a trusted peer, the client is resolved in this order:
/// 1. `real_ip_header` (e.g. `CF-Connecting-IP`), when configured and it
///    holds a valid IP. A CDN overwrites this header, so the client cannot
///    choose its value.
/// 2. `X-Forwarded-For`, walked from the RIGHT (nginx `real_ip_recursive
///    on`): each entry was appended by the hop to its right, so entries are
///    skipped only while they are themselves trusted proxies
///    (`trusted_proxies.isTrustedProxy(ip)`); the first untrusted address is
///    the client. The LEFTMOST entry is whatever the client sent -- CDNs and
///    proxies append to it rather than replace it -- so before #791 taking
///    it let any client behind a trusted CDN pick its own `client_ip`,
///    bypassing per-IP rate limiting and forging access-log addresses. The
///    walk stops at the first entry that is empty or not a valid IP.
/// 3. `X-Real-IP`, when it holds a valid IP (also when `X-Forwarded-For`
///    yields no usable address).
/// 4. `default`.
pub fn extractClientIp(
    request: *const Request,
    trusted_forwarding_source: bool,
    real_ip_header: []const u8,
    trusted_proxies: anytype,
    default: []const u8,
) []const u8 {
    if (!trusted_forwarding_source) return default;

    if (real_ip_header.len > 0) {
        if (request.headers.get(real_ip_header)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t");
            if (access_control.parseIp(trimmed) != null) return trimmed;
        }
    }

    if (request.headers.contains("x-forwarded-for")) {
        if (rightmostUntrustedForwardedFor(request, trusted_proxies)) |ip| return ip;
    }

    if (request.headers.get("x-real-ip")) |xri| {
        const trimmed = std.mem.trim(u8, xri, " \t");
        if (access_control.parseIp(trimmed) != null) return trimmed;
    }
    return default;
}

/// Walk every `X-Forwarded-For` entry right to left -- across repeated
/// header lines, which RFC 9110 §5.3 defines as one comma-joined list --
/// returning the first address that is not a trusted proxy. An empty or
/// unparseable member ends the walk: nothing left of it is attested by a
/// trusted hop. If every entry reached is trusted, the leftmost of them is
/// returned; null when the rightmost member is already unusable.
fn rightmostUntrustedForwardedFor(request: *const Request, trusted_proxies: anytype) ?[]const u8 {
    var candidate: ?[]const u8 = null;
    const all = request.headers.iterator();
    var line_idx = all.len;
    while (line_idx > 0) {
        line_idx -= 1;
        const header = all[line_idx];
        if (!std.ascii.eqlIgnoreCase(header.name, "x-forwarded-for")) continue;
        var it = std.mem.splitBackwardsScalar(u8, header.value, ',');
        while (it.next()) |raw_entry| {
            const entry = std.mem.trim(u8, raw_entry, " \t");
            if (access_control.parseIp(entry) == null) return candidate;
            candidate = entry;
            if (!trusted_proxies.isTrustedProxy(entry)) return candidate;
        }
    }
    return candidate;
}

// Tests

test "RequestContext tracks timing and identity" {
    const allocator = std.testing.allocator;
    var ctx = RequestContext.init(allocator, "req-001", "127.0.0.1");

    try std.testing.expect(!ctx.authenticated);
    try std.testing.expect(ctx.identity == null);
    try std.testing.expectEqualStrings("req-001", ctx.request_id);

    ctx.setIdentity("user-abc");
    try std.testing.expect(ctx.authenticated);
    try std.testing.expectEqualStrings("user-abc", ctx.identity.?);
}

test "RequestContext tracks asserted user scope context" {
    const allocator = std.testing.allocator;
    var ctx = RequestContext.init(allocator, "req-003", "127.0.0.1");

    ctx.setAuthContext("user-42", "user-42", "bearclaw-web", "bearclaw.operator");
    try std.testing.expect(ctx.authenticated);
    try std.testing.expectEqualStrings("user-42", ctx.identity.?);
    try std.testing.expectEqualStrings("user-42", ctx.user_id.?);
    try std.testing.expectEqualStrings("bearclaw-web", ctx.device_id.?);
    try std.testing.expectEqualStrings("bearclaw.operator", ctx.scopes.?);
}

test "RequestContext setApiVersion and setIdempotencyKey" {
    const allocator = std.testing.allocator;
    var ctx = RequestContext.init(allocator, "req-002", "10.0.0.1");

    try std.testing.expect(ctx.api_version == null);
    ctx.setApiVersion(2);
    try std.testing.expectEqual(@as(u16, 2), ctx.api_version.?);

    try std.testing.expect(ctx.idempotency_key == null);
    ctx.setIdempotencyKey("idem-xyz");
    try std.testing.expectEqualStrings("idem-xyz", ctx.idempotency_key.?);
}

test "EarlyDataContext tracks current and prior hop exposure" {
    try std.testing.expect(!(@as(EarlyDataContext, .{}).replayExposed()));
    try std.testing.expect((@as(EarlyDataContext, .{ .transport_early = true })).replayExposed());
    try std.testing.expect((@as(EarlyDataContext, .{ .inbound_marker = true })).replayExposed());
}

test "EarlyDataContext retries upstream 425 only for current-hop early data" {
    try std.testing.expect(!(@as(EarlyDataContext, .{})).mayRetryUpstream425());
    try std.testing.expect((@as(EarlyDataContext, .{ .transport_early = true })).mayRetryUpstream425());
    try std.testing.expect(!(@as(EarlyDataContext, .{ .inbound_marker = true })).mayRetryUpstream425());
    try std.testing.expect(!(@as(EarlyDataContext, .{ .transport_early = true, .inbound_marker = true })).mayRetryUpstream425());
}

const TestHandshakeBarrier = struct {
    complete: bool = false,
    waits: usize = 0,

    fn isComplete(ptr: *anyopaque) bool {
        const self: *TestHandshakeBarrier = @ptrCast(@alignCast(ptr));
        return self.complete;
    }

    fn waitOrDrive(ptr: *anyopaque) anyerror!void {
        const self: *TestHandshakeBarrier = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        self.complete = true;
    }

    fn barrier(self: *TestHandshakeBarrier) DownstreamHandshakeBarrier {
        return .{
            .ctx = self,
            .is_complete_fn = isComplete,
            .wait_or_drive_fn = waitOrDrive,
        };
    }
};

test "EarlyDataContext handshake barrier defaults complete and can be driven" {
    try std.testing.expect((@as(EarlyDataContext, .{})).downstreamHandshakeComplete());

    var test_barrier = TestHandshakeBarrier{};
    var ctx = EarlyDataContext{ .downstream_handshake = test_barrier.barrier() };
    try std.testing.expect(!ctx.downstreamHandshakeComplete());
    try ctx.waitOrDriveDownstreamHandshake();
    try std.testing.expect(ctx.downstreamHandshakeComplete());
    try std.testing.expectEqual(@as(usize, 1), test_barrier.waits);
}

/// Test trusted-proxy set: 10.0.0.0/8 stands in for a CDN/sidecar tier.
const TestTrustedProxies = struct {
    pub fn isTrustedProxy(_: TestTrustedProxies, ip: []const u8) bool {
        const block = access_control.parseCidr("10.0.0.0/8").?;
        const parsed = access_control.parseIp(ip) orelse return false;
        return block.contains(parsed);
    }
};

fn expectClientIp(raw: []const u8, trusted: bool, real_ip_header: []const u8, trusted_proxies: anytype, default: []const u8, expected: []const u8) !void {
    const result = try Request.parse(std.testing.allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();
    try std.testing.expectEqualStrings(expected, extractClientIp(&req, trusted, real_ip_header, trusted_proxies, default));
}

test "extractClientIp takes the rightmost X-Forwarded-For entry, not the client-chosen leftmost (#791)" {
    // A client behind a CDN sends `X-Forwarded-For: 203.0.113.7`; the CDN
    // appends the real address. Taking the first entry let every request
    // pick its own rate-limit bucket and access-log address.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7, 198.51.100.20\r\n\r\n",
        true,
        "",
        no_trusted_proxies,
        "127.0.0.1",
        "198.51.100.20",
    );
}

test "extractClientIp skips trusted proxy hops right to left (#791)" {
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7, 198.51.100.20, 10.0.0.5, 10.0.0.6\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "198.51.100.20",
    );
    // Every hop trusted: the leftmost is the best remaining answer.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 10.0.0.1, 10.0.0.2\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "10.0.0.1",
    );
}

test "extractClientIp walks repeated X-Forwarded-For lines as one list (#791)" {
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-For: 198.51.100.20, 10.0.0.5\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "198.51.100.20",
    );
}

test "extractClientIp stops the walk at an invalid X-Forwarded-For entry (#791)" {
    // The walk never crosses garbage to reach a client-chosen address.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7, unknown, 10.0.0.5\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "10.0.0.5",
    );
    // An invalid rightmost entry falls back to the connection address.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7, not-an-ip\r\n\r\n",
        true,
        "",
        no_trusted_proxies,
        "127.0.0.1",
        "127.0.0.1",
    );
}

test "extractClientIp does not cross an empty X-Forwarded-For member (#791)" {
    // `203.0.113.7, , 10.0.0.5`: the empty member is not attested by the
    // trusted hop, so the walk must stop at 10.0.0.5 rather than skip it.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7, , 10.0.0.5\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "10.0.0.5",
    );
    // Same boundary across repeated header lines: an empty trailing member
    // on the first line stops the walk before its client-chosen address.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7,\r\nX-Forwarded-For: 10.0.0.5\r\n\r\n",
        true,
        "",
        TestTrustedProxies{},
        "127.0.0.1",
        "10.0.0.5",
    );
}

test "extractClientIp falls through unusable X-Forwarded-For to X-Real-IP (#791)" {
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: not-an-ip\r\nX-Real-IP: 198.51.100.20\r\n\r\n",
        true,
        "",
        no_trusted_proxies,
        "127.0.0.1",
        "198.51.100.20",
    );
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: \r\nX-Real-IP: 198.51.100.20\r\n\r\n",
        true,
        "",
        no_trusted_proxies,
        "127.0.0.1",
        "198.51.100.20",
    );
    // Neither usable: the connection address.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: not-an-ip\r\nX-Real-IP: also-not\r\n\r\n",
        true,
        "",
        no_trusted_proxies,
        "127.0.0.1",
        "127.0.0.1",
    );
}

test "extractClientIp prefers the configured real-IP header (#791)" {
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nCF-Connecting-IP: 198.51.100.20\r\nX-Forwarded-For: 203.0.113.7, 198.51.100.21\r\n\r\n",
        true,
        "CF-Connecting-IP",
        no_trusted_proxies,
        "127.0.0.1",
        "198.51.100.20",
    );
    // An invalid or missing real-IP header falls through to X-Forwarded-For.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nCF-Connecting-IP: bogus\r\nX-Forwarded-For: 203.0.113.7, 198.51.100.21\r\n\r\n",
        true,
        "CF-Connecting-IP",
        no_trusted_proxies,
        "127.0.0.1",
        "198.51.100.21",
    );
    // The real-IP header is honored only from a trusted forwarding source.
    try expectClientIp(
        "GET / HTTP/1.1\r\nHost: localhost\r\nCF-Connecting-IP: 198.51.100.20\r\n\r\n",
        false,
        "CF-Connecting-IP",
        no_trusted_proxies,
        "127.0.0.1",
        "127.0.0.1",
    );
}

test "extractClientIp falls back to X-Real-IP" {
    const allocator = std.testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 9.8.7.6\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, true, "", no_trusted_proxies, "fallback");
    try std.testing.expectEqualStrings("9.8.7.6", ip);
}

test "extractClientIp uses default when no proxy headers" {
    const allocator = std.testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, true, "", no_trusted_proxies, "192.168.1.1");
    try std.testing.expectEqualStrings("192.168.1.1", ip);
}

test "extractClientIp ignores X-Forwarded-For/X-Real-IP from an untrusted forwarding source (#673)" {
    // Before #673 this function had no trust gate at all: any client could
    // rewrite the client_ip used to key rate-limit buckets and access logs
    // just by sending X-Forwarded-For, even behind a correctly configured
    // `trusted_upstream_identities`. The untrusted path must always return
    // the real connection IP, identically to "no proxy headers present".
    const allocator = std.testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 6.6.6.6, 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, false, "", no_trusted_proxies, "127.0.0.1");
    try std.testing.expectEqualStrings("127.0.0.1", ip);
}
