const std = @import("std");
const compat = @import("zig_compat");
const Allocator = std.mem.Allocator;
const Request = @import("request.zig").Request;
const RequestLifecycle = @import("request_lifecycle.zig").RequestLifecycle;

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

/// Extract the client IP from request headers or connection info.
/// Checks X-Forwarded-For and X-Real-IP before falling back to
/// the provided default (connection remote address).
pub fn extractClientIp(request: *const Request, default: []const u8) []const u8 {
    // Prefer X-Forwarded-For first IP
    if (request.headers.get("x-forwarded-for")) |xff| {
        if (std.mem.findScalar(u8, xff, ',')) |comma| {
            const first = std.mem.trim(u8, xff[0..comma], " \t");
            if (first.len > 0) return first;
        } else {
            const trimmed = std.mem.trim(u8, xff, " \t");
            if (trimmed.len > 0) return trimmed;
        }
    }
    // Then X-Real-IP
    if (request.headers.get("x-real-ip")) |xri| {
        const trimmed = std.mem.trim(u8, xri, " \t");
        if (trimmed.len > 0) return trimmed;
    }
    return default;
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

test "extractClientIp prefers X-Forwarded-For" {
    const allocator = std.testing.allocator;

    // Build request with X-Forwarded-For header
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, "fallback");
    try std.testing.expectEqualStrings("1.2.3.4", ip);
}

test "extractClientIp falls back to X-Real-IP" {
    const allocator = std.testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 9.8.7.6\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, "fallback");
    try std.testing.expectEqualStrings("9.8.7.6", ip);
}

test "extractClientIp uses default when no proxy headers" {
    const allocator = std.testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, 1024 * 1024);
    var req = result.request;
    defer req.deinit();

    const ip = extractClientIp(&req, "192.168.1.1");
    try std.testing.expectEqualStrings("192.168.1.1", ip);
}
