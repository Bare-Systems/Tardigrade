//! Route dispatch, middleware, operational handlers, HTTP/3 request handling,
//! mirror/subrequest glue, and access logging for the edge gateway. Connection
//! setup remains in edge_gateway; endpoint behavior lives here.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const ga = @import("gateway_auth.zig");
const gcp = @import("gateway_control_plane_proxy.zig");
const gp = @import("gateway_proxy.zig");
const gpr = @import("gateway_protocols.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const gs = @import("gateway_state.zig");
const gstatic = @import("gateway_static_runtime.zig");

const JSON_CONTENT_TYPE = "application/json";
const GatewayState = gs.GatewayState;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const authorizeRequest = ga.authorizeRequest;
const authorizeViaSubrequest = ga.authorizeViaSubrequest;
const hostMatchesPatterns = ga.hostMatchesPatterns;
const resolveRequestConfig = ga.resolveRequestConfig;
const isGeoBlocked = ga.isGeoBlocked;
const executeBoundedControlPlaneJsonProxy = gcp.executeBoundedControlPlaneJsonProxy;
const applyResponseHeaders = gp.applyResponseHeaders;
const appendProxyQueryString = gp.appendProxyQueryString;
const buildApiErrorJson = gp.buildApiErrorJson;
const resolveProxyTarget = gp.resolveProxyTarget;
const sendApiError = gp.sendApiError;
const setRequestIdHeaders = gp.setRequestIdHeaders;
const writeRequestIdHeaders = gp.writeRequestIdHeaders;
const writeSecurityHeaders = gp.writeSecurityHeaders;
const handleFastcgiRoute = gpr.handleFastcgiRoute;
const executeBufferedDataPlaneProxyRequest = gproxy_runtime.executeBufferedDataPlaneProxyRequest;
const handleLocationProxyPass = gproxy_runtime.handleLocationProxyPass;
const proxySuffixPathForLocation = gproxy_runtime.proxySuffixPathForLocation;
const handleStaticLocation = gstatic.handleStaticLocation;
const maybeResolveStaticErrorPage = gstatic.maybeResolveStaticErrorPage;
const serveTryFilesFallback = gstatic.serveTryFilesFallback;

/// The route a request resolves to, decided independently of executing it.
/// Kept exhaustive so a new route kind forces a decision at every dispatch site.
pub const RouteDecision = union(enum) {
    reload_status,
    metrics,
    location: http.location_router.MatchResult,
    unmatched,
};

/// Resolve a request to its route. Convenience over `resolveRoutePath` for the
/// h1 `http.Request`.
///
/// TODO(#201): the transcript route is intentionally NOT part of `RouteDecision`
/// yet. `handleTranscriptRoute` returns null for a `/transcripts/…` path that is
/// not a recognized transcript endpoint, letting it fall through to location
/// matching / try_files; a `.transcript` decision variant would swallow that
/// fall-through and change behavior. So it stays a pre-check in `routeRequest`
/// until that matcher is split from its handler. Fold it in with the pre-route
/// middleware stage (later #201 PR).
pub fn resolveRoute(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, request: *const http.Request) RouteDecision {
    return resolveRoutePath(allocator, cfg.metrics_path, cfg.location_blocks, request.uri.path);
}

/// Pure route-matching precedence — no I/O, no mutation of `state`/`request`.
/// Decoupled from `EdgeConfig`/`Request` so h1, h3, and pure-Zig h3 can share
/// the same precedence (h3 has `http3_session.StreamRequest`, not `http.Request`)
/// and so it is directly unit-testable without constructing a full config.
/// Mirrors the order previously inlined in `routeRequest`: reload-status path,
/// then the configured metrics path, then location blocks.
pub fn resolveRoutePath(
    allocator: std.mem.Allocator,
    metrics_path: []const u8,
    location_blocks: []const http.location_router.LocationBlock,
    path: []const u8,
) RouteDecision {
    if (std.mem.eql(u8, path, "/tardigrade/reload/status")) return .reload_status;
    if (metrics_path.len > 0 and std.mem.eql(u8, path, metrics_path)) return .metrics;
    if (http.location_router.matchLocation(allocator, path, location_blocks)) |matched| {
        return .{ .location = matched };
    }
    return .unmatched;
}

fn routeReplaySafe(block: *const http.location_router.LocationBlock) bool {
    return block.early_data == .replay_safe;
}

fn locationEarlyDataDecision(
    early_ctx: http.request_context.EarlyDataContext,
    method_safe: bool,
    block: *const http.location_router.LocationBlock,
) http.early_data.Decision {
    if (block.auth == .required) return .too_early;
    return switch (block.action) {
        .static_root, .return_response => http.early_data.decide(.{
            .replay_exposed = early_ctx.replayExposed(),
            .transport_early = early_ctx.transport_early,
            .inbound_marker = early_ctx.inbound_marker,
            .method_safe = method_safe,
            .route_replay_safe = routeReplaySafe(block),
            .action_class = .local,
            .proxy_origin_rfc8470 = false,
        }),
        .proxy_pass => http.early_data.decide(.{
            .replay_exposed = early_ctx.replayExposed(),
            .transport_early = early_ctx.transport_early,
            .inbound_marker = early_ctx.inbound_marker,
            .method_safe = method_safe,
            .route_replay_safe = routeReplaySafe(block),
            .action_class = .proxy,
            .proxy_origin_rfc8470 = block.proxy_early_data == .rfc8470,
        }),
        .fastcgi_pass, .rewrite => .too_early,
    };
}

fn isTranscriptRoutePath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/transcripts") or
        std.mem.startsWith(u8, path, "/transcripts/") or
        std.mem.eql(u8, path, "/bearclaw/transcripts") or
        std.mem.startsWith(u8, path, "/bearclaw/transcripts/");
}

pub fn earlyDataDecisionForRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    early_ctx: http.request_context.EarlyDataContext,
    method: http.Method,
    path: []const u8,
    has_body_framing: bool,
) http.early_data.Decision {
    return earlyDataDecisionForRawMethod(allocator, cfg, early_ctx, method.toString(), path, has_body_framing);
}

pub fn earlyDataDecisionForRawMethod(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    early_ctx: http.request_context.EarlyDataContext,
    method: []const u8,
    path: []const u8,
    has_body_framing: bool,
) http.early_data.Decision {
    if (!early_ctx.replayExposed()) return .ordinary;
    if (has_body_framing) return .too_early;
    if (isTranscriptRoutePath(path)) return .too_early;
    if (hasMatchingMirrorRule(cfg.mirror_rules, method, path)) return .too_early;

    return switch (resolveRoutePath(allocator, cfg.metrics_path, cfg.location_blocks, path)) {
        .reload_status, .metrics, .unmatched => .too_early,
        .location => |matched| locationEarlyDataDecision(early_ctx, http.early_data.methodSafe(method), matched.block),
    };
}

fn hasMatchingMirrorRule(
    rules: []const edge_config.EdgeConfig.MirrorRule,
    method: []const u8,
    path: []const u8,
) bool {
    for (rules) |rule| {
        if (!http.rewrite.methodMatches(rule.method, method)) continue;
        if (!http.rewrite.regexMatches(rule.pattern, path)) continue;
        return true;
    }
    return false;
}

fn metricsEarlyDataSource(early_ctx: http.request_context.EarlyDataContext) ?http.metrics.EarlyDataSource {
    return switch (early_ctx.source()) {
        .none => null,
        .transport => .transport,
        .header => .header,
        .both => .both,
    };
}

fn h3ForwardEarlyDataMarker(early_ctx: http.request_context.EarlyDataContext, decision: http.early_data.Decision) bool {
    if (decision != .forward_rfc8470) return false;
    return early_ctx.inbound_marker or (early_ctx.transport_early and early_ctx.downstreamHandshakeComplete() == false);
}

fn h3RequestHandshakeComplete(ctx: *anyopaque) bool {
    const request: *const http.http3_session.StreamRequest = @ptrCast(@alignCast(ctx));
    if (request.downstream_handshake) |barrier| return barrier.isComplete();
    return request.downstream_handshake_complete;
}

fn h3RequestDriveHandshake(ctx: *anyopaque) anyerror!void {
    const request: *const http.http3_session.StreamRequest = @ptrCast(@alignCast(ctx));
    if (request.downstream_handshake) |barrier| try barrier.waitOrDrive();
}

pub fn writeTooEarlyResponse(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    const plan = http.early_data.tooEarlyPlan();
    const payload = try buildApiErrorJson(allocator, plan.code, "Too Early", correlation_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response
        .setStatus(plan.status)
        .setConnection(keep_alive)
        .setHeader("Cache-Control", "no-store");
    setRequestIdHeaders(&response, correlation_id);
    ctx.response_bytes = payload.len;
    applyResponseHeaders(state, &response);
    try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    state.metricsRecord(@intFromEnum(plan.status));
    state.metricsRecordErrorCode(plan.code);
    return @intFromEnum(plan.status);
}

test "resolveRoutePath: reload-status and metrics precede location matching" {
    const blocks = [_]http.location_router.LocationBlock{
        .{ .match_type = .prefix, .pattern = "/", .priority = 0, .action = .{ .return_response = .{ .status = 200, .body = "" } } },
    };
    const Tag = std.meta.Tag(RouteDecision);
    // reload-status wins over a configured metrics path and a catch-all location.
    try std.testing.expectEqual(Tag.reload_status, std.meta.activeTag(resolveRoutePath(std.testing.allocator, "/metrics", &blocks, "/tardigrade/reload/status")));
    // metrics path wins over a matching location.
    try std.testing.expectEqual(Tag.metrics, std.meta.activeTag(resolveRoutePath(std.testing.allocator, "/metrics", &blocks, "/metrics")));
    // an empty metrics_path disables the metrics route, falling to the location.
    try std.testing.expectEqual(Tag.location, std.meta.activeTag(resolveRoutePath(std.testing.allocator, "", &blocks, "/metrics")));
}

test "resolveRoutePath: location match carries the block, else unmatched" {
    const blocks = [_]http.location_router.LocationBlock{
        .{ .match_type = .exact, .pattern = "/app", .priority = 1, .action = .{ .proxy_pass = "" } },
    };
    switch (resolveRoutePath(std.testing.allocator, "/status/metrics", &blocks, "/app")) {
        .location => |m| try std.testing.expectEqualStrings("/app", m.block.pattern),
        else => try std.testing.expect(false),
    }
    try std.testing.expectEqual(std.meta.Tag(RouteDecision).unmatched, std.meta.activeTag(resolveRoutePath(std.testing.allocator, "/status/metrics", &blocks, "/nope")));
}

test "earlyDataDecisionForRequest gates H1 routes before side effects" {
    var blocks = [_]http.location_router.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/off",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        },
        .{
            .match_type = .exact,
            .pattern = "/safe",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
            .early_data = .replay_safe,
        },
        .{
            .match_type = .exact,
            .pattern = "/proxy",
            .priority = 2,
            .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
        .{
            .match_type = .exact,
            .pattern = "/auth",
            .priority = 3,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
            .early_data = .replay_safe,
            .auth = .required,
        },
        .{
            .match_type = .exact,
            .pattern = "/rewrite",
            .priority = 4,
            .action = .{ .rewrite = .{ .replacement = "/safe", .flag = .last } },
            .early_data = .replay_safe,
        },
    };
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);

    const ordinary = http.request_context.EarlyDataContext{};
    const early = http.request_context.EarlyDataContext{ .transport_early = true };
    try std.testing.expectEqual(http.early_data.Decision.ordinary, earlyDataDecisionForRequest(std.testing.allocator, &cfg, ordinary, .GET, "/off", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/off", false));
    try std.testing.expectEqual(http.early_data.Decision.execute_local, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/safe", false));
    try std.testing.expectEqual(http.early_data.Decision.execute_local, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .HEAD, "/safe", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/safe", true));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .HEAD, "/safe", true));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .POST, "/safe", false));
    try std.testing.expectEqual(http.early_data.Decision.forward_rfc8470, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/proxy", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/auth", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/rewrite", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, cfg.metrics_path, false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/transcripts", false));
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/missing", false));
}

test "earlyDataDecisionForRequest rejects matching mirrors before side effects" {
    var blocks = [_]http.location_router.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/safe",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
            .early_data = .replay_safe,
        },
    };
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "GET", .pattern = "^/safe$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    cfg.mirror_rules = mirrors[0..];

    const early = http.request_context.EarlyDataContext{ .transport_early = true };
    try std.testing.expectEqual(http.early_data.Decision.too_early, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .GET, "/safe", false));
    try std.testing.expectEqual(http.early_data.Decision.execute_local, earlyDataDecisionForRequest(std.testing.allocator, &cfg, early, .HEAD, "/safe", false));
}

test "writeTooEarlyResponse emits no-store 425 without double-counting callers" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var ctx = http.request_context.RequestContext.init(allocator, "req-425", "127.0.0.1");
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const status = try writeTooEarlyResponse(allocator, &output.writer, &state, &ctx, "req-425", false);

    const raw = output.written();
    try std.testing.expectEqual(@as(u16, 425), status);
    try std.testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 425 Too Early\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, raw, "cache-control: no-store\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "\"code\":\"too_early\"") != null);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
}

/// The rendering decision for a location `return` directive, shared by h1 and h3
/// (#201). A non-redirect return is GET/HEAD-only (ASVS-14.5.1) — accepting
/// DELETE/PUT/PATCH on `return 200 ok` would mislead the client into believing a
/// destructive op succeeded; redirects (3xx) are method-agnostic. Each protocol
/// computes the plan, then renders it its own way (h1 to the socket writer, h3
/// into an http.Response).
pub const ReturnResponsePlan = union(enum) {
    method_not_allowed,
    redirect: struct { status: u16, location: []const u8 },
    body: struct { status: u16, body: []const u8 },
};

pub const ReturnResponseWriteResult = struct {
    status: u16,
    error_code: ?[]const u8 = null,
};

pub fn planReturnResponse(request_is_get_or_head: bool, status: u16, body: []const u8) ReturnResponsePlan {
    const is_redirect = status >= 300 and status < 400;
    if (!is_redirect and !request_is_get_or_head) return .method_not_allowed;
    if (is_redirect and body.len > 0) return .{ .redirect = .{ .status = status, .location = body } };
    return .{ .body = .{ .status = status, .body = body } };
}

pub fn planDirectResponse(status: u16, body: []const u8) ReturnResponsePlan {
    return planReturnResponse(true, status, body);
}

/// Render a configured direct response for HTTP/1.x routes and rewrite stages.
///
/// Route matching, rewrite evaluation, and metrics/logging stay with the caller;
/// this stage owns shared status/header/body shaping for the socket response.
pub fn writeReturnResponsePlan(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    plan: ReturnResponsePlan,
    correlation_id: []const u8,
    keep_alive: bool,
) !ReturnResponseWriteResult {
    switch (plan) {
        .method_not_allowed => {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Method Not Allowed", correlation_id);
            defer allocator.free(payload);
            var response = http.Response.json(allocator, payload);
            defer response.deinit();
            _ = response.setStatus(.method_not_allowed).setConnection(keep_alive);
            setRequestIdHeaders(&response, correlation_id);
            ctx.response_bytes = payload.len;
            applyResponseHeaders(state, &response);
            try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
            return .{ .status = 405, .error_code = "invalid_request" };
        },
        .redirect => |r| {
            var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
            defer response.deinit();
            _ = response.setConnection(keep_alive);
            setRequestIdHeaders(&response, correlation_id);
            ctx.response_bytes = 0;
            applyResponseHeaders(state, &response);
            try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
            return .{ .status = r.status };
        },
        .body => |b| {
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(@enumFromInt(b.status))
                .setBody(b.body)
                .setContentType("text/plain; charset=utf-8")
                .setConnection(keep_alive);
            setRequestIdHeaders(&response, correlation_id);
            ctx.response_bytes = b.body.len;
            applyResponseHeaders(state, &response);
            try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
            return .{ .status = b.status };
        },
    }
}

pub fn writeReturnResponse(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request_is_get_or_head: bool,
    status: u16,
    body: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
) !ReturnResponseWriteResult {
    return writeReturnResponsePlan(allocator, writer, state, ctx, planReturnResponse(request_is_get_or_head, status, body), correlation_id, keep_alive);
}

fn recordReturnResponseMetrics(state: *GatewayState, result: ReturnResponseWriteResult) void {
    state.metricsRecord(result.status);
    if (result.error_code) |code| state.metricsRecordErrorCode(code);
}

test "planReturnResponse: non-redirect return is GET/HEAD only" {
    try std.testing.expect(std.meta.activeTag(planReturnResponse(true, 200, "ok")) == .body);
    try std.testing.expect(std.meta.activeTag(planReturnResponse(false, 200, "ok")) == .method_not_allowed);
}

test "planReturnResponse: redirects are method-agnostic" {
    switch (planReturnResponse(false, 302, "/new")) {
        .redirect => |r| {
            try std.testing.expectEqual(@as(u16, 302), r.status);
            try std.testing.expectEqualStrings("/new", r.location);
        },
        else => try std.testing.expect(false),
    }
    // A redirect status with no body renders the status without a Location header.
    try std.testing.expect(std.meta.activeTag(planReturnResponse(true, 301, "")) == .body);
}

test "planDirectResponse preserves configured rewrite return behavior" {
    try std.testing.expect(std.meta.activeTag(planDirectResponse(200, "ok")) == .body);
    switch (planDirectResponse(302, "/new")) {
        .redirect => |r| try std.testing.expectEqualStrings("/new", r.location),
        else => {
            try std.testing.expect(false);
        },
    }
}

fn initHandlerTestState(state: *GatewayState, allocator: std.mem.Allocator, add_headers: []const edge_config.EdgeConfig.HeaderPair) void {
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.session_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.security_headers = .{
        .x_frame_options = "DENY",
        .x_content_type_options = "nosniff",
        .content_security_policy = "",
        .strict_transport_security = "",
        .referrer_policy = "",
        .permissions_policy = "",
        .x_xss_protection = "",
        .cross_origin_opener_policy = "",
        .cross_origin_resource_policy = "",
    };
    state.add_headers = add_headers;
    state.http3_alt_svc = null;
    state.http3_advertisement_state = .disabled;
    state.http3_runtime = null;
    state.session_store = null;
}

fn minimalAuthConfig(blocks: []http.location_router.LocationBlock, token_hashes: [][]const u8) edge_config.EdgeConfig {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.basic_auth_hashes = &.{};
    cfg.auth_token_hashes = token_hashes;
    cfg.jwt_secret = "";
    cfg.jwt_issuer = "";
    cfg.jwt_audience = "";
    cfg.auth_request_url = "";
    cfg.location_blocks = blocks;
    cfg.metrics_path = "/status/metrics";
    cfg.mirror_rules = &.{};
    return cfg;
}

fn minimalHttp3ProxyConfig(blocks: []http.location_router.LocationBlock) edge_config.EdgeConfig {
    var cfg = minimalAuthConfig(blocks, &.{});
    cfg.server_names = &.{};
    cfg.server_blocks = &.{};
    cfg.upstream_base_url = "";
    cfg.upstream_tls_verify = false;
    cfg.upstream_tls_ca_bundle = "";
    cfg.upstream_tls_server_name = "";
    cfg.upstream_tls_client_cert = "";
    cfg.upstream_tls_client_key = "";
    cfg.upstream_protocol = .http1;
    cfg.upstream_timeout_ms = 5000;
    cfg.upstream_connect_timeout_ms = 5000;
    cfg.upstream_response_timeout_ms = 5000;
    cfg.upstream_timeout_budget_ms = 0;
    cfg.upstream_retry_attempts = 1;
    cfg.upstream_retry_idempotent_only = true;
    cfg.upstream_max_fails = 0;
    cfg.upstream_fail_timeout_ms = 0;
    cfg.upstream_active_health_interval_ms = 0;
    cfg.upstream_slow_start_ms = 0;
    cfg.max_buffered_upstream_response_bytes = 64 * 1024;
    cfg.proxy_buffer_limits = .{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    cfg.upstream_pool_enabled = false;
    cfg.upstream_pool_max_idle_per_host = 0;
    cfg.upstream_pool_idle_timeout_ms = 0;
    cfg.upstream_pool_max_lifetime_ms = 0;
    cfg.upstream_pool_max_active_per_host = 0;
    cfg.tls_cert_path = "";
    cfg.tls_key_path = "";
    cfg.add_headers = &.{};
    return cfg;
}

fn initHttp3ProxyTestState(state: *GatewayState, allocator: std.mem.Allocator, add_headers: []const edge_config.EdgeConfig.HeaderPair) void {
    initHandlerTestState(state, allocator, add_headers);
    state.circuit_mutex = .{};
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{});
    state.upstream_mutex = .{};
    state.upstream_health = std.StringHashMap(gs.UpstreamHealth).init(allocator);
    state.upstream_active_requests = std.StringHashMap(usize).init(allocator);
    state.upstream_pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    state.h2_pool = http.upstream_h2.H2ConnPool.init(allocator, .{});
    state.proxy_buffer_limits = .{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
}

fn deinitHttp3ProxyTestState(state: *GatewayState) void {
    state.upstream_pool.deinit();
    state.h2_pool.deinit();
    var active_it = state.upstream_active_requests.keyIterator();
    while (active_it.next()) |key| state.allocator.free(key.*);
    state.upstream_active_requests.deinit();
    var health_it = state.upstream_health.keyIterator();
    while (health_it.next()) |key| state.allocator.free(key.*);
    state.upstream_health.deinit();
}

fn recordTestReturnMetrics(state: *GatewayState, result: ReturnResponseWriteResult) void {
    state.metricsRecord(result.status);
    if (result.error_code) |code| state.metricsRecordErrorCode(code);
}

test "writeReturnResponsePlan writes body response headers bytes and caller-owned metrics" {
    const allocator = std.testing.allocator;
    const add_headers = [_]edge_config.EdgeConfig.HeaderPair{.{ .name = "X-Test-Header", .value = "stage" }};
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, add_headers[0..]);
    var ctx = http.request_context.RequestContext.init(allocator, "req-body", "127.0.0.1");
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const result = try writeReturnResponsePlan(allocator, &output.writer, &state, &ctx, planDirectResponse(200, "ok"), "req-body", true);
    recordTestReturnMetrics(&state, result);

    const raw = output.written();
    try std.testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, raw, "X-Request-ID: req-body\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "X-Correlation-ID: req-body\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "x-frame-options: DENY\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "x-test-header: stage\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, raw, "\r\n\r\nok"));
    try std.testing.expectEqual(@as(usize, 2), ctx.response_bytes);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_2xx);
}

test "writeReturnResponsePlan writes redirects with zero response bytes" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var ctx = http.request_context.RequestContext.init(allocator, "req-redirect", "127.0.0.1");
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const result = try writeReturnResponsePlan(allocator, &output.writer, &state, &ctx, planDirectResponse(302, "/new"), "req-redirect", false);
    recordTestReturnMetrics(&state, result);

    const raw = output.written();
    try std.testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 302 Found\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, raw, "location: /new\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "Content-Length: 0\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, raw, "\r\n\r\n"));
    try std.testing.expectEqual(@as(usize, 0), ctx.response_bytes);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_3xx);
}

test "writeReturnResponsePlan reports 405 metrics ownership to caller" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var ctx = http.request_context.RequestContext.init(allocator, "req-405", "127.0.0.1");
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const result = try writeReturnResponsePlan(allocator, &output.writer, &state, &ctx, planReturnResponse(false, 200, "ok"), "req-405", false);
    try std.testing.expectEqual(@as(u64, 0), state.metrics.total_requests);
    recordTestReturnMetrics(&state, result);

    const raw = output.written();
    try std.testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 405 Method Not Allowed\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, raw, "\"code\":\"invalid_request\"") != null);
    try std.testing.expect(ctx.response_bytes > 0);
    try std.testing.expectEqual(@as(u16, 405), result.status);
    try std.testing.expectEqualStrings("invalid_request", result.error_code.?);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.err_invalid_request);
}

pub fn routeRequest(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
    streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
) !u16 {
    const writer = conn.writer();
    if (try handleTranscriptRoute(allocator, writer, state, request, correlation_id, keep_alive.*)) |status| {
        state.metricsRecord(status);
        return status;
    }

    switch (resolveRoute(allocator, cfg, request)) {
        .reload_status => {
            const status = try handleReloadStatusRoute(allocator, writer, state, correlation_id, keep_alive.*);
            state.metricsRecord(status);
            return status;
        },
        .metrics => {
            const status = try handleMetricsRoute(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*);
            state.metricsRecord(status);
            return status;
        },
        .unmatched => {},
        .location => |matched| {
            if (try enforceLocationAuth(allocator, writer, cfg, state, ctx, request, matched, correlation_id, keep_alive.*, client_ip)) |status| {
                return status;
            }
            if (try executeLocationAction(
                conn,
                allocator,
                cfg,
                state,
                ctx,
                request,
                matched,
                correlation_id,
                keep_alive,
                client_ip,
                streaming_request_body,
            )) |status| {
                return status;
            }
        },
    }

    if (serveTryFilesFallback(allocator, conn, cfg, request, correlation_id, keep_alive.*, state)) |status| {
        state.metricsRecord(status);
        return status;
    } else |_| {}

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive.*, state);
    state.metricsRecord(404);
    return 404;
}

fn enforceLocationAuth(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    matched: http.location_router.MatchResult,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
) !?u16 {
    if (matched.block.auth != .required or ctx.authenticated or ctx.identity != null) return null;

    var auth_res = try authorizeRequest(allocator, cfg, &request.headers);
    defer auth_res.deinit(allocator);
    if (auth_res.ok) {
        if (auth_res.identity) |identity| {
            ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
            auth_res.identity = null;
            auth_res.user_id = null;
            auth_res.device_id = null;
            auth_res.scopes = null;
        }
        return null;
    }

    if (http.session.fromHeaders(&request.headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            ctx.setIdentity(identity);
            return null;
        }
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
        return 401;
    }

    if (cfg.auth_request_url.len > 0 and authorizeViaSubrequest(allocator, cfg, request, correlation_id, client_ip)) {
        ctx.authenticated = true;
        return null;
    }

    const auth_status: http.Status = if (auth_res.failure_reason == .invalid) .forbidden else .unauthorized;
    const auth_code = if (auth_res.failure_reason == .invalid) "forbidden" else "unauthorized";
    const auth_message = if (auth_res.failure_reason == .invalid) "Forbidden" else "Unauthorized";
    const auth_status_code: u16 = @intFromEnum(auth_status);
    try sendApiError(allocator, writer, auth_status, auth_code, auth_message, correlation_id, keep_alive, state);
    return auth_status_code;
}

test "enforceLocationAuth records invalid session rejection exactly once" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var ctx = http.request_context.RequestContext.init(allocator, "req-session", "127.0.0.1");
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/private",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        .auth = .required,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    const parsed = try http.Request.parse(
        allocator,
        "GET /private HTTP/1.1\r\nHost: example.test\r\nX-Session-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    var request = parsed.request;
    defer request.deinit();
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const matched = http.location_router.matchLocation(allocator, request.uri.path, cfg.location_blocks).?;

    const status = (try enforceLocationAuth(allocator, &output.writer, &cfg, &state, &ctx, &request, matched, "req-session", false, "127.0.0.1")).?;

    try std.testing.expectEqual(@as(u16, 401), status);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.err_unauthorized);
}

test "enforceLocationAuth records invalid authorization rejection exactly once" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var ctx = http.request_context.RequestContext.init(allocator, "req-auth", "127.0.0.1");
    const allowed_hashes = [_][]const u8{"0000000000000000000000000000000000000000000000000000000000000000"};
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/private",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        .auth = .required,
    }};
    var mutable_allowed_hashes = allowed_hashes;
    var cfg = minimalAuthConfig(blocks[0..], mutable_allowed_hashes[0..]);
    const parsed = try http.Request.parse(
        allocator,
        "GET /private HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer wrong-token\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    var request = parsed.request;
    defer request.deinit();
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const matched = http.location_router.matchLocation(allocator, request.uri.path, cfg.location_blocks).?;

    const status = (try enforceLocationAuth(allocator, &output.writer, &cfg, &state, &ctx, &request, matched, "req-auth", false, "127.0.0.1")).?;

    try std.testing.expectEqual(@as(u16, 403), status);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.err_forbidden);
}

fn executeLocationAction(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    matched: http.location_router.MatchResult,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
    streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
) !?u16 {
    const writer = conn.writer();
    switch (matched.block.action) {
        .proxy_pass => |target| {
            return try handleLocationProxyPass(
                allocator,
                conn,
                writer,
                cfg,
                state,
                ctx,
                request,
                target,
                proxySuffixPathForLocation(request.uri.path, matched, cfg.location_blocks),
                correlation_id,
                keep_alive.*,
                client_ip,
                ctx.identity,
                ctx.user_id,
                ctx.device_id,
                ctx.scopes,
                request.headers.get("host"),
                matched.block.pattern,
                matched.block,
                streaming_request_body,
            );
        },
        .fastcgi_pass => |upstream| {
            return try handleFastcgiRoute(allocator, writer, cfg, upstream, request, client_ip, correlation_id, keep_alive.*, state);
        },
        .return_response => |ret| {
            const result = try writeReturnResponse(
                allocator,
                writer,
                state,
                ctx,
                request.method == .GET or request.method == .HEAD,
                ret.status,
                ret.body,
                correlation_id,
                keep_alive.*,
            );
            recordReturnResponseMetrics(state, result);
            return result.status;
        },
        .rewrite => |rw| {
            request.uri.path = rw.replacement;
            return null;
        },
        .static_root => |root_cfg| {
            if (try handleStaticLocation(allocator, conn, request, matched, root_cfg, correlation_id, keep_alive.*, state)) |status| {
                return status;
            }
            return null;
        },
    }
}

pub fn primeRequestAuthContext(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    headers: *const http.Headers,
) !void {
    if (ctx.authenticated or ctx.identity != null) return;

    var auth_res = try authorizeRequest(allocator, cfg, headers);
    defer auth_res.deinit(allocator);
    if (auth_res.ok) {
        if (auth_res.identity) |identity| {
            ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
            auth_res.identity = null;
            auth_res.user_id = null;
            auth_res.device_id = null;
            auth_res.scopes = null;
        } else {
            ctx.authenticated = true;
        }
        return;
    }

    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            ctx.setIdentity(identity);
        }
    }
}

fn handleTranscriptRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !?u16 {
    const transcript_path = normalizeTranscriptRoutePath(request.uri.path) orelse return null;

    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (state.transcript_store_path.len == 0) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript store not configured", correlation_id, keep_alive, state);
        return 404;
    }

    if (std.mem.eql(u8, transcript_path, "/transcripts")) {
        const limit = parseTranscriptLimit(request.uri.query);
        const transcripts = try http.transcript_store.listRecent(allocator, state.transcript_store_path, limit);
        defer {
            for (transcripts) |*summary| summary.deinit(allocator);
            allocator.free(transcripts);
        }
        const payload = try jsonifyTranscriptSummaries(allocator, transcripts);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    if (std.mem.startsWith(u8, transcript_path, "/transcripts/")) {
        const id_raw = std.mem.trim(u8, transcript_path["/transcripts/".len..], " \t\r\n");
        const id = std.fmt.parseInt(usize, id_raw, 10) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid transcript id", correlation_id, keep_alive, state);
            return 400;
        };
        var entry = (try http.transcript_store.getById(allocator, state.transcript_store_path, id)) orelse {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript not found", correlation_id, keep_alive, state);
            return 404;
        };
        defer entry.deinit(allocator);
        const payload = try jsonifyTranscriptEntry(allocator, &entry);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    return null;
}

fn handleReloadStatusRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    state.reload_mutex.lock();
    const ok = state.last_reload_ok;
    const at_ms = state.last_reload_at_ms;
    const err_slice = state.last_reload_error[0..state.last_reload_error_len];
    state.reload_mutex.unlock();

    const payload = if (at_ms == 0)
        try std.fmt.allocPrint(allocator, "{{\"ok\":null,\"at_ms\":null,\"error\":null}}", .{})
    else if (ok)
        try std.fmt.allocPrint(allocator, "{{\"ok\":true,\"at_ms\":{d},\"error\":null}}", .{at_ms})
    else
        try std.fmt.allocPrint(allocator, "{{\"ok\":false,\"at_ms\":{d},\"error\":\"{s}\"}}", .{ at_ms, err_slice });
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(payload)
        .setContentType("application/json")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    return 200;
}

fn handleMetricsRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (cfg.metrics_require_auth and !ctx.authenticated and ctx.identity == null) {
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
        state.metricsRecordErrorCode("unauthorized");
        return 401;
    }

    const payload = try state.metricsToPrometheus(allocator);
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(if (request.method == .HEAD) "" else payload)
        .setContentType("text/plain; version=0.0.4; charset=utf-8")
        .setConnection(keep_alive);
    setRequestIdHeaders(&response, correlation_id);
    if (request.method == .HEAD) {
        _ = response.setContentLength(payload.len);
        ctx.response_bytes = 0;
        applyResponseHeaders(state, &response);
        try response.writeHeadWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    } else {
        ctx.response_bytes = payload.len;
        applyResponseHeaders(state, &response);
        try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    }
    return 200;
}

fn normalizeTranscriptRoutePath(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/transcripts") or std.mem.startsWith(u8, path, "/transcripts/")) return path;
    if (std.mem.eql(u8, path, "/bearclaw/transcripts")) return "/transcripts";
    if (std.mem.startsWith(u8, path, "/bearclaw/transcripts/")) return path["/bearclaw".len..];
    return null;
}

fn parseTranscriptLimit(query: ?[]const u8) usize {
    const raw = parseQueryParam(query, "limit") orelse return 50;
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return 50;
    return std.math.clamp(parsed, 1, 200);
}

fn jsonifyTranscriptSummaries(allocator: std.mem.Allocator, transcripts: []const http.transcript_store.Summary) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcripts = transcripts }, .{});
}

fn jsonifyTranscriptEntry(allocator: std.mem.Allocator, transcript: *const http.transcript_store.StoredEntry) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcript = transcript }, .{});
}

fn writeJsonPayload(
    writer: anytype,
    allocator: std.mem.Allocator,
    payload: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
    head_only: bool,
) !void {
    var response = http.Response.json(allocator, if (head_only) "" else payload);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    if (head_only) {
        try response.writeHeadWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    } else {
        try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    }
}

fn rateLimitDescriptor(identity: ?[]const u8, client_ip: []const u8, buf: *[192]u8) []const u8 {
    if (identity) |id| {
        return std.fmt.bufPrint(buf, "identity:{s}", .{id}) catch blk: {
            const hash = std.hash.Wyhash.hash(0, id);
            break :blk std.fmt.bufPrint(buf, "identity-hash:{x}", .{hash}) catch "identity-hash";
        };
    }
    return std.fmt.bufPrint(buf, "ip:{s}", .{client_ip}) catch blk: {
        const hash = std.hash.Wyhash.hash(0, client_ip);
        break :blk std.fmt.bufPrint(buf, "ip-hash:{x}", .{hash}) catch "ip-hash";
    };
}

pub fn runMiddlewarePipeline(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !bool {
    const client_ip = ctx.client_ip;

    if (cfg.geo_blocked_countries.len > 0) {
        const country = request.headers.get(cfg.geo_country_header);
        if (isGeoBlocked(cfg.geo_blocked_countries, country)) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Geo access denied", correlation_id, keep_alive, state);
            logAccessForRequest(state, ctx, request, 403);
            return true;
        }
    }

    const limits = cfg.request_limits;
    const uri_check = http.request_limits.validateUriLength(request.uri.path.len, limits);
    if (uri_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(uri_check, &msg_buf);
        try sendApiError(allocator, writer, .uri_too_long, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "URI too long: {d} bytes", .{request.uri.path.len});
        logAccessForRequest(state, ctx, request, 414);
        return true;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(header_count_check, &msg_buf);
        try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccessForRequest(state, ctx, request, 431);
        return true;
    }
    for (request.headers.iterator()) |h| {
        const header_len = h.name.len + h.value.len + 2; // "name: value"
        const header_size_check = http.request_limits.validateHeaderSize(header_len, limits);
        if (header_size_check != .ok) {
            var msg_buf: [256]u8 = undefined;
            const msg = http.request_limits.rejectionMessage(header_size_check, &msg_buf);
            try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Header too large: {d} bytes", .{header_len});
            logAccessForRequest(state, ctx, request, 431);
            return true;
        }
    }
    {
        var headers_total: usize = 0;
        for (request.headers.iterator()) |h| headers_total += h.name.len + h.value.len + 4; // ": \r\n"
        const total_check = http.request_limits.validateHeadersTotalSize(headers_total, limits);
        if (total_check != .ok) {
            var msg_buf: [256]u8 = undefined;
            const msg = http.request_limits.rejectionMessage(total_check, &msg_buf);
            try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Headers total too large: {d} bytes", .{headers_total});
            logAccessForRequest(state, ctx, request, 431);
            return true;
        }
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccessForRequest(state, ctx, request, 413);
            return true;
        }
    }

    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, keep_alive, state);
            logAccessForRequest(state, ctx, request, 403);
            return true;
        }
    }

    var rate_limit_buf: [192]u8 = undefined;
    const limit_key = rateLimitDescriptor(ctx.identity, client_ip, &rate_limit_buf);
    if (!state.rateLimitAllow(limit_key)) {
        const payload = try buildApiErrorJson(allocator, "rate_limited", "Rate limit exceeded", correlation_id);
        defer allocator.free(payload);
        var response = http.Response.json(allocator, payload);
        defer response.deinit();
        _ = response
            .setStatus(.too_many_requests)
            .setConnection(keep_alive)
            .setHeader("Retry-After", "1")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
        state.metricsRecord(429);
        state.metricsRecordErrorCode("rate_limited");
        logAccessForRequest(state, ctx, request, 429);
        return true;
    }

    return false;
}

fn streamSseTopic(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    topic: []const u8,
    last_event_id_start: u64,
    correlation_id: []const u8,
) !void {
    try writer.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("X-Accel-Buffering: no\r\n");
    try writeRequestIdHeaders(writer, correlation_id);
    try writeSecurityHeaders(writer, &state.security_headers);
    for (state.add_headers) |pair| {
        try writer.print("{s}: {s}\r\n", .{ pair.name, pair.value });
    }
    try writer.writeAll("\r\n");

    var last_event_id = last_event_id_start;
    var last_send_ms = http.event_loop.monotonicMs();
    var last_comment_ms = last_send_ms;
    const poll_ms = @max(cfg.sse_poll_interval_ms, 10);

    while (!http.shutdown.isShutdownRequested()) {
        if (cfg.sse_max_backlog > 0 and last_event_id > 0) {
            if (state.event_hub.oldestId(topic)) |oldest| {
                if (last_event_id + cfg.sse_max_backlog < oldest) {
                    try writeSseEvent(writer, oldest, "backlog_exceeded");
                    return;
                }
            }
        }

        const events = try state.event_hub.snapshotSince(allocator, topic, last_event_id);
        defer http.event_hub.deinitSnapshot(allocator, events);

        if (events.len > 0) {
            for (events) |event| {
                try writeSseEvent(writer, event.id, event.payload);
                last_event_id = event.id;
            }
            last_send_ms = http.event_loop.monotonicMs();
        } else {
            const now_ms = http.event_loop.monotonicMs();
            if (now_ms - last_comment_ms >= 15_000) {
                try writer.writeAll(": keepalive\n\n");
                last_comment_ms = now_ms;
            }
            if (cfg.sse_idle_timeout_ms > 0 and now_ms - last_send_ms >= cfg.sse_idle_timeout_ms) return;
        }

        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(@as(i64, @intCast(poll_ms))), .awake) catch {}; // interrupt wakes are fine; SSE poll loop continues
    }
}

fn writeSseEvent(writer: anytype, id: u64, payload: []const u8) !void {
    try writer.print("id: {d}\n", .{id});
    var line_it = std.mem.splitScalar(u8, payload, '\n');
    while (line_it.next()) |line| {
        try writer.print("data: {s}\n", .{line});
    }
    try writer.writeAll("\n");
}

pub fn parseQueryParam(query: ?[]const u8, key: []const u8) ?[]const u8 {
    const raw = query orelse return null;
    var it = std.mem.splitScalar(u8, raw, '&');
    while (it.next()) |part| {
        const eq = std.mem.findScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t\r\n");
        if (!std.mem.eql(u8, name, key)) continue;
        return std.mem.trim(u8, part[eq + 1 ..], " \t\r\n");
    }
    return null;
}

fn generateCommandId(allocator: std.mem.Allocator) ![]const u8 {
    var rnd: [16]u8 = undefined;
    compat.randomBytes(&rnd);
    return std.fmt.allocPrint(allocator, "cmd-{d}-{f}", .{
        compat.milliTimestamp(),
        compat.fmtSliceHexLower(&rnd),
    });
}

const AsyncCommandJob = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []u8,
    command_name: []u8,
    upstream_path: []u8,
    envelope: []u8,
    correlation_id: []u8,
    client_ip: []u8,
    identity: ?[]u8,
    incoming_host: ?[]u8,
    incoming_x_forwarded_for: ?[]u8,
    api_version: ?u32,
};

fn spawnAsyncCommandExecution(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) void {
    const job = createAsyncCommandJob(
        state.allocator,
        cfg,
        state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        api_version,
        incoming_host,
        incoming_x_forwarded_for,
    ) catch return;
    const t = std.Thread.spawn(.{}, runAsyncCommandJob, .{job}) catch {
        destroyAsyncCommandJob(job);
        state.commandLifecycleSetFailed(command_id, "async_spawn_failed");
        return;
    };
    t.detach();
}

fn createAsyncCommandJob(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) !*AsyncCommandJob {
    const job = try allocator.create(AsyncCommandJob);
    errdefer allocator.destroy(job);
    job.* = .{
        .allocator = allocator,
        .cfg = cfg,
        .state = state,
        .command_id = dupeOrEmpty(allocator, command_id),
        .command_name = dupeOrEmpty(allocator, command_name),
        .upstream_path = dupeOrEmpty(allocator, upstream_path),
        .envelope = dupeOrEmpty(allocator, envelope),
        .correlation_id = dupeOrEmpty(allocator, correlation_id),
        .client_ip = dupeOrEmpty(allocator, client_ip),
        .identity = if (identity) |id| allocator.dupe(u8, id) catch null else null,
        .incoming_host = if (incoming_host) |h| allocator.dupe(u8, h) catch null else null,
        .incoming_x_forwarded_for = if (incoming_x_forwarded_for) |xff| allocator.dupe(u8, xff) catch null else null,
        .api_version = api_version,
    };
    return job;
}

fn dupeOrEmpty(allocator: std.mem.Allocator, src: []const u8) []u8 {
    return allocator.dupe(u8, src) catch allocator.alloc(u8, 0) catch unreachable;
}

fn destroyAsyncCommandJob(job: *AsyncCommandJob) void {
    const alloc = job.allocator;
    if (job.command_id.len > 0) alloc.free(job.command_id);
    if (job.command_name.len > 0) alloc.free(job.command_name);
    if (job.upstream_path.len > 0) alloc.free(job.upstream_path);
    if (job.envelope.len > 0) alloc.free(job.envelope);
    if (job.correlation_id.len > 0) alloc.free(job.correlation_id);
    if (job.client_ip.len > 0) alloc.free(job.client_ip);
    if (job.identity) |id| alloc.free(id);
    if (job.incoming_host) |h| alloc.free(h);
    if (job.incoming_x_forwarded_for) |xff| alloc.free(xff);
    alloc.destroy(job);
}

fn runAsyncCommandJob(job: *AsyncCommandJob) void {
    defer destroyAsyncCommandJob(job);

    job.state.commandLifecycleSetRunning(job.command_id);
    const exec = executeBoundedControlPlaneJsonProxy(
        job.allocator,
        job.cfg,
        .commands,
        job.cfg.proxy_pass_commands_prefix,
        job.upstream_path,
        job.envelope,
        job.correlation_id,
        job.client_ip,
        job.identity,
        null,
        null,
        null,
        job.api_version,
        job.incoming_host,
        job.incoming_x_forwarded_for,
        std.io.null_writer,
        job.state,
        false,
        null,
    ) catch |err| {
        job.state.commandLifecycleSetFailed(job.command_id, @errorName(err));
        return;
    };

    switch (exec) {
        .streamed_status => |streamed| {
            job.state.commandLifecycleSetCompleted(job.command_id, streamed.status, "", JSON_CONTENT_TYPE);
        },
        .buffered => |resp| {
            defer job.allocator.free(resp.body);
            defer job.allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| job.allocator.free(cd);
            if (resp.location) |location| job.allocator.free(location);
            job.state.commandLifecycleSetCompleted(job.command_id, resp.status, resp.body, resp.content_type);
        },
    }
}

test "async command jobs copy request-owned inputs onto long-lived allocator" {
    var request_arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    const request_allocator = request_arena_state.allocator();

    const command_id = try request_allocator.dupe(u8, "cmd-request-owned");
    const command_name = try request_allocator.dupe(u8, "chat.send");
    const upstream_path = try request_allocator.dupe(u8, "/run");
    const envelope = try request_allocator.dupe(u8, "{\"ok\":true}");
    const correlation_id = try request_allocator.dupe(u8, "corr-123");
    const client_ip = try request_allocator.dupe(u8, "127.0.0.1");
    const identity = try request_allocator.dupe(u8, "identity-1");
    const incoming_host = try request_allocator.dupe(u8, "example.test");
    const incoming_xff = try request_allocator.dupe(u8, "10.0.0.1");

    var cfg: edge_config.EdgeConfig = undefined;
    var state: GatewayState = undefined;
    state.allocator = std.testing.allocator;

    const job = try createAsyncCommandJob(
        std.testing.allocator,
        &cfg,
        &state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        1,
        incoming_host,
        incoming_xff,
    );
    defer destroyAsyncCommandJob(job);

    request_arena_state.deinit();

    try std.testing.expectEqualStrings("cmd-request-owned", job.command_id);
    try std.testing.expectEqualStrings("chat.send", job.command_name);
    try std.testing.expectEqualStrings("/run", job.upstream_path);
    try std.testing.expectEqualStrings("{\"ok\":true}", job.envelope);
    try std.testing.expectEqualStrings("corr-123", job.correlation_id);
    try std.testing.expectEqualStrings("127.0.0.1", job.client_ip);
    try std.testing.expectEqualStrings("identity-1", job.identity.?);
    try std.testing.expectEqualStrings("example.test", job.incoming_host.?);
    try std.testing.expectEqualStrings("10.0.0.1", job.incoming_x_forwarded_for.?);
}

pub fn parseLastEventId(raw: ?[]const u8) u64 {
    const value = raw orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0;
}

pub fn applyInternalRedirectRules(
    method: []const u8,
    path: []const u8,
    rules: []const edge_config.EdgeConfig.InternalRedirectRule,
    named_locations: []const edge_config.EdgeConfig.NamedLocation,
) []const u8 {
    var current = path;
    var hops: usize = 0;
    while (hops < 6) : (hops += 1) {
        var changed = false;
        for (rules) |rule| {
            if (!http.rewrite.methodMatches(rule.method, method)) continue;
            if (!http.rewrite.regexMatches(rule.pattern, current)) continue;
            if (rule.target.len > 1 and rule.target[0] == '@') {
                if (resolveNamedLocation(rule.target[1..], named_locations)) |named| {
                    current = named;
                    changed = true;
                    break;
                }
            } else {
                current = rule.target;
                changed = true;
                break;
            }
        }
        if (!changed) break;
    }
    return current;
}

pub fn evaluateConditionalRules(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.ConditionalRule,
    path: []const u8,
    request_uri: []const u8,
    host: []const u8,
    args: []const u8,
) !?http.rewrite.Outcome {
    for (rules) |rule| {
        const input = switch (rule.variable) {
            .request_uri => request_uri,
            .http_host => host,
            .args => args,
        };

        switch (rule.action) {
            .rewrite => |rw| {
                const replacement = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    rw.replacement,
                    rule.case_insensitive,
                ) orelse continue;
                switch (rw.flag) {
                    .redirect => return .{ .redirect = .{ .status = 302, .location = replacement } },
                    .permanent => return .{ .redirect = .{ .status = 301, .location = replacement } },
                    .@"break", .last => return .{ .pass = replacement },
                }
            },
            .returned => |ret| {
                const body = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    ret.body,
                    rule.case_insensitive,
                ) orelse continue;
                return .{ .returned = .{ .status = ret.status, .body = body } };
            },
        }
    }
    _ = path;
    return null;
}

fn resolveNamedLocation(name: []const u8, named_locations: []const edge_config.EdgeConfig.NamedLocation) ?[]const u8 {
    for (named_locations) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.path;
    }
    return null;
}

pub fn spawnMirrorRequests(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.MirrorRule,
    method: []const u8,
    path: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    content_type: ?[]const u8,
) void {
    for (rules) |rule| {
        if (!http.rewrite.methodMatches(rule.method, method)) continue;
        if (!http.rewrite.regexMatches(rule.pattern, path)) continue;
        var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
        defer client.deinit();
        const uri = std.Uri.parse(rule.target_url) catch continue;
        var header_buf: [1024]u8 = undefined;
        var headers = [_]std.http.Header{
            .{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id },
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
            .{ .name = "X-Mirror-Client-IP", .value = client_ip },
            .{ .name = "Content-Type", .value = content_type orelse "application/octet-stream" },
        };
        var req = client.request(.POST, uri, .{
            .extra_headers = headers[0..],
            .headers = .{ .content_type = .{ .override = content_type orelse "application/octet-stream" } },
        }) catch continue;
        defer req.deinit();
        req.sendBodyComplete(@constCast(body)) catch continue;
        _ = req.receiveHead(&header_buf) catch {}; // subrequest response is intentionally ignored; fire-and-forget
    }
}

const SubrequestPayload = struct {
    method: std.http.Method = .GET,
    url: []u8,
    body: ?[]u8 = null,
};

const SubrequestResult = struct {
    status: u16,
    body: []u8,
    content_type: []const u8,
};

fn parseSubrequestPayload(allocator: std.mem.Allocator, body: []const u8) !SubrequestPayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const url_val = obj.get("url") orelse return error.InvalidPayload;
    if (url_val != .string) return error.InvalidPayload;
    const method = if (obj.get("method")) |m| blk: {
        if (m != .string) break :blk std.http.Method.GET;
        break :blk if (std.ascii.eqlIgnoreCase(m.string, "POST")) std.http.Method.POST else std.http.Method.GET;
    } else std.http.Method.GET;
    const req_body = if (obj.get("body")) |b| blk: {
        if (b != .string) break :blk null;
        break :blk try allocator.dupe(u8, b.string);
    } else null;
    return .{
        .method = method,
        .url = try allocator.dupe(u8, url_val.string),
        .body = req_body,
    };
}

fn executeSubrequest(allocator: std.mem.Allocator, url: []const u8, method: std.http.Method, req_body: ?[]const u8) !SubrequestResult {
    var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer client.deinit();
    const uri = try std.Uri.parse(url);
    var header_buf: [16 * 1024]u8 = undefined;
    var req = try client.request(method, uri, .{});
    defer req.deinit();
    if (req_body) |b| {
        try req.sendBodyComplete(@constCast(b));
    } else {
        try req.sendBodiless();
    }
    var resp = try req.receiveHead(&header_buf);
    const resp_status = @intFromEnum(resp.head.status);
    const resp_content_type = resp.head.content_type orelse "application/octet-stream";
    var resp_buf: [8192]u8 = undefined;
    const body_data = try resp.reader(&resp_buf).allocRemaining(allocator, .limited(2 * 1024 * 1024));
    return .{
        .status = resp_status,
        .body = body_data,
        .content_type = resp_content_type,
    };
}

pub const Http3DispatchContext = struct {
    config_store: *ReloadableConfigStore,
    cfg: *const edge_config.EdgeConfig,
    cfg_lease: ?*gs.ConfigLease = null,
    state: *GatewayState,
};

const Http3LocationOutcome = union(enum) {
    not_handled,
    handled,
    rewritten: struct {
        path: []const u8,
        query: ?[]const u8,
    },
};

/// Shape an HTTP/3 `http.Response` for a return plan: status, body, content-type,
/// correlation id, and a `Location` header for redirects. Returns the emitted
/// status. Kept free of gateway state (metrics/security headers stay in the
/// caller) so the h3 rendering — the part that had drifted from h1 — is
/// unit-testable without a live QUIC listener (#201).
fn shapeHttp3ReturnResponse(
    allocator: std.mem.Allocator,
    response: *http.Response,
    correlation_id: []const u8,
    plan: ReturnResponsePlan,
) !u16 {
    switch (plan) {
        .method_not_allowed => {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Method Not Allowed", correlation_id);
            _ = response
                .setStatus(.method_not_allowed)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            return 405;
        },
        .redirect => |r| {
            _ = response
                .setStatus(@enumFromInt(r.status))
                .setBody(r.location)
                .setContentType("text/plain; charset=utf-8")
                .setHeader(http.correlation.HEADER_NAME, correlation_id)
                .setHeader("location", r.location);
            return r.status;
        },
        .body => |b| {
            _ = response
                .setStatus(@enumFromInt(b.status))
                .setBody(b.body)
                .setContentType("text/plain; charset=utf-8")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            return b.status;
        },
    }
}

test "shapeHttp3ReturnResponse: non-redirect return on a non-GET/HEAD method renders 405 JSON" {
    const allocator = std.testing.allocator;
    var response = http.Response.init(allocator);
    defer response.deinit();
    const status = try shapeHttp3ReturnResponse(allocator, &response, "cid", planReturnResponse(false, 200, "ok"));
    try std.testing.expectEqual(@as(u16, 405), status);
    try std.testing.expectEqual(@as(u16, 405), @intFromEnum(response.status));
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type") orelse "");
    try std.testing.expect(response.body != null);
}

test "shapeHttp3ReturnResponse: redirect sets status and Location header" {
    const allocator = std.testing.allocator;
    var response = http.Response.init(allocator);
    defer response.deinit();
    const status = try shapeHttp3ReturnResponse(allocator, &response, "cid", planReturnResponse(false, 302, "/new"));
    try std.testing.expectEqual(@as(u16, 302), status);
    try std.testing.expectEqual(@as(u16, 302), @intFromEnum(response.status));
    try std.testing.expectEqualStrings("/new", response.headers.get("location") orelse "");
}

test "shapeHttp3ReturnResponse: GET body path renders the body" {
    const allocator = std.testing.allocator;
    var response = http.Response.init(allocator);
    defer response.deinit();
    const status = try shapeHttp3ReturnResponse(allocator, &response, "cid", planReturnResponse(true, 200, "ok"));
    try std.testing.expectEqual(@as(u16, 200), status);
    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(response.status));
    try std.testing.expectEqualStrings("ok", response.body orelse "");
}

fn finalizeHttp3Response(response: *http.Response) void {
    if (response.headers.get("x-request-id")) |request_id| {
        _ = response.setHeader(http.correlation.HEADER_NAME, request_id);
    } else if (response.headers.get("x-correlation-id")) |correlation_id| {
        _ = response.setHeader(http.correlation.REQUEST_HEADER_NAME, correlation_id);
    }
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(if (response.body) |body| body.len else 0);
}

fn rejectHttp3ProxyError(
    allocator: std.mem.Allocator,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    status: http.Status,
    code: []const u8,
    message: []const u8,
    correlation_id: []const u8,
) !void {
    try rejectHttp3ProxyErrorWithState(allocator, response, ctx.state, status, code, message, correlation_id);
}

fn rejectHttp3ProxyErrorWithState(
    allocator: std.mem.Allocator,
    response: *http.Response,
    state: *GatewayState,
    status: http.Status,
    code: []const u8,
    message: []const u8,
    correlation_id: []const u8,
) !void {
    const payload = try buildApiErrorJson(allocator, code, message, correlation_id);
    _ = response
        .setStatus(status)
        .setBodyOwned(payload)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(state, response);
    state.metricsRecord(@intFromEnum(status));
    state.metricsRecordErrorCode(code);
}

fn applyHttp3ProxyResponse(
    allocator: std.mem.Allocator,
    response: *http.Response,
    state: *GatewayState,
    upstream_response: *const gproxy_runtime.DataPlaneProxyResponse,
    correlation_id: []const u8,
) !void {
    const buffered_response = upstream_response.boundedBufferedForCompatibility();

    _ = response
        .setStatus(@enumFromInt(buffered_response.status_code))
        .setBodyOwned(try allocator.dupe(u8, buffered_response.body))
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    for (buffered_response.headers) |header| {
        _ = response.setHeader(header.name, header.value);
    }
    finalizeHttp3Response(response);
    applyResponseHeaders(state, response);
    state.metricsRecord(upstream_response.statusCode());
}

fn recordHttp3ProxyOutcome(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    selection_base_url: []const u8,
    absolute_target: bool,
    status_code: u16,
    permit: http.circuit_breaker.Permit,
) void {
    if (status_code >= 500) {
        if (absolute_target) {
            state.circuitRecordFailurePermit(permit);
        } else {
            state.recordProxyUpstreamFailure(cfg, selection_base_url, permit);
        }
    } else if (status_code != @intFromEnum(http.Status.too_early)) {
        if (absolute_target) {
            state.circuitRecordSuccessPermit(permit);
        } else {
            state.recordProxyUpstreamSuccess(cfg, selection_base_url, permit);
        }
    } else {
        state.circuitReleasePermit(permit);
    }
}

const Http3BufferedProxyAttemptExecutor = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    cfg_lease: ?*gs.ConfigLease,
    state: *GatewayState,
    request: *const http.http3_session.StreamRequest,
    upstream_url: []const u8,
    unix_socket_path: ?[]const u8,
    method: []const u8,
    headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    selection_base_url: []const u8,
    absolute_target: bool,
    budget_start_ms: u64,
    last_attempt_start_ms: u64 = 0,
    circuit_permit: ?http.circuit_breaker.Permit = null,

    pub fn recordEarlyUpstream425Action(
        self: *Http3BufferedProxyAttemptExecutor,
        action: http.metrics.EarlyDataUpstream425Action,
    ) void {
        self.state.metricsRecordEarlyDataUpstream425(action);
    }

    pub fn recordEarlyRetryResult(
        self: *Http3BufferedProxyAttemptExecutor,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        self.state.metricsRecordEarlyDataRetry(result);
    }

    pub fn perAttemptTimeoutMs(self: *Http3BufferedProxyAttemptExecutor) !u32 {
        if (self.cfg.upstream_timeout_budget_ms == 0) return self.cfg.upstream_timeout_ms;
        const elapsed_ms = http.event_loop.monotonicMs() - self.budget_start_ms;
        if (elapsed_ms >= self.cfg.upstream_timeout_budget_ms) return error.ProxyBudgetExhausted;
        const remaining = self.cfg.upstream_timeout_budget_ms - elapsed_ms;
        if (self.cfg.upstream_timeout_ms == 0) {
            return @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
        }
        return @intCast(@min(@as(u64, self.cfg.upstream_timeout_ms), remaining));
    }

    pub fn execute(
        self: *Http3BufferedProxyAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !gproxy_runtime.DataPlaneProxyResponse {
        _ = attempt;
        if (self.circuit_permit == null) {
            self.circuit_permit = self.state.circuitTryAcquirePermit() orelse return error.CircuitOpen;
        }
        const per_attempt_timeout_ms = try self.perAttemptTimeoutMs();
        self.state.recordUpstreamAttemptStart(self.selection_base_url);
        self.last_attempt_start_ms = http.event_loop.monotonicMs();
        const resp = executeBufferedDataPlaneProxyRequest(
            self.allocator,
            self.cfg,
            self.upstream_url,
            self.unix_socket_path,
            self.method,
            self.headers,
            self.body,
            self.correlation_id,
            self.client_ip,
            self.forwarded_proto,
            self.incoming_host,
            null,
            null,
            null,
            null,
            null,
            forward_early_data,
            per_attempt_timeout_ms,
            self.cfg.upstream_connect_timeout_ms,
            self.cfg.upstream_response_timeout_ms,
            null,
            &self.state.upstream_pool,
            &self.state.h2_pool,
        );
        self.state.recordUpstreamAttemptEnd(self.selection_base_url);
        return resp;
    }

    pub fn onBufferedResponse(
        self: *Http3BufferedProxyAttemptExecutor,
        result: *gproxy_runtime.DataPlaneProxyResponse,
    ) !void {
        const upstream_ttfb_ms = http.event_loop.monotonicMs() - self.last_attempt_start_ms;
        self.state.metricsRecordProxyBufferedRequest(result.bodyLen(), upstream_ttfb_ms);
    }

    pub fn onStaleConnectionRetry(
        self: *Http3BufferedProxyAttemptExecutor,
        stale_conn_retries: usize,
        max_stale_conn_retries: usize,
    ) !void {
        self.state.logger.warn(self.correlation_id, "h3 proxy retrying on fresh connection after stale upstream keep-alive ({d}/{d})", .{ stale_conn_retries, max_stale_conn_retries });
    }

    pub fn releaseCircuitProbe(self: *Http3BufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        self.state.circuitReleasePermit(permit);
        self.circuit_permit = null;
    }

    fn recordCircuitFailure(self: *Http3BufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        if (self.absolute_target) {
            self.state.circuitRecordFailurePermit(permit);
        } else {
            self.state.recordProxyUpstreamFailure(self.cfg, self.selection_base_url, permit);
        }
        self.circuit_permit = null;
    }

    fn recordCircuitSuccess(self: *Http3BufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        if (self.absolute_target) {
            self.state.circuitRecordSuccessPermit(permit);
        } else {
            self.state.recordProxyUpstreamSuccess(self.cfg, self.selection_base_url, permit);
        }
        self.circuit_permit = null;
    }

    pub fn onTerminalAttemptError(
        self: *Http3BufferedProxyAttemptExecutor,
        err: anyerror,
    ) !void {
        if (gproxy_runtime.proxyAttemptErrorCountsAsUpstreamFailure(err)) {
            self.recordCircuitFailure();
        } else {
            self.releaseCircuitProbe();
        }
    }

    pub fn onConfiguredErrorRetry(
        self: *Http3BufferedProxyAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        err: anyerror,
    ) !void {
        self.state.logger.warn(self.correlation_id, "h3 proxy attempt {d}/{d} failed: {}", .{ configured_attempt_index + 1, max_attempts, err });
    }

    pub fn onEarly425Retry(
        self: *Http3BufferedProxyAttemptExecutor,
        result: *gproxy_runtime.DataPlaneProxyResponse,
    ) !void {
        self.state.logger.debug(self.correlation_id, "h3 retrying early-data upstream 425 once after downstream handshake completion", .{});
        self.state.metricsReleaseProxyBufferedBytes(result.bodyLen());
        result.deinit(self.allocator);
    }

    pub fn parkEarly425Retry(
        self: *Http3BufferedProxyAttemptExecutor,
        result: *gproxy_runtime.DataPlaneProxyResponse,
    ) !void {
        self.state.logger.debug(self.correlation_id, "h3 parking early-data upstream 425 retry until downstream handshake completion", .{});
        var plan = try Http3Early425ProxyContinuation.init(self.allocator, self);
        errdefer {
            plan.circuit_permit = null;
            plan.deinit(self.allocator);
            self.allocator.destroy(plan);
        }
        try self.request.parkEarly425Retry(.{
            .ctx = plan,
            .resume_fn = Http3Early425ProxyContinuation.run,
            .deinit_fn = Http3Early425ProxyContinuation.destroy,
        });
        self.circuit_permit = null;
        self.state.metricsReleaseProxyBufferedBytes(result.bodyLen());
        result.deinit(self.allocator);
    }

    pub fn onEarly425HandshakeFailure(
        self: *Http3BufferedProxyAttemptExecutor,
        err: anyerror,
    ) !void {
        self.state.logger.warn(self.correlation_id, "h3 could not complete downstream handshake before early-data 425 retry: {}", .{err});
    }

    pub fn onConfigured5xxRetry(
        self: *Http3BufferedProxyAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        result: *gproxy_runtime.DataPlaneProxyResponse,
    ) !void {
        self.recordCircuitFailure();
        self.state.logger.warn(self.correlation_id, "h3 proxy attempt {d}/{d} got {d}, retrying", .{ configured_attempt_index + 1, max_attempts, result.statusCode() });
        self.state.metricsReleaseProxyBufferedBytes(result.bodyLen());
        result.deinit(self.allocator);
    }
};

const Http3Early425ProxyContinuation = struct {
    config_lease: gs.ConfigLease,
    cfg_snapshot: edge_config.EdgeConfig,
    state: *GatewayState,
    upstream_url: []u8,
    unix_socket_path: ?[]const u8,
    method: []u8,
    headers: http.Headers,
    body: []u8,
    correlation_id: []u8,
    client_ip: []u8,
    forwarded_proto: []u8,
    incoming_host: ?[]u8,
    selection_base_url: []const u8,
    absolute_target: bool,
    budget_start_ms: u64,
    last_attempt_start_ms: u64 = 0,
    circuit_permit: ?http.circuit_breaker.Permit = null,
    transport_early: bool,
    test_execute_ctx: ?*anyopaque = null,
    test_execute_fn: ?*const fn (?*anyopaque, *Http3Early425ProxyContinuation, u32, bool) anyerror!gproxy_runtime.DataPlaneProxyResponse = null,

    fn init(
        allocator: std.mem.Allocator,
        executor: *const Http3BufferedProxyAttemptExecutor,
    ) !*Http3Early425ProxyContinuation {
        const plan = try allocator.create(Http3Early425ProxyContinuation);
        errdefer allocator.destroy(plan);

        const source_lease = executor.cfg_lease orelse return error.Http3Early425RetryCannotPark;
        var retained_lease = source_lease.retain();
        errdefer retained_lease.release();

        const method = try allocator.dupe(u8, executor.method);
        errdefer allocator.free(method);
        var headers = http.Headers.init(allocator);
        errdefer headers.deinit();
        for (executor.headers.iterator()) |header| {
            try headers.append(header.name, header.value);
        }
        const body = try allocator.dupe(u8, executor.body);
        errdefer allocator.free(body);
        const upstream_url = try allocator.dupe(u8, executor.upstream_url);
        errdefer allocator.free(upstream_url);
        const correlation_id = try allocator.dupe(u8, executor.correlation_id);
        errdefer allocator.free(correlation_id);
        const client_ip = try allocator.dupe(u8, executor.client_ip);
        errdefer allocator.free(client_ip);
        const forwarded_proto = try allocator.dupe(u8, executor.forwarded_proto);
        errdefer allocator.free(forwarded_proto);
        const incoming_host = if (executor.incoming_host) |value| try allocator.dupe(u8, value) else null;
        errdefer if (incoming_host) |value| allocator.free(value);

        plan.* = .{
            .config_lease = retained_lease,
            .cfg_snapshot = executor.cfg.*,
            .state = executor.state,
            .upstream_url = upstream_url,
            .unix_socket_path = executor.unix_socket_path,
            .method = method,
            .headers = headers,
            .body = body,
            .correlation_id = correlation_id,
            .client_ip = client_ip,
            .forwarded_proto = forwarded_proto,
            .incoming_host = incoming_host,
            .selection_base_url = executor.selection_base_url,
            .absolute_target = executor.absolute_target,
            .budget_start_ms = executor.budget_start_ms,
            .circuit_permit = executor.circuit_permit,
            .transport_early = executor.request.transport_early,
        };
        return plan;
    }

    fn deinit(self: *Http3Early425ProxyContinuation, allocator: std.mem.Allocator) void {
        if (self.circuit_permit) |permit| {
            self.state.circuitReleasePermit(permit);
            self.circuit_permit = null;
        }
        self.config_lease.release();
        allocator.free(self.upstream_url);
        allocator.free(self.method);
        self.headers.deinit();
        allocator.free(self.body);
        allocator.free(self.correlation_id);
        allocator.free(self.client_ip);
        allocator.free(self.forwarded_proto);
        if (self.incoming_host) |value| allocator.free(value);
        self.* = undefined;
    }

    fn destroy(ctx: *anyopaque, allocator: std.mem.Allocator) void {
        const self: *Http3Early425ProxyContinuation = @ptrCast(@alignCast(ctx));
        self.deinit(allocator);
        allocator.destroy(self);
    }

    fn perAttemptTimeoutMs(self: *Http3Early425ProxyContinuation) !u32 {
        if (self.cfg_snapshot.upstream_timeout_budget_ms == 0) return self.cfg_snapshot.upstream_timeout_ms;
        const elapsed_ms = http.event_loop.monotonicMs() - self.budget_start_ms;
        if (elapsed_ms >= self.cfg_snapshot.upstream_timeout_budget_ms) return error.ProxyBudgetExhausted;
        const remaining = self.cfg_snapshot.upstream_timeout_budget_ms - elapsed_ms;
        if (self.cfg_snapshot.upstream_timeout_ms == 0) {
            return @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
        }
        return @intCast(@min(@as(u64, self.cfg_snapshot.upstream_timeout_ms), remaining));
    }

    fn execute(self: *Http3Early425ProxyContinuation, per_attempt_timeout_ms: u32, forward_early_data: bool) !gproxy_runtime.DataPlaneProxyResponse {
        if (self.circuit_permit == null) {
            self.circuit_permit = self.state.circuitTryAcquirePermit() orelse return error.CircuitOpen;
        }
        if (self.test_execute_fn) |test_execute| {
            return test_execute(self.test_execute_ctx, self, per_attempt_timeout_ms, forward_early_data);
        }
        self.state.recordUpstreamAttemptStart(self.selection_base_url);
        self.last_attempt_start_ms = http.event_loop.monotonicMs();
        const resp = executeBufferedDataPlaneProxyRequest(
            self.headers.allocator,
            &self.cfg_snapshot,
            self.upstream_url,
            self.unix_socket_path,
            self.method,
            &self.headers,
            self.body,
            self.correlation_id,
            self.client_ip,
            self.forwarded_proto,
            self.incoming_host,
            null,
            null,
            null,
            null,
            null,
            forward_early_data,
            per_attempt_timeout_ms,
            self.cfg_snapshot.upstream_connect_timeout_ms,
            self.cfg_snapshot.upstream_response_timeout_ms,
            null,
            &self.state.upstream_pool,
            &self.state.h2_pool,
        );
        self.state.recordUpstreamAttemptEnd(self.selection_base_url);
        return resp;
    }

    fn run(ctx: *anyopaque, allocator: std.mem.Allocator, response: *http.Response) !void {
        const self: *Http3Early425ProxyContinuation = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.transport_early);
        const max_stale_conn_retries: usize = 2;
        var stale_conn_retries: usize = 0;
        var retried_recorded = false;
        while (true) {
            const per_attempt_timeout_ms = self.perAttemptTimeoutMs() catch |err| {
                self.state.metricsRecordEarlyDataRetry(.failure);
                if (err == error.OutOfMemory) return error.OutOfMemory;
                if (self.circuit_permit) |permit| {
                    self.state.circuitReleasePermit(permit);
                    self.circuit_permit = null;
                }
                try rejectHttp3ProxyErrorWithState(allocator, response, self.state, .gateway_timeout, "upstream_timeout", "Upstream request timed out", self.correlation_id);
                return;
            };
            if (!retried_recorded) {
                self.state.metricsRecordEarlyDataUpstream425(.retried);
                retried_recorded = true;
            }
            var upstream_response = self.execute(per_attempt_timeout_ms, false) catch |err| {
                if (gproxy_runtime.shouldRetryStaleUpstreamConnection(err, self.method, stale_conn_retries, max_stale_conn_retries, true)) {
                    stale_conn_retries += 1;
                    self.state.logger.warn(self.correlation_id, "h3 parked proxy retrying on fresh connection after stale upstream keep-alive ({d}/{d})", .{ stale_conn_retries, max_stale_conn_retries });
                    continue;
                }
                self.state.metricsRecordEarlyDataRetry(.failure);
                if (err == error.ProxyBudgetExhausted or err == error.RequestCancelled) {
                    const permit = self.circuit_permit;
                    if (err == error.ProxyBudgetExhausted) {
                        if (permit) |p| self.state.circuitReleasePermit(p);
                        self.circuit_permit = null;
                    }
                    if (err == error.RequestCancelled) {
                        if (permit) |p| {
                            if (self.absolute_target) {
                                self.state.circuitRecordFailurePermit(p);
                            } else {
                                self.state.recordProxyUpstreamFailure(&self.cfg_snapshot, self.selection_base_url, p);
                            }
                            self.circuit_permit = null;
                        }
                    }
                    try rejectHttp3ProxyErrorWithState(allocator, response, self.state, .gateway_timeout, "upstream_timeout", "Upstream request timed out", self.correlation_id);
                    return;
                }
                if (err == error.UpstreamAtCapacity) {
                    if (self.circuit_permit) |p| self.state.circuitReleasePermit(p);
                    self.circuit_permit = null;
                    try rejectHttp3ProxyErrorWithState(allocator, response, self.state, .service_unavailable, "upstream_saturated", "Upstream connection limit reached", self.correlation_id);
                    return;
                }
                if (err == error.CircuitOpen) {
                    try rejectHttp3ProxyErrorWithState(allocator, response, self.state, .service_unavailable, "upstream_circuit_open", "Upstream circuit breaker open", self.correlation_id);
                    return;
                }
                if (err == error.OutOfMemory) {
                    if (self.circuit_permit) |p| self.state.circuitReleasePermit(p);
                    self.circuit_permit = null;
                    return error.OutOfMemory;
                }
                const permit = self.circuit_permit;
                if (gproxy_runtime.proxyAttemptErrorCountsAsUpstreamFailure(err)) {
                    if (permit) |p| {
                        if (self.absolute_target) {
                            self.state.circuitRecordFailurePermit(p);
                        } else {
                            self.state.recordProxyUpstreamFailure(&self.cfg_snapshot, self.selection_base_url, p);
                        }
                        self.circuit_permit = null;
                    }
                } else {
                    if (permit) |p| self.state.circuitReleasePermit(p);
                    self.circuit_permit = null;
                }
                const err_status: http.Status = switch (err) {
                    error.Timeout, error.TimedOut, error.WouldBlock => .gateway_timeout,
                    else => .bad_gateway,
                };
                const err_code = if (err_status == .gateway_timeout) "upstream_timeout" else "upstream_error";
                const err_msg = if (err_status == .gateway_timeout) "Upstream request timed out" else "Upstream connection failed";
                try rejectHttp3ProxyErrorWithState(allocator, response, self.state, err_status, err_code, err_msg, self.correlation_id);
                return;
            };
            defer upstream_response.deinit(allocator);
            const upstream_ttfb_ms = http.event_loop.monotonicMs() - self.last_attempt_start_ms;
            self.state.metricsRecordProxyBufferedRequest(upstream_response.bodyLen(), upstream_ttfb_ms);
            defer self.state.metricsReleaseProxyBufferedBytes(upstream_response.bodyLen());
            if (upstream_response.statusCode() == @intFromEnum(http.Status.too_early)) {
                self.state.metricsRecordEarlyDataUpstream425(.forwarded);
                self.state.metricsRecordEarlyDataRetry(.too_early);
            } else {
                self.state.metricsRecordEarlyDataRetry(.success);
            }
            if (self.circuit_permit) |permit| {
                recordHttp3ProxyOutcome(self.state, &self.cfg_snapshot, self.selection_base_url, self.absolute_target, upstream_response.statusCode(), permit);
                self.circuit_permit = null;
            }
            try applyHttp3ProxyResponse(allocator, response, self.state, &upstream_response, self.correlation_id);
            return;
        }
    }
};

fn handleHttp3LocationProxyPass(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    matched: http.location_router.MatchResult,
    request_path: []const u8,
    request_query: ?[]const u8,
    target: []const u8,
    correlation_id: []const u8,
    early_ctx: *http.request_context.EarlyDataContext,
    forward_early_data: bool,
) !void {
    const resolved = try resolveProxyTarget(allocator, ctx.cfg.upstream_base_url, target, proxySuffixPathForLocation(request_path, matched, ctx.cfg.location_blocks));
    defer allocator.free(resolved.url);
    var upstream_url = try appendProxyQueryString(allocator, resolved.url, request_query);
    defer upstream_url.deinit(allocator);
    const absolute_target = gs.isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"));

    const max_attempts = gproxy_runtime.proxyRetryAttemptLimit(ctx.cfg.upstream_retry_attempts, ctx.cfg.upstream_retry_idempotent_only, request.method);
    var attempt_executor = Http3BufferedProxyAttemptExecutor{
        .allocator = allocator,
        .cfg = ctx.cfg,
        .cfg_lease = ctx.cfg_lease,
        .state = ctx.state,
        .request = request,
        .upstream_url = upstream_url.value,
        .unix_socket_path = resolved.unix_socket_path,
        .method = request.method,
        .headers = &request.headers,
        .body = request.body,
        .correlation_id = correlation_id,
        .client_ip = request.headers.get("x-real-ip") orelse "unknown",
        .forwarded_proto = if (edge_config.hasTlsFiles(ctx.cfg)) "https" else "http",
        .incoming_host = request.headers.get(":authority") orelse request.headers.get("host"),
        .selection_base_url = ctx.cfg.upstream_base_url,
        .absolute_target = absolute_target,
        .budget_start_ms = http.event_loop.monotonicMs(),
    };

    var upstream_response: gproxy_runtime.DataPlaneProxyResponse = switch (try gproxy_runtime.runBufferedProxyAttempts(
        early_ctx,
        forward_early_data,
        request.method,
        matched.block,
        max_attempts,
        2,
        ctx.cfg.upstream_retry_idempotent_only,
        &attempt_executor,
    )) {
        .response => |upstream_response| upstream_response,
        .early_425_retry_parked => return error.Http3RequestParked,
        .upstream_at_capacity => {
            try rejectHttp3ProxyError(allocator, response, ctx, .service_unavailable, "upstream_saturated", "Upstream connection limit reached", correlation_id);
            return;
        },
        .circuit_open => {
            try rejectHttp3ProxyError(allocator, response, ctx, .service_unavailable, "upstream_circuit_open", "Upstream circuit breaker open", correlation_id);
            return;
        },
        .request_cancelled, .retry_budget_exhausted => {
            try rejectHttp3ProxyError(allocator, response, ctx, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id);
            return;
        },
        .terminal_error => |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            const err_status: http.Status = switch (err) {
                error.Timeout, error.TimedOut, error.WouldBlock => .gateway_timeout,
                else => .bad_gateway,
            };
            const err_code = if (err_status == .gateway_timeout) "upstream_timeout" else "upstream_error";
            const err_msg = if (err_status == .gateway_timeout) "Upstream request timed out" else "Upstream connection failed";
            try rejectHttp3ProxyError(allocator, response, ctx, err_status, err_code, err_msg, correlation_id);
            return;
        },
    };
    defer upstream_response.deinit(allocator);
    defer ctx.state.metricsReleaseProxyBufferedBytes(upstream_response.bodyLen());
    if (attempt_executor.circuit_permit) |permit| {
        recordHttp3ProxyOutcome(ctx.state, ctx.cfg, ctx.cfg.upstream_base_url, absolute_target, upstream_response.statusCode(), permit);
        attempt_executor.circuit_permit = null;
    }
    try applyHttp3ProxyResponse(allocator, response, ctx.state, &upstream_response, correlation_id);
}

fn handleHttp3StaticLocation(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
) !bool {
    if (!(std.mem.eql(u8, request.method, "GET") or std.mem.eql(u8, request.method, "HEAD"))) return false;

    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request_path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, 404)) orelse return false;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(302);
                return true;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(302);
                    return true;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    // Compress the body for HTTP/3 responses (all H3 responses are buffered —
    // no sendfile path). Compression is skipped for HEAD, 304, or when config
    // or client do not allow it.
    const is_head_req = std.mem.eql(u8, request.method, "HEAD");
    const raw_body: []const u8 = if (is_head_req) "" else (served.body orelse "");
    var compress_result: http.compression.CompressionResult = .{ .body = null, .compressed = false };
    defer if (compress_result.body) |b| allocator.free(b);
    if (!is_head_req and raw_body.len > 0) {
        compress_result = http.compression.compressResponse(
            allocator,
            raw_body,
            served.content_type,
            request.headers.get("accept-encoding"),
            ctx.state.compression_config,
        );
    }
    const out_body: []const u8 = compress_result.body orelse raw_body;
    _ = response
        .setStatus(served.status_code)
        .setBodyOwned(try allocator.dupe(u8, out_body))
        .setContentType(served.content_type)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    if (compress_result.compressed) {
        if (compress_result.encoding) |enc| _ = response.setHeader("Content-Encoding", enc.headerValue());
        _ = response.setHeader("Vary", "Accept-Encoding");
    }
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(out_body.len);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(@intFromEnum(served.status_code));
    return true;
}

fn rejectHttp3AuthRequiredLocation(
    allocator: std.mem.Allocator,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    correlation_id: []const u8,
) !void {
    const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
    _ = response
        .setStatus(.unauthorized)
        .setBodyOwned(payload)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(401);
    ctx.state.metricsRecordErrorCode("unauthorized");
}

fn routeHttp3Location(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
    correlation_id: []const u8,
) !Http3LocationOutcome {
    // Share the h1/h3 route-matching precedence (#201, PR 3). h3 serves only
    // location routes today; the reload-status and metrics endpoints (which the
    // shared resolver ranks ahead of locations) fall through to the caller's 404
    // — h3 does not expose those operational endpoints yet.
    const route_decision = resolveRoutePath(allocator, ctx.cfg.metrics_path, ctx.cfg.location_blocks, request_path);

    var early_ctx = http.request_context.EarlyDataContext{
        .transport_early = request.transport_early,
        .inbound_marker = request.headers.hasEarlyDataMarker(),
        .downstream_handshake = .{
            .ctx = @constCast(request),
            .is_complete_fn = h3RequestHandshakeComplete,
            .wait_or_drive_fn = h3RequestDriveHandshake,
        },
    };
    if (metricsEarlyDataSource(early_ctx)) |source| {
        ctx.state.metricsRecordEarlyDataRequest(.h3, source);
    }

    const decision = earlyDataDecisionForRawMethod(
        allocator,
        ctx.cfg,
        early_ctx,
        request.method,
        request_path,
        request.body.len != 0,
    );
    const forward_early_data = h3ForwardEarlyDataMarker(early_ctx, decision);
    switch (decision) {
        .execute_local => {
            ctx.state.metricsRecordEarlyDataDecision(.h3, .accepted);
        },
        .forward_rfc8470 => {
            ctx.state.metricsRecordEarlyDataDecision(.h3, .forwarded);
        },
        .too_early, .defer_until_handshake => {
            ctx.state.metricsRecordEarlyDataDecision(.h3, if (decision == .defer_until_handshake) .deferred else .too_early);
            const payload = try buildApiErrorJson(allocator, "too_early", "Too Early", correlation_id);
            _ = response
                .setStatus(.too_early)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader("cache-control", "no-store")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(425);
            ctx.state.metricsRecordErrorCode("too_early");
            return .handled;
        },
        .ordinary => {},
    }

    const matched = switch (route_decision) {
        .location => |m| m,
        .reload_status, .metrics, .unmatched => return .not_handled,
    };

    const split = splitHttp3PathAndQuery(request.path);
    const request_query = split[1];
    if (matched.block.auth == .required) {
        try rejectHttp3AuthRequiredLocation(allocator, response, ctx, correlation_id);
        return .handled;
    }
    switch (matched.block.action) {
        .proxy_pass => |target| {
            try handleHttp3LocationProxyPass(allocator, request, response, ctx, matched, request_path, request_query, target, correlation_id, &early_ctx, forward_early_data);
            return .handled;
        },
        .return_response => |ret| {
            // h3 now enforces the same GET/HEAD guard as h1 for non-redirect
            // returns (previously missing — h3 served `return 200` on any method).
            const is_get_or_head = std.mem.eql(u8, request.method, "GET") or std.mem.eql(u8, request.method, "HEAD");
            const status = try shapeHttp3ReturnResponse(allocator, response, correlation_id, planReturnResponse(is_get_or_head, ret.status, ret.body));
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(status);
            return .handled;
        },
        .rewrite => |rw| {
            const rewritten_path, const rewritten_query = splitHttp3PathAndQuery(rw.replacement);
            return .{ .rewritten = .{ .path = rewritten_path, .query = rewritten_query } };
        },
        .static_root => |root_cfg| {
            if (try handleHttp3StaticLocation(allocator, request, response, matched, root_cfg, correlation_id, ctx, request_path)) {
                return .handled;
            }
            return .not_handled;
        },
        .fastcgi_pass => return .not_handled,
    }
}

test "routeHttp3Location rejects auth-required locations before action execution" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/private",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "secret" } },
        .auth = .required,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/private"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
    };
    defer request.deinit();
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/private", "h3-auth");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 401), @intFromEnum(response.status));
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type") orelse "");
    try std.testing.expect(std.mem.indexOf(u8, response.body orelse "", "\"code\":\"unauthorized\"") != null);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.err_unauthorized);
}

test "recordHttp3ProxyOutcome keeps absolute target failures out of passive health" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    state.circuit_mutex = .{};
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 30_000 });

    var cfg = minimalHttp3ProxyConfig(&.{});
    cfg.upstream_base_url = "http://configured.example";
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;

    recordHttp3ProxyOutcome(&state, &cfg, cfg.upstream_base_url, true, 500, state.circuitTryAcquirePermit().?);

    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);
    try std.testing.expectEqualStrings("open", state.circuitStateName());
}

test "routeHttp3Location rejects prior-hop Early-Data on ordinary 1-RTT before auth side effects" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/private",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "secret" } },
        .early_data = .replay_safe,
        .auth = .required,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/private"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = false,
    };
    defer request.deinit();
    try request.headers.append("Early-Data", "1");
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/private", "h3-early-header");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 425), @intFromEnum(response.status));
    try std.testing.expect(std.mem.indexOf(u8, response.body orelse "", "\"code\":\"too_early\"") != null);
    try std.testing.expectEqual(@as(u64, 0), state.metrics.err_unauthorized);

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"header\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"too_early\"} 1") != null);
}

test "routeHttp3Location accepts replay-safe current-hop transport provenance" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/safe",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        .early_data = .replay_safe,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/safe"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
    };
    defer request.deinit();
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/safe", "h3-transport");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(response.status));
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"transport\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"accepted\"} 1") != null);
}

test "h3 RFC8470 forwarding marker uses provenance and handshake state" {
    var dummy: u8 = 0;
    try std.testing.expect(h3ForwardEarlyDataMarker(.{ .inbound_marker = true }, .forward_rfc8470));
    try std.testing.expect(h3ForwardEarlyDataMarker(.{
        .transport_early = true,
        .downstream_handshake = .{
            .ctx = &dummy,
            .is_complete_fn = struct {
                fn incomplete(_: *anyopaque) bool {
                    return false;
                }
            }.incomplete,
            .wait_or_drive_fn = struct {
                fn drive(_: *anyopaque) anyerror!void {}
            }.drive,
        },
    }, .forward_rfc8470));
    try std.testing.expect(!h3ForwardEarlyDataMarker(.{ .transport_early = true }, .forward_rfc8470));
    try std.testing.expect(!h3ForwardEarlyDataMarker(.{}, .ordinary));
}

test "routeHttp3Location rejects unknown replay-exposed methods before action execution" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/safe",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "side-effect" } },
        .early_data = .replay_safe,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "FOO"),
        .path = try allocator.dupe(u8, "/safe"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
    };
    defer request.deinit();
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/safe", "h3-unknown-method");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 425), @intFromEnum(response.status));
    try std.testing.expect(std.mem.indexOf(u8, response.body orelse "", "side-effect") == null);
    try std.testing.expect(std.mem.indexOf(u8, response.body orelse "", "\"code\":\"too_early\"") != null);
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"too_early\"} 1") != null);
}

test "routeHttp3Location preflights early data before unmatched routes fall through" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/missing"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
    };
    defer request.deinit();
    try request.headers.append("Early-Data", "1");
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/missing", "h3-missing-early");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 425), @intFromEnum(response.status));
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"header\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"too_early\"} 1") != null);
}

test "routeHttp3Location preflights transport early data before operational routes fall through" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, cfg.metrics_path),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
    };
    defer request.deinit();
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, cfg.metrics_path, "h3-metrics-early");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 425), @intFromEnum(response.status));
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"transport\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"too_early\"} 1") != null);
}

test "routeHttp3Location preserves ordinary unmatched not-handled behavior" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/missing"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
    };
    defer request.deinit();
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/missing", "h3-missing-ordinary");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).not_handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(response.status));
}

test "routeHttp3Location replay-safe acceptance handles combined prior-hop and current-hop provenance" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    initHandlerTestState(&state, allocator, &.{});
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/safe",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        .early_data = .replay_safe,
    }};
    var token_hashes = [_][]const u8{};
    var cfg = minimalAuthConfig(blocks[0..], token_hashes[0..]);
    var config_store: ReloadableConfigStore = undefined;
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/safe"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
    };
    defer request.deinit();
    try request.headers.append("Early-Data", "1");
    var response = http.Response.init(allocator);
    defer response.deinit();

    const outcome = try routeHttp3Location(allocator, &request, &response, &dispatch_ctx, "/safe", "h3-both");

    try std.testing.expectEqual(std.meta.Tag(Http3LocationOutcome).handled, std.meta.activeTag(outcome));
    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(response.status));
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"both\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"accepted\"} 1") != null);
}

const H3ProxyOrigin = struct {
    allocator: std.mem.Allocator,
    listen_fd: std.posix.fd_t,
    listen_port: u16,
    thread: ?std.Thread = null,
    statuses: []const u16,
    mutex: compat.Mutex = .{},
    requests: std.ArrayList([]u8) = .empty,

    fn start(allocator: std.mem.Allocator, statuses: []const u16) !H3ProxyOrigin {
        const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        try std.testing.expect(listen_fd >= 0);
        _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
        var sin: std.c.sockaddr.in = .{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, 0),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
            .zero = [_]u8{0} ** 8,
        };
        try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
        try std.testing.expect(std.c.listen(listen_fd, 8) == 0);
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
        return .{
            .allocator = allocator,
            .listen_fd = listen_fd,
            .listen_port = std.mem.bigToNative(u16, bound.port),
            .statuses = statuses,
        };
    }

    fn run(self: *H3ProxyOrigin) !void {
        self.thread = try std.Thread.spawn(.{}, H3ProxyOrigin.threadMain, .{self});
    }

    fn stop(self: *H3ProxyOrigin) void {
        if (self.thread) |_| {
            if (compat.tcpConnectToHost(self.allocator, "127.0.0.1", self.port())) |stream| {
                stream.close();
            } else |_| {}
        }
        if (self.thread) |thread| thread.join();
        _ = std.c.close(self.listen_fd);
        self.mutex.lock();
        for (self.requests.items) |raw| self.allocator.free(raw);
        self.requests.deinit(self.allocator);
        self.mutex.unlock();
        self.* = undefined;
    }

    fn port(self: *const H3ProxyOrigin) u16 {
        return self.listen_port;
    }

    fn requestCount(self: *H3ProxyOrigin) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.requests.items.len;
    }

    fn requestContains(self: *H3ProxyOrigin, index: usize, needle: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.requests.items.len) return false;
        return std.mem.indexOf(u8, self.requests.items[index], needle) != null;
    }

    fn threadMain(self: *H3ProxyOrigin) void {
        var idx: usize = 0;
        while (idx < self.statuses.len) : (idx += 1) {
            const fd = std.c.accept(self.listen_fd, null, null);
            if (fd < 0) return;
            defer _ = std.c.close(fd);
            var raw = std.ArrayList(u8).empty;
            defer raw.deinit(self.allocator);
            var buf: [1024]u8 = undefined;
            while (true) {
                const n = std.c.read(fd, &buf, buf.len);
                if (n == 0) return;
                if (n < 0) return;
                raw.appendSlice(self.allocator, buf[0..@intCast(n)]) catch return;
                if (std.mem.indexOf(u8, raw.items, "\r\n\r\n") != null) break;
            }
            const owned = self.allocator.dupe(u8, raw.items) catch return;
            self.mutex.lock();
            self.requests.append(self.allocator, owned) catch {
                self.mutex.unlock();
                self.allocator.free(owned);
                return;
            };
            self.mutex.unlock();
            const body = if (self.statuses[idx] == 200) "ok" else "too early";
            var response_buf: [256]u8 = undefined;
            const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 {d} test\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
                self.statuses[idx], body.len, body,
            }) catch return;
            _ = std.c.write(fd, response.ptr, response.len);
        }
    }
};

const H3ParkCapture = struct {
    parked: ?http.http3_session.StreamRequest.Early425RetryContinuation = null,

    fn park(ctx: *anyopaque, continuation: http.http3_session.StreamRequest.Early425RetryContinuation) anyerror!void {
        const self: *H3ParkCapture = @ptrCast(@alignCast(ctx));
        if (self.parked != null) return error.TestDuplicatePark;
        self.parked = continuation;
    }

    fn take(self: *H3ParkCapture) http.http3_session.StreamRequest.Early425RetryContinuation {
        const parked = self.parked.?;
        self.parked = null;
        return parked;
    }
};

const TestHttp3RequestHandshake = struct {
    complete: bool = false,

    fn isComplete(ctx: *anyopaque) bool {
        const self: *TestHttp3RequestHandshake = @ptrCast(@alignCast(ctx));
        return self.complete;
    }

    fn waitOrDrive(_: *anyopaque) anyerror!void {}

    fn barrier(self: *TestHttp3RequestHandshake) http.request_context.DownstreamHandshakeBarrier {
        return .{
            .ctx = self,
            .is_complete_fn = isComplete,
            .wait_or_drive_fn = waitOrDrive,
        };
    }
};

const H3ContinuationAttempt = union(enum) {
    status: u16,
    err: anyerror,
};

const H3ContinuationExecuteScript = struct {
    allocator: std.mem.Allocator,
    attempts: []const H3ContinuationAttempt,
    calls: usize = 0,
    forward_early_data: std.ArrayList(bool) = .empty,
    timeouts_ms: std.ArrayList(u32) = .empty,

    fn deinit(self: *H3ContinuationExecuteScript) void {
        self.forward_early_data.deinit(self.allocator);
        self.timeouts_ms.deinit(self.allocator);
    }

    fn execute(
        ctx: ?*anyopaque,
        continuation: *Http3Early425ProxyContinuation,
        per_attempt_timeout_ms: u32,
        forward_early_data: bool,
    ) !gproxy_runtime.DataPlaneProxyResponse {
        const self: *H3ContinuationExecuteScript = @ptrCast(@alignCast(ctx.?));
        try self.forward_early_data.append(self.allocator, forward_early_data);
        try self.timeouts_ms.append(self.allocator, per_attempt_timeout_ms);
        continuation.last_attempt_start_ms = http.event_loop.monotonicMs();
        const attempt = self.calls;
        self.calls += 1;
        if (attempt >= self.attempts.len) return error.TestMissingContinuationAttempt;
        return switch (self.attempts[attempt]) {
            .err => |err| err,
            .status => |status| response: {
                const body = if (status == 200) "ok" else "too early";
                const raw = try std.fmt.allocPrint(
                    self.allocator,
                    "HTTP/1.1 {d} test\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                    .{ status, body.len, body },
                );
                defer self.allocator.free(raw);
                break :response .{ .bounded_buffered = try gp.parseBufferedUpstreamResponse(self.allocator, raw) };
            },
        };
    }
};

test "h3 proxy early 425 parks and resumes exact ordinary continuation" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{ 425, 200 });
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 7,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expect(origin.requestContains(0, "\r\nEarly-Data: 1\r\n"));
    try std.testing.expect(capture.parked != null);
    try std.testing.expect(request.transport_early);

    var continuation = capture.take();
    defer continuation.deinit(allocator);
    const plan: *Http3Early425ProxyContinuation = @ptrCast(@alignCast(continuation.ctx));
    try std.testing.expect(plan.transport_early);
    blocks[0].action = .{ .return_response = .{ .status = 418, .body = "reloaded" } };
    blocks[0].early_data = .off;
    var resumed_response = http.Response.init(allocator);
    defer resumed_response.deinit();
    try continuation.run(allocator, &resumed_response);

    try std.testing.expectEqual(@as(usize, 2), origin.requestCount());
    try std.testing.expect(!origin.requestContains(1, "\r\nEarly-Data: 1\r\n"));
    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(resumed_response.status));
    try std.testing.expectEqualStrings("ok", resumed_response.body orelse "");

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h3\",source=\"transport\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"forwarded\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"success\"} 1") != null);
}

test "h3 proxy parked early 425 forwards second 425 without third delivery" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{ 425, 425, 200 });
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 9,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expect(origin.requestContains(0, "\r\nEarly-Data: 1\r\n"));

    var continuation = capture.take();
    defer continuation.deinit(allocator);
    var resumed_response = http.Response.init(allocator);
    defer resumed_response.deinit();
    try continuation.run(allocator, &resumed_response);

    try std.testing.expectEqual(@as(usize, 2), origin.requestCount());
    try std.testing.expect(!origin.requestContains(1, "\r\nEarly-Data: 1\r\n"));
    try std.testing.expectEqual(@as(u16, 425), @intFromEnum(resumed_response.status));

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"forwarded\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"too_early\"} 1") != null);
}

test "h3 proxy parked early 425 carries half-open permit across stale retry" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{425});
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    cfg.upstream_timeout_ms = 0;
    cfg.upstream_timeout_budget_ms = 10_000;
    cfg.upstream_max_fails = 1;
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 13,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expect(origin.requestContains(0, "\r\nEarly-Data: 1\r\n"));
    try std.testing.expectEqualStrings("half-open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);

    var continuation = capture.take();
    defer continuation.deinit(allocator);
    const plan: *Http3Early425ProxyContinuation = @ptrCast(@alignCast(continuation.ctx));
    const original_budget_start_ms = plan.budget_start_ms;
    const scripted = [_]H3ContinuationAttempt{
        .{ .err = error.HttpConnectionClosing },
        .{ .status = 200 },
    };
    var execute_script = H3ContinuationExecuteScript{
        .allocator = allocator,
        .attempts = &scripted,
    };
    defer execute_script.deinit();
    plan.test_execute_ctx = &execute_script;
    plan.test_execute_fn = H3ContinuationExecuteScript.execute;

    var resumed_response = http.Response.init(allocator);
    defer resumed_response.deinit();
    try continuation.run(allocator, &resumed_response);

    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(resumed_response.status));
    try std.testing.expectEqualStrings("ok", resumed_response.body orelse "");
    try std.testing.expectEqual(@as(usize, 2), execute_script.calls);
    try std.testing.expectEqualSlices(bool, &.{ false, false }, execute_script.forward_early_data.items);
    try std.testing.expectEqual(@as(usize, 2), execute_script.timeouts_ms.items.len);
    try std.testing.expect(execute_script.timeouts_ms.items[1] <= execute_script.timeouts_ms.items[0]);
    try std.testing.expectEqual(original_budget_start_ms, plan.budget_start_ms);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_health.count());
    try std.testing.expectEqualStrings("closed", state.circuitStateName());

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"failure\"} 0") != null);
}

test "h3 proxy parked early 425 records failure after stale recovery exhausts" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{425});
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    cfg.upstream_max_fails = 1;
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 30_000 });
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 15,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());

    var continuation = capture.take();
    defer continuation.deinit(allocator);
    const plan: *Http3Early425ProxyContinuation = @ptrCast(@alignCast(continuation.ctx));
    const scripted = [_]H3ContinuationAttempt{
        .{ .err = error.HttpConnectionClosing },
        .{ .err = error.HttpConnectionClosing },
        .{ .err = error.HttpConnectionClosing },
    };
    var execute_script = H3ContinuationExecuteScript{
        .allocator = allocator,
        .attempts = &scripted,
    };
    defer execute_script.deinit();
    plan.test_execute_ctx = &execute_script;
    plan.test_execute_fn = H3ContinuationExecuteScript.execute;

    var resumed_response = http.Response.init(allocator);
    defer resumed_response.deinit();
    try continuation.run(allocator, &resumed_response);

    try std.testing.expectEqual(@as(u16, 502), @intFromEnum(resumed_response.status));
    try std.testing.expectEqual(@as(usize, 3), execute_script.calls);
    try std.testing.expectEqualSlices(bool, &.{ false, false, false }, execute_script.forward_early_data.items);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_health.count());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"failure\"} 1") != null);
}

test "h3 proxy parked half-open 425 releases permit when destroyed before resume" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{425});
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 17,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqualStrings("half-open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);

    var continuation = capture.take();
    continuation.deinit(allocator);

    const next_probe = state.circuitTryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    defer state.circuitReleasePermit(next_probe);
    try std.testing.expectEqualStrings("half-open", state.circuitStateName());
}

test "h3 proxy parked early 425 fails without origin retry after budget expires" {
    const allocator = std.testing.allocator;
    var origin = try H3ProxyOrigin.start(allocator, &.{ 425, 200 });
    defer origin.stop();
    try origin.run();

    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{origin.port()});
    defer allocator.free(target);
    var blocks = [_]http.location_router.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/proxy/",
        .priority = 0,
        .action = .{ .proxy_pass = target },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    var cfg = minimalHttp3ProxyConfig(blocks[0..]);
    cfg.upstream_timeout_budget_ms = 1;
    var config_store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer config_store.deinit();
    var state: GatewayState = undefined;
    initHttp3ProxyTestState(&state, allocator, &.{});
    defer deinitHttp3ProxyTestState(&state);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);
    var dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = &cfg,
        .state = &state,
    };
    var barrier = TestHttp3RequestHandshake{ .complete = false };
    var capture = H3ParkCapture{};
    var request = http.http3_session.StreamRequest{
        .allocator = allocator,
        .stream_id = 11,
        .method = try allocator.dupe(u8, "GET"),
        .path = try allocator.dupe(u8, "/proxy/item"),
        .authority = null,
        .headers = http.Headers.init(allocator),
        .body = try allocator.alloc(u8, 0),
        .transport_early = true,
        .downstream_handshake = barrier.barrier(),
        .park_early_425_retry = .{ .ctx = &capture, .park_fn = H3ParkCapture.park },
    };
    defer request.deinit();
    var first_response = http.Response.init(allocator);
    defer first_response.deinit();

    try std.testing.expectError(error.Http3RequestParked, handleHttp3Request(allocator, &request, &first_response, &dispatch_ctx));
    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqualStrings("half-open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);
    compat.sleepNs(3 * std.time.ns_per_ms);

    var continuation = capture.take();
    defer continuation.deinit(allocator);
    var resumed_response = http.Response.init(allocator);
    defer resumed_response.deinit();
    try continuation.run(allocator, &resumed_response);

    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqual(@as(u16, 504), @intFromEnum(resumed_response.status));
    const next_probe = state.circuitTryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    defer state.circuitReleasePermit(next_probe);

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") == null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"failure\"} 1") != null);
}

fn handleHttp3Connection(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
) !void {
    const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
    var http3_path, _ = splitHttp3PathAndQuery(request.path);
    var rewrite_budget: usize = 0;
    while (rewrite_budget < 4) : (rewrite_budget += 1) {
        switch (try routeHttp3Location(allocator, request, response, ctx, http3_path, correlation_id)) {
            .handled => return,
            .not_handled => break,
            .rewritten => |rewrite_result| {
                http3_path = rewrite_result.path;
            },
        }
    }

    const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
    _ = response
        .setStatus(.not_found)
        .setBodyOwned(payload)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(404);
}

fn splitHttp3PathAndQuery(path: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.findScalar(u8, path, '?')) |idx| {
        return .{ path[0..idx], path[idx + 1 ..] };
    }
    return .{ path, null };
}

pub fn handleHttp3Request(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    user_data: ?*anyopaque,
) !void {
    const ctx: *Http3DispatchContext = @ptrCast(@alignCast(user_data orelse return error.InvalidArgument));
    var cfg_lease = ctx.config_store.acquire();
    defer cfg_lease.release();
    const active_cfg = cfg_lease.cfg;
    const authority = request.headers.get(":authority") orelse request.headers.get("host");
    var effective_cfg_storage = active_cfg.*;
    const effective_cfg = resolveRequestConfig(active_cfg, authority, &effective_cfg_storage) orelse {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    };
    if (!hostMatchesPatterns(effective_cfg.server_names, authority)) {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    }

    var effective_ctx = ctx.*;
    effective_ctx.cfg = effective_cfg;
    effective_ctx.cfg_lease = &cfg_lease;
    try handleHttp3Connection(allocator, request, response, &effective_ctx);
}

/// Emit an access-log line pulling method/path/user-agent straight from the
/// request — the shape repeated at every guard and terminal. Prefer this over
/// calling `logAccess` with the four fields spelled out.
pub fn logAccessForRequest(state: *GatewayState, ctx: *const http.request_context.RequestContext, request: *const http.Request, status: u16) void {
    logAccess(state, ctx, request.method.toString(), request.uri.path, status, request.headers.get("user-agent") orelse "");
}

pub fn logAccess(state: *GatewayState, ctx: *const http.request_context.RequestContext, method: []const u8, path: []const u8, status: u16, user_agent: []const u8) void {
    state.metricsRecordLatencyMs(ctx.elapsedMs());
    const cancel_reason: []const u8 = if (ctx.lifecycle) |lc|
        if (lc.token.reason) |reason| @tagName(reason) else ""
    else
        "";
    const entry = http.access_log.AccessLogEntry{
        .method = method,
        .path = path,
        .status = status,
        .latency_ms = ctx.elapsedMs(),
        .client_ip = ctx.client_ip,
        .correlation_id = ctx.request_id,
        .upstream_addr = ctx.upstream_addr orelse "",
        .upstream_status = ctx.upstream_status,
        .identity = ctx.identity orelse "-",
        .user_agent = user_agent,
        .bytes_sent = ctx.response_bytes,
        .response_bytes = ctx.response_bytes,
        .error_category = classifyErrorCategory(status),
        .cancel_reason = cancel_reason,
        .early_data_source = @tagName(ctx.early_data.source()),
        .early_data_action = @tagName(ctx.early_data_action),
        .early_data_retry_result = @tagName(ctx.early_data_retry_result),
        .early_data_replay_exposed = ctx.early_data.replayExposed(),
    };
    entry.log();
}

pub fn classifyErrorCategory(status: u16) []const u8 {
    return if (status < 400)
        "-"
    else if (status == 400 or status == 413 or status == 414)
        "invalid_request"
    else if (status == 401 or status == 403)
        "authz"
    else if (status == 408)
        "request_timeout"
    else if (status == 429)
        "rate_limited"
    else if (status == 503)
        "upstream_unavailable"
    else if (status == 504)
        "upstream_timeout"
    else if (status >= 500)
        "internal_error"
    else
        "client_error";
}

test "classifyErrorCategory maps statuses" {
    try std.testing.expectEqualStrings("-", classifyErrorCategory(200));
    try std.testing.expectEqualStrings("invalid_request", classifyErrorCategory(400));
    try std.testing.expectEqualStrings("authz", classifyErrorCategory(401));
    try std.testing.expectEqualStrings("rate_limited", classifyErrorCategory(429));
    try std.testing.expectEqualStrings("upstream_unavailable", classifyErrorCategory(503));
    try std.testing.expectEqualStrings("upstream_timeout", classifyErrorCategory(504));
    try std.testing.expectEqualStrings("internal_error", classifyErrorCategory(500));
}

test "parseQueryParam extracts topic" {
    const value = parseQueryParam("topic=alerts&foo=bar", "topic");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("alerts", value.?);
    try std.testing.expect(parseQueryParam("foo=bar", "topic") == null);
}

test "parseLastEventId handles invalid values" {
    try std.testing.expectEqual(@as(u64, 42), parseLastEventId("42"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId("bad"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId(null));
}

// Pull gateway_static_runtime and the bounded proxy transports into the
// unit-test runner so their tests are discovered and executed as part of the
// gateway handler suite.
test {
    _ = @import("gateway_static_runtime.zig");
    _ = @import("gateway_proxy.zig");
    _ = @import("gateway_proxy_runtime.zig");
    _ = @import("gateway_control_plane_proxy.zig");
}
