//! Admission and upstream dial for an RFC 8441 Extended CONNECT WebSocket
//! request over downstream HTTP/2 (#864).
//!
//! Reuses the same gates the H1 WebSocket path enforces (`handleWebSocketUpgrade`
//! / `handleLocationWebSocketProxyPass` in `gateway_handlers.zig` /
//! `gateway_proxy_runtime.zig`): route opt-in via `proxy_websocket on`,
//! auth/client-cert/forward_auth, Origin policy, 0-RTT replay safety,
//! capacity, and the circuit breaker, before translating to a fresh H1
//! `ws://`/`wss://` origin handshake (`gateway_proxy.openWebSocketUpstreamForH2`).
//!
//! Deliberately does not replicate the H1 path's multi-hop `rewrite` chain:
//! RFC 8441 Extended CONNECT addresses a location directly, and nothing in
//! #864's acceptance criteria asks for rewrite chasing on a tunnel request.
//! A location that rewrites to a WebSocket target is answered `not_matched`,
//! as if no location had a `proxy_websocket on` opt-in.

const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const ga = @import("gateway_auth.zig");
const gfa = @import("gateway_forward_auth.zig");
const ghandlers = @import("gateway_handlers.zig");
const gph = @import("gateway_proxy_headers.zig");
const gp = @import("gateway_proxy.zig");
const gpt = @import("gateway_proxy_target.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");

const GatewayState = gs.GatewayState;

pub const Refused = struct {
    status_code: u16,
    /// Static metrics/log label; never client-facing (the H2 response
    /// carries no body for this path, see the doc comment on `Outcome`).
    code: []const u8 = "",
    outcome: http.metrics.WebSocketUpgradeOutcome = .denied,
};

/// The dialed, handshake-verified upstream connection and the tunnel policy
/// the admitting location carries, owned until the caller either tears it
/// down (`deinit`) or hands it to the relay.
pub const Switched = struct {
    allocator: std.mem.Allocator,
    upgraded: *gp.UpgradedUpstream,
    upstream_base_url: []u8,
    circuit_permit: http.circuit_breaker.Permit,
    absolute_target: bool,
    idle_timeout_ms: u32,
    max_lifetime_ms: u32,
    drain_timeout_ms: u64,
    reload_drain: ?http.h2_websocket_relay.ReloadDrain,

    pub fn deinit(self: *Switched) void {
        self.upgraded.deinit();
        self.allocator.free(self.upstream_base_url);
        self.allocator.destroy(self);
    }
};

pub const Outcome = union(enum) {
    /// No location on this connection's effective configuration opted into
    /// `proxy_websocket on` for this path. The caller refuses the stream the
    /// same way it already refuses ordinary CONNECT.
    not_matched,
    /// A gate denied the request, or the upstream handshake failed, before
    /// any tunnel was admitted. Carries the status code only -- see the
    /// module doc comment for why this does not relay a body over H2.
    refused: Refused,
    switched: *Switched,
};

/// Run every WebSocket admission gate for `request` (already synthesized
/// from the Extended CONNECT's pseudo-headers) and, if admitted, dial and
/// handshake the upstream. Runs synchronously on the caller's thread: see
/// the call site in `edge_gateway.zig` for why that is an acceptable,
/// explicitly scoped tradeoff for this phase.
pub fn admit(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *http.Request,
    connection_ip: []const u8,
    correlation_id: []const u8,
    transport_early: bool,
    config_superseded_at: ?*const std.atomic.Value(u64),
) !Outcome {
    var effective_cfg_storage = cfg.*;
    const route_cfg = routeConfig(cfg, request, &effective_cfg_storage) orelse cfg;

    if (!gph.isTrustedUpstream(route_cfg, connection_ip)) gph.stripUntrustedForwardingHeaders(&request.headers, route_cfg);
    const client_ip = http.request_context.extractClientIp(
        request,
        gph.isExplicitlyTrustedUpstream(route_cfg, connection_ip),
        route_cfg.real_ip_header,
        gph.TrustedProxySet{ .cfg = route_cfg },
        connection_ip,
    );

    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    defer {
        if (ctx.identity) |v| allocator.free(v);
        if (ctx.user_id) |v| allocator.free(v);
        if (ctx.device_id) |v| allocator.free(v);
        if (ctx.scopes) |v| allocator.free(v);
    }
    try ghandlers.primeRequestAuthContext(allocator, route_cfg, state, &ctx, &request.headers);

    if (geoOrLimitsOrAclOrRateDenial(route_cfg, state, request, connection_ip, client_ip, ctx.identity)) |denial| {
        return .{ .refused = denial };
    }

    const matched = http.location_router.matchLocation(allocator, request.uri.path, route_cfg.location_blocks) orelse return .not_matched;
    const websocket = matched.block.websocket orelse return .not_matched;
    const target = switch (matched.block.action) {
        .proxy_pass => |value| value,
        else => return .not_matched,
    };

    if (matched.block.auth == .required and !ctx.authenticated and ctx.identity == null) {
        return .{ .refused = .{ .status_code = 401, .code = "unauthorized" } };
    }
    if (ghandlers.clientCertDenial(matched.block.client_cert, request.headers.client_cert)) |denial| {
        return .{ .refused = .{ .status_code = 403, .code = denial.code } };
    }

    // Opening an upstream connection is a side effect a replayed 0-RTT
    // handshake must never cause (mirrors H1's `ctx.early_data.replayExposed()`
    // gate and ordinary H2's `forward_auth` early-data refusal).
    if (transport_early or request.headers.hasEarlyDataMarker()) {
        return .{ .refused = .{ .status_code = 425, .code = "too_early" } };
    }

    var forward_auth_decision: ?gfa.Decision = null;
    defer if (forward_auth_decision) |*d| d.deinit();
    if (matched.block.forward_auth) |*fa| {
        const target_with_query = if (request.uri.query) |q| try std.fmt.allocPrint(allocator, "{s}?{s}", .{ request.uri.path, q }) else try allocator.dupe(u8, request.uri.path);
        defer allocator.free(target_with_query);
        var decision = try gfa.authorize(allocator, route_cfg, fa, .{
            .method = "CONNECT",
            .uri = target_with_query,
            .host = request.headers.get("host"),
            .proto = if (edge_config.usesNativeTls(route_cfg)) "https" else "http",
            .client_ip = client_ip,
            .correlation_id = correlation_id,
            .headers = &request.headers,
            .body = null,
        });
        state.metricsRecordForwardAuth(.h2, decision.outcome);
        if (!decision.allowed()) {
            const status = decision.status;
            const code = decision.errorCode();
            forward_auth_decision = decision;
            return .{ .refused = .{ .status_code = status, .code = code } };
        }
        forward_auth_decision = decision;
    }

    if (ga.evaluatePolicy(state, route_cfg, "CONNECT", request.uri.path, ctx.identity, ctx.device_id, &request.headers)) |_| {
        return .{ .refused = .{ .status_code = 403, .code = "forbidden" } };
    }

    if (!http.websocket.originAllowed(websocket.origins, request.headers.get("origin"))) {
        return .{ .refused = .{ .status_code = 403, .code = "websocket_origin_denied" } };
    }

    if (!state.tryAcquireWebSocketTunnel(route_cfg.proxy_websocket_max_tunnels)) {
        return .{ .refused = .{ .status_code = 503, .code = "websocket_capacity", .outcome = .capacity } };
    }
    var tunnel_admitted = false;
    defer if (!tunnel_admitted) state.releaseWebSocketTunnel();

    const pool = gs.upstreamPoolForScope(route_cfg, .global);
    const absolute_target = gs.isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"));
    const selected_base_url = if (absolute_target) route_cfg.upstream_base_url else state.nextUpstreamBaseUrl(route_cfg, pool, client_ip, target);
    const suffix_path = gproxy_runtime.proxySuffixPathForLocation(request.uri.path, matched, route_cfg.location_blocks);
    const resolved = try gpt.resolveProxyTarget(allocator, selected_base_url, target, suffix_path);
    defer allocator.free(resolved.url);
    var upstream_url = try gpt.appendProxyQueryString(allocator, resolved.url, request.uri.query);
    defer upstream_url.deinit(allocator);

    const circuit_permit = state.circuitTryAcquirePermit() orelse {
        return .{ .refused = .{ .status_code = 503, .code = "upstream_circuit_open", .outcome = .upstream_error } };
    };
    state.recordUpstreamAttemptStart(selected_base_url);
    var attempt_ended = false;
    defer if (!attempt_ended) state.recordUpstreamAttemptEnd(selected_base_url);

    const result = gp.openWebSocketUpstreamForH2(
        allocator,
        state.allocator,
        route_cfg,
        upstream_url.value,
        resolved.unix_socket_path,
        .{
            .request_headers = &request.headers,
            .correlation_id = correlation_id,
            .client_ip = client_ip,
            .forwarded_proto = if (edge_config.usesNativeTls(route_cfg)) "https" else "http",
            .incoming_host = request.headers.get("host"),
            .proxy_set_headers = matched.block.proxy_set_headers,
            .auth_identity = ctx.identity,
            .auth_user_id = ctx.user_id,
            .auth_device_id = ctx.device_id,
            .auth_scopes = ctx.scopes,
        },
        null,
        state.proxyBufferObserver(),
        state.proxyBufferGlobalAccount(),
        &state.upstream_pool,
    ) catch |err| {
        if (err == error.OutOfMemory) {
            state.circuitReleasePermit(circuit_permit);
            return err;
        }
        recordDialOutcome(state, route_cfg, selected_base_url, absolute_target, circuit_permit, false);
        state.logger.warn(correlation_id, "H2 websocket upstream handshake failed: {}", .{err});
        return .{ .refused = .{ .status_code = 502, .code = "upstream_websocket_invalid", .outcome = .upstream_error } };
    };

    switch (result) {
        .refused => |status_code| {
            recordDialOutcome(state, route_cfg, selected_base_url, absolute_target, circuit_permit, status_code < 500);
            return .{ .refused = .{ .status_code = status_code, .code = "upstream_refused", .outcome = .upstream_refused } };
        },
        .switched => |upgraded| {
            recordDialOutcome(state, route_cfg, selected_base_url, absolute_target, circuit_permit, true);
            errdefer upgraded.deinit();
            const owned_base_url = try allocator.dupe(u8, selected_base_url);
            errdefer allocator.free(owned_base_url);
            const switched = try allocator.create(Switched);
            switched.* = .{
                .allocator = allocator,
                .upgraded = upgraded,
                .upstream_base_url = owned_base_url,
                .circuit_permit = circuit_permit,
                .absolute_target = absolute_target,
                .idle_timeout_ms = websocket.idle_timeout_ms,
                .max_lifetime_ms = websocket.max_lifetime_ms,
                .drain_timeout_ms = route_cfg.shutdown_drain_timeout_ms,
                // Reload behavior is fixed here, at admission, from this
                // stream's own configuration (mirrors H1's identical comment
                // at its `tunnel_opts` construction site): a later reload can
                // end the tunnel (drain) but never change which policy or
                // timeout applies to it.
                .reload_drain = gproxy_runtime.websocketReloadDrain(&websocket, route_cfg, config_superseded_at),
            };
            tunnel_admitted = true;
            attempt_ended = true; // ownership of the in-flight accounting moves to the tunnel's own close bookkeeping.
            return .{ .switched = switched };
        },
    }
}

fn recordDialOutcome(state: *GatewayState, cfg: *const edge_config.EdgeConfig, base_url: []const u8, absolute_target: bool, permit: http.circuit_breaker.Permit, success: bool) void {
    if (success) {
        if (absolute_target) {
            state.circuitRecordSuccessPermit(permit);
        } else {
            state.recordProxyUpstreamSuccess(cfg, base_url, permit);
        }
    } else if (absolute_target) {
        state.circuitRecordFailurePermit(permit);
    } else {
        state.recordProxyUpstreamFailure(cfg, base_url, permit);
    }
}

fn routeConfig(
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    storage: *edge_config.EdgeConfig,
) ?*const edge_config.EdgeConfig {
    if (ga.resolveRequestConfig(cfg, request.headers.get("host"), storage)) |effective_cfg| {
        if (ga.hostMatchesServerNames(effective_cfg, request)) return effective_cfg;
    }
    if (cfg.location_blocks.len > 0) return cfg;
    if (cfg.server_blocks.len == 1) {
        storage.* = cfg.*;
        const block = &cfg.server_blocks[0];
        storage.server_names = block.server_names;
        if (block.location_blocks.len > 0) storage.location_blocks = block.location_blocks;
        if (block.upstream_base_url.len > 0) storage.upstream_base_url = block.upstream_base_url;
        return storage;
    }
    return null;
}

fn geoOrLimitsOrAclOrRateDenial(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *const http.Request,
    peer_ip: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
) ?Refused {
    if (cfg.geo_blocked_countries.len > 0) {
        if (!gph.isTrustedGeoSource(cfg, peer_ip)) {
            return .{ .status_code = 403, .code = "forbidden" };
        }
        const country = request.headers.get(cfg.geo_country_header);
        if (isGeoBlocked(cfg.geo_blocked_countries, country)) {
            return .{ .status_code = 403, .code = "forbidden" };
        }
    }

    const limits = cfg.request_limits;
    if (http.request_limits.validateUriLength(request.uri.path.len, limits) != .ok) {
        return .{ .status_code = 414, .code = "invalid_request" };
    }
    if (http.request_limits.validateHeaderCount(request.headers.count(), limits) != .ok) {
        return .{ .status_code = 431, .code = "invalid_request" };
    }
    var headers_total: usize = 0;
    for (request.headers.iterator()) |h| {
        const header_len = h.name.len + h.value.len + 2;
        if (http.request_limits.validateHeaderSize(header_len, limits) != .ok) {
            return .{ .status_code = 431, .code = "invalid_request" };
        }
        headers_total += h.name.len + h.value.len + 4;
    }
    if (http.request_limits.validateHeadersTotalSize(headers_total, limits) != .ok) {
        return .{ .status_code = 431, .code = "invalid_request" };
    }

    if (cfg.parsed_access_control) |acl| {
        if (acl.check(client_ip) == .denied) {
            return .{ .status_code = 403, .code = "forbidden" };
        }
    }

    if (cfg.rate_limit_rps > 0 and cfg.rate_limit_burst > 0) {
        var rate_limit_buf: [192]u8 = undefined;
        const limit_key = rateLimitDescriptor(identity, client_ip, &rate_limit_buf);
        if (!state.rateLimitAllow(limit_key)) {
            return .{ .status_code = 429, .code = "rate_limited" };
        }
    }

    return null;
}

fn isGeoBlocked(blocked: []const []const u8, country: ?[]const u8) bool {
    const c = country orelse return false;
    for (blocked) |b| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, b, " \t\r\n"), std.mem.trim(u8, c, " \t\r\n"))) return true;
    }
    return false;
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
