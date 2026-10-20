const compat = @import("zig_compat");
const std = @import("std");
const secrets = @import("crypto").secrets;
const http = @import("http.zig");
const tls_core = @import("tls_core");
const edge_config = @import("edge_config.zig");
const gpc = @import("gateway_proxy_cache.zig");
const gpdc = @import("gateway_proxy_disk_cache.zig");
const acme_renewal = @import("acme_renewal.zig");

/// Shared inbound request buffer size limit, also used as a default proxy
/// response buffer ceiling when no explicit limit is configured.
pub const MAX_REQUEST_SIZE: usize = 256 * 1024;

pub const ProxyCacheLookup = struct {
    cached: http.idempotency.CachedResponse,
    is_stale: bool,
};

pub const ProxyResponseCacheRevalidationAdmission = enum {
    admitted,
    concurrency,
    unavailable,
};

pub const UpstreamHealth = struct {
    fail_count: u32 = 0,
    unhealthy_until_ms: u64 = 0,
    probe: http.health_checker.State = .{},
    slow_start_until_ms: u64 = 0,
};

pub const ConnectionSlotResult = enum {
    accepted,
    over_ip_limit,
    over_global_limit,
    over_global_memory_limit,
};

pub const Http2PendingStream = struct {
    method: ?[]u8 = null,
    path: ?[]u8 = null,
    authority: ?[]u8 = null,
    headers: http.Headers,
    body: std.array_list.Managed(u8),
    priority_weight: u8 = 16,
    transport_early: bool = false,
    dispatch_count: u8 = 0,
    early_request_recorded: bool = false,
    deferred_recorded: bool = false,
    /// Set when inbound DATA would grow `body` past the configured request
    /// body limit. Further DATA payload is dropped (neither appended nor
    /// credited back) once set, bounding memory regardless of how long the
    /// client keeps streaming; the stream is rejected with 413 on dispatch
    /// without ever reaching the upstream.
    body_limit_exceeded: bool = false,

    pub fn init(allocator: std.mem.Allocator) Http2PendingStream {
        return .{
            .headers = http.Headers.init(allocator),
            .body = std.array_list.Managed(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Http2PendingStream, allocator: std.mem.Allocator) void {
        if (self.method) |m| allocator.free(m);
        if (self.path) |p| allocator.free(p);
        if (self.authority) |a| allocator.free(a);
        self.headers.deinit();
        self.body.deinit();
        self.* = undefined;
    }

    /// Logical request bytes retained while an HTTP/2 stream is awaiting
    /// dispatch.  Include headers and pseudo-header routing state as well as
    /// the body so many header-heavy held streams cannot bypass the
    /// connection memory ceiling.
    pub fn retainedBytes(self: *const Http2PendingStream) usize {
        var total = self.body.items.len;
        if (self.method) |value| total +|= value.len;
        if (self.path) |value| total +|= value.len;
        if (self.authority) |value| total +|= value.len;
        for (self.headers.iterator()) |header| {
            total +|= header.name.len +| header.value.len +| 4;
        }
        return total;
    }
};

/// Internal/test-only hook for attaching an HTTP/2 stream to a persistent,
/// bidirectional stream session (#867) instead of ordinary finite dispatch.
/// Production traffic never sets this -- `run()`'s `GatewayState` literal
/// never does, and this ticket deliberately does not negotiate RFC 8441
/// CONNECT/WebSocket semantics that would let a real client request one.
/// It exists so the connection-owned session registry, DATA routing,
/// wake-fd polling, and RST/GOAWAY/shutdown teardown in
/// `handleHttp2Connection` run through the exact production code path a
/// future protocol upgrade will reuse, proven end to end by a real H2
/// client/server test rather than by calling session helpers directly.
pub const H2SessionTestHook = struct {
    ctx: ?*anyopaque = null,
    /// Decide whether this stream's parsed headers request a persistent
    /// session rather than ordinary finite dispatch.
    shouldAttach: *const fn (ctx: ?*anyopaque, ps: *const Http2PendingStream) bool,
    /// Ownership of the session's *consumer* side transfers to this call; it
    /// must eventually call `session.consumerDetach()` from its own thread,
    /// never touching the connection socket.
    attach: *const fn (ctx: ?*anyopaque, session: *http.h2_stream_session.Session) void,
};

pub const UpstreamScope = enum {
    global,
    chat,
    commands,
};

pub fn upstreamScopeName(scope: UpstreamScope) []const u8 {
    return switch (scope) {
        .global => "global",
        .chat => "chat",
        .commands => "commands",
    };
}

pub fn proxyScopeForPath(path: []const u8) UpstreamScope {
    if (http.api_router.matchRoute(path, 1, "/chat")) return .chat;
    if (http.api_router.matchRoute(path, 1, "/commands")) return .commands;
    return .global;
}

pub fn maxBufferedUpstreamResponseBytes(cfg: *const edge_config.EdgeConfig) usize {
    return if (cfg.max_buffered_upstream_response_bytes > 0)
        cfg.max_buffered_upstream_response_bytes
    else
        MAX_REQUEST_SIZE;
}

/// Append `name{upstream="<escaped host>"} <value>\n` to a Prometheus buffer.
fn appendUpstreamLabelMetric(
    out: *std.array_list.Managed(u8),
    name: []const u8,
    upstream: []const u8,
    comptime value_fmt: []const u8,
    value_args: anytype,
) !void {
    try out.appendSlice(name);
    try out.appendSlice("{upstream=\"");
    for (upstream) |c| switch (c) {
        '\\' => try out.appendSlice("\\\\"),
        '"' => try out.appendSlice("\\\""),
        '\n' => try out.appendSlice("\\n"),
        else => try out.append(c),
    };
    try out.appendSlice("\"} ");
    try out.print(value_fmt, value_args);
    try out.appendSlice("\n");
}

/// Per-origin series that also carry the buffer `direction`. Cardinality stays
/// bounded: two fixed directions per configured origin, and the direction label
/// takes the same values as the process-wide buffer family.
fn appendUpstreamDirectionLabelMetric(
    out: *std.array_list.Managed(u8),
    name: []const u8,
    upstream: []const u8,
    direction: http.proxy_buffer_account.Direction,
    comptime value_fmt: []const u8,
    value_args: anytype,
) !void {
    try out.appendSlice(name);
    try out.appendSlice("{upstream=\"");
    for (upstream) |c| switch (c) {
        '\\' => try out.appendSlice("\\\\"),
        '"' => try out.appendSlice("\\\""),
        '\n' => try out.appendSlice("\\n"),
        else => try out.append(c),
    };
    try out.appendSlice("\",direction=\"");
    try out.appendSlice(direction.label());
    try out.appendSlice("\"} ");
    try out.print(value_fmt, value_args);
    try out.appendSlice("\n");
}

pub const UpstreamPoolView = struct {
    fallback_url: []const u8,
    primary_urls: []const []const u8,
    primary_weights: []const u32,
    backup_urls: []const []const u8,
};

pub const StickyAffinityRequest = struct {
    location_key: []u8,
    cookie_name: []u8,
    requested_upstream: ?[]u8,

    fn deinit(self: *StickyAffinityRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.location_key);
        allocator.free(self.cookie_name);
        if (self.requested_upstream) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const StickyUpstreamSelection = struct {
    base_url: []const u8,
    used_requested: bool,
};

pub const CommandLifecycleStatus = enum {
    pending,
    running,
    completed,
    failed,
};

pub const CommandLifecycleEntry = struct {
    status: CommandLifecycleStatus,
    command_type: []u8,
    correlation_id: []u8,
    identity: []u8,
    created_ms: i64,
    updated_ms: i64,
    response_status: u16,
    response_body: []u8,
    response_content_type: []u8,
    error_message: []u8,
};

pub const CommandLifecycleSnapshot = struct {
    status: CommandLifecycleStatus,
    response_status: u16,
    response_body: []u8,
    response_content_type: []u8,
    error_message: []u8,

    fn deinit(self: *CommandLifecycleSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.response_body);
        allocator.free(self.response_content_type);
        allocator.free(self.error_message);
        self.* = undefined;
    }
};

pub const ApprovalStatus = enum {
    pending,
    approved,
    denied,
    escalated,
};

pub const ApprovalDecision = enum {
    approve,
    deny,
};

pub const ApprovalValidation = enum {
    approved,
    pending,
    denied,
    escalated,
    invalid,
    missing,
};

pub const ApprovalEntry = struct {
    method: []u8,
    path: []u8,
    identity: []u8,
    command_id: []u8,
    status: ApprovalStatus,
    created_ms: i64,
    expires_ms: i64,
    decided_ms: i64,
    decided_by: []u8,
    /// True once the escalation webhook has been fired for this entry.
    escalation_fired: bool = false,

    fn deinit(self: *ApprovalEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        allocator.free(self.identity);
        allocator.free(self.command_id);
        allocator.free(self.decided_by);
        self.* = undefined;
    }
};

pub const ApprovalCreateResult = struct {
    token: []u8,
    expires_ms: i64,
};

pub const MuxChannelKind = enum {
    events,
    command,
};

pub const MuxChannel = struct {
    name: []u8,
    kind: MuxChannelKind,
    topic: ?[]u8 = null,
    last_event_id: u64 = 0,
    command_id: ?[]u8 = null,
    last_command_status: ?CommandLifecycleStatus = null,
};

pub const MuxPendingFrame = struct {
    payload: []u8,
};

pub const MuxResumeState = struct {
    channels: []MuxChannel,
    expires_ms: i64,
};

pub const MuxDeviceCount = struct {
    device_id: []u8,
    count: usize,
};

pub const MuxMetricsSnapshot = struct {
    device_counts: []MuxDeviceCount,
};

fn appendPrometheusLabelValue(out: *std.array_list.Managed(u8), value: []const u8) !void {
    for (value) |byte| switch (byte) {
        '\\' => try out.appendSlice("\\\\"),
        '"' => try out.appendSlice("\\\""),
        '\n' => try out.appendSlice("\\n"),
        else => try out.append(byte),
    };
}

fn deinitMuxMetricsSnapshot(allocator: std.mem.Allocator, device_counts: []MuxDeviceCount) void {
    for (device_counts) |entry| allocator.free(entry.device_id);
    allocator.free(device_counts);
}

/// #256-G: `quic.udp.BufferTuningStatus` -> `http.metrics.QuicUdpBufferStatus`.
/// Takes `anytype` so this file does not need its own `@import("quic")` just
/// for one enum's tag names; the two enums are kept in lockstep by the
/// exhaustive switch below (a new `BufferTuningStatus` variant fails to
/// compile here until it is handled).
fn quicUdpBufferStatusFrom(status: anytype) http.metrics.QuicUdpBufferStatus {
    return switch (status) {
        .default => .default,
        .applied => .applied,
        .clamped => .clamped,
        .unverified => .unverified,
        .unsupported => .unsupported,
    };
}

fn deinitMuxPendingFrames(allocator: std.mem.Allocator, pending: *std.array_list.Managed(MuxPendingFrame)) void {
    for (pending.items) |frame| allocator.free(frame.payload);
    pending.deinit();
}

fn deinitMuxChannel(allocator: std.mem.Allocator, ch: *MuxChannel) void {
    allocator.free(ch.name);
    if (ch.topic) |t| allocator.free(t);
    if (ch.command_id) |id| allocator.free(id);
    ch.* = undefined;
}

fn cloneMuxChannel(allocator: std.mem.Allocator, ch: *const MuxChannel) !MuxChannel {
    return .{
        .name = try allocator.dupe(u8, ch.name),
        .kind = ch.kind,
        .topic = if (ch.topic) |topic| try allocator.dupe(u8, topic) else null,
        .last_event_id = ch.last_event_id,
        .command_id = if (ch.command_id) |command_id| try allocator.dupe(u8, command_id) else null,
        .last_command_status = ch.last_command_status,
    };
}

fn cloneMuxChannels(allocator: std.mem.Allocator, channels: []const MuxChannel) ![]MuxChannel {
    var out = try allocator.alloc(MuxChannel, channels.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*ch| deinitMuxChannel(allocator, ch);
        allocator.free(out);
    }
    for (channels, 0..) |ch, idx| {
        out[idx] = try cloneMuxChannel(allocator, &ch);
        initialized += 1;
    }
    return out;
}

fn deinitMuxResumeState(allocator: std.mem.Allocator, saved_state: *MuxResumeState) void {
    for (saved_state.channels) |*ch| deinitMuxChannel(allocator, ch);
    allocator.free(saved_state.channels);
    saved_state.* = undefined;
}

/// Persistent gateway state shared across connections.
///
/// # Ownership, lifetime, and threading model
///
/// `GatewayState` is created once at startup (`edge_gateway.zig`), lives for the
/// whole process, and is shared by reference across all threads. It mixes four
/// kinds of fields; each field below is tagged with which kind it is.
///
/// ## Threads that touch this struct
/// - **Main event loop** (one thread): the accept loop plus periodic maintenance
///   (health-probe dispatch, proxy-cache maintenance, DNS refresh, reload/drain).
/// - **Worker pool** (N threads): execute requests with blocking I/O; reach into
///   the shared sub-stores, counters, and maps through the locked accessor
///   methods on this struct.
/// - **Background health-probe thread** (transient): spawned by the main loop and
///   gated by `health_probe_running`; runs upstream probes off the hot path.
///
/// ## Synchronization domains (mutex → fields it guards)
/// All locking is centralized in this file; callers use the accessor methods
/// rather than touching the fields directly.
/// - `connection_mutex` → `active_connections_total`, `active_connections_by_ip`,
///   `active_fds`, `fd_to_ip`, `active_ws_streams`, `active_sse_streams`,
///   `active_mux_connections`, `active_mux_subscriptions`,
///   `mux_subscriptions_by_device`, `fastcgi_next_request_id`.
/// - `upstream_mutex` → `upstream_health`, `upstream_active_requests`,
///   `upstream_rr_index`, `upstream_backup_rr_index`, `lb_random_state` (the
///   load-balancer selection state mutated by the `*Locked` selectors).
/// - `circuit_mutex` → `circuit_breaker`.
/// - `metrics_mutex` → `metrics`.
/// - `rate_limiter_mutex` → `rate_limiter`.
/// - `idempotency_mutex` → `idempotency_store`.
/// - `proxy_cache_mutex` → `proxy_cache_store`, `proxy_cache_locks`,
///   `proxy_cache_path`, `proxy_cache_ttl_seconds`.
/// - `session_mutex` → `session_store`.
/// - `transcript_mutex` → serializes appends to the `transcript_store_path` file.
/// - `command_mutex` → `command_lifecycle`.
/// - `approval_mutex` → `approvals` (and the per-identity pending count derived
///   from it).
/// - `approval_persist_mutex` → serializes approval snapshot+write pairs to the
///   `approval_store_path` file. Acquired BEFORE `approval_mutex` and held
///   across the snapshot and the write, so the durable file cannot be
///   overwritten by an older snapshot. Never take `approval_mutex` first and
///   then this one.
/// - `runtime_mutex` → `mux_resume_state`, and the reload-time rebinding of the
///   hot config-derived fields (`add_headers`, `http3_alt_svc`, `hsts_value`,
///   `security_headers`, the `max_*` limits, `compression_config`, log level).
/// - `reload_mutex` → `last_reload_ok`, `last_reload_at_ms`, `last_reload_error`,
///   `last_reload_error_len`.
///
/// ## Lock-free fields
/// - **Atomics:** `in_flight_requests` (request-slot counter) and
///   `health_probe_running` (acquire/release handoff between the main loop and
///   the probe thread). No mutex required.
/// - **Main-event-loop-only** (never touched by workers, so unsynchronized):
///   `next_active_health_probe_ms`, `next_proxy_cache_maintenance_ms`,
///   `http3_runtime`, and `dns_discovery` (which self-synchronizes internally).
///
/// ## Ownership / lifetime classification
/// - **Borrowed from the active `EdgeConfig`** (NOT freed here; lifetime is the
///   config version): `add_headers`, `proxy_cache_path`, `session_store_path`,
///   `approval_store_path`, `approval_escalation_webhook`, `transcript_store_path`,
///   and the scalar/POD config snapshots (`max_*`, `*_ttl*`, `compression_config`,
///   `security_headers` contents). The startup config is borrowed by the
///   `ReloadableConfigStore`; on reload a new version is installed and the old one
///   is retained until in-flight leases release, so borrowed slices stay valid for
///   readers holding a lease. Note: `add_headers` and `proxy_cache_path` are rebound
///   on reload; the store path/URL fields are restart-only (see below).
/// - **Heap-owned by `GatewayState`** (freed in `deinit`): `hsts_value`,
///   `http3_alt_svc`; every `StringHashMap` key (all are `dupe`d on insert) and
///   the duped IP values in `fd_to_ip`; the nested allocations owned by
///   `command_lifecycle`, `approvals`, and `mux_resume_state` entries; and the
///   self-managed sub-stores (`rate_limiter`, `idempotency_store`,
///   `proxy_cache_store`, `session_store`, `acme_challenge_store`,
///   `event_hub`, `request_buffer_pool`, `relay_buffer_pool`, `upstream_client`,
///   `dns_discovery`), each of which owns and frees its own internal state.
///
/// ## `deinit` ordering
/// `deinit` tears down in this order: self-managed sub-stores first (each
/// independent), then the owned scalar buffers (`hsts_value`, `http3_alt_svc`),
/// then every map — freeing duped keys (and, for
/// `command_lifecycle`/`approvals`/`mux_resume_state`, freeing nested
/// values) before calling the map's own `deinit`. Maps are independent of each
/// other, so their relative order does not matter; the invariant is keys/values
/// freed *before* the backing map is destroyed.
///
/// ## Reload / drain behavior
/// `applyReloadedRuntimeConfig` (`gateway_shutdown.zig`) re-derives the owned
/// config-derived fields (`hsts_value`, `http3_alt_svc`, `security_headers`) —
/// freeing the previous allocation — and rebinds the hot borrowed fields
/// (`add_headers`, `proxy_cache_path`) and scalar limits to the new config under
/// the appropriate locks. All owned *runtime* state (connection accounting,
/// in-flight counter, upstream health/active-request maps, circuit breaker,
/// metrics, pools, and the sub-stores not keyed off changed config) survives a
/// reload untouched. NOTE: `session_store_path`, `approval_store_path`,
/// `transcript_store_path`, and `approval_escalation_webhook` are bound once at
/// startup and intentionally NOT rebound on reload — they remain valid because
/// the startup config outlives the process, but changes to those paths/URLs
/// require a full restart. `applyReloadedRuntimeConfig` detects changes to these
/// fields and logs a WARN so operators know the new value was not applied.
const proxy_response_cache_mutation_lane_count: usize = 64;

pub const GatewayState = struct {
    allocator: std.mem.Allocator,
    // --- Synchronization primitives (see the struct doc comment for the full
    // mutex → field map, and docs/CONCURRENCY.md for hot-path classification
    // and improvement proposals). Each guards the fields named alongside it.
    //
    // HOT-PATH mutexes (taken on every request — see docs/CONCURRENCY.md #214):
    //   metrics_mutex      — taken once per response; candidate for atomic counters
    //   rate_limiter_mutex — taken once per request when rate limiting enabled
    //   upstream_mutex     — taken once per proxied request for LB selection
    //   circuit_mutex      — taken once per proxied request when CB enabled
    //   proxy_response_cache_mutex — taken once (lookup) or twice (lookup
    //     then fill) per cacheable GET proxy_pass request, only when the
    //     generic response cache is enabled (#901)
    //
    // WARM-PATH mutexes (taken per connection, not per request on keepalive):
    //   connection_mutex
    //
    // COLD-PATH mutexes (feature-specific or control-plane only):
    //   idempotency_mutex, proxy_cache_mutex, session_mutex, transcript_mutex,
    //   command_mutex, approval_mutex, runtime_mutex
    // ---
    connection_mutex: compat.Mutex = .{}, // connection accounting + fastcgi/mux-sub maps
    rate_limiter_mutex: compat.Mutex = .{}, // [HOT] rate_limiter
    idempotency_mutex: compat.Mutex = .{}, // idempotency_store
    proxy_cache_mutex: compat.Mutex = .{}, // proxy_cache_store + proxy_cache_locks + path/ttl
    session_mutex: compat.Mutex = .{}, // session_store
    transcript_mutex: compat.Mutex = .{}, // transcript file appends
    command_mutex: compat.Mutex = .{}, // command_lifecycle
    approval_mutex: compat.Mutex = .{}, // approvals + pending-per-identity count
    approval_persist_mutex: compat.Mutex = .{}, // serializes approval snapshot+write ordering
    circuit_mutex: compat.Mutex = .{}, // [HOT] circuit_breaker
    metrics_mutex: compat.Mutex = .{}, // [HOT] metrics — priority candidate for atomic counters
    upstream_mutex: compat.Mutex = .{}, // [HOT] upstream_health/active_requests + LB selection state
    runtime_mutex: compat.Mutex = .{}, // mux_resume_state + reload-time config rebinding
    rate_limiter: ?http.rate_limiter.RateLimiter, // owned; rebuilt on reload [rate_limiter_mutex]
    idempotency_store: ?http.idempotency.IdempotencyStore, // owned [idempotency_mutex]
    proxy_cache_store: ?http.idempotency.IdempotencyStore, // owned; rebuilt on reload [proxy_cache_mutex]
    proxy_cache_path: []const u8, // borrowed from cfg; rebound on reload [proxy_cache_mutex]
    proxy_cache_ttl_seconds: u32, // cfg snapshot [proxy_cache_mutex]
    proxy_response_cache_mutex: compat.Mutex = .{}, // guards proxy_response_cache + proxy_response_cache_generation
    /// Fixed striped lanes order same-key RAM+disk mutations without making
    /// disjoint keys share a process-wide lock across filesystem I/O.
    proxy_response_cache_mutation_lanes: [proxy_response_cache_mutation_lane_count]compat.Mutex = @splat(.{}),
    /// Generic `proxy_pass` GET response cache (#901). Owned and rebuilt on
    /// every reload. The generation binds entries to the config lease that
    /// created them, excluding old in-flight fills after a reload.
    /// `null` when `cfg.proxy_cache_ttl_seconds == 0`, the same
    /// disabled-by-default convention as `proxy_cache_store`. Distinct from
    /// `proxy_cache_store`/`proxy_cache_path` above, which remain the
    /// control-plane JSON proxy's own (differently-shaped) cache. [proxy_response_cache_mutex]
    proxy_response_cache: ?gpc.ProxyResponseCache,
    proxy_response_cache_generation: u64 = 0,
    /// Bounded, crash-safe disk tier for the same cache (#903). Owned and
    /// rebuilt on every reload alongside `proxy_response_cache`, under the
    /// same mutex. `null` when `cfg.proxy_cache_path` is empty, or when
    /// opening/validating it failed (fails open to memory-only caching
    /// rather than aborting the reload/startup). [proxy_response_cache_mutex]
    proxy_response_cache_disk: ?gpdc.DiskCache = null,
    proxy_response_cache_disk_accepting: bool = true,
    /// Number of callers currently using `proxy_response_cache_disk` without
    /// the global cache mutex held. Reload changes the generation first, then
    /// waits for this count to drain before destroying the tier.
    proxy_response_cache_disk_inflight: usize = 0,
    proxy_response_cache_condition: compat.Condition = .{},
    /// Per-key single-flight guard for stale-while-revalidate background
    /// refresh (#903): a key present here already has a background
    /// revalidation thread in flight. [proxy_response_cache_mutex]
    proxy_response_cache_revalidation_locks: std.StringHashMap(void),
    /// Global cap on simultaneous background revalidations across every
    /// key, independent of the per-key lock above (#903). Registration is
    /// serialized with reload under `proxy_response_cache_mutex`; the atomic
    /// value also lets completion publish its progress to the drain waiter.
    proxy_response_cache_revalidation_inflight: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// cfg snapshot, read from request-handling threads without
    /// `proxy_response_cache_mutex` (an atomic rather than a plain field
    /// since reload writes it from a different thread than every reader).
    proxy_response_cache_revalidation_max_concurrency: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Shared cancellation barrier for detached revalidation workers. Reload
    /// and shutdown cancel it and wait for every worker before replacing cache
    /// state or freeing `GatewayState`.
    proxy_response_cache_revalidation_cancel: http.cancellation.CancellationToken = http.cancellation.CancellationToken.init(0),
    security_headers: http.security_headers.SecurityHeaders, // cfg-derived; re-derived on reload [runtime_mutex]
    /// Owned HSTS header value. Empty when HSTS is disabled or TLS is not
    /// configured. Heap-owned; re-derived (old value freed) on reload. [runtime_mutex]
    hsts_value: []u8 = &.{},
    add_headers: []const edge_config.EdgeConfig.HeaderPair, // borrowed from cfg; rebound on reload [runtime_mutex]
    http3_alt_svc: ?[]u8, // owned effective advertisement; re-derived (old freed) on reload [runtime_mutex]
    http3_advertisement_state: http.http3_runtime.EffectiveAdvertisementState, // cfg/runtime-derived [runtime_mutex]
    http3_runtime: ?*http.http3_runtime.Runtime, // owned pointer; main-event-loop-only
    session_store: ?http.session.SessionStore, // owned [session_mutex]
    session_store_path: []const u8, // borrowed from startup cfg; restart-only (warns on change at reload)

    logger: http.logger.Logger, // owned; min_level updated on reload [runtime_mutex]
    metrics: http.metrics.Metrics, // shared counters [metrics_mutex]
    compression_config: http.compression.CompressionConfig, // cfg snapshot; updated on reload [runtime_mutex]
    circuit_breaker: http.circuit_breaker.CircuitBreaker, // shared [circuit_mutex]
    upstream_client: std.http.Client, // owned; self-synchronized HTTP client
    /// ACME HTTP-01 challenge token store (null when ACME automation is disabled).
    /// Owned; main-loop-only.
    acme_challenge_store: ?http.acme_client.ChallengeStore,
    event_hub: http.event_hub.EventHub, // owned; self-synchronized
    request_buffer_pool: http.buffer_pool.BufferPool, // owned; self-synchronized
    relay_buffer_pool: http.buffer_pool.BufferPool, // owned; self-synchronized
    max_connections_per_ip: u32, // cfg snapshot; updated on reload [runtime_mutex]
    max_active_connections: u32, // cfg snapshot; updated on reload [runtime_mutex]
    active_connections_total: usize, // runtime accounting [connection_mutex]
    /// Atomic count of HTTP requests currently being executed. Lock-free.
    in_flight_requests: std.atomic.Value(u32),
    /// Maximum concurrent in-flight requests (0 = unlimited). Requests exceeding
    /// this limit are rejected with 503 before any work is done. cfg snapshot;
    /// updated on reload [runtime_mutex].
    max_in_flight_requests: u32,
    /// Open (or opening) WebSocket tunnels (#812). Lock-free.
    websocket_tunnels: std.atomic.Value(u32) = .init(0),
    /// Most tunnel slots held at once since start (observability only).
    websocket_tunnels_high_water: std.atomic.Value(u32) = .init(0),
    /// Active long-lived streamed HTTP responses (#841). Admission uses the
    /// cap from the configuration generation being admitted.
    response_stream_lifecycle: http.response_stream_lifecycle.Lifecycle = .{},
    /// Absolute graceful-shutdown deadline for admitted response streams.
    /// Zero means shutdown orchestration has not published one yet. The
    /// shutdown owner publishes this once from its startup-owned policy;
    /// relays only observe it.
    response_stream_shutdown_deadline_ms: std.atomic.Value(u64) = .init(0),
    /// Tunnel cap used when `proxy_websocket_max_tunnels` is 0: derived from
    /// the descriptor limit (#818). Set once at startup.
    websocket_default_max_tunnels: u32 = 0,
    /// Reactor that owns established WebSocket tunnels (#818), so they do not
    /// hold a worker thread each. Null in unit tests and when a tunnel must
    /// run inline. Set once at startup; outlives every worker.
    tunnel_reactor: ?*http.tunnel_reactor.Reactor = null,
    /// The process-lifetime ACME renewal worker (#835, A5), when
    /// `tls_acme_enabled`. Set once at startup; outlives every worker. Used
    /// only to pull a bounded, secret-free status snapshot at metrics scrape
    /// time (`overlayAcmeRenewalStatus`) -- the renewal thread itself never
    /// touches `GatewayState`.
    acme_renewal_worker: ?*acme_renewal.Worker = null,
    /// Process-wide, bounded worker pool that executes finite HTTP/2 request
    /// jobs off each connection's frame-reader loop (#866). Null in unit
    /// tests and when disabled; `respondHttp2Stream` falls back to inline
    /// synchronous execution in that case. Set once at startup; outlives
    /// every connection.
    h2_request_executor: ?*http.h2_request_executor.Executor = null,
    /// Internal/test-only hook (#867); see `H2SessionTestHook`. Null in
    /// production and in every other unit test; only the live H2 session
    /// integration test sets it.
    h2_session_test_hook: ?H2SessionTestHook = null,
    active_ws_streams: usize, // runtime accounting [connection_mutex]
    active_sse_streams: usize, // runtime accounting [connection_mutex]
    active_mux_connections: usize, // runtime accounting [connection_mutex]
    active_mux_subscriptions: usize, // runtime accounting [connection_mutex]
    connection_memory_estimate_bytes: usize, // cfg-derived; updated on reload [runtime_mutex]
    max_total_connection_memory_bytes: usize, // cfg snapshot; updated on reload [runtime_mutex]
    proxy_buffer_limits: http.proxy_buffer_account.Limits, // cfg snapshot; updated on reload [runtime_mutex]
    /// Process-wide proxy buffer reservations (#140). Lock-free and shared by
    /// every worker, so its hard limit caps aggregate proxy body memory no
    /// matter how many origins or streams are in flight. [atomic, no mutex]
    proxy_buffer_global_account: http.proxy_buffer_account.Aggregate = http.proxy_buffer_account.Aggregate.init(.global, 0),
    tls_buffer_limits: @import("tls_core").encrypted_stream.BufferLimits, // cfg snapshot for native TLS; updated on reload [runtime_mutex]
    upstream_rr_index: usize, // LB selection state [upstream_mutex]
    upstream_backup_rr_index: usize, // LB selection state [upstream_mutex]
    lb_random_state: u64, // LB selection state [upstream_mutex]
    next_active_health_probe_ms: u64, // schedule; main-event-loop-only
    next_proxy_cache_maintenance_ms: u64, // schedule; main-event-loop-only
    /// Set to true while a background health-probe thread is running so the
    /// event loop does not dispatch a second batch before the first finishes.
    /// Atomic acquire/release handoff between the main loop and the probe thread.
    health_probe_running: std.atomic.Value(bool),
    upstream_health: std.StringHashMap(UpstreamHealth), // owned keys [upstream_mutex]
    upstream_active_requests: std.StringHashMap(usize), // owned keys [upstream_mutex]
    upstream_pool: http.upstream_pool.UpstreamPool, // owned; self-synchronized keep-alive pool (#141; data-plane + FastCGI)
    h2_pool: http.upstream_h2.H2ConnPool, // owned; per-origin HTTP/2 multiplexing pool (#145)
    fastcgi_next_request_id: std.StringHashMap(u16), // owned keys [connection_mutex]
    proxy_cache_locks: std.StringHashMap(u32), // owned keys [proxy_cache_mutex]
    active_connections_by_ip: std.StringHashMap(u32), // owned keys [connection_mutex]
    active_fds: std.AutoHashMap(std.posix.fd_t, void), // runtime accounting [connection_mutex]
    fd_to_ip: std.AutoHashMap(std.posix.fd_t, []u8), // owned IP values [connection_mutex]
    command_lifecycle: std.StringHashMap(CommandLifecycleEntry), // owned keys+nested values [command_mutex]
    approvals: std.StringHashMap(ApprovalEntry), // owned keys+nested values [approval_mutex]
    mux_subscriptions_by_device: std.StringHashMap(usize), // owned keys [connection_mutex]
    mux_resume_state: std.StringHashMap(MuxResumeState), // owned keys+nested values [runtime_mutex]
    /// Path to persistent approval store file (empty = in-memory only).
    /// Borrowed from startup cfg; restart-only (warns on change at reload).
    approval_store_path: []const u8,
    /// Webhook URL for escalation notifications (empty = disabled).
    /// Borrowed from startup cfg; restart-only (warns on change at reload).
    approval_escalation_webhook: []const u8,
    /// Approval TTL in milliseconds. cfg snapshot.
    approval_ttl_ms: i64,
    /// Max concurrent pending approval requests per identity (0 = unlimited).
    /// cfg snapshot.
    approval_max_pending_per_identity: u32,
    /// Borrowed from startup cfg; restart-only (warns on change at reload). [transcript_mutex guards appends]
    transcript_store_path: []const u8,
    /// DNS-based upstream discovery state. Active when
    /// cfg.upstream_dns_discovery_host or cfg.upstream_srv_name is non-empty.
    /// Owned; self-synchronized; refreshed by a detached background thread.
    dns_discovery: http.dns_discovery.DnsDiscovery,
    /// Reload state: set by hotReloadConfig on every attempt so operators can
    /// query the outcome without tailing logs. [reload_mutex]
    reload_mutex: compat.Mutex = .{},
    last_reload_ok: bool = false,
    last_reload_at_ms: i64 = 0,
    last_reload_error: [256]u8 = undefined,
    last_reload_error_len: usize = 0,

    pub fn deinit(self: *GatewayState) void {
        self.proxyResponseCachePrepareReload(self.proxy_response_cache_generation +% 1);
        self.dns_discovery.deinit();
        if (self.rate_limiter) |*rl| rl.deinit();
        if (self.idempotency_store) |*is| is.deinit();
        if (self.proxy_cache_store) |*pc| pc.deinit();
        if (self.proxy_response_cache) |*prc| prc.deinit();
        if (self.proxy_response_cache_disk) |*disk| disk.deinit();
        var revalidation_lock_it = self.proxy_response_cache_revalidation_locks.iterator();
        while (revalidation_lock_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.proxy_response_cache_revalidation_locks.deinit();
        if (self.session_store) |*ss| ss.deinit();
        self.upstream_client.deinit();
        if (self.acme_challenge_store) |*store| store.deinit();
        self.event_hub.deinit();
        self.request_buffer_pool.deinit();
        self.relay_buffer_pool.deinit();
        if (self.hsts_value.len > 0) self.allocator.free(self.hsts_value);
        if (self.http3_alt_svc) |value| self.allocator.free(value);
        var upstream_it = self.upstream_health.iterator();
        while (upstream_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_health.deinit();
        var upstream_active_it = self.upstream_active_requests.iterator();
        while (upstream_active_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_active_requests.deinit();
        self.upstream_pool.deinit();
        self.h2_pool.deinit();
        var fastcgi_id_it = self.fastcgi_next_request_id.iterator();
        while (fastcgi_id_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.fastcgi_next_request_id.deinit();
        var cache_lock_it = self.proxy_cache_locks.iterator();
        while (cache_lock_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.proxy_cache_locks.deinit();
        var ip_it = self.active_connections_by_ip.iterator();
        while (ip_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.active_connections_by_ip.deinit();
        self.active_fds.deinit();

        var fd_it = self.fd_to_ip.iterator();
        while (fd_it.next()) |entry| self.allocator.free(entry.value_ptr.*);
        self.fd_to_ip.deinit();
        var cmd_it = self.command_lifecycle.iterator();
        while (cmd_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.command_type);
            self.allocator.free(entry.value_ptr.correlation_id);
            self.allocator.free(entry.value_ptr.identity);
            self.allocator.free(entry.value_ptr.response_body);
            self.allocator.free(entry.value_ptr.response_content_type);
            self.allocator.free(entry.value_ptr.error_message);
        }
        self.command_lifecycle.deinit();
        var approval_it = self.approvals.iterator();
        while (approval_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.approvals.deinit();
        var mux_sub_it = self.mux_subscriptions_by_device.iterator();
        while (mux_sub_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.mux_subscriptions_by_device.deinit();
        var mux_resume_it = self.mux_resume_state.iterator();
        while (mux_resume_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            deinitMuxResumeState(self.allocator, entry.value_ptr);
        }
        self.mux_resume_state.deinit();
    }

    /// A leased FastCGI upstream connection. `conn` must be handed back via
    /// `releaseFastcgiStream` (on success with `allow_reuse=true`, otherwise
    /// false so the pool closes it).
    pub const FastcgiLease = struct {
        conn: http.upstream_pool.PooledConn,
        reused: bool,
    };

    /// FastCGI keep-alive connections share the generic upstream pool (#141
    /// Phase 2), keyed under a `fastcgi:` prefix so they never mix with HTTP
    /// upstream connections. This replaces the former ad-hoc fixed-size pool,
    /// giving FastCGI idle-timeout / max-lifetime eviction and pool metrics.
    fn fastcgiPoolKey(buf: []u8, endpoint: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "fastcgi:{s}", .{endpoint}) catch endpoint;
    }

    pub fn acquireFastcgiStream(self: *GatewayState, endpoint: []const u8, connect_timeout_ms: u32) !FastcgiLease {
        var key_buf: [512]u8 = undefined;
        const key = fastcgiPoolKey(&key_buf, endpoint);
        const now = http.event_loop.monotonicMs();
        // checkout reserves an active slot before connecting (per-origin cap,
        // #239); a failed connect must release the reservation.
        if (try self.upstream_pool.checkout(key, now)) |conn| {
            return .{ .conn = conn, .reused = true };
        }
        const stream = http.fastcgi.connect(self.allocator, endpoint, connect_timeout_ms) catch |err| {
            self.upstream_pool.releaseSlot(key);
            return err;
        };
        self.upstream_pool.noteNewConnection(key);
        return .{ .conn = .{ .stream = stream, .tls = null, .created_ms = now, .last_used_ms = now }, .reused = false };
    }

    pub fn releaseFastcgiStream(self: *GatewayState, endpoint: []const u8, conn: http.upstream_pool.PooledConn, allow_reuse: bool) void {
        var key_buf: [512]u8 = undefined;
        const key = fastcgiPoolKey(&key_buf, endpoint);
        self.upstream_pool.release(key, conn, allow_reuse, http.event_loop.monotonicMs());
    }

    pub fn nextFastcgiRequestId(self: *GatewayState, endpoint: []const u8) u16 {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.fastcgi_next_request_id.getPtr(endpoint)) |value| {
            const next = value.*;
            value.* = if (next == std.math.maxInt(u16)) 1 else next + 1;
            return next;
        }

        const owned_key = self.allocator.dupe(u8, endpoint) catch return 1;
        self.fastcgi_next_request_id.put(owned_key, 2) catch {
            self.allocator.free(owned_key);
            return 1;
        };
        return 1;
    }

    pub fn tryAcquireConnectionSlot(self: *GatewayState, fd: std.posix.fd_t, ip_key: []const u8) !ConnectionSlotResult {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.max_active_connections > 0 and self.active_connections_total >= self.max_active_connections) {
            self.metrics_mutex.lock();
            self.metrics.recordConnectionRejection();
            self.metrics_mutex.unlock();
            return .over_global_limit;
        }
        if (self.max_total_connection_memory_bytes > 0 and self.connection_memory_estimate_bytes > 0) {
            const projected: u128 = (@as(u128, self.active_connections_total) + 1) * @as(u128, self.connection_memory_estimate_bytes);
            if (projected > self.max_total_connection_memory_bytes) {
                self.metrics_mutex.lock();
                self.metrics.recordConnectionRejection();
                self.metrics_mutex.unlock();
                return .over_global_memory_limit;
            }
        }

        var ip_slot_acquired = false;
        if (self.max_connections_per_ip > 0) {
            const current = self.active_connections_by_ip.get(ip_key) orelse 0;
            if (current >= self.max_connections_per_ip) {
                self.metrics_mutex.lock();
                self.metrics.recordConnectionRejection();
                self.metrics_mutex.unlock();
                return .over_ip_limit;
            }

            if (current == 0) {
                const owned_key = try self.allocator.dupe(u8, ip_key);
                errdefer self.allocator.free(owned_key);
                try self.active_connections_by_ip.put(owned_key, 1);
            } else {
                try self.active_connections_by_ip.put(ip_key, current + 1);
            }
            ip_slot_acquired = true;

            const owned_fd_ip = try self.allocator.dupe(u8, ip_key);
            errdefer self.allocator.free(owned_fd_ip);
            self.fd_to_ip.put(fd, owned_fd_ip) catch |err| {
                if (self.active_connections_by_ip.getPtr(ip_key)) |count| {
                    if (count.* > 1) {
                        count.* -= 1;
                    } else {
                        if (self.active_connections_by_ip.fetchRemove(ip_key)) |kv| {
                            self.allocator.free(kv.key);
                        }
                    }
                }
                return err;
            };
        }

        self.active_fds.put(fd, {}) catch |err| {
            if (ip_slot_acquired) {
                if (self.fd_to_ip.fetchRemove(fd)) |removed| self.allocator.free(removed.value);
                if (self.active_connections_by_ip.getPtr(ip_key)) |count| {
                    if (count.* > 1) {
                        count.* -= 1;
                    } else {
                        if (self.active_connections_by_ip.fetchRemove(ip_key)) |kv| {
                            self.allocator.free(kv.key);
                        }
                    }
                }
            }
            return err;
        };
        self.active_connections_total += 1;
        self.metrics_mutex.lock();
        self.metrics.setActiveConnections(self.active_connections_total);
        self.metrics_mutex.unlock();
        return .accepted;
    }

    pub fn releaseConnectionSlot(self: *GatewayState, fd: std.posix.fd_t) void {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.active_fds.fetchRemove(fd) != null and self.active_connections_total > 0) {
            self.active_connections_total -= 1;
            self.metrics_mutex.lock();
            self.metrics.setActiveConnections(self.active_connections_total);
            self.metrics_mutex.unlock();
        }
        if (self.max_connections_per_ip == 0) return;

        const removed = self.fd_to_ip.fetchRemove(fd) orelse return;
        defer self.allocator.free(removed.value);

        if (self.active_connections_by_ip.getPtr(removed.value)) |count| {
            if (count.* > 1) {
                count.* -= 1;
            } else {
                if (self.active_connections_by_ip.fetchRemove(removed.value)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }
    }

    /// Attempt to reserve an in-flight request slot.
    ///
    /// Returns false (and the caller should respond 503) when
    /// `max_in_flight_requests > 0` and the limit is already reached.
    pub fn tryAcquireRequestSlot(self: *GatewayState) bool {
        if (self.max_in_flight_requests == 0) return true;
        const prev = self.in_flight_requests.fetchAdd(1, .acq_rel);
        if (prev >= self.max_in_flight_requests) {
            _ = self.in_flight_requests.fetchSub(1, .acq_rel);
            return false;
        }
        return true;
    }

    /// Release a previously-acquired in-flight request slot.
    pub fn releaseRequestSlot(self: *GatewayState) void {
        if (self.max_in_flight_requests == 0) return;
        _ = self.in_flight_requests.fetchSub(1, .acq_rel);
    }

    /// Reserve a WebSocket tunnel slot (#812) before the upstream is
    /// contacted. `configured_max` is `proxy_websocket_max_tunnels`; zero uses
    /// the startup default.
    pub fn tryAcquireWebSocketTunnel(self: *GatewayState, configured_max: u32) bool {
        const cap = if (configured_max > 0) configured_max else self.websocket_default_max_tunnels;
        const prev = self.websocket_tunnels.fetchAdd(1, .acq_rel);
        if (prev >= cap) {
            _ = self.websocket_tunnels.fetchSub(1, .acq_rel);
            return false;
        }
        _ = self.websocket_tunnels_high_water.fetchMax(prev + 1, .monotonic);
        return true;
    }

    pub fn releaseWebSocketTunnel(self: *GatewayState) void {
        _ = self.websocket_tunnels.fetchSub(1, .acq_rel);
    }

    /// Reserve a long-lived response-stream slot and retain the exact config
    /// generation that admitted it. Capacity failures are observable and do
    /// not retain a generation or change the active gauge.
    pub fn tryAcquireResponseStream(
        self: *GatewayState,
        config_lease: *ConfigLease,
        location: *const http.location_router.LocationBlock,
        now_ms: u64,
    ) ?ResponseStreamAdmission {
        const admission = tryReserveResponseStream(&self.response_stream_lifecycle, config_lease, location.response_stream, now_ms) orelse {
            self.metricsRecordResponseStreamAdmission(.capacity);
            return null;
        };
        self.metricsRecordResponseStreamAdmission(.admitted);
        return admission;
    }

    /// Finish one admitted stream exactly once, releasing both its process
    /// slot and its configuration-generation lease.
    pub fn finishResponseStream(
        self: *GatewayState,
        admission: *ResponseStreamAdmission,
        reason: http.response_stream_lifecycle.CloseReason,
        now_ms: u64,
    ) void {
        std.debug.assert(reason != .capacity);
        const duration_ms = now_ms -| admission.opened_at_ms;
        admission.release();
        self.metricsRecordResponseStreamClosed(reason, duration_ms);
    }

    /// Read the process-wide, absolute shutdown deadline for response-stream
    /// relays. It is deliberately nullable so starting a stream never creates
    /// a deadline from a request's configuration generation.
    pub fn responseStreamShutdownDeadlineMs(self: *const GatewayState) ?u64 {
        const deadline_ms = self.response_stream_shutdown_deadline_ms.load(.acquire);
        return if (deadline_ms == 0) null else deadline_ms;
    }

    /// Publish the absolute shutdown deadline established by the process
    /// shutdown coordinator. Callers must provide a real monotonic deadline;
    /// the relay layer never derives or extends it itself.
    pub fn publishResponseStreamShutdownDeadline(self: *GatewayState, deadline_ms: u64) void {
        std.debug.assert(deadline_ms != 0);
        self.response_stream_shutdown_deadline_ms.store(deadline_ms, .release);
    }

    /// HOT PATH: taken once per request when rate limiting is enabled.
    /// See docs/CONCURRENCY.md §5 for improvement proposals (shard the map).
    pub fn rateLimitAllow(self: *GatewayState, descriptor: []const u8) bool {
        self.rate_limiter_mutex.lock();
        defer self.rate_limiter_mutex.unlock();
        if (self.rate_limiter) |*rl| {
            return rl.allow(descriptor) != null;
        }
        return true;
    }

    pub fn idempotencyGetCopy(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8) !?http.idempotency.CachedResponse {
        self.idempotency_mutex.lock();
        defer self.idempotency_mutex.unlock();
        if (self.idempotency_store) |*store| {
            if (store.get(key)) |cached| {
                const body = try allocator.dupe(u8, cached.body);
                errdefer allocator.free(body);
                const ct = try allocator.dupe(u8, cached.content_type);
                return .{
                    .status = cached.status,
                    .body = body,
                    .content_type = ct,
                    .created_ns = cached.created_ns,
                };
            }
        }
        return null;
    }

    pub fn idempotencyPut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.idempotency_mutex.lock();
        defer self.idempotency_mutex.unlock();
        if (self.idempotency_store) |*store| {
            try store.put(key, status, body, content_type);
        }
    }

    pub fn proxyCacheGetCopyWithStale(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8, stale_seconds: u32) !?ProxyCacheLookup {
        self.proxy_cache_mutex.lock();
        var locked = true;
        defer if (locked) self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            if (store.getWithStale(key, stale_seconds)) |lookup| {
                const body = try allocator.dupe(u8, lookup.response.body);
                errdefer allocator.free(body);
                const ct = try allocator.dupe(u8, lookup.response.content_type);
                locked = false;
                self.proxy_cache_mutex.unlock();
                return .{
                    .cached = .{
                        .status = lookup.response.status,
                        .body = body,
                        .content_type = ct,
                        .created_ns = lookup.response.created_ns,
                    },
                    .is_stale = lookup.is_stale,
                };
            }
        }
        locked = false;
        self.proxy_cache_mutex.unlock();

        if (self.proxy_cache_path.len == 0) return null;
        const disk_lookup = try proxyCacheReadFromDisk(allocator, self.proxy_cache_path, key, self.proxy_cache_ttl_seconds, stale_seconds);
        if (disk_lookup) |found| {
            self.proxy_cache_mutex.lock();
            defer self.proxy_cache_mutex.unlock();
            if (self.proxy_cache_store) |*store| {
                store.put(key, found.cached.status, found.cached.body, found.cached.content_type) catch {}; // cache write is best-effort; a miss on the next request is acceptable
            }
        }
        return disk_lookup;
    }

    pub fn proxyCachePut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.proxy_cache_mutex.lock();
        var locked = true;
        defer if (locked) self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            try store.put(key, status, body, content_type);
        }
        locked = false;
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            try proxyCacheWriteToDisk(self.proxy_cache_path, key, status, body, content_type);
        }
    }

    pub fn proxyCacheDelete(self: *GatewayState, key: []const u8) bool {
        self.proxy_cache_mutex.lock();
        var removed = false;
        if (self.proxy_cache_store) |*store| {
            removed = store.delete(key);
        }
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed = proxyCacheDeleteFromDisk(self.proxy_cache_path, key) or removed;
        }
        return removed;
    }

    pub fn proxyCachePurgeAll(self: *GatewayState) usize {
        self.proxy_cache_mutex.lock();
        var removed: usize = 0;
        if (self.proxy_cache_store) |*store| {
            removed += store.clear();
        }
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed += proxyCachePurgeDisk(self.proxy_cache_path);
        }
        return removed;
    }

    pub fn proxyCacheTryLock(self: *GatewayState, key: []const u8) !bool {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.contains(key)) return false;
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.proxy_cache_locks.put(owned, 1);
        return true;
    }

    pub fn proxyCacheUnlock(self: *GatewayState, key: []const u8) void {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    pub fn proxyCacheWaitForUnlock(self: *GatewayState, key: []const u8, timeout_ms: u32) bool {
        const deadline = http.event_loop.monotonicMs() + timeout_ms;
        while (http.event_loop.monotonicMs() < deadline) {
            self.proxy_cache_mutex.lock();
            const locked = self.proxy_cache_locks.contains(key);
            self.proxy_cache_mutex.unlock();
            if (!locked) return true;
            std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(10), .awake) catch {}; // interrupt wakes are fine; loop continues immediately
        }
        return false;
    }

    const ProxyResponseCacheMutationGuard = struct {
        state: *GatewayState,
        lanes: [3]usize = undefined,
        count: usize = 0,

        fn unlock(self: ProxyResponseCacheMutationGuard) void {
            var remaining = self.count;
            while (remaining > 0) {
                remaining -= 1;
                self.state.proxy_response_cache_mutation_lanes[self.lanes[remaining]].unlock();
            }
        }
    };

    fn proxyResponseCacheMutationLane(key: []const u8) usize {
        return @intCast(std.hash.Wyhash.hash(0x5447_434d_5554, key) % proxy_response_cache_mutation_lane_count);
    }

    fn lockProxyResponseCacheMutations(self: *GatewayState, keys: []const []const u8) ProxyResponseCacheMutationGuard {
        std.debug.assert(keys.len > 0 and keys.len <= 3);
        var guard = ProxyResponseCacheMutationGuard{ .state = self };
        for (keys) |key| {
            const lane = proxyResponseCacheMutationLane(key);
            var insertion = guard.count;
            var duplicate = false;
            var i: usize = 0;
            while (i < guard.count) : (i += 1) {
                if (guard.lanes[i] == lane) {
                    duplicate = true;
                    break;
                }
                if (guard.lanes[i] > lane) {
                    insertion = i;
                    break;
                }
            }
            if (duplicate) continue;
            var move = guard.count;
            while (move > insertion) : (move -= 1) guard.lanes[move] = guard.lanes[move - 1];
            guard.lanes[insertion] = lane;
            guard.count += 1;
        }
        for (guard.lanes[0..guard.count]) |lane| self.proxy_response_cache_mutation_lanes[lane].lock();
        return guard;
    }

    /// #901: generic `proxy_pass` response-cache lookup. Returns a deep copy
    /// allocated from `scratch` (the caller's request-scoped arena), so the
    /// mutex here never needs to stay held past this call -- no cache
    /// operation here crosses network I/O. #903: on a memory miss, falls
    /// through to the disk tier after leasing the current generation under
    /// `proxy_response_cache_mutex`. The filesystem read runs without that
    /// global memory-cache lock; reload publishes its new generation and
    /// waits for leased disk operations before destroying the old tier.
    /// Every disk hit is hydrated back into memory before it is returned.
    /// A stale representation in particular needs an in-memory entry and
    /// revision token before conditional background revalidation can be
    /// admitted. If promotion fails, this fails open as a cache miss and the
    /// request reaches the origin synchronously.
    fn proxyResponseCacheLookupMemory(
        cache: *gpc.ProxyResponseCache,
        scratch: std.mem.Allocator,
        primary_key: []const u8,
        effective_key: []const u8,
        now_ms: u64,
    ) !?gpc.LookupResult {
        if (try cache.lookup(scratch, effective_key, now_ms)) |hit| return hit;
        if (!std.mem.eql(u8, primary_key, effective_key)) return try cache.lookup(scratch, primary_key, now_ms);
        return null;
    }

    pub fn proxyResponseCacheLookup(
        self: *GatewayState,
        scratch: std.mem.Allocator,
        generation: u64,
        primary_key: []const u8,
        effective_key: []const u8,
        now_ms: u64,
    ) !?gpc.LookupResult {
        {
            self.proxy_response_cache_mutex.lock();
            defer self.proxy_response_cache_mutex.unlock();
            if (self.proxy_response_cache_generation != generation) return null;
            if (self.proxy_response_cache) |*cache| {
                if (try proxyResponseCacheLookupMemory(cache, scratch, primary_key, effective_key, now_ms)) |hit| return hit;
            }
        }
        return self.proxyResponseCacheDiskLookup(scratch, generation, primary_key, effective_key, now_ms);
    }

    fn proxyResponseCacheAcquireDisk(self: *GatewayState, generation: u64) ?*gpdc.DiskCache {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        if (self.proxy_response_cache_generation != generation) return null;
        if (!self.proxy_response_cache_disk_accepting) return null;
        const disk = if (self.proxy_response_cache_disk) |*value| value else return null;
        self.proxy_response_cache_disk_inflight += 1;
        return disk;
    }

    fn proxyResponseCacheReleaseDisk(self: *GatewayState) void {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        std.debug.assert(self.proxy_response_cache_disk_inflight > 0);
        self.proxy_response_cache_disk_inflight -= 1;
        if (self.proxy_response_cache_disk_inflight == 0) self.proxy_response_cache_condition.broadcast();
    }

    fn proxyResponseCacheDiskLookup(
        self: *GatewayState,
        scratch: std.mem.Allocator,
        generation: u64,
        primary_key: []const u8,
        effective_key: []const u8,
        now_ms: u64,
    ) !?gpc.LookupResult {
        const mutation_guard = self.lockProxyResponseCacheMutations(&.{ primary_key, effective_key });
        defer mutation_guard.unlock();

        // A live fill may have won after the caller's initial RAM miss but
        // before this ordered disk promotion began. Prefer that newer RAM
        // representation and never replace it with the older snapshot.
        {
            self.proxy_response_cache_mutex.lock();
            defer self.proxy_response_cache_mutex.unlock();
            if (self.proxy_response_cache_generation != generation) return null;
            if (self.proxy_response_cache) |*cache| {
                if (try proxyResponseCacheLookupMemory(cache, scratch, primary_key, effective_key, now_ms)) |hit| return hit;
            }
        }

        const disk = self.proxyResponseCacheAcquireDisk(generation) orelse return null;
        const loaded = disk.get(scratch, effective_key, now_ms) orelse {
            self.proxyResponseCacheReleaseDisk();
            return null;
        };
        // `loaded` owns its bytes in request scratch, so the tier lease can
        // end before taking the memory-cache mutex. Reload waits for disk
        // leases while holding that mutex; carrying the lease into hydration
        // would invert the lock order and deadlock.
        self.proxyResponseCacheReleaseDisk();

        if (loaded.vary_primary_key) |stored_primary| {
            if (!std.mem.eql(u8, stored_primary, primary_key)) return null;
        } else if (!std.mem.eql(u8, primary_key, effective_key)) {
            return null;
        }

        const stale = now_ms >= loaded.expires_at_ms;
        const resident_seconds = (now_ms -| loaded.stored_at_ms) / 1000;
        const age_seconds: u32 = @intCast(@min(@as(u64, loaded.initial_age_seconds) + resident_seconds, std.math.maxInt(u32)));
        var result = gpc.LookupResult{
            .status_code = loaded.status_code,
            .reason = @constCast(loaded.reason),
            .headers = loaded.headers,
            .body = @constCast(loaded.body),
            .age_seconds = age_seconds,
            .stale = stale,
        };
        const views = try scratch.alloc(gpc.CacheHeaderView, loaded.headers.len);
        for (loaded.headers, 0..) |h, i| views[i] = .{ .name = h.name, .value = h.value };
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        if (self.proxy_response_cache_generation != generation) return null;
        const cache = if (self.proxy_response_cache) |*value| value else return null;
        // The primary lane is held through disk read and promotion. This
        // second check handles a fill that won before lane acquisition and
        // prevents an old secondary snapshot from changing a newer direct
        // primary back to Vary.
        if (try proxyResponseCacheLookupMemory(cache, scratch, primary_key, effective_key, now_ms)) |hit| return hit;
        const params = gpc.PutParams{
            .status_code = loaded.status_code,
            .reason = loaded.reason,
            .headers = views,
            .body = loaded.body,
            .ttl_seconds = 0,
            .initial_age_seconds = loaded.initial_age_seconds,
            .absolute_timing = .{
                .stored_at_ms = loaded.stored_at_ms,
                .expires_at_ms = loaded.expires_at_ms,
                .swr_until_ms = loaded.swr_until_ms,
            },
        };
        if (loaded.vary_primary_key) |primary| {
            cache.putVaryVariant(now_ms, primary, effective_key, params) catch return null;
        } else {
            cache.put(now_ms, effective_key, params) catch return null;
        }
        result.revision = cache.entryRevision(effective_key) orelse return null;
        return result;
    }

    /// #901: fills one entry. Fails open: every error (too large, at
    /// capacity, disabled, or allocation failure) just means the next
    /// request is a miss too -- the caller already proxied this response
    /// normally and only needs the error to count a `fill_error` metric.
    /// #903: also write-through to the disk tier (best-effort, outside
    /// `proxy_response_cache_mutex` -- disk I/O never happens while that
    /// lock is held).
    ///
    /// This is a direct (unvaried) fill, which can displace an existing
    /// on-disk Vary family. #937/#943: that admission is decided *before*
    /// RAM is touched -- if disk cannot durably guard the transition, this
    /// returns an error without ever calling `cache.put`, so RAM is never
    /// left pointing at a direct representation that disk's own restart
    /// recovery cannot yet prove supersedes the stale Vary secondaries.
    pub fn proxyResponseCachePut(self: *GatewayState, now_ms: u64, generation: u64, key: []const u8, params: gpc.PutParams) !void {
        const mutation_guard = self.lockProxyResponseCacheMutations(&.{key});
        defer mutation_guard.unlock();

        const disk = self.proxyResponseCacheAcquireDisk(generation);
        defer if (disk != null) self.proxyResponseCacheReleaseDisk();
        const admission = if (disk) |d| d.beginPolicyTransitionIfVaryTracked(key) else .not_needed;
        if (admission == .refused) return error.ProxyResponseCacheDiskTransitionNotDurable;
        defer if (disk) |d| d.endPolicyTransition(admission);

        self.proxy_response_cache_mutex.lock();
        if (self.proxy_response_cache_generation != generation) {
            self.proxy_response_cache_mutex.unlock();
            return error.ProxyResponseCacheGenerationMismatch;
        }
        if (self.proxy_response_cache) |*cache| {
            cache.put(now_ms, key, params) catch |err| {
                self.proxy_response_cache_mutex.unlock();
                return err;
            };
            self.proxy_response_cache_mutex.unlock();
            if (disk) |d| proxyResponseCacheDiskPutWithDisk(d, now_ms, key, null, params);
            return;
        }
        self.proxy_response_cache_mutex.unlock();
        return error.ProxyResponseCacheDisabled;
    }

    /// Atomically register a background refresh against the current cache
    /// generation. Reload stops admission and publishes its next generation
    /// under this same mutex before waiting for the registered count to
    /// drain, closing the old load/increment race.
    pub fn proxyResponseCacheTryRegisterRevalidation(
        self: *GatewayState,
        generation: u64,
        primary_key: []const u8,
        effective_key: []const u8,
        revision: u64,
        now_ms: u64,
    ) !ProxyResponseCacheRevalidationAdmission {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        if (self.proxy_response_cache_generation != generation or
            self.proxy_response_cache_revalidation_cancel.isStopped()) return .unavailable;
        const max_concurrency = self.proxy_response_cache_revalidation_max_concurrency.load(.acquire);
        if (max_concurrency == 0) return .unavailable;
        if (self.proxy_response_cache_revalidation_inflight.load(.acquire) >= max_concurrency) return .concurrency;
        const cache = if (self.proxy_response_cache) |*value| value else return .unavailable;
        if (!cache.canRevalidate(effective_key, revision, now_ms)) return .unavailable;
        if (self.proxy_response_cache_revalidation_locks.contains(primary_key)) return .unavailable;
        const owned = try self.allocator.dupe(u8, primary_key);
        errdefer self.allocator.free(owned);
        try self.proxy_response_cache_revalidation_locks.put(owned, {});
        _ = self.proxy_response_cache_revalidation_inflight.fetchAdd(1, .acq_rel);
        return .admitted;
    }

    pub fn proxyResponseCacheUnlockRevalidation(self: *GatewayState, key: []const u8) void {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        if (self.proxy_response_cache_revalidation_locks.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    pub fn proxyResponseCacheRecordRevalidationFailure(self: *GatewayState, generation: u64, key: []const u8, revision: u64, now_ms: u64) void {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        if (self.proxy_response_cache_generation != generation) return;
        if (self.proxy_response_cache) |*cache| cache.recordRevalidationFailure(key, revision, now_ms);
    }

    /// Remove one obsolete representation from both tiers. The disk lease
    /// keeps reload from destroying the tier while unlinking outside the
    /// global memory-cache mutex.
    pub fn proxyResponseCacheInvalidate(self: *GatewayState, generation: u64, key: []const u8, expected_revision: u64) void {
        const mutation_guard = self.lockProxyResponseCacheMutations(&.{key});
        defer mutation_guard.unlock();
        self.proxy_response_cache_mutex.lock();
        if (self.proxy_response_cache_generation != generation) {
            self.proxy_response_cache_mutex.unlock();
            return;
        }
        const removed = if (self.proxy_response_cache) |*cache| cache.removeIfRevision(key, expected_revision) else false;
        self.proxy_response_cache_mutex.unlock();
        if (!removed) return;
        const disk = self.proxyResponseCacheAcquireDisk(generation) orelse return;
        defer self.proxyResponseCacheReleaseDisk();
        disk.remove(key);
    }

    /// #903: best-effort disk write-through, called with
    /// `proxy_response_cache_mutex` already released. A disk tier that is
    /// disabled, unavailable, or refuses the object (too large, at
    /// capacity) silently leaves the in-memory fill as the only copy.
    fn proxyResponseCacheDiskPut(self: *GatewayState, now_ms: u64, generation: u64, key: []const u8, vary_primary_key: ?[]const u8, params: gpc.PutParams) void {
        const disk = self.proxyResponseCacheAcquireDisk(generation) orelse return;
        defer self.proxyResponseCacheReleaseDisk();
        proxyResponseCacheDiskPutWithDisk(disk, now_ms, key, vary_primary_key, params);
    }

    /// Same as `proxyResponseCacheDiskPut`, but for a caller that already
    /// holds its own lease on `disk` (for example, one that had to acquire
    /// it earlier to decide `beginPolicyTransitionIfVaryTracked` before
    /// committing a RAM representation switch). Does not acquire or release
    /// any lease itself.
    fn proxyResponseCacheDiskPutWithDisk(disk: *gpdc.DiskCache, now_ms: u64, key: []const u8, vary_primary_key: ?[]const u8, params: gpc.PutParams) void {
        const expires_at_ms = now_ms + @as(u64, params.ttl_seconds - params.initial_age_seconds) * 1000;
        disk.put(key, .{
            .status_code = params.status_code,
            .reason = params.reason,
            .headers = params.headers,
            .body = params.body,
            .stored_at_ms = now_ms,
            .expires_at_ms = expires_at_ms,
            .swr_until_ms = expires_at_ms + @as(u64, params.swr_seconds) * 1000,
            .initial_age_seconds = params.initial_age_seconds,
            .vary_primary_key = vary_primary_key,
        }, now_ms);
    }

    /// #902: whether `primary_key` currently resolves through the bounded
    /// `Vary: Accept-Encoding` variant index rather than a direct entry.
    /// Consulted before building the effective lookup/fill key for a
    /// request. The memory check releases the global cache mutex before a
    /// generation-leased disk metadata lookup can wait on the disk mutex.
    pub fn proxyResponseCacheIsVaryTracked(self: *GatewayState, generation: u64, primary_key: []const u8) bool {
        self.proxy_response_cache_mutex.lock();
        if (self.proxy_response_cache_generation != generation) {
            self.proxy_response_cache_mutex.unlock();
            return false;
        }
        const memory_tracked = if (self.proxy_response_cache) |*cache| cache.isVaryTracked(primary_key) else false;
        self.proxy_response_cache_mutex.unlock();
        if (memory_tracked) return true;

        const disk = self.proxyResponseCacheAcquireDisk(generation) orelse return false;
        defer self.proxyResponseCacheReleaseDisk();
        return disk.isVaryTracked(primary_key);
    }

    /// #902: fills one `Vary: Accept-Encoding` variant and registers it in
    /// the bounded per-resource variant index. Same fail-open contract as
    /// `proxyResponseCachePut`.
    pub fn proxyResponseCachePutVaryVariant(self: *GatewayState, now_ms: u64, generation: u64, primary_key: []const u8, secondary_key: []const u8, params: gpc.PutParams) !void {
        const mutation_guard = self.lockProxyResponseCacheMutations(&.{ primary_key, secondary_key });
        defer mutation_guard.unlock();
        self.proxy_response_cache_mutex.lock();
        if (self.proxy_response_cache_generation != generation) {
            self.proxy_response_cache_mutex.unlock();
            return error.ProxyResponseCacheGenerationMismatch;
        }
        if (self.proxy_response_cache) |*cache| {
            cache.putVaryVariant(now_ms, primary_key, secondary_key, params) catch |err| {
                self.proxy_response_cache_mutex.unlock();
                return err;
            };
            self.proxy_response_cache_mutex.unlock();
            self.proxyResponseCacheDiskPut(now_ms, generation, secondary_key, primary_key, params);
            return;
        }
        self.proxy_response_cache_mutex.unlock();
        return error.ProxyResponseCacheDisabled;
    }

    /// Replace the exact representation that launched a background 200
    /// refresh. The expected revision is checked in the same ordered
    /// mutation that commits RAM and persists disk, so a delayed worker can
    /// neither overwrite nor durably outlive a newer foreground fill.
    ///
    /// When `secondary_key` is null this is a direct refresh, which, like
    /// `proxyResponseCachePut`, can displace an existing on-disk Vary
    /// family. #937/#943: that admission is decided before RAM is touched,
    /// so a durable guard failure aborts without ever switching RAM to the
    /// new direct representation.
    pub fn proxyResponseCacheReplaceRevalidated(
        self: *GatewayState,
        now_ms: u64,
        generation: u64,
        primary_key: []const u8,
        effective_key: []const u8,
        expected_revision: u64,
        secondary_key: ?[]const u8,
        params: gpc.PutParams,
    ) !void {
        const mutation_guard = if (secondary_key) |secondary|
            self.lockProxyResponseCacheMutations(&.{ primary_key, effective_key, secondary })
        else
            self.lockProxyResponseCacheMutations(&.{ primary_key, effective_key });
        defer mutation_guard.unlock();

        const disk = self.proxyResponseCacheAcquireDisk(generation);
        defer if (disk != null) self.proxyResponseCacheReleaseDisk();
        const admission = if (secondary_key == null)
            (if (disk) |d| d.beginPolicyTransitionIfVaryTracked(primary_key) else .not_needed)
        else
            .not_needed;
        if (admission == .refused) return error.ProxyResponseCacheDiskTransitionNotDurable;
        defer if (disk) |d| d.endPolicyTransition(admission);

        self.proxy_response_cache_mutex.lock();
        if (self.proxy_response_cache_generation != generation) {
            self.proxy_response_cache_mutex.unlock();
            return error.ProxyResponseCacheGenerationMismatch;
        }
        const cache = if (self.proxy_response_cache) |*value| value else {
            self.proxy_response_cache_mutex.unlock();
            return error.ProxyResponseCacheDisabled;
        };
        if (cache.entryRevision(effective_key) != expected_revision) {
            self.proxy_response_cache_mutex.unlock();
            return error.CacheRevisionMismatch;
        }
        if (secondary_key) |secondary| {
            cache.putVaryVariant(now_ms, primary_key, secondary, params) catch |err| {
                self.proxy_response_cache_mutex.unlock();
                return err;
            };
        } else {
            cache.put(now_ms, primary_key, params) catch |err| {
                self.proxy_response_cache_mutex.unlock();
                return err;
            };
        }
        self.proxy_response_cache_mutex.unlock();

        const d = disk orelse return;
        if (secondary_key) |secondary| {
            proxyResponseCacheDiskPutWithDisk(d, now_ms, secondary, primary_key, params);
        } else {
            proxyResponseCacheDiskPutWithDisk(d, now_ms, primary_key, null, params);
        }
    }

    pub fn proxyResponseCacheRefreshNotModified(
        self: *GatewayState,
        scratch: std.mem.Allocator,
        now_ms: u64,
        generation: u64,
        primary_key: []const u8,
        effective_key: []const u8,
        expected_revision: u64,
        response_headers: []const gpc.CacheHeaderView,
        ttl_ceiling_seconds: u32,
        swr_ceiling_seconds: u32,
    ) !void {
        const mutation_guard = self.lockProxyResponseCacheMutations(&.{ primary_key, effective_key });
        defer mutation_guard.unlock();
        const snapshot = blk: {
            self.proxy_response_cache_mutex.lock();
            defer self.proxy_response_cache_mutex.unlock();
            if (self.proxy_response_cache_generation != generation) return error.ProxyResponseCacheGenerationMismatch;
            const cache = if (self.proxy_response_cache) |*value| value else return error.ProxyResponseCacheDisabled;
            try cache.refreshNotModified(
                now_ms,
                primary_key,
                effective_key,
                expected_revision,
                response_headers,
                ttl_ceiling_seconds,
                swr_ceiling_seconds,
            );
            break :blk (try cache.persistenceSnapshot(scratch, effective_key)).?;
        };

        const disk = self.proxyResponseCacheAcquireDisk(generation) orelse return;
        defer self.proxyResponseCacheReleaseDisk();
        disk.put(effective_key, .{
            .status_code = snapshot.status_code,
            .reason = snapshot.reason,
            .headers = snapshot.headers,
            .body = snapshot.body,
            .stored_at_ms = snapshot.stored_at_ms,
            .expires_at_ms = snapshot.expires_at_ms,
            .swr_until_ms = snapshot.swr_until_ms,
            .initial_age_seconds = snapshot.initial_age_seconds,
            .vary_primary_key = snapshot.vary_primary_key,
        }, now_ms);
    }

    /// Stop admitting background refreshes, cancel active origin requests,
    /// publish the next generation, and wait until both detached workers and
    /// leased disk operations have stopped touching cache-owned state.
    pub fn proxyResponseCachePrepareReload(self: *GatewayState, next_generation: u64) void {
        self.proxy_response_cache_mutex.lock();
        self.proxy_response_cache_revalidation_max_concurrency.store(0, .release);
        self.proxy_response_cache_generation = next_generation;
        self.proxy_response_cache_disk_accepting = false;
        self.proxy_response_cache_revalidation_cancel.cancel(.shutdown);
        while (self.proxy_response_cache_revalidation_inflight.load(.acquire) != 0 or self.proxy_response_cache_disk_inflight != 0) {
            self.proxy_response_cache_condition.wait(&self.proxy_response_cache_mutex);
        }
        self.proxy_response_cache_mutex.unlock();
    }

    pub fn proxyResponseCacheRevalidationFinished(self: *GatewayState) void {
        self.proxy_response_cache_mutex.lock();
        defer self.proxy_response_cache_mutex.unlock();
        const previous = self.proxy_response_cache_revalidation_inflight.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) self.proxy_response_cache_condition.broadcast();
    }

    test "proxy response cache revalidation admission is generation scoped and backed off" {
        var state: GatewayState = undefined;
        state.allocator = std.testing.allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(std.testing.allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = null;
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 7;
        state.proxy_response_cache_revalidation_locks = std.StringHashMap(void).init(std.testing.allocator);
        defer state.proxy_response_cache_revalidation_locks.deinit();
        state.proxy_response_cache_revalidation_inflight = std.atomic.Value(u32).init(0);
        state.proxy_response_cache_revalidation_max_concurrency = std.atomic.Value(u32).init(1);
        state.proxy_response_cache_revalidation_cancel = http.cancellation.CancellationToken.init(0);

        try state.proxy_response_cache.?.put(0, "key", .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=1" }},
            .body = "body",
            .ttl_seconds = 1,
            .swr_seconds = 30,
        });
        const revision = state.proxy_response_cache.?.entryRevision("key").?;
        try std.testing.expectEqual(ProxyResponseCacheRevalidationAdmission.admitted, try state.proxyResponseCacheTryRegisterRevalidation(7, "key", "key", revision, 1_500));
        try std.testing.expectEqual(ProxyResponseCacheRevalidationAdmission.concurrency, try state.proxyResponseCacheTryRegisterRevalidation(7, "other", "key", revision, 1_500));
        state.proxyResponseCacheRecordRevalidationFailure(7, "key", revision, 1_500);
        state.proxyResponseCacheUnlockRevalidation("key");
        state.proxyResponseCacheRevalidationFinished();

        try std.testing.expectEqual(ProxyResponseCacheRevalidationAdmission.unavailable, try state.proxyResponseCacheTryRegisterRevalidation(7, "key", "key", revision, 2_499));
        try std.testing.expectEqual(ProxyResponseCacheRevalidationAdmission.admitted, try state.proxyResponseCacheTryRegisterRevalidation(7, "key", "key", revision, 2_500));
        state.proxyResponseCacheUnlockRevalidation("key");
        state.proxyResponseCacheRevalidationFinished();

        state.proxyResponseCachePrepareReload(8);
        try std.testing.expectEqual(ProxyResponseCacheRevalidationAdmission.unavailable, try state.proxyResponseCacheTryRegisterRevalidation(7, "key", "key", revision, 3_000));
    }

    test "proxy response cache rejects a different config generation" {
        var state: GatewayState = undefined;
        state.allocator = std.testing.allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(std.testing.allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
        });
        state.proxy_response_cache_disk = null;
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 7;
        defer state.proxy_response_cache.?.deinit();

        const params = gpc.PutParams{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
            .body = "old-generation",
            .ttl_seconds = 60,
        };
        try state.proxyResponseCachePut(1_000, 7, "key", params);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expect((try state.proxyResponseCacheLookup(arena.allocator(), 8, "key", "key", 1_001)) == null);
        try std.testing.expectError(error.ProxyResponseCacheGenerationMismatch, state.proxyResponseCachePut(1_001, 8, "key-2", params));
        try std.testing.expect((try state.proxyResponseCacheLookup(arena.allocator(), 7, "key", "key", 1_001)) != null);
    }

    test "stale background mutations cannot replace or invalidate a newer revision" {
        var state: GatewayState = undefined;
        state.allocator = std.testing.allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(std.testing.allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = null;
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 3;

        try state.proxyResponseCachePut(0, 3, "key", .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=1" }},
            .body = "v1",
            .ttl_seconds = 1,
            .swr_seconds = 30,
        });
        const v1_revision = state.proxy_response_cache.?.entryRevision("key").?;
        try state.proxyResponseCachePut(1_100, 3, "key", .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=30" }},
            .body = "v2",
            .ttl_seconds = 30,
        });
        const v2_revision = state.proxy_response_cache.?.entryRevision("key").?;

        try std.testing.expectError(error.CacheRevisionMismatch, state.proxyResponseCacheReplaceRevalidated(1_200, 3, "key", "key", v1_revision, null, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=30" }},
            .body = "delayed-v1",
            .ttl_seconds = 30,
        }));
        state.proxyResponseCacheInvalidate(3, "key", v1_revision);

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const hit = (try state.proxyResponseCacheLookup(arena.allocator(), 3, "key", "key", 1_300)).?;
        try std.testing.expectEqualStrings("v2", hit.body);
        try std.testing.expectEqual(v2_revision, hit.revision);

        state.proxyResponseCacheInvalidate(3, "key", v2_revision);
        try std.testing.expect((try state.proxyResponseCacheLookup(arena.allocator(), 3, "key", "key", 1_301)) == null);
    }

    test "disk promotion prefers a newer RAM fill for direct and Vary keys" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
            .max_vary_variants = 4,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 1 << 20,
            .max_vary_variants = 4,
        }, 99);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 5;

        const direct_key = "a" ** 64;
        const primary_key = "b" ** 64;
        const secondary_key = "c" ** 64;
        const disk_headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=30" }};
        state.proxy_response_cache_disk.?.put(direct_key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &disk_headers,
            .body = "disk-v1",
            .stored_at_ms = 0,
            .expires_at_ms = 30_000,
            .swr_until_ms = 30_000,
            .initial_age_seconds = 0,
        }, 0);
        state.proxy_response_cache_disk.?.put(secondary_key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &disk_headers,
            .body = "disk-vary-v1",
            .stored_at_ms = 0,
            .expires_at_ms = 30_000,
            .swr_until_ms = 30_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary_key,
        }, 0);
        try state.proxy_response_cache.?.put(1_000, direct_key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &disk_headers,
            .body = "ram-v2",
            .ttl_seconds = 30,
        });
        try state.proxy_response_cache.?.putVaryVariant(1_000, primary_key, secondary_key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &disk_headers,
            .body = "ram-vary-v2",
            .ttl_seconds = 30,
        });

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const direct = (try state.proxyResponseCacheDiskLookup(arena.allocator(), 5, direct_key, direct_key, 1_001)).?;
        const variant = (try state.proxyResponseCacheDiskLookup(arena.allocator(), 5, primary_key, secondary_key, 1_001)).?;
        try std.testing.expectEqualStrings("ram-v2", direct.body);
        try std.testing.expectEqualStrings("ram-vary-v2", variant.body);

        // A disk metadata waiter must not carry the global RAM-cache mutex.
        // Hold the disk mutex to make the wait deterministic, then prove an
        // unrelated memory operation can still acquire its lock.
        const unknown_primary = "d" ** 64;
        var started = std.atomic.Value(bool).init(false);
        var tracked = true;
        const Check = struct {
            fn run(target: *GatewayState, key: []const u8, signal: *std.atomic.Value(bool), result: *bool) void {
                signal.store(true, .release);
                result.* = target.proxyResponseCacheIsVaryTracked(5, key);
            }
        };
        state.proxy_response_cache_disk.?.mutex.lock();
        const waiter = try std.Thread.spawn(.{}, Check.run, .{ &state, unknown_primary, &started, &tracked });
        while (!started.load(.acquire)) std.atomic.spinLoopHint();
        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        const memory_lock_available = state.proxy_response_cache_mutex.tryLock();
        if (memory_lock_available) state.proxy_response_cache_mutex.unlock();
        state.proxy_response_cache_disk.?.mutex.unlock();
        waiter.join();
        try std.testing.expect(memory_lock_available);
        try std.testing.expect(!tracked);
    }

    test "proxyResponseCachePut does not switch RAM to direct when disk cannot durably guard the transition" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
            .max_vary_variants = 4,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 1 << 20,
            .max_vary_variants = 4,
        }, 101);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 9;

        const primary = "b" ** 64;
        const secondary = "c" ** 64;
        const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=30" }};

        // Seed an existing Vary secondary for `primary` on both tiers.
        state.proxy_response_cache_disk.?.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "disk-vary-v1",
            .stored_at_ms = 0,
            .expires_at_ms = 30_000,
            .swr_until_ms = 30_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 0);
        try state.proxy_response_cache.?.putVaryVariant(0, primary, secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "ram-vary-v1",
            .ttl_seconds = 30,
        });

        // The durable write-ahead transition guard itself fails.
        state.proxy_response_cache_disk.?.state_dir.fault = .write;
        state.proxy_response_cache_disk.?.state_dir.fault_file = "disk-cache.transitioning";

        // #937/#943: a direct fill that would displace this Vary family
        // must fail before RAM is ever touched, not after.
        try std.testing.expectError(error.ProxyResponseCacheDiskTransitionNotDurable, state.proxyResponseCachePut(1_000, 9, primary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "direct-v1",
            .ttl_seconds = 30,
        }));

        // RAM must still be exactly as it was before the attempt: still
        // Vary-tracked, never switched to a direct representation disk
        // cannot yet prove supersedes the old secondary after a restart.
        try std.testing.expect(state.proxy_response_cache.?.isVaryTracked(primary));
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const hit = (try state.proxyResponseCacheLookup(arena.allocator(), 9, primary, secondary, 1_001)).?;
        try std.testing.expectEqualStrings("ram-vary-v1", hit.body);
    }

    test "proxy response cache lookup releases mutex when scratch allocation fails" {
        var state: GatewayState = undefined;
        state.allocator = std.testing.allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(std.testing.allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
        });
        state.proxy_response_cache_disk = null;
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 4;
        defer state.proxy_response_cache.?.deinit();
        try state.proxy_response_cache.?.put(0, "key", .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
            .body = "body",
            .ttl_seconds = 60,
        });

        var no_memory: [0]u8 = .{};
        var failing = std.heap.FixedBufferAllocator.init(&no_memory);
        try std.testing.expectError(error.OutOfMemory, state.proxyResponseCacheLookup(failing.allocator(), 4, "key", "key", 1));
        try std.testing.expect(state.proxy_response_cache_mutex.tryLock());
        state.proxy_response_cache_mutex.unlock();
    }

    test "disk variant promotion holds the primary lane across read and hydration" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 32 * 1024,
            .max_vary_variants = 4,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 1 << 20,
            .max_vary_variants = 4,
        }, 100);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 6;

        const primary = "1" ** 64;
        const candidates = [_][]const u8{ "2" ** 64, "3" ** 64, "4" ** 64, "5" ** 64, "6" ** 64 };
        var secondary = candidates[0];
        for (candidates) |candidate| {
            if (proxyResponseCacheMutationLane(primary) != proxyResponseCacheMutationLane(candidate) and
                !gpdc.DiskCache.keysShareIoLane(primary, candidate))
            {
                secondary = candidate;
                break;
            }
        }
        try std.testing.expect(proxyResponseCacheMutationLane(primary) != proxyResponseCacheMutationLane(secondary));
        try std.testing.expect(!gpdc.DiskCache.keysShareIoLane(primary, secondary));
        const headers = [_]gpc.CacheHeaderView{
            .{ .name = "Cache-Control", .value = "max-age=60" },
            .{ .name = "Vary", .value = "Accept-Encoding" },
        };
        state.proxy_response_cache_disk.?.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "disk-variant-v1",
            .stored_at_ms = 0,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 0);

        var read_barrier = gpdc.TestIoBarrier{ .key = secondary };
        state.proxy_response_cache_disk.?.test_read_barrier = &read_barrier;
        const Lookup = struct {
            fn run(target: *GatewayState, primary_key: []const u8, effective_key: []const u8, saw_variant: *std.atomic.Value(bool)) void {
                var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
                defer arena.deinit();
                const hit = target.proxyResponseCacheLookup(arena.allocator(), 6, primary_key, effective_key, 1) catch null;
                if (hit) |value| saw_variant.store(std.mem.eql(u8, value.body, "disk-variant-v1"), .release);
            }
        };
        var saw_variant = std.atomic.Value(bool).init(false);
        const lookup = try std.Thread.spawn(.{}, Lookup.run, .{ &state, primary, secondary, &saw_variant });
        read_barrier.waitUntilReached();

        const Fill = struct {
            fn run(target: *GatewayState, primary_key: []const u8, done: *std.atomic.Value(bool)) void {
                target.proxyResponseCachePut(2, 6, primary_key, .{
                    .status_code = 200,
                    .reason = "OK",
                    .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
                    .body = "direct-v2",
                    .ttl_seconds = 60,
                }) catch {};
                done.store(true, .release);
            }
        };
        var fill_done = std.atomic.Value(bool).init(false);
        const fill = std.Thread.spawn(.{}, Fill.run, .{ &state, primary, &fill_done }) catch |err| {
            read_barrier.release();
            lookup.join();
            return err;
        };
        var attempts: usize = 0;
        while (!fill_done.load(.acquire) and attempts < 50) : (attempts += 1) {
            std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        state.proxy_response_cache_mutex.lock();
        const direct_committed_while_promotion_blocked = state.proxy_response_cache.?.entryRevision(primary) != null;
        state.proxy_response_cache_mutex.unlock();
        read_barrier.release();
        lookup.join();
        fill.join();
        state.proxy_response_cache_disk.?.test_read_barrier = null;

        try std.testing.expect(!direct_committed_while_promotion_blocked);
        try std.testing.expect(saw_variant.load(.acquire));
        try std.testing.expect(fill_done.load(.acquire));
        state.proxy_response_cache_mutex.lock();
        defer state.proxy_response_cache_mutex.unlock();
        try std.testing.expect(state.proxy_response_cache.?.entryRevision(primary) != null);
        try std.testing.expect(state.proxy_response_cache.?.entryRevision(secondary) == null);
        try std.testing.expect(!state.proxy_response_cache.?.isVaryTracked(primary));
    }

    test "a stale Vary secondary cannot resurrect through the public lookup after a busy-sibling fence transition" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 32 * 1024,
            .max_vary_variants = 4,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 1 << 20,
            .max_vary_variants = 4,
        }, 101);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 11;

        const primary = "1" ** 64;
        const candidates = [_][]const u8{ "2" ** 64, "3" ** 64, "4" ** 64, "5" ** 64, "6" ** 64 };
        var secondary = candidates[0];
        for (candidates) |candidate| {
            if (proxyResponseCacheMutationLane(primary) != proxyResponseCacheMutationLane(candidate) and
                !gpdc.DiskCache.keysShareIoLane(primary, candidate))
            {
                secondary = candidate;
                break;
            }
        }

        // The request that chose this secondary is long gone: only the disk
        // tier remembers it, as the review's "particularly after the new
        // direct RAM entry expires/evicts" scenario describes.
        state.proxy_response_cache_disk.?.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
            .body = "stale-variant",
            .stored_at_ms = 0,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 0);

        // A concurrent writer's I/O lane keeps the secondary from being
        // durably retired, exactly as in the disk-tier unit test, but here
        // the policy transition itself runs through the public GatewayState
        // write path.
        state.proxy_response_cache_disk.?.io_lanes[gpdc.DiskCache.ioLane(secondary)].lock();
        try state.proxyResponseCachePut(1, 11, primary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
            .body = "direct",
            .ttl_seconds = 60,
        });
        state.proxy_response_cache_disk.?.io_lanes[gpdc.DiskCache.ioLane(secondary)].unlock();

        try std.testing.expect(!state.proxyResponseCacheIsVaryTracked(11, primary));

        // The new direct RAM entry has since expired/evicted; only the disk
        // tier (primary fence plus the still-undeleted secondary file)
        // remains, matching the review scenario precisely.
        {
            state.proxy_response_cache_mutex.lock();
            defer state.proxy_response_cache_mutex.unlock();
            const revision = state.proxy_response_cache.?.entryRevision(primary).?;
            try std.testing.expect(state.proxy_response_cache.?.removeIfRevision(primary, revision));
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        // A request that still believes the secondary is the right
        // representation (it checked `isVaryTracked` before the transition
        // above) must get a safe miss, never the superseded body.
        const hit = try state.proxyResponseCacheLookup(arena.allocator(), 11, primary, secondary, 2);
        try std.testing.expect(hit == null);
    }

    test "proxy response cache serializes racing fills without exceeding its cap" {
        // Two origin responses can complete at nearly the same instant.  The
        // gateway lock must make this a one-entry store rather than a
        // check-then-insert race that transiently exceeds the configured cap.
        var state: GatewayState = undefined;
        state.allocator = std.testing.allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(std.testing.allocator, .{
            .max_object_bytes = 1024,
            .max_entries = 1,
            .max_total_bytes = 1024,
        });
        state.proxy_response_cache_disk = null;
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 9;
        defer state.proxy_response_cache.?.deinit();

        const Fill = struct {
            fn run(target: *GatewayState, body: []const u8) void {
                target.proxyResponseCachePut(1_000, 9, "same-key", .{
                    .status_code = 200,
                    .reason = "OK",
                    .headers = &.{},
                    .body = body,
                    .ttl_seconds = 60,
                }) catch {};
            }
        };
        const first = try std.Thread.spawn(.{}, Fill.run, .{ &state, "first-response" });
        const second = try std.Thread.spawn(.{}, Fill.run, .{ &state, "second-response" });
        first.join();
        second.join();

        {
            state.proxy_response_cache_mutex.lock();
            defer state.proxy_response_cache_mutex.unlock();
            const cache = &state.proxy_response_cache.?;
            try std.testing.expectEqual(@as(usize, 1), cache.map.count());
            try std.testing.expect(cache.total_bytes <= cache.limits.max_total_bytes);
        }

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const hit = (try state.proxyResponseCacheLookup(arena.allocator(), 9, "same-key", "same-key", 1_001)).?;
        try std.testing.expect(std.mem.eql(u8, hit.body, "first-response") or std.mem.eql(u8, hit.body, "second-response"));
    }

    test "racing same-key fills leave RAM and disk in the same commit order" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 16 * 1024,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 4,
            .max_total_bytes = 1 << 20,
        }, 71);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 11;

        const key = "e" ** 64;
        var second_started = std.atomic.Value(bool).init(false);
        const Fill = struct {
            fn run(target: *GatewayState, cache_key: []const u8, body: []const u8, started: ?*std.atomic.Value(bool)) void {
                if (started) |signal| signal.store(true, .release);
                target.proxyResponseCachePut(1_000, 11, cache_key, .{
                    .status_code = 200,
                    .reason = "OK",
                    .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
                    .body = body,
                    .ttl_seconds = 60,
                }) catch {};
            }
        };

        // Freeze v1 after its RAM commit but before its disk write. A second
        // fill then reaches the mutation barrier. Releasing the disk must
        // persist v1 first and v2 second, matching their RAM commit order.
        //
        // Held on the key's own I/O lane, not `DiskCache.mutex`: #937/#943's
        // write-ahead transition-guard admission now takes that mutex
        // *before* the RAM commit too (to check whether the primary is
        // Vary-tracked), so holding it externally here would freeze v1
        // before its RAM commit ever lands, not just before its disk write.
        const key_lane = gpdc.DiskCache.ioLane(key);
        state.proxy_response_cache_disk.?.io_lanes[key_lane].lock();
        const first = std.Thread.spawn(.{}, Fill.run, .{ &state, key, "first", null }) catch |err| {
            state.proxy_response_cache_disk.?.io_lanes[key_lane].unlock();
            return err;
        };
        while (true) {
            state.proxy_response_cache_mutex.lock();
            const committed = state.proxy_response_cache.?.entryRevision(key) != null;
            state.proxy_response_cache_mutex.unlock();
            if (committed) break;
            std.atomic.spinLoopHint();
        }
        const second = std.Thread.spawn(.{}, Fill.run, .{ &state, key, "second", &second_started }) catch |err| {
            state.proxy_response_cache_disk.?.io_lanes[key_lane].unlock();
            first.join();
            return err;
        };
        while (!second_started.load(.acquire)) std.atomic.spinLoopHint();
        state.proxy_response_cache_disk.?.io_lanes[key_lane].unlock();
        first.join();
        second.join();

        var memory_arena = std.heap.ArenaAllocator.init(allocator);
        defer memory_arena.deinit();
        const memory_hit = (try state.proxyResponseCacheLookup(memory_arena.allocator(), 11, key, key, 1_001)).?;
        var disk_arena = std.heap.ArenaAllocator.init(allocator);
        defer disk_arena.deinit();
        const disk_hit = state.proxy_response_cache_disk.?.get(disk_arena.allocator(), key, 1_001).?;
        try std.testing.expectEqualStrings("second", memory_hit.body);
        try std.testing.expectEqualStrings("second", disk_hit.body);
    }

    test "stalled disk write on one stripe does not block another key's RAM fill and hit" {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);

        var state: GatewayState = undefined;
        state.allocator = allocator;
        state.proxy_response_cache_mutex = .{};
        state.proxy_response_cache_mutation_lanes = @splat(.{});
        state.proxy_response_cache = gpc.ProxyResponseCache.init(allocator, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 32 * 1024,
        });
        defer state.proxy_response_cache.?.deinit();
        state.proxy_response_cache_disk = try gpdc.DiskCache.init(allocator, root_path, .{
            .max_object_bytes = 4096,
            .max_entries = 8,
            .max_total_bytes = 1 << 20,
        }, 72);
        defer state.proxy_response_cache_disk.?.deinit();
        state.proxy_response_cache_disk_accepting = true;
        state.proxy_response_cache_disk_inflight = 0;
        state.proxy_response_cache_condition = .{};
        state.proxy_response_cache_generation = 12;

        const key_a = "6" ** 64;
        const candidates = [_][]const u8{ "7" ** 64, "8" ** 64, "9" ** 64, "a" ** 64, "b" ** 64 };
        var key_b = candidates[0];
        for (candidates) |candidate| {
            if (proxyResponseCacheMutationLane(candidate) != proxyResponseCacheMutationLane(key_a) and
                !gpdc.DiskCache.keysShareIoLane(candidate, key_a))
            {
                key_b = candidate;
                break;
            }
        }
        try std.testing.expect(proxyResponseCacheMutationLane(key_b) != proxyResponseCacheMutationLane(key_a));
        try std.testing.expect(!gpdc.DiskCache.keysShareIoLane(key_b, key_a));

        var barrier = gpdc.TestWriteBarrier{ .key = key_a };
        state.proxy_response_cache_disk.?.test_write_barrier = &barrier;
        const Fill = struct {
            fn run(target: *GatewayState, key: []const u8, body: []const u8, done: *std.atomic.Value(bool)) void {
                target.proxyResponseCachePut(1_000, 12, key, .{
                    .status_code = 200,
                    .reason = "OK",
                    .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
                    .body = body,
                    .ttl_seconds = 60,
                }) catch {};
                done.store(true, .release);
            }
        };
        var a_done = std.atomic.Value(bool).init(false);
        const writer_a = try std.Thread.spawn(.{}, Fill.run, .{ &state, key_a, "blocked-a", &a_done });
        barrier.waitUntilReached();
        var b_done = std.atomic.Value(bool).init(false);
        const writer_b = std.Thread.spawn(.{}, Fill.run, .{ &state, key_b, "ready-b", &b_done }) catch |err| {
            barrier.release();
            writer_a.join();
            return err;
        };
        var attempts: usize = 0;
        while (!b_done.load(.acquire) and attempts < 100) : (attempts += 1) {
            std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        const b_completed_while_a_blocked = b_done.load(.acquire);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const b_hit = if (b_completed_while_a_blocked)
            try state.proxyResponseCacheLookup(arena.allocator(), 12, key_b, key_b, 1_001)
        else
            null;
        barrier.release();
        writer_a.join();
        writer_b.join();
        state.proxy_response_cache_disk.?.test_write_barrier = null;

        try std.testing.expect(b_completed_while_a_blocked);
        try std.testing.expectEqualStrings("ready-b", b_hit.?.body);
        try std.testing.expect(a_done.load(.acquire));
    }

    pub fn createSession(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8, client_ip: []const u8, device_id: ?[]const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const token = try self.session_store.?.create(identity, client_ip, device_id);
        self.persistSessionsLocked();
        return try allocator.dupe(u8, token);
    }

    pub fn validateSessionIdentity(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| {
            if (ss.validate(token)) |session| {
                self.persistSessionsLocked();
                return allocator.dupe(u8, session.identity) catch null;
            }
        }
        return null;
    }

    pub fn revokeSession(self: *GatewayState, token: []const u8) bool {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| {
            const revoked = ss.revoke(token);
            if (revoked) self.persistSessionsLocked();
            return revoked;
        }
        return false;
    }

    pub fn countSessionsByIdentity(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8) !usize {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const sessions = try self.session_store.?.listByIdentity(allocator, identity);
        defer allocator.free(sessions);
        return sessions.len;
    }

    pub fn refreshSession(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8, client_ip: []const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const existing = self.session_store.?.validate(token) orelse return error.InvalidSession;
        const new_token = try self.session_store.?.create(existing.identity, client_ip, existing.device_id);
        _ = self.session_store.?.revoke(token);
        self.persistSessionsLocked();
        return try allocator.dupe(u8, new_token);
    }

    pub fn persistSessionsLocked(self: *GatewayState) void {
        if (self.session_store_path.len == 0) return;
        if (self.session_store) |*ss| {
            http.session_store_file.persist(self.allocator, self.session_store_path, ss) catch |err| {
                self.logger.warn(null, "session store persist failed: {}", .{err});
            };
        }
    }

    pub fn appendTranscript(
        self: *GatewayState,
        scope: []const u8,
        route: []const u8,
        correlation_id: []const u8,
        identity: ?[]const u8,
        client_ip: []const u8,
        upstream_url: []const u8,
        request_body: []const u8,
        response_status: u16,
        response_content_type: []const u8,
        response_body: []const u8,
        redacted_values: []const []const u8,
    ) void {
        if (self.transcript_store_path.len == 0) return;
        self.transcript_mutex.lock();
        defer self.transcript_mutex.unlock();
        http.transcript_store.append(self.allocator, self.transcript_store_path, .{
            .ts_ms = compat.milliTimestamp(),
            .scope = scope,
            .route = route,
            .correlation_id = correlation_id,
            .identity = identity orelse "",
            .client_ip = client_ip,
            .upstream_url = upstream_url,
            .request_body = request_body,
            .response_status = response_status,
            .response_content_type = response_content_type,
            .response_body = response_body,
        }, redacted_values) catch |err| {
            self.logger.warn(correlation_id, "transcript store append failed: {}", .{err});
        };
    }

    pub fn commandLifecycleCreate(self: *GatewayState, command_id: []const u8, command_type: []const u8, correlation_id: []const u8, identity: []const u8) !void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.contains(command_id)) return error.CommandAlreadyExists;
        const now = compat.milliTimestamp();
        const owned_id = try self.allocator.dupe(u8, command_id);
        errdefer self.allocator.free(owned_id);
        const owned_cmd = try self.allocator.dupe(u8, command_type);
        errdefer self.allocator.free(owned_cmd);
        const owned_corr = try self.allocator.dupe(u8, correlation_id);
        errdefer self.allocator.free(owned_corr);
        const owned_ident = try self.allocator.dupe(u8, identity);
        errdefer self.allocator.free(owned_ident);
        const response_body = try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(response_body);
        const response_content_type = try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(response_content_type);
        const error_message = try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(error_message);
        const entry = CommandLifecycleEntry{
            .status = .pending,
            .command_type = owned_cmd,
            .correlation_id = owned_corr,
            .identity = owned_ident,
            .created_ms = now,
            .updated_ms = now,
            .response_status = 0,
            .response_body = response_body,
            .response_content_type = response_content_type,
            .error_message = error_message,
        };
        try self.command_lifecycle.putNoClobber(owned_id, entry);
    }

    pub fn commandLifecycleSetRunning(self: *GatewayState, command_id: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            entry.status = .running;
            entry.updated_ms = compat.milliTimestamp();
        }
    }

    pub fn commandLifecycleSetCompleted(self: *GatewayState, command_id: []const u8, status: u16, body: []const u8, content_type: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            // Allocate the entire replacement before changing live state. An
            // allocation failure must leave the old, fully owned snapshot in
            // place rather than dangling pointers to buffers we already freed.
            const new_body = self.allocator.dupe(u8, body) catch return;
            const new_content_type = self.allocator.dupe(u8, content_type) catch {
                self.allocator.free(new_body);
                return;
            };
            const new_error = self.allocator.dupe(u8, "") catch {
                self.allocator.free(new_body);
                self.allocator.free(new_content_type);
                return;
            };
            self.allocator.free(entry.response_body);
            self.allocator.free(entry.response_content_type);
            self.allocator.free(entry.error_message);
            entry.status = .completed;
            entry.updated_ms = compat.milliTimestamp();
            entry.response_status = status;
            entry.response_body = new_body;
            entry.response_content_type = new_content_type;
            entry.error_message = new_error;
        }
    }

    pub fn commandLifecycleSetFailed(self: *GatewayState, command_id: []const u8, message: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            const new_error = self.allocator.dupe(u8, message) catch return;
            self.allocator.free(entry.error_message);
            entry.status = .failed;
            entry.updated_ms = compat.milliTimestamp();
            entry.error_message = new_error;
        }
    }

    pub fn commandLifecycleSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?[]const u8 {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const entry = self.command_lifecycle.get(command_id) orelse return null;
        var parsed_body = if (entry.response_body.len > 0 and
            (std.mem.startsWith(u8, entry.response_body, "{") or std.mem.startsWith(u8, entry.response_body, "[")))
            std.json.parseFromSlice(std.json.Value, allocator, entry.response_body, .{}) catch null
        else
            null;
        defer if (parsed_body) |*parsed| parsed.deinit();

        const response_body: std.json.Value = if (parsed_body) |parsed| switch (parsed.value) {
            .object, .array => parsed.value,
            else => .{ .string = "" },
        } else .{ .string = "" };
        return compat.stringifyAlloc(allocator, .{
            .command_id = command_id,
            .status = @tagName(entry.status),
            .command = entry.command_type,
            .correlation_id = entry.correlation_id,
            .identity = entry.identity,
            .created_ms = entry.created_ms,
            .updated_ms = entry.updated_ms,
            .response_status = entry.response_status,
            .response_content_type = entry.response_content_type,
            .response_body = response_body,
            .@"error" = entry.error_message,
        }, .{}) catch null;
    }

    pub fn commandLifecycleGet(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?CommandLifecycleSnapshot {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const entry = self.command_lifecycle.get(command_id) orelse return null;
        const response_body = allocator.dupe(u8, entry.response_body) catch return null;
        errdefer allocator.free(response_body);
        const response_content_type = allocator.dupe(u8, entry.response_content_type) catch return null;
        errdefer allocator.free(response_content_type);
        const error_message = allocator.dupe(u8, entry.error_message) catch return null;
        return .{
            .status = entry.status,
            .response_status = entry.response_status,
            .response_body = response_body,
            .response_content_type = response_content_type,
            .error_message = error_message,
        };
    }

    pub fn approvalCreate(self: *GatewayState, allocator: std.mem.Allocator, method: []const u8, path: []const u8, identity: []const u8, command_id: ?[]const u8) !ApprovalCreateResult {
        const result = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();

            // Rate-limit: cap pending approvals per identity.
            if (self.approval_max_pending_per_identity > 0) {
                if (self.approvalCountPendingForIdentityLocked(identity) >= self.approval_max_pending_per_identity) {
                    return error.TooManyPendingApprovals;
                }
            }

            var rnd: [16]u8 = undefined;
            compat.randomBytes(&rnd);
            const token = try std.fmt.allocPrint(self.allocator, "apr-{d}-{f}", .{
                compat.milliTimestamp(),
                compat.fmtSliceHexLower(&rnd),
            });
            errdefer self.allocator.free(token);
            const now = compat.milliTimestamp();
            const expires_ms = now + self.approval_ttl_ms;
            const owned_method = try self.allocator.dupe(u8, method);
            errdefer self.allocator.free(owned_method);
            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            const owned_identity = try self.allocator.dupe(u8, identity);
            errdefer self.allocator.free(owned_identity);
            const owned_command_id = try self.allocator.dupe(u8, command_id orelse "");
            errdefer self.allocator.free(owned_command_id);
            const owned_decided_by = try self.allocator.dupe(u8, "");
            errdefer self.allocator.free(owned_decided_by);
            // Allocate the caller's result before publishing the map entry. If
            // this allocation failed after insertion, errdefer would otherwise
            // free the map's newly owned key and leave a dangling credential.
            const result_token = try allocator.dupe(u8, token);
            errdefer allocator.free(result_token);
            const entry = ApprovalEntry{
                .method = owned_method,
                .path = owned_path,
                .identity = owned_identity,
                .command_id = owned_command_id,
                .status = .pending,
                .created_ms = now,
                .expires_ms = expires_ms,
                .decided_ms = 0,
                .decided_by = owned_decided_by,
            };
            try self.approvals.putNoClobber(token, entry);
            break :blk ApprovalCreateResult{
                .token = result_token,
                .expires_ms = expires_ms,
            };
        };
        // Persist outside the mutex.
        self.persistApprovals();
        return result;
    }

    pub fn approvalRespond(self: *GatewayState, token: []const u8, decision: ApprovalDecision, actor: []const u8) bool {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const success = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk false;
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            if (entry.status != .pending) break :blk false;
            const decided_by = self.allocator.dupe(u8, actor) catch break :blk false;
            self.allocator.free(entry.decided_by);
            entry.status = if (decision == .approve) .approved else .denied;
            entry.decided_ms = compat.milliTimestamp();
            entry.decided_by = decided_by;
            break :blk true;
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        if (success) self.persistApprovals();
        return success;
    }

    pub fn approvalValidate(self: *GatewayState, token: []const u8, method: []const u8, path: []const u8, identity: ?[]const u8) ApprovalValidation {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const result = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk ApprovalValidation.missing;
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            // The configured policy route is a regex, but an issued approval
            // is a bearer credential for one concrete request scope. Treating
            // its stored path as another regex let metacharacters broaden the
            // approval, and methodMatches made a caller-supplied `*` universal.
            if (!std.ascii.eqlIgnoreCase(entry.method, method)) break :blk ApprovalValidation.invalid;
            if (!std.mem.eql(u8, entry.path, path)) break :blk ApprovalValidation.invalid;
            if (entry.identity.len > 0) {
                const request_identity = identity orelse break :blk ApprovalValidation.invalid;
                if (!std.mem.eql(u8, entry.identity, request_identity)) break :blk ApprovalValidation.invalid;
            }
            // TTL applies to the approval token, not merely to how long a
            // reviewer has to decide. Previously an approved persisted token
            // remained reusable forever because only pending entries expired.
            if (compat.milliTimestamp() >= entry.expires_ms and entry.status != .escalated) break :blk ApprovalValidation.invalid;
            break :blk switch (entry.status) {
                .pending => ApprovalValidation.pending,
                .approved => ApprovalValidation.approved,
                .denied => ApprovalValidation.denied,
                .escalated => ApprovalValidation.escalated,
            };
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        return result;
    }

    pub fn approvalSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const json = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk @as(?[]const u8, null);
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            const command_id: ?[]const u8 = if (entry.command_id.len > 0) entry.command_id else null;
            const decided_by: ?[]const u8 = if (entry.decided_by.len > 0) entry.decided_by else null;
            break :blk compat.stringifyAlloc(allocator, .{
                .approval_token = token,
                .status = @tagName(entry.status),
                .method = entry.method,
                .path = entry.path,
                .identity = entry.identity,
                .command_id = command_id,
                .created_ms = entry.created_ms,
                .expires_ms = entry.expires_ms,
                .decided_ms = entry.decided_ms,
                .decided_by = decided_by,
            }, .{}) catch null;
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        return json;
    }

    /// Returns true if the entry was JUST escalated (status transitioned from pending).
    /// Must be called with approval_mutex held.
    pub fn approvalEscalateIfExpiredLocked(entry: *ApprovalEntry) bool {
        if (entry.status != .pending) return false;
        const now = compat.milliTimestamp();
        if (now >= entry.expires_ms) {
            entry.status = .escalated;
            entry.decided_ms = now;
            return true;
        }
        return false;
    }

    /// Count pending approvals for a given identity. Must be called with approval_mutex held.
    pub fn approvalCountPendingForIdentityLocked(self: *GatewayState, identity: []const u8) u32 {
        var count: u32 = 0;
        var it = self.approvals.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.status == .pending and std.mem.eql(u8, e.identity, identity)) {
                count += 1;
            }
        }
        return count;
    }

    /// Build a JSON payload for the escalation webhook. Must be called with approval_mutex held.
    /// Returns an allocator-owned slice or null on OOM.
    pub fn buildApprovalWebhookPayloadLocked(self: *GatewayState, token: []const u8, entry: *const ApprovalEntry) ?[]u8 {
        const command_id: ?[]const u8 = if (entry.command_id.len > 0) entry.command_id else null;
        return compat.stringifyAlloc(self.allocator, .{
            .event = "escalated",
            .approval_token = token,
            .method = entry.method,
            .path = entry.path,
            .identity = entry.identity,
            .command_id = command_id,
            .created_ms = entry.created_ms,
            .expires_ms = entry.expires_ms,
        }, .{}) catch null;
    }

    /// Snapshot all approval entries into a slice suitable for persistence.
    /// Must be called with approval_mutex held. Caller frees via http.approval_store.freeLoaded.
    pub fn approvalSnapshotEntriesLocked(self: *GatewayState, allocator: std.mem.Allocator) ![]http.approval_store.StoredApproval {
        var out = try allocator.alloc(http.approval_store.StoredApproval, self.approvals.count());
        var i: usize = 0;
        errdefer {
            // Match `approval_store.freeEntry`'s disposition even on this
            // allocation-failure path: the partially built snapshot already
            // holds real approval tokens.
            for (out[0..i]) |e| {
                secrets.secureZeroAndFree(allocator, @constCast(e.token));
                secrets.secureZeroAndFree(allocator, @constCast(e.identity));
                secrets.secureZeroAndFree(allocator, @constCast(e.decided_by));
                allocator.free(e.method);
                allocator.free(e.path);
                allocator.free(e.command_id);
                allocator.free(e.status);
            }
            allocator.free(out);
        }
        var it = self.approvals.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            out[i] = .{
                .token = try allocator.dupe(u8, kv.key_ptr.*),
                .method = try allocator.dupe(u8, e.method),
                .path = try allocator.dupe(u8, e.path),
                .identity = try allocator.dupe(u8, e.identity),
                .command_id = try allocator.dupe(u8, e.command_id),
                .status = try allocator.dupe(u8, @tagName(e.status)),
                .created_ms = e.created_ms,
                .expires_ms = e.expires_ms,
                .decided_ms = e.decided_ms,
                .decided_by = try allocator.dupe(u8, e.decided_by),
                .escalation_fired = e.escalation_fired,
            };
            i += 1;
        }
        return out[0..i];
    }

    /// Persist all approvals to disk (no-op when store path is unconfigured).
    /// Write the approval store to disk.
    ///
    /// Two orderings matter here, and a unique temp filename gives neither:
    ///
    ///  1. Only one persist may be in flight at a time. Concurrent writers
    ///     otherwise race on the same temp path, where one can unlink the
    ///     other's still-open file and fail its rename.
    ///  2. The durable file must end up holding the NEWEST state. Snapshotting
    ///     before serializing writes lets a delayed older snapshot land after a
    ///     newer one and resurrect stale approvals.
    ///
    /// `approval_persist_mutex` is therefore acquired FIRST and held across both
    /// the snapshot and the write, so a caller that waits for it snapshots the
    /// state as of when it won the lock rather than when it was called.
    pub fn persistApprovals(self: *GatewayState) void {
        if (self.approval_store_path.len == 0) return;

        self.approval_persist_mutex.lock();
        defer self.approval_persist_mutex.unlock();

        const snapshot = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            break :blk self.approvalSnapshotEntriesLocked(self.allocator) catch return;
        };
        defer http.approval_store.freeLoaded(self.allocator, snapshot);
        http.approval_store.persist(self.allocator, self.approval_store_path, snapshot) catch |err| {
            self.logger.warn(null, "approval store persist failed: {}", .{err});
        };
    }

    pub fn circuitTryAcquirePermit(self: *GatewayState) ?http.circuit_breaker.Permit {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.tryAcquirePermit();
    }

    pub fn circuitRecordFailurePermit(self: *GatewayState, permit: http.circuit_breaker.Permit) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordFailurePermit(permit);
    }

    pub fn circuitRecordSuccessPermit(self: *GatewayState, permit: http.circuit_breaker.Permit) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordSuccessPermit(permit);
    }

    pub fn circuitReleasePermit(self: *GatewayState, permit: http.circuit_breaker.Permit) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.releasePermit(permit);
    }

    pub fn circuitStateName(self: *GatewayState) []const u8 {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.stateName();
    }

    /// HOT PATH: taken once per completed response (every request).
    /// Priority candidate for removal — see docs/CONCURRENCY.md §2.
    pub fn metricsRecord(self: *GatewayState, status: u16) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordRequest(status);
    }

    pub fn metricsRecordLatencyMs(self: *GatewayState, latency_ms: i64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordLatencyMs(latency_ms);
    }

    pub fn metricsRecordQueueRejection(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQueueRejection();
    }

    pub fn metricsRecordAccept(self: *GatewayState, shard_id: u16) void {
        self.metrics.recordAccept(shard_id);
    }

    pub fn metricsRecordAcceptError(self: *GatewayState, shard_id: u16, reason: http.metrics.AcceptErrorReason) void {
        self.metrics.recordAcceptError(shard_id, reason);
    }

    pub fn metricsRecordAcceptBatch(self: *GatewayState, shard_id: u16, batch_size: u32) void {
        self.metrics.recordAcceptBatch(shard_id, batch_size);
    }

    pub fn metricsRecordAcceptFairnessYield(self: *GatewayState, shard_id: u16) void {
        self.metrics.recordAcceptFairnessYield(shard_id);
    }

    pub fn metricsSetListenerShards(self: *GatewayState, count: u16) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setListenerShards(count);
    }

    pub fn metricsRecordMuxFrameError(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordMuxFrameError();
    }

    pub fn metricsRecordErrorCode(self: *GatewayState, code: []const u8) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordErrorCode(code);
    }

    pub fn metricsRecordEarlyDataRequest(self: *GatewayState, protocol: http.metrics.HttpProtocol, source: http.metrics.EarlyDataSource) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordHttpEarlyDataRequest(protocol, source);
    }

    pub fn metricsRecordForwardAuth(self: *GatewayState, protocol: http.metrics.HttpProtocol, outcome: http.metrics.ForwardAuthOutcome) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordForwardAuth(protocol, outcome);
    }

    pub fn metricsRecordWebSocketUpgrade(self: *GatewayState, outcome: http.metrics.WebSocketUpgradeOutcome) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordWebSocketUpgrade(outcome);
    }

    pub fn metricsRecordWebSocketTunnelClosed(self: *GatewayState, stats: http.tunnel.Stats) void {
        const reason = std.meta.stringToEnum(http.metrics.WebSocketCloseReason, @tagName(stats.close_reason)) orelse .upstream_error;
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordWebSocketTunnelClosed(reason, stats.client_to_upstream_bytes, stats.upstream_to_client_bytes, stats.duration_ms);
    }

    pub fn metricsRecordResponseStreamAdmission(self: *GatewayState, outcome: http.response_stream_lifecycle.AdmissionOutcome) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordResponseStreamAdmission(outcome);
    }

    pub fn metricsRecordResponseStreamClosed(self: *GatewayState, reason: http.response_stream_lifecycle.CloseReason, duration_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordResponseStreamClosed(reason, duration_ms);
    }

    pub fn metricsRecordEarlyDataDecision(self: *GatewayState, protocol: http.metrics.HttpProtocol, decision: http.metrics.EarlyDataDecision) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordHttpEarlyDataDecision(protocol, decision);
    }

    pub fn metricsRecordEarlyDataUpstream425(self: *GatewayState, action: http.metrics.EarlyDataUpstream425Action) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordHttpEarlyDataUpstream425(action);
    }

    pub fn metricsRecordEarlyDataRetry(self: *GatewayState, result: http.metrics.EarlyDataRetryResult) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordHttpEarlyDataRetry(result);
    }

    pub fn metricsRecordHttp3EarlyDataCompat(self: *GatewayState, decision: http.metrics.H3EarlyDataCompatDecision) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordHttp3EarlyDataCompat(decision);
    }

    /// #523: the QUIC/H3 server's authoritative 0-RTT accept/reject decision.
    pub fn metricsRecordQuicEarlyDataDecision(self: *GatewayState, decision: http.metrics.QuicEarlyDataDecision) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQuicEarlyDataDecision(decision);
    }

    /// #523: a single 0-RTT packet's authentication/admission outcome.
    pub fn metricsRecordQuicZeroRttPacket(self: *GatewayState, outcome: http.metrics.QuicZeroRttPacketOutcome) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQuicZeroRttPacket(outcome);
    }

    pub fn metricsRecordQuicTransportDelta(self: *GatewayState, delta: http.metrics.QuicTransportDelta) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQuicTransportDelta(delta);
    }

    pub fn metricsSetQuicConnectionsActive(self: *GatewayState, active: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setQuicConnectionsActive(active);
    }

    pub fn metricsRecordQuicHandshakeFailure(self: *GatewayState, stage: http.metrics.QuicHandshakeFailureStage) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQuicHandshakeFailure(stage);
    }

    pub fn metricsRecordH3RequestLatency(self: *GatewayState, latency_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordH3RequestLatency(latency_ms);
    }

    pub fn metricsRecordReloadAttempt(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordReloadAttempt();
    }

    pub fn metricsRecordReloadSuccess(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordReloadSuccess();
    }

    pub fn metricsRecordReloadFailure(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordReloadFailure();
    }

    pub fn metricsRecordDrain(self: *GatewayState, timed_out: bool, forced_closes: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordDrain(timed_out, forced_closes);
    }

    pub fn metricsRecordProxyStreamingRequest(self: *GatewayState, ttfb_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyStreamingRequest(ttfb_ms);
    }

    pub fn metricsRecordProxyBufferedRequest(self: *GatewayState, buffered_bytes: usize, ttfb_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferedRequest(buffered_bytes, ttfb_ms);
    }

    pub fn metricsReleaseProxyBufferedBytes(self: *GatewayState, buffered_bytes: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.releaseProxyBufferedBytes(buffered_bytes) catch unreachable;
    }

    pub fn metricsRecordProxyClientAbort(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyClientAbort();
    }

    pub fn metricsRecordProxyUpstreamAbort(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyUpstreamAbort();
    }

    pub fn metricsRecordProxyLocalCapacityAbort(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyLocalCapacityAbort();
    }

    pub fn metricsRecordProxyStreamingFallback(self: *GatewayState, reason: http.metrics.ProxyStreamingFallbackReason) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyStreamingFallback(reason);
    }

    pub fn metricsRecordProxyCacheOutcome(self: *GatewayState, outcome: http.metrics.ProxyCacheOutcome) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyCacheOutcome(outcome);
    }

    pub fn metricsRecordProxyBufferReservation(
        self: *GatewayState,
        direction: http.proxy_buffer_account.Direction,
        bytes: usize,
        high_watermark: bool,
        limit_exceeded: bool,
    ) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferReservation(direction, bytes, high_watermark, limit_exceeded);
    }

    pub fn metricsReleaseProxyBufferReservation(self: *GatewayState, direction: http.proxy_buffer_account.Direction, bytes: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.releaseProxyBufferReservation(direction, bytes) catch unreachable;
    }

    pub fn metricsRecordProxyBufferLimitExceeded(
        self: *GatewayState,
        direction: http.proxy_buffer_account.Direction,
        scope: http.proxy_buffer_account.Scope,
    ) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferLimitExceeded(direction, scope);
    }

    /// The process-wide aggregate every proxy body reservation clears. Its hard
    /// limit tracks `proxy_buffer_limits.global_hard_limit` across reloads.
    pub fn proxyBufferGlobalAccount(self: *GatewayState) *http.proxy_buffer_account.Aggregate {
        return &self.proxy_buffer_global_account;
    }

    pub fn proxyBufferObserver(self: *GatewayState) http.proxy_buffer_account.Observer {
        return .{
            .context = self,
            .recordReservationFn = recordProxyBufferReservationObserved,
            .releaseReservationFn = releaseProxyBufferReservationObserved,
            .recordAggregateLimitExceededFn = recordProxyBufferAggregateLimitExceededObserved,
            .recordReadPauseFn = recordProxyBufferReadPauseObserved,
            .recordReadResumeFn = recordProxyBufferReadResumeObserved,
            .recordRetainedBytesFn = recordProxyBufferRetainedObserved,
            .releaseRetainedBytesFn = releaseProxyBufferRetainedObserved,
        };
    }

    fn recordProxyBufferRetainedObserved(context: *anyopaque, direction: http.proxy_buffer_account.Direction, bytes: usize) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferRetained(direction, bytes);
    }

    fn releaseProxyBufferRetainedObserved(context: *anyopaque, direction: http.proxy_buffer_account.Direction, bytes: usize) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.releaseProxyBufferRetained(direction, bytes) catch unreachable;
    }

    fn recordProxyBufferReadPauseObserved(context: *anyopaque, side: http.proxy_buffer_account.Side) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferReadPause(side.label());
    }

    fn recordProxyBufferReadResumeObserved(context: *anyopaque, side: http.proxy_buffer_account.Side) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferReadResume(side.label());
    }

    fn recordProxyBufferAggregateLimitExceededObserved(
        context: *anyopaque,
        direction: http.proxy_buffer_account.Direction,
        scope: http.proxy_buffer_account.Scope,
    ) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metricsRecordProxyBufferLimitExceeded(direction, scope);
    }

    fn recordProxyBufferReservationObserved(
        context: *anyopaque,
        direction: http.proxy_buffer_account.Direction,
        bytes: usize,
        high_watermark: bool,
        limit_exceeded: bool,
    ) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metricsRecordProxyBufferReservation(direction, bytes, high_watermark, limit_exceeded);
    }

    fn releaseProxyBufferReservationObserved(context: *anyopaque, direction: http.proxy_buffer_account.Direction, bytes: usize) void {
        const self: *GatewayState = @ptrCast(@alignCast(context));
        self.metricsReleaseProxyBufferReservation(direction, bytes);
    }

    pub fn metricsSetWorkerPoolStats(self: *GatewayState, active_jobs: usize, queued_jobs: usize, worker_threads: usize, queue_capacity: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setWorkerPoolStats(active_jobs, queued_jobs, worker_threads, queue_capacity);
    }

    pub fn metricsRecordWorkerQueueWaitNs(self: *GatewayState, wait_ns: i64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordWorkerQueueWaitNs(wait_ns);
    }

    /// #256-G: copy the live H3 runtime's transport-state snapshot (packet
    /// counts, DPLPMTUD probe/black-hole counts + effective PLPMTU, ECN
    /// state/counters, requested-vs-effective UDP socket buffer sizes) into
    /// a metrics snapshot just before rendering — the runtime owns these
    /// counters, not `Metrics`, the same reason `overlayUpstreamPoolStats`
    /// exists below. A no-op when HTTP/3 is not enabled (`http3_runtime` is
    /// null), leaving every field at its zero default.
    fn overlayQuicTransportSnapshot(self: *GatewayState, snapshot: *http.metrics.Metrics) void {
        const rt = self.http3_runtime orelse return;
        const rs = rt.snapshot();

        snapshot.quic_packets_sent_total = @intCast(rs.packets_sent);
        snapshot.quic_packets_received_total = @intCast(rs.packets_received);
        snapshot.quic_pmtu_probes_sent_total = @intCast(rs.pmtu_probes_sent);
        snapshot.quic_pmtu_black_holes_total = @intCast(rs.pmtu_black_holes);
        snapshot.quic_effective_plpmtu_bytes_last = @intCast(rs.plpmtu_last_bytes);
        snapshot.quic_effective_plpmtu_bytes_lifetime_min = @intCast(rs.plpmtu_lifetime_min_bytes);
        snapshot.quic_effective_plpmtu_bytes_lifetime_max = @intCast(rs.plpmtu_lifetime_max_bytes);

        snapshot.quic_ecn_enabled = if (rs.ecn_enabled) 1 else 0;
        snapshot.quic_ecn_marked_sent_total = @intCast(rs.ecn_marked_sent);
        snapshot.quic_ecn_paths_validated_total = @intCast(rs.ecn_paths_validated);
        snapshot.quic_ecn_paths_disabled_total = @intCast(rs.ecn_paths_disabled);
        snapshot.quic_ecn_ce_received_total = @intCast(rs.ecn_ce_received);

        snapshot.quic_udp_recv_buffer_requested_bytes = @intCast(rs.udp_buffers.recv.requested_bytes orelse 0);
        snapshot.quic_udp_recv_buffer_effective_bytes = @intCast(rs.udp_buffers.recv.effective_bytes orelse 0);
        snapshot.quic_udp_recv_buffer_granted_bytes = @intCast(rs.udp_buffers.recv.granted_bytes orelse 0);
        snapshot.quic_udp_recv_buffer_status = quicUdpBufferStatusFrom(rs.udp_buffers.recv.status);
        snapshot.quic_udp_send_buffer_requested_bytes = @intCast(rs.udp_buffers.send.requested_bytes orelse 0);
        snapshot.quic_udp_send_buffer_effective_bytes = @intCast(rs.udp_buffers.send.effective_bytes orelse 0);
        snapshot.quic_udp_send_buffer_granted_bytes = @intCast(rs.udp_buffers.send.granted_bytes orelse 0);
        snapshot.quic_udp_send_buffer_status = quicUdpBufferStatusFrom(rs.udp_buffers.send.status);
    }

    /// Copy the live upstream keep-alive pool counters into a metrics snapshot
    /// just before rendering (the pool owns these counters, not `Metrics`).
    fn overlayUpstreamPoolStats(self: *GatewayState, snapshot: *http.metrics.Metrics) void {
        const ps = self.upstream_pool.aggregateStats();
        snapshot.upstream_connections_new = ps.new_total;
        snapshot.upstream_connections_reused = ps.reused_total;
        snapshot.upstream_connections_reused_local = ps.reused_local_total;
        snapshot.upstream_connections_reused_cross_worker = ps.reused_cross_worker_total;
        snapshot.upstream_connections_idle = ps.idle;
        snapshot.upstream_stale_retries = ps.stale_retries_total;
    }

    /// Append per-upstream labelled pool series and the connect-latency
    /// histogram to a Prometheus exposition buffer (#141 Phase 1b). These are
    /// not part of the flat `Metrics` serializer because they are dynamically
    /// keyed by origin.
    fn appendUpstreamPoolPrometheus(self: *GatewayState, out: *std.array_list.Managed(u8)) !void {
        const snaps = try self.upstream_pool.snapshotHosts(self.allocator);
        defer http.upstream_pool.freeHostSnapshots(self.allocator, snaps);
        if (snaps.len > 0) {
            try out.appendSlice(
                \\# HELP tardigrade_upstream_pool_connections_new_total Upstream connections opened per origin (keep-alive pool misses)
                \\# TYPE tardigrade_upstream_pool_connections_new_total counter
                \\# HELP tardigrade_upstream_pool_connections_reused_total Upstream connections served from the pool per origin
                \\# TYPE tardigrade_upstream_pool_connections_reused_total counter
                \\# HELP tardigrade_upstream_pool_connections_reused_local_total Pool reuses where the same worker thread parked and reclaimed the connection
                \\# TYPE tardigrade_upstream_pool_connections_reused_local_total counter
                \\# HELP tardigrade_upstream_pool_connections_reused_cross_worker_total Pool reuses where a different worker thread reclaimed a parked connection (shared-pool reuse)
                \\# TYPE tardigrade_upstream_pool_connections_reused_cross_worker_total counter
                \\# HELP tardigrade_upstream_pool_connections_idle Idle upstream connections held in the pool per origin
                \\# TYPE tardigrade_upstream_pool_connections_idle gauge
                \\# HELP tardigrade_upstream_pool_connections_active In-flight upstream connections per origin
                \\# TYPE tardigrade_upstream_pool_connections_active gauge
                \\# HELP tardigrade_upstream_pool_stale_retries_total Stale-connection retries per origin
                \\# TYPE tardigrade_upstream_pool_stale_retries_total counter
                \\# HELP tardigrade_upstream_pool_stale_retries_zero_byte_total Fresh-connection retries (any method) after a reused connection failed with proof that zero request bytes were sent
                \\# TYPE tardigrade_upstream_pool_stale_retries_zero_byte_total counter
                \\# HELP tardigrade_upstream_pool_stale_retries_idempotent_total Fresh-connection retries of idempotent requests after an ambiguous failure on a reused connection
                \\# TYPE tardigrade_upstream_pool_stale_retries_idempotent_total counter
                \\# HELP tardigrade_upstream_pool_stale_replay_refused_total Non-idempotent requests not replayed after an ambiguous failure on a reused connection
                \\# TYPE tardigrade_upstream_pool_stale_replay_refused_total counter
                \\# HELP tardigrade_upstream_pool_checkout_stale_plaintext_unexpected_total Plaintext idle checkouts rejected because unexpected bytes or peer state were readable
                \\# TYPE tardigrade_upstream_pool_checkout_stale_plaintext_unexpected_total counter
                \\# HELP tardigrade_upstream_pool_checkout_stale_tls_application_plaintext_total TLS idle checkouts rejected because decrypted application data was queued
                \\# TYPE tardigrade_upstream_pool_checkout_stale_tls_application_plaintext_total counter
                \\# HELP tardigrade_upstream_pool_checkout_stale_tls_peer_closed_total TLS idle checkouts rejected because peer close was observed
                \\# TYPE tardigrade_upstream_pool_checkout_stale_tls_peer_closed_total counter
                \\# HELP tardigrade_upstream_pool_checkout_stale_tls_drive_error_total TLS idle checkouts rejected because record draining failed
                \\# TYPE tardigrade_upstream_pool_checkout_stale_tls_drive_error_total counter
                \\# HELP tardigrade_upstream_pool_checkout_stale_tls_drain_budget_total TLS idle checkouts rejected because the bounded drain budget was exhausted
                \\# TYPE tardigrade_upstream_pool_checkout_stale_tls_drain_budget_total counter
                \\# HELP tardigrade_upstream_pool_checkout_quarantined_tls_incomplete_total TLS idle checkouts quarantined because incomplete ciphertext needed later draining
                \\# TYPE tardigrade_upstream_pool_checkout_quarantined_tls_incomplete_total counter
                \\# HELP tardigrade_upstream_pool_release_rejected_lifetime_total Released upstream connections closed because pool lifetime bounds rejected them
                \\# TYPE tardigrade_upstream_pool_release_rejected_lifetime_total counter
                \\# HELP tardigrade_upstream_pool_release_rejected_capacity_total Released upstream connections closed because the idle pool was full
                \\# TYPE tardigrade_upstream_pool_release_rejected_capacity_total counter
                \\# HELP tardigrade_upstream_pool_release_not_reusable_total Released upstream connections closed because HTTP response handling marked them non-reusable
                \\# TYPE tardigrade_upstream_pool_release_not_reusable_total counter
                \\# HELP tardigrade_upstream_pool_at_capacity_total Checkouts rejected fail-fast at the per-origin active cap
                \\# TYPE tardigrade_upstream_pool_at_capacity_total counter
                \\# HELP tardigrade_upstream_pool_reuse_ratio Reuse ratio (reused / (reused + new)) per origin
                \\# TYPE tardigrade_upstream_pool_reuse_ratio gauge
                \\
            );
        }
        for (snaps) |snap| {
            const s = snap.stats;
            const total = s.reused_total + s.new_total;
            const ratio: f64 = if (total == 0) 0 else @as(f64, @floatFromInt(s.reused_total)) / @as(f64, @floatFromInt(total));
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_new_total", snap.host, "{d}", .{s.new_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_reused_total", snap.host, "{d}", .{s.reused_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_reused_local_total", snap.host, "{d}", .{s.reused_local_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_reused_cross_worker_total", snap.host, "{d}", .{s.reused_cross_worker_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_idle", snap.host, "{d}", .{s.idle});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_connections_active", snap.host, "{d}", .{s.active});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_stale_retries_total", snap.host, "{d}", .{s.stale_retries_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_stale_retries_zero_byte_total", snap.host, "{d}", .{s.stale_retries_zero_byte_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_stale_retries_idempotent_total", snap.host, "{d}", .{s.stale_retries_idempotent_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_stale_replay_refused_total", snap.host, "{d}", .{s.stale_replay_refused_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_stale_plaintext_unexpected_total", snap.host, "{d}", .{s.checkout_stale_plaintext_unexpected});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_stale_tls_application_plaintext_total", snap.host, "{d}", .{s.checkout_stale_tls_application_plaintext});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_stale_tls_peer_closed_total", snap.host, "{d}", .{s.checkout_stale_tls_peer_closed});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_stale_tls_drive_error_total", snap.host, "{d}", .{s.checkout_stale_tls_drive_error});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_stale_tls_drain_budget_total", snap.host, "{d}", .{s.checkout_stale_tls_drain_budget});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_checkout_quarantined_tls_incomplete_total", snap.host, "{d}", .{s.checkout_quarantined_tls_incomplete});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_release_rejected_lifetime_total", snap.host, "{d}", .{s.release_rejected_lifetime});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_release_rejected_capacity_total", snap.host, "{d}", .{s.release_rejected_capacity});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_release_not_reusable_total", snap.host, "{d}", .{s.release_not_reusable});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_at_capacity_total", snap.host, "{d}", .{s.at_capacity_total});
            try appendUpstreamLabelMetric(out, "tardigrade_upstream_pool_reuse_ratio", snap.host, "{d:.4}", .{ratio});
        }

        // Per-origin HTTP/1 proxy buffer accounting (#140). Rendered from its
        // own map rather than the host stats above: an origin gets a buffer
        // account whenever it is proxied to, including with connection pooling
        // disabled, so the two memberships differ. Cardinality is one series
        // per configured origin per direction — the same bound as the h1
        // connection series and the h2 pool's buffer series.
        const origin_buffers = try self.upstream_pool.snapshotOriginBuffers(self.allocator);
        defer http.upstream_pool.freeOriginBufferSnapshots(self.allocator, origin_buffers);
        if (origin_buffers.len > 0) {
            try out.appendSlice(
                \\# HELP tardigrade_upstream_pool_buffered_bytes Bytes currently held against this HTTP/1 origin's proxy buffer account, by direction
                \\# TYPE tardigrade_upstream_pool_buffered_bytes gauge
                \\# HELP tardigrade_upstream_pool_buffer_limit_exceeded_total Origin-scope proxy buffer hard-limit refusals per HTTP/1 origin, by direction
                \\# TYPE tardigrade_upstream_pool_buffer_limit_exceeded_total counter
                \\
            );
            for (origin_buffers) |snap| {
                inline for (.{
                    http.proxy_buffer_account.Direction.downstream_to_upstream,
                    http.proxy_buffer_account.Direction.upstream_to_downstream,
                }) |direction| {
                    try appendUpstreamDirectionLabelMetric(out, "tardigrade_upstream_pool_buffered_bytes", snap.origin, direction, "{d}", .{snap.bufferedBytes(direction)});
                    try appendUpstreamDirectionLabelMetric(out, "tardigrade_upstream_pool_buffer_limit_exceeded_total", snap.origin, direction, "{d}", .{snap.bufferLimitExceeded(direction)});
                }
            }
        }

        const lat = self.upstream_pool.connectLatencySnapshot();
        try out.appendSlice(
            \\# HELP tardigrade_upstream_connect_latency_ms Upstream TCP connect latency histogram in milliseconds
            \\# TYPE tardigrade_upstream_connect_latency_ms histogram
            \\
        );
        var cumulative: u64 = 0;
        inline for (http.upstream_pool.connect_latency_bounds_ms, 0..) |bound, i| {
            cumulative += lat.buckets[i];
            try out.print("tardigrade_upstream_connect_latency_ms_bucket{{le=\"{d}\"}} {d}\n", .{ bound, cumulative });
        }
        cumulative += lat.buckets[http.upstream_pool.connect_latency_bounds_ms.len];
        try out.print("tardigrade_upstream_connect_latency_ms_bucket{{le=\"+Inf\"}} {d}\n", .{cumulative});
        try out.print("tardigrade_upstream_connect_latency_ms_sum {d}\n", .{lat.sum_ms});
        try out.print("tardigrade_upstream_connect_latency_ms_count {d}\n", .{lat.count});

        const proto = self.upstream_pool.protocolCounts();
        try out.appendSlice(
            \\# HELP tardigrade_upstream_protocol_requests_total Upstream requests by negotiated application protocol
            \\# TYPE tardigrade_upstream_protocol_requests_total counter
            \\
        );
        try out.print("tardigrade_upstream_protocol_requests_total{{protocol=\"h1\"}} {d}\n", .{proto.h1});
        try out.print("tardigrade_upstream_protocol_requests_total{{protocol=\"h2\"}} {d}\n", .{proto.h2});

        try out.appendSlice(
            \\# HELP tardigrade_upstream_h2_streaming_upload_fallback_total Streaming upload requests that requested h2/h2c upstreams but fell back to h1 because the h2 pool was unavailable
            \\# TYPE tardigrade_upstream_h2_streaming_upload_fallback_total counter
            \\
        );
        try out.print("tardigrade_upstream_h2_streaming_upload_fallback_total {d}\n", .{self.upstream_pool.h2StreamingUploadFallbacks()});

        const lock_stats = self.upstream_pool.lockContentionStats();
        try out.appendSlice(
            \\# HELP tardigrade_upstream_pool_lock_wait_ns_total Nanoseconds spent waiting to acquire the shared upstream-pool mutex
            \\# TYPE tardigrade_upstream_pool_lock_wait_ns_total counter
            \\# HELP tardigrade_upstream_pool_lock_acquires_total Shared upstream-pool mutex acquisitions
            \\# TYPE tardigrade_upstream_pool_lock_acquires_total counter
            \\
        );
        try out.print("tardigrade_upstream_pool_lock_wait_ns_total {d}\n", .{lock_stats.wait_ns_total});
        try out.print("tardigrade_upstream_pool_lock_acquires_total {d}\n", .{lock_stats.acquires_total});

        // Completed-exchange latency by negotiated protocol (#145 — the
        // "upstream p99 by protocol" acceptance row).
        const req_lat = self.upstream_pool.requestLatencySnapshot();
        try out.appendSlice(
            \\# HELP tardigrade_upstream_request_latency_ms Completed upstream exchange latency by negotiated protocol in milliseconds
            \\# TYPE tardigrade_upstream_request_latency_ms histogram
            \\
        );
        inline for (.{ "h1", "h2" }) |label| {
            const hist = if (comptime std.mem.eql(u8, label, "h2")) req_lat.h2 else req_lat.h1;
            var req_cumulative: u64 = 0;
            inline for (http.upstream_pool.request_latency_bounds_ms, 0..) |bound, i| {
                req_cumulative += hist.buckets[i];
                try out.print("tardigrade_upstream_request_latency_ms_bucket{{protocol=\"{s}\",le=\"{d}\"}} {d}\n", .{ label, bound, req_cumulative });
            }
            req_cumulative += hist.buckets[http.upstream_pool.request_latency_bounds_ms.len];
            try out.print("tardigrade_upstream_request_latency_ms_bucket{{protocol=\"{s}\",le=\"+Inf\"}} {d}\n", .{ label, req_cumulative });
            try out.print("tardigrade_upstream_request_latency_ms_sum{{protocol=\"{s}\"}} {d}\n", .{ label, hist.sum_ms });
            try out.print("tardigrade_upstream_request_latency_ms_count{{protocol=\"{s}\"}} {d}\n", .{ label, hist.count });
        }

        const h2 = self.h2_pool.snapshot();
        try out.appendSlice(
            \\# HELP tardigrade_upstream_h2_connections_active Open multiplexing HTTP/2 upstream connections
            \\# TYPE tardigrade_upstream_h2_connections_active gauge
            \\# HELP tardigrade_upstream_h2_streams_active In-flight HTTP/2 upstream streams across all connections
            \\# TYPE tardigrade_upstream_h2_streams_active gauge
            \\# HELP tardigrade_upstream_h2_stream_resets_total RST_STREAM frames received on HTTP/2 upstream connections
            \\# TYPE tardigrade_upstream_h2_stream_resets_total counter
            \\# HELP tardigrade_upstream_h2_goaway_total GOAWAY frames received on HTTP/2 upstream connections
            \\# TYPE tardigrade_upstream_h2_goaway_total counter
            \\
        );
        try out.print("tardigrade_upstream_h2_connections_active {d}\n", .{h2.connections_active});
        try out.print("tardigrade_upstream_h2_streams_active {d}\n", .{h2.streams_active});
        try out.print("tardigrade_upstream_h2_stream_resets_total {d}\n", .{h2.stream_resets_total});
        try out.print("tardigrade_upstream_h2_goaway_total {d}\n", .{h2.goaway_total});

        // Per-origin h2 series (#238), named with a `_pool_` prefix (like the
        // labelled h1 `tardigrade_upstream_pool_*` series) so a label-blind
        // sum() over the labelled family never double-counts the bare globals
        // above. The label value is the pool key (`h2:host:port`), matching
        // the scheme-prefixed h1 label convention.
        const h2_origins = try self.h2_pool.snapshotOrigins(self.allocator);
        defer http.upstream_h2.freeH2OriginSnapshots(self.allocator, h2_origins);
        if (h2_origins.len > 0) {
            try out.appendSlice(
                \\# HELP tardigrade_upstream_h2_pool_connections_active Open multiplexing HTTP/2 upstream connections per origin
                \\# TYPE tardigrade_upstream_h2_pool_connections_active gauge
                \\# HELP tardigrade_upstream_h2_pool_streams_active In-flight HTTP/2 upstream streams per origin
                \\# TYPE tardigrade_upstream_h2_pool_streams_active gauge
                \\# HELP tardigrade_upstream_h2_pool_stream_resets_total RST_STREAM frames received per origin
                \\# TYPE tardigrade_upstream_h2_pool_stream_resets_total counter
                \\# HELP tardigrade_upstream_h2_pool_goaway_total GOAWAY frames received per origin
                \\# TYPE tardigrade_upstream_h2_pool_goaway_total counter
                \\# HELP tardigrade_upstream_h2_pool_buffered_bytes Bytes currently held against this origin's proxy buffer account, by direction
                \\# TYPE tardigrade_upstream_h2_pool_buffered_bytes gauge
                \\# HELP tardigrade_upstream_h2_pool_buffer_limit_exceeded_total Origin-scope proxy buffer hard-limit refusals per origin, by direction
                \\# TYPE tardigrade_upstream_h2_pool_buffer_limit_exceeded_total counter
                \\
            );
            for (h2_origins) |snap| {
                try appendUpstreamLabelMetric(out, "tardigrade_upstream_h2_pool_connections_active", snap.origin, "{d}", .{snap.connections_active});
                try appendUpstreamLabelMetric(out, "tardigrade_upstream_h2_pool_streams_active", snap.origin, "{d}", .{snap.streams_active});
                try appendUpstreamLabelMetric(out, "tardigrade_upstream_h2_pool_stream_resets_total", snap.origin, "{d}", .{snap.stream_resets_total});
                try appendUpstreamLabelMetric(out, "tardigrade_upstream_h2_pool_goaway_total", snap.origin, "{d}", .{snap.goaway_total});
                inline for (.{
                    http.proxy_buffer_account.Direction.downstream_to_upstream,
                    http.proxy_buffer_account.Direction.upstream_to_downstream,
                }) |direction| {
                    try appendUpstreamDirectionLabelMetric(out, "tardigrade_upstream_h2_pool_buffered_bytes", snap.origin, direction, "{d}", .{snap.bufferedBytes(direction)});
                    try appendUpstreamDirectionLabelMetric(out, "tardigrade_upstream_h2_pool_buffer_limit_exceeded_total", snap.origin, direction, "{d}", .{snap.bufferLimitExceeded(direction)});
                }
            }
        }
    }

    pub fn metricsToJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        const mux_snapshot = try self.muxMetricsSnapshot(allocator);
        defer deinitMuxMetricsSnapshot(allocator, mux_snapshot.device_counts);

        self.metrics_mutex.lock();
        var metrics_snapshot = self.metrics;
        self.metrics_mutex.unlock();
        self.overlayUpstreamPoolStats(&metrics_snapshot);

        // Delegate the counter list to the canonical serializer so the served
        // JSON can never drift from `Metrics.toJson` (mirrors how
        // `metricsToPrometheus` delegates to `Metrics.toPrometheus`). The only
        // field unique to the served endpoint — `mux_subscriptions_by_device` —
        // is appended just before the closing brace.
        const base = try metrics_snapshot.toJson(allocator);
        defer allocator.free(base);
        std.debug.assert(base.len > 0 and base[base.len - 1] == '}');

        var device_json = std.array_list.Managed(u8).init(allocator);
        errdefer device_json.deinit();
        try device_json.append('{');
        for (mux_snapshot.device_counts, 0..) |entry, idx| {
            if (idx > 0) try device_json.append(',');
            try device_json.print("{f}:{d}", .{ std.json.fmt(entry.device_id, .{}), entry.count });
        }
        try device_json.append('}');
        const device_json_owned = try device_json.toOwnedSlice();
        defer allocator.free(device_json_owned);

        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        try out.appendSlice(base[0 .. base.len - 1]); // canonical body, minus the closing '}'
        try out.print(",\"mux_subscriptions_by_device\":{s}}}", .{device_json_owned});
        return out.toOwnedSlice();
    }

    /// Live WebSocket reactor load (#818), read from the reactor's own
    /// atomics at scrape time.
    fn overlayWebSocketReactorStats(self: *GatewayState, metrics_snapshot: *http.metrics.Metrics) void {
        const slots_high_water = self.websocket_tunnels_high_water.load(.monotonic);
        const reactor = self.tunnel_reactor orelse {
            metrics_snapshot.setWebSocketReactorStats(.{ .slots_high_water = slots_high_water });
            return;
        };
        const snapshot = reactor.snapshot();
        metrics_snapshot.setWebSocketReactorStats(.{
            .slots_high_water = slots_high_water,
            .threads = snapshot.threads,
            .tunnels = snapshot.tunnels,
            .max_thread_tunnels = snapshot.max_shard_tunnels,
            .handoffs_total = snapshot.handoffs_total,
            .wakeups_total = snapshot.wakeups_total,
            .rejected_total = snapshot.rejected_total,
            .queue_depth = snapshot.queue_depth,
            .queue_high_water = snapshot.queue_high_water,
        });
    }

    /// Bounded, secret-free ACME renewal status (#835 A5's observability
    /// criterion: next attempt, expiry, failure class per managed group),
    /// read from the live worker's own mutex-guarded snapshot at scrape
    /// time -- the renewal thread itself never touches `GatewayState`.
    /// Labeled by `acme.groups.groupId`, never a hostname or CA URL.
    fn overlayAcmeRenewalStatus(self: *GatewayState, metrics_snapshot: *http.metrics.Metrics) void {
        comptime {
            // `http/metrics.zig` cannot import `acme/groups.zig` directly (it
            // is reachable from module roots that do not include `acme/`),
            // so its bounds are a duplicated local constant; catch any drift
            // here instead of silently truncating a scrape.
            if (http.metrics.max_acme_renewal_groups != http.acme.groups.max_groups) @compileError("http.metrics.max_acme_renewal_groups must match acme.groups.max_groups");
            if (http.metrics.acme_renewal_group_id_len != http.acme.groups.group_id_len) @compileError("http.metrics.acme_renewal_group_id_len must match acme.groups.group_id_len");
        }
        const worker = self.acme_renewal_worker orelse return;
        const n = @min(worker.group_list.len, http.metrics.max_acme_renewal_groups);
        var statuses: [http.metrics.max_acme_renewal_groups]acme_renewal.GroupStatus = undefined;
        worker.snapshotStatus(statuses[0..n]);

        var rendered: [http.metrics.max_acme_renewal_groups]http.metrics.AcmeRenewalGroupStatus = undefined;
        for (worker.group_list.slice()[0..n], 0..) |group, i| {
            var id_buf: [http.acme.groups.group_id_len]u8 = undefined;
            _ = http.acme.groups.groupId(&id_buf, group.slice());
            rendered[i] = .{
                .group_id = id_buf,
                .not_after = statuses[i].not_after,
                .next_attempt_at = statuses[i].next_attempt_at,
                .consecutive_failures = statuses[i].consecutive_failures,
                .last_failure_class = if (statuses[i].last_failure_class) |c| @as(u8, @intFromEnum(c)) else null,
                .activation_pending = statuses[i].activation_pending,
            };
        }
        metrics_snapshot.setAcmeRenewalStatus(rendered[0..n]);
    }

    pub fn metricsToPrometheus(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        const mux_snapshot = try self.muxMetricsSnapshot(allocator);
        defer deinitMuxMetricsSnapshot(allocator, mux_snapshot.device_counts);

        self.metrics_mutex.lock();
        var metrics_snapshot = self.metrics;
        self.metrics_mutex.unlock();
        self.overlayUpstreamPoolStats(&metrics_snapshot);
        self.overlayQuicTransportSnapshot(&metrics_snapshot);
        self.overlayWebSocketReactorStats(&metrics_snapshot);
        self.overlayAcmeRenewalStatus(&metrics_snapshot);

        const base = try metrics_snapshot.toPrometheus(allocator);
        defer allocator.free(base);

        var combined = std.array_list.Managed(u8).init(allocator);
        errdefer combined.deinit();
        try combined.appendSlice(base);
        self.runtime_mutex.lock();
        const proxy_buffer_limits = self.proxy_buffer_limits;
        const tls_buffer_limits = self.tls_buffer_limits;
        const http3_advertisement_state = self.http3_advertisement_state;
        self.runtime_mutex.unlock();
        try appendProxyBufferConfigPrometheus(&combined, proxy_buffer_limits);
        try self.appendProxyBufferAggregatePrometheus(&combined);
        try appendTlsBufferConfigPrometheus(&combined, tls_buffer_limits);
        try combined.appendSlice(
            \\# HELP tardigrade_http3_effective_state HTTP/3 effective listener and advertisement state
            \\# TYPE tardigrade_http3_effective_state gauge
            \\
        );
        try combined.print("tardigrade_http3_effective_state{{state=\"{s}\"}} 1\n", .{@tagName(http3_advertisement_state)});
        if (mux_snapshot.device_counts.len > 0) {
            try combined.appendSlice(
                \\# HELP tardigrade_mux_device_channels Current active mux channels by device
                \\# TYPE tardigrade_mux_device_channels gauge
                \\
            );
            for (mux_snapshot.device_counts) |entry| {
                try combined.appendSlice("tardigrade_mux_device_channels{device_id=\"");
                try appendPrometheusLabelValue(&combined, entry.device_id);
                try combined.print("\"}} {d}\n", .{entry.count});
            }
        }
        try self.appendUpstreamPoolPrometheus(&combined);
        return combined.toOwnedSlice();
    }

    /// The bytes the global hard limit is actually checked against, read
    /// straight from the account that does the checking.
    ///
    /// This is deliberately a separate series from
    /// `tardigrade_buffered_bytes_current{scope="global"}`: that gauge is a
    /// roll-up of every proxy-owned buffer (bounded buffered responses, HTTP/1
    /// relay buffers, request-side buffers, HTTP/2 queues), whereas
    /// `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` is currently enforced
    /// only against HTTP/2 streaming response queues. Comparing the roll-up
    /// with the limit would mislead under mixed traffic; this series is the one
    /// an operator can put next to the configured limit.
    fn appendProxyBufferAggregatePrometheus(self: *GatewayState, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_proxy_buffer_aggregate_bytes_current Bytes reserved at the aggregate scope the configured hard limit is enforced against (HTTP/2 stream queues, HTTP/1 relay buffers, and request-direction upload buffers)
            \\# TYPE tardigrade_proxy_buffer_aggregate_bytes_current gauge
            \\
        );
        inline for (.{
            .{ "downstream_to_upstream", http.proxy_buffer_account.Direction.downstream_to_upstream },
            .{ "upstream_to_downstream", http.proxy_buffer_account.Direction.upstream_to_downstream },
        }) |entry| {
            try out.print(
                "tardigrade_proxy_buffer_aggregate_bytes_current{{direction=\"{s}\",scope=\"global\"}} {d}\n",
                .{ entry[0], self.proxy_buffer_global_account.currentBytes(entry[1]) },
            );
        }
    }

    fn appendProxyBufferConfigPrometheus(out: *std.array_list.Managed(u8), limits: http.proxy_buffer_account.Limits) !void {
        try out.appendSlice(
            \\# HELP tardigrade_buffer_config_limit_bytes Configured proxy buffer accounting limits in bytes
            \\# TYPE tardigrade_buffer_config_limit_bytes gauge
            \\
        );
        inline for (.{ "downstream_to_upstream", "upstream_to_downstream" }) |direction| {
            try out.print("tardigrade_buffer_config_limit_bytes{{direction=\"{s}\",scope=\"stream\",limit=\"low\"}} {d}\n", .{ direction, limits.per_stream_low_watermark });
            try out.print("tardigrade_buffer_config_limit_bytes{{direction=\"{s}\",scope=\"stream\",limit=\"high\"}} {d}\n", .{ direction, limits.per_stream_high_watermark });
            try out.print("tardigrade_buffer_config_limit_bytes{{direction=\"{s}\",scope=\"stream\",limit=\"hard\"}} {d}\n", .{ direction, limits.per_stream_hard_limit });
            try out.print("tardigrade_buffer_config_limit_bytes{{direction=\"{s}\",scope=\"origin\",limit=\"hard\"}} {d}\n", .{ direction, limits.per_origin_hard_limit });
            try out.print("tardigrade_buffer_config_limit_bytes{{direction=\"{s}\",scope=\"global\",limit=\"hard\"}} {d}\n", .{ direction, limits.global_hard_limit });
        }
    }

    fn appendTlsBufferConfigPrometheus(out: *std.array_list.Managed(u8), limits: @import("tls_core").encrypted_stream.BufferLimits) !void {
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffer_config_limit_bytes Configured native TLS buffer limits in bytes
            \\# TYPE tardigrade_tls_buffer_config_limit_bytes gauge
            \\
        );
        inline for (.{
            .{ "inbound_ciphertext", limits.inbound_ciphertext },
            .{ "inbound_plaintext", limits.inbound_plaintext },
            .{ "outbound_ciphertext", limits.outbound_ciphertext },
            .{ "handshake", limits.handshake },
        }) |entry| {
            try out.print("tardigrade_tls_buffer_config_limit_bytes{{queue=\"{s}\",limit=\"low\"}} {d}\n", .{ entry[0], entry[1].low });
            try out.print("tardigrade_tls_buffer_config_limit_bytes{{queue=\"{s}\",limit=\"high\"}} {d}\n", .{ entry[0], entry[1].high });
            try out.print("tardigrade_tls_buffer_config_limit_bytes{{queue=\"{s}\",limit=\"hard\"}} {d}\n", .{ entry[0], entry[1].hard });
        }
    }

    /// HOT PATH (proxy mode): taken once per proxied request for LB selection.
    /// See docs/CONCURRENCY.md §6 — upstream_rr_index is a candidate for atomic CAS.
    pub fn nextUpstreamBaseUrl(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, hash_key: []const u8) []const u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();
        if (pool.primary_urls.len == 0) {
            if (self.selectDiscoveredLocked(cfg, client_ip, hash_key, null, now_ms)) |picked| return picked.base_url;
        }
        return self.nextUpstreamBaseUrlLocked(cfg, pool, client_ip, hash_key, now_ms);
    }

    fn discoveredHealthy(ctx: DiscoveredHealthCtx, url: []const u8) bool {
        return ctx.state.isUpstreamHealthyLocked(ctx.cfg, url, ctx.now_ms);
    }

    const DiscoveredHealthCtx = struct {
        state: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        now_ms: u64,
    };

    /// Select from the DNS-discovered live set (static pool has no primaries).
    /// Priority groups stay first-class: only the first group with a healthy
    /// endpoint is ever considered, so lower-priority groups are unreachable
    /// while a higher one has any healthy member. `round_robin` uses smooth
    /// weighted RR over SRV targets (exact weights) with address rotation; the
    /// other algorithms select among the active group's addresses via the
    /// normal pool machinery (they treat addresses equally). `requested`
    /// (sticky affinity) is honoured only while it is healthy and in the active
    /// group. Returns null when discovery has no live set.
    ///
    /// Caller holds upstream_mutex. The discovery mutex is taken (blocking) for
    /// a short critical section; lock order is upstream_mutex then
    /// dns_discovery.mutex, and the refresh worker only ever takes the latter,
    /// never blocking under it. Returned slices are interned strings that stay
    /// valid after the lock is released.
    fn selectDiscoveredLocked(
        self: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        client_ip: []const u8,
        hash_key: []const u8,
        requested: ?[]const u8,
        now_ms: u64,
    ) ?StickyUpstreamSelection {
        const d = &self.dns_discovery;
        d.mutex.lock();
        defer d.mutex.unlock();
        if (d.groupCount() == 0) return null;
        const ctx: DiscoveredHealthCtx = .{ .state = self, .cfg = cfg, .now_ms = now_ms };
        // No healthy endpoint anywhere: keep traffic on the primary group so a
        // recovering backend is re-probed rather than leaving the discovered set.
        const g = d.firstHealthyGroup(ctx, discoveredHealthy) orelse 0;
        const group = d.groupUrls(g);
        if (group.len == 0) return null;

        if (requested) |candidate| {
            for (group) |u| {
                if (std.mem.eql(u8, u, candidate) and discoveredHealthy(ctx, u)) {
                    return .{ .base_url = u, .used_requested = true };
                }
            }
        }

        if (cfg.upstream_lb_algorithm == .round_robin) {
            if (d.pickWeighted(g, ctx, discoveredHealthy)) |u| return .{ .base_url = u, .used_requested = false };
            const idx = self.upstream_rr_index % group.len;
            self.upstream_rr_index = (idx + 1) % group.len;
            return .{ .base_url = group[idx], .used_requested = false };
        }
        const view: UpstreamPoolView = .{
            .fallback_url = group[0],
            .primary_urls = group,
            .primary_weights = &.{},
            .backup_urls = &.{},
        };
        return .{ .base_url = self.nextUpstreamBaseUrlLocked(cfg, view, client_ip, hash_key, now_ms), .used_requested = false };
    }

    pub fn nextStickyUpstreamBaseUrl(
        self: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        pool: UpstreamPoolView,
        client_ip: []const u8,
        hash_key: []const u8,
        requested_upstream: ?[]const u8,
    ) StickyUpstreamSelection {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();

        if (pool.primary_urls.len == 0) {
            if (self.selectDiscoveredLocked(cfg, client_ip, hash_key, requested_upstream, now_ms)) |picked| return picked;
        }

        if (requested_upstream) |candidate| {
            if (self.isStickyUpstreamHealthyLocked(cfg, pool, candidate, now_ms)) {
                return .{ .base_url = candidate, .used_requested = true };
            }
        }

        return .{
            .base_url = self.nextUpstreamBaseUrlLocked(cfg, pool, client_ip, hash_key, now_ms),
            .used_requested = false,
        };
    }

    pub fn nextUpstreamBaseUrlLocked(
        self: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        pool: UpstreamPoolView,
        client_ip: []const u8,
        hash_key: []const u8,
        now_ms: u64,
    ) []const u8 {
        if (pool.primary_urls.len == 0) {
            return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
        }

        switch (cfg.upstream_lb_algorithm) {
            .least_connections => {
                if (self.selectLeastConnectionsUpstreamLocked(cfg, pool, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .ip_hash => {
                if (self.selectIpHashUpstreamLocked(cfg, pool, client_ip, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .generic_hash => {
                if (self.selectGenericHashUpstreamLocked(cfg, pool, hash_key, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .random_two_choices => {
                if (self.selectRandomTwoChoicesUpstreamLocked(cfg, pool, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .round_robin => {},
        }
        const primary_slots = primaryWeightedSlotCount(pool.primary_urls, pool.primary_weights);
        const start = self.upstream_rr_index % primary_slots;

        var offset: usize = 0;
        while (offset < primary_slots) : (offset += 1) {
            const ticket = (start + offset) % primary_slots;
            const idx = weightedTicketToIndex(pool.primary_urls, pool.primary_weights, ticket);
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms) and self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) {
                self.upstream_rr_index = (ticket + 1) % primary_slots;
                return candidate;
            }
        }

        // Fallback pass: choose any healthy backend even if still in slow-start.
        offset = 0;
        while (offset < primary_slots) : (offset += 1) {
            const ticket = (start + offset) % primary_slots;
            const idx = weightedTicketToIndex(pool.primary_urls, pool.primary_weights, ticket);
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (ticket + 1) % primary_slots;
                return candidate;
            }
        }

        return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
    }

    pub fn isStickyUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, candidate: []const u8, now_ms: u64) bool {
        for (pool.primary_urls, 0..) |upstream, idx| {
            if (!std.mem.eql(u8, upstream, candidate)) continue;
            if (!self.isUpstreamHealthyLocked(cfg, upstream, now_ms)) return false;
            if (self.slowStartAllowsTrafficLocked(cfg, upstream, now_ms, @intCast(idx))) return true;
        }
        for (pool.primary_urls) |upstream| {
            if (std.mem.eql(u8, upstream, candidate)) {
                return self.isUpstreamHealthyLocked(cfg, upstream, now_ms);
            }
        }
        for (pool.backup_urls, 0..) |upstream, idx| {
            if (!std.mem.eql(u8, upstream, candidate)) continue;
            if (!self.isUpstreamHealthyLocked(cfg, upstream, now_ms)) return false;
            if (self.slowStartAllowsTrafficLocked(cfg, upstream, now_ms, @intCast(idx))) return true;
        }
        for (pool.backup_urls) |upstream| {
            if (std.mem.eql(u8, upstream, candidate)) {
                return self.isUpstreamHealthyLocked(cfg, upstream, now_ms);
            }
        }
        if (std.mem.eql(u8, pool.fallback_url, candidate)) {
            return self.isUpstreamHealthyLocked(cfg, candidate, now_ms);
        }
        return false;
    }

    pub fn selectLeastConnectionsUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        var best_idx: ?usize = null;
        var best_load: usize = std.math.maxInt(usize);
        for (pool.primary_urls, 0..) |candidate, idx| {
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;

            const load = self.upstream_active_requests.get(candidate) orelse 0;
            if (best_idx == null or load < best_load) {
                best_idx = idx;
                best_load = load;
            }
        }
        if (best_idx) |idx| {
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return pool.primary_urls[idx];
        }
        return null;
    }

    pub fn selectIpHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;
        const start = ipHashIndex(client_ip, pool.primary_urls.len);

        var offset: usize = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn selectGenericHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, hash_key: []const u8, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;
        const start = ipHashIndex(hash_key, pool.primary_urls.len);

        var offset: usize = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn nextLbRandomLocked(self: *GatewayState) u64 {
        self.lb_random_state = lcrngNext(self.lb_random_state);
        return self.lb_random_state;
    }

    pub fn nextRandomIndexLocked(self: *GatewayState, len: usize) usize {
        if (len == 0) return 0;
        return @intCast(self.nextLbRandomLocked() % len);
    }

    pub fn selectRandomTwoChoicesUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;

        const first_idx = self.nextRandomIndexLocked(pool.primary_urls.len);
        var second_idx = first_idx;
        if (pool.primary_urls.len > 1) {
            second_idx = self.nextRandomIndexLocked(pool.primary_urls.len - 1);
            if (second_idx >= first_idx) second_idx += 1;
        }

        const first = pool.primary_urls[first_idx];
        const second = pool.primary_urls[second_idx];
        const first_healthy = self.isUpstreamHealthyLocked(cfg, first, now_ms);
        const second_healthy = self.isUpstreamHealthyLocked(cfg, second, now_ms);
        const first_strict = first_healthy and self.slowStartAllowsTrafficLocked(cfg, first, now_ms, @intCast(first_idx));
        const second_strict = second_healthy and self.slowStartAllowsTrafficLocked(cfg, second, now_ms, @intCast(second_idx));

        const chosen_idx: ?usize = blk: {
            if (first_strict and second_strict) {
                const first_load = self.upstream_active_requests.get(first) orelse 0;
                const second_load = self.upstream_active_requests.get(second) orelse 0;
                break :blk if (second_load < first_load) second_idx else first_idx;
            }
            if (first_strict) break :blk first_idx;
            if (second_strict) break :blk second_idx;
            if (first_healthy and second_healthy) {
                const first_load = self.upstream_active_requests.get(first) orelse 0;
                const second_load = self.upstream_active_requests.get(second) orelse 0;
                break :blk if (second_load < first_load) second_idx else first_idx;
            }
            if (first_healthy) break :blk first_idx;
            if (second_healthy) break :blk second_idx;
            break :blk null;
        };

        if (chosen_idx) |idx| {
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return pool.primary_urls[idx];
        }
        return null;
    }

    pub fn selectPrimaryFallbackWithBackupsLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) []const u8 {
        if (self.selectBackupUpstreamLocked(cfg, pool, now_ms)) |backup| {
            return backup;
        }
        // If all primary backends are currently unhealthy, still probe primaries in round-robin order.
        return selectUpstreamBaseUrlWeighted(pool.primary_urls, pool.primary_weights, pool.fallback_url, &self.upstream_rr_index);
    }

    pub fn selectBackupUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        if (pool.backup_urls.len == 0) return null;

        const start = self.upstream_backup_rr_index % pool.backup_urls.len;
        var offset: usize = 0;
        while (offset < pool.backup_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.backup_urls.len;
            const candidate = pool.backup_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_backup_rr_index = (idx + 1) % pool.backup_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.backup_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.backup_urls.len;
            const candidate = pool.backup_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_backup_rr_index = (idx + 1) % pool.backup_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn recordUpstreamFailure(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
        if (cfg.upstream_max_fails == 0) return;

        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count +|= 1;
            if (health.fail_count >= cfg.upstream_max_fails) {
                health.fail_count = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
            }
            self.updateUpstreamHealthMetricLocked();
            return;
        }

        const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
        self.upstream_health.put(owned, .{}) catch {
            self.allocator.free(owned);
            return;
        };
        if (self.upstream_health.getPtr(owned)) |health| {
            health.fail_count = 1;
            if (health.fail_count >= cfg.upstream_max_fails) {
                health.fail_count = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
            }
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn recordUpstreamSuccess(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
        if (cfg.upstream_max_fails == 0) return;

        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count = 0;
            health.unhealthy_until_ms = 0;
            health.slow_start_until_ms = 0;
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn recordProxyUpstreamFailure(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, permit: http.circuit_breaker.Permit) void {
        self.recordUpstreamFailure(cfg, upstream_base_url);
        self.circuitRecordFailurePermit(permit);
    }

    pub fn recordProxyUpstreamSuccess(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, permit: http.circuit_breaker.Permit) void {
        self.recordUpstreamSuccess(cfg, upstream_base_url);
        self.circuitRecordSuccessPermit(permit);
    }

    pub fn recordActiveProbeResult(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, healthy: bool) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        const health = if (self.upstream_health.getPtr(upstream_base_url)) |existing|
            existing
        else blk: {
            const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
            self.upstream_health.put(owned, .{}) catch {
                self.allocator.free(owned);
                return;
            };
            break :blk self.upstream_health.getPtr(owned).?;
        };

        const health_cfg = activeHealthConfig(cfg, upstream_base_url);
        const transition = if (healthy)
            health.probe.recordSuccess(health_cfg)
        else
            health.probe.recordFailure(health_cfg);

        switch (transition) {
            .marked_up => {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                self.beginSlowStartLocked(cfg, health, http.event_loop.monotonicMs());
            },
            .marked_down => {
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
                health.slow_start_until_ms = 0;
            },
            else => {},
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn isUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64) bool {
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            if (health.unhealthy_until_ms != 0 and now_ms >= health.unhealthy_until_ms) {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                self.beginSlowStartLocked(cfg, health, now_ms);
                self.updateUpstreamHealthMetricLocked();
            }
            if (health.unhealthy_until_ms != 0 and now_ms < health.unhealthy_until_ms) return false;
            if (cfg.upstream_active_health_interval_ms > 0 and !health.probe.isRoutable()) return false;
            return true;
        }
        return true;
    }

    pub fn slowStartAllowsTrafficLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64, ticket: u64) bool {
        if (cfg.upstream_slow_start_ms == 0) return true;
        const health = self.upstream_health.getPtr(upstream_base_url) orelse return true;
        if (health.slow_start_until_ms == 0) return true;
        if (now_ms >= health.slow_start_until_ms) {
            health.slow_start_until_ms = 0;
            return true;
        }

        const remaining = health.slow_start_until_ms - now_ms;
        if (remaining >= cfg.upstream_slow_start_ms) return false;
        const elapsed = cfg.upstream_slow_start_ms - remaining;
        const allowed_percent: u64 = @max(1, (elapsed * 100) / cfg.upstream_slow_start_ms);
        return (ticket % 100) < allowed_percent;
    }

    pub fn beginSlowStartLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, health: *UpstreamHealth, now_ms: u64) void {
        _ = self;
        if (cfg.upstream_slow_start_ms == 0) {
            health.slow_start_until_ms = 0;
            return;
        }
        health.slow_start_until_ms = now_ms + cfg.upstream_slow_start_ms;
    }

    pub fn updateUpstreamHealthMetricLocked(self: *GatewayState) void {
        const now_ms = http.event_loop.monotonicMs();
        var unhealthy: usize = 0;
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            const health = entry.value_ptr.*;
            if (health.unhealthy_until_ms > now_ms or !health.probe.isRoutable()) unhealthy += 1;
        }
        self.metrics_mutex.lock();
        self.metrics.setUpstreamUnhealthyBackends(unhealthy);
        self.metrics_mutex.unlock();
    }

    pub fn upstreamUnhealthyCount(self: *GatewayState) usize {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();
        var unhealthy: usize = 0;
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            const health = entry.value_ptr.*;
            if (health.unhealthy_until_ms > now_ms or !health.probe.isRoutable()) unhealthy += 1;
        }
        return unhealthy;
    }

    pub fn recordUpstreamAttemptStart(self: *GatewayState, upstream_base_url: []const u8) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        if (self.upstream_active_requests.getPtr(upstream_base_url)) |count| {
            count.* += 1;
            return;
        }
        const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
        self.upstream_active_requests.put(owned, 1) catch {
            self.allocator.free(owned);
        };
    }

    pub fn recordUpstreamAttemptEnd(self: *GatewayState, upstream_base_url: []const u8) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        if (self.upstream_active_requests.getPtr(upstream_base_url)) |count| {
            if (count.* > 1) {
                count.* -= 1;
            } else {
                if (self.upstream_active_requests.fetchRemove(upstream_base_url)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }
    }

    pub fn streamCountAdjust(self: *GatewayState, ws_delta: i32, sse_delta: i32) void {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        if (ws_delta < 0) {
            const dec: usize = @intCast(-ws_delta);
            self.active_ws_streams = if (self.active_ws_streams > dec) self.active_ws_streams - dec else 0;
        } else if (ws_delta > 0) {
            self.active_ws_streams += @intCast(ws_delta);
        }
        if (sse_delta < 0) {
            const dec: usize = @intCast(-sse_delta);
            self.active_sse_streams = if (self.active_sse_streams > dec) self.active_sse_streams - dec else 0;
        } else if (sse_delta > 0) {
            self.active_sse_streams += @intCast(sse_delta);
        }
    }

    pub fn streamCounts(self: *GatewayState) struct { ws: usize, sse: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .ws = self.active_ws_streams, .sse = self.active_sse_streams };
    }

    pub fn muxConnectionAdjust(self: *GatewayState, delta: i32) void {
        self.connection_mutex.lock();
        if (delta < 0) {
            const dec: usize = @intCast(-delta);
            self.active_mux_connections = if (self.active_mux_connections > dec) self.active_mux_connections - dec else 0;
        } else if (delta > 0) {
            self.active_mux_connections += @intCast(delta);
        }
        const active = self.active_mux_connections;
        self.connection_mutex.unlock();

        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setMuxConnections(active);
    }

    pub fn muxSubscriptionCount(self: *GatewayState, device_id: []const u8) usize {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return self.mux_subscriptions_by_device.get(device_id) orelse 0;
    }

    pub fn muxSubscriptionAdjust(self: *GatewayState, device_id: []const u8, delta: i32) void {
        self.connection_mutex.lock();
        if (delta < 0) {
            const dec: usize = @intCast(-delta);
            self.active_mux_subscriptions = if (self.active_mux_subscriptions > dec) self.active_mux_subscriptions - dec else 0;
            if (self.mux_subscriptions_by_device.getPtr(device_id)) |count_ptr| {
                count_ptr.* = if (count_ptr.* > dec) count_ptr.* - dec else 0;
                if (count_ptr.* == 0) {
                    if (self.mux_subscriptions_by_device.fetchRemove(device_id)) |removed| {
                        self.allocator.free(removed.key);
                    }
                }
            }
        } else if (delta > 0) {
            const inc: usize = @intCast(delta);
            self.active_mux_subscriptions += inc;
            if (self.mux_subscriptions_by_device.getPtr(device_id)) |count_ptr| {
                count_ptr.* += inc;
            } else {
                const owned = self.allocator.dupe(u8, device_id) catch {
                    self.connection_mutex.unlock();
                    return;
                };
                self.mux_subscriptions_by_device.put(owned, inc) catch {
                    self.allocator.free(owned);
                    self.connection_mutex.unlock();
                    return;
                };
            }
        }
        const active = self.active_mux_subscriptions;
        self.connection_mutex.unlock();

        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setMuxSubscriptions(active);
    }

    pub fn muxMetricsSnapshot(self: *GatewayState, allocator: std.mem.Allocator) !MuxMetricsSnapshot {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        var device_counts = std.array_list.Managed(MuxDeviceCount).init(allocator);
        errdefer {
            for (device_counts.items) |entry| allocator.free(entry.device_id);
            device_counts.deinit();
        }
        var it = self.mux_subscriptions_by_device.iterator();
        while (it.next()) |entry| {
            try device_counts.append(.{
                .device_id = try allocator.dupe(u8, entry.key_ptr.*),
                .count = entry.value_ptr.*,
            });
        }
        return .{ .device_counts = try device_counts.toOwnedSlice() };
    }

    pub fn saveMuxResumeState(self: *GatewayState, device_id: []const u8, channels: []const MuxChannel, grace_ms: u32) void {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        if (self.mux_resume_state.fetchRemove(device_id)) |removed| {
            self.allocator.free(removed.key);
            var value = removed.value;
            deinitMuxResumeState(self.allocator, &value);
        }
        if (grace_ms == 0 or channels.len == 0) return;

        const owned_key = self.allocator.dupe(u8, device_id) catch return;
        const owned_channels = cloneMuxChannels(self.allocator, channels) catch {
            self.allocator.free(owned_key);
            return;
        };
        self.mux_resume_state.put(owned_key, .{
            .channels = owned_channels,
            .expires_ms = compat.milliTimestamp() + @as(i64, grace_ms),
        }) catch {
            var saved_state = MuxResumeState{ .channels = owned_channels, .expires_ms = 0 };
            deinitMuxResumeState(self.allocator, &saved_state);
            self.allocator.free(owned_key);
        };
    }

    pub fn takeMuxResumeState(self: *GatewayState, allocator: std.mem.Allocator, device_id: []const u8) ?[]MuxChannel {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        const removed = self.mux_resume_state.fetchRemove(device_id) orelse return null;
        defer self.allocator.free(removed.key);
        var saved = removed.value;
        defer deinitMuxResumeState(self.allocator, &saved);
        if (saved.expires_ms < compat.milliTimestamp()) return null;
        return cloneMuxChannels(allocator, saved.channels) catch null;
    }

    pub fn connectionCounts(self: *GatewayState) struct { active: usize, per_ip: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .active = self.active_connections_total, .per_ip = self.active_connections_by_ip.count() };
    }

    pub fn upstreamHealthJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        try out.appendSlice("{\"upstreams\":[");
        var first = true;
        const now_ms = http.event_loop.monotonicMs();
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            if (!first) try out.appendSlice(",");
            first = false;
            const url = entry.key_ptr.*;
            const h = entry.value_ptr.*;
            const healthy = (h.unhealthy_until_ms == 0 or h.unhealthy_until_ms <= now_ms) and h.probe.isRoutable();
            try out.print("{f}", .{std.json.fmt(.{
                .url = url,
                .healthy = healthy,
                .unhealthy_until_ms = h.unhealthy_until_ms,
                .active_status = h.probe.status.asString(),
            }, .{})});
        }
        try out.appendSlice("]}");
        return out.toOwnedSlice();
    }
};

/// #903: opens (or declines to open) the disk tier for a fresh/reloaded
/// config. `null` whenever `proxy_cache_path` is empty or the cache is
/// disabled outright, and also on any `DiskCache.init` failure -- a
/// misconfigured or unavailable disk tier degrades to memory-only caching
/// rather than aborting startup/reload.
pub fn openProxyResponseCacheDisk(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) ?gpdc.DiskCache {
    if (cfg.proxy_cache_ttl_seconds == 0 or cfg.proxy_cache_path.len == 0) return null;
    return gpdc.DiskCache.init(allocator, cfg.proxy_cache_path, .{
        .max_object_bytes = cfg.proxy_response_cache_max_object_bytes,
        .max_entries = cfg.proxy_response_cache_disk_max_entries,
        .max_total_bytes = cfg.proxy_response_cache_disk_max_total_bytes,
        .max_vary_variants = cfg.proxy_response_cache_max_vary_variants,
    }, cfg.proxy_response_cache_disk_fingerprint) catch |err| {
        std.log.warn("proxy response cache disk tier unavailable at '{s}' ({s}); continuing with memory-only caching", .{ cfg.proxy_cache_path, @errorName(err) });
        return null;
    };
}

/// Linear congruential PRNG step used for load-balancing randomness.
/// Always called while holding GatewayState.upstream_mutex; exposed as a
/// standalone pure function so it can be unit-tested independently.
pub fn lcrngNext(state: u64) u64 {
    return state *% 6364136223846793005 +% 1442695040888963407;
}

pub fn upstreamPoolForScope(cfg: *const edge_config.EdgeConfig, scope: UpstreamScope) UpstreamPoolView {
    return switch (scope) {
        .chat => if (cfg.upstream_chat_base_urls.len > 0 or cfg.upstream_chat_backup_base_urls.len > 0)
            .{
                .fallback_url = cfg.upstream_base_url,
                .primary_urls = cfg.upstream_chat_base_urls,
                .primary_weights = cfg.upstream_chat_base_url_weights,
                .backup_urls = cfg.upstream_chat_backup_base_urls,
            }
        else
            upstreamPoolForScope(cfg, .global),
        .commands => if (cfg.upstream_commands_base_urls.len > 0 or cfg.upstream_commands_backup_base_urls.len > 0)
            .{
                .fallback_url = cfg.upstream_base_url,
                .primary_urls = cfg.upstream_commands_base_urls,
                .primary_weights = cfg.upstream_commands_base_url_weights,
                .backup_urls = cfg.upstream_commands_backup_base_urls,
            }
        else
            upstreamPoolForScope(cfg, .global),
        .global => .{
            .fallback_url = cfg.upstream_base_url,
            .primary_urls = cfg.upstream_base_urls,
            .primary_weights = cfg.upstream_base_url_weights,
            .backup_urls = cfg.upstream_backup_base_urls,
        },
    };
}

fn stickyCookieSecret(cfg: *const edge_config.EdgeConfig) []const u8 {
    if (cfg.trust_shared_secret.len > 0) return cfg.trust_shared_secret;
    if (cfg.jwt_secret.len > 0) return cfg.jwt_secret;
    return "";
}

pub fn stickyAffinityEligible(cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, proxy_pass_target: []const u8) bool {
    if (stickyCookieSecret(cfg).len == 0) return false;
    if (isAbsoluteHttpUrl(std.mem.trim(u8, proxy_pass_target, " \t\r\n"))) return false;

    // A discovery-only pool has no static primaries; its endpoint count is not
    // known here, so treat it as eligible (a single endpoint makes the cookie
    // harmless).
    if (pool.primary_urls.len == 0 and (cfg.upstream_srv_name.len > 0 or cfg.upstream_dns_discovery_host.len > 0)) return true;

    var upstreams: usize = pool.primary_urls.len + pool.backup_urls.len;
    if (upstreams == 0 and pool.fallback_url.len > 0) upstreams = 1;
    return upstreams > 1;
}

/// C1 cache entries are keyed by a stable effective origin. A relative
/// `proxy_pass` backed by a pool can choose a different primary, backup, or
/// discovery result per request, so it cannot safely use the generic cache
/// until selection is made part of its key. Keep the cache conservative and
/// bypass those routes rather than selecting twice or replaying one member's
/// representation for another member.
pub fn proxyResponseCacheHasDynamicUpstream(cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, proxy_pass_target: []const u8) bool {
    if (isAbsoluteHttpUrl(std.mem.trim(u8, proxy_pass_target, " \t\r\n"))) return false;
    if (pool.primary_urls.len > 1 or pool.backup_urls.len > 0) return true;
    return pool.primary_urls.len == 0 and (cfg.upstream_srv_name.len > 0 or cfg.upstream_dns_discovery_host.len > 0);
}

test "proxy response cache bypasses dynamic relative upstream pools" {
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    const one = [_][]const u8{"http://one.example"};
    const two = [_][]const u8{ "http://one.example", "http://two.example" };
    const backup = [_][]const u8{"http://backup.example"};

    try std.testing.expect(!proxyResponseCacheHasDynamicUpstream(&cfg, .{
        .fallback_url = one[0],
        .primary_urls = &one,
        .primary_weights = &.{},
        .backup_urls = &.{},
    }, "/api"));
    try std.testing.expect(proxyResponseCacheHasDynamicUpstream(&cfg, .{
        .fallback_url = one[0],
        .primary_urls = &two,
        .primary_weights = &.{},
        .backup_urls = &.{},
    }, "/api"));
    try std.testing.expect(proxyResponseCacheHasDynamicUpstream(&cfg, .{
        .fallback_url = one[0],
        .primary_urls = &one,
        .primary_weights = &.{},
        .backup_urls = &backup,
    }, "/api"));
    cfg.upstream_dns_discovery_host = "origin.example";
    try std.testing.expect(proxyResponseCacheHasDynamicUpstream(&cfg, .{
        .fallback_url = one[0],
        .primary_urls = &.{},
        .primary_weights = &.{},
        .backup_urls = &.{},
    }, "/api"));
    try std.testing.expect(!proxyResponseCacheHasDynamicUpstream(&cfg, .{
        .fallback_url = one[0],
        .primary_urls = &two,
        .primary_weights = &.{},
        .backup_urls = &.{},
    }, "http://fixed.example/api"));
}

pub fn prepareStickyAffinityRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    pool: UpstreamPoolView,
    headers: *const http.Headers,
    incoming_host: ?[]const u8,
    location_id: []const u8,
    proxy_pass_target: []const u8,
) !?StickyAffinityRequest {
    if (!stickyAffinityEligible(cfg, pool, proxy_pass_target)) return null;

    const host = if (incoming_host) |value|
        std.mem.trim(u8, value, " \t\r\n")
    else
        "";
    const normalized_host = if (host.len > 0) host else "-";
    const location_key = try std.fmt.allocPrint(allocator, "{s}|{s}", .{ normalized_host, location_id });
    errdefer allocator.free(location_key);
    const cookie_name = try affinityCookieName(allocator, location_key);
    errdefer allocator.free(cookie_name);
    const requested_upstream = try parseStickyCookieUpstream(allocator, cfg, headers, location_key, cookie_name);

    return .{
        .location_key = location_key,
        .cookie_name = cookie_name,
        .requested_upstream = requested_upstream,
    };
}

fn affinityCookieName(allocator: std.mem.Allocator, location_key: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "__Host-tg-aff-{x}", .{std.hash.Wyhash.hash(0, location_key)});
}

pub fn buildStickySetCookieHeader(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    affinity: *const StickyAffinityRequest,
    selected_upstream: []const u8,
) !?[]u8 {
    if (affinity.requested_upstream) |requested| {
        if (std.mem.eql(u8, requested, selected_upstream)) return null;
    }

    const value = try stickyCookieValue(allocator, stickyCookieSecret(cfg), affinity.location_key, selected_upstream);
    defer allocator.free(value);
    return try std.fmt.allocPrint(
        allocator,
        "{s}={s}; Path=/; HttpOnly; Secure; SameSite=Lax",
        .{ affinity.cookie_name, value },
    );
}

fn stickyCookieValue(
    allocator: std.mem.Allocator,
    secret: []const u8,
    location_key: []const u8,
    upstream_base_url: []const u8,
) ![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const upstream_b64 = try allocator.alloc(u8, enc.calcSize(upstream_base_url.len));
    defer allocator.free(upstream_b64);
    _ = enc.encode(upstream_b64, upstream_base_url);

    const signature_hex = try stickyCookieSignatureHex(allocator, secret, location_key, upstream_base_url);
    defer allocator.free(signature_hex);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ upstream_b64, signature_hex });
}

fn stickyCookieSignatureHex(
    allocator: std.mem.Allocator,
    secret: []const u8,
    location_key: []const u8,
    upstream_base_url: []const u8,
) ![]u8 {
    const material = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ location_key, upstream_base_url });
    defer allocator.free(material);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, material, secret);
    return std.fmt.allocPrint(allocator, "{f}", .{compat.fmtSliceHexLower(&mac)});
}

fn parseStickyCookieUpstream(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    headers: *const http.Headers,
    location_key: []const u8,
    cookie_name: []const u8,
) !?[]u8 {
    const raw_cookie = findCookieValue(headers, cookie_name) orelse return null;
    const dot = std.mem.findScalarLast(u8, raw_cookie, '.') orelse return null;
    const encoded_upstream = raw_cookie[0..dot];
    const provided_sig = raw_cookie[dot + 1 ..];
    if (encoded_upstream.len == 0 or provided_sig.len == 0) return null;

    const dec = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = dec.calcSizeForSlice(encoded_upstream) catch return null;
    const upstream = try allocator.alloc(u8, decoded_len);
    dec.decode(upstream, encoded_upstream) catch {
        allocator.free(upstream);
        return null;
    };

    const expected_sig = try stickyCookieSignatureHex(allocator, stickyCookieSecret(cfg), location_key, upstream);
    defer allocator.free(expected_sig);
    if (!std.mem.eql(u8, expected_sig, provided_sig)) {
        allocator.free(upstream);
        return null;
    }

    return upstream;
}

fn findCookieValue(headers: *const http.Headers, cookie_name: []const u8) ?[]const u8 {
    for (headers.iterator()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        if (findCookieValueInHeader(header.value, cookie_name)) |value| return value;
    }
    return null;
}

fn findCookieValueInHeader(cookie_header: []const u8, cookie_name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |segment_raw| {
        const segment = std.mem.trim(u8, segment_raw, " \t\r\n");
        if (segment.len <= cookie_name.len or segment[cookie_name.len] != '=') continue;
        if (!std.mem.eql(u8, segment[0..cookie_name.len], cookie_name)) continue;
        return std.mem.trim(u8, segment[cookie_name.len + 1 ..], " \t\r\n");
    }
    return null;
}

fn selectUpstreamBaseUrl(base_urls: []const []const u8, fallback: []const u8, rr_index: *usize) []const u8 {
    if (base_urls.len == 0) return fallback;
    const idx = rr_index.* % base_urls.len;
    rr_index.* = (idx + 1) % base_urls.len;
    return base_urls[idx];
}

fn primaryWeightedSlotCount(base_urls: []const []const u8, weights: []const u32) usize {
    if (base_urls.len == 0) return 0;
    if (weights.len != base_urls.len or weights.len == 0) return base_urls.len;

    var total: usize = 0;
    for (weights) |w| total +|= w;
    return if (total == 0) base_urls.len else total;
}

fn weightedTicketToIndex(base_urls: []const []const u8, weights: []const u32, ticket: usize) usize {
    if (base_urls.len == 0) return 0;
    if (weights.len != base_urls.len or weights.len == 0) return ticket % base_urls.len;

    const total = primaryWeightedSlotCount(base_urls, weights);
    var remaining = ticket % total;
    for (weights, 0..) |w, idx| {
        if (remaining < w) return idx;
        remaining -= w;
    }
    return base_urls.len - 1;
}

fn selectUpstreamBaseUrlWeighted(base_urls: []const []const u8, weights: []const u32, fallback: []const u8, rr_index: *usize) []const u8 {
    if (base_urls.len == 0) return fallback;
    const slots = primaryWeightedSlotCount(base_urls, weights);
    const ticket = rr_index.* % slots;
    const idx = weightedTicketToIndex(base_urls, weights, ticket);
    rr_index.* = (ticket + 1) % slots;
    return base_urls[idx];
}

fn ipHashIndex(client_ip: []const u8, len: usize) usize {
    if (len == 0) return 0;
    const hash = std.hash.Wyhash.hash(0, client_ip);
    return @intCast(hash % len);
}

pub const WorkerContext = struct {
    config_store: *ReloadableConfigStore,
    state: *GatewayState,
    native_credentials: ?*http.native_tls_connection.NativeCredentialStore,
    /// SNI-keyed downstream client-certificate policies (#763); present on
    /// every native TLS listener so mTLS can be enabled by hot reload.
    client_policies: ?*http.native_tls_connection.ClientPolicySet = null,
    /// Borrowed credential provider used by the native TCP TLS accept path.
    /// Appliance profile: borrowed from the `ApplianceCredentials` owner.
    /// Otherwise: borrowed from the generic native credential store.
    native_tls_provider: ?tls_core.credentials.CredentialProvider = null,
    /// #488: process-shared native TLS/QUIC resumption runtime, borrowed
    /// for the lifetime of every native TCP connection this worker accepts.
    /// `null` when native resumption is disabled (the default) or the
    /// downstream path is not native TLS.
    resumption_runtime: ?*tls_core.resumption_runtime.Runtime = null,
    /// #368 Slice 2: process-shared anti-replay gate, borrowed for the
    /// lifetime of every native TCP connection this worker accepts — the
    /// same store instance shared with native QUIC/H3, so worker-local
    /// duplicate 0-RTT acceptance is impossible. `null` leaves each
    /// backend's own default gate in place (fail-closed `.unavailable`).
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate = null,
    session_pool: *ConnectionSessionPool,
    /// Event loop used to (un)watch idle keepalive connections (#138). A worker
    /// re-arms a parked fd here; the loop thread dispatches it back on readiness.
    event_loop: *http.event_loop.EventLoop,
    /// Active nonblocking downstream connections keyed by fd. Native TLS and
    /// resumable HTTP phases park here while waiting for carrier or protocol
    /// readiness; idle HTTP/1.1 keepalive still uses `parked`.
    active: *http.downstream_connection.ActiveRegistry,
    /// Registry of idle keepalive connections parked off the worker pool (#138).
    parked: *http.keepalive_park.ParkedRegistry,

    pub fn acquireConfig(self: *WorkerContext) ConfigLease {
        return self.config_store.acquire();
    }
};

pub const ManagedConfigVersion = struct {
    cfg: *const edge_config.EdgeConfig,
    owned_cfg: ?*edge_config.EdgeConfig,
    ref_count: usize,
    generation: u64,
    /// Monotonic time (ms) at which a successful reload replaced this
    /// generation, or 0 while it is current. Written once, by the install
    /// that supersedes it: a failed reload never installs, and a later reload
    /// replaces a newer generation, so the value is never moved. Long-lived
    /// work leased on this generation (WebSocket tunnels in `drain` mode,
    /// #812) reads it to time its own shutdown.
    superseded_at_ms: std.atomic.Value(u64) = .init(0),
    /// Parsed IP access-control policy for THIS configuration generation.
    ///
    /// The ACL lives here, not on `GatewayState`, because authorization state
    /// must share the lifetime and generation of the configuration a request is
    /// leasing. A single global ACL has two defects that a mutex cannot fix:
    /// reload frees the rule slice while a worker may be inside `check()`, and a
    /// request holding an older config lease can observe a newer (or absent)
    /// ACL and skip a denial its own configuration still requires. Owned by the
    /// version and destroyed only when the last lease releases it.
    access_control: ?http.access_control.AccessControl = null,
    /// SNI-keyed downstream client-auth policies for THIS generation (#763).
    /// Like the ACL, they live with the configuration a connection leases, so
    /// the TLS handshake policy, Host admission and routing of one connection
    /// always come from one generation, whatever reloads happen meanwhile.
    /// The version holds one reference; connections retain their own.
    client_policies: ?*tls_core.client_trust.PolicySnapshot = null,

    /// The ACL to enforce for a request holding this version, if any.
    pub fn accessControl(self: *ManagedConfigVersion) ?*http.access_control.AccessControl {
        if (self.access_control) |*acl| return acl;
        return null;
    }
};

pub const ConfigLease = struct {
    store: *ReloadableConfigStore,
    version: *ManagedConfigVersion,
    cfg: *const edge_config.EdgeConfig,

    /// ACL paired with this lease's configuration generation.
    pub fn accessControl(self: ConfigLease) ?*http.access_control.AccessControl {
        return self.version.accessControl();
    }

    pub fn retain(self: *ConfigLease) ConfigLease {
        return self.store.retain(self.version);
    }

    pub fn release(self: *ConfigLease) void {
        self.store.release(self.version);
        self.* = undefined;
    }
};

/// A process slot plus a lease on the exact configuration generation that
/// admitted a long-lived response stream (#841). This is intentionally
/// independent of HTTP/1 and HTTP/2 relay state so either path can compose it.
pub const ResponseStreamAdmission = struct {
    lifecycle: *http.response_stream_lifecycle.Lifecycle,
    config_lease: ConfigLease,
    generation: u64,
    policy: http.response_stream_lifecycle.AdmissionPolicy,
    opened_at_ms: u64,

    /// The first successful reload that superseded this admission generation.
    /// A failed or merely prepared reload leaves this at null.
    pub fn supersededAtMs(self: *const ResponseStreamAdmission) ?u64 {
        const stamp = self.config_lease.version.superseded_at_ms.load(.acquire);
        return if (stamp == 0) null else stamp;
    }

    /// Drain deadline fixed by the admission policy and the first successful
    /// superseding reload. Preserve streams have no reload deadline.
    pub fn reloadDeadlineMs(self: *const ResponseStreamAdmission) ?u64 {
        if (self.policy.reload == .preserve) return null;
        const stamp = self.supersededAtMs() orelse return null;
        return stamp +| self.policy.reload_timeout_ms;
    }

    pub fn release(self: *ResponseStreamAdmission) void {
        self.lifecycle.release();
        self.config_lease.release();
        self.* = undefined;
    }
};

/// Protocol-neutral admission primitive used by the gateway wrapper and unit
/// tests. A successful result owns one lifecycle slot and one retained config
/// lease until `ResponseStreamAdmission.release`.
pub fn tryReserveResponseStream(
    lifecycle: *http.response_stream_lifecycle.Lifecycle,
    config_lease: *ConfigLease,
    overrides: http.response_stream_lifecycle.LocationOverrides,
    now_ms: u64,
) ?ResponseStreamAdmission {
    const cfg = config_lease.cfg;
    if (!lifecycle.tryReserve(cfg.proxy_response_stream_max_active)) return null;
    return .{
        .lifecycle = lifecycle,
        .config_lease = config_lease.retain(),
        .generation = config_lease.version.generation,
        .policy = overrides.resolve(.{
            .max_active = cfg.proxy_response_stream_max_active,
            .reload = cfg.proxy_response_stream_reload,
            .reload_timeout_ms = cfg.proxy_response_stream_reload_timeout_ms,
        }),
        .opened_at_ms = now_ms,
    };
}

pub const ReloadableConfigStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: *ManagedConfigVersion,
    retired: std.ArrayList(*ManagedConfigVersion),
    next_generation: u64 = 1,

    pub fn initBorrowed(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !ReloadableConfigStore {
        return .{
            .allocator = allocator,
            .current = try createBorrowedVersion(allocator, cfg),
            .retired = .empty,
        };
    }

    pub fn deinit(self: *ReloadableConfigStore) void {
        for (self.retired.items) |version| {
            self.destroyVersion(version);
        }
        self.retired.deinit(self.allocator);
        self.destroyVersion(self.current);
        self.* = undefined;
    }

    pub fn acquire(self: *ReloadableConfigStore) ConfigLease {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.current.ref_count += 1;
        return .{
            .store = self,
            .version = self.current,
            .cfg = self.current.cfg,
        };
    }

    pub fn retain(self: *ReloadableConfigStore, version: *ManagedConfigVersion) ConfigLease {
        self.mutex.lock();
        defer self.mutex.unlock();

        version.ref_count += 1;
        return .{
            .store = self,
            .version = version,
            .cfg = version.cfg,
        };
    }

    /// Attach the startup generation's parsed ACL. Called once, before any
    /// worker is accepting, so it needs no synchronization.
    ///
    /// `cfg_ptr` must be the same configuration this store was initialized with;
    /// publishing the borrowed pointer is what lets request paths reach the ACL
    /// paired with their lease.
    pub fn setInitialAccessControl(
        self: *ReloadableConfigStore,
        cfg_ptr: *edge_config.EdgeConfig,
        acl: ?http.access_control.AccessControl,
    ) void {
        std.debug.assert(self.current.cfg == cfg_ptr);
        self.current.access_control = acl;
        cfg_ptr.parsed_access_control = self.current.accessControl();
    }

    /// Attach a reload generation's parsed ACL to a prepared-but-not-installed
    /// version. The version owns the ACL from here on, so it stays alive for
    /// every request that later leases this generation and is freed only when
    /// the last of those leases is released.
    /// Attach the startup generation's client-auth policy snapshot (takes
    /// ownership of one reference). Called once, before workers accept.
    pub fn setInitialClientPolicies(self: *ReloadableConfigStore, snapshot: ?*tls_core.client_trust.PolicySnapshot) void {
        self.current.client_policies = snapshot;
    }

    /// Attach a reload generation's client-auth policy snapshot to a
    /// prepared-but-not-installed version (takes ownership of one reference).
    pub fn setPreparedClientPolicies(version: *ManagedConfigVersion, snapshot: ?*tls_core.client_trust.PolicySnapshot) void {
        version.client_policies = snapshot;
    }

    pub fn setPreparedAccessControl(
        version: *ManagedConfigVersion,
        acl: ?http.access_control.AccessControl,
    ) void {
        version.access_control = acl;
        if (version.owned_cfg) |owned| owned.parsed_access_control = version.accessControl();
    }

    pub fn prepareOwned(self: *ReloadableConfigStore, cfg_ptr: *edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try createOwnedVersion(self.allocator, cfg_ptr);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.retired.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.destroyVersion(version);
            return err;
        };
        self.next_generation += 1;
        version.generation = self.next_generation;
        return version;
    }

    pub fn installPrepared(self: *ReloadableConfigStore, new_version: *ManagedConfigVersion) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const old_version = self.current;
        if (new_version.generation <= old_version.generation) {
            new_version.generation = old_version.generation + 1;
        }
        self.next_generation = @max(self.next_generation, new_version.generation);
        self.current = new_version;
        // Never 0, which means "still current".
        _ = old_version.superseded_at_ms.cmpxchgStrong(0, @max(http.event_loop.monotonicMs(), 1), .acq_rel, .acquire);
        self.retired.appendAssumeCapacity(old_version);
        std.debug.assert(old_version.ref_count > 0);
        old_version.ref_count -= 1;
        self.collectRetiredLocked();
    }

    pub fn release(self: *ReloadableConfigStore, version: *ManagedConfigVersion) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        std.debug.assert(version.ref_count > 0);
        version.ref_count -= 1;
        self.collectRetiredLocked();
    }

    pub fn collectRetiredLocked(self: *ReloadableConfigStore) void {
        var idx: usize = 0;
        while (idx < self.retired.items.len) {
            const version = self.retired.items[idx];
            if (version.ref_count == 0) {
                self.destroyVersion(version);
                _ = self.retired.swapRemove(idx);
                continue;
            }
            idx += 1;
        }
    }

    pub fn destroyVersion(self: *ReloadableConfigStore, version: *ManagedConfigVersion) void {
        // Safe precisely because this runs only at ref_count == 0: no request
        // can still be inside `check()` on these rules.
        if (version.access_control) |*acl| acl.deinit();
        if (version.client_policies) |snapshot| snapshot.release();
        if (version.owned_cfg) |owned_cfg| {
            owned_cfg.deinit(self.allocator);
            self.allocator.destroy(owned_cfg);
        }
        self.allocator.destroy(version);
    }

    pub fn createBorrowedVersion(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try allocator.create(ManagedConfigVersion);
        version.* = .{
            .cfg = cfg,
            .owned_cfg = null,
            .ref_count = 1,
            .generation = 1,
        };
        return version;
    }

    pub fn createOwnedVersion(allocator: std.mem.Allocator, cfg_ptr: *edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try allocator.create(ManagedConfigVersion);
        version.* = .{
            .cfg = cfg_ptr,
            .owned_cfg = cfg_ptr,
            .ref_count = 1,
            .generation = 0,
        };
        return version;
    }
};

pub const ConnectionSession = struct {
    pending_buf: ?[]u8 = null,
    pending_len: usize = 0,
    pending_early_prefix_len: usize = 0,
    current_request_transport_early: bool = false,
    proxy_protocol_checked: bool = false,
    proxy_client_ip_len: usize = 0,
    proxy_client_ip_buf: [64]u8 = undefined,
};

pub const ConnectionSessionPool = struct {
    allocator: std.mem.Allocator,
    buffer_pool: *http.buffer_pool.BufferPool,
    mutex: compat.Mutex = .{},
    free_list: std.ArrayList(*ConnectionSession),
    max_cached: usize,

    pub fn init(allocator: std.mem.Allocator, buffer_pool: *http.buffer_pool.BufferPool, max_cached: usize) ConnectionSessionPool {
        return .{
            .allocator = allocator,
            .buffer_pool = buffer_pool,
            .free_list = .empty,
            .max_cached = max_cached,
        };
    }

    pub fn deinit(self: *ConnectionSessionPool) void {
        for (self.free_list.items) |session| {
            if (session.pending_buf) |buf| self.buffer_pool.release(buf);
            self.allocator.destroy(session);
        }
        self.free_list.deinit(self.allocator);
    }

    pub fn acquire(self: *ConnectionSessionPool) !*ConnectionSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len > 0) {
            const session = self.free_list.pop().?;
            session.* = .{};
            return session;
        }
        const session = try self.allocator.create(ConnectionSession);
        session.* = .{};
        return session;
    }

    pub fn release(self: *ConnectionSessionPool, session: *ConnectionSession) void {
        if (session.pending_buf) |buf| self.buffer_pool.release(buf);
        session.pending_len = 0;
        session.pending_buf = null;
        session.proxy_protocol_checked = false;
        session.proxy_client_ip_len = 0;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len >= self.max_cached) {
            self.allocator.destroy(session);
            return;
        }
        self.free_list.append(self.allocator, session) catch {
            self.allocator.destroy(session);
        };
    }
};

/// Load persisted approvals from disk into state at startup.
/// Prunes entries older than 1 hour that are no longer pending.
pub fn loadApprovalStore(state: *GatewayState) !void {
    const stored = try http.approval_store.load(state.allocator, state.approval_store_path);
    defer http.approval_store.freeLoaded(state.allocator, stored);

    const now = compat.milliTimestamp();
    const retention_ms: i64 = 3_600_000; // 1 hour retention for decided entries

    for (stored) |s| {
        const status = std.meta.stringToEnum(ApprovalStatus, s.status) orelse .escalated;
        // Prune old decided entries; always keep pending ones.
        if (status != .pending and s.decided_ms > 0 and (now - s.decided_ms) > retention_ms) {
            continue;
        }
        const token_key = state.allocator.dupe(u8, s.token) catch continue;
        const entry = ApprovalEntry{
            .method = state.allocator.dupe(u8, s.method) catch {
                state.allocator.free(token_key);
                continue;
            },
            .path = state.allocator.dupe(u8, s.path) catch {
                state.allocator.free(token_key);
                continue;
            },
            .identity = state.allocator.dupe(u8, s.identity) catch {
                state.allocator.free(token_key);
                continue;
            },
            .command_id = state.allocator.dupe(u8, s.command_id) catch {
                state.allocator.free(token_key);
                continue;
            },
            .status = status,
            .created_ms = s.created_ms,
            .expires_ms = s.expires_ms,
            .decided_ms = s.decided_ms,
            .decided_by = state.allocator.dupe(u8, s.decided_by) catch {
                state.allocator.free(token_key);
                continue;
            },
            .escalation_fired = s.escalation_fired,
        };
        state.approvals.put(token_key, entry) catch {
            state.allocator.free(token_key);
        };
    }
}

pub fn loadSessionStore(state: *GatewayState) !void {
    if (state.session_store == null or state.session_store_path.len == 0) return;
    const stored = try http.session_store_file.load(state.allocator, state.session_store_path);
    defer http.session_store_file.freeLoaded(state.allocator, stored);
    if (state.session_store) |*store| {
        try http.session_store_file.restore(state.allocator, store, stored);
    }
}

// Helper functions used by GatewayState methods (must live here to avoid
// cross-module calls from within the struct).

pub fn isAbsoluteHttpUrl(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "http://") or std.mem.startsWith(u8, value, "https://");
}

pub fn activeHealthConfig(cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) http.health_checker.Config {
    var success_status = cfg.upstream_active_health_success_status;
    for (cfg.upstream_active_health_success_status_overrides) |entry| {
        if (std.mem.eql(u8, upstream_base_url, entry.upstream_base_url)) {
            success_status = entry.range;
            break;
        }
    }
    return .{
        .path = cfg.upstream_active_health_path,
        .interval_ms = cfg.upstream_active_health_interval_ms,
        .timeout_ms = cfg.upstream_active_health_timeout_ms,
        .fail_threshold = cfg.upstream_active_health_fail_threshold,
        .success_threshold = cfg.upstream_active_health_success_threshold,
        .success_status_min = success_status.min,
        .success_status_max = success_status.max,
    };
}

fn proxyCacheFilePath(allocator: std.mem.Allocator, cache_path: []const u8, key: []const u8) ![]u8 {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &key_digest, .{});
    var key_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&key_digest_hex, "{f}", .{compat.fmtSliceHexLower(&key_digest)}) catch unreachable;
    return std.fmt.allocPrint(allocator, "{s}/{s}.cache", .{ cache_path, key_digest_hex[0..] });
}

fn proxyCacheWriteToDisk(cache_path: []const u8, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
    if (cache_path.len == 0) return;
    compat.cwd().makePath(cache_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const allocator = std.heap.page_allocator;
    const file_path = try proxyCacheFilePath(allocator, cache_path, key);
    defer allocator.free(file_path);

    var fc = try compat.cwd().createFile(file_path, .{ .truncate = true, .read = false });
    defer fc.close();
    const header = try std.fmt.allocPrint(allocator, "{d}\n{d}\n{s}\n\n", .{ status, compat.nanoTimestamp(), content_type });
    defer allocator.free(header);
    try fc.writeAll(header);
    try fc.writeAll(body);
}

fn proxyCacheReadFromDisk(
    allocator: std.mem.Allocator,
    cache_path: []const u8,
    key: []const u8,
    ttl_seconds: u32,
    stale_seconds: u32,
) !?ProxyCacheLookup {
    if (cache_path.len == 0) return null;
    const file_path = try proxyCacheFilePath(allocator, cache_path, key);
    defer allocator.free(file_path);

    const raw = compat.cwd().readFileAlloc(allocator, file_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(raw);

    const l1 = std.mem.findScalar(u8, raw, '\n') orelse return null;
    const l2 = std.mem.findScalarPos(u8, raw, l1 + 1, '\n') orelse return null;
    const l3 = std.mem.findScalarPos(u8, raw, l2 + 1, '\n') orelse return null;
    if (l3 + 1 >= raw.len or raw[l3 + 1] != '\n') return null;
    const body_start = l3 + 2;

    const status = std.fmt.parseInt(u16, std.mem.trim(u8, raw[0..l1], " \t\r\n"), 10) catch return null;
    const created_ns = std.fmt.parseInt(i128, std.mem.trim(u8, raw[l1 + 1 .. l2], " \t\r\n"), 10) catch return null;
    const ct_slice = std.mem.trim(u8, raw[l2 + 1 .. l3], " \t\r\n");
    const now_ns = compat.nanoTimestamp();
    const age_ns = now_ns - created_ns;
    const ttl_ns: i128 = @as(i128, ttl_seconds) * std.time.ns_per_s;
    const stale_ns: i128 = @as(i128, stale_seconds) * std.time.ns_per_s;
    if (age_ns > ttl_ns + stale_ns) {
        _ = proxyCacheDeleteFromDisk(cache_path, key);
        return null;
    }

    const body = try allocator.dupe(u8, raw[body_start..]);
    errdefer allocator.free(body);
    const ct = try allocator.dupe(u8, ct_slice);
    return .{
        .cached = .{
            .status = status,
            .body = body,
            .content_type = ct,
            .created_ns = created_ns,
        },
        .is_stale = age_ns > ttl_ns,
    };
}

fn proxyCacheDeleteFromDisk(cache_path: []const u8, key: []const u8) bool {
    if (cache_path.len == 0) return false;
    const allocator = std.heap.page_allocator;
    const file_path = proxyCacheFilePath(allocator, cache_path, key) catch return false;
    defer allocator.free(file_path);
    compat.cwd().deleteFile(file_path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return false,
    };
    return true;
}

fn proxyCachePurgeDisk(cache_path: []const u8) usize {
    if (cache_path.len == 0) return 0;
    var dir = compat.cwd().openDir(cache_path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var removed: usize = 0;
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        dir.deleteFile(entry.name) catch continue;
        removed += 1;
    }
    return removed;
}

// Tests for types and functions defined in this module.
test "lcrngNext produces distinct successive values" {
    // Verify the LCG advances state on each step.
    const seed: u64 = 1;
    const v1 = lcrngNext(seed);
    const v2 = lcrngNext(v1);
    const v3 = lcrngNext(v2);
    try std.testing.expect(v1 != seed);
    try std.testing.expect(v2 != v1);
    try std.testing.expect(v3 != v2);
}

test "lcrngNext is deterministic" {
    // Same seed always produces the same sequence — important for reproducible
    // load-balancing behaviour in tests.
    const seed: u64 = 0xDEADBEEFCAFEBABE;
    try std.testing.expectEqual(lcrngNext(seed), lcrngNext(seed));
    try std.testing.expectEqual(lcrngNext(lcrngNext(seed)), lcrngNext(lcrngNext(seed)));
}

test "lcrngNext never returns zero from non-zero seed" {
    // LCG multiplier is odd and addend is odd, so the period is 2^64.
    // Verify a run of 1024 steps from a non-zero seed never wraps to zero
    // (statistical sanity check, not a proof of full period).
    var state: u64 = 42;
    var i: usize = 0;
    while (i < 1024) : (i += 1) {
        state = lcrngNext(state);
        try std.testing.expect(state != 0);
    }
}

test "selectUpstreamBaseUrl round-robins across configured bases" {
    var idx: usize = 0;
    const base_urls = [_][]const u8{
        "http://upstream-a:8080",
        "http://upstream-b:8080",
        "http://upstream-c:8080",
    };

    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-b:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
}

test "selectUpstreamBaseUrlWeighted honors configured weights" {
    var idx: usize = 0;
    const base_urls = [_][]const u8{
        "http://upstream-a:8080",
        "http://upstream-b:8080",
        "http://upstream-c:8080",
    };
    const weights = [_]u32{ 3, 1, 2 };

    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-b:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
}

test "connection session pool reuses released sessions" {
    var buffer_pool = http.buffer_pool.BufferPool.init(std.testing.allocator, 1024, 4);
    defer buffer_pool.deinit();
    var pool = ConnectionSessionPool.init(std.testing.allocator, &buffer_pool, 4);
    defer pool.deinit();

    const first = try pool.acquire();
    first.pending_len = 42;
    pool.release(first);

    const second = try pool.acquire();
    defer pool.release(second);

    try std.testing.expect(first == second);
    try std.testing.expectEqual(@as(usize, 0), second.pending_len);
}

test "reloadable config store retires old config after last lease" {
    var first_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    var second_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});

    var store = try ReloadableConfigStore.initBorrowed(std.testing.allocator, &first_cfg);
    defer store.deinit();

    var lease = store.acquire();
    try store.retired.ensureUnusedCapacity(std.testing.allocator, 1);
    const new_version = try ReloadableConfigStore.createBorrowedVersion(std.testing.allocator, &second_cfg);
    store.installPrepared(new_version);

    try std.testing.expectEqual(@as(u64, 2), store.current.generation);
    try std.testing.expectEqual(@as(usize, 1), store.retired.items.len);
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), store.retired.items.len);
}

// ---------------------------------------------------------------------------
// Overload / resource-exhaustion accounting tests (#172).
//
// These drive the real connection-slot and in-flight-request accounting
// methods to prove each configured limit rejects deterministically and — just
// as importantly — that neither acceptance nor rejection leaks accounting
// state. `std.testing.allocator` fails the test on any leaked duped IP key, so
// a balanced acquire/release sequence is itself the leak-free invariant check.
//
// GatewayState has too many fields to construct fully here, but the accounting
// methods touch only the subset initialized below and never perform any syscall
// on the (fake) fds, so an `undefined` base with that subset set is safe.
// ---------------------------------------------------------------------------

fn initSlotTestState(gs: *GatewayState, allocator: std.mem.Allocator) void {
    gs.allocator = allocator;
    gs.tunnel_reactor = null;
    gs.acme_renewal_worker = null;
    gs.h2_request_executor = null;
    gs.connection_mutex = .{};
    gs.metrics_mutex = .{};
    gs.runtime_mutex = .{};
    gs.metrics = http.metrics.Metrics.init();
    gs.active_connections_total = 0;
    gs.max_active_connections = 0;
    gs.max_connections_per_ip = 0;
    gs.max_in_flight_requests = 0;
    gs.in_flight_requests = std.atomic.Value(u32).init(0);
    gs.connection_memory_estimate_bytes = 0;
    gs.max_total_connection_memory_bytes = 0;
    gs.proxy_buffer_limits = .{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    gs.tls_buffer_limits = @import("tls_core").encrypted_stream.BufferLimits.defaults();
    gs.active_connections_by_ip = std.StringHashMap(u32).init(allocator);
    gs.active_fds = std.AutoHashMap(std.posix.fd_t, void).init(allocator);
    gs.fd_to_ip = std.AutoHashMap(std.posix.fd_t, []u8).init(allocator);
}

fn deinitSlotTestState(gs: *GatewayState) void {
    gs.active_connections_by_ip.deinit();
    gs.active_fds.deinit();
    gs.fd_to_ip.deinit();
}

test "connection slot enforces global limit and accounting is leak-free" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    gs.max_active_connections = 2;

    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(1001, "10.0.0.1"));
    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(1002, "10.0.0.2"));
    try std.testing.expectEqual(@as(usize, 2), gs.active_connections_total);

    // Third connection is rejected at the global cap and must not be tracked.
    try std.testing.expectEqual(ConnectionSlotResult.over_global_limit, try gs.tryAcquireConnectionSlot(1003, "10.0.0.3"));
    try std.testing.expectEqual(@as(usize, 2), gs.active_connections_total);
    try std.testing.expectEqual(@as(usize, 2), gs.active_fds.count());
    try std.testing.expectEqual(@as(u64, 1), gs.metrics.connection_rejections);

    // Releasing both returns accounting to baseline (no leak).
    gs.releaseConnectionSlot(1001);
    gs.releaseConnectionSlot(1002);
    try std.testing.expectEqual(@as(usize, 0), gs.active_connections_total);
    try std.testing.expectEqual(@as(usize, 0), gs.active_fds.count());
    try std.testing.expectEqual(@as(u32, 0), gs.metrics.active_connections);
}

test "connection slot enforces per-IP limit independently of other IPs" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    gs.max_connections_per_ip = 1;

    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(2001, "1.1.1.1"));
    // Second connection from the same IP is rejected.
    try std.testing.expectEqual(ConnectionSlotResult.over_ip_limit, try gs.tryAcquireConnectionSlot(2002, "1.1.1.1"));
    // A different IP is unaffected.
    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(2003, "2.2.2.2"));
    try std.testing.expectEqual(@as(usize, 2), gs.active_connections_total);
    try std.testing.expectEqual(@as(u32, 1), gs.active_connections_by_ip.get("1.1.1.1").?);

    gs.releaseConnectionSlot(2001);
    gs.releaseConnectionSlot(2003);
    // Per-IP bookkeeping is fully reclaimed (entry removed, duped key freed).
    try std.testing.expectEqual(@as(usize, 0), gs.active_connections_by_ip.count());
    try std.testing.expectEqual(@as(usize, 0), gs.fd_to_ip.count());
    try std.testing.expectEqual(@as(usize, 0), gs.active_connections_total);
}

test "connection slot enforces total memory budget via projection" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    gs.connection_memory_estimate_bytes = 100;
    gs.max_total_connection_memory_bytes = 250; // admits 2, rejects the 3rd

    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(3001, "10.0.0.1"));
    try std.testing.expectEqual(ConnectionSlotResult.accepted, try gs.tryAcquireConnectionSlot(3002, "10.0.0.2"));
    // Projected (2+1)*100 = 300 > 250 -> rejected.
    try std.testing.expectEqual(ConnectionSlotResult.over_global_memory_limit, try gs.tryAcquireConnectionSlot(3003, "10.0.0.3"));
    try std.testing.expectEqual(@as(usize, 2), gs.active_connections_total);
    try std.testing.expectEqual(@as(usize, 2), gs.active_fds.count());

    gs.releaseConnectionSlot(3001);
    gs.releaseConnectionSlot(3002);
    try std.testing.expectEqual(@as(usize, 0), gs.active_connections_total);
}

test "connection memory projection does not overflow at large counts" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    // A per-connection estimate near usize-max with a large existing count would
    // overflow a usize multiply; the projection widens to u128 so it rejects
    // deterministically instead of wrapping to a small value and admitting.
    gs.connection_memory_estimate_bytes = std.math.maxInt(usize);
    gs.max_total_connection_memory_bytes = std.math.maxInt(usize);
    gs.active_connections_total = 1_000_000;
    try std.testing.expectEqual(ConnectionSlotResult.over_global_memory_limit, try gs.tryAcquireConnectionSlot(4001, "10.0.0.1"));
    // Nothing was admitted, so no slot to release; counts unchanged.
    try std.testing.expectEqual(@as(usize, 0), gs.active_fds.count());
}

test "in-flight request slot rejects over limit and balances on release" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    gs.max_in_flight_requests = 2;

    try std.testing.expect(gs.tryAcquireRequestSlot());
    try std.testing.expect(gs.tryAcquireRequestSlot());
    // Third concurrent request is rejected without leaving a reservation behind.
    try std.testing.expect(!gs.tryAcquireRequestSlot());
    try std.testing.expectEqual(@as(u32, 2), gs.in_flight_requests.load(.acquire));

    gs.releaseRequestSlot();
    // A slot freed up, so the next acquire succeeds again.
    try std.testing.expect(gs.tryAcquireRequestSlot());
    gs.releaseRequestSlot();
    gs.releaseRequestSlot();
    try std.testing.expectEqual(@as(u32, 0), gs.in_flight_requests.load(.acquire));
}

test "in-flight request slot is unlimited and release is a no-op when disabled" {
    var gs: GatewayState = undefined;
    initSlotTestState(&gs, std.testing.allocator);
    defer deinitSlotTestState(&gs);
    gs.max_in_flight_requests = 0; // disabled

    var i: usize = 0;
    while (i < 1000) : (i += 1) try std.testing.expect(gs.tryAcquireRequestSlot());
    gs.releaseRequestSlot(); // must not underflow the counter
    try std.testing.expectEqual(@as(u32, 0), gs.in_flight_requests.load(.acquire));
}

// ---------------------------------------------------------------------------
// Upstream-pool / pending-upstream overload + metrics-JSON drift tests (#172).
//
// The upstream "connection pool exhausted" and "too many pending upstream
// requests" scenarios from #172 are not single env caps — they are governed by
// per-upstream active-request accounting (`upstream_active_requests`, used by
// the least-connections balancer to shed load) and the circuit breaker. These
// tests drive that real accounting to prove load sheds deterministically and
// leaves no accounting leak, and that the served metrics JSON can never drift
// from the canonical serializer.
// ---------------------------------------------------------------------------

fn initUpstreamTestState(gs: *GatewayState, allocator: std.mem.Allocator) void {
    gs.allocator = allocator;
    gs.tunnel_reactor = null;
    gs.acme_renewal_worker = null;
    gs.h2_request_executor = null;
    gs.upstream_mutex = .{};
    gs.circuit_mutex = .{};
    gs.metrics_mutex = .{};
    gs.metrics = http.metrics.Metrics.init();
    gs.upstream_rr_index = 0;
    gs.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{});
    gs.upstream_health = std.StringHashMap(UpstreamHealth).init(allocator);
    gs.upstream_active_requests = std.StringHashMap(usize).init(allocator);
}

fn deinitUpstreamTestState(gs: *GatewayState) void {
    var h_it = gs.upstream_health.iterator();
    while (h_it.next()) |entry| gs.allocator.free(entry.key_ptr.*);
    gs.upstream_health.deinit();
    var a_it = gs.upstream_active_requests.iterator();
    while (a_it.next()) |entry| gs.allocator.free(entry.key_ptr.*);
    gs.upstream_active_requests.deinit();
}

test "upstream active-request accounting saturates and drains without leaking" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);

    const url = "http://10.0.0.1:8080";
    var i: usize = 0;
    while (i < 64) : (i += 1) gs.recordUpstreamAttemptStart(url);
    // In-flight count tracks every pending upstream request exactly.
    try std.testing.expectEqual(@as(usize, 64), gs.upstream_active_requests.get(url).?);

    i = 0;
    while (i < 64) : (i += 1) gs.recordUpstreamAttemptEnd(url);
    // Draining to zero removes the entry and frees its duped key — no growth, no
    // leak (std.testing.allocator fails the test on any retained key).
    try std.testing.expectEqual(@as(?usize, null), gs.upstream_active_requests.get(url));
    try std.testing.expectEqual(@as(usize, 0), gs.upstream_active_requests.count());
}

test "least-connections selection sheds a saturated upstream to the idle one" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);

    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_active_health_interval_ms = 0;
    cfg.upstream_slow_start_ms = 0;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;

    const a = "http://a:8080";
    const b = "http://b:8080";
    const urls = [_][]const u8{ a, b };
    const weights = [_]u32{ 1, 1 };
    const pool = UpstreamPoolView{
        .fallback_url = "",
        .primary_urls = &urls,
        .primary_weights = &weights,
        .backup_urls = &.{},
    };

    // Saturate A with pending upstream requests; B stays idle.
    var i: usize = 0;
    while (i < 8) : (i += 1) gs.recordUpstreamAttemptStart(a);

    gs.upstream_mutex.lock();
    const chosen = gs.selectLeastConnectionsUpstreamLocked(&cfg, pool, 0);
    gs.upstream_mutex.unlock();
    // Deterministically sheds to the least-loaded healthy backend.
    try std.testing.expectEqualStrings(b, chosen.?);

    // With every backend unhealthy, selection returns null so the caller sheds
    // the request rather than queueing it without bound.
    gs.recordUpstreamFailure(&cfg, a);
    gs.recordUpstreamFailure(&cfg, b);
    gs.upstream_mutex.lock();
    const none = gs.selectLeastConnectionsUpstreamLocked(&cfg, pool, 0);
    gs.upstream_mutex.unlock();
    try std.testing.expectEqual(@as(?[]const u8, null), none);
}

test "gateway circuit breaker opens under upstream failure pressure" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);
    gs.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 3, .timeout_ms = 30_000 });

    gs.circuitRecordFailurePermit(gs.circuitTryAcquirePermit().?);
    gs.circuitRecordFailurePermit(gs.circuitTryAcquirePermit().?);
    gs.circuitRecordFailurePermit(gs.circuitTryAcquirePermit().?);
    // Open: requests fast-fail deterministically instead of piling onto a sick
    // upstream (the recovery timeout has not elapsed).
    try std.testing.expect(gs.circuitTryAcquirePermit() == null);
    try std.testing.expectEqualStrings("open", gs.circuitStateName());
}

test "upstream health JSON escapes configured origin URLs" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 30_000;
    const url = "http://origin/\"}],\"forged\":true";
    gs.recordUpstreamFailure(&cfg, url);

    const payload = try gs.upstreamHealthJson(std.testing.allocator);
    defer std.testing.allocator.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload, .{});
    defer parsed.deinit();
    const first = parsed.value.object.get("upstreams").?.array.items[0].object;
    try std.testing.expectEqualStrings(url, first.get("url").?.string);
    try std.testing.expect(first.get("forged") == null);
}

test "gateway circuit breaker recovers through a half-open probe" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);
    gs.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });

    gs.circuitRecordFailurePermit(gs.circuitTryAcquirePermit().?);
    // timeout_ms = 0 → the next acquire admits one probe in half-open state.
    const permit = gs.circuitTryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expectEqualStrings("half-open", gs.circuitStateName());
    gs.circuitRecordSuccessPermit(permit);
    try std.testing.expectEqualStrings("closed", gs.circuitStateName());
}

test "gateway proxy outcome accounting drives live circuit breaker" {
    var gs: GatewayState = undefined;
    initUpstreamTestState(&gs, std.testing.allocator);
    defer deinitUpstreamTestState(&gs);
    gs.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 2, .timeout_ms = 30_000 });

    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_max_fails = 0;

    gs.recordUpstreamFailure(&cfg, "http://origin.example");
    gs.recordUpstreamFailure(&cfg, "http://origin.example");
    try std.testing.expect(gs.circuitTryAcquirePermit() != null);
    try std.testing.expectEqualStrings("closed", gs.circuitStateName());

    gs.recordProxyUpstreamFailure(&cfg, "http://origin.example", gs.circuitTryAcquirePermit().?);
    try std.testing.expect(gs.circuitTryAcquirePermit() != null);
    gs.recordProxyUpstreamFailure(&cfg, "http://origin.example", gs.circuitTryAcquirePermit().?);

    try std.testing.expect(gs.circuitTryAcquirePermit() == null);
    try std.testing.expectEqualStrings("open", gs.circuitStateName());
}

fn initMetricsJsonTestState(gs: *GatewayState, allocator: std.mem.Allocator) void {
    gs.allocator = allocator;
    gs.tunnel_reactor = null;
    gs.acme_renewal_worker = null;
    gs.h2_request_executor = null;
    gs.connection_mutex = .{};
    gs.metrics_mutex = .{};
    gs.runtime_mutex = .{};
    gs.metrics = http.metrics.Metrics.init();
    gs.mux_subscriptions_by_device = std.StringHashMap(usize).init(allocator);
    // metricsToJson/metricsToPrometheus overlay the upstream pool's live
    // counters, so the pool must be a valid (empty) instance here.
    gs.upstream_pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    gs.h2_pool = http.upstream_h2.H2ConnPool.init(allocator, .{});
    gs.http3_advertisement_state = .disabled;
    // metricsToPrometheus overlays the H3 runtime's transport snapshot
    // (#256-G) when one is attached; this fixture has none.
    gs.http3_runtime = null;
    gs.proxy_buffer_limits = http.proxy_buffer_account.Limits.defaults();
    // The state starts as `undefined`, so every field the metrics path reads
    // has to be set here — the aggregate account is rendered as a gauge, and
    // leaving it uninitialized would put garbage in the served metrics.
    gs.proxy_buffer_global_account = http.proxy_buffer_account.Aggregate.init(
        .global,
        gs.proxy_buffer_limits.global_hard_limit,
    );
    gs.tls_buffer_limits = @import("tls_core").encrypted_stream.BufferLimits.defaults();
}

test "served metrics JSON exposes every counter the canonical serializer does" {
    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.mux_subscriptions_by_device.deinit();

    // Drive a couple of counters that the previously hand-maintained served
    // serializer had drifted away from.
    gs.metrics.recordRequest(200);
    gs.metrics.event_loop_iterations = 7;
    gs.metrics.health_probe_runs = 3;

    const served = try gs.metricsToJson(std.testing.allocator);
    defer std.testing.allocator.free(served);
    const canonical = try gs.metrics.toJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);

    var canon_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, canonical, .{});
    defer canon_parsed.deinit();
    var served_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, served, .{});
    defer served_parsed.deinit();

    // Every canonical counter must appear in the served JSON; this fails the
    // moment a new Metrics field is added without flowing through to the status
    // endpoint, which is exactly the drift that dropped event_loop_iterations
    // and health_probe_runs before the dedup.
    var it = canon_parsed.value.object.iterator();
    while (it.next()) |entry| {
        try std.testing.expect(served_parsed.value.object.contains(entry.key_ptr.*));
    }
    // The served endpoint additionally carries the per-device mux breakdown.
    try std.testing.expect(served_parsed.value.object.contains("mux_subscriptions_by_device"));
    // Explicit regression pins for the two fields the old serializer had lost.
    try std.testing.expect(served_parsed.value.object.contains("event_loop_iterations"));
    try std.testing.expect(served_parsed.value.object.contains("health_probe_runs"));
}

test "served Prometheus metrics expose h2 streaming upload fallback counter" {
    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.h2_pool.deinit();
    defer gs.upstream_pool.deinit();
    defer gs.mux_subscriptions_by_device.deinit();

    gs.upstream_pool.recordH2StreamingUploadFallback();
    try gs.mux_subscriptions_by_device.put("device\"}\\metric=\"forged", 3);

    const prom = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "# HELP tardigrade_upstream_h2_streaming_upload_fallback_total Streaming upload requests that requested h2/h2c upstreams but fell back to h1 because the h2 pool was unavailable") != null);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_upstream_h2_streaming_upload_fallback_total counter") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_upstream_h2_streaming_upload_fallback_total 1\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_config_limit_bytes{direction=\"upstream_to_downstream\",scope=\"stream\",limit=\"high\"} 786432\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_config_limit_bytes{queue=\"outbound_ciphertext\",limit=\"hard\"}") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http3_effective_state{state=\"disabled\"} 1\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_mux_device_channels{device_id=\"device\\\"}\\\\metric=\\\"forged\"} 3\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "metric=\"forged\"") == null);
}

test "served Prometheus metrics expose bounded ACME renewal status labeled by group-id digest, never a hostname" {
    // `overlayAcmeRenewalStatus` only ever touches `group_list`/`statuses`
    // (through `snapshotStatus`'s own mutex), so a worker built from
    // `undefined` with just those fields set is a faithful, minimal stand-in
    // for the live renewal thread this test never needs to start.
    var worker: acme_renewal.Worker = undefined;
    worker.allocator = std.testing.allocator;
    worker.group_list = try http.acme.groups.parse("alpha.example.test;beta.example.test");
    worker.status_mutex = .{};
    worker.statuses = @splat(.{});
    worker.statuses[0] = .{ .not_after = 1_700_100_000, .next_attempt_at = 1_700_050_000, .consecutive_failures = 2, .last_failure_class = .transport };
    worker.statuses[1] = .{ .not_after = null, .next_attempt_at = 1_700_000_500, .consecutive_failures = 0, .last_failure_class = null };

    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.h2_pool.deinit();
    defer gs.upstream_pool.deinit();
    defer gs.mux_subscriptions_by_device.deinit();
    gs.acme_renewal_worker = &worker;

    const prom = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(prom);

    var id_buf_a: [http.acme.groups.group_id_len]u8 = undefined;
    const group_a = http.acme.groups.groupId(&id_buf_a, &.{"alpha.example.test"});
    var id_buf_b: [http.acme.groups.group_id_len]u8 = undefined;
    const group_b = http.acme.groups.groupId(&id_buf_b, &.{"beta.example.test"});

    const line_a_not_after = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_not_after_seconds{{group=\"{s}\"}} 1700100000\n", .{group_a});
    defer std.testing.allocator.free(line_a_not_after);
    try std.testing.expect(std.mem.find(u8, prom, line_a_not_after) != null);
    const line_a_next = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_next_attempt_timestamp_seconds{{group=\"{s}\"}} 1700050000\n", .{group_a});
    defer std.testing.allocator.free(line_a_next);
    try std.testing.expect(std.mem.find(u8, prom, line_a_next) != null);
    const line_a_failures = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_consecutive_failures{{group=\"{s}\"}} 2\n", .{group_a});
    defer std.testing.allocator.free(line_a_failures);
    try std.testing.expect(std.mem.find(u8, prom, line_a_failures) != null);
    const line_a_class = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_last_failure{{group=\"{s}\",class=\"transport\"}} 1\n", .{group_a});
    defer std.testing.allocator.free(line_a_class);
    try std.testing.expect(std.mem.find(u8, prom, line_a_class) != null);
    const line_a_no_class = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_last_failure{{group=\"{s}\",class=\"persistence\"}} 0\n", .{group_a});
    defer std.testing.allocator.free(line_a_no_class);
    try std.testing.expect(std.mem.find(u8, prom, line_a_no_class) != null);

    // `beta.example.test`'s absent `not_after` (no committed certificate
    // yet) must never render a bogus zero/sentinel gauge value.
    const missing_not_after = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_not_after_seconds{{group=\"{s}\"}}", .{group_b});
    defer std.testing.allocator.free(missing_not_after);
    try std.testing.expect(std.mem.find(u8, prom, missing_not_after) == null);
    const line_b_next = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_next_attempt_timestamp_seconds{{group=\"{s}\"}} 1700000500\n", .{group_b});
    defer std.testing.allocator.free(line_b_next);
    try std.testing.expect(std.mem.find(u8, prom, line_b_next) != null);
    const line_b_no_failure = try std.fmt.allocPrint(std.testing.allocator, "tardigrade_acme_renewal_last_failure{{group=\"{s}\",class=\"transport\"}} 0\n", .{group_b});
    defer std.testing.allocator.free(line_b_no_failure);
    try std.testing.expect(std.mem.find(u8, prom, line_b_no_failure) != null);

    // Never the raw hostname, never a CA URL -- only the bounded group-id
    // digest label (design §9.4).
    try std.testing.expect(std.mem.find(u8, prom, "alpha.example.test") == null);
    try std.testing.expect(std.mem.find(u8, prom, "beta.example.test") == null);
}

fn deinitCommandLifecycleTestMap(gs: *GatewayState) void {
    var it = gs.command_lifecycle.iterator();
    while (it.next()) |entry| {
        gs.allocator.free(entry.key_ptr.*);
        gs.allocator.free(entry.value_ptr.command_type);
        gs.allocator.free(entry.value_ptr.correlation_id);
        gs.allocator.free(entry.value_ptr.identity);
        gs.allocator.free(entry.value_ptr.response_body);
        gs.allocator.free(entry.value_ptr.response_content_type);
        gs.allocator.free(entry.value_ptr.error_message);
    }
    gs.command_lifecycle.deinit();
}

fn deinitApprovalTestMap(gs: *GatewayState) void {
    var it = gs.approvals.iterator();
    while (it.next()) |entry| {
        gs.allocator.free(entry.key_ptr.*);
        entry.value_ptr.deinit(gs.allocator);
    }
    gs.approvals.deinit();
}

test "command lifecycle JSON escapes fields and validates embedded upstream JSON" {
    var gs: GatewayState = undefined;
    gs.allocator = std.testing.allocator;
    gs.command_mutex = .{};
    gs.command_lifecycle = std.StringHashMap(CommandLifecycleEntry).init(gs.allocator);
    defer deinitCommandLifecycleTestMap(&gs);

    const command_id = "cmd-\"quoted\n";
    try gs.commandLifecycleCreate(command_id, "run\"}],\"forged\":true", "corr\r\nquoted", "identity\\\"");
    try std.testing.expectError(
        error.CommandAlreadyExists,
        gs.commandLifecycleCreate(command_id, "duplicate", "duplicate", "duplicate"),
    );
    gs.commandLifecycleSetCompleted(command_id, 200, "{\"nested\":[1,true]}", "application/json\r\nx-forged: yes");

    const json = gs.commandLifecycleSnapshotJson(std.testing.allocator, command_id) orelse return error.TestExpectedJson;
    defer std.testing.allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(command_id, object.get("command_id").?.string);
    try std.testing.expectEqualStrings("run\"}],\"forged\":true", object.get("command").?.string);
    try std.testing.expectEqualStrings("corr\r\nquoted", object.get("correlation_id").?.string);
    try std.testing.expectEqualStrings("identity\\\"", object.get("identity").?.string);
    try std.testing.expectEqualStrings("application/json\r\nx-forged: yes", object.get("response_content_type").?.string);
    try std.testing.expectEqual(@as(i64, 1), object.get("response_body").?.object.get("nested").?.array.items[0].integer);

    // A body which merely starts like JSON is data, not permission to splice
    // arbitrary bytes into the lifecycle response.
    gs.commandLifecycleSetCompleted(command_id, 502, "{\"closed\":true} trailing", "application/json");
    const invalid_json_body = gs.commandLifecycleSnapshotJson(std.testing.allocator, command_id) orelse return error.TestExpectedJson;
    defer std.testing.allocator.free(invalid_json_body);
    var invalid_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, invalid_json_body, .{});
    defer invalid_parsed.deinit();
    try std.testing.expectEqualStrings("", invalid_parsed.value.object.get("response_body").?.string);
    try std.testing.expect(invalid_parsed.value.object.get("forged") == null);
}

test "approval JSON and escalation webhook escape untrusted fields" {
    var gs: GatewayState = undefined;
    gs.allocator = std.testing.allocator;
    gs.approval_mutex = .{};
    gs.approval_persist_mutex = .{};
    gs.approvals = std.StringHashMap(ApprovalEntry).init(gs.allocator);
    gs.approval_store_path = "";
    gs.approval_escalation_webhook = "";
    gs.approval_ttl_ms = 60_000;
    gs.approval_max_pending_per_identity = 0;
    defer deinitApprovalTestMap(&gs);

    const identity = "alice\"},\"approved\":true,\n\"tail\":\"";
    const command_id = "cmd-\"quoted";
    const created = try gs.approvalCreate(std.testing.allocator, "POST", "/deploy?x=\"quoted\"", identity, command_id);
    defer std.testing.allocator.free(created.token);
    try std.testing.expect(gs.approvalRespond(created.token, .approve, "reviewer\r\n\"quoted\""));

    const snapshot = gs.approvalSnapshotJson(std.testing.allocator, created.token) orelse return error.TestExpectedJson;
    defer std.testing.allocator.free(snapshot);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, snapshot, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(identity, object.get("identity").?.string);
    try std.testing.expectEqualStrings(command_id, object.get("command_id").?.string);
    try std.testing.expectEqualStrings("reviewer\r\n\"quoted\"", object.get("decided_by").?.string);
    try std.testing.expect(object.get("approved") == null);

    const entry = gs.approvals.getPtr(created.token).?;
    const webhook = gs.buildApprovalWebhookPayloadLocked(created.token, entry) orelse return error.TestExpectedJson;
    defer std.testing.allocator.free(webhook);
    var webhook_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, webhook, .{});
    defer webhook_parsed.deinit();
    try std.testing.expectEqualStrings(identity, webhook_parsed.value.object.get("identity").?.string);
    try std.testing.expect(webhook_parsed.value.object.get("approved") == null);
}

test "approved tokens remain exact-scoped, identity-bound, and time-bounded" {
    var gs: GatewayState = undefined;
    gs.allocator = std.testing.allocator;
    gs.approval_mutex = .{};
    gs.approval_persist_mutex = .{};
    gs.approvals = std.StringHashMap(ApprovalEntry).init(gs.allocator);
    gs.approval_store_path = "";
    gs.approval_escalation_webhook = "";
    gs.approval_ttl_ms = 60_000;
    gs.approval_max_pending_per_identity = 0;
    defer deinitApprovalTestMap(&gs);

    const created = try gs.approvalCreate(std.testing.allocator, "POST", "/deploy/.*", "alice", null);
    defer std.testing.allocator.free(created.token);
    try std.testing.expect(gs.approvalRespond(created.token, .approve, "reviewer"));
    try std.testing.expectEqual(ApprovalValidation.approved, gs.approvalValidate(created.token, "POST", "/deploy/.*", "alice"));
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(created.token, "POST", "/deploy/admin", "alice"));
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(created.token, "GET", "/deploy/.*", "alice"));
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(created.token, "POST", "/deploy/.*", null));
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(created.token, "POST", "/deploy/.*", "mallory"));

    gs.approvals.getPtr(created.token).?.expires_ms = compat.milliTimestamp() - 1;
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(created.token, "POST", "/deploy/.*", "alice"));

    const wildcard = try gs.approvalCreate(std.testing.allocator, "*", "/deploy", "", null);
    defer std.testing.allocator.free(wildcard.token);
    try std.testing.expect(gs.approvalRespond(wildcard.token, .approve, "reviewer"));
    try std.testing.expectEqual(ApprovalValidation.invalid, gs.approvalValidate(wildcard.token, "POST", "/deploy", null));
}

test "command and approval mutations remain atomic on allocation failure" {
    var gs: GatewayState = undefined;
    gs.allocator = std.testing.allocator;
    gs.command_mutex = .{};
    gs.command_lifecycle = std.StringHashMap(CommandLifecycleEntry).init(gs.allocator);
    defer deinitCommandLifecycleTestMap(&gs);
    try gs.commandLifecycleCreate("cmd", "run", "corr", "identity");

    var command_fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    gs.allocator = command_fail.allocator();
    gs.commandLifecycleSetCompleted("cmd", 200, "{\"ok\":true}", "application/json");
    gs.allocator = std.testing.allocator;
    const command = gs.command_lifecycle.get("cmd").?;
    try std.testing.expectEqual(CommandLifecycleStatus.pending, command.status);
    try std.testing.expectEqual(@as(u16, 0), command.response_status);
    try std.testing.expectEqualStrings("", command.response_body);

    gs.approval_mutex = .{};
    gs.approval_persist_mutex = .{};
    gs.approvals = std.StringHashMap(ApprovalEntry).init(gs.allocator);
    gs.approval_store_path = "";
    gs.approval_escalation_webhook = "";
    gs.approval_ttl_ms = 60_000;
    gs.approval_max_pending_per_identity = 0;
    defer deinitApprovalTestMap(&gs);
    const created = try gs.approvalCreate(std.testing.allocator, "POST", "/deploy", "identity", null);
    defer std.testing.allocator.free(created.token);

    var approval_fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    gs.allocator = approval_fail.allocator();
    try std.testing.expect(!gs.approvalRespond(created.token, .approve, "reviewer"));
    gs.allocator = std.testing.allocator;
    const approval = gs.approvals.get(created.token).?;
    try std.testing.expectEqual(ApprovalStatus.pending, approval.status);
    try std.testing.expectEqualStrings("", approval.decided_by);
}

test "command lifecycle creation releases every partial allocation on OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var gs: GatewayState = undefined;
            gs.allocator = allocator;
            gs.tunnel_reactor = null;
            gs.acme_renewal_worker = null;
            gs.h2_request_executor = null;
            gs.command_mutex = .{};
            gs.command_lifecycle = std.StringHashMap(CommandLifecycleEntry).init(allocator);
            defer deinitCommandLifecycleTestMap(&gs);
            try gs.commandLifecycleCreate("cmd", "run", "corr", "identity");
        }
    }.run, .{});
}

test "approval creation releases every partial allocation on OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var gs: GatewayState = undefined;
            gs.allocator = allocator;
            gs.tunnel_reactor = null;
            gs.acme_renewal_worker = null;
            gs.h2_request_executor = null;
            gs.approval_mutex = .{};
            gs.approval_persist_mutex = .{};
            gs.approvals = std.StringHashMap(ApprovalEntry).init(allocator);
            gs.approval_store_path = "";
            gs.approval_escalation_webhook = "";
            gs.approval_ttl_ms = 60_000;
            gs.approval_max_pending_per_identity = 0;
            defer deinitApprovalTestMap(&gs);
            const created = try gs.approvalCreate(allocator, "POST", "/deploy", "identity", "cmd");
            defer allocator.free(created.token);
        }
    }.run, .{});
}

test "#256-G: served Prometheus metrics overlay the attached H3 runtime's transport snapshot" {
    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.h2_pool.deinit();
    defer gs.upstream_pool.deinit();
    defer gs.mux_subscriptions_by_device.deinit();

    // `snapshot()` only ever touches `snapshot_mutex`/`snapshot_state`, so a
    // Runtime with just those two fields populated is a safe, minimal
    // fixture — the rest legitimately stays `undefined` for this test.
    var rt: http.http3_runtime.Runtime = undefined;
    rt.snapshot_mutex = .{};
    rt.snapshot_state = .{
        .packets_sent = 42,
        .packets_received = 41,
        .pmtu_probes_sent = 3,
        .pmtu_black_holes = 1,
        .plpmtu_last_bytes = 1452,
        .plpmtu_lifetime_min_bytes = 1200,
        .plpmtu_lifetime_max_bytes = 1452,
        .ecn_enabled = true,
        .ecn_marked_sent = 10,
        .ecn_paths_validated = 2,
        .ecn_paths_disabled = 1,
        .ecn_ce_received = 5,
        .udp_buffers = .{
            .recv = .{ .requested_bytes = 4_194_304, .effective_bytes = 2_097_152, .granted_bytes = 1_048_576, .status = .clamped },
            .send = .{ .requested_bytes = 4_194_304, .effective_bytes = 4_194_304, .granted_bytes = 4_194_304, .status = .applied },
        },
    };
    gs.http3_runtime = &rt;

    const prom = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_sent_total 42") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pmtu_probes_total 3") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_effective_plpmtu_bytes_lifetime_min 1200") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_enabled 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_paths_disabled_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_requested_bytes{direction=\"recv\"} 4194304") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_effective_bytes{direction=\"recv\"} 2097152") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"recv\",status=\"clamped\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"send\",status=\"applied\"} 1") != null);
}

test "served Prometheus metrics expose the aggregate bytes the global limit is enforced against" {
    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.h2_pool.deinit();
    defer gs.upstream_pool.deinit();
    defer gs.mux_subscriptions_by_device.deinit();

    gs.proxy_buffer_global_account.setHardLimit(4096);
    try gs.proxy_buffer_global_account.reserve(.upstream_to_downstream, 1500);

    // A buffered response also moves the generic roll-up gauge. The two series
    // are intentionally different quantities: the roll-up covers every
    // proxy-owned buffer, while the aggregate gauge is exactly what the
    // configured global hard limit is checked against.
    gs.metrics.recordProxyBufferedRequest(64, 5);

    const prom = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_buffer_aggregate_bytes_current{direction=\"upstream_to_downstream\",scope=\"global\"} 1500\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_buffer_aggregate_bytes_current{direction=\"downstream_to_upstream\",scope=\"global\"} 0\n") != null);
    // The roll-up reports the buffered response, not the enforced reservation.
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffered_bytes_current{direction=\"upstream_to_downstream\",scope=\"global\"} 64\n") != null);

    gs.proxy_buffer_global_account.release(.upstream_to_downstream, 1500);
    const drained = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(drained);
    try std.testing.expect(std.mem.find(u8, drained, "tardigrade_proxy_buffer_aggregate_bytes_current{direction=\"upstream_to_downstream\",scope=\"global\"} 0\n") != null);
}

test "served Prometheus metrics reflect updated proxy buffer limit snapshot" {
    var gs: GatewayState = undefined;
    initMetricsJsonTestState(&gs, std.testing.allocator);
    defer gs.h2_pool.deinit();
    defer gs.upstream_pool.deinit();
    defer gs.mux_subscriptions_by_device.deinit();

    gs.runtime_mutex.lock();
    gs.proxy_buffer_limits = .{
        .per_stream_low_watermark = 128 * 1024,
        .per_stream_high_watermark = 384 * 1024,
        .per_stream_hard_limit = 512 * 1024,
        .per_origin_hard_limit = 2 * 1024 * 1024,
        .global_hard_limit = 4 * 1024 * 1024,
    };
    gs.tls_buffer_limits.outbound_ciphertext.high = gs.tls_buffer_limits.outbound_ciphertext.low + 16;
    gs.runtime_mutex.unlock();

    const prom = try gs.metricsToPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_config_limit_bytes{direction=\"upstream_to_downstream\",scope=\"stream\",limit=\"high\"} 393216\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_config_limit_bytes{direction=\"downstream_to_upstream\",scope=\"global\",limit=\"hard\"} 4194304\n") != null);
}

fn initApprovalTestState(gs: *GatewayState, allocator: std.mem.Allocator, store_path: []const u8) void {
    gs.allocator = allocator;
    gs.tunnel_reactor = null;
    gs.acme_renewal_worker = null;
    gs.h2_request_executor = null;
    gs.approval_mutex = .{};
    gs.approval_persist_mutex = .{};
    gs.approvals = std.StringHashMap(ApprovalEntry).init(allocator);
    gs.approval_store_path = store_path;
    gs.approval_escalation_webhook = "";
    gs.approval_ttl_ms = 300_000;
    gs.approval_max_pending_per_identity = 0;
    gs.logger = http.logger.Logger.init(.err, "test");
}

/// Insert a pending approval WITHOUT triggering persistence.
///
/// `approvalCreate` persists as part of its contract, which would re-enter
/// `approval_persist_mutex`; these tests drive persistence explicitly.
fn insertApprovalForTest(gs: *GatewayState, token: []const u8, path: []const u8, identity: []const u8) !void {
    gs.approval_mutex.lock();
    defer gs.approval_mutex.unlock();
    const now = compat.milliTimestamp();
    try gs.approvals.put(try gs.allocator.dupe(u8, token), .{
        .method = try gs.allocator.dupe(u8, "POST"),
        .path = try gs.allocator.dupe(u8, path),
        .identity = try gs.allocator.dupe(u8, identity),
        .command_id = try gs.allocator.dupe(u8, ""),
        .status = .pending,
        .created_ms = now,
        .expires_ms = now + 300_000,
        .decided_ms = 0,
        .decided_by = try gs.allocator.dupe(u8, ""),
    });
}

fn deinitApprovalTestState(gs: *GatewayState) void {
    var it = gs.approvals.iterator();
    while (it.next()) |kv| {
        gs.allocator.free(kv.key_ptr.*);
        var entry = kv.value_ptr.*;
        entry.deinit(gs.allocator);
    }
    gs.approvals.deinit();
}

test "approval persistence snapshots after winning the persist lock, not before" {
    // Regression for the stale-snapshot ordering bug: a unique temp filename
    // serializes nothing. A persist that was called early but ran late used to
    // write the state it observed at call time, overwriting newer approvals.
    //
    // The race is made deterministic by holding the persistence lock while a
    // second mutation lands: the blocked writer must publish the state as of
    // when it acquires the lock, so the newer approval has to be in the file.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/approvals.json", .{tmp_abs});
    defer allocator.free(path);

    var gs: GatewayState = undefined;
    initApprovalTestState(&gs, allocator, path);
    defer deinitApprovalTestState(&gs);

    try insertApprovalForTest(&gs, "apr-first", "/first", "alice");

    // Block persistence, then start a writer that must wait for the lock.
    gs.approval_persist_mutex.lock();
    const Runner = struct {
        fn run(state: *GatewayState) void {
            state.persistApprovals();
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&gs});

    // While that writer is queued, a newer approval is accepted. A snapshot
    // taken at call time would not contain it.
    try insertApprovalForTest(&gs, "apr-second", "/second", "bob");

    gs.approval_persist_mutex.unlock();
    thread.join();

    const loaded = try http.approval_store.load(allocator, path);
    defer http.approval_store.freeLoaded(allocator, loaded);

    var saw_first = false;
    var saw_second = false;
    for (loaded) |entry| {
        if (std.mem.eql(u8, entry.path, "/first")) saw_first = true;
        if (std.mem.eql(u8, entry.path, "/second")) saw_second = true;
    }
    try std.testing.expect(saw_first);
    // The durable file holds the newest complete state, not a stale snapshot.
    try std.testing.expect(saw_second);
    try std.testing.expectEqual(@as(usize, 2), loaded.len);
}

test "concurrent approval persists do not lose the final state" {
    // Companion to the ordering test: many interleaved persists must leave a
    // complete, parseable file rather than one writer's temp file unlinked by
    // another's, or a torn/partial store.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/approvals.json", .{tmp_abs});
    defer allocator.free(path);

    var gs: GatewayState = undefined;
    initApprovalTestState(&gs, allocator, path);
    defer deinitApprovalTestState(&gs);

    const Worker = struct {
        fn run(state: *GatewayState, prefix: []const u8, label: []const u8) void {
            var i: usize = 0;
            while (i < 8) : (i += 1) {
                var token_buf: [32]u8 = undefined;
                const token = std.fmt.bufPrint(&token_buf, "{s}-{d}", .{ prefix, i }) catch return;
                insertApprovalForTest(state, token, label, "alice") catch return;
                // Every mutation persists, exactly as the request paths do, so
                // the writers genuinely contend on the same store file.
                state.persistApprovals();
            }
        }
    };
    const a = try std.Thread.spawn(.{}, Worker.run, .{ &gs, "apr-a", "/a" });
    const b = try std.Thread.spawn(.{}, Worker.run, .{ &gs, "apr-b", "/b" });
    a.join();
    b.join();

    // A final persist publishes the terminal state; it must match memory
    // exactly, proving no earlier writer clobbered it with a stale snapshot.
    gs.persistApprovals();
    const loaded = try http.approval_store.load(allocator, path);
    defer http.approval_store.freeLoaded(allocator, loaded);
    try std.testing.expectEqual(@as(usize, 16), loaded.len);
}

test "an in-flight config lease keeps enforcing its own ACL across a reload" {
    // Regression for the ACL hot-reload finding. Two defects are covered:
    //
    //  1. Use-after-free: reload used to `deinit()` the live ACL while a worker
    //     could be inside `check()` on its rule slice.
    //  2. Mixed generations: a request holding an older config lease could
    //     observe the NEWER (or absent) ACL and skip a denial that its own
    //     leased configuration still required.
    //
    // A mutex alone fixes only the first. Pairing ACL lifetime with the config
    // generation fixes both, which is what this asserts.
    const allocator = std.testing.allocator;

    var old_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    old_cfg.access_control_rules = "deny 203.0.113.0/24, allow 0.0.0.0/0";

    var store = try ReloadableConfigStore.initBorrowed(allocator, &old_cfg);
    defer store.deinit();
    store.setInitialAccessControl(&old_cfg, try http.access_control.AccessControl.fromConfig(
        allocator,
        old_cfg.access_control_rules,
        .allow,
    ));

    // A request begins under the old generation and holds its lease.
    var in_flight = store.acquire();
    try std.testing.expect(in_flight.cfg.parsed_access_control != null);
    try std.testing.expectEqual(
        http.access_control.AccessResult.denied,
        in_flight.cfg.parsed_access_control.?.check("203.0.113.7"),
    );

    // Meanwhile a reload installs a generation with NO access control at all.
    const new_cfg = try allocator.create(edge_config.EdgeConfig);
    new_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    new_cfg.access_control_rules = "";
    const prepared = try store.prepareOwned(new_cfg);
    ReloadableConfigStore.setPreparedAccessControl(prepared, null);
    store.installPrepared(prepared);

    // The in-flight request still enforces the ACL it leased. Previously this
    // request would have seen `state.access_control == null` and allowed the
    // very address its own configuration denies.
    try std.testing.expect(in_flight.cfg.parsed_access_control != null);
    try std.testing.expectEqual(
        http.access_control.AccessResult.denied,
        in_flight.cfg.parsed_access_control.?.check("203.0.113.7"),
    );

    // A request that starts after the reload sees the new policy.
    var fresh = store.acquire();
    try std.testing.expect(fresh.cfg.parsed_access_control == null);
    fresh.release();

    // Releasing the last old lease is what retires the old generation and frees
    // its ACL — never while a request could still be inside `check()`.
    in_flight.release();
}

test "a successful reload stamps the superseded generation once; failed reloads never do (#812)" {
    const allocator = std.testing.allocator;
    var first_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    first_cfg.access_control_rules = "";
    var store = try ReloadableConfigStore.initBorrowed(allocator, &first_cfg);
    defer store.deinit();

    // A tunnel admitted under the first generation holds its lease.
    var tunnel_lease = store.acquire();
    defer tunnel_lease.release();
    try std.testing.expectEqual(@as(u64, 0), tunnel_lease.version.superseded_at_ms.load(.acquire));

    // A reload that is prepared but rejected is destroyed, never installed.
    const rejected_cfg = try allocator.create(edge_config.EdgeConfig);
    rejected_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    rejected_cfg.access_control_rules = "";
    store.destroyVersion(try store.prepareOwned(rejected_cfg));
    try std.testing.expectEqual(@as(u64, 0), tunnel_lease.version.superseded_at_ms.load(.acquire));

    const second_cfg = try allocator.create(edge_config.EdgeConfig);
    second_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    second_cfg.access_control_rules = "";
    const second = try store.prepareOwned(second_cfg);
    store.installPrepared(second);
    const first_stamp = tunnel_lease.version.superseded_at_ms.load(.acquire);
    try std.testing.expect(first_stamp != 0);
    try std.testing.expectEqual(@as(u64, 0), second.superseded_at_ms.load(.acquire));

    // A later reload supersedes the second generation; the first generation's
    // stamp, and so any drain deadline derived from it, does not move.
    compat.sleepNs(5 * std.time.ns_per_ms);
    const third_cfg = try allocator.create(edge_config.EdgeConfig);
    third_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    third_cfg.access_control_rules = "";
    store.installPrepared(try store.prepareOwned(third_cfg));
    try std.testing.expectEqual(first_stamp, tunnel_lease.version.superseded_at_ms.load(.acquire));
}

test "response-stream admission retains its config generation across reloads (#841)" {
    const allocator = std.testing.allocator;
    var first_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    first_cfg.access_control_rules = "";
    first_cfg.proxy_response_stream_max_active = 1;
    first_cfg.proxy_response_stream_reload = .drain;
    first_cfg.proxy_response_stream_reload_timeout_ms = 25;
    var store = try ReloadableConfigStore.initBorrowed(allocator, &first_cfg);
    defer store.deinit();
    var lifecycle: http.response_stream_lifecycle.Lifecycle = .{};

    var request_lease = store.acquire();
    var admission = tryReserveResponseStream(&lifecycle, &request_lease, .{ .reload_timeout_ms = 7 }, 100).?;
    defer admission.release();
    request_lease.release();
    try std.testing.expectEqual(@as(u64, 1), admission.generation);
    try std.testing.expectEqual(http.response_stream_lifecycle.ReloadPolicy.drain, admission.policy.reload);
    try std.testing.expect(admission.supersededAtMs() == null);
    try std.testing.expectEqual(@as(u32, 1), lifecycle.activeCount());

    // Preparing and rejecting a reload cannot schedule this stream to drain.
    const rejected_cfg = try allocator.create(edge_config.EdgeConfig);
    rejected_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    rejected_cfg.access_control_rules = "";
    store.destroyVersion(try store.prepareOwned(rejected_cfg));
    try std.testing.expect(admission.supersededAtMs() == null);
    try std.testing.expect(admission.reloadDeadlineMs() == null);

    // Only installation stamps the retained generation, and the deadline uses
    // the location override captured at admission.
    const next_cfg = try allocator.create(edge_config.EdgeConfig);
    next_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    next_cfg.access_control_rules = "";
    store.installPrepared(try store.prepareOwned(next_cfg));
    const stamp = admission.supersededAtMs().?;
    try std.testing.expectEqual(stamp + 7, admission.reloadDeadlineMs().?);
}

test "response-stream capacity failure retains neither slot nor generation (#841)" {
    const allocator = std.testing.allocator;
    var cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.access_control_rules = "";
    cfg.proxy_response_stream_max_active = 1;
    var store = try ReloadableConfigStore.initBorrowed(allocator, &cfg);
    defer store.deinit();
    var lifecycle: http.response_stream_lifecycle.Lifecycle = .{};
    var request_lease = store.acquire();
    defer request_lease.release();

    var first = tryReserveResponseStream(&lifecycle, &request_lease, .{}, 0).?;
    try std.testing.expect(tryReserveResponseStream(&lifecycle, &request_lease, .{}, 0) == null);
    try std.testing.expectEqual(@as(u32, 1), lifecycle.activeCount());
    first.release();
    try std.testing.expectEqual(@as(u32, 0), lifecycle.activeCount());
}

test "a reloaded ACL is published atomically with its own generation" {
    // The inverse direction: a reload that ADDS an ACL must not leave a window
    // where the new configuration is live but its ACL is not, and old leases
    // must not start enforcing rules their generation never had.
    const allocator = std.testing.allocator;

    var old_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    old_cfg.access_control_rules = "";
    var store = try ReloadableConfigStore.initBorrowed(allocator, &old_cfg);
    defer store.deinit();
    store.setInitialAccessControl(&old_cfg, null);

    var permissive_lease = store.acquire();
    try std.testing.expect(permissive_lease.cfg.parsed_access_control == null);

    const new_cfg = try allocator.create(edge_config.EdgeConfig);
    new_cfg.* = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    // The version owns this config, so `destroyVersion` frees its fields: the
    // rules must be a real allocation, not a literal.
    new_cfg.access_control_rules = try allocator.dupe(u8, "deny 198.51.100.0/24, allow 0.0.0.0/0");
    const prepared = try store.prepareOwned(new_cfg);
    ReloadableConfigStore.setPreparedAccessControl(prepared, try http.access_control.AccessControl.fromConfig(
        allocator,
        new_cfg.access_control_rules,
        .allow,
    ));
    store.installPrepared(prepared);

    // New generation: ACL is already attached the moment it becomes current.
    var strict_lease = store.acquire();
    try std.testing.expectEqual(
        http.access_control.AccessResult.denied,
        strict_lease.cfg.parsed_access_control.?.check("198.51.100.5"),
    );
    // Old generation: unchanged, still permissive.
    try std.testing.expect(permissive_lease.cfg.parsed_access_control == null);

    strict_lease.release();
    permissive_lease.release();
}

test "discovery-only pool: sticky affinity and priority groups (#766)" {
    const allocator = std.testing.allocator;
    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    const original_srv_name = cfg.upstream_srv_name;
    cfg.upstream_srv_name = "_api._tcp.service.test";
    defer cfg.upstream_srv_name = original_srv_name; // cfg.deinit frees the original

    var gs: GatewayState = undefined;
    gs.upstream_mutex = .{};
    gs.metrics_mutex = .{};
    gs.metrics = http.metrics.Metrics.init();
    gs.upstream_rr_index = 0;
    gs.upstream_health = std.StringHashMap(UpstreamHealth).init(allocator);
    defer {
        var it = gs.upstream_health.iterator();
        while (it.next()) |e| allocator.free(e.key_ptr.*);
        gs.upstream_health.deinit();
    }
    gs.upstream_active_requests = std.StringHashMap(usize).init(allocator);
    defer gs.upstream_active_requests.deinit();
    gs.dns_discovery = http.dns_discovery.DnsDiscovery.init(allocator, .{ .srv_name = "_api._tcp.service.test" });
    defer gs.dns_discovery.deinit();
    gs.dns_discovery.applySuccess(1, &.{
        .{ .priority = 10, .weight = 1, .target_id = 0, .url = "https://10.0.0.1:443" },
        .{ .priority = 10, .weight = 1, .target_id = 1, .url = "https://10.0.0.2:443" },
        .{ .priority = 20, .weight = 1, .target_id = 2, .url = "https://10.0.0.9:443" },
    }, 10_000);

    const empty_pool: UpstreamPoolView = .{ .fallback_url = "http://static.invalid", .primary_urls = &.{}, .primary_weights = &.{}, .backup_urls = &.{} };
    // Sticky request stays on its endpoint while it is in the active group.
    const sticky = gs.nextStickyUpstreamBaseUrl(&cfg, empty_pool, "1.2.3.4", "k", "https://10.0.0.2:443");
    try std.testing.expect(sticky.used_requested);
    try std.testing.expectEqualStrings("https://10.0.0.2:443", sticky.base_url);
    // A lower-priority endpoint is never honoured while group 10 is healthy.
    const lower = gs.nextStickyUpstreamBaseUrl(&cfg, empty_pool, "1.2.3.4", "k", "https://10.0.0.9:443");
    try std.testing.expect(!lower.used_requested);
    try std.testing.expect(!std.mem.eql(u8, lower.base_url, "https://10.0.0.9:443"));
    // Every algorithm stays inside the active group.
    inline for (.{ .round_robin, .least_connections, .ip_hash, .generic_hash, .random_two_choices }) |algo| {
        cfg.upstream_lb_algorithm = algo;
        for (0..20) |_| {
            const url = gs.nextUpstreamBaseUrl(&cfg, empty_pool, "1.2.3.4", "k");
            try std.testing.expect(!std.mem.eql(u8, url, "https://10.0.0.9:443"));
            try std.testing.expect(!std.mem.eql(u8, url, "http://static.invalid"));
        }
    }
    // Both primaries unhealthy: group 20 becomes active and the dead sticky
    // endpoint is rejected.
    cfg.upstream_lb_algorithm = .round_robin;
    for ([_][]const u8{ "https://10.0.0.1:443", "https://10.0.0.2:443" }) |u| {
        try gs.upstream_health.put(try allocator.dupe(u8, u), .{ .unhealthy_until_ms = std.math.maxInt(u64) });
    }
    const down = gs.nextStickyUpstreamBaseUrl(&cfg, empty_pool, "1.2.3.4", "k", "https://10.0.0.1:443");
    try std.testing.expect(!down.used_requested);
    try std.testing.expectEqualStrings("https://10.0.0.9:443", down.base_url);
}
