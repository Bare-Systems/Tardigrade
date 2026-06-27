const std = @import("std");
const compat = @import("../zig_compat.zig");

/// Server-wide metrics counters.
///
/// Tracks request counts, status code distribution, and uptime.
/// All fields are updated atomically for thread-safety readiness.
pub const Metrics = struct {
    /// Total requests processed.
    total_requests: u64,
    /// Requests by status code class.
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    /// Current active accepted client connections.
    active_connections: u64,
    /// Current active mux websocket connections.
    mux_connections: u64,
    /// Current active mux channels across all connected clients.
    mux_subscriptions: u64,
    /// Total listener rejections from connection slot limits.
    connection_rejections: u64,
    /// Total listener rejections due to worker queue saturation.
    queue_rejections: u64,
    /// Current number of upstream backends marked unhealthy.
    upstream_unhealthy_backends: u64,
    /// Proxy transfer mode and buffering counters.
    proxy_streaming_requests: u64,
    proxy_buffered_requests: u64,
    proxy_buffered_bytes_current: u64,
    proxy_buffered_bytes_total: u64,
    proxy_client_aborts: u64,
    proxy_upstream_aborts: u64,
    proxy_ttfb_ms_count: u64,
    proxy_ttfb_ms_sum: u64,
    // Upstream keep-alive connection pool (#141). Populated from the pool's own
    // snapshot at render time.
    upstream_connections_new: u64,
    upstream_connections_reused: u64,
    upstream_connections_idle: u64,
    upstream_stale_retries: u64,
    /// Request latency histogram bucket counts (milliseconds).
    latency_le_1ms: u64,
    latency_le_5ms: u64,
    latency_le_10ms: u64,
    latency_le_25ms: u64,
    latency_le_50ms: u64,
    latency_le_100ms: u64,
    latency_le_250ms: u64,
    latency_le_500ms: u64,
    latency_le_1000ms: u64,
    latency_gt_1000ms: u64,
    latency_count: u64,
    latency_sum_ms: u64,
    /// Current number of worker jobs actively executing request work.
    worker_active_jobs: u64,
    /// Current number of connections queued for the worker pool.
    worker_queued_jobs: u64,
    /// Configured number of worker threads in the pool.
    worker_threads: u64,
    /// Configured maximum queue depth for the worker pool.
    worker_queue_capacity: u64,
    /// Worker queue wait time histogram: time from submit() to worker dispatch (microseconds).
    worker_queue_wait_le_100us: u64,
    worker_queue_wait_le_500us: u64,
    worker_queue_wait_le_1ms: u64,
    worker_queue_wait_le_5ms: u64,
    worker_queue_wait_le_10ms: u64,
    worker_queue_wait_le_50ms: u64,
    worker_queue_wait_gt_50ms: u64,
    worker_queue_wait_count: u64,
    worker_queue_wait_sum_us: u64,
    /// Idle keepalive connections currently parked off the worker pool (#138).
    keepalive_parked: u64,
    /// Total parked-connection resume dispatches.
    keepalive_resumes_total: u64,
    /// Total parked connections closed by the idle-keepalive reaper.
    keepalive_timeouts_total: u64,
    /// Total parked connections closed (resume-close, idle reap, or drain).
    keepalive_closed_total: u64,
    /// Error category counters.
    err_invalid_request: u64,
    err_unauthorized: u64,
    err_rate_limited: u64,
    err_upstream_timeout: u64,
    err_upstream_unavailable: u64,
    err_internal_error: u64,
    err_overload: u64,
    err_request_timeout: u64,
    mux_frame_errors: u64,
    /// Total event loop iterations (timer tick fires).
    event_loop_iterations: u64,
    /// Total background active health-probe batches dispatched.
    health_probe_runs: u64,
    /// Total config hot-reload attempts (incremented when a SIGHUP reload starts).
    reload_attempts_total: u64,
    /// Total config hot-reloads that loaded, validated, and installed successfully.
    reload_success_total: u64,
    /// Total config hot-reloads rejected (load/validation/bookkeeping failure); the
    /// previous config stays active.
    reload_failure_total: u64,
    /// Total graceful-shutdown drains started.
    drain_total: u64,
    /// Total drains that hit the configured drain timeout before work finished.
    drain_timeouts_total: u64,
    /// Total queued (unstarted) connections force-closed because a drain timed out.
    drain_forced_closes_total: u64,
    /// Server start time (nanoseconds since boot).
    started_ns: i128,

    pub fn init() Metrics {
        return .{
            .total_requests = 0,
            .status_2xx = 0,
            .status_3xx = 0,
            .status_4xx = 0,
            .status_5xx = 0,
            .active_connections = 0,
            .mux_connections = 0,
            .mux_subscriptions = 0,
            .connection_rejections = 0,
            .queue_rejections = 0,
            .upstream_unhealthy_backends = 0,
            .proxy_streaming_requests = 0,
            .proxy_buffered_requests = 0,
            .proxy_buffered_bytes_current = 0,
            .proxy_buffered_bytes_total = 0,
            .proxy_client_aborts = 0,
            .proxy_upstream_aborts = 0,
            .proxy_ttfb_ms_count = 0,
            .proxy_ttfb_ms_sum = 0,
            .upstream_connections_new = 0,
            .upstream_connections_reused = 0,
            .upstream_connections_idle = 0,
            .upstream_stale_retries = 0,
            .latency_le_1ms = 0,
            .latency_le_5ms = 0,
            .latency_le_10ms = 0,
            .latency_le_25ms = 0,
            .latency_le_50ms = 0,
            .latency_le_100ms = 0,
            .latency_le_250ms = 0,
            .latency_le_500ms = 0,
            .latency_le_1000ms = 0,
            .latency_gt_1000ms = 0,
            .latency_count = 0,
            .latency_sum_ms = 0,
            .worker_active_jobs = 0,
            .worker_queued_jobs = 0,
            .worker_threads = 0,
            .worker_queue_capacity = 0,
            .worker_queue_wait_le_100us = 0,
            .worker_queue_wait_le_500us = 0,
            .worker_queue_wait_le_1ms = 0,
            .worker_queue_wait_le_5ms = 0,
            .worker_queue_wait_le_10ms = 0,
            .worker_queue_wait_le_50ms = 0,
            .worker_queue_wait_gt_50ms = 0,
            .worker_queue_wait_count = 0,
            .worker_queue_wait_sum_us = 0,
            .keepalive_parked = 0,
            .keepalive_resumes_total = 0,
            .keepalive_timeouts_total = 0,
            .keepalive_closed_total = 0,
            .err_invalid_request = 0,
            .err_unauthorized = 0,
            .err_rate_limited = 0,
            .err_upstream_timeout = 0,
            .err_upstream_unavailable = 0,
            .err_internal_error = 0,
            .err_overload = 0,
            .err_request_timeout = 0,
            .mux_frame_errors = 0,
            .event_loop_iterations = 0,
            .health_probe_runs = 0,
            .reload_attempts_total = 0,
            .reload_success_total = 0,
            .reload_failure_total = 0,
            .drain_total = 0,
            .drain_timeouts_total = 0,
            .drain_forced_closes_total = 0,
            .started_ns = compat.nanoTimestamp(),
        };
    }

    /// Record a completed request with the given status code.
    pub fn recordRequest(self: *Metrics, status: u16) void {
        self.total_requests += 1;
        if (status >= 200 and status < 300) {
            self.status_2xx += 1;
        } else if (status >= 300 and status < 400) {
            self.status_3xx += 1;
        } else if (status >= 400 and status < 500) {
            self.status_4xx += 1;
        } else if (status >= 500) {
            self.status_5xx += 1;
        }
    }

    pub fn setActiveConnections(self: *Metrics, active: usize) void {
        self.active_connections = @intCast(active);
    }

    pub fn setMuxConnections(self: *Metrics, active: usize) void {
        self.mux_connections = @intCast(active);
    }

    pub fn setMuxSubscriptions(self: *Metrics, active: usize) void {
        self.mux_subscriptions = @intCast(active);
    }

    pub fn recordConnectionRejection(self: *Metrics) void {
        self.connection_rejections += 1;
    }

    pub fn recordQueueRejection(self: *Metrics) void {
        self.queue_rejections += 1;
    }

    pub fn recordMuxFrameError(self: *Metrics) void {
        self.mux_frame_errors += 1;
    }

    pub fn recordEventLoopIteration(self: *Metrics) void {
        self.event_loop_iterations += 1;
    }

    pub fn recordHealthProbeRun(self: *Metrics) void {
        self.health_probe_runs += 1;
    }

    /// Record the start of a config hot-reload attempt.
    pub fn recordReloadAttempt(self: *Metrics) void {
        self.reload_attempts_total += 1;
    }

    /// Record a successful config hot-reload (loaded, validated, installed).
    pub fn recordReloadSuccess(self: *Metrics) void {
        self.reload_success_total += 1;
    }

    /// Record a rejected config hot-reload; the previous config stays active.
    pub fn recordReloadFailure(self: *Metrics) void {
        self.reload_failure_total += 1;
    }

    /// Record a graceful-shutdown drain. `timed_out` is true when the drain
    /// deadline elapsed before work finished; `forced_closes` is the number of
    /// queued (unstarted) connections force-closed as a result.
    pub fn recordDrain(self: *Metrics, timed_out: bool, forced_closes: usize) void {
        self.drain_total += 1;
        if (timed_out) self.drain_timeouts_total += 1;
        self.drain_forced_closes_total += @intCast(forced_closes);
    }

    pub fn setUpstreamUnhealthyBackends(self: *Metrics, count: usize) void {
        self.upstream_unhealthy_backends = @intCast(count);
    }

    pub fn recordProxyStreamingRequest(self: *Metrics, ttfb_ms: u64) void {
        self.proxy_streaming_requests += 1;
        self.recordProxyTtfbMs(ttfb_ms);
    }

    pub fn recordProxyBufferedRequest(self: *Metrics, buffered_bytes: usize, ttfb_ms: u64) void {
        const bytes: u64 = @intCast(buffered_bytes);
        self.proxy_buffered_requests += 1;
        self.proxy_buffered_bytes_current += bytes;
        self.proxy_buffered_bytes_total += bytes;
        self.recordProxyTtfbMs(ttfb_ms);
    }

    pub fn releaseProxyBufferedBytes(self: *Metrics, buffered_bytes: usize) void {
        const bytes: u64 = @intCast(buffered_bytes);
        self.proxy_buffered_bytes_current = if (bytes >= self.proxy_buffered_bytes_current) 0 else self.proxy_buffered_bytes_current - bytes;
    }

    pub fn recordProxyClientAbort(self: *Metrics) void {
        self.proxy_client_aborts += 1;
    }

    pub fn recordProxyUpstreamAbort(self: *Metrics) void {
        self.proxy_upstream_aborts += 1;
    }

    fn recordProxyTtfbMs(self: *Metrics, ttfb_ms: u64) void {
        self.proxy_ttfb_ms_count += 1;
        self.proxy_ttfb_ms_sum += ttfb_ms;
    }

    pub fn recordLatencyMs(self: *Metrics, latency_ms: i64) void {
        const latency_u64: u64 = if (latency_ms <= 0) 0 else @intCast(latency_ms);
        self.latency_count += 1;
        self.latency_sum_ms += latency_u64;

        if (latency_u64 <= 1) {
            self.latency_le_1ms += 1;
        } else if (latency_u64 <= 5) {
            self.latency_le_5ms += 1;
        } else if (latency_u64 <= 10) {
            self.latency_le_10ms += 1;
        } else if (latency_u64 <= 25) {
            self.latency_le_25ms += 1;
        } else if (latency_u64 <= 50) {
            self.latency_le_50ms += 1;
        } else if (latency_u64 <= 100) {
            self.latency_le_100ms += 1;
        } else if (latency_u64 <= 250) {
            self.latency_le_250ms += 1;
        } else if (latency_u64 <= 500) {
            self.latency_le_500ms += 1;
        } else if (latency_u64 <= 1000) {
            self.latency_le_1000ms += 1;
        } else {
            self.latency_gt_1000ms += 1;
        }
    }

    pub fn setWorkerPoolStats(self: *Metrics, active_jobs: usize, queued_jobs: usize, worker_threads: usize, queue_capacity: usize) void {
        self.worker_active_jobs = @intCast(active_jobs);
        self.worker_queued_jobs = @intCast(queued_jobs);
        self.worker_threads = @intCast(worker_threads);
        self.worker_queue_capacity = @intCast(queue_capacity);
    }

    /// Record the time a connection spent in the worker queue waiting for dispatch.
    /// `wait_ns` is the elapsed nanoseconds between submit() and worker pickup.
    pub fn recordWorkerQueueWaitNs(self: *Metrics, wait_ns: i64) void {
        const ns: u64 = if (wait_ns <= 0) 0 else @intCast(wait_ns);
        const us: u64 = ns / 1000;
        self.worker_queue_wait_count += 1;
        self.worker_queue_wait_sum_us += us;
        if (us <= 100) {
            self.worker_queue_wait_le_100us += 1;
        } else if (us <= 500) {
            self.worker_queue_wait_le_500us += 1;
        } else if (us <= 1_000) {
            self.worker_queue_wait_le_1ms += 1;
        } else if (us <= 5_000) {
            self.worker_queue_wait_le_5ms += 1;
        } else if (us <= 10_000) {
            self.worker_queue_wait_le_10ms += 1;
        } else if (us <= 50_000) {
            self.worker_queue_wait_le_50ms += 1;
        } else {
            self.worker_queue_wait_gt_50ms += 1;
        }
    }

    fn workerQueueWaitBucketCumulative(self: *const Metrics, le_us: u64) u64 {
        var total: u64 = 0;
        if (le_us >= 100) total += self.worker_queue_wait_le_100us;
        if (le_us >= 500) total += self.worker_queue_wait_le_500us;
        if (le_us >= 1_000) total += self.worker_queue_wait_le_1ms;
        if (le_us >= 5_000) total += self.worker_queue_wait_le_5ms;
        if (le_us >= 10_000) total += self.worker_queue_wait_le_10ms;
        if (le_us >= 50_000) total += self.worker_queue_wait_le_50ms;
        return total;
    }

    /// Snapshot of the idle keepalive parked-connection registry (#138).
    pub fn setKeepaliveStats(self: *Metrics, parked: usize, resumes_total: u64, timeouts_total: u64, closed_total: u64) void {
        self.keepalive_parked = @intCast(parked);
        self.keepalive_resumes_total = resumes_total;
        self.keepalive_timeouts_total = timeouts_total;
        self.keepalive_closed_total = closed_total;
    }

    fn latencyBucketCumulative(self: *const Metrics, le_ms: u64) u64 {
        var total: u64 = 0;
        if (le_ms >= 1) total += self.latency_le_1ms;
        if (le_ms >= 5) total += self.latency_le_5ms;
        if (le_ms >= 10) total += self.latency_le_10ms;
        if (le_ms >= 25) total += self.latency_le_25ms;
        if (le_ms >= 50) total += self.latency_le_50ms;
        if (le_ms >= 100) total += self.latency_le_100ms;
        if (le_ms >= 250) total += self.latency_le_250ms;
        if (le_ms >= 500) total += self.latency_le_500ms;
        if (le_ms >= 1000) total += self.latency_le_1000ms;
        return total;
    }

    pub fn recordErrorCode(self: *Metrics, code: []const u8) void {
        if (std.mem.eql(u8, code, "invalid_request")) {
            self.err_invalid_request += 1;
        } else if (std.mem.eql(u8, code, "unauthorized")) {
            self.err_unauthorized += 1;
        } else if (std.mem.eql(u8, code, "rate_limited")) {
            self.err_rate_limited += 1;
        } else if (std.mem.eql(u8, code, "upstream_timeout")) {
            self.err_upstream_timeout += 1;
        } else if (std.mem.eql(u8, code, "upstream_unavailable")) {
            self.err_upstream_unavailable += 1;
        } else if (std.mem.eql(u8, code, "internal_error")) {
            self.err_internal_error += 1;
        } else if (std.mem.eql(u8, code, "overload")) {
            self.err_overload += 1;
        } else if (std.mem.eql(u8, code, "request_timeout")) {
            self.err_request_timeout += 1;
        }
    }

    /// Uptime in seconds.
    pub fn uptimeSeconds(self: *const Metrics) u64 {
        const now = compat.nanoTimestamp();
        const elapsed_ns = now - self.started_ns;
        if (elapsed_ns <= 0) return 0;
        return @intCast(@divFloor(elapsed_ns, std.time.ns_per_s));
    }

    /// Format metrics in Prometheus text exposition format.
    /// Caller owns the returned memory.
    pub fn toPrometheus(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();

        try out.print(
            \\# HELP tardigrade_requests_total Total HTTP requests processed
            \\# TYPE tardigrade_requests_total counter
            \\tardigrade_requests_total {d}
            \\# HELP tardigrade_requests_2xx_total Total 2xx responses
            \\# TYPE tardigrade_requests_2xx_total counter
            \\tardigrade_requests_2xx_total {d}
            \\# HELP tardigrade_requests_3xx_total Total 3xx responses
            \\# TYPE tardigrade_requests_3xx_total counter
            \\tardigrade_requests_3xx_total {d}
            \\# HELP tardigrade_requests_4xx_total Total 4xx responses
            \\# TYPE tardigrade_requests_4xx_total counter
            \\tardigrade_requests_4xx_total {d}
            \\# HELP tardigrade_requests_5xx_total Total 5xx responses
            \\# TYPE tardigrade_requests_5xx_total counter
            \\tardigrade_requests_5xx_total {d}
            \\# HELP tardigrade_uptime_seconds Server uptime in seconds
            \\# TYPE tardigrade_uptime_seconds gauge
            \\tardigrade_uptime_seconds {d}
            \\# HELP tardigrade_active_connections Current active accepted client connections
            \\# TYPE tardigrade_active_connections gauge
            \\tardigrade_active_connections {d}
            \\# HELP tardigrade_mux_connections Current active mux websocket connections
            \\# TYPE tardigrade_mux_connections gauge
            \\tardigrade_mux_connections {d}
            \\# HELP tardigrade_mux_subscriptions Current active mux channels across all connected clients
            \\# TYPE tardigrade_mux_subscriptions gauge
            \\tardigrade_mux_subscriptions {d}
            \\# HELP tardigrade_connection_rejections_total Total listener rejections from connection-slot limits
            \\# TYPE tardigrade_connection_rejections_total counter
            \\tardigrade_connection_rejections_total {d}
            \\# HELP tardigrade_queue_rejections_total Total listener rejections due to worker queue saturation
            \\# TYPE tardigrade_queue_rejections_total counter
            \\tardigrade_queue_rejections_total {d}
            \\# HELP tardigrade_upstream_unhealthy_backends Current upstream backends marked unhealthy
            \\# TYPE tardigrade_upstream_unhealthy_backends gauge
            \\tardigrade_upstream_unhealthy_backends {d}
            \\
        , .{
            self.total_requests,
            self.status_2xx,
            self.status_3xx,
            self.status_4xx,
            self.status_5xx,
            self.uptimeSeconds(),
            self.active_connections,
            self.mux_connections,
            self.mux_subscriptions,
            self.connection_rejections,
            self.queue_rejections,
            self.upstream_unhealthy_backends,
        });

        try out.print(
            \\# HELP tardigrade_proxy_streaming_requests_total Total proxied requests served through streaming mode
            \\# TYPE tardigrade_proxy_streaming_requests_total counter
            \\tardigrade_proxy_streaming_requests_total {d}
            \\# HELP tardigrade_proxy_buffered_requests_total Total proxied requests served through bounded buffered mode
            \\# TYPE tardigrade_proxy_buffered_requests_total counter
            \\tardigrade_proxy_buffered_requests_total {d}
            \\# HELP tardigrade_proxy_buffered_bytes_current Current response bytes retained by buffered proxy requests
            \\# TYPE tardigrade_proxy_buffered_bytes_current gauge
            \\tardigrade_proxy_buffered_bytes_current {d}
            \\# HELP tardigrade_proxy_buffered_bytes_total Total response bytes retained by buffered proxy requests
            \\# TYPE tardigrade_proxy_buffered_bytes_total counter
            \\tardigrade_proxy_buffered_bytes_total {d}
            \\# HELP tardigrade_proxy_client_aborts_total Total proxied transfers aborted by downstream clients
            \\# TYPE tardigrade_proxy_client_aborts_total counter
            \\tardigrade_proxy_client_aborts_total {d}
            \\# HELP tardigrade_proxy_upstream_aborts_total Total proxied transfers aborted by upstream origins
            \\# TYPE tardigrade_proxy_upstream_aborts_total counter
            \\tardigrade_proxy_upstream_aborts_total {d}
            \\# HELP tardigrade_proxy_ttfb_ms Proxied upstream time to first byte in milliseconds
            \\# TYPE tardigrade_proxy_ttfb_ms summary
            \\tardigrade_proxy_ttfb_ms_sum {d}
            \\tardigrade_proxy_ttfb_ms_count {d}
            \\# HELP tardigrade_upstream_connections_new_total Upstream connections opened (keep-alive pool misses)
            \\# TYPE tardigrade_upstream_connections_new_total counter
            \\tardigrade_upstream_connections_new_total {d}
            \\# HELP tardigrade_upstream_connections_reused_total Upstream connections served from the keep-alive pool
            \\# TYPE tardigrade_upstream_connections_reused_total counter
            \\tardigrade_upstream_connections_reused_total {d}
            \\# HELP tardigrade_upstream_connections_idle Upstream connections currently held idle in the pool
            \\# TYPE tardigrade_upstream_connections_idle gauge
            \\tardigrade_upstream_connections_idle {d}
            \\# HELP tardigrade_upstream_stale_retries_total Idempotent retries after a reused upstream connection was found dead
            \\# TYPE tardigrade_upstream_stale_retries_total counter
            \\tardigrade_upstream_stale_retries_total {d}
            \\
        , .{
            self.proxy_streaming_requests,
            self.proxy_buffered_requests,
            self.proxy_buffered_bytes_current,
            self.proxy_buffered_bytes_total,
            self.proxy_client_aborts,
            self.proxy_upstream_aborts,
            self.proxy_ttfb_ms_sum,
            self.proxy_ttfb_ms_count,
            self.upstream_connections_new,
            self.upstream_connections_reused,
            self.upstream_connections_idle,
            self.upstream_stale_retries,
        });

        try out.print(
            \\# HELP tardigrade_request_latency_ms Request latency histogram in milliseconds
            \\# TYPE tardigrade_request_latency_ms histogram
            \\tardigrade_request_latency_ms_bucket{{le="1"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="5"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="10"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="25"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="50"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="100"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="250"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="500"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="1000"}} {d}
            \\tardigrade_request_latency_ms_bucket{{le="+Inf"}} {d}
            \\tardigrade_request_latency_ms_sum {d}
            \\tardigrade_request_latency_ms_count {d}
            \\
        , .{
            self.latencyBucketCumulative(1),
            self.latencyBucketCumulative(5),
            self.latencyBucketCumulative(10),
            self.latencyBucketCumulative(25),
            self.latencyBucketCumulative(50),
            self.latencyBucketCumulative(100),
            self.latencyBucketCumulative(250),
            self.latencyBucketCumulative(500),
            self.latencyBucketCumulative(1000),
            self.latency_count,
            self.latency_sum_ms,
            self.latency_count,
        });

        try out.print(
            \\# HELP tardigrade_worker_active_jobs Current worker jobs actively executing request work
            \\# TYPE tardigrade_worker_active_jobs gauge
            \\tardigrade_worker_active_jobs {d}
            \\# HELP tardigrade_worker_queued_jobs Current connections queued for worker-pool dispatch
            \\# TYPE tardigrade_worker_queued_jobs gauge
            \\tardigrade_worker_queued_jobs {d}
            \\# HELP tardigrade_worker_threads Configured worker thread count
            \\# TYPE tardigrade_worker_threads gauge
            \\tardigrade_worker_threads {d}
            \\# HELP tardigrade_worker_queue_capacity Configured worker queue capacity
            \\# TYPE tardigrade_worker_queue_capacity gauge
            \\tardigrade_worker_queue_capacity {d}
            \\# HELP tardigrade_worker_queue_wait_us Time a connection waited in the worker queue before dispatch (microseconds)
            \\# TYPE tardigrade_worker_queue_wait_us histogram
            \\tardigrade_worker_queue_wait_us_bucket{{le="100"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="500"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="1000"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="5000"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="10000"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="50000"}} {d}
            \\tardigrade_worker_queue_wait_us_bucket{{le="+Inf"}} {d}
            \\tardigrade_worker_queue_wait_us_sum {d}
            \\tardigrade_worker_queue_wait_us_count {d}
            \\# HELP tardigrade_error_invalid_request_total Total invalid_request API errors
            \\# TYPE tardigrade_error_invalid_request_total counter
            \\tardigrade_error_invalid_request_total {d}
            \\# HELP tardigrade_error_unauthorized_total Total unauthorized API errors
            \\# TYPE tardigrade_error_unauthorized_total counter
            \\tardigrade_error_unauthorized_total {d}
            \\# HELP tardigrade_error_rate_limited_total Total rate_limited API errors
            \\# TYPE tardigrade_error_rate_limited_total counter
            \\tardigrade_error_rate_limited_total {d}
            \\# HELP tardigrade_error_upstream_timeout_total Total upstream_timeout API errors
            \\# TYPE tardigrade_error_upstream_timeout_total counter
            \\tardigrade_error_upstream_timeout_total {d}
            \\# HELP tardigrade_error_upstream_unavailable_total Total upstream_unavailable API errors
            \\# TYPE tardigrade_error_upstream_unavailable_total counter
            \\tardigrade_error_upstream_unavailable_total {d}
            \\# HELP tardigrade_error_internal_error_total Total internal_error API errors
            \\# TYPE tardigrade_error_internal_error_total counter
            \\tardigrade_error_internal_error_total {d}
            \\# HELP tardigrade_error_overload_total Total overload API errors
            \\# TYPE tardigrade_error_overload_total counter
            \\tardigrade_error_overload_total {d}
            \\# HELP tardigrade_error_request_timeout_total Total request_timeout API errors
            \\# TYPE tardigrade_error_request_timeout_total counter
            \\tardigrade_error_request_timeout_total {d}
            \\# HELP tardigrade_mux_frame_errors_total Total mux frame parse or validation errors
            \\# TYPE tardigrade_mux_frame_errors_total counter
            \\tardigrade_mux_frame_errors_total {d}
            \\# HELP tardigrade_event_loop_iterations_total Total event loop timer-tick iterations
            \\# TYPE tardigrade_event_loop_iterations_total counter
            \\tardigrade_event_loop_iterations_total {d}
            \\# HELP tardigrade_health_probe_runs_total Total background active health-probe batches dispatched
            \\# TYPE tardigrade_health_probe_runs_total counter
            \\tardigrade_health_probe_runs_total {d}
            \\# HELP tardigrade_reload_attempts_total Total config hot-reload attempts
            \\# TYPE tardigrade_reload_attempts_total counter
            \\tardigrade_reload_attempts_total {d}
            \\# HELP tardigrade_reload_success_total Total successful config hot-reloads
            \\# TYPE tardigrade_reload_success_total counter
            \\tardigrade_reload_success_total {d}
            \\# HELP tardigrade_reload_failure_total Total rejected config hot-reloads (previous config kept)
            \\# TYPE tardigrade_reload_failure_total counter
            \\tardigrade_reload_failure_total {d}
            \\# HELP tardigrade_drain_total Total graceful-shutdown drains started
            \\# TYPE tardigrade_drain_total counter
            \\tardigrade_drain_total {d}
            \\# HELP tardigrade_drain_timeouts_total Total drains that hit the drain timeout
            \\# TYPE tardigrade_drain_timeouts_total counter
            \\tardigrade_drain_timeouts_total {d}
            \\# HELP tardigrade_drain_forced_closes_total Total queued connections force-closed on drain timeout
            \\# TYPE tardigrade_drain_forced_closes_total counter
            \\tardigrade_drain_forced_closes_total {d}
            \\
        , .{
            self.worker_active_jobs,
            self.worker_queued_jobs,
            self.worker_threads,
            self.worker_queue_capacity,
            self.workerQueueWaitBucketCumulative(100),
            self.workerQueueWaitBucketCumulative(500),
            self.workerQueueWaitBucketCumulative(1_000),
            self.workerQueueWaitBucketCumulative(5_000),
            self.workerQueueWaitBucketCumulative(10_000),
            self.workerQueueWaitBucketCumulative(50_000),
            self.worker_queue_wait_count,
            self.worker_queue_wait_sum_us,
            self.worker_queue_wait_count,
            self.err_invalid_request,
            self.err_unauthorized,
            self.err_rate_limited,
            self.err_upstream_timeout,
            self.err_upstream_unavailable,
            self.err_internal_error,
            self.err_overload,
            self.err_request_timeout,
            self.mux_frame_errors,
            self.event_loop_iterations,
            self.health_probe_runs,
            self.reload_attempts_total,
            self.reload_success_total,
            self.reload_failure_total,
            self.drain_total,
            self.drain_timeouts_total,
            self.drain_forced_closes_total,
        });

        try out.print(
            \\# HELP tardigrade_keepalive_parked_connections Idle keepalive connections currently parked off the worker pool
            \\# TYPE tardigrade_keepalive_parked_connections gauge
            \\tardigrade_keepalive_parked_connections {d}
            \\# HELP tardigrade_keepalive_resumes_total Total parked-connection resume dispatches
            \\# TYPE tardigrade_keepalive_resumes_total counter
            \\tardigrade_keepalive_resumes_total {d}
            \\# HELP tardigrade_keepalive_timeouts_total Total parked connections closed by the idle-keepalive reaper
            \\# TYPE tardigrade_keepalive_timeouts_total counter
            \\tardigrade_keepalive_timeouts_total {d}
            \\# HELP tardigrade_keepalive_closed_total Total parked connections closed (resume-close, idle reap, or drain)
            \\# TYPE tardigrade_keepalive_closed_total counter
            \\tardigrade_keepalive_closed_total {d}
            \\
        , .{
            self.keepalive_parked,
            self.keepalive_resumes_total,
            self.keepalive_timeouts_total,
            self.keepalive_closed_total,
        });

        return out.toOwnedSlice();
    }

    /// Format metrics as a JSON string.
    /// Caller owns the returned memory.
    pub fn toJson(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        try out.print(
            \\{{"total_requests":{d},"status_2xx":{d},"status_3xx":{d},"status_4xx":{d},"status_5xx":{d},"uptime_seconds":{d},"active_connections":{d},"mux_connections":{d},"mux_subscriptions":{d},"connection_rejections":{d},"queue_rejections":{d},"upstream_unhealthy_backends":{d},"proxy_streaming_requests_total":{d},"proxy_buffered_requests_total":{d},"proxy_buffered_bytes_current":{d},"proxy_buffered_bytes_total":{d},"proxy_client_aborts_total":{d},"proxy_upstream_aborts_total":{d},"proxy_ttfb_ms_count":{d},"proxy_ttfb_ms_sum":{d},"upstream_connections_new_total":{d},"upstream_connections_reused_total":{d},"upstream_connections_idle":{d},"upstream_stale_retries_total":{d}
        , .{
            self.total_requests,
            self.status_2xx,
            self.status_3xx,
            self.status_4xx,
            self.status_5xx,
            self.uptimeSeconds(),
            self.active_connections,
            self.mux_connections,
            self.mux_subscriptions,
            self.connection_rejections,
            self.queue_rejections,
            self.upstream_unhealthy_backends,
            self.proxy_streaming_requests,
            self.proxy_buffered_requests,
            self.proxy_buffered_bytes_current,
            self.proxy_buffered_bytes_total,
            self.proxy_client_aborts,
            self.proxy_upstream_aborts,
            self.proxy_ttfb_ms_count,
            self.proxy_ttfb_ms_sum,
            self.upstream_connections_new,
            self.upstream_connections_reused,
            self.upstream_connections_idle,
            self.upstream_stale_retries,
        });
        try out.print(
            \\,"request_latency_ms_count":{d},"request_latency_ms_sum":{d},"worker_active_jobs":{d},"worker_queued_jobs":{d},"worker_threads":{d},"worker_queue_capacity":{d},"worker_queue_wait_count":{d},"worker_queue_wait_sum_us":{d},"error_invalid_request":{d},"error_unauthorized":{d},"error_rate_limited":{d},"error_upstream_timeout":{d},"error_upstream_unavailable":{d},"error_internal_error":{d},"error_overload":{d},"error_request_timeout":{d},"mux_frame_errors":{d},"event_loop_iterations":{d},"health_probe_runs":{d},"reload_attempts_total":{d},"reload_success_total":{d},"reload_failure_total":{d},"drain_total":{d},"drain_timeouts_total":{d},"drain_forced_closes_total":{d}}}
        , .{
            self.latency_count,
            self.latency_sum_ms,
            self.worker_active_jobs,
            self.worker_queued_jobs,
            self.worker_threads,
            self.worker_queue_capacity,
            self.worker_queue_wait_count,
            self.worker_queue_wait_sum_us,
            self.err_invalid_request,
            self.err_unauthorized,
            self.err_rate_limited,
            self.err_upstream_timeout,
            self.err_upstream_unavailable,
            self.err_internal_error,
            self.err_overload,
            self.err_request_timeout,
            self.mux_frame_errors,
            self.event_loop_iterations,
            self.health_probe_runs,
            self.reload_attempts_total,
            self.reload_success_total,
            self.reload_failure_total,
            self.drain_total,
            self.drain_timeouts_total,
            self.drain_forced_closes_total,
        });
        return out.toOwnedSlice();
    }
};

// Tests

test "Metrics init starts at zero" {
    const m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.total_requests);
    try std.testing.expectEqual(@as(u64, 0), m.status_2xx);
    try std.testing.expectEqual(@as(u64, 0), m.status_4xx);
    try std.testing.expectEqual(@as(u64, 0), m.active_connections);
    try std.testing.expectEqual(@as(u64, 0), m.mux_connections);
    try std.testing.expectEqual(@as(u64, 0), m.mux_subscriptions);
    try std.testing.expectEqual(@as(u64, 0), m.mux_frame_errors);
    try std.testing.expectEqual(@as(u64, 0), m.proxy_streaming_requests);
    try std.testing.expectEqual(@as(u64, 0), m.proxy_buffered_bytes_current);
}

test "Metrics recordRequest tracks status classes" {
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(201);
    m.recordRequest(301);
    m.recordRequest(404);
    m.recordRequest(500);
    m.recordRequest(503);

    try std.testing.expectEqual(@as(u64, 6), m.total_requests);
    try std.testing.expectEqual(@as(u64, 2), m.status_2xx);
    try std.testing.expectEqual(@as(u64, 1), m.status_3xx);
    try std.testing.expectEqual(@as(u64, 1), m.status_4xx);
    try std.testing.expectEqual(@as(u64, 2), m.status_5xx);
}

test "Metrics uptimeSeconds is non-negative" {
    const m = Metrics.init();
    try std.testing.expect(m.uptimeSeconds() <= 1);
}

test "Metrics tracks active connections and rejections" {
    var m = Metrics.init();
    m.setActiveConnections(7);
    m.setMuxConnections(2);
    m.setMuxSubscriptions(5);
    m.recordLatencyMs(0);
    m.recordLatencyMs(6);
    m.recordLatencyMs(1200);
    m.setWorkerPoolStats(3, 4, 8, 1024);
    m.recordConnectionRejection();
    m.recordQueueRejection();
    m.recordQueueRejection();
    m.recordMuxFrameError();
    m.recordProxyStreamingRequest(12);
    m.recordProxyBufferedRequest(128, 8);
    m.releaseProxyBufferedBytes(64);
    m.recordProxyClientAbort();
    m.recordProxyUpstreamAbort();

    try std.testing.expectEqual(@as(u64, 7), m.active_connections);
    try std.testing.expectEqual(@as(u64, 2), m.mux_connections);
    try std.testing.expectEqual(@as(u64, 5), m.mux_subscriptions);
    try std.testing.expectEqual(@as(u64, 3), m.latency_count);
    try std.testing.expectEqual(@as(u64, 1206), m.latency_sum_ms);
    try std.testing.expectEqual(@as(u64, 3), m.worker_active_jobs);
    try std.testing.expectEqual(@as(u64, 4), m.worker_queued_jobs);
    try std.testing.expectEqual(@as(u64, 8), m.worker_threads);
    try std.testing.expectEqual(@as(u64, 1024), m.worker_queue_capacity);
    try std.testing.expectEqual(@as(u64, 1), m.connection_rejections);
    try std.testing.expectEqual(@as(u64, 2), m.queue_rejections);
    try std.testing.expectEqual(@as(u64, 1), m.mux_frame_errors);
    try std.testing.expectEqual(@as(u64, 1), m.proxy_streaming_requests);
    try std.testing.expectEqual(@as(u64, 1), m.proxy_buffered_requests);
    try std.testing.expectEqual(@as(u64, 64), m.proxy_buffered_bytes_current);
    try std.testing.expectEqual(@as(u64, 128), m.proxy_buffered_bytes_total);
    try std.testing.expectEqual(@as(u64, 1), m.proxy_client_aborts);
    try std.testing.expectEqual(@as(u64, 1), m.proxy_upstream_aborts);
    try std.testing.expectEqual(@as(u64, 2), m.proxy_ttfb_ms_count);
    try std.testing.expectEqual(@as(u64, 20), m.proxy_ttfb_ms_sum);
    m.setUpstreamUnhealthyBackends(3);
    try std.testing.expectEqual(@as(u64, 3), m.upstream_unhealthy_backends);
    m.recordErrorCode("invalid_request");
    m.recordErrorCode("overload");
    try std.testing.expectEqual(@as(u64, 1), m.err_invalid_request);
    try std.testing.expectEqual(@as(u64, 1), m.err_overload);
}

test "recordErrorCode counts only the canonical overload label" {
    // Regression guard: every overload path (accept-time connection/queue
    // rejections and in-flight backpressure) must use exactly "overload".
    // A near-miss like "overloaded" must not silently drop the count.
    var m = Metrics.init();
    m.recordErrorCode("overload");
    try std.testing.expectEqual(@as(u64, 1), m.err_overload);
    m.recordErrorCode("overloaded"); // not a recognized label -> no-op
    m.recordErrorCode("");
    try std.testing.expectEqual(@as(u64, 1), m.err_overload);
}

test "recordErrorCode counts request_timeout errors" {
    // The request-total-timeout path records "request_timeout"; it must have a
    // matching counter so the error is observable (previously a silent no-op).
    var m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.err_request_timeout);
    m.recordErrorCode("request_timeout");
    m.recordErrorCode("request_timeout");
    try std.testing.expectEqual(@as(u64, 2), m.err_request_timeout);
}

test "reload and drain counters record lifecycle events (#170)" {
    var m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.reload_attempts_total);

    m.recordReloadAttempt();
    m.recordReloadSuccess();
    m.recordReloadAttempt();
    m.recordReloadFailure();
    try std.testing.expectEqual(@as(u64, 2), m.reload_attempts_total);
    try std.testing.expectEqual(@as(u64, 1), m.reload_success_total);
    try std.testing.expectEqual(@as(u64, 1), m.reload_failure_total);

    // A clean drain: no timeout, no forced closes.
    m.recordDrain(false, 0);
    // A drain that timed out and force-closed 3 queued connections.
    m.recordDrain(true, 3);
    try std.testing.expectEqual(@as(u64, 2), m.drain_total);
    try std.testing.expectEqual(@as(u64, 1), m.drain_timeouts_total);
    try std.testing.expectEqual(@as(u64, 3), m.drain_forced_closes_total);
}

test "reload and drain counters appear in Prometheus and JSON output (#170)" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordReloadAttempt();
    m.recordReloadFailure();
    m.recordDrain(true, 2);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_reload_attempts_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_reload_failure_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_drain_timeouts_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_drain_forced_closes_total 2") != null);

    const json = try m.toJson(allocator);
    defer allocator.free(json);
    try std.testing.expect(std.mem.find(u8, json, "\"reload_attempts_total\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"drain_forced_closes_total\":2") != null);
}

test "Metrics toPrometheus produces valid Prometheus text" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(500);
    m.recordProxyStreamingRequest(3);
    m.recordProxyBufferedRequest(42, 4);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_requests_total 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_requests_2xx_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_requests_5xx_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_active_connections") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_connection_rejections_total") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_queue_rejections_total") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_upstream_unhealthy_backends") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_request_latency_ms_bucket{le=\"1\"}") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_request_latency_ms_count") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_requests_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_buffered_requests_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_buffered_bytes_current 42") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_ttfb_ms_count 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_active_jobs") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queued_jobs") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_error_invalid_request_total") != null);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_requests_total counter") != null);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_uptime_seconds gauge") != null);
}

test "Metrics toJson produces valid JSON" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(404);
    m.recordProxyStreamingRequest(5);
    m.recordProxyBufferedRequest(17, 7);

    const json = try m.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.find(u8, json, "\"total_requests\":2") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"status_2xx\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"status_4xx\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"active_connections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"connection_rejections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"queue_rejections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"upstream_unhealthy_backends\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"proxy_streaming_requests_total\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"proxy_buffered_requests_total\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"proxy_buffered_bytes_current\":17") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"proxy_ttfb_ms_sum\":12") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"request_latency_ms_count\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"request_latency_ms_sum\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"worker_active_jobs\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"worker_queued_jobs\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"error_invalid_request\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"uptime_seconds\":") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"event_loop_iterations\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"health_probe_runs\":0") != null);
}

test "Metrics event loop iteration and health probe counters" {
    var m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.event_loop_iterations);
    try std.testing.expectEqual(@as(u64, 0), m.health_probe_runs);
    m.recordEventLoopIteration();
    m.recordEventLoopIteration();
    m.recordHealthProbeRun();
    try std.testing.expectEqual(@as(u64, 2), m.event_loop_iterations);
    try std.testing.expectEqual(@as(u64, 1), m.health_probe_runs);
}

test "Metrics toPrometheus includes event loop counters" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordEventLoopIteration();
    m.recordHealthProbeRun();
    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_event_loop_iterations_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_health_probe_runs_total 1") != null);
}

test "recordWorkerQueueWaitNs buckets correctly (#136)" {
    var m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.worker_queue_wait_count);
    try std.testing.expectEqual(@as(u64, 0), m.worker_queue_wait_sum_us);

    // ≤100µs: 50µs
    m.recordWorkerQueueWaitNs(50_000);
    // ≤500µs: 300µs
    m.recordWorkerQueueWaitNs(300_000);
    // ≤1ms: 800µs
    m.recordWorkerQueueWaitNs(800_000);
    // ≤5ms: 2ms
    m.recordWorkerQueueWaitNs(2_000_000);
    // ≤10ms: 7ms
    m.recordWorkerQueueWaitNs(7_000_000);
    // ≤50ms: 20ms
    m.recordWorkerQueueWaitNs(20_000_000);
    // >50ms: 100ms
    m.recordWorkerQueueWaitNs(100_000_000);

    try std.testing.expectEqual(@as(u64, 7), m.worker_queue_wait_count);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_100us);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_500us);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_1ms);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_5ms);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_10ms);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_le_50ms);
    try std.testing.expectEqual(@as(u64, 1), m.worker_queue_wait_gt_50ms);
    // sum: 50 + 300 + 800 + 2000 + 7000 + 20000 + 100000 = 130150 µs
    try std.testing.expectEqual(@as(u64, 130150), m.worker_queue_wait_sum_us);
}

test "worker queue wait histogram appears in Prometheus and JSON output (#136)" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordWorkerQueueWaitNs(500_000); // 500µs → ≤500µs bucket

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queue_wait_us_bucket{le=\"100\"}") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queue_wait_us_bucket{le=\"500\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queue_wait_us_count 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queue_wait_us_sum 500") != null);

    const json = try m.toJson(allocator);
    defer allocator.free(json);
    try std.testing.expect(std.mem.find(u8, json, "\"worker_queue_wait_count\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"worker_queue_wait_sum_us\":500") != null);
}
