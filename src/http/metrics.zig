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
    mux_frame_errors: u64,
    /// Total event loop iterations (timer tick fires).
    event_loop_iterations: u64,
    /// Total background active health-probe batches dispatched.
    health_probe_runs: u64,
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
            .mux_frame_errors = 0,
            .event_loop_iterations = 0,
            .health_probe_runs = 0,
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

    pub fn setUpstreamUnhealthyBackends(self: *Metrics, count: usize) void {
        self.upstream_unhealthy_backends = @intCast(count);
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
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);

        try out.print(allocator,
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

        try out.print(allocator,
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

        try out.print(allocator,
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
            \\# HELP tardigrade_mux_frame_errors_total Total mux frame parse or validation errors
            \\# TYPE tardigrade_mux_frame_errors_total counter
            \\tardigrade_mux_frame_errors_total {d}
            \\# HELP tardigrade_event_loop_iterations_total Total event loop timer-tick iterations
            \\# TYPE tardigrade_event_loop_iterations_total counter
            \\tardigrade_event_loop_iterations_total {d}
            \\# HELP tardigrade_health_probe_runs_total Total background active health-probe batches dispatched
            \\# TYPE tardigrade_health_probe_runs_total counter
            \\tardigrade_health_probe_runs_total {d}
            \\
        , .{
            self.worker_active_jobs,
            self.worker_queued_jobs,
            self.worker_threads,
            self.worker_queue_capacity,
            self.err_invalid_request,
            self.err_unauthorized,
            self.err_rate_limited,
            self.err_upstream_timeout,
            self.err_upstream_unavailable,
            self.err_internal_error,
            self.err_overload,
            self.mux_frame_errors,
            self.event_loop_iterations,
            self.health_probe_runs,
        });

        try out.print(allocator,
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

        return out.toOwnedSlice(allocator);
    }

    /// Format metrics as a JSON string.
    /// Caller owns the returned memory.
    pub fn toJson(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\{{"total_requests":{d},"status_2xx":{d},"status_3xx":{d},"status_4xx":{d},"status_5xx":{d},"uptime_seconds":{d},"active_connections":{d},"mux_connections":{d},"mux_subscriptions":{d},"connection_rejections":{d},"queue_rejections":{d},"upstream_unhealthy_backends":{d},"request_latency_ms_count":{d},"request_latency_ms_sum":{d},"worker_active_jobs":{d},"worker_queued_jobs":{d},"worker_threads":{d},"worker_queue_capacity":{d},"error_invalid_request":{d},"error_unauthorized":{d},"error_rate_limited":{d},"error_upstream_timeout":{d},"error_upstream_unavailable":{d},"error_internal_error":{d},"error_overload":{d},"mux_frame_errors":{d},"event_loop_iterations":{d},"health_probe_runs":{d}}}
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
            self.latency_count,
            self.latency_sum_ms,
            self.worker_active_jobs,
            self.worker_queued_jobs,
            self.worker_threads,
            self.worker_queue_capacity,
            self.err_invalid_request,
            self.err_unauthorized,
            self.err_rate_limited,
            self.err_upstream_timeout,
            self.err_upstream_unavailable,
            self.err_internal_error,
            self.err_overload,
            self.mux_frame_errors,
            self.event_loop_iterations,
            self.health_probe_runs,
        });
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
    m.setUpstreamUnhealthyBackends(3);
    try std.testing.expectEqual(@as(u64, 3), m.upstream_unhealthy_backends);
    m.recordErrorCode("invalid_request");
    m.recordErrorCode("overload");
    try std.testing.expectEqual(@as(u64, 1), m.err_invalid_request);
    try std.testing.expectEqual(@as(u64, 1), m.err_overload);
}

test "Metrics toPrometheus produces valid Prometheus text" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(500);

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

    const json = try m.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.find(u8, json, "\"total_requests\":2") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"status_2xx\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"status_4xx\":1") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"active_connections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"connection_rejections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"queue_rejections\":0") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"upstream_unhealthy_backends\":0") != null);
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
