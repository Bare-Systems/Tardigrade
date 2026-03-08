const std = @import("std");

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
    /// Total listener rejections from connection slot limits.
    connection_rejections: u64,
    /// Total listener rejections due to worker queue saturation.
    queue_rejections: u64,
    /// Current number of upstream backends marked unhealthy.
    upstream_unhealthy_backends: u64,
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
            .connection_rejections = 0,
            .queue_rejections = 0,
            .upstream_unhealthy_backends = 0,
            .started_ns = std.time.nanoTimestamp(),
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

    pub fn recordConnectionRejection(self: *Metrics) void {
        self.connection_rejections += 1;
    }

    pub fn recordQueueRejection(self: *Metrics) void {
        self.queue_rejections += 1;
    }

    pub fn setUpstreamUnhealthyBackends(self: *Metrics, count: usize) void {
        self.upstream_unhealthy_backends = @intCast(count);
    }

    /// Uptime in seconds.
    pub fn uptimeSeconds(self: *const Metrics) u64 {
        const now = std.time.nanoTimestamp();
        const elapsed_ns = now - self.started_ns;
        if (elapsed_ns <= 0) return 0;
        return @intCast(@divFloor(elapsed_ns, std.time.ns_per_s));
    }

    /// Format metrics in Prometheus text exposition format.
    /// Caller owns the returned memory.
    pub fn toPrometheus(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
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
            self.connection_rejections,
            self.queue_rejections,
            self.upstream_unhealthy_backends,
        });
    }

    /// Format metrics as a JSON string.
    /// Caller owns the returned memory.
    pub fn toJson(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\{{"total_requests":{d},"status_2xx":{d},"status_3xx":{d},"status_4xx":{d},"status_5xx":{d},"uptime_seconds":{d},"active_connections":{d},"connection_rejections":{d},"queue_rejections":{d},"upstream_unhealthy_backends":{d}}}
        , .{
            self.total_requests,
            self.status_2xx,
            self.status_3xx,
            self.status_4xx,
            self.status_5xx,
            self.uptimeSeconds(),
            self.active_connections,
            self.connection_rejections,
            self.queue_rejections,
            self.upstream_unhealthy_backends,
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
    m.recordConnectionRejection();
    m.recordQueueRejection();
    m.recordQueueRejection();

    try std.testing.expectEqual(@as(u64, 7), m.active_connections);
    try std.testing.expectEqual(@as(u64, 1), m.connection_rejections);
    try std.testing.expectEqual(@as(u64, 2), m.queue_rejections);
    m.setUpstreamUnhealthyBackends(3);
    try std.testing.expectEqual(@as(u64, 3), m.upstream_unhealthy_backends);
}

test "Metrics toPrometheus produces valid Prometheus text" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(500);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_requests_total 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_requests_2xx_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_requests_5xx_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_active_connections") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_connection_rejections_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_queue_rejections_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "tardigrade_upstream_unhealthy_backends") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "# TYPE tardigrade_requests_total counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, prom, "# TYPE tardigrade_uptime_seconds gauge") != null);
}

test "Metrics toJson produces valid JSON" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordRequest(200);
    m.recordRequest(404);

    const json = try m.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"total_requests\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status_2xx\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status_4xx\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"active_connections\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"connection_rejections\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"queue_rejections\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"upstream_unhealthy_backends\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"uptime_seconds\":") != null);
}
