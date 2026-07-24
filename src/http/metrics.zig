const std = @import("std");
const compat = @import("zig_compat");
const proxy_buffer_account = @import("proxy_buffer_account.zig");
const encrypted_stream = @import("tls_core").encrypted_stream;

pub const TlsBufferConnectionMetrics = struct {
    active: bool = false,
    backend: encrypted_stream.BackendKind = .openssl,
    current: encrypted_stream.QueueBytes = .{},
    counters: encrypted_stream.BufferCounters = .{},
};

const tls_backend_count = 2;
const tls_queue_count = 4;
const tls_direction_count = 2;

const TlsQueue = enum { inbound_ciphertext, inbound_plaintext, outbound_ciphertext, handshake };
const TlsDirection = enum { carrier_read, plaintext_write };

/// #488: native TLS/QUIC resumption metric labels. Every label here is a
/// fixed, closed enum — never a raw ticket, PSK, identity, handle, SNI/ALPN
/// value, certificate byte, key ID, ciphertext, decrypted state, filesystem
/// path, or arbitrary error string.
pub const ResumptionTransport = enum { record, quic };
pub const ResumptionOutcome = enum { accepted, full_handshake, incompatible, miss, fatal };
pub const ResumptionMode = enum { stateful, stateless, hybrid };
pub const TicketResult = enum { success, rejected, failed };

pub const HttpProtocol = enum { h1, h2, h3 };
pub const EarlyDataSource = enum { transport, header, both };
pub const EarlyDataDecision = enum { accepted, too_early, deferred, forwarded };
pub const EarlyDataUpstream425Action = enum { forwarded, retried };
pub const EarlyDataRetryResult = enum { success, too_early, failure };
pub const H3EarlyDataCompatDecision = enum { compatible, transport_incompatible, settings_incompatible, missing_state };

const resumption_transport_count = 2;
const resumption_outcome_count = 5;
const resumption_mode_count = 3;
const ticket_result_count = 3;
const http_protocol_count = 3;
const early_data_source_count = 3;
const early_data_decision_count = 4;
const early_data_upstream_425_action_count = 2;
const early_data_retry_result_count = 3;
const h3_early_data_compat_decision_count = 4;

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
    proxy_buffer_downstream_to_upstream_stream_current: u64,
    proxy_buffer_downstream_to_upstream_global_current: u64,
    proxy_buffer_upstream_to_downstream_stream_current: u64,
    proxy_buffer_upstream_to_downstream_global_current: u64,
    proxy_buffer_high_watermark_downstream_to_upstream_stream: u64,
    proxy_buffer_high_watermark_upstream_to_downstream_stream: u64,
    proxy_buffer_limit_exceeded_downstream_to_upstream_stream: u64,
    proxy_buffer_limit_exceeded_upstream_to_downstream_stream: u64,
    proxy_buffer_read_pauses_downstream: u64,
    proxy_buffer_read_pauses_upstream: u64,
    proxy_buffer_read_resumes_downstream: u64,
    proxy_buffer_read_resumes_upstream: u64,
    tls_buffered_bytes_current: [tls_backend_count][tls_queue_count]u64,
    tls_buffer_pause_events: [tls_backend_count][tls_direction_count]u64,
    tls_buffer_resume_events: [tls_backend_count][tls_direction_count]u64,
    tls_buffer_limit_exceeded: [tls_backend_count][tls_queue_count]u64,
    tls_buffer_stalled_drives: [tls_backend_count]u64,
    proxy_client_aborts: u64,
    proxy_upstream_aborts: u64,
    proxy_streaming_fallback_policy_disabled: u64,
    proxy_streaming_fallback_retries_configured: u64,
    proxy_streaming_fallback_unix_socket_target: u64,
    proxy_streaming_fallback_upstream_mtls_target: u64,
    proxy_streaming_fallback_chunked_request_upload: u64,
    proxy_streaming_fallback_missing_content_length: u64,
    proxy_streaming_fallback_body_too_large: u64,
    proxy_streaming_fallback_body_dependent_middleware: u64,
    proxy_streaming_fallback_unsupported_route_type: u64,
    proxy_ttfb_ms_count: u64,
    proxy_ttfb_ms_sum: u64,
    // Upstream keep-alive connection pool (#141). Populated from the pool's own
    // snapshot at render time.
    upstream_connections_new: u64,
    upstream_connections_reused: u64,
    upstream_connections_reused_local: u64,
    upstream_connections_reused_cross_worker: u64,
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
    err_forbidden: u64,
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
    /// #488: native TLS/QUIC resumption attempts by transport.
    tls_resumption_attempt_total: [resumption_transport_count]u64,
    /// #488: native resumption outcomes by transport and outcome.
    tls_resumption_outcome_total: [resumption_transport_count][resumption_outcome_count]u64,
    /// #488: server-side ticket issuance attempts by transport, mode, result.
    tls_ticket_issue_total: [resumption_transport_count][resumption_mode_count][ticket_result_count]u64,
    /// #488: client-side ticket storage attempts by result.
    tls_ticket_store_total: [ticket_result_count]u64,
    /// #488: server-side ticket resolution attempts by mode and result.
    tls_ticket_resolve_total: [resumption_mode_count][ticket_result_count]u64,
    /// HTTP early-data replay-exposed requests by protocol and source.
    http_early_data_requests_total: [http_protocol_count][early_data_source_count]u64,
    /// HTTP early-data decisions by protocol.
    http_early_data_decisions_total: [http_protocol_count][early_data_decision_count]u64,
    /// Upstream 425 handling actions (bounded RFC 8470 semantics only).
    http_early_data_upstream_425_total: [early_data_upstream_425_action_count]u64,
    /// Local one-shot upstream 425 retry outcomes.
    http_early_data_retry_total: [early_data_retry_result_count]u64,
    /// HTTP/3 early-data compatibility outcomes.
    http3_early_data_compat_total: [h3_early_data_compat_decision_count]u64,
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
            .proxy_buffer_downstream_to_upstream_stream_current = 0,
            .proxy_buffer_downstream_to_upstream_global_current = 0,
            .proxy_buffer_upstream_to_downstream_stream_current = 0,
            .proxy_buffer_upstream_to_downstream_global_current = 0,
            .proxy_buffer_high_watermark_downstream_to_upstream_stream = 0,
            .proxy_buffer_high_watermark_upstream_to_downstream_stream = 0,
            .proxy_buffer_limit_exceeded_downstream_to_upstream_stream = 0,
            .proxy_buffer_limit_exceeded_upstream_to_downstream_stream = 0,
            .proxy_buffer_read_pauses_downstream = 0,
            .proxy_buffer_read_pauses_upstream = 0,
            .proxy_buffer_read_resumes_downstream = 0,
            .proxy_buffer_read_resumes_upstream = 0,
            .tls_buffered_bytes_current = zeroTlsQueueMatrix(),
            .tls_buffer_pause_events = zeroTlsDirectionMatrix(),
            .tls_buffer_resume_events = zeroTlsDirectionMatrix(),
            .tls_buffer_limit_exceeded = zeroTlsQueueMatrix(),
            .tls_buffer_stalled_drives = .{0} ** tls_backend_count,
            .proxy_client_aborts = 0,
            .proxy_upstream_aborts = 0,
            .proxy_streaming_fallback_policy_disabled = 0,
            .proxy_streaming_fallback_retries_configured = 0,
            .proxy_streaming_fallback_unix_socket_target = 0,
            .proxy_streaming_fallback_upstream_mtls_target = 0,
            .proxy_streaming_fallback_chunked_request_upload = 0,
            .proxy_streaming_fallback_missing_content_length = 0,
            .proxy_streaming_fallback_body_too_large = 0,
            .proxy_streaming_fallback_body_dependent_middleware = 0,
            .proxy_streaming_fallback_unsupported_route_type = 0,
            .proxy_ttfb_ms_count = 0,
            .proxy_ttfb_ms_sum = 0,
            .upstream_connections_new = 0,
            .upstream_connections_reused = 0,
            .upstream_connections_reused_local = 0,
            .upstream_connections_reused_cross_worker = 0,
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
            .err_forbidden = 0,
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
            .tls_resumption_attempt_total = .{0} ** resumption_transport_count,
            .tls_resumption_outcome_total = .{.{0} ** resumption_outcome_count} ** resumption_transport_count,
            .tls_ticket_issue_total = .{.{.{0} ** ticket_result_count} ** resumption_mode_count} ** resumption_transport_count,
            .tls_ticket_store_total = .{0} ** ticket_result_count,
            .tls_ticket_resolve_total = .{.{0} ** ticket_result_count} ** resumption_mode_count,
            .http_early_data_requests_total = .{.{0} ** early_data_source_count} ** http_protocol_count,
            .http_early_data_decisions_total = .{.{0} ** early_data_decision_count} ** http_protocol_count,
            .http_early_data_upstream_425_total = .{0} ** early_data_upstream_425_action_count,
            .http_early_data_retry_total = .{0} ** early_data_retry_result_count,
            .http3_early_data_compat_total = .{0} ** h3_early_data_compat_decision_count,
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

    /// #488: record one native TLS/QUIC resumption attempt (a connection
    /// where a PSK-bearing ClientHello was offered/resolved).
    pub fn recordResumptionAttempt(self: *Metrics, transport: ResumptionTransport) void {
        self.tls_resumption_attempt_total[resumptionTransportIndex(transport)] += 1;
    }

    /// #488: record the resolved outcome of a resumption attempt.
    pub fn recordResumptionOutcome(self: *Metrics, transport: ResumptionTransport, outcome: ResumptionOutcome) void {
        self.tls_resumption_outcome_total[resumptionTransportIndex(transport)][resumptionOutcomeIndex(outcome)] += 1;
    }

    /// #488: record a server-side post-handshake ticket issuance attempt.
    pub fn recordTicketIssue(self: *Metrics, transport: ResumptionTransport, mode: ResumptionMode, result: TicketResult) void {
        self.tls_ticket_issue_total[resumptionTransportIndex(transport)][resumptionModeIndex(mode)][ticketResultIndex(result)] += 1;
    }

    /// #488: record a client-side ticket storage attempt.
    pub fn recordTicketStore(self: *Metrics, result: TicketResult) void {
        self.tls_ticket_store_total[ticketResultIndex(result)] += 1;
    }

    /// #488: record a server-side ticket/handle resolution attempt.
    pub fn recordTicketResolve(self: *Metrics, mode: ResumptionMode, result: TicketResult) void {
        self.tls_ticket_resolve_total[resumptionModeIndex(mode)][ticketResultIndex(result)] += 1;
    }

    pub fn recordHttpEarlyDataRequest(self: *Metrics, protocol: HttpProtocol, source: EarlyDataSource) void {
        self.http_early_data_requests_total[httpProtocolIndex(protocol)][earlyDataSourceIndex(source)] += 1;
    }

    pub fn recordHttpEarlyDataDecision(self: *Metrics, protocol: HttpProtocol, decision: EarlyDataDecision) void {
        self.http_early_data_decisions_total[httpProtocolIndex(protocol)][earlyDataDecisionIndex(decision)] += 1;
    }

    pub fn recordHttpEarlyDataUpstream425(self: *Metrics, action: EarlyDataUpstream425Action) void {
        self.http_early_data_upstream_425_total[earlyDataUpstream425ActionIndex(action)] += 1;
    }

    pub fn recordHttpEarlyDataRetry(self: *Metrics, result: EarlyDataRetryResult) void {
        self.http_early_data_retry_total[earlyDataRetryResultIndex(result)] += 1;
    }

    pub fn recordHttp3EarlyDataCompat(self: *Metrics, decision: H3EarlyDataCompatDecision) void {
        self.http3_early_data_compat_total[h3EarlyDataCompatDecisionIndex(decision)] += 1;
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
        self.recordProxyBufferBytes(.upstream_to_downstream, .stream, buffered_bytes);
        self.recordProxyBufferBytes(.upstream_to_downstream, .global, buffered_bytes);
        self.recordProxyTtfbMs(ttfb_ms);
    }

    pub fn releaseProxyBufferedBytes(self: *Metrics, buffered_bytes: usize) !void {
        const bytes: u64 = @intCast(buffered_bytes);
        if (bytes > self.proxy_buffered_bytes_current) return error.BufferAccountingUnderflow;
        self.proxy_buffered_bytes_current -= bytes;
        try self.releaseProxyBufferReservation(.upstream_to_downstream, buffered_bytes);
    }

    pub fn recordProxyBufferReservation(
        self: *Metrics,
        direction: proxy_buffer_account.Direction,
        bytes: usize,
        high_watermark: bool,
        limit_exceeded: bool,
    ) void {
        self.recordProxyBufferBytes(direction, .stream, bytes);
        self.recordProxyBufferBytes(direction, .global, bytes);
        if (high_watermark) self.recordProxyBufferHighWatermark(direction, .stream);
        if (limit_exceeded) self.recordProxyBufferLimitExceeded(direction, .stream);
    }

    pub fn releaseProxyBufferReservation(self: *Metrics, direction: proxy_buffer_account.Direction, bytes: usize) !void {
        const value: u64 = @intCast(bytes);
        var stream_slot: *u64 = undefined;
        var global_slot: *u64 = undefined;
        switch (direction) {
            .downstream_to_upstream => {
                stream_slot = &self.proxy_buffer_downstream_to_upstream_stream_current;
                global_slot = &self.proxy_buffer_downstream_to_upstream_global_current;
            },
            .upstream_to_downstream => {
                stream_slot = &self.proxy_buffer_upstream_to_downstream_stream_current;
                global_slot = &self.proxy_buffer_upstream_to_downstream_global_current;
            },
        }
        if (value > stream_slot.* or value > global_slot.*) return error.BufferAccountingUnderflow;
        stream_slot.* -= value;
        global_slot.* -= value;
    }

    pub fn recordProxyBufferBytes(self: *Metrics, direction: proxy_buffer_account.Direction, scope: proxy_buffer_account.Scope, bytes: usize) void {
        const value: u64 = @intCast(bytes);
        switch (direction) {
            .downstream_to_upstream => switch (scope) {
                .stream => self.proxy_buffer_downstream_to_upstream_stream_current += value,
                .global => self.proxy_buffer_downstream_to_upstream_global_current += value,
                else => {},
            },
            .upstream_to_downstream => switch (scope) {
                .stream => self.proxy_buffer_upstream_to_downstream_stream_current += value,
                .global => self.proxy_buffer_upstream_to_downstream_global_current += value,
                else => {},
            },
        }
    }

    pub fn releaseProxyBufferBytes(self: *Metrics, direction: proxy_buffer_account.Direction, scope: proxy_buffer_account.Scope, bytes: usize) !void {
        const value: u64 = @intCast(bytes);
        const slot = switch (direction) {
            .downstream_to_upstream => switch (scope) {
                .stream => &self.proxy_buffer_downstream_to_upstream_stream_current,
                .global => &self.proxy_buffer_downstream_to_upstream_global_current,
                else => return,
            },
            .upstream_to_downstream => switch (scope) {
                .stream => &self.proxy_buffer_upstream_to_downstream_stream_current,
                .global => &self.proxy_buffer_upstream_to_downstream_global_current,
                else => return,
            },
        };
        if (value > slot.*) return error.BufferAccountingUnderflow;
        slot.* -= value;
    }

    pub fn recordProxyBufferHighWatermark(self: *Metrics, direction: proxy_buffer_account.Direction, scope: proxy_buffer_account.Scope) void {
        if (scope != .stream) return;
        switch (direction) {
            .downstream_to_upstream => self.proxy_buffer_high_watermark_downstream_to_upstream_stream += 1,
            .upstream_to_downstream => self.proxy_buffer_high_watermark_upstream_to_downstream_stream += 1,
        }
    }

    pub fn recordProxyBufferLimitExceeded(self: *Metrics, direction: proxy_buffer_account.Direction, scope: proxy_buffer_account.Scope) void {
        if (scope != .stream) return;
        switch (direction) {
            .downstream_to_upstream => self.proxy_buffer_limit_exceeded_downstream_to_upstream_stream += 1,
            .upstream_to_downstream => self.proxy_buffer_limit_exceeded_upstream_to_downstream_stream += 1,
        }
    }

    pub fn recordProxyBufferReadPause(self: *Metrics, side: []const u8) void {
        if (std.mem.eql(u8, side, "downstream")) {
            self.proxy_buffer_read_pauses_downstream += 1;
        } else if (std.mem.eql(u8, side, "upstream")) {
            self.proxy_buffer_read_pauses_upstream += 1;
        }
    }

    pub fn recordProxyBufferReadResume(self: *Metrics, side: []const u8) void {
        if (std.mem.eql(u8, side, "downstream")) {
            self.proxy_buffer_read_resumes_downstream += 1;
        } else if (std.mem.eql(u8, side, "upstream")) {
            self.proxy_buffer_read_resumes_upstream += 1;
        }
    }

    pub fn observeTlsBufferSnapshot(
        self: *Metrics,
        state: *TlsBufferConnectionMetrics,
        backend: encrypted_stream.BackendKind,
        snapshot: encrypted_stream.BufferSnapshot,
    ) !void {
        if (state.active) try self.releaseTlsCurrentBytes(state.backend, state.current);
        self.recordTlsCurrentBytes(backend, snapshot.current);
        if (state.active and state.backend == backend) {
            self.recordTlsCounterDeltas(backend, state.counters, snapshot.counters);
        } else {
            self.recordTlsCounterDeltas(backend, .{}, snapshot.counters);
        }
        state.* = .{
            .active = true,
            .backend = backend,
            .current = snapshot.current,
            .counters = snapshot.counters,
        };
    }

    pub fn releaseTlsBufferSnapshot(self: *Metrics, state: *TlsBufferConnectionMetrics) !void {
        if (!state.active) return;
        try self.releaseTlsCurrentBytes(state.backend, state.current);
        state.* = .{};
    }

    fn recordTlsCurrentBytes(self: *Metrics, backend: encrypted_stream.BackendKind, current: encrypted_stream.QueueBytes) void {
        const backend_idx = tlsBackendIndex(backend);
        self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_ciphertext)] += @intCast(current.inbound_ciphertext);
        self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_plaintext)] += @intCast(current.inbound_plaintext);
        self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.outbound_ciphertext)] += @intCast(current.outbound_ciphertext);
        self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.handshake)] += @intCast(current.handshake);
    }

    fn releaseTlsCurrentBytes(self: *Metrics, backend: encrypted_stream.BackendKind, current: encrypted_stream.QueueBytes) !void {
        const backend_idx = tlsBackendIndex(backend);
        try subtractGauge(&self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_ciphertext)], current.inbound_ciphertext);
        try subtractGauge(&self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_plaintext)], current.inbound_plaintext);
        try subtractGauge(&self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.outbound_ciphertext)], current.outbound_ciphertext);
        try subtractGauge(&self.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.handshake)], current.handshake);
    }

    fn recordTlsCounterDeltas(
        self: *Metrics,
        backend: encrypted_stream.BackendKind,
        previous: encrypted_stream.BufferCounters,
        next: encrypted_stream.BufferCounters,
    ) void {
        const backend_idx = tlsBackendIndex(backend);
        self.tls_buffer_pause_events[backend_idx][tlsDirectionIndex(.carrier_read)] += monotonicDelta(previous.inbound_read_pauses, next.inbound_read_pauses);
        self.tls_buffer_resume_events[backend_idx][tlsDirectionIndex(.carrier_read)] += monotonicDelta(previous.inbound_read_resumes, next.inbound_read_resumes);
        self.tls_buffer_pause_events[backend_idx][tlsDirectionIndex(.plaintext_write)] += monotonicDelta(previous.plaintext_write_pauses, next.plaintext_write_pauses);
        self.tls_buffer_resume_events[backend_idx][tlsDirectionIndex(.plaintext_write)] += monotonicDelta(previous.plaintext_write_resumes, next.plaintext_write_resumes);
        self.tls_buffer_limit_exceeded[backend_idx][tlsQueueIndex(.inbound_ciphertext)] += monotonicDelta(previous.hard_limits.inbound_ciphertext, next.hard_limits.inbound_ciphertext);
        self.tls_buffer_limit_exceeded[backend_idx][tlsQueueIndex(.inbound_plaintext)] += monotonicDelta(previous.hard_limits.inbound_plaintext, next.hard_limits.inbound_plaintext);
        self.tls_buffer_limit_exceeded[backend_idx][tlsQueueIndex(.outbound_ciphertext)] += monotonicDelta(previous.hard_limits.outbound_ciphertext, next.hard_limits.outbound_ciphertext);
        self.tls_buffer_limit_exceeded[backend_idx][tlsQueueIndex(.handshake)] += monotonicDelta(previous.hard_limits.handshake, next.hard_limits.handshake);
        self.tls_buffer_stalled_drives[backend_idx] += monotonicDelta(previous.stalled_drives, next.stalled_drives);
    }

    pub fn recordProxyClientAbort(self: *Metrics) void {
        self.proxy_client_aborts += 1;
    }

    pub fn recordProxyUpstreamAbort(self: *Metrics) void {
        self.proxy_upstream_aborts += 1;
    }

    pub fn recordProxyStreamingFallback(self: *Metrics, reason: []const u8) void {
        if (std.mem.eql(u8, reason, "policy_disabled")) {
            self.proxy_streaming_fallback_policy_disabled += 1;
        } else if (std.mem.eql(u8, reason, "retries_configured")) {
            self.proxy_streaming_fallback_retries_configured += 1;
        } else if (std.mem.eql(u8, reason, "unix_socket_target")) {
            self.proxy_streaming_fallback_unix_socket_target += 1;
        } else if (std.mem.eql(u8, reason, "upstream_mtls_target")) {
            self.proxy_streaming_fallback_upstream_mtls_target += 1;
        } else if (std.mem.eql(u8, reason, "chunked_request_upload")) {
            self.proxy_streaming_fallback_chunked_request_upload += 1;
        } else if (std.mem.eql(u8, reason, "missing_content_length")) {
            self.proxy_streaming_fallback_missing_content_length += 1;
        } else if (std.mem.eql(u8, reason, "body_too_large")) {
            self.proxy_streaming_fallback_body_too_large += 1;
        } else if (std.mem.eql(u8, reason, "body_dependent_middleware")) {
            self.proxy_streaming_fallback_body_dependent_middleware += 1;
        } else if (std.mem.eql(u8, reason, "unsupported_route_type")) {
            self.proxy_streaming_fallback_unsupported_route_type += 1;
        }
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
        } else if (std.mem.eql(u8, code, "forbidden")) {
            self.err_forbidden += 1;
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
            \\
        , .{
            self.proxy_streaming_requests,
            self.proxy_buffered_requests,
            self.proxy_buffered_bytes_current,
            self.proxy_buffered_bytes_total,
        });

        try out.print(
            \\# HELP tardigrade_buffered_bytes_current Current proxy-owned body bytes by direction and accounting scope
            \\# TYPE tardigrade_buffered_bytes_current gauge
            \\tardigrade_buffered_bytes_current{{direction="downstream_to_upstream",scope="stream"}} {d}
            \\tardigrade_buffered_bytes_current{{direction="downstream_to_upstream",scope="global"}} {d}
            \\tardigrade_buffered_bytes_current{{direction="upstream_to_downstream",scope="stream"}} {d}
            \\tardigrade_buffered_bytes_current{{direction="upstream_to_downstream",scope="global"}} {d}
            \\# HELP tardigrade_buffer_high_watermark_events_total Proxy buffer high-watermark transitions by direction and scope
            \\# TYPE tardigrade_buffer_high_watermark_events_total counter
            \\tardigrade_buffer_high_watermark_events_total{{direction="downstream_to_upstream",scope="stream"}} {d}
            \\tardigrade_buffer_high_watermark_events_total{{direction="upstream_to_downstream",scope="stream"}} {d}
            \\# HELP tardigrade_buffer_read_pauses_total Reserved for future proxy reads paused by stalled buffer pressure side
            \\# TYPE tardigrade_buffer_read_pauses_total counter
            \\tardigrade_buffer_read_pauses_total{{side="downstream"}} {d}
            \\tardigrade_buffer_read_pauses_total{{side="upstream"}} {d}
            \\# HELP tardigrade_buffer_read_resumes_total Reserved for future proxy reads resumed after buffer pressure drops
            \\# TYPE tardigrade_buffer_read_resumes_total counter
            \\tardigrade_buffer_read_resumes_total{{side="downstream"}} {d}
            \\tardigrade_buffer_read_resumes_total{{side="upstream"}} {d}
            \\# HELP tardigrade_buffer_limit_exceeded_total Proxy buffer hard-limit exceedance events by direction and scope
            \\# TYPE tardigrade_buffer_limit_exceeded_total counter
            \\tardigrade_buffer_limit_exceeded_total{{direction="downstream_to_upstream",scope="stream"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="upstream_to_downstream",scope="stream"}} {d}
            \\
        , .{
            self.proxy_buffer_downstream_to_upstream_stream_current,
            self.proxy_buffer_downstream_to_upstream_global_current,
            self.proxy_buffer_upstream_to_downstream_stream_current,
            self.proxy_buffer_upstream_to_downstream_global_current,
            self.proxy_buffer_high_watermark_downstream_to_upstream_stream,
            self.proxy_buffer_high_watermark_upstream_to_downstream_stream,
            self.proxy_buffer_read_pauses_downstream,
            self.proxy_buffer_read_pauses_upstream,
            self.proxy_buffer_read_resumes_downstream,
            self.proxy_buffer_read_resumes_upstream,
            self.proxy_buffer_limit_exceeded_downstream_to_upstream_stream,
            self.proxy_buffer_limit_exceeded_upstream_to_downstream_stream,
        });

        try self.appendTlsBufferPrometheus(&out);
        try self.appendResumptionPrometheus(&out);
        try self.appendHttpEarlyDataPrometheus(&out);

        try out.print(
            \\# HELP tardigrade_proxy_client_aborts_total Total proxied transfers aborted by downstream clients
            \\# TYPE tardigrade_proxy_client_aborts_total counter
            \\tardigrade_proxy_client_aborts_total {d}
            \\# HELP tardigrade_proxy_upstream_aborts_total Total proxied transfers aborted by upstream origins
            \\# TYPE tardigrade_proxy_upstream_aborts_total counter
            \\tardigrade_proxy_upstream_aborts_total {d}
            \\# HELP tardigrade_proxy_streaming_fallback_total Total streaming eligibility fallback events by reason
            \\# TYPE tardigrade_proxy_streaming_fallback_total counter
            \\tardigrade_proxy_streaming_fallback_total{{reason="policy_disabled"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="retries_configured"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="unix_socket_target"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="upstream_mtls_target"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="chunked_request_upload"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="missing_content_length"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="body_too_large"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="body_dependent_middleware"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="unsupported_route_type"}} {d}
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
            \\# HELP tardigrade_upstream_connections_reused_local_total Pool reuses reclaimed by the same worker thread that parked them
            \\# TYPE tardigrade_upstream_connections_reused_local_total counter
            \\tardigrade_upstream_connections_reused_local_total {d}
            \\# HELP tardigrade_upstream_connections_reused_cross_worker_total Pool reuses reclaimed by a different worker thread (shared-pool cross-worker reuse)
            \\# TYPE tardigrade_upstream_connections_reused_cross_worker_total counter
            \\tardigrade_upstream_connections_reused_cross_worker_total {d}
            \\# HELP tardigrade_upstream_connections_idle Upstream connections currently held idle in the pool
            \\# TYPE tardigrade_upstream_connections_idle gauge
            \\tardigrade_upstream_connections_idle {d}
            \\# HELP tardigrade_upstream_stale_retries_total Idempotent retries after a reused upstream connection was found dead
            \\# TYPE tardigrade_upstream_stale_retries_total counter
            \\tardigrade_upstream_stale_retries_total {d}
            \\
        , .{
            self.proxy_client_aborts,
            self.proxy_upstream_aborts,
            self.proxy_streaming_fallback_policy_disabled,
            self.proxy_streaming_fallback_retries_configured,
            self.proxy_streaming_fallback_unix_socket_target,
            self.proxy_streaming_fallback_upstream_mtls_target,
            self.proxy_streaming_fallback_chunked_request_upload,
            self.proxy_streaming_fallback_missing_content_length,
            self.proxy_streaming_fallback_body_too_large,
            self.proxy_streaming_fallback_body_dependent_middleware,
            self.proxy_streaming_fallback_unsupported_route_type,
            self.proxy_ttfb_ms_sum,
            self.proxy_ttfb_ms_count,
            self.upstream_connections_new,
            self.upstream_connections_reused,
            self.upstream_connections_reused_local,
            self.upstream_connections_reused_cross_worker,
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
            \\# HELP tardigrade_error_forbidden_total Total forbidden API errors
            \\# TYPE tardigrade_error_forbidden_total counter
            \\tardigrade_error_forbidden_total {d}
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
            self.err_forbidden,
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

    fn appendTlsBufferPrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffered_bytes_current Current TLS-owned or adapter-measurable bytes by backend and queue
            \\# TYPE tardigrade_tls_buffered_bytes_current gauge
            \\
        );
        inline for (.{ encrypted_stream.BackendKind.openssl, encrypted_stream.BackendKind.pure_zig_record }) |backend| {
            inline for (.{ TlsQueue.inbound_ciphertext, TlsQueue.inbound_plaintext, TlsQueue.outbound_ciphertext, TlsQueue.handshake }) |queue| {
                try out.print("tardigrade_tls_buffered_bytes_current{{backend=\"{s}\",queue=\"{s}\"}} {d}\n", .{
                    tlsBackendLabel(backend),
                    tlsQueueLabel(queue),
                    self.tls_buffered_bytes_current[tlsBackendIndex(backend)][tlsQueueIndex(queue)],
                });
            }
        }
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffer_pause_events_total TLS buffer pause transitions by backend and direction
            \\# TYPE tardigrade_tls_buffer_pause_events_total counter
            \\
        );
        inline for (.{ encrypted_stream.BackendKind.openssl, encrypted_stream.BackendKind.pure_zig_record }) |backend| {
            inline for (.{ TlsDirection.carrier_read, TlsDirection.plaintext_write }) |direction| {
                try out.print("tardigrade_tls_buffer_pause_events_total{{backend=\"{s}\",direction=\"{s}\"}} {d}\n", .{
                    tlsBackendLabel(backend),
                    tlsDirectionLabel(direction),
                    self.tls_buffer_pause_events[tlsBackendIndex(backend)][tlsDirectionIndex(direction)],
                });
            }
        }
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffer_resume_events_total TLS buffer resume transitions by backend and direction
            \\# TYPE tardigrade_tls_buffer_resume_events_total counter
            \\
        );
        inline for (.{ encrypted_stream.BackendKind.openssl, encrypted_stream.BackendKind.pure_zig_record }) |backend| {
            inline for (.{ TlsDirection.carrier_read, TlsDirection.plaintext_write }) |direction| {
                try out.print("tardigrade_tls_buffer_resume_events_total{{backend=\"{s}\",direction=\"{s}\"}} {d}\n", .{
                    tlsBackendLabel(backend),
                    tlsDirectionLabel(direction),
                    self.tls_buffer_resume_events[tlsBackendIndex(backend)][tlsDirectionIndex(direction)],
                });
            }
        }
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffer_limit_exceeded_total TLS buffer hard-limit exceedance events by backend and queue
            \\# TYPE tardigrade_tls_buffer_limit_exceeded_total counter
            \\
        );
        inline for (.{ encrypted_stream.BackendKind.openssl, encrypted_stream.BackendKind.pure_zig_record }) |backend| {
            inline for (.{ TlsQueue.inbound_ciphertext, TlsQueue.inbound_plaintext, TlsQueue.outbound_ciphertext, TlsQueue.handshake }) |queue| {
                try out.print("tardigrade_tls_buffer_limit_exceeded_total{{backend=\"{s}\",queue=\"{s}\"}} {d}\n", .{
                    tlsBackendLabel(backend),
                    tlsQueueLabel(queue),
                    self.tls_buffer_limit_exceeded[tlsBackendIndex(backend)][tlsQueueIndex(queue)],
                });
            }
        }
        try out.appendSlice(
            \\# HELP tardigrade_tls_buffer_stalled_drives_total TLS drive calls that made no progress while backpressured
            \\# TYPE tardigrade_tls_buffer_stalled_drives_total counter
            \\
        );
        inline for (.{ encrypted_stream.BackendKind.openssl, encrypted_stream.BackendKind.pure_zig_record }) |backend| {
            try out.print("tardigrade_tls_buffer_stalled_drives_total{{backend=\"{s}\"}} {d}\n", .{
                tlsBackendLabel(backend),
                self.tls_buffer_stalled_drives[tlsBackendIndex(backend)],
            });
        }
    }

    /// #488: native TLS/QUIC resumption and ticket counters. Every label
    /// rendered here comes from a fixed, closed enum (`resumption*Label`/
    /// `ticketResultLabel`) — never a raw secret or high-cardinality value.
    fn appendResumptionPrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_tls_resumption_attempt_total Native TLS/QUIC resumption attempts by transport
            \\# TYPE tardigrade_tls_resumption_attempt_total counter
            \\
        );
        inline for (.{ ResumptionTransport.record, ResumptionTransport.quic }) |transport| {
            try out.print("tardigrade_tls_resumption_attempt_total{{transport=\"{s}\"}} {d}\n", .{
                resumptionTransportLabel(transport),
                self.tls_resumption_attempt_total[resumptionTransportIndex(transport)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_tls_resumption_outcome_total Native TLS/QUIC resumption outcomes by transport and outcome
            \\# TYPE tardigrade_tls_resumption_outcome_total counter
            \\
        );
        inline for (.{ ResumptionTransport.record, ResumptionTransport.quic }) |transport| {
            inline for (.{ ResumptionOutcome.accepted, ResumptionOutcome.full_handshake, ResumptionOutcome.incompatible, ResumptionOutcome.miss, ResumptionOutcome.fatal }) |outcome| {
                try out.print("tardigrade_tls_resumption_outcome_total{{transport=\"{s}\",outcome=\"{s}\"}} {d}\n", .{
                    resumptionTransportLabel(transport),
                    resumptionOutcomeLabel(outcome),
                    self.tls_resumption_outcome_total[resumptionTransportIndex(transport)][resumptionOutcomeIndex(outcome)],
                });
            }
        }

        try out.appendSlice(
            \\# HELP tardigrade_tls_ticket_issue_total Server-side ticket issuance attempts by transport, mode, and result
            \\# TYPE tardigrade_tls_ticket_issue_total counter
            \\
        );
        inline for (.{ ResumptionTransport.record, ResumptionTransport.quic }) |transport| {
            inline for (.{ ResumptionMode.stateful, ResumptionMode.stateless, ResumptionMode.hybrid }) |mode| {
                inline for (.{ TicketResult.success, TicketResult.rejected, TicketResult.failed }) |result| {
                    try out.print("tardigrade_tls_ticket_issue_total{{transport=\"{s}\",mode=\"{s}\",result=\"{s}\"}} {d}\n", .{
                        resumptionTransportLabel(transport),
                        resumptionModeLabel(mode),
                        ticketResultLabel(result),
                        self.tls_ticket_issue_total[resumptionTransportIndex(transport)][resumptionModeIndex(mode)][ticketResultIndex(result)],
                    });
                }
            }
        }

        try out.appendSlice(
            \\# HELP tardigrade_tls_ticket_store_total Client-side ticket storage attempts by result
            \\# TYPE tardigrade_tls_ticket_store_total counter
            \\
        );
        inline for (.{ TicketResult.success, TicketResult.rejected, TicketResult.failed }) |result| {
            try out.print("tardigrade_tls_ticket_store_total{{result=\"{s}\"}} {d}\n", .{
                ticketResultLabel(result),
                self.tls_ticket_store_total[ticketResultIndex(result)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_tls_ticket_resolve_total Server-side ticket/handle resolution attempts by mode and result
            \\# TYPE tardigrade_tls_ticket_resolve_total counter
            \\
        );
        inline for (.{ ResumptionMode.stateful, ResumptionMode.stateless, ResumptionMode.hybrid }) |mode| {
            inline for (.{ TicketResult.success, TicketResult.rejected, TicketResult.failed }) |result| {
                try out.print("tardigrade_tls_ticket_resolve_total{{mode=\"{s}\",result=\"{s}\"}} {d}\n", .{
                    resumptionModeLabel(mode),
                    ticketResultLabel(result),
                    self.tls_ticket_resolve_total[resumptionModeIndex(mode)][ticketResultIndex(result)],
                });
            }
        }
    }

    fn appendHttpEarlyDataPrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_http_early_data_requests_total Replay-exposed HTTP requests by protocol and source
            \\# TYPE tardigrade_http_early_data_requests_total counter
            \\
        );
        inline for (.{ HttpProtocol.h1, HttpProtocol.h2, HttpProtocol.h3 }) |protocol| {
            inline for (.{ EarlyDataSource.transport, EarlyDataSource.header, EarlyDataSource.both }) |source| {
                try out.print("tardigrade_http_early_data_requests_total{{protocol=\"{s}\",source=\"{s}\"}} {d}\n", .{
                    httpProtocolLabel(protocol),
                    earlyDataSourceLabel(source),
                    self.http_early_data_requests_total[httpProtocolIndex(protocol)][earlyDataSourceIndex(source)],
                });
            }
        }

        try out.appendSlice(
            \\# HELP tardigrade_http_early_data_decisions_total Early-data policy decisions by protocol
            \\# TYPE tardigrade_http_early_data_decisions_total counter
            \\
        );
        inline for (.{ HttpProtocol.h1, HttpProtocol.h2, HttpProtocol.h3 }) |protocol| {
            inline for (.{ EarlyDataDecision.accepted, EarlyDataDecision.too_early, EarlyDataDecision.deferred, EarlyDataDecision.forwarded }) |decision| {
                try out.print("tardigrade_http_early_data_decisions_total{{protocol=\"{s}\",decision=\"{s}\"}} {d}\n", .{
                    httpProtocolLabel(protocol),
                    earlyDataDecisionLabel(decision),
                    self.http_early_data_decisions_total[httpProtocolIndex(protocol)][earlyDataDecisionIndex(decision)],
                });
            }
        }

        try out.appendSlice(
            \\# HELP tardigrade_http_early_data_upstream_425_total Upstream 425 handling actions
            \\# TYPE tardigrade_http_early_data_upstream_425_total counter
            \\
        );
        inline for (.{ EarlyDataUpstream425Action.forwarded, EarlyDataUpstream425Action.retried }) |action| {
            try out.print("tardigrade_http_early_data_upstream_425_total{{action=\"{s}\"}} {d}\n", .{
                earlyDataUpstream425ActionLabel(action),
                self.http_early_data_upstream_425_total[earlyDataUpstream425ActionIndex(action)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_http_early_data_retry_total Bounded local upstream-425 retry outcomes
            \\# TYPE tardigrade_http_early_data_retry_total counter
            \\
        );
        inline for (.{ EarlyDataRetryResult.success, EarlyDataRetryResult.too_early, EarlyDataRetryResult.failure }) |result| {
            try out.print("tardigrade_http_early_data_retry_total{{result=\"{s}\"}} {d}\n", .{
                earlyDataRetryResultLabel(result),
                self.http_early_data_retry_total[earlyDataRetryResultIndex(result)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_http3_early_data_compat_total HTTP/3 early-data compatibility outcomes
            \\# TYPE tardigrade_http3_early_data_compat_total counter
            \\
        );
        inline for (.{ H3EarlyDataCompatDecision.compatible, H3EarlyDataCompatDecision.transport_incompatible, H3EarlyDataCompatDecision.settings_incompatible, H3EarlyDataCompatDecision.missing_state }) |decision| {
            try out.print("tardigrade_http3_early_data_compat_total{{decision=\"{s}\"}} {d}\n", .{
                h3EarlyDataCompatDecisionLabel(decision),
                self.http3_early_data_compat_total[h3EarlyDataCompatDecisionIndex(decision)],
            });
        }
    }

    /// Format metrics as a JSON string.
    /// Caller owns the returned memory.
    pub fn toJson(self: *const Metrics, allocator: std.mem.Allocator) ![]u8 {
        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        try out.print(
            \\{{"total_requests":{d},"status_2xx":{d},"status_3xx":{d},"status_4xx":{d},"status_5xx":{d},"uptime_seconds":{d},"active_connections":{d},"mux_connections":{d},"mux_subscriptions":{d},"connection_rejections":{d},"queue_rejections":{d},"upstream_unhealthy_backends":{d},"proxy_streaming_requests_total":{d},"proxy_buffered_requests_total":{d},"proxy_buffered_bytes_current":{d},"proxy_buffered_bytes_total":{d},"proxy_client_aborts_total":{d},"proxy_upstream_aborts_total":{d},"proxy_ttfb_ms_count":{d},"proxy_ttfb_ms_sum":{d},"upstream_connections_new_total":{d},"upstream_connections_reused_total":{d},"upstream_connections_reused_local_total":{d},"upstream_connections_reused_cross_worker_total":{d},"upstream_connections_idle":{d},"upstream_stale_retries_total":{d}
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
            self.upstream_connections_reused_local,
            self.upstream_connections_reused_cross_worker,
            self.upstream_connections_idle,
            self.upstream_stale_retries,
        });
        try out.print(
            \\,"request_latency_ms_count":{d},"request_latency_ms_sum":{d},"worker_active_jobs":{d},"worker_queued_jobs":{d},"worker_threads":{d},"worker_queue_capacity":{d},"worker_queue_wait_count":{d},"worker_queue_wait_sum_us":{d},"error_invalid_request":{d},"error_unauthorized":{d},"error_forbidden":{d},"error_rate_limited":{d},"error_upstream_timeout":{d},"error_upstream_unavailable":{d},"error_internal_error":{d},"error_overload":{d},"error_request_timeout":{d},"mux_frame_errors":{d},"event_loop_iterations":{d},"health_probe_runs":{d},"reload_attempts_total":{d},"reload_success_total":{d},"reload_failure_total":{d},"drain_total":{d},"drain_timeouts_total":{d},"drain_forced_closes_total":{d}}}
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
            self.err_forbidden,
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

fn zeroTlsQueueMatrix() [tls_backend_count][tls_queue_count]u64 {
    return .{.{0} ** tls_queue_count} ** tls_backend_count;
}

fn zeroTlsDirectionMatrix() [tls_backend_count][tls_direction_count]u64 {
    return .{.{0} ** tls_direction_count} ** tls_backend_count;
}

fn tlsBackendIndex(backend: encrypted_stream.BackendKind) usize {
    return switch (backend) {
        .openssl => 0,
        .pure_zig_record => 1,
    };
}

fn tlsQueueIndex(queue: TlsQueue) usize {
    return switch (queue) {
        .inbound_ciphertext => 0,
        .inbound_plaintext => 1,
        .outbound_ciphertext => 2,
        .handshake => 3,
    };
}

fn tlsDirectionIndex(direction: TlsDirection) usize {
    return switch (direction) {
        .carrier_read => 0,
        .plaintext_write => 1,
    };
}

fn tlsBackendLabel(backend: encrypted_stream.BackendKind) []const u8 {
    return switch (backend) {
        .openssl => "openssl",
        .pure_zig_record => "pure_zig_record",
    };
}

fn tlsQueueLabel(queue: TlsQueue) []const u8 {
    return switch (queue) {
        .inbound_ciphertext => "inbound_ciphertext",
        .inbound_plaintext => "inbound_plaintext",
        .outbound_ciphertext => "outbound_ciphertext",
        .handshake => "handshake",
    };
}

fn tlsDirectionLabel(direction: TlsDirection) []const u8 {
    return switch (direction) {
        .carrier_read => "carrier_read",
        .plaintext_write => "plaintext_write",
    };
}

fn resumptionTransportIndex(transport: ResumptionTransport) usize {
    return switch (transport) {
        .record => 0,
        .quic => 1,
    };
}

fn resumptionOutcomeIndex(outcome: ResumptionOutcome) usize {
    return switch (outcome) {
        .accepted => 0,
        .full_handshake => 1,
        .incompatible => 2,
        .miss => 3,
        .fatal => 4,
    };
}

fn resumptionModeIndex(mode: ResumptionMode) usize {
    return switch (mode) {
        .stateful => 0,
        .stateless => 1,
        .hybrid => 2,
    };
}

fn ticketResultIndex(result: TicketResult) usize {
    return switch (result) {
        .success => 0,
        .rejected => 1,
        .failed => 2,
    };
}

fn resumptionTransportLabel(transport: ResumptionTransport) []const u8 {
    return switch (transport) {
        .record => "record",
        .quic => "quic",
    };
}

fn resumptionOutcomeLabel(outcome: ResumptionOutcome) []const u8 {
    return switch (outcome) {
        .accepted => "accepted",
        .full_handshake => "full_handshake",
        .incompatible => "incompatible",
        .miss => "miss",
        .fatal => "fatal",
    };
}

fn resumptionModeLabel(mode: ResumptionMode) []const u8 {
    return switch (mode) {
        .stateful => "stateful",
        .stateless => "stateless",
        .hybrid => "hybrid",
    };
}

fn ticketResultLabel(result: TicketResult) []const u8 {
    return switch (result) {
        .success => "success",
        .rejected => "rejected",
        .failed => "failed",
    };
}

fn httpProtocolIndex(protocol: HttpProtocol) usize {
    return switch (protocol) {
        .h1 => 0,
        .h2 => 1,
        .h3 => 2,
    };
}

fn earlyDataSourceIndex(source: EarlyDataSource) usize {
    return switch (source) {
        .transport => 0,
        .header => 1,
        .both => 2,
    };
}

fn earlyDataDecisionIndex(decision: EarlyDataDecision) usize {
    return switch (decision) {
        .accepted => 0,
        .too_early => 1,
        .deferred => 2,
        .forwarded => 3,
    };
}

fn earlyDataUpstream425ActionIndex(action: EarlyDataUpstream425Action) usize {
    return switch (action) {
        .forwarded => 0,
        .retried => 1,
    };
}

fn earlyDataRetryResultIndex(result: EarlyDataRetryResult) usize {
    return switch (result) {
        .success => 0,
        .too_early => 1,
        .failure => 2,
    };
}

fn h3EarlyDataCompatDecisionIndex(decision: H3EarlyDataCompatDecision) usize {
    return switch (decision) {
        .compatible => 0,
        .transport_incompatible => 1,
        .settings_incompatible => 2,
        .missing_state => 3,
    };
}

fn httpProtocolLabel(protocol: HttpProtocol) []const u8 {
    return switch (protocol) {
        .h1 => "h1",
        .h2 => "h2",
        .h3 => "h3",
    };
}

fn earlyDataSourceLabel(source: EarlyDataSource) []const u8 {
    return switch (source) {
        .transport => "transport",
        .header => "header",
        .both => "both",
    };
}

fn earlyDataDecisionLabel(decision: EarlyDataDecision) []const u8 {
    return switch (decision) {
        .accepted => "accepted",
        .too_early => "too_early",
        .deferred => "deferred",
        .forwarded => "forwarded",
    };
}

fn earlyDataUpstream425ActionLabel(action: EarlyDataUpstream425Action) []const u8 {
    return switch (action) {
        .forwarded => "forwarded",
        .retried => "retried",
    };
}

fn earlyDataRetryResultLabel(result: EarlyDataRetryResult) []const u8 {
    return switch (result) {
        .success => "success",
        .too_early => "too_early",
        .failure => "failure",
    };
}

fn h3EarlyDataCompatDecisionLabel(decision: H3EarlyDataCompatDecision) []const u8 {
    return switch (decision) {
        .compatible => "compatible",
        .transport_incompatible => "transport_incompatible",
        .settings_incompatible => "settings_incompatible",
        .missing_state => "missing_state",
    };
}

fn monotonicDelta(previous: u64, next: u64) u64 {
    return if (next >= previous) next - previous else next;
}

fn subtractGauge(slot: *u64, amount: usize) !void {
    const value: u64 = @intCast(amount);
    if (value > slot.*) return error.BufferAccountingUnderflow;
    slot.* -= value;
}

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
    try m.releaseProxyBufferedBytes(64);
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
    m.recordErrorCode("forbidden");
    m.recordErrorCode("overload");
    try std.testing.expectEqual(@as(u64, 1), m.err_invalid_request);
    try std.testing.expectEqual(@as(u64, 1), m.err_forbidden);
    try std.testing.expectEqual(@as(u64, 1), m.err_overload);
}

test "Metrics proxy buffer release reports accounting underflow" {
    var m = Metrics.init();
    m.recordProxyBufferBytes(.upstream_to_downstream, .stream, 32);
    try m.releaseProxyBufferBytes(.upstream_to_downstream, .stream, 16);
    try std.testing.expectEqual(@as(u64, 16), m.proxy_buffer_upstream_to_downstream_stream_current);
    try std.testing.expectError(error.BufferAccountingUnderflow, m.releaseProxyBufferBytes(.upstream_to_downstream, .stream, 17));
    try std.testing.expectEqual(@as(u64, 16), m.proxy_buffer_upstream_to_downstream_stream_current);

    m.recordProxyBufferedRequest(8, 0);
    try std.testing.expectError(error.BufferAccountingUnderflow, m.releaseProxyBufferedBytes(9));
    try std.testing.expectEqual(@as(u64, 8), m.proxy_buffered_bytes_current);
}

test "Metrics TLS buffer observation applies current bytes and counter deltas once" {
    var m = Metrics.init();
    var state = TlsBufferConnectionMetrics{};
    const backend = encrypted_stream.BackendKind.pure_zig_record;
    const backend_idx = tlsBackendIndex(backend);

    const snapshot = encrypted_stream.BufferSnapshot{
        .current = .{
            .inbound_ciphertext = 11,
            .inbound_plaintext = 7,
            .outbound_ciphertext = 13,
            .handshake = 3,
        },
        .counters = .{
            .inbound_read_pauses = 1,
            .inbound_read_resumes = 1,
            .plaintext_write_pauses = 2,
            .plaintext_write_resumes = 1,
            .hard_limits = .{ .outbound_ciphertext = 1 },
            .stalled_drives = 4,
        },
    };

    try m.observeTlsBufferSnapshot(&state, backend, snapshot);
    try m.observeTlsBufferSnapshot(&state, backend, snapshot);

    try std.testing.expectEqual(@as(u64, 11), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_ciphertext)]);
    try std.testing.expectEqual(@as(u64, 13), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.outbound_ciphertext)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_buffer_pause_events[backend_idx][tlsDirectionIndex(.carrier_read)]);
    try std.testing.expectEqual(@as(u64, 2), m.tls_buffer_pause_events[backend_idx][tlsDirectionIndex(.plaintext_write)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_buffer_limit_exceeded[backend_idx][tlsQueueIndex(.outbound_ciphertext)]);
    try std.testing.expectEqual(@as(u64, 4), m.tls_buffer_stalled_drives[backend_idx]);

    try m.releaseTlsBufferSnapshot(&state);
    try std.testing.expectEqual(@as(u64, 0), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_ciphertext)]);
    try std.testing.expectEqual(@as(u64, 0), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.outbound_ciphertext)]);
}

test "Metrics TLS buffer current bytes remain per connection and underflow reports" {
    var m = Metrics.init();
    var first = TlsBufferConnectionMetrics{};
    var second = TlsBufferConnectionMetrics{};
    const backend = encrypted_stream.BackendKind.pure_zig_record;
    const backend_idx = tlsBackendIndex(backend);

    try m.observeTlsBufferSnapshot(&first, backend, .{ .current = .{ .inbound_plaintext = 10 } });
    try m.observeTlsBufferSnapshot(&second, backend, .{ .current = .{ .inbound_plaintext = 7 } });
    try std.testing.expectEqual(@as(u64, 17), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_plaintext)]);

    try m.releaseTlsBufferSnapshot(&first);
    try std.testing.expectEqual(@as(u64, 7), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_plaintext)]);
    try m.releaseTlsBufferSnapshot(&second);
    try std.testing.expectEqual(@as(u64, 0), m.tls_buffered_bytes_current[backend_idx][tlsQueueIndex(.inbound_plaintext)]);

    var corrupted = TlsBufferConnectionMetrics{
        .active = true,
        .backend = backend,
        .current = .{ .inbound_plaintext = 1 },
    };
    try std.testing.expectError(error.BufferAccountingUnderflow, m.releaseTlsBufferSnapshot(&corrupted));
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
    m.recordProxyBufferHighWatermark(.upstream_to_downstream, .stream);
    m.recordProxyBufferReadPause("upstream");
    m.recordProxyBufferReadResume("upstream");
    m.recordProxyBufferLimitExceeded(.upstream_to_downstream, .stream);

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
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffered_bytes_current{direction=\"upstream_to_downstream\",scope=\"stream\"} 42") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_high_watermark_events_total{direction=\"upstream_to_downstream\",scope=\"stream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_read_pauses_total{side=\"upstream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_read_resumes_total{side=\"upstream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_limit_exceeded_total{direction=\"upstream_to_downstream\",scope=\"stream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_ttfb_ms_count 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_active_jobs") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_worker_queued_jobs") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_error_invalid_request_total") != null);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_requests_total counter") != null);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_uptime_seconds gauge") != null);
}

test "resumption and ticket counters default to zero and record by label (#488)" {
    var m = Metrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.tls_resumption_attempt_total[resumptionTransportIndex(.record)]);
    try std.testing.expectEqual(@as(u64, 0), m.tls_resumption_attempt_total[resumptionTransportIndex(.quic)]);

    m.recordResumptionAttempt(.record);
    m.recordResumptionAttempt(.record);
    m.recordResumptionAttempt(.quic);
    try std.testing.expectEqual(@as(u64, 2), m.tls_resumption_attempt_total[resumptionTransportIndex(.record)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_resumption_attempt_total[resumptionTransportIndex(.quic)]);

    m.recordResumptionOutcome(.record, .accepted);
    m.recordResumptionOutcome(.quic, .full_handshake);
    m.recordResumptionOutcome(.quic, .fatal);
    try std.testing.expectEqual(@as(u64, 1), m.tls_resumption_outcome_total[resumptionTransportIndex(.record)][resumptionOutcomeIndex(.accepted)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_resumption_outcome_total[resumptionTransportIndex(.quic)][resumptionOutcomeIndex(.full_handshake)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_resumption_outcome_total[resumptionTransportIndex(.quic)][resumptionOutcomeIndex(.fatal)]);

    m.recordTicketIssue(.record, .stateful, .success);
    m.recordTicketIssue(.quic, .hybrid, .failed);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_issue_total[resumptionTransportIndex(.record)][resumptionModeIndex(.stateful)][ticketResultIndex(.success)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_issue_total[resumptionTransportIndex(.quic)][resumptionModeIndex(.hybrid)][ticketResultIndex(.failed)]);

    m.recordTicketStore(.success);
    m.recordTicketStore(.rejected);
    m.recordTicketStore(.rejected);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_store_total[ticketResultIndex(.success)]);
    try std.testing.expectEqual(@as(u64, 2), m.tls_ticket_store_total[ticketResultIndex(.rejected)]);

    m.recordTicketResolve(.stateless, .success);
    m.recordTicketResolve(.stateless, .failed);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_resolve_total[resumptionModeIndex(.stateless)][ticketResultIndex(.success)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_resolve_total[resumptionModeIndex(.stateless)][ticketResultIndex(.failed)]);
}

test "resumption and ticket counters appear in Prometheus output with closed-enum labels only (#488)" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordResumptionAttempt(.quic);
    m.recordResumptionOutcome(.quic, .accepted);
    m.recordTicketIssue(.record, .stateful, .success);
    m.recordTicketStore(.success);
    m.recordTicketResolve(.hybrid, .success);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_resumption_attempt_total{transport=\"quic\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_resumption_outcome_total{transport=\"quic\",outcome=\"accepted\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_issue_total{transport=\"record\",mode=\"stateful\",result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_store_total{result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_resolve_total{mode=\"hybrid\",result=\"success\"} 1") != null);
}

test "Metrics records proxy streaming fallback reasons" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordProxyStreamingFallback("policy_disabled");
    m.recordProxyStreamingFallback("retries_configured");
    m.recordProxyStreamingFallback("unix_socket_target");
    m.recordProxyStreamingFallback("upstream_mtls_target");
    m.recordProxyStreamingFallback("chunked_request_upload");
    m.recordProxyStreamingFallback("missing_content_length");
    m.recordProxyStreamingFallback("body_too_large");
    m.recordProxyStreamingFallback("body_dependent_middleware");
    m.recordProxyStreamingFallback("unsupported_route_type");

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"policy_disabled\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"retries_configured\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"unix_socket_target\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"upstream_mtls_target\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"chunked_request_upload\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"missing_content_length\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"body_too_large\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"body_dependent_middleware\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_streaming_fallback_total{reason=\"unsupported_route_type\"} 1") != null);
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

test "early-data metrics record bounded labels and emit Prometheus series" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();

    m.recordHttpEarlyDataRequest(.h1, .header);
    m.recordHttpEarlyDataRequest(.h2, .transport);
    m.recordHttpEarlyDataDecision(.h1, .too_early);
    m.recordHttpEarlyDataDecision(.h2, .deferred);
    m.recordHttpEarlyDataDecision(.h3, .accepted);
    m.recordHttpEarlyDataUpstream425(.forwarded);
    m.recordHttpEarlyDataUpstream425(.retried);
    m.recordHttpEarlyDataRetry(.success);
    m.recordHttpEarlyDataRetry(.too_early);
    m.recordHttp3EarlyDataCompat(.compatible);
    m.recordHttp3EarlyDataCompat(.missing_state);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h1\",source=\"header\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h2\",source=\"transport\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h1\",decision=\"too_early\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h2\",decision=\"deferred\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h3\",decision=\"accepted\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"forwarded\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_upstream_425_total{action=\"retried\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_retry_total{result=\"too_early\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http3_early_data_compat_total{decision=\"compatible\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http3_early_data_compat_total{decision=\"missing_state\"} 1") != null);
}
