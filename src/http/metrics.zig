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
pub const TicketKeyReloadOutcome = enum { initial_load_success, initial_load_failure, reload_accepted, reload_rejected };

pub const HttpProtocol = enum { h1, h2, h3 };
pub const ResponseWriteMode = enum { writev, single_write, tls_buffered, fallback };
pub const AcceptErrorReason = enum {
    poll,
    accept,

    pub fn label(self: AcceptErrorReason) []const u8 {
        return @tagName(self);
    }
};

/// Why a reverse-proxy request took the bounded buffered path instead of
/// streaming (#139). This lives here, next to the counters, so it is the single
/// source of truth: `recordProxyStreamingFallback` switches over it
/// exhaustively, and adding a case is a compile error until that case has a
/// counter and a Prometheus series. `gateway_proxy_runtime` re-exports it as
/// `StreamingFallbackReason` for the eligibility checks that produce it.
pub const ProxyStreamingFallbackReason = enum {
    policy_disabled,
    retries_configured,
    missing_content_length,
    body_too_large,
    body_dependent_middleware,
    unsupported_route_type,
    early_data_retry_semantics,

    /// The `reason=` label value; identical to the tag name by construction, so
    /// a label can never drift from its enum case.
    pub fn label(self: ProxyStreamingFallbackReason) []const u8 {
        return @tagName(self);
    }
};
pub const EarlyDataSource = enum { transport, header, both };
pub const EarlyDataDecision = enum { accepted, too_early, deferred, forwarded };
pub const EarlyDataUpstream425Action = enum { forwarded, retried };
pub const EarlyDataRetryResult = enum { success, too_early, failure };
pub const H3EarlyDataCompatDecision = enum { compatible, transport_incompatible, settings_incompatible, missing_state };

/// #368 Slice 3: process-local anti-replay store outcomes. Mirrors
/// `tls_core.early_data_replay.Event` one-for-one (bridged in
/// `edge_gateway.zig`'s `mapEarlyDataReplayEvent`, matching the
/// `nativeResumptionOutcomeValue`-style bridge pattern) — a fixed, closed
/// enum, never a ticket fingerprint, ticket identity, client address,
/// request path, user ID, PSK, or binder.
pub const EarlyDataReplayOutcome = enum { accepted, duplicate, capacity_rejected, expired, unavailable, startup_quarantine };

/// #523: mirrors `tls_core.tls13_backend.EarlyDataDecision` one-for-one
/// (bridged in `http3_runtime.zig`'s `accept()` `EventSink`) — the QUIC/H3
/// server's authoritative 0-RTT accept/reject decision, made once per
/// connection as soon as the ClientHello is processed, independent of
/// whether any `.zero_rtt` packet ever actually arrives. `not_attempted`
/// is deliberately excluded: that's the vast majority of ordinary
/// connections and isn't itself an outcome worth counting.
pub const QuicEarlyDataDecision = enum {
    accepted,
    disabled,
    ticket_not_capable,
    selected_identity_not_zero,
    age_skew,
    transport_incompatible,
    application_incompatible,
    replay_rejected,
    replay_unavailable,
    resource_limited,
};

/// #523: mirrors `quic.connection.ZeroRttPacketOutcome` one-for-one
/// (bridged the same way) — per-packet 0-RTT authentication/admission
/// outcomes, distinguishing policy/keys-unavailable from a genuine AEAD
/// authentication failure and from an authenticated duplicate.
pub const QuicZeroRttPacketOutcome = enum {
    accepted,
    keys_unavailable,
    authentication_failed,
    duplicate,
    malformed,
};

pub const QuicHandshakeFailureStage = enum { initial, handshake };
pub const QuicFlowControlScope = enum { connection, stream };

/// #256-D/#256-G: mirrors `quic.udp.BufferTuningStatus` without this module
/// depending on the `quic` package — `GatewayState.overlayQuicTransportSnapshot`
/// translates between the two. See that struct's doc comment for what each
/// value means; the short version is "no request" / "kernel gave you at
/// least what you asked" / "kernel gave you less" / "accepted but couldn't
/// read back" / "kernel refused outright".
pub const QuicUdpBufferStatus = enum { default, applied, clamped, unverified, unsupported };

fn quicUdpBufferStatusLabel(status: QuicUdpBufferStatus) []const u8 {
    return switch (status) {
        .default => "default",
        .applied => "applied",
        .clamped => "clamped",
        .unverified => "unverified",
        .unsupported => "unsupported",
    };
}

pub const QuicTransportDelta = struct {
    retry: u64 = 0,
    amplification_blocked: u64 = 0,
    pto: u64 = 0,
    packets_lost: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    stream_resets: u64 = 0,
    connection_flow_blocked: u64 = 0,
    stream_flow_blocked: u64 = 0,
    deprotection_failures: u64 = 0,
};

const resumption_transport_count = 2;
const resumption_outcome_count = 5;
const resumption_mode_count = 3;
const ticket_result_count = 3;
const ticket_key_reload_outcome_count = 4;
const http_protocol_count = 3;
const response_write_mode_count = 4;
const accept_error_reason_count = 2;
const early_data_source_count = 3;
const early_data_decision_count = 4;
const early_data_upstream_425_action_count = 2;
const early_data_retry_result_count = 3;
const h3_early_data_compat_decision_count = 4;
const early_data_replay_outcome_count = 6;
const quic_early_data_decision_count = 10;
const quic_zero_rtt_packet_outcome_count = 5;
const quic_handshake_failure_stage_count = 2;
const quic_flow_control_scope_count = 2;

/// Maximum number of listener shards tracked in per-shard metric arrays.
/// Shard IDs >= this value are clamped to the last bucket.
pub const max_listener_shards: usize = 64;
const accept_batch_bucket_count = 6;

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
    proxy_buffer_limit_exceeded_downstream_to_upstream_origin: u64,
    proxy_buffer_limit_exceeded_upstream_to_downstream_origin: u64,
    proxy_buffer_limit_exceeded_downstream_to_upstream_global: u64,
    proxy_buffer_limit_exceeded_upstream_to_downstream_global: u64,
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
    proxy_local_capacity_aborts: u64,
    proxy_streaming_fallback_policy_disabled: u64,
    proxy_streaming_fallback_retries_configured: u64,
    proxy_streaming_fallback_missing_content_length: u64,
    proxy_streaming_fallback_body_too_large: u64,
    proxy_streaming_fallback_body_dependent_middleware: u64,
    proxy_streaming_fallback_unsupported_route_type: u64,
    proxy_streaming_fallback_early_data_retry_semantics: u64,
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
    /// #512: persistent native stateless ticket-key load/reload outcomes by
    /// closed enum. Never contains paths, key IDs, key bytes, nonces, or
    /// ciphertext.
    tls_ticket_key_reload_total: [ticket_key_reload_outcome_count]u64,
    /// HTTP early-data replay-exposed requests by protocol and source.
    http_early_data_requests_total: [http_protocol_count][early_data_source_count]u64,
    response_write_mode_total: [response_write_mode_count]u64,
    response_writev_iovecs_total: u64,
    response_write_errors_total: [response_write_mode_count]u64,
    /// HTTP early-data decisions by protocol.
    http_early_data_decisions_total: [http_protocol_count][early_data_decision_count]u64,
    /// Upstream 425 handling actions (bounded RFC 8470 semantics only).
    http_early_data_upstream_425_total: [early_data_upstream_425_action_count]u64,
    /// Local one-shot upstream 425 retry outcomes.
    http_early_data_retry_total: [early_data_retry_result_count]u64,
    /// HTTP/3 early-data compatibility outcomes.
    http3_early_data_compat_total: [h3_early_data_compat_decision_count]u64,
    /// #368 Slice 3: process-local anti-replay store outcomes by bounded,
    /// closed-enum outcome. See `EarlyDataReplayOutcome`.
    tls_early_data_replay_total: [early_data_replay_outcome_count]u64,
    /// #523: the QUIC/H3 server's authoritative 0-RTT accept/reject
    /// decision by outcome. See `QuicEarlyDataDecision`.
    quic_early_data_decision_total: [quic_early_data_decision_count]u64,
    /// #523: per-packet 0-RTT authentication/admission outcomes. See
    /// `QuicZeroRttPacketOutcome`.
    quic_zero_rtt_packet_total: [quic_zero_rtt_packet_outcome_count]u64,
    /// #255 Slice 5: low-cardinality QUIC transport counters, folded from
    /// per-connection cumulative transport/path/stream/TLS snapshots.
    quic_connections_active: u64,
    quic_handshake_failures_total: [quic_handshake_failure_stage_count]u64,
    quic_retry_total: u64,
    quic_amplification_blocked_total: u64,
    quic_pto_total: u64,
    quic_packets_lost_total: u64,
    quic_bytes_sent_total: u64,
    quic_bytes_received_total: u64,
    quic_stream_resets_total: u64,
    quic_flow_control_blocked_total: [quic_flow_control_scope_count]u64,
    quic_deprotection_failures_total: u64,
    /// #256-G: populated at render time from `http3_runtime.Snapshot` by
    /// `GatewayState.overlayQuicTransportSnapshot` (mirrors how
    /// `overlayUpstreamPoolStats` overlays the upstream pool's own live
    /// stats), not accumulated via `recordQuicTransportDelta` — the runtime
    /// snapshot is already the authoritative accumulator for these fields,
    /// so there is no second counter to keep in sync.
    quic_packets_sent_total: u64,
    quic_packets_received_total: u64,
    quic_pmtu_probes_sent_total: u64,
    quic_pmtu_black_holes_total: u64,
    /// See `http3_runtime.Snapshot.plpmtu_last_bytes` / `_min_bytes` / `_max_bytes`
    /// for exactly what these three mean — not a single listener-wide "the
    /// PLPMTU".
    quic_effective_plpmtu_bytes_last: u64,
    quic_effective_plpmtu_bytes_lifetime_min: u64,
    quic_effective_plpmtu_bytes_lifetime_max: u64,
    /// 0/1 gauge: whether ECN is actually running on this listener right now.
    quic_ecn_enabled: u64,
    quic_ecn_marked_sent_total: u64,
    quic_ecn_paths_validated_total: u64,
    quic_ecn_paths_disabled_total: u64,
    quic_ecn_ce_received_total: u64,
    /// #256-D/#256-G: requested vs kernel-effective/granted UDP socket
    /// buffer sizes, read back via `getsockopt` at bind time. 0 means
    /// "nothing was explicitly requested" (kernel default in effect) for the
    /// `_requested_bytes` fields, or "not read back" for `_effective_bytes`/
    /// `_granted_bytes` — never a real socket buffer size on any platform
    /// this transport runs on. Do not infer one from the other: `status`
    /// says whether the request was granted, clamped, or refused.
    quic_udp_recv_buffer_requested_bytes: u64,
    quic_udp_recv_buffer_effective_bytes: u64,
    quic_udp_recv_buffer_granted_bytes: u64,
    quic_udp_recv_buffer_status: QuicUdpBufferStatus,
    quic_udp_send_buffer_requested_bytes: u64,
    quic_udp_send_buffer_effective_bytes: u64,
    quic_udp_send_buffer_granted_bytes: u64,
    quic_udp_send_buffer_status: QuicUdpBufferStatus,
    h3_requests_total: u64,
    h3_request_latency_le_1ms: u64,
    h3_request_latency_le_5ms: u64,
    h3_request_latency_le_10ms: u64,
    h3_request_latency_le_25ms: u64,
    h3_request_latency_le_50ms: u64,
    h3_request_latency_le_100ms: u64,
    h3_request_latency_le_250ms: u64,
    h3_request_latency_le_500ms: u64,
    h3_request_latency_le_1000ms: u64,
    h3_request_latency_gt_1000ms: u64,
    h3_request_latency_count: u64,
    h3_request_latency_sum_ms: u64,
    /// #255 Slice 3: process-wide QPACK dynamic decoder observability. These
    /// remain zero until the live H3 path composes the dynamic decoder.
    h3_qpack_blocked_streams_current: u64,
    h3_qpack_blocked_streams_total: u64,
    h3_qpack_unblocked_streams_total: u64,
    h3_qpack_cancelled_streams_total: u64,
    h3_qpack_table_bytes: u64,
    h3_qpack_decode_failures_total: u64,
    /// Total graceful-shutdown drains started.
    drain_total: u64,
    /// Total drains that hit the configured drain timeout before work finished.
    drain_timeouts_total: u64,
    /// Total queued (unstarted) connections force-closed because a drain timed out.
    drain_forced_closes_total: u64,
    /// Listener sharding: configured number of active listener shards (1 = single/default).
    listener_shards: u16,
    /// Per-shard accepted connections total. Index by shard ID (clamped to max_listener_shards-1).
    accepts_total: [max_listener_shards]std.atomic.Value(u64),
    /// Per-shard accept errors total, split by a bounded reason label.
    accept_errors_total: [max_listener_shards][accept_error_reason_count]std.atomic.Value(u64),
    /// Per-shard accept readiness batches by size bucket.
    accept_batch_size_buckets: [max_listener_shards][accept_batch_bucket_count]std.atomic.Value(u64),
    accept_batch_size_sum: [max_listener_shards]std.atomic.Value(u64),
    accept_batch_size_count: [max_listener_shards]std.atomic.Value(u64),
    accept_batches_total: [max_listener_shards]std.atomic.Value(u64),
    accept_fairness_yields_total: [max_listener_shards]std.atomic.Value(u64),
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
            .proxy_buffer_limit_exceeded_downstream_to_upstream_origin = 0,
            .proxy_buffer_limit_exceeded_upstream_to_downstream_origin = 0,
            .proxy_buffer_limit_exceeded_downstream_to_upstream_global = 0,
            .proxy_buffer_limit_exceeded_upstream_to_downstream_global = 0,
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
            .proxy_local_capacity_aborts = 0,
            .proxy_streaming_fallback_policy_disabled = 0,
            .proxy_streaming_fallback_retries_configured = 0,
            .proxy_streaming_fallback_missing_content_length = 0,
            .proxy_streaming_fallback_body_too_large = 0,
            .proxy_streaming_fallback_body_dependent_middleware = 0,
            .proxy_streaming_fallback_unsupported_route_type = 0,
            .proxy_streaming_fallback_early_data_retry_semantics = 0,
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
            .tls_ticket_key_reload_total = .{0} ** ticket_key_reload_outcome_count,
            .http_early_data_requests_total = .{.{0} ** early_data_source_count} ** http_protocol_count,
            .response_write_mode_total = .{0} ** response_write_mode_count,
            .response_writev_iovecs_total = 0,
            .response_write_errors_total = .{0} ** response_write_mode_count,
            .http_early_data_decisions_total = .{.{0} ** early_data_decision_count} ** http_protocol_count,
            .http_early_data_upstream_425_total = .{0} ** early_data_upstream_425_action_count,
            .http_early_data_retry_total = .{0} ** early_data_retry_result_count,
            .http3_early_data_compat_total = .{0} ** h3_early_data_compat_decision_count,
            .tls_early_data_replay_total = .{0} ** early_data_replay_outcome_count,
            .quic_early_data_decision_total = .{0} ** quic_early_data_decision_count,
            .quic_zero_rtt_packet_total = .{0} ** quic_zero_rtt_packet_outcome_count,
            .quic_connections_active = 0,
            .quic_handshake_failures_total = .{0} ** quic_handshake_failure_stage_count,
            .quic_retry_total = 0,
            .quic_amplification_blocked_total = 0,
            .quic_pto_total = 0,
            .quic_packets_lost_total = 0,
            .quic_bytes_sent_total = 0,
            .quic_bytes_received_total = 0,
            .quic_stream_resets_total = 0,
            .quic_flow_control_blocked_total = .{0} ** quic_flow_control_scope_count,
            .quic_deprotection_failures_total = 0,
            .quic_packets_sent_total = 0,
            .quic_packets_received_total = 0,
            .quic_pmtu_probes_sent_total = 0,
            .quic_pmtu_black_holes_total = 0,
            .quic_effective_plpmtu_bytes_last = 0,
            .quic_effective_plpmtu_bytes_lifetime_min = 0,
            .quic_effective_plpmtu_bytes_lifetime_max = 0,
            .quic_ecn_enabled = 0,
            .quic_ecn_marked_sent_total = 0,
            .quic_ecn_paths_validated_total = 0,
            .quic_ecn_paths_disabled_total = 0,
            .quic_ecn_ce_received_total = 0,
            .quic_udp_recv_buffer_requested_bytes = 0,
            .quic_udp_recv_buffer_effective_bytes = 0,
            .quic_udp_recv_buffer_granted_bytes = 0,
            .quic_udp_recv_buffer_status = .default,
            .quic_udp_send_buffer_requested_bytes = 0,
            .quic_udp_send_buffer_effective_bytes = 0,
            .quic_udp_send_buffer_granted_bytes = 0,
            .quic_udp_send_buffer_status = .default,
            .h3_requests_total = 0,
            .h3_request_latency_le_1ms = 0,
            .h3_request_latency_le_5ms = 0,
            .h3_request_latency_le_10ms = 0,
            .h3_request_latency_le_25ms = 0,
            .h3_request_latency_le_50ms = 0,
            .h3_request_latency_le_100ms = 0,
            .h3_request_latency_le_250ms = 0,
            .h3_request_latency_le_500ms = 0,
            .h3_request_latency_le_1000ms = 0,
            .h3_request_latency_gt_1000ms = 0,
            .h3_request_latency_count = 0,
            .h3_request_latency_sum_ms = 0,
            .h3_qpack_blocked_streams_current = 0,
            .h3_qpack_blocked_streams_total = 0,
            .h3_qpack_unblocked_streams_total = 0,
            .h3_qpack_cancelled_streams_total = 0,
            .h3_qpack_table_bytes = 0,
            .h3_qpack_decode_failures_total = 0,
            .drain_total = 0,
            .drain_timeouts_total = 0,
            .drain_forced_closes_total = 0,
            .listener_shards = 1,
            .accepts_total = zeroAtomicShardCounters(),
            .accept_errors_total = zeroAtomicShardReasonCounters(),
            .accept_batch_size_buckets = zeroAtomicShardBatchCounters(),
            .accept_batch_size_sum = zeroAtomicShardCounters(),
            .accept_batch_size_count = zeroAtomicShardCounters(),
            .accept_batches_total = zeroAtomicShardCounters(),
            .accept_fairness_yields_total = zeroAtomicShardCounters(),
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

    pub fn recordTicketKeyReload(self: *Metrics, outcome: TicketKeyReloadOutcome) void {
        self.tls_ticket_key_reload_total[ticketKeyReloadOutcomeIndex(outcome)] += 1;
    }

    pub fn recordHttpEarlyDataRequest(self: *Metrics, protocol: HttpProtocol, source: EarlyDataSource) void {
        self.http_early_data_requests_total[httpProtocolIndex(protocol)][earlyDataSourceIndex(source)] += 1;
    }

    pub fn recordResponseWriteMode(self: *Metrics, mode: ResponseWriteMode, iovecs: usize) void {
        self.response_write_mode_total[responseWriteModeIndex(mode)] += 1;
        if (mode == .writev) self.response_writev_iovecs_total += @intCast(iovecs);
    }

    pub fn recordResponseWriteError(self: *Metrics, mode: ResponseWriteMode) void {
        self.response_write_errors_total[responseWriteModeIndex(mode)] += 1;
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

    /// #368 Slice 3: record a process-local anti-replay store outcome.
    pub fn recordEarlyDataReplay(self: *Metrics, outcome: EarlyDataReplayOutcome) void {
        self.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(outcome)] += 1;
    }

    /// #523: record the QUIC/H3 server's authoritative 0-RTT accept/reject
    /// decision for one connection.
    pub fn recordQuicEarlyDataDecision(self: *Metrics, decision: QuicEarlyDataDecision) void {
        self.quic_early_data_decision_total[quicEarlyDataDecisionIndex(decision)] += 1;
    }

    /// #523: record one 0-RTT packet's authentication/admission outcome.
    pub fn recordQuicZeroRttPacket(self: *Metrics, outcome: QuicZeroRttPacketOutcome) void {
        self.quic_zero_rtt_packet_total[quicZeroRttPacketOutcomeIndex(outcome)] += 1;
    }

    pub fn setQuicConnectionsActive(self: *Metrics, active: usize) void {
        self.quic_connections_active = @intCast(active);
    }

    pub fn recordQuicHandshakeFailure(self: *Metrics, stage: QuicHandshakeFailureStage) void {
        self.quic_handshake_failures_total[quicHandshakeFailureStageIndex(stage)] += 1;
    }

    pub fn recordQuicTransportDelta(self: *Metrics, delta: QuicTransportDelta) void {
        self.quic_retry_total += delta.retry;
        self.quic_amplification_blocked_total += delta.amplification_blocked;
        self.quic_pto_total += delta.pto;
        self.quic_packets_lost_total += delta.packets_lost;
        self.quic_bytes_sent_total += delta.bytes_sent;
        self.quic_bytes_received_total += delta.bytes_received;
        self.quic_stream_resets_total += delta.stream_resets;
        self.quic_flow_control_blocked_total[quicFlowControlScopeIndex(.connection)] += delta.connection_flow_blocked;
        self.quic_flow_control_blocked_total[quicFlowControlScopeIndex(.stream)] += delta.stream_flow_blocked;
        self.quic_deprotection_failures_total += delta.deprotection_failures;
    }

    pub fn recordH3RequestLatency(self: *Metrics, latency_ms: u64) void {
        self.h3_requests_total += 1;
        self.h3_request_latency_count += 1;
        self.h3_request_latency_sum_ms += latency_ms;
        if (latency_ms <= 1) self.h3_request_latency_le_1ms += 1;
        if (latency_ms <= 5) self.h3_request_latency_le_5ms += 1;
        if (latency_ms <= 10) self.h3_request_latency_le_10ms += 1;
        if (latency_ms <= 25) self.h3_request_latency_le_25ms += 1;
        if (latency_ms <= 50) self.h3_request_latency_le_50ms += 1;
        if (latency_ms <= 100) self.h3_request_latency_le_100ms += 1;
        if (latency_ms <= 250) self.h3_request_latency_le_250ms += 1;
        if (latency_ms <= 500) self.h3_request_latency_le_500ms += 1;
        if (latency_ms <= 1000) self.h3_request_latency_le_1000ms += 1 else self.h3_request_latency_gt_1000ms += 1;
    }

    pub const H3QpackSnapshot = struct {
        current_blocked_streams: u64 = 0,
        blocked_streams: u64 = 0,
        unblocked_streams: u64 = 0,
        cancelled_streams: u64 = 0,
        table_bytes: u64 = 0,
        decode_failures: u64 = 0,
    };

    /// Fold one connection's cumulative QPACK metrics. Gauge values are
    /// adjusted from previous/current state so multi-connection totals compose
    /// and teardown can subtract the final per-connection snapshot.
    pub fn recordH3QpackSnapshotDelta(self: *Metrics, previous: H3QpackSnapshot, current: H3QpackSnapshot) void {
        self.h3_qpack_blocked_streams_total += current.blocked_streams -| previous.blocked_streams;
        self.h3_qpack_unblocked_streams_total += current.unblocked_streams -| previous.unblocked_streams;
        self.h3_qpack_cancelled_streams_total += current.cancelled_streams -| previous.cancelled_streams;
        self.h3_qpack_decode_failures_total += current.decode_failures -| previous.decode_failures;
        self.h3_qpack_blocked_streams_current = addGaugeDelta(
            self.h3_qpack_blocked_streams_current,
            previous.current_blocked_streams,
            current.current_blocked_streams,
        );
        self.h3_qpack_table_bytes = addGaugeDelta(self.h3_qpack_table_bytes, previous.table_bytes, current.table_bytes);
    }

    pub fn removeH3QpackSnapshot(self: *Metrics, snapshot: H3QpackSnapshot) void {
        self.h3_qpack_blocked_streams_current -|= snapshot.current_blocked_streams;
        self.h3_qpack_table_bytes -|= snapshot.table_bytes;
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

    /// Set the number of active listener shards (call once at startup).
    pub fn setListenerShards(self: *Metrics, count: u16) void {
        self.listener_shards = @max(count, 1);
    }

    /// Record one accepted connection on the given shard.
    pub fn recordAccept(self: *Metrics, shard_id: u16) void {
        const idx = @min(@as(usize, shard_id), max_listener_shards - 1);
        _ = self.accepts_total[idx].fetchAdd(1, .monotonic);
    }

    /// Record one accept-path error on the given shard.
    pub fn recordAcceptError(self: *Metrics, shard_id: u16, reason: AcceptErrorReason) void {
        const idx = @min(@as(usize, shard_id), max_listener_shards - 1);
        _ = self.accept_errors_total[idx][acceptErrorReasonIndex(reason)].fetchAdd(1, .monotonic);
    }

    pub fn recordAcceptBatch(self: *Metrics, shard_id: u16, batch_size: u32) void {
        const idx = @min(@as(usize, shard_id), max_listener_shards - 1);
        const size: u64 = @intCast(batch_size);
        _ = self.accept_batches_total[idx].fetchAdd(1, .monotonic);
        _ = self.accept_batch_size_count[idx].fetchAdd(1, .monotonic);
        _ = self.accept_batch_size_sum[idx].fetchAdd(size, .monotonic);

        const bucket_idx = acceptBatchBucketIndex(batch_size);
        var i: usize = bucket_idx;
        while (i < accept_batch_bucket_count) : (i += 1) {
            _ = self.accept_batch_size_buckets[idx][i].fetchAdd(1, .monotonic);
        }
    }

    pub fn recordAcceptFairnessYield(self: *Metrics, shard_id: u16) void {
        const idx = @min(@as(usize, shard_id), max_listener_shards - 1);
        _ = self.accept_fairness_yields_total[idx].fetchAdd(1, .monotonic);
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
        // A fully buffered response holds one allocation for exactly as long as
        // it holds the bytes, so both scopes move together here.
        try self.releaseProxyBufferReservation(.upstream_to_downstream, buffered_bytes);
        try self.releaseProxyBufferRetained(.upstream_to_downstream, buffered_bytes);
    }

    /// Per-stream logical queue occupancy. Deliberately does **not** touch the
    /// aggregate gauge: the `scope="global"` series reports retained allocation
    /// (what the global hard limit enforces), which a partially drained queue
    /// still owns. Callers pair this with `recordProxyBufferRetained`.
    pub fn recordProxyBufferReservation(
        self: *Metrics,
        direction: proxy_buffer_account.Direction,
        bytes: usize,
        high_watermark: bool,
        limit_exceeded: bool,
    ) void {
        self.recordProxyBufferBytes(direction, .stream, bytes);
        if (high_watermark) self.recordProxyBufferHighWatermark(direction, .stream);
        if (limit_exceeded) self.recordProxyBufferLimitExceeded(direction, .stream);
    }

    pub fn releaseProxyBufferReservation(self: *Metrics, direction: proxy_buffer_account.Direction, bytes: usize) !void {
        try self.releaseProxyBufferBytes(direction, .stream, bytes);
    }

    /// Bytes entering the aggregate scopes, i.e. allocation an owner retains.
    pub fn recordProxyBufferRetained(self: *Metrics, direction: proxy_buffer_account.Direction, bytes: usize) void {
        self.recordProxyBufferBytes(direction, .global, bytes);
    }

    pub fn releaseProxyBufferRetained(self: *Metrics, direction: proxy_buffer_account.Direction, bytes: usize) !void {
        try self.releaseProxyBufferBytes(direction, .global, bytes);
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
        switch (scope) {
            .stream => switch (direction) {
                .downstream_to_upstream => self.proxy_buffer_limit_exceeded_downstream_to_upstream_stream += 1,
                .upstream_to_downstream => self.proxy_buffer_limit_exceeded_upstream_to_downstream_stream += 1,
            },
            .origin => switch (direction) {
                .downstream_to_upstream => self.proxy_buffer_limit_exceeded_downstream_to_upstream_origin += 1,
                .upstream_to_downstream => self.proxy_buffer_limit_exceeded_upstream_to_downstream_origin += 1,
            },
            .global => switch (direction) {
                .downstream_to_upstream => self.proxy_buffer_limit_exceeded_downstream_to_upstream_global += 1,
                .upstream_to_downstream => self.proxy_buffer_limit_exceeded_upstream_to_downstream_global += 1,
            },
            // Downstream-connection scope has no proxy body queue of its own.
            .connection => {},
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

    /// A relay truncated because *this proxy* ran out of buffer capacity after
    /// the response head was committed. Deliberately separate from
    /// `proxy_upstream_aborts`, which means the origin aborted.
    pub fn recordProxyLocalCapacityAbort(self: *Metrics) void {
        self.proxy_local_capacity_aborts += 1;
    }

    /// Exhaustive by construction: a new `ProxyStreamingFallbackReason` case
    /// fails to compile here until it is given a counter, which is what keeps a
    /// reason from being emitted into a metric that silently drops it.
    pub fn recordProxyStreamingFallback(self: *Metrics, reason: ProxyStreamingFallbackReason) void {
        switch (reason) {
            .policy_disabled => self.proxy_streaming_fallback_policy_disabled += 1,
            .retries_configured => self.proxy_streaming_fallback_retries_configured += 1,
            .missing_content_length => self.proxy_streaming_fallback_missing_content_length += 1,
            .body_too_large => self.proxy_streaming_fallback_body_too_large += 1,
            .body_dependent_middleware => self.proxy_streaming_fallback_body_dependent_middleware += 1,
            .unsupported_route_type => self.proxy_streaming_fallback_unsupported_route_type += 1,
            .early_data_retry_semantics => self.proxy_streaming_fallback_early_data_retry_semantics += 1,
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
            \\# HELP tardigrade_buffer_read_pauses_total Proxy reads paused by buffer pressure, by peer side
            \\# TYPE tardigrade_buffer_read_pauses_total counter
            \\tardigrade_buffer_read_pauses_total{{side="downstream"}} {d}
            \\tardigrade_buffer_read_pauses_total{{side="upstream"}} {d}
            \\# HELP tardigrade_buffer_read_resumes_total Proxy reads resumed after buffer pressure dropped below the low watermark, by peer side
            \\# TYPE tardigrade_buffer_read_resumes_total counter
            \\tardigrade_buffer_read_resumes_total{{side="downstream"}} {d}
            \\tardigrade_buffer_read_resumes_total{{side="upstream"}} {d}
            \\# HELP tardigrade_buffer_limit_exceeded_total Proxy buffer hard-limit exceedance events by direction and scope
            \\# TYPE tardigrade_buffer_limit_exceeded_total counter
            \\tardigrade_buffer_limit_exceeded_total{{direction="downstream_to_upstream",scope="stream"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="upstream_to_downstream",scope="stream"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="downstream_to_upstream",scope="origin"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="upstream_to_downstream",scope="origin"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="downstream_to_upstream",scope="global"}} {d}
            \\tardigrade_buffer_limit_exceeded_total{{direction="upstream_to_downstream",scope="global"}} {d}
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
            self.proxy_buffer_limit_exceeded_downstream_to_upstream_origin,
            self.proxy_buffer_limit_exceeded_upstream_to_downstream_origin,
            self.proxy_buffer_limit_exceeded_downstream_to_upstream_global,
            self.proxy_buffer_limit_exceeded_upstream_to_downstream_global,
        });

        try self.appendTlsBufferPrometheus(&out);
        try self.appendResponseWritePrometheus(&out);
        try self.appendResumptionPrometheus(&out);
        try self.appendQuicH3Prometheus(&out);
        try self.appendHttpEarlyDataPrometheus(&out);
        try self.appendEarlyDataReplayPrometheus(&out);

        try out.print(
            \\# HELP tardigrade_proxy_client_aborts_total Total proxied transfers aborted by downstream clients
            \\# TYPE tardigrade_proxy_client_aborts_total counter
            \\tardigrade_proxy_client_aborts_total {d}
            \\# HELP tardigrade_proxy_upstream_aborts_total Total proxied transfers aborted by upstream origins
            \\# TYPE tardigrade_proxy_upstream_aborts_total counter
            \\tardigrade_proxy_upstream_aborts_total {d}
            \\# HELP tardigrade_proxy_local_capacity_aborts_total Total proxied responses truncated after commitment because local proxy buffer capacity was exhausted
            \\# TYPE tardigrade_proxy_local_capacity_aborts_total counter
            \\tardigrade_proxy_local_capacity_aborts_total {d}
            \\# HELP tardigrade_proxy_streaming_fallback_total Total streaming eligibility fallback events by reason
            \\# TYPE tardigrade_proxy_streaming_fallback_total counter
            \\tardigrade_proxy_streaming_fallback_total{{reason="policy_disabled"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="retries_configured"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="missing_content_length"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="body_too_large"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="body_dependent_middleware"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="unsupported_route_type"}} {d}
            \\tardigrade_proxy_streaming_fallback_total{{reason="early_data_retry_semantics"}} {d}
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
            \\# HELP tardigrade_upstream_stale_retries_total Fresh-connection retries after a reused upstream connection was found dead
            \\# TYPE tardigrade_upstream_stale_retries_total counter
            \\tardigrade_upstream_stale_retries_total {d}
            \\
        , .{
            self.proxy_client_aborts,
            self.proxy_upstream_aborts,
            self.proxy_local_capacity_aborts,
            self.proxy_streaming_fallback_policy_disabled,
            self.proxy_streaming_fallback_retries_configured,
            self.proxy_streaming_fallback_missing_content_length,
            self.proxy_streaming_fallback_body_too_large,
            self.proxy_streaming_fallback_body_dependent_middleware,
            self.proxy_streaming_fallback_unsupported_route_type,
            self.proxy_streaming_fallback_early_data_retry_semantics,
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

        // Listener sharding metrics
        try out.print(
            \\# HELP tardigrade_listener_shards Configured number of active listener shards
            \\# TYPE tardigrade_listener_shards gauge
            \\tardigrade_listener_shards {d}
            \\# HELP tardigrade_accepts_total Total accepted connections per listener shard
            \\# TYPE tardigrade_accepts_total counter
            \\# HELP tardigrade_accept_errors_total Total accept-path errors per listener shard
            \\# TYPE tardigrade_accept_errors_total counter
            \\# HELP tardigrade_accept_batch_size Accepted connections drained from one listener readiness turn
            \\# TYPE tardigrade_accept_batch_size histogram
            \\# HELP tardigrade_accept_batches_total Total listener readiness turns that accepted at least one connection
            \\# TYPE tardigrade_accept_batches_total counter
            \\# HELP tardigrade_accept_fairness_yields_total Total accept batches stopped early by the fairness yield limit
            \\# TYPE tardigrade_accept_fairness_yields_total counter
            \\
        , .{self.listener_shards});
        {
            const n = @min(@as(usize, self.listener_shards), max_listener_shards);
            for (0..n) |i| {
                try out.print("tardigrade_accepts_total{{shard=\"{d}\"}} {d}\n", .{ i, self.accepts_total[i].load(.monotonic) });
            }
            for (0..n) |i| {
                inline for (.{ AcceptErrorReason.poll, AcceptErrorReason.accept }) |reason| {
                    try out.print("tardigrade_accept_errors_total{{shard=\"{d}\",reason=\"{s}\"}} {d}\n", .{
                        i,
                        reason.label(),
                        self.accept_errors_total[i][acceptErrorReasonIndex(reason)].load(.monotonic),
                    });
                }
            }
            for (0..n) |i| {
                inline for (.{ 1, 2, 4, 8, 16 }) |le| {
                    try out.print("tardigrade_accept_batch_size_bucket{{shard=\"{d}\",le=\"{d}\"}} {d}\n", .{
                        i,
                        le,
                        self.accept_batch_size_buckets[i][acceptBatchBucketIndex(le)].load(.monotonic),
                    });
                }
                try out.print("tardigrade_accept_batch_size_bucket{{shard=\"{d}\",le=\"+Inf\"}} {d}\n", .{
                    i,
                    self.accept_batch_size_buckets[i][accept_batch_bucket_count - 1].load(.monotonic),
                });
                try out.print("tardigrade_accept_batch_size_sum{{shard=\"{d}\"}} {d}\n", .{ i, self.accept_batch_size_sum[i].load(.monotonic) });
                try out.print("tardigrade_accept_batch_size_count{{shard=\"{d}\"}} {d}\n", .{ i, self.accept_batch_size_count[i].load(.monotonic) });
                try out.print("tardigrade_accept_batches_total{{shard=\"{d}\"}} {d}\n", .{ i, self.accept_batches_total[i].load(.monotonic) });
                try out.print("tardigrade_accept_fairness_yields_total{{shard=\"{d}\"}} {d}\n", .{ i, self.accept_fairness_yields_total[i].load(.monotonic) });
            }
        }

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

    fn appendResponseWritePrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_response_write_mode_total HTTP/1 response write attempts by transport mode
            \\# TYPE tardigrade_response_write_mode_total counter
            \\
        );
        inline for (.{ ResponseWriteMode.writev, ResponseWriteMode.single_write, ResponseWriteMode.tls_buffered, ResponseWriteMode.fallback }) |mode| {
            try out.print("tardigrade_response_write_mode_total{{mode=\"{s}\"}} {d}\n", .{
                responseWriteModeLabel(mode),
                self.response_write_mode_total[responseWriteModeIndex(mode)],
            });
        }
        try out.print(
            \\# HELP tardigrade_response_writev_iovecs_total Total iovecs submitted by HTTP/1 response writev attempts
            \\# TYPE tardigrade_response_writev_iovecs_total counter
            \\tardigrade_response_writev_iovecs_total {d}
            \\# HELP tardigrade_response_write_errors_total HTTP/1 response write errors by transport mode
            \\# TYPE tardigrade_response_write_errors_total counter
            \\
        , .{self.response_writev_iovecs_total});
        inline for (.{ ResponseWriteMode.writev, ResponseWriteMode.single_write, ResponseWriteMode.tls_buffered, ResponseWriteMode.fallback }) |mode| {
            try out.print("tardigrade_response_write_errors_total{{mode=\"{s}\"}} {d}\n", .{
                responseWriteModeLabel(mode),
                self.response_write_errors_total[responseWriteModeIndex(mode)],
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

        try out.appendSlice(
            \\# HELP tardigrade_tls_ticket_key_reload_total Persistent native stateless ticket-key load/reload outcomes by outcome
            \\# TYPE tardigrade_tls_ticket_key_reload_total counter
            \\
        );
        inline for (.{ TicketKeyReloadOutcome.initial_load_success, TicketKeyReloadOutcome.initial_load_failure, TicketKeyReloadOutcome.reload_accepted, TicketKeyReloadOutcome.reload_rejected }) |outcome| {
            try out.print("tardigrade_tls_ticket_key_reload_total{{outcome=\"{s}\"}} {d}\n", .{
                ticketKeyReloadOutcomeLabel(outcome),
                self.tls_ticket_key_reload_total[ticketKeyReloadOutcomeIndex(outcome)],
            });
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

        try out.appendSlice(
            \\# HELP tardigrade_quic_early_data_decision_total QUIC/H3 server authoritative 0-RTT accept/reject decisions
            \\# TYPE tardigrade_quic_early_data_decision_total counter
            \\
        );
        inline for (.{
            QuicEarlyDataDecision.accepted,
            QuicEarlyDataDecision.disabled,
            QuicEarlyDataDecision.ticket_not_capable,
            QuicEarlyDataDecision.selected_identity_not_zero,
            QuicEarlyDataDecision.age_skew,
            QuicEarlyDataDecision.transport_incompatible,
            QuicEarlyDataDecision.application_incompatible,
            QuicEarlyDataDecision.replay_rejected,
            QuicEarlyDataDecision.replay_unavailable,
            QuicEarlyDataDecision.resource_limited,
        }) |decision| {
            try out.print("tardigrade_quic_early_data_decision_total{{decision=\"{s}\"}} {d}\n", .{
                quicEarlyDataDecisionLabel(decision),
                self.quic_early_data_decision_total[quicEarlyDataDecisionIndex(decision)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_quic_zero_rtt_packet_total Per-packet 0-RTT authentication/admission outcomes
            \\# TYPE tardigrade_quic_zero_rtt_packet_total counter
            \\
        );
        inline for (.{
            QuicZeroRttPacketOutcome.accepted,
            QuicZeroRttPacketOutcome.keys_unavailable,
            QuicZeroRttPacketOutcome.authentication_failed,
            QuicZeroRttPacketOutcome.duplicate,
            QuicZeroRttPacketOutcome.malformed,
        }) |outcome| {
            try out.print("tardigrade_quic_zero_rtt_packet_total{{outcome=\"{s}\"}} {d}\n", .{
                quicZeroRttPacketOutcomeLabel(outcome),
                self.quic_zero_rtt_packet_total[quicZeroRttPacketOutcomeIndex(outcome)],
            });
        }

        try out.print(
            \\# HELP tardigrade_h3_qpack_blocked_streams Current HTTP/3 QPACK blocked streams
            \\# TYPE tardigrade_h3_qpack_blocked_streams gauge
            \\tardigrade_h3_qpack_blocked_streams {d}
            \\# HELP tardigrade_h3_qpack_blocked_streams_total Total HTTP/3 QPACK streams that became blocked
            \\# TYPE tardigrade_h3_qpack_blocked_streams_total counter
            \\tardigrade_h3_qpack_blocked_streams_total {d}
            \\# HELP tardigrade_h3_qpack_unblocked_streams_total Total HTTP/3 QPACK streams unblocked by encoder progress
            \\# TYPE tardigrade_h3_qpack_unblocked_streams_total counter
            \\tardigrade_h3_qpack_unblocked_streams_total {d}
            \\# HELP tardigrade_h3_qpack_cancelled_streams_total Total HTTP/3 QPACK blocked streams cancelled before unblock
            \\# TYPE tardigrade_h3_qpack_cancelled_streams_total counter
            \\tardigrade_h3_qpack_cancelled_streams_total {d}
            \\# HELP tardigrade_h3_qpack_table_bytes Current HTTP/3 QPACK dynamic table bytes
            \\# TYPE tardigrade_h3_qpack_table_bytes gauge
            \\tardigrade_h3_qpack_table_bytes {d}
            \\# HELP tardigrade_h3_qpack_decode_failures_total Total HTTP/3 QPACK dynamic decode failures
            \\# TYPE tardigrade_h3_qpack_decode_failures_total counter
            \\tardigrade_h3_qpack_decode_failures_total {d}
            \\
        , .{
            self.h3_qpack_blocked_streams_current,
            self.h3_qpack_blocked_streams_total,
            self.h3_qpack_unblocked_streams_total,
            self.h3_qpack_cancelled_streams_total,
            self.h3_qpack_table_bytes,
            self.h3_qpack_decode_failures_total,
        });
    }

    fn appendQuicH3Prometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.print(
            \\# HELP tardigrade_quic_connections_active Active native QUIC connections
            \\# TYPE tardigrade_quic_connections_active gauge
            \\tardigrade_quic_connections_active {d}
            \\# HELP tardigrade_quic_retry_total QUIC Retry packets sent
            \\# TYPE tardigrade_quic_retry_total counter
            \\tardigrade_quic_retry_total {d}
            \\# HELP tardigrade_quic_amplification_blocked_total QUIC sends blocked by anti-amplification limits
            \\# TYPE tardigrade_quic_amplification_blocked_total counter
            \\tardigrade_quic_amplification_blocked_total {d}
            \\# HELP tardigrade_quic_pto_total QUIC probe timeout events
            \\# TYPE tardigrade_quic_pto_total counter
            \\tardigrade_quic_pto_total {d}
            \\# HELP tardigrade_quic_packets_lost_total QUIC packets declared lost
            \\# TYPE tardigrade_quic_packets_lost_total counter
            \\tardigrade_quic_packets_lost_total {d}
            \\# HELP tardigrade_quic_bytes_sent_total QUIC UDP datagram payload bytes sent by this listener
            \\# TYPE tardigrade_quic_bytes_sent_total counter
            \\tardigrade_quic_bytes_sent_total {d}
            \\# HELP tardigrade_quic_bytes_received_total QUIC UDP datagram payload bytes received by this listener
            \\# TYPE tardigrade_quic_bytes_received_total counter
            \\tardigrade_quic_bytes_received_total {d}
            \\# HELP tardigrade_quic_stream_resets_total QUIC stream reset events
            \\# TYPE tardigrade_quic_stream_resets_total counter
            \\tardigrade_quic_stream_resets_total {d}
            \\# HELP tardigrade_quic_deprotection_failures_total QUIC packet deprotection authentication failures
            \\# TYPE tardigrade_quic_deprotection_failures_total counter
            \\tardigrade_quic_deprotection_failures_total {d}
            \\# HELP tardigrade_h3_requests_total HTTP/3 requests completed by the native runtime
            \\# TYPE tardigrade_h3_requests_total counter
            \\tardigrade_h3_requests_total {d}
            \\
        , .{
            self.quic_connections_active,
            self.quic_retry_total,
            self.quic_amplification_blocked_total,
            self.quic_pto_total,
            self.quic_packets_lost_total,
            self.quic_bytes_sent_total,
            self.quic_bytes_received_total,
            self.quic_stream_resets_total,
            self.quic_deprotection_failures_total,
            self.h3_requests_total,
        });

        try out.appendSlice(
            \\# HELP tardigrade_quic_handshake_failures_total QUIC handshake failures by bounded stage
            \\# TYPE tardigrade_quic_handshake_failures_total counter
            \\
        );
        inline for (.{ QuicHandshakeFailureStage.initial, QuicHandshakeFailureStage.handshake }) |stage| {
            try out.print("tardigrade_quic_handshake_failures_total{{stage=\"{s}\"}} {d}\n", .{
                quicHandshakeFailureStageLabel(stage),
                self.quic_handshake_failures_total[quicHandshakeFailureStageIndex(stage)],
            });
        }

        try out.appendSlice(
            \\# HELP tardigrade_quic_flow_control_blocked_total QUIC flow-control blocked events by bounded scope
            \\# TYPE tardigrade_quic_flow_control_blocked_total counter
            \\
        );
        inline for (.{ QuicFlowControlScope.connection, QuicFlowControlScope.stream }) |scope| {
            try out.print("tardigrade_quic_flow_control_blocked_total{{scope=\"{s}\"}} {d}\n", .{
                quicFlowControlScopeLabel(scope),
                self.quic_flow_control_blocked_total[quicFlowControlScopeIndex(scope)],
            });
        }

        try self.appendQuicPmtuEcnBufferPrometheus(out);

        try out.appendSlice(
            \\# HELP tardigrade_h3_request_latency_ms HTTP/3 request latency in milliseconds
            \\# TYPE tardigrade_h3_request_latency_ms histogram
        );
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "1", self.h3_request_latency_le_1ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "5", self.h3_request_latency_le_5ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "10", self.h3_request_latency_le_10ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "25", self.h3_request_latency_le_25ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "50", self.h3_request_latency_le_50ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "100", self.h3_request_latency_le_100ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "250", self.h3_request_latency_le_250ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "500", self.h3_request_latency_le_500ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "1000", self.h3_request_latency_le_1000ms);
        try appendHistogramBucket(out, "tardigrade_h3_request_latency_ms", "+Inf", self.h3_request_latency_count);
        try out.print(
            \\tardigrade_h3_request_latency_ms_sum {d}
            \\tardigrade_h3_request_latency_ms_count {d}
            \\
        , .{ self.h3_request_latency_sum_ms, self.h3_request_latency_count });
    }

    /// #256-G: benchmark/status-facing bridge for state that #256-A..E
    /// already compute per-connection or per-listener but never exported to
    /// Prometheus — packet counts, DPLPMTUD probe/black-hole counts and the
    /// effective PLPMTU, ECN state/counters, and requested-vs-effective UDP
    /// socket buffer sizes. All values are populated at render time from
    /// `http3_runtime.Snapshot` by `GatewayState.overlayQuicTransportSnapshot`;
    /// no peer address, connection ID, or other high-cardinality label is
    /// ever attached to any of these series. #255 remains the canonical
    /// owner of QUIC/H3 observability generally — this is the smallest
    /// bridge needed to make existing #256 transport state benchmark-visible,
    /// not a competing metrics subsystem.
    fn appendQuicPmtuEcnBufferPrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.print(
            \\# HELP tardigrade_quic_packets_sent_total QUIC packets sent by this listener
            \\# TYPE tardigrade_quic_packets_sent_total counter
            \\tardigrade_quic_packets_sent_total {d}
            \\# HELP tardigrade_quic_packets_received_total QUIC packets received by this listener
            \\# TYPE tardigrade_quic_packets_received_total counter
            \\tardigrade_quic_packets_received_total {d}
            \\# HELP tardigrade_quic_pmtu_probes_total DPLPMTUD probe packets sent (#256-B)
            \\# TYPE tardigrade_quic_pmtu_probes_total counter
            \\tardigrade_quic_pmtu_probes_total {d}
            \\# HELP tardigrade_quic_pmtu_black_holes_total DPLPMTUD black-hole fallbacks triggered (#256-B)
            \\# TYPE tardigrade_quic_pmtu_black_holes_total counter
            \\tardigrade_quic_pmtu_black_holes_total {d}
            \\# HELP tardigrade_quic_effective_plpmtu_bytes_last Active-path PLPMTU of the most recently folded connection. Not a listener-wide aggregate — see http3_runtime.Snapshot doc comment.
            \\# TYPE tardigrade_quic_effective_plpmtu_bytes_last gauge
            \\tardigrade_quic_effective_plpmtu_bytes_last {d}
            \\# HELP tardigrade_quic_effective_plpmtu_bytes_lifetime_min Smallest active-path PLPMTU observed since this listener started. Never resets and is NOT scoped to any single benchmark scenario or pass — do not read this as evidence of path convergence within one run.
            \\# TYPE tardigrade_quic_effective_plpmtu_bytes_lifetime_min gauge
            \\tardigrade_quic_effective_plpmtu_bytes_lifetime_min {d}
            \\# HELP tardigrade_quic_effective_plpmtu_bytes_lifetime_max Largest active-path PLPMTU observed since this listener started. Never resets and is NOT scoped to any single benchmark scenario or pass.
            \\# TYPE tardigrade_quic_effective_plpmtu_bytes_lifetime_max gauge
            \\tardigrade_quic_effective_plpmtu_bytes_lifetime_max {d}
            \\# HELP tardigrade_quic_ecn_enabled Whether ECN is running on this listener (operator requested it and the kernel agreed)
            \\# TYPE tardigrade_quic_ecn_enabled gauge
            \\tardigrade_quic_ecn_enabled {d}
            \\# HELP tardigrade_quic_ecn_marked_sent_total ECT-marked packets sent (#256-E)
            \\# TYPE tardigrade_quic_ecn_marked_sent_total counter
            \\tardigrade_quic_ecn_marked_sent_total {d}
            \\# HELP tardigrade_quic_ecn_paths_validated_total Paths that validated peer ECN feedback (#256-E)
            \\# TYPE tardigrade_quic_ecn_paths_validated_total counter
            \\tardigrade_quic_ecn_paths_validated_total {d}
            \\# HELP tardigrade_quic_ecn_paths_disabled_total Paths that disabled ECN after failed validation (#256-E); non-zero is expected on the open internet
            \\# TYPE tardigrade_quic_ecn_paths_disabled_total counter
            \\tardigrade_quic_ecn_paths_disabled_total {d}
            \\# HELP tardigrade_quic_ecn_ce_received_total CE-marked packets received (#256-E)
            \\# TYPE tardigrade_quic_ecn_ce_received_total counter
            \\tardigrade_quic_ecn_ce_received_total {d}
            \\
        , .{
            self.quic_packets_sent_total,
            self.quic_packets_received_total,
            self.quic_pmtu_probes_sent_total,
            self.quic_pmtu_black_holes_total,
            self.quic_effective_plpmtu_bytes_last,
            self.quic_effective_plpmtu_bytes_lifetime_min,
            self.quic_effective_plpmtu_bytes_lifetime_max,
            self.quic_ecn_enabled,
            self.quic_ecn_marked_sent_total,
            self.quic_ecn_paths_validated_total,
            self.quic_ecn_paths_disabled_total,
            self.quic_ecn_ce_received_total,
        });

        try out.print(
            \\# HELP tardigrade_quic_udp_buffer_requested_bytes Requested SO_RCVBUF/SO_SNDBUF size by direction (#256-D). 0 means nothing was explicitly requested (kernel default in effect) — never a real socket buffer size.
            \\# TYPE tardigrade_quic_udp_buffer_requested_bytes gauge
            \\tardigrade_quic_udp_buffer_requested_bytes{{direction="recv"}} {d}
            \\tardigrade_quic_udp_buffer_requested_bytes{{direction="send"}} {d}
            \\# HELP tardigrade_quic_udp_buffer_effective_bytes getsockopt(SO_RCVBUF/SO_SNDBUF) readback by direction (#256-D). 0 means the readback was not taken/failed — never a real socket buffer size.
            \\# TYPE tardigrade_quic_udp_buffer_effective_bytes gauge
            \\tardigrade_quic_udp_buffer_effective_bytes{{direction="recv"}} {d}
            \\tardigrade_quic_udp_buffer_effective_bytes{{direction="send"}} {d}
            \\# HELP tardigrade_quic_udp_buffer_granted_bytes Readback restated in requested units, comparable to _requested_bytes (#256-D). 0 means nothing was requested or the readback failed.
            \\# TYPE tardigrade_quic_udp_buffer_granted_bytes gauge
            \\tardigrade_quic_udp_buffer_granted_bytes{{direction="recv"}} {d}
            \\tardigrade_quic_udp_buffer_granted_bytes{{direction="send"}} {d}
            \\# HELP tardigrade_quic_udp_buffer_status Current buffer-tuning outcome by direction: default, applied, clamped, unverified, or unsupported (#256-D)
            \\# TYPE tardigrade_quic_udp_buffer_status gauge
            \\tardigrade_quic_udp_buffer_status{{direction="recv",status="{s}"}} 1
            \\tardigrade_quic_udp_buffer_status{{direction="send",status="{s}"}} 1
            \\
        , .{
            self.quic_udp_recv_buffer_requested_bytes,
            self.quic_udp_send_buffer_requested_bytes,
            self.quic_udp_recv_buffer_effective_bytes,
            self.quic_udp_send_buffer_effective_bytes,
            self.quic_udp_recv_buffer_granted_bytes,
            self.quic_udp_send_buffer_granted_bytes,
            quicUdpBufferStatusLabel(self.quic_udp_recv_buffer_status),
            quicUdpBufferStatusLabel(self.quic_udp_send_buffer_status),
        });
    }

    /// #368 Slice 3: process-local anti-replay store outcomes. Every label
    /// comes from the fixed, closed `EarlyDataReplayOutcome` enum — never a
    /// ticket fingerprint, ticket identity, client address, request path,
    /// user ID, PSK, or binder.
    fn appendEarlyDataReplayPrometheus(self: *const Metrics, out: *std.array_list.Managed(u8)) !void {
        try out.appendSlice(
            \\# HELP tardigrade_tls_early_data_replay_total Process-local 0-RTT anti-replay store outcomes by outcome
            \\# TYPE tardigrade_tls_early_data_replay_total counter
            \\
        );
        inline for (.{
            EarlyDataReplayOutcome.accepted,
            EarlyDataReplayOutcome.duplicate,
            EarlyDataReplayOutcome.capacity_rejected,
            EarlyDataReplayOutcome.expired,
            EarlyDataReplayOutcome.unavailable,
            EarlyDataReplayOutcome.startup_quarantine,
        }) |outcome| {
            try out.print("tardigrade_tls_early_data_replay_total{{outcome=\"{s}\"}} {d}\n", .{
                earlyDataReplayOutcomeLabel(outcome),
                self.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(outcome)],
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

fn addGaugeDelta(current_total: u64, previous_value: u64, current_value: u64) u64 {
    if (current_value >= previous_value) {
        return current_total + (current_value - previous_value);
    }
    return current_total -| (previous_value - current_value);
}

fn zeroTlsQueueMatrix() [tls_backend_count][tls_queue_count]u64 {
    return .{.{0} ** tls_queue_count} ** tls_backend_count;
}

fn zeroTlsDirectionMatrix() [tls_backend_count][tls_direction_count]u64 {
    return .{.{0} ** tls_direction_count} ** tls_backend_count;
}

fn zeroAtomicShardCounters() [max_listener_shards]std.atomic.Value(u64) {
    var counters: [max_listener_shards]std.atomic.Value(u64) = undefined;
    for (&counters) |*counter| counter.* = std.atomic.Value(u64).init(0);
    return counters;
}

fn zeroAtomicShardReasonCounters() [max_listener_shards][accept_error_reason_count]std.atomic.Value(u64) {
    var counters: [max_listener_shards][accept_error_reason_count]std.atomic.Value(u64) = undefined;
    for (&counters) |*shard| {
        for (shard) |*counter| counter.* = std.atomic.Value(u64).init(0);
    }
    return counters;
}

fn zeroAtomicShardBatchCounters() [max_listener_shards][accept_batch_bucket_count]std.atomic.Value(u64) {
    var counters: [max_listener_shards][accept_batch_bucket_count]std.atomic.Value(u64) = undefined;
    for (&counters) |*shard| {
        for (shard) |*counter| counter.* = std.atomic.Value(u64).init(0);
    }
    return counters;
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

fn responseWriteModeIndex(mode: ResponseWriteMode) usize {
    return switch (mode) {
        .writev => 0,
        .single_write => 1,
        .tls_buffered => 2,
        .fallback => 3,
    };
}

fn acceptErrorReasonIndex(reason: AcceptErrorReason) usize {
    return switch (reason) {
        .poll => 0,
        .accept => 1,
    };
}

fn acceptBatchBucketIndex(batch_size: u32) usize {
    if (batch_size <= 1) return 0;
    if (batch_size <= 2) return 1;
    if (batch_size <= 4) return 2;
    if (batch_size <= 8) return 3;
    if (batch_size <= 16) return 4;
    return 5;
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

fn earlyDataReplayOutcomeIndex(outcome: EarlyDataReplayOutcome) usize {
    return switch (outcome) {
        .accepted => 0,
        .duplicate => 1,
        .capacity_rejected => 2,
        .expired => 3,
        .unavailable => 4,
        .startup_quarantine => 5,
    };
}

fn quicEarlyDataDecisionIndex(decision: QuicEarlyDataDecision) usize {
    return switch (decision) {
        .accepted => 0,
        .disabled => 1,
        .ticket_not_capable => 2,
        .selected_identity_not_zero => 3,
        .age_skew => 4,
        .transport_incompatible => 5,
        .application_incompatible => 6,
        .replay_rejected => 7,
        .replay_unavailable => 8,
        .resource_limited => 9,
    };
}

fn quicZeroRttPacketOutcomeIndex(outcome: QuicZeroRttPacketOutcome) usize {
    return switch (outcome) {
        .accepted => 0,
        .keys_unavailable => 1,
        .authentication_failed => 2,
        .duplicate => 3,
        .malformed => 4,
    };
}

fn quicHandshakeFailureStageIndex(stage: QuicHandshakeFailureStage) usize {
    return switch (stage) {
        .initial => 0,
        .handshake => 1,
    };
}

fn quicFlowControlScopeIndex(scope: QuicFlowControlScope) usize {
    return switch (scope) {
        .connection => 0,
        .stream => 1,
    };
}

fn ticketKeyReloadOutcomeIndex(outcome: TicketKeyReloadOutcome) usize {
    return switch (outcome) {
        .initial_load_success => 0,
        .initial_load_failure => 1,
        .reload_accepted => 2,
        .reload_rejected => 3,
    };
}

fn httpProtocolLabel(protocol: HttpProtocol) []const u8 {
    return switch (protocol) {
        .h1 => "h1",
        .h2 => "h2",
        .h3 => "h3",
    };
}

fn responseWriteModeLabel(mode: ResponseWriteMode) []const u8 {
    return switch (mode) {
        .writev => "writev",
        .single_write => "single_write",
        .tls_buffered => "tls_buffered",
        .fallback => "fallback",
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

fn earlyDataReplayOutcomeLabel(outcome: EarlyDataReplayOutcome) []const u8 {
    return switch (outcome) {
        .accepted => "accepted",
        .duplicate => "duplicate",
        .capacity_rejected => "capacity_rejected",
        .expired => "expired",
        .unavailable => "unavailable",
        .startup_quarantine => "startup_quarantine",
    };
}

fn quicEarlyDataDecisionLabel(decision: QuicEarlyDataDecision) []const u8 {
    return switch (decision) {
        .accepted => "accepted",
        .disabled => "disabled",
        .ticket_not_capable => "ticket_not_capable",
        .selected_identity_not_zero => "selected_identity_not_zero",
        .age_skew => "age_skew",
        .transport_incompatible => "transport_incompatible",
        .application_incompatible => "application_incompatible",
        .replay_rejected => "replay_rejected",
        .replay_unavailable => "replay_unavailable",
        .resource_limited => "resource_limited",
    };
}

fn quicZeroRttPacketOutcomeLabel(outcome: QuicZeroRttPacketOutcome) []const u8 {
    return switch (outcome) {
        .accepted => "accepted",
        .keys_unavailable => "keys_unavailable",
        .authentication_failed => "authentication_failed",
        .duplicate => "duplicate",
        .malformed => "malformed",
    };
}

fn quicHandshakeFailureStageLabel(stage: QuicHandshakeFailureStage) []const u8 {
    return switch (stage) {
        .initial => "initial",
        .handshake => "handshake",
    };
}

fn quicFlowControlScopeLabel(scope: QuicFlowControlScope) []const u8 {
    return switch (scope) {
        .connection => "connection",
        .stream => "stream",
    };
}

fn appendHistogramBucket(out: *std.array_list.Managed(u8), name: []const u8, le: []const u8, value: u64) !void {
    try out.print("{s}_bucket{{le=\"{s}\"}} {d}\n", .{ name, le, value });
}

fn ticketKeyReloadOutcomeLabel(outcome: TicketKeyReloadOutcome) []const u8 {
    return switch (outcome) {
        .initial_load_success => "initial_load_success",
        .initial_load_failure => "initial_load_failure",
        .reload_accepted => "reload_accepted",
        .reload_rejected => "reload_rejected",
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
    // Local-capacity truncations are counted separately from origin aborts:
    // `tardigrade_proxy_upstream_aborts_total` means the *origin* gave up.
    try std.testing.expectEqual(@as(u64, 0), m.proxy_local_capacity_aborts);
    m.recordProxyLocalCapacityAbort();
    try std.testing.expectEqual(@as(u64, 1), m.proxy_local_capacity_aborts);
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
    m.recordProxyBufferLimitExceeded(.upstream_to_downstream, .origin);
    m.recordProxyBufferLimitExceeded(.downstream_to_upstream, .global);

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
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_limit_exceeded_total{direction=\"upstream_to_downstream\",scope=\"origin\"} 1") != null);
    // A local-capacity truncation must not land in the upstream-abort series.
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_proxy_local_capacity_aborts_total 0") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_limit_exceeded_total{direction=\"downstream_to_upstream\",scope=\"global\"} 1") != null);
    // Aggregate scopes are counted independently of the per-stream scope.
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_limit_exceeded_total{direction=\"downstream_to_upstream\",scope=\"origin\"} 0") != null);
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

    m.recordTicketKeyReload(.initial_load_success);
    m.recordTicketKeyReload(.reload_rejected);
    m.recordTicketKeyReload(.reload_rejected);
    try std.testing.expectEqual(@as(u64, 1), m.tls_ticket_key_reload_total[ticketKeyReloadOutcomeIndex(.initial_load_success)]);
    try std.testing.expectEqual(@as(u64, 2), m.tls_ticket_key_reload_total[ticketKeyReloadOutcomeIndex(.reload_rejected)]);
}

test "resumption and ticket counters appear in Prometheus output with closed-enum labels only (#488)" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordResumptionAttempt(.quic);
    m.recordResumptionOutcome(.quic, .accepted);
    m.recordTicketIssue(.record, .stateful, .success);
    m.recordTicketStore(.success);
    m.recordTicketResolve(.hybrid, .success);
    m.recordTicketKeyReload(.reload_accepted);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_resumption_attempt_total{transport=\"quic\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_resumption_outcome_total{transport=\"quic\",outcome=\"accepted\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_issue_total{transport=\"record\",mode=\"stateful\",result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_store_total{result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_resolve_total{mode=\"hybrid\",result=\"success\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_ticket_key_reload_total{outcome=\"reload_accepted\"} 1") != null);
}

test "#368 Slice 3: early-data replay counters default to zero and record by outcome" {
    var m = Metrics.init();
    inline for (.{
        EarlyDataReplayOutcome.accepted,
        EarlyDataReplayOutcome.duplicate,
        EarlyDataReplayOutcome.capacity_rejected,
        EarlyDataReplayOutcome.expired,
        EarlyDataReplayOutcome.unavailable,
        EarlyDataReplayOutcome.startup_quarantine,
    }) |outcome| {
        try std.testing.expectEqual(@as(u64, 0), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(outcome)]);
    }

    m.recordEarlyDataReplay(.accepted);
    m.recordEarlyDataReplay(.accepted);
    m.recordEarlyDataReplay(.duplicate);
    m.recordEarlyDataReplay(.capacity_rejected);
    m.recordEarlyDataReplay(.expired);
    m.recordEarlyDataReplay(.unavailable);
    m.recordEarlyDataReplay(.startup_quarantine);

    try std.testing.expectEqual(@as(u64, 2), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.accepted)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.duplicate)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.capacity_rejected)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.expired)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.unavailable)]);
    try std.testing.expectEqual(@as(u64, 1), m.tls_early_data_replay_total[earlyDataReplayOutcomeIndex(.startup_quarantine)]);
}

test "#368 Slice 3: early-data replay counters appear in Prometheus output with closed-enum labels only, duplicate and unavailable distinguishable" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();
    m.recordEarlyDataReplay(.accepted);
    m.recordEarlyDataReplay(.duplicate);
    m.recordEarlyDataReplay(.duplicate);
    m.recordEarlyDataReplay(.capacity_rejected);
    m.recordEarlyDataReplay(.unavailable);
    m.recordEarlyDataReplay(.startup_quarantine);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "# TYPE tardigrade_tls_early_data_replay_total counter") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"accepted\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"duplicate\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"capacity_rejected\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"expired\"} 0") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"unavailable\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_early_data_replay_total{outcome=\"startup_quarantine\"} 1") != null);
}

test "Metrics records proxy streaming fallback reasons" {
    const allocator = std.testing.allocator;
    // Driven by the enum itself, so a new reason is covered here the moment it
    // exists. The recorder's exhaustive switch is what makes that safe: a case
    // without a counter does not compile, and this asserts the counter also
    // reaches the Prometheus surface rather than incrementing into the void.
    var m = Metrics.init();
    for (std.enums.values(ProxyStreamingFallbackReason)) |reason| {
        m.recordProxyStreamingFallback(reason);
    }

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    for (std.enums.values(ProxyStreamingFallbackReason)) |reason| {
        var expected_buf: [128]u8 = undefined;
        const expected = try std.fmt.bufPrint(
            &expected_buf,
            "tardigrade_proxy_streaming_fallback_total{{reason=\"{s}\"}} 1",
            .{reason.label()},
        );
        try std.testing.expect(std.mem.find(u8, prom, expected) != null);
    }
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

test "H3 QPACK metrics expose current blocked gauge and monotonic counters" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();

    const empty = Metrics.H3QpackSnapshot{};
    const conn_a = Metrics.H3QpackSnapshot{
        .current_blocked_streams = 2,
        .blocked_streams = 3,
        .table_bytes = 128,
        .decode_failures = 1,
    };
    const conn_b = Metrics.H3QpackSnapshot{
        .current_blocked_streams = 1,
        .blocked_streams = 1,
        .table_bytes = 64,
    };
    const conn_a_later = Metrics.H3QpackSnapshot{
        .current_blocked_streams = 1,
        .blocked_streams = 3,
        .unblocked_streams = 1,
        .table_bytes = 96,
        .decode_failures = 2,
    };

    m.recordH3QpackSnapshotDelta(empty, conn_a);
    m.recordH3QpackSnapshotDelta(empty, conn_b);
    m.recordH3QpackSnapshotDelta(conn_a, conn_a_later);

    try std.testing.expectEqual(@as(u64, 2), m.h3_qpack_blocked_streams_current);
    try std.testing.expectEqual(@as(u64, 160), m.h3_qpack_table_bytes);
    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_qpack_blocked_streams 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_qpack_blocked_streams_total 4") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_qpack_unblocked_streams_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_qpack_table_bytes 160") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_qpack_decode_failures_total 2") != null);

    m.removeH3QpackSnapshot(conn_a_later);
    m.removeH3QpackSnapshot(conn_b);
    try std.testing.expectEqual(@as(u64, 0), m.h3_qpack_blocked_streams_current);
    try std.testing.expectEqual(@as(u64, 0), m.h3_qpack_table_bytes);
    try std.testing.expectEqual(@as(u64, 4), m.h3_qpack_blocked_streams_total);
}

test "QUIC and H3 transport metrics expose bounded labels and consistent latency histogram" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();

    m.setQuicConnectionsActive(2);
    m.recordQuicHandshakeFailure(.initial);
    m.recordQuicHandshakeFailure(.handshake);
    m.recordQuicTransportDelta(.{
        .retry = 1,
        .amplification_blocked = 2,
        .pto = 3,
        .packets_lost = 4,
        .bytes_sent = 1200,
        .bytes_received = 2400,
        .stream_resets = 5,
        .connection_flow_blocked = 6,
        .stream_flow_blocked = 7,
        .deprotection_failures = 8,
    });
    m.recordH3RequestLatency(4);
    m.recordH3RequestLatency(1200);

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_connections_active 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_handshake_failures_total{stage=\"initial\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_handshake_failures_total{stage=\"handshake\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_retry_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_amplification_blocked_total 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pto_total 3") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_lost_total 4") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_bytes_sent_total 1200") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_bytes_received_total 2400") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_stream_resets_total 5") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"connection\"} 6") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"stream\"} 7") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_deprotection_failures_total 8") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_requests_total 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_request_latency_ms_bucket{le=\"5\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_request_latency_ms_bucket{le=\"+Inf\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_request_latency_ms_sum 1204") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_h3_request_latency_ms_count 2") != null);
}

test "#256-G: QUIC packet/PMTU/ECN/UDP-buffer transport state renders with requested-vs-effective distinction" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();

    // These fields are populated by GatewayState.overlayQuicTransportSnapshot
    // at render time, not by a Metrics setter — set them directly here the
    // way the overlay would.
    m.quic_packets_sent_total = 42;
    m.quic_packets_received_total = 41;
    m.quic_pmtu_probes_sent_total = 3;
    m.quic_pmtu_black_holes_total = 1;
    m.quic_effective_plpmtu_bytes_last = 1452;
    m.quic_effective_plpmtu_bytes_lifetime_min = 1200;
    m.quic_effective_plpmtu_bytes_lifetime_max = 1452;
    m.quic_ecn_enabled = 1;
    m.quic_ecn_marked_sent_total = 10;
    m.quic_ecn_paths_validated_total = 2;
    m.quic_ecn_paths_disabled_total = 1;
    m.quic_ecn_ce_received_total = 5;
    // Distinct requested/effective/granted values so a test that mixed them
    // up would fail — this is exactly the confusion #256-G forbids.
    m.quic_udp_recv_buffer_requested_bytes = 4_194_304;
    m.quic_udp_recv_buffer_effective_bytes = 2_097_152;
    m.quic_udp_recv_buffer_granted_bytes = 1_048_576;
    m.quic_udp_recv_buffer_status = .clamped;
    m.quic_udp_send_buffer_requested_bytes = 4_194_304;
    m.quic_udp_send_buffer_effective_bytes = 8_388_608;
    m.quic_udp_send_buffer_granted_bytes = 4_194_304;
    m.quic_udp_send_buffer_status = .applied;

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_sent_total 42") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_received_total 41") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pmtu_probes_total 3") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pmtu_black_holes_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_effective_plpmtu_bytes_last 1452") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_effective_plpmtu_bytes_lifetime_min 1200") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_effective_plpmtu_bytes_lifetime_max 1452") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_enabled 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_marked_sent_total 10") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_paths_validated_total 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_paths_disabled_total 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_ce_received_total 5") != null);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_requested_bytes{direction=\"recv\"} 4194304") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_effective_bytes{direction=\"recv\"} 2097152") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_granted_bytes{direction=\"recv\"} 1048576") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"recv\",status=\"clamped\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_requested_bytes{direction=\"send\"} 4194304") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_effective_bytes{direction=\"send\"} 8388608") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_granted_bytes{direction=\"send\"} 4194304") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"send\",status=\"applied\"} 1") != null);
}

test "#256-G: QUIC transport state defaults to zero/default when no H3 runtime is attached" {
    const allocator = std.testing.allocator;
    const m = Metrics.init();

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_sent_total 0") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_ecn_enabled 0") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"recv\",status=\"default\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_quic_udp_buffer_status{direction=\"send\",status=\"default\"} 1") != null);
}

test "listener sharding metrics record per-shard accepts and errors and emit Prometheus series (#137)" {
    const allocator = std.testing.allocator;
    var m = Metrics.init();

    // Default: single shard.
    try std.testing.expectEqual(@as(u16, 1), m.listener_shards);

    // Configure 3 shards.
    m.setListenerShards(3);
    try std.testing.expectEqual(@as(u16, 3), m.listener_shards);

    // Record accepts and errors on different shards.
    m.recordAccept(0);
    m.recordAccept(0);
    m.recordAccept(1);
    m.recordAcceptError(2, .accept);
    m.recordAcceptError(2, .poll);
    m.recordAcceptBatch(0, 1);
    m.recordAcceptBatch(0, 3);
    m.recordAcceptBatch(1, 17);
    m.recordAcceptFairnessYield(0);

    try std.testing.expectEqual(@as(u64, 2), m.accepts_total[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.accepts_total[1].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), m.accepts_total[2].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), m.accept_errors_total[0][acceptErrorReasonIndex(.accept)].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.accept_errors_total[2][acceptErrorReasonIndex(.accept)].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.accept_errors_total[2][acceptErrorReasonIndex(.poll)].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), m.accept_batches_total[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 4), m.accept_batch_size_sum[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.accept_fairness_yields_total[0].load(.monotonic));

    // Out-of-bounds shard IDs are clamped.
    m.recordAccept(@as(u16, max_listener_shards) + 10);
    try std.testing.expectEqual(@as(u64, 1), m.accepts_total[max_listener_shards - 1].load(.monotonic));

    const prom = try m.toPrometheus(allocator);
    defer allocator.free(prom);

    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_listener_shards 3") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accepts_total{shard=\"0\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accepts_total{shard=\"1\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_errors_total{shard=\"2\",reason=\"accept\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_errors_total{shard=\"2\",reason=\"poll\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batch_size_bucket{shard=\"0\",le=\"1\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batch_size_bucket{shard=\"0\",le=\"4\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batch_size_bucket{shard=\"1\",le=\"+Inf\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batch_size_sum{shard=\"0\"} 4") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batch_size_count{shard=\"0\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_batches_total{shard=\"0\"} 2") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_accept_fairness_yields_total{shard=\"0\"} 1") != null);
}
