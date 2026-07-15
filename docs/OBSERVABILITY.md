# Observability

This document defines Tardigrade's operator-facing observability contract for
the stable HTTP/1.1 gateway path.

## Structured Logs

Runtime logs and access logs are JSON by default.

- runtime logs: `ts`, `level`, `component`, `msg`, and when available both
  `request_id` and `correlation_id`
- access logs: `type`, `ts`, `request_id`, `correlation_id`, `method`, `path`,
  `status`, `latency_ms`, `client_ip`, `upstream_addr`, `upstream_status`,
  `identity`, `bytes_sent`, `response_bytes`, and `error_category`

Access logs are written through `src/http/access_log.zig`. Runtime component
logs are written through `src/http/logger.zig`.

## Metrics

`/status/metrics` exports Prometheus text metrics for:

- total requests and status-class counters
- request latency histogram: `tardigrade_request_latency_ms`
- active connections
- worker-pool active jobs, queued jobs, configured threads, and queue capacity
- event-loop iterations
- queue and connection rejections
- upstream unhealthy backend count
- reverse-proxy streaming and buffered request counters:
  `tardigrade_proxy_streaming_requests_total` and
  `tardigrade_proxy_buffered_requests_total`
- reverse-proxy buffered byte gauges/counters:
  `tardigrade_proxy_buffered_bytes_current` and
  `tardigrade_proxy_buffered_bytes_total`
- shared proxy buffer accounting gauges/counters:
  `tardigrade_buffered_bytes_current{direction,scope}`,
  `tardigrade_buffer_high_watermark_events_total{direction,scope}`,
  `tardigrade_buffer_read_pauses_total{side}`,
  `tardigrade_buffer_read_resumes_total{side}`, and
  `tardigrade_buffer_limit_exceeded_total{direction,scope}`. Labels are fixed
  to protocol-independent directions, scopes, and sides; they never include
  URLs, request IDs, or stream IDs.
- configured proxy buffer limits:
  `tardigrade_buffer_config_limit_bytes{direction,scope,limit}` for the
  per-stream low/high/hard watermarks plus per-origin/global hard-limit
  settings.
- reverse-proxy abort counters:
  `tardigrade_proxy_client_aborts_total` and
  `tardigrade_proxy_upstream_aborts_total`
- reverse-proxy streaming fallback event counter:
  `tardigrade_proxy_streaming_fallback_total{reason=...}` with fixed reasons
  `policy_disabled`, `retries_configured`, `unix_socket_target`, and
  `upstream_mtls_target` for response-path eligibility plus
  `chunked_request_upload`, `missing_content_length`, `body_too_large`,
  `body_dependent_middleware`, and `unsupported_route_type` for request-upload
  eligibility. Upload and response eligibility are evaluated separately, so one
  request can contribute more than one fallback event.
- reverse-proxy upstream TTFB summary: `tardigrade_proxy_ttfb_ms`

The latency histogram is intentionally global rather than route-labeled to keep
hot-path overhead predictable.

## Request Tracing

Tardigrade always maintains a request identifier.

- inbound `X-Request-ID` is accepted when safe
- `X-Correlation-ID` remains supported as a legacy alias
- generated IDs are echoed back in both headers
- proxied upstream requests receive the same request ID headers

For W3C Trace Context, proxied upstream requests also propagate `traceparent`.
When no inbound `traceparent` exists, Tardigrade originates one for the hop.

`src/http/trace_context.zig` covers the wire-format handling; this is trace
propagation, not full span export.

## Resource Limits and Overload Behavior

Tardigrade is a fixed-resource edge gateway: it accepts work onto a bounded
worker pool with blocking I/O and rejects load it cannot serve rather than
allocating without bound. This section catalogs every configured limit, the
overload path it guards, the deterministic outcome when the limit is reached,
and the signal an operator should watch.

Two outcome shapes exist:

- **Deterministic HTTP response** — when an HTTP response is still possible, the
  client receives a fixed, predictable status. Accept-time rejections share the
  exact byte string `gateway_accept.overload_response_503` (a `503` with
  `Connection: close`, `Content-Length: 0`, and `Retry-After: 1`).
- **Safe socket close** — when no meaningful HTTP response can be produced (for
  example a queued fd discarded during a shutdown drain), the socket is closed
  rather than left in a partial or ambiguous state.

### Configured limits

| Scenario | Config (env) | Default | Enforced in | Outcome when reached |
|---|---|---|---|---|
| File descriptors | `TARDIGRADE_FD_SOFT_LIMIT` | OS default | `gateway_accept.applyFdSoftLimit` | Soft `RLIMIT_NOFILE` raised toward the hard cap at startup; `accept()` errors are logged, the loop yields, and the listener keeps running |
| Global connection limit | `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | 0 (unlimited) | `GatewayState.tryAcquireConnectionSlot` → `.over_global_limit` | Deterministic `503`; `connection_rejections` + `error_overload` incremented |
| Per-IP connection limit | `TARDIGRADE_MAX_CONNECTIONS_PER_IP` | 0 (unlimited) | `tryAcquireConnectionSlot` → `.over_ip_limit` | Deterministic `503`; `connection_rejections` + `error_overload`; warn log names the IP |
| Connection memory budget | `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` | 0 (off) | `tryAcquireConnectionSlot` → `.over_global_memory_limit` | Projected `(active+1) × per-conn estimate` over budget → deterministic `503`; `connection_rejections` + `error_overload` |
| Worker queue saturation | `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` (+ per-worker depth) | 0 (uses pool default) | `WorkerPool.submit` → `error.QueueFull` | Slot released, deterministic `503`; `queue_rejections` + `error_overload` |
| Concurrent in-flight requests | `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | 0 (unlimited) | `GatewayState.tryAcquireRequestSlot` | Returns `503` before any request work; `error_overload` incremented |
| URI too long | `TARDIGRADE_MAX_URI_LENGTH` | 8 KiB | `request_limits.validateUriLength` | `414`-class rejection before body allocation |
| Too many headers | `TARDIGRADE_MAX_HEADER_COUNT` | 100 | `request_limits.validateHeaderCount` | `431`-class rejection before body allocation |
| Single header too large | `TARDIGRADE_MAX_HEADER_SIZE` | 8 KiB | `request_limits.validateHeaderSize` | `431`-class rejection |
| All headers too large | `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE` | 32 KiB | `request_limits.validateHeadersTotalSize` | `431` before body allocation |
| Request body too large | `TARDIGRADE_MAX_BODY_SIZE` | 1 MiB | `request_limits.validateBodySize` | `413`-class rejection |
| Proxy per-stream buffer low watermark | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES` | 256 KiB | proxy buffer accounting | Paired with high watermark for pause/resume decisions; must satisfy `low < high <= hard` |
| Proxy per-stream buffer high watermark | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` | 768 KiB | proxy buffer accounting | High-watermark transition is observable through `tardigrade_buffer_high_watermark_events_total` |
| Proxy per-stream buffer hard limit | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES` | 1 MiB | proxy buffer accounting | Hard-limit exceedance is observable through `tardigrade_buffer_limit_exceeded_total`; enforcement lands per proxy path as backpressure work expands |
| Proxy per-origin buffer hard limit | `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | 0 (not enforced yet) | future aggregate proxy buffer accounting | When non-zero, must be at least the per-stream hard limit |
| Proxy global buffer hard limit | `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | 0 (not enforced yet) | future aggregate proxy buffer accounting | When non-zero, must be at least the per-stream hard limit |
| Parked keepalive backlog | idle-park timeout / `max_requests_per_connection` | — | `keepalive_park.ParkedRegistry` | Idle parked connections reaped on the timer tick (`timeouts_total`); none hold a worker while idle |

The request-size limits are enforced in two layers: the HTTP parser
(`http/headers.zig`) applies fixed backstops (per-header 8 KiB, all-headers
32 KiB, header count 100) that bound parse-time allocation regardless of
config, and the handler (`gateway_handlers.zig`) then applies the
operator-configured `request_limits` values. Configuring a value *stricter*
than the parser backstop tightens the limit; a value *looser* is still capped
by the parser backstop. All request-limit rejections are deterministic and
emit a `warn` runtime log plus the corresponding access-log status.

Notes on the two pool-style resources called out in the issue:

- **Request/relay buffer pools** (`http/buffer_pool.zig`) are caches, not hard
  caps: `acquire` always returns a buffer (reused when available, freshly
  allocated otherwise) and `release` frees anything beyond `max_cached` instead
  of growing without bound. Backpressure that actually bounds buffer demand
  comes from the connection and in-flight limits above, not from the pool.
- **Upstream connection pool / pending upstream requests** are bounded by the
  per-upstream health and active-request accounting in `GatewayState`
  (`upstream_active_requests`) together with the circuit breaker; an unhealthy
  or saturated upstream fails the affected request rather than the listener. The
  least-connections balancer sheds a saturated backend to the least-loaded
  healthy one and returns no candidate when every backend is unhealthy (the
  request is shed deterministically rather than queued without bound); the
  circuit breaker fast-fails once a backend trips its failure threshold and
  recovers through a single half-open probe. Both paths have fault-injection
  coverage in `src/gateway_state.zig`.
- **Log / metrics sink slow or unavailable** — access logging is best-effort and
  never blocks the request that emitted it. In buffered mode the buffer flushes
  at its configured threshold and is cleared regardless of the write outcome, so
  a stalled sink cannot grow retained memory without bound. A write the sink
  refuses is dropped (not retried) and counted, so a stalled sink is observable
  rather than silent. Bounded-buffer + drop-counting behavior is pinned by a
  fault-injecting-sink test in `src/http/access_log.zig`.

### Distinguishing overload causes

Every overload cause maps to a distinct signal so operators can tell them apart
without reading source:

- **Metrics** — `tardigrade_connection_rejections_total` counts connection-slot
  rejections (global / per-IP / memory); `tardigrade_queue_rejections_total`
  counts worker-queue saturation; `tardigrade_error_overload_total` aggregates
  both accept-time families. `active_connections`, `worker_queued_jobs`, and
  `worker_queue_capacity` show how close the gateway is to its caps.
- **Logs** — each accept-time rejection emits a distinct `warn` runtime log:
  per-IP limit names the offending IP, the global and memory limits each have
  their own message, and queue-submit failures log the submit error. Request
  validation rejections surface through the access log `error_category`.

The metrics that drive these counters are unit-tested in
`src/http/metrics.zig`; the deterministic accept-time response is pinned by a
regression test in `src/gateway_accept.zig`.

### Operator troubleshooting

| Symptom | Likely cause | First checks |
|---|---|---|
| Clients see `503` + `Retry-After`, `connection_rejections` climbing | Global or per-IP connection cap, or memory budget, reached | Compare `active_connections` to `TARDIGRADE_MAX_ACTIVE_CONNECTIONS`; grep runtime logs for `connection limit reached` / `memory estimate limit`; check for a single hot IP |
| `503`s with `queue_rejections` climbing while CPU is not saturated | Worker queue full faster than workers drain | Watch `worker_queued_jobs` vs `worker_queue_capacity` and `worker_active_jobs`; raise worker count or `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH`, or investigate slow upstreams holding workers |
| `503`s with no rejection counters moving | In-flight request cap hit | Review `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` against expected concurrency |
| `accept error` logs, new connections refused | File-descriptor exhaustion | Verify `TARDIGRADE_FD_SOFT_LIMIT` and the OS hard `RLIMIT_NOFILE`; look for fd leaks via `active_connections` not returning to baseline |
| `413` / `431` / `414` in access logs | Oversized body, headers, or URI | Confirm the configured request limits match legitimate client traffic before raising them |
| Tail latency spikes under many idle keepalive clients | Parked-connection backlog or too-long idle timeout | Watch parked `timeouts_total`; tune the idle-park timeout and `max_requests_per_connection` |
| Gaps in access logs, throughput otherwise normal | Log sink (stderr pipe / syslog) slow or unavailable | Logging is best-effort: dropped lines are counted internally and the request path is never blocked; check the downstream log collector / pipe rather than the gateway |
| All requests to one backend failing fast with no upstream contact | Circuit breaker open for that backend | Expected protection after repeated upstream failures; confirm the upstream is healthy — the breaker recovers via a half-open probe once `upstream_fail_timeout` elapses |

Tuning principle: raise a limit only after confirming the gateway has headroom
(CPU, memory, fds) to honor it. The limits exist so that exhaustion produces a
predictable `503` or a clean socket close instead of unbounded allocation or
worker starvation.

## Reload and Shutdown

Tardigrade supports zero-downtime configuration reload and graceful shutdown.
Both are driven by POSIX signals delivered to the running process (the
`tardigrade reload` / `tardigrade stop` CLI commands send these for you).

| Signal | Effect |
|---|---|
| `SIGHUP` | Hot-reload configuration from the environment / config file. |
| `SIGUSR1` | Reopen the error log (log rotation). |
| `SIGUSR2` | Begin graceful shutdown (alias of the upgrade path). |
| `SIGTERM` / `SIGINT` | Begin graceful shutdown. |

### Hot reload (SIGHUP)

On `SIGHUP` the gateway re-reads its configuration and applies it without
dropping connections:

1. **Load** the new configuration from the environment / config file.
2. **Validate** it. Invalid configuration is rejected here.
3. **Install** the new config version through a lease-counted store
   (`ReloadableConfigStore`): in-flight requests keep the config version they
   started with, and the old version is retired only after its last lease is
   released. New requests pick up the new version once installation completes.

Guarantees:

- **A failed reload never replaces the active config.** If load or validation
  fails, the previous configuration stays active and continues serving traffic;
  the failure is recorded and logged.
- **In-flight requests are not disrupted** by a reload; they finish on the
  config they began with.
- Reload status is queryable at `GET /tardigrade/reload/status`, which returns
  `{"ok": <bool|null>, "at_ms": <ts>, "error": <string|null>}`.

### Graceful shutdown and drain

On a shutdown signal the accept loop stops taking new connections and the worker
pool drains:

- **Active (already-dispatched) requests are allowed to finish** up to
  `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`. During shutdown each request's deadline
  is also capped to the remaining drain window so a single slow request cannot
  block shutdown indefinitely.
- **Queued (not-yet-started) connections** that remain when the drain deadline
  elapses are **force-closed** (their sockets are closed; no partial HTTP
  response is emitted). A drain timeout of `0` closes queued connections
  immediately with no wait.
- After the drain completes the worker threads are joined and the process exits.

### Reload / shutdown observability

Logs (runtime, via `src/http/logger.zig`):

- `configuration hot-reload starting` / `configuration hot-reload applied`
- `config reload failed during load` / `config reload rejected by validation` /
  `config reload allocation failed` / `config reload bookkeeping failed`
- `Shutdown requested; draining active connection work (timeout=… active_connections=…)`
- `drain timeout elapsed; force-closed N queued connection(s)`
- `Graceful shutdown complete (forced_closes=… drain_timed_out=…)`

Metrics (`/status/metrics`):

| Metric | Meaning |
|---|---|
| `tardigrade_reload_attempts_total` | Reloads started (SIGHUP received and processed). |
| `tardigrade_reload_success_total` | Reloads that loaded, validated, and installed. |
| `tardigrade_reload_failure_total` | Reloads rejected; previous config kept. |
| `tardigrade_drain_total` | Graceful-shutdown drains started. |
| `tardigrade_drain_timeouts_total` | Drains that hit the drain timeout. |
| `tardigrade_drain_forced_closes_total` | Queued connections force-closed on drain timeout. |

A healthy reload increments `reload_attempts_total` and `reload_success_total`
together; a rejected reload increments `reload_attempts_total` and
`reload_failure_total` while the reload-status endpoint reports `ok: false` with
the rejection reason.

## QUIC / HTTP-3 (pure-Zig backend)

The pure-Zig QUIC/H3 stack (#240) has its own transport-level observability
seam — qlog event tracing, TLS key logging for local decryption, and planned
Prometheus counters — designed in [`QUIC_QLOG.md`](QUIC_QLOG.md). Unlike the
stable HTTP/1.1 contract above, these paths are **disabled by default** and are
**sensitive/debug-only**: a key log decrypts the connection. They are for local
debugging and the interop harness (#247), never a production default.
