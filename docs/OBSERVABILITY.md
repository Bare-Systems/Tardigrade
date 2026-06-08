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
- reverse-proxy abort counters:
  `tardigrade_proxy_client_aborts_total` and
  `tardigrade_proxy_upstream_aborts_total`
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
| Concurrent in-flight requests | `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | 0 (unlimited) | `GatewayState.tryAcquireRequestSlot` | Returns `503` before any request work; counted as a server error |
| URI too long | `TARDIGRADE_MAX_URI_LENGTH` (per-route) | 8 KiB | `request_limits.validateUriLength` | `414`-class rejection before body allocation |
| Too many headers | `max_header_count` | 100 | `request_limits.validateHeaderCount` | `431`-class rejection before body allocation |
| Single header too large | `max_header_size` | 8 KiB | `request_limits.validateHeaderSize` | `431`-class rejection |
| All headers too large | `max_headers_total_size` | 32 KiB | `request_limits.validateHeadersTotalSize` | `431` before body allocation |
| Request body too large | `max_body_size` | 1 MiB | `request_limits.validateBodySize` | `413`-class rejection |
| Parked keepalive backlog | idle-park timeout / `max_requests_per_connection` | — | `keepalive_park.ParkedRegistry` | Idle parked connections reaped on the timer tick (`timeouts_total`); none hold a worker while idle |

Notes on the two pool-style resources called out in the issue:

- **Request/relay buffer pools** (`http/buffer_pool.zig`) are caches, not hard
  caps: `acquire` always returns a buffer (reused when available, freshly
  allocated otherwise) and `release` frees anything beyond `max_cached` instead
  of growing without bound. Backpressure that actually bounds buffer demand
  comes from the connection and in-flight limits above, not from the pool.
- **Upstream connection pool / pending upstream requests** are bounded by the
  per-upstream health and active-request accounting in `GatewayState`
  (`upstream_active_requests`) together with the circuit breaker; an unhealthy
  or saturated upstream fails the affected request rather than the listener.

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

Tuning principle: raise a limit only after confirming the gateway has headroom
(CPU, memory, fds) to honor it. The limits exist so that exhaustion produces a
predictable `503` or a clean socket close instead of unbounded allocation or
worker starvation.
