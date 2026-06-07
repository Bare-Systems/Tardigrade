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
