<h1 align="center">Tardigrade</h1>

<p align="center">
  A small Zig HTTP server and edge gateway for static delivery, reverse proxying,
  config-driven routing, TLS termination, and operator-friendly reloads.
</p>

---

Tardigrade is an early-stage Zig service runtime for lightweight edge deployments,
internal platforms, and controlled lab environments.

## Support Status

The official Core v1 support contract lives in
`docs/SUPPORT_MATRIX.md`.

Stable Core v1 currently covers:

- static file serving
- reverse proxying
- config-driven routing with `server` and `location` blocks
- TLS termination
- config validation, reload, and graceful drain behavior
- access logging, Prometheus metrics, request limits, rate limiting, and
  basic upstream health checks

Visible but non-Core-v1 surfaces such as HTTP/2, HTTP/3/QUIC, WebSocket/SSE,
ACME, FastCGI/uWSGI/SCGI, memcached, and BearClaw-specific auth/session/
transcript/approval flows are classified separately in the support matrix.

Some protocol and gateway features are still experimental. Prefer the example
configs, the support matrix, and the integration tests as the source of truth
when evaluating a specific capability.

## Quick Start

### Prerequisites

- [Zig](https://ziglang.org/) 0.16.0

### Build and run from source

```bash
git clone https://github.com/Bare-Systems/Tardigrade.git
cd Tardigrade
zig build run
```

The default development listener starts on `http://localhost:8069`.

### Install latest release

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

## Basic Usage

```bash
./zig-out/bin/tardigrade run
./zig-out/bin/tardigrade validate -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade status -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade print-config -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade reload -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade stop -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade config init
```

`validate` now prints the resolved config path plus a compact summary of the
effective listener, pid file, protocol toggles, worker settings, and metrics
path. `status` reports whether the configured pid is running when a pid or pid
file is available, and `print-config` prints the same effective-config summary
without starting the runtime.

## Minimal Config Example

```nginx
listen_port 8069;
root ./public;
try_files $uri /index.html;

location /api/ {
    proxy_pass http://127.0.0.1:8080;
}

location = /health {
    return 200 ok;
}
```

When proxying, Tardigrade strips hop-by-hop request headers, including headers
named by the incoming `Connection` header, before forwarding requests upstream.
Buffered upstream response bodies use a dedicated limit controlled by
`TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` (default `262144`), so
operators can raise proxy payload ceilings without changing inbound request
parsing limits.
Streaming proxy mode is available for large HTTP upstream transfers:
`TARDIGRADE_PROXY_STREAMING_MODE=off|response|full` keeps the default buffered
behavior, streams upstream responses, or streams both upstream responses and
eligible fixed-length client request bodies. `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE`
defaults to `16384` bytes and is capped at 1 MiB. Streaming is used on simple
single-attempt HTTP proxy routes; Unix-socket upstreams, custom upstream mTLS,
retry-enabled paths, rewrites, mirrors, and auth subrequests stay on the
bounded buffered compatibility path.
When an upstream container is replaced on the same host:port, the first request
that hits a dead pooled keep-alive socket now evicts that stale connection so
later requests reconnect cleanly without restarting Tardigrade. If an upstream
closes an idle keep-alive connection just as Tardigrade reuses it (so the
response read returns zero bytes), Tardigrade transparently retries the request
on a fresh connection instead of returning a `502` — the request was never
delivered, so this is safe for idempotent methods (and for any method when
`TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY=false`). Proxy requests
that send an explicit zero-length `POST` body are also forwarded without
triggering a runtime panic.
Large buffered proxy responses now preserve the upstream body exactly instead of
duplicating the first body chunk after the internal 8 KiB response scratch
buffer fills.

Static file requests are percent-decoded and normalized before filesystem
access. Traversal attempts and symlink escapes outside the configured root are
rejected with `403`.

On plain HTTP connections, static file responses use a file-backed transfer
path when the OS supports it, while TLS and other transformed response paths
continue to use the buffered fallback.

When authentication credentials are present, rate limiting keys on the
authenticated identity before routing. Requests without resolved auth context
still fall back to client IP rate limiting.

Hot reloads now retire superseded configs after in-flight requests drain, so
repeated `reload` or `SIGHUP` cycles do not retain old config allocations.

Connection handling is intentionally split: the main thread runs a non-blocking
accept/event loop, while accepted sockets move onto a bounded worker pool for
blocking TLS, HTTP parsing, proxying, and response writes. Between requests an
idle HTTP/1.1 keepalive connection is **parked** off the worker pool — its state
returns to the event loop and the worker is freed — so idle clients do not
consume worker capacity and connections far exceeding the worker count stay
served with a low tail (HTTP/2 connections multiplex internally and are not
parked). Because of this, `worker_threads` can be sized to CPU count rather than
to peak concurrent connections. `/status/metrics` exports
`tardigrade_active_connections`, `tardigrade_worker_active_jobs`,
`tardigrade_worker_queued_jobs`, `tardigrade_worker_threads`,
`tardigrade_event_loop_iterations_total`, and the parked-connection gauges
`tardigrade_keepalive_parked_connections`, `tardigrade_keepalive_resumes_total`,
`tardigrade_keepalive_timeouts_total`, and `tardigrade_keepalive_closed_total`,
so operators can see whether load is building at the listener, the worker queue,
parked keepalive connections, or inside active request work.

Tardigrade accepts a safe inbound `X-Request-ID` or legacy
`X-Correlation-ID`, generates one when neither is valid, echoes both response
headers, and forwards the same ID upstream. JSON access logs include
`request_id`, `latency_ms`, `upstream_addr`, `upstream_status`, and
`response_bytes`.

Prometheus metrics are available on `TARDIGRADE_METRICS_PATH` (default
`/status/metrics`). Set the path to an empty string to disable the endpoint, or
set `TARDIGRADE_METRICS_REQUIRE_AUTH=true` to require the configured request
auth controls before serving metrics. The endpoint now includes a global
`tardigrade_request_latency_ms` histogram, proxy streaming/buffered counters,
proxy buffered-byte gauges/counters, proxy abort counters, upstream TTFB summary
metrics, and the worker/event-loop gauges documented in
`docs/OBSERVABILITY.md`.

Proxy hops also propagate W3C `traceparent` in addition to Tardigrade's
request ID headers, so upstream services can correlate the same request through
logs, metrics, and trace context.

Security validation is treated as a release gate. The current security program,
corpus replay entrypoint, and internal pentest workflow are documented in
`docs/SECURITY_TEST_PLAN.md` and `docs/PENTEST_PLAYBOOK.md`.

## Documentation

| Topic | Location |
| --- | --- |
| Core v1 support matrix | `docs/SUPPORT_MATRIX.md` |
| Code review checklist | `docs/CODE_REVIEW_CHECKLIST.md` |
| Observability | `docs/OBSERVABILITY.md` |
| Release checklist | `docs/RELEASE_CHECKLIST.md` |
| Packaging | `packaging/README.md` |
| Benchmarks | `benchmarks/README.md` |
| Security test plan | `docs/SECURITY_TEST_PLAN.md` |
| Pentest playbook | `docs/PENTEST_PLAYBOOK.md` |
| BearClaw example | `examples/bearclaw/README.md` |
| Security policy | `SECURITY.md` |
| Contributing | `CONTRIBUTING.md` |
| Release history | `CHANGELOG.md` |

## Testing

```bash
# Unit tests
zig build test --summary all --error-style verbose --multiline-errors

# Security corpus replay
zig build test-security-corpus

# Integration tests (requires a running tardigrade instance and system OpenSSL)
zig build test-integration
```

## Performance

Benchmark releases should be captured from saved JSON under `benchmarks/baselines/`
and refreshed with `./benchmarks/report.sh <baseline.json> --update-readme README.md`.
Canonical benchmark runs are taken from a dedicated benchmark target, not from a
local laptop fallback run. Saved benchmark JSON now captures p50/p95/p99/p999
latencies, and when the run is given `--pid` or `--pid-file`, sampled target
CPU plus peak RSS for each scenario.

<!-- BENCHMARK_REPORT_START -->
| Scenario | req/s | p50 (ms) | p95 (ms) | p99 (ms) | p999 (ms) | CPU % | Peak RSS (MiB) | MB/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `keepalive` | 4700 | 0.4 | - | 41.8 | - | - | - | - | 0 |
| `proxy-http1` | 1724 | 1.3 | - | 114.9 | - | - | - | - | 0 |
| `static-http1` | 4586 | 0.4 | - | 46.1 | - | - | - | - | 0 |

> **v0.32.0-18-gb44f8c1** · 2026-05-02 · tool: `wrk` · 4 connections · 30s per scenario · host: `127.0.0.1`
> driver: `loopback (dedicated benchmark target)` · env: `release-baseline` · workers: `2` · config: `release-baseline config`
> CPU/RSS columns are sampled from the target Tardigrade process only when the run used `--pid` or `--pid-file`; otherwise they remain `-`.
>
> Run `./benchmarks/run.sh --save benchmarks/baselines/$(git describe --tags).json` then `./benchmarks/report.sh <file> --update-readme README.md` to refresh this table.
<!-- BENCHMARK_REPORT_END -->

## Formatting

Check formatting before committing:

```bash
zig fmt --check build.zig src/ tests/
```

Apply formatting in-place:

```bash
zig fmt build.zig src/ tests/
```
