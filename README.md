<h1 align="center">Tardigrade</h1>

<p align="center">
  A small Zig HTTP server and edge gateway for static delivery, reverse proxying,
  config-driven routing, TLS termination, and operator-friendly reloads.
</p>

---

Tardigrade is an early-stage Zig service runtime for lightweight edge deployments,
internal platforms, and controlled lab environments.

The project currently focuses on:

- static file serving
- reverse proxying
- config-driven routing with `server` and `location` blocks
- TLS termination
- config validation and hot reloads
- access logging and basic operational controls

Some protocol and gateway features are still experimental. Prefer the example
configs and integration tests as the source of truth when evaluating a specific
capability.

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
./zig-out/bin/tardigrade reload -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade stop -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade config init
```

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

Tardigrade accepts a safe inbound `X-Request-ID` or legacy
`X-Correlation-ID`, generates one when neither is valid, echoes both response
headers, and forwards the same ID upstream. JSON access logs include
`request_id`, `latency_ms`, `upstream_addr`, `upstream_status`, and
`response_bytes`.

Prometheus metrics are available on `TARDIGRADE_METRICS_PATH` (default
`/status/metrics`). Set the path to an empty string to disable the endpoint, or
set `TARDIGRADE_METRICS_REQUIRE_AUTH=true` to require the configured request
auth controls before serving metrics.

Security validation is treated as a release gate. The current security program,
corpus replay entrypoint, and internal pentest workflow are documented in
`docs/SECURITY_TEST_PLAN.md` and `docs/PENTEST_PLAYBOOK.md`.

## Documentation

| Topic | Location |
| --- | --- |
| Zig 0.16 engineering guide | `docs/ZIG_ENGINEERING_GUIDE.md` |
| Code review checklist | `docs/CODE_REVIEW_CHECKLIST.md` |
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
local laptop fallback run.

<!-- BENCHMARK_REPORT_START -->
| Scenario | req/s | p50 (ms) | p99 (ms) | MB/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| `keepalive` | 4700 | 0.4 | 41.8 | - | 0 |
| `proxy-http1` | 1724 | 1.3 | 114.9 | - | 0 |
| `static-http1` | 4586 | 0.4 | 46.1 | - | 0 |

> **v0.32.0-18-gb44f8c1** · 2026-05-02 · tool: `wrk` · 4 connections · 30s per scenario · host: `127.0.0.1`
> driver: `loopback (dedicated benchmark target)` · env: `release-baseline` · workers: `2` · config: `release-baseline config`
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
