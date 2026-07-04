<h1 align="center">Tardigrade</h1>

<p align="center">
  <strong>A small Zig edge server for static file serving, reverse proxying, TLS termination, and operator-friendly reloads.</strong>
</p>

<p align="center">
  <a href="https://github.com/Bare-Systems/Tardigrade/releases">Releases</a> |
  <a href="docs/SUPPORT_MATRIX.md">Support Matrix</a> |
  <a href="docs/OBSERVABILITY.md">Observability</a> |
  <a href="SECURITY.md">Security</a> |
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/Bare-Systems/Tardigrade/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Bare-Systems/Tardigrade/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Bare-Systems/Tardigrade/actions/workflows/scorecard.yml"><img alt="OSSF Scorecard" src="https://github.com/Bare-Systems/Tardigrade/actions/workflows/scorecard.yml/badge.svg"></a>
  <a href="https://github.com/Bare-Systems/Tardigrade/releases"><img alt="GitHub release" src="https://img.shields.io/github/v/release/Bare-Systems/Tardigrade?include_prereleases"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Bare-Systems/Tardigrade"></a>
</p>

---

### Host-native edge serving in Zig

Tardigrade is a lightweight HTTP/1.1 server and reverse proxy for deployments
that want a small native binary, config-driven routing, observable runtime
behavior, and predictable reloads.

It is early-stage software with a deliberately narrow stable core. The official
compatibility promise is documented in the [Core v1 support matrix](docs/SUPPORT_MATRIX.md).

---

### Menu

- [Features](#features)
- [Install](#install)
- [Build from source](#build-from-source)
- [Quick start](#quick-start)
- [Overview](#overview)
- [Full documentation](#full-documentation)
- [Performance](#performance)
- [Development](#development)
- [Getting help](#getting-help)
- [About](#about)

## Features

- Static file serving with normalized path handling, range support, cache
  validation, and symlink escape protection.
- Reverse proxying with config-driven `location` routing, upstream health checks,
  retries for safe connection-drop cases, and optional bounded streaming for
  larger HTTP transfers.
- TLS termination for the stable HTTP/1.1 edge path.
- Hot reloads and graceful drain behavior for operator-managed deployments.
- JSON access logs, request IDs, W3C `traceparent` forwarding, and Prometheus
  metrics at `/status/metrics` by default.
- Request limits, rate limiting, security headers, and release-gated security
  regression tests.
- A native packaging path with release archives, DEB/RPM package builders,
  service files, checksums, SBOMs, and provenance attestation.

HTTP/2, HTTP/3/QUIC, WebSocket/SSE, ACME, FastCGI, uWSGI, SCGI, memcached, and
BearClaw-specific flows exist in-tree, but they are not all part of the stable
Core v1 contract. Check the [support matrix](docs/SUPPORT_MATRIX.md) before
depending on a specific surface.

## Install

The fastest way to install the latest release is the official install script:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

The installer downloads the matching Linux release archive (`x86_64` or
`aarch64`), verifies it against `tardigrade-checksums.txt`, and installs
`tardigrade` into `$HOME/.local/bin` by default.

Other install paths:

- Download release archives directly from [GitHub Releases](https://github.com/Bare-Systems/Tardigrade/releases).
- Build from source (see below).

## Build from source

Requirements:

- [Zig](https://ziglang.org/) 0.16.0
- OpenSSL development libraries on Linux, for example `libssl-dev` on Debian or
  Ubuntu
- Optional HTTP/3 support additionally requires the `ngtcp2`, `nghttp3`, and
  `ngtcp2_crypto_ossl` system libraries. Enable it explicitly with
  `-Denable-http3-ngtcp2=true`.

For development:

```bash
git clone https://github.com/Bare-Systems/Tardigrade.git
cd Tardigrade
zig build run
```

For a release-mode binary:

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/tardigrade --help
```

With explicit version metadata:

```bash
zig build -Doptimize=ReleaseFast -Dversion="$(git describe --tags --always)"
```

Useful build options are documented in [CONTRIBUTING.md](CONTRIBUTING.md#build-options).

## Quick start

Create a small static root:

```bash
mkdir -p public
printf '%s\n' '<h1>Hello from Tardigrade</h1>' > public/index.html
```

Create `tardigrade.conf`:

```nginx
listen 8069;
server_name localhost;

root ./public;
try_files $uri /index.html;

location = /health {
    return 200 ok;
}

location /api/ {
    proxy_pass http://127.0.0.1:8080;
}
```

Build and run:

```bash
zig build
./zig-out/bin/tardigrade run -c ./tardigrade.conf
```

Then open:

- `http://localhost:8069/`
- `http://localhost:8069/health`

Common CLI commands:

```bash
./zig-out/bin/tardigrade check ./tardigrade.conf
./zig-out/bin/tardigrade config validate ./tardigrade.conf
./zig-out/bin/tardigrade validate -c ./tardigrade.conf
./zig-out/bin/tardigrade print-config -c ./tardigrade.conf
./zig-out/bin/tardigrade status -c ./tardigrade.conf
./zig-out/bin/tardigrade reload -c ./tardigrade.conf
./zig-out/bin/tardigrade stop -c ./tardigrade.conf
./zig-out/bin/tardigrade config init
```

`check` performs a dry parse and semantic validation without starting listeners
or connecting to upstreams. When no path is supplied, it validates
`./tardigrade.toml`; pass the path explicitly when using the nginx-style
`tardigrade.conf` examples.

## Overview

Tardigrade's stable Core v1 identity is intentionally focused: a host-native
Zig HTTP/1.1 edge server and reverse proxy with predictable operator behavior.
The main thread handles the non-blocking accept/event loop, while accepted
connections move through a bounded worker pool for blocking TLS, parsing,
proxying, and response writes.

Idle HTTP/1.1 keep-alive connections are parked off the worker pool between
requests, so idle clients do not consume worker capacity. HTTP/2 multiplexes
internally and is tracked as an experimental surface rather than part of the
default stable release contract.

Configuration is nginx-inspired and can be checked before startup with
`tardigrade check <config>`. Runtime inspection commands such as `status` and
`print-config` are designed to make package and service deployments easier to
operate without guessing which config file or pid file is active.

## Full documentation

| Topic | Location |
| --- | --- |
| Core v1 support matrix | [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) |
| Concurrency & hot-path audit | [docs/CONCURRENCY.md](docs/CONCURRENCY.md) |
| Observability | [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) |
| Proxy security | [docs/PROXY_SECURITY.md](docs/PROXY_SECURITY.md) |
| Security test plan | [docs/SECURITY_TEST_PLAN.md](docs/SECURITY_TEST_PLAN.md) |
| Pentest playbook | [docs/PENTEST_PLAYBOOK.md](docs/PENTEST_PLAYBOOK.md) |
| Code review checklist | [docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md) |
| Release checklist | [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) |
| Packaging | [packaging/README.md](packaging/README.md) |
| Benchmarks | [benchmarks/README.md](benchmarks/README.md) |
| BearClaw example | [examples/bearclaw/README.md](examples/bearclaw/README.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Release history | [CHANGELOG.md](CHANGELOG.md) |

## Performance

Canonical benchmark runs are captured from a dedicated benchmark target, not a
local laptop fallback run. Saved benchmark JSON records latency percentiles,
throughput, errors, and optional target CPU/RSS samples.

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

## Development

Use Zig `0.16.0` for local validation.

```bash
# Format check
zig fmt --check build.zig src/ tests/

# Unit tests
zig build test --summary all --error-style verbose

# Security corpus replay
zig build test-security-corpus

# Integration tests
zig build test-integration

# Allocation budget report
zig build bench-allocations
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md) before making
larger changes.

## Getting help

- Use [GitHub Issues](https://github.com/Bare-Systems/Tardigrade/issues) for
  actionable bug reports and feature requests.
- Use [SECURITY.md](SECURITY.md) for vulnerability reporting instructions.
- Include the config, command, logs, platform, and whether the affected surface
  is listed as stable or experimental in the support matrix.

## About

Tardigrade is developed by Bare Systems as a host-native edge component for
small services, internal platforms, and controlled deployments. It is licensed
under the [Apache License 2.0](LICENSE).
