# Tardigrade Benchmarks

Repeatable benchmark and regression harness for Tardigrade.

## Quick start

```bash
# Start a local Tardigrade instance (adjust env as needed)
TARDIGRADE_LISTEN_PORT=8069 ./zig-out/bin/tardigrade &

# Run all default scenarios with wrk (30 s, 50 connections)
./benchmarks/run.sh

# Save a baseline for the current release
./benchmarks/run.sh --save benchmarks/baselines/$(git describe --tags).json

# Compare a future run against that baseline
./benchmarks/run.sh --baseline benchmarks/baselines/<tag>.json
```

## Prerequisites

Install at least one load-generation tool. The runner auto-detects in this order:

| Tool | Install | Supports |
|---|---|---|
| [`wrk`](https://github.com/wg/wrk) | `brew install wrk` / apt | HTTP/1.1 |
| [`h2load`](https://nghttp2.org/) | `brew install nghttp2` / apt | HTTP/1.1 + HTTP/2 |
| [`fortio`](https://fortio.org/) | `brew install fortio` / apt | HTTP/1.1, JSON output |
| [`k6`](https://k6.io/) | `brew install k6` / apt | HTTP/1.1 + HTTP/2 |

`jq` is required for result formatting and baseline comparison.

## Scenarios

| Scenario | Description |
|---|---|
| `static-http1` | Static file serving over HTTP/1.1 (hits `/health`) |
| `proxy-http1` | Reverse proxy route over HTTP/1.1 |
| `proxy-http2` | Reverse proxy route over HTTP/2 (requires `h2load`) |
| `keepalive` | Keep-alive connection reuse |
| `reload-under-load` | SIGHUP sent mid-run; measures degradation during reload |

Run a subset: `--scenarios static-http1,keepalive`

## Options

```
--host HOST           Target host (default: 127.0.0.1)
--port PORT           Target port (default: 8069)
--tls                 Use HTTPS
--insecure            Skip TLS certificate verification
--duration SECS       Seconds per scenario (default: 30)
--connections N       Concurrent connections (default: 50)
--threads N           wrk worker threads (default: 4)
--scenarios LIST      Comma-separated scenario names
--tool TOOL           Force tool: wrk|h2load|fortio|k6
--baseline FILE       Compare against a baseline JSON file
--save FILE           Write results JSON to a file
--threshold PCT       Regression threshold percentage (default: 10)
```

Exit code 2 indicates at least one scenario regressed beyond the threshold.

## Baseline files

Baseline JSON files live under `benchmarks/baselines/`. File names should be the
git tag of the Tardigrade release that produced them, e.g. `v0.50.json`. These
files are checked into the repository so regressions can be caught in CI.

```
benchmarks/baselines/
└── v0.50.json     # baseline captured on the v0.50 release
```

## Recommended test host

Benchmark results are only meaningful when the test environment is controlled:

- Dedicated machine or VM (no shared tenants)
- Pin to specific CPU cores if the machine has more than Tardigrade needs
- Disable power management / frequency scaling (`cpufreq-set -g performance`)
- Run the benchmark driver on a separate host from Tardigrade when possible

Document the test host in each baseline file's `_meta.host` field.

## CI integration

Add a regression check to CI by storing a pinned baseline and running:

```yaml
- name: Regression benchmark
  run: |
    ./benchmarks/run.sh \
      --duration 10 \
      --connections 20 \
      --baseline benchmarks/baselines/latest.json \
      --threshold 15
```

Exit code 2 fails the job. Keep CI duration short (10 s) and connections low (20)
to avoid flaky results in shared runner environments.
