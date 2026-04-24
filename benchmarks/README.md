# Tardigrade Benchmarks

Repeatable benchmark and regression harness for Tardigrade.

## Quick start

```bash
# Start a local Tardigrade instance (adjust env as needed)
TARDIGRADE_LISTEN_PORT=8069 ./zig-out/bin/tardigrade &

# Run all default scenarios with auto-detected tool (30 s, 50 connections)
./benchmarks/run.sh

# Save a baseline for the current release
./benchmarks/run.sh --save benchmarks/baselines/$(git describe --tags).json

# Compare a future run against that baseline
./benchmarks/run.sh --baseline benchmarks/baselines/<tag>.json

# Generate a markdown report from a saved baseline
./benchmarks/report.sh benchmarks/baselines/<tag>.json

# Update the README performance table in-place
./benchmarks/report.sh benchmarks/baselines/<tag>.json --update-readme README.md
```

## Prerequisites

Install at least one load-generation tool. The runner auto-detects in this order:

| Tool | Install | Supports |
|---|---|---|
| [`wrk`](https://github.com/wg/wrk) | `brew install wrk` / apt | HTTP/1.1 |
| [`h2load`](https://nghttp2.org/) | `brew install nghttp2` / apt | HTTP/1.1 + HTTP/2 |
| [`fortio`](https://fortio.org/) | `brew install fortio` / apt | HTTP/1.1, JSON output |
| [`k6`](https://k6.io/) | `brew install k6` / apt | HTTP/1.1 + HTTP/2 + behavioral scenarios |

`jq` is required for result formatting, baseline comparison, and report generation.

## Scenarios

### Throughput scenarios (all tools)

These measure raw request throughput and run with whichever tool is auto-detected.

| Scenario | Description |
|---|---|
| `static-http1` | Static file serving over HTTP/1.1 (hits `/health`) |
| `proxy-http1` | Reverse proxy route over HTTP/1.1 |
| `proxy-http2` | Reverse proxy route over HTTP/2 (requires `h2load`) |
| `keepalive` | Keep-alive connection reuse |
| `reload-under-load` | SIGHUP sent mid-run; measures degradation during reload |

### k6-only behavioral scenarios

These verify correctness under load, not just raw throughput. They require `--tool k6`.

| Scenario | Script | What it tests |
|---|---|---|
| `auth-enforcement` | `scenarios/auth-enforcement.js` | Unauthenticated requests get 401; authenticated get 2xx — under concurrent load |
| `rate-limit` | `scenarios/rate-limit.js` | Firing requests faster than `TARDIGRADE_RATE_LIMIT_RPS` produces 429s |
| `spike` | `scenarios/spike.js` | Sudden surge to peak VUs; checks error rate <5% and p99 <1 s |

Run a subset: `--scenarios static-http1,keepalive`

Run only k6 behavioral tests: `--tool k6 --scenarios auth-enforcement,rate-limit,spike`

## k6 scenario environment variables

| Variable | Default | Description |
|---|---|---|
| `AUTH_TOKEN` | _(empty)_ | Bearer token for the `auth-enforcement` authenticated path |
| `AUTH_PROTECTED_PATH` | `/v1/status` | Path that requires auth in `auth-enforcement` |
| `RATE_LIMIT_RPS` | `10` | Configured RPS ceiling; should match `TARDIGRADE_RATE_LIMIT_RPS` |
| `RATE_LIMIT_PATH` | `/health` | Path to hammer in `rate-limit` |
| `SPIKE_PEAK` | `150` | Peak VU count in `spike` |

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

## Generating a report

`report.sh` reads the JSON produced by `--save` and emits a markdown table:

```bash
# Print to stdout
./benchmarks/report.sh benchmarks/baselines/v0.61.json

# Update the README performance table in-place (between the marker comments)
./benchmarks/report.sh benchmarks/baselines/v0.61.json --update-readme README.md
```

The table includes req/s, p50, p99, error count, tool, version tag, and capture date.
To refresh the table after a release, re-run the benchmark with `--save` and then
re-run `report.sh --update-readme`.

## Baseline files

Baseline JSON files live under `benchmarks/baselines/`. File names should be the
git tag of the Tardigrade release that produced them, e.g. `v0.61.json`. These
files are checked into the repository so regressions can be caught in CI.

```
benchmarks/baselines/
└── v0.61.json     # baseline captured on the v0.61 release
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

For behavioral correctness in CI, add a k6-only step:

```yaml
- name: k6 behavioral checks
  run: |
    ./benchmarks/run.sh \
      --tool k6 \
      --duration 15 \
      --connections 20 \
      --scenarios auth-enforcement,rate-limit
```
