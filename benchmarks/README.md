# Tardigrade Benchmarks

Repeatable benchmark and regression harness for Tardigrade.

## Default Policy

Run benchmarks on the dedicated homelab perf target by default.

- Canonical benchmark, regression, and release-baseline runs belong on
  `tardigrade-perf`.
- Run the load driver inside `tardigrade-perf` against `127.0.0.1` for
  published numbers.
- Only run benchmarks on the local laptop when explicitly requested or when the
  homelab target is unavailable.
- Treat any laptop-local run as fallback data, not as the canonical performance
  result.

## Quick start

```bash
# Capture a release baseline JSON + markdown report
./benchmarks/release-baseline.sh \
  --meta-file benchmarks/targets/release-baseline.json \
  --update-readme README.md \
  -- \
  --host 192.168.86.55 \
  --host-header tardigrade-perf \
  --proxy-path /proxy/health

# Fallback only: local/shared-runner smoke test
# Use this only when explicitly requested or when the homelab target is unavailable.
./benchmarks/ci-smoke.sh
```

## Prerequisites

Install at least one load-generation tool. The runner auto-detects in this order:

| Tool | Install | Supports |
|---|---|---|
| [`wrk`](https://github.com/wg/wrk) | `brew install wrk` / apt | HTTP/1.1 |
| [`h2load`](https://nghttp2.org/) | `brew install nghttp2` / apt | HTTP/1.1 + HTTP/2; HTTP/3 if built with nghttp3+ngtcp2 |
| [`fortio`](https://fortio.org/) | `brew install fortio` / apt | HTTP/1.1, JSON output |
| [`k6`](https://k6.io/) | `brew install k6` / apt | HTTP/1.1 + HTTP/2 (over TLS) + behavioral scenarios |

`jq` is required for result formatting, baseline comparison, and report generation.

## Release baseline process

The release benchmark flow is now codified in-repo:

1. Capture the benchmark with `./benchmarks/release-baseline.sh`.
2. Save the JSON under `benchmarks/baselines/<tag>.json`.
3. Compare against the previous release baseline JSON.
4. Emit a markdown report next to the JSON.
5. Refresh the README benchmark block from that saved baseline.

`release-baseline.sh` is a thin wrapper over `run.sh` and `report.sh`. It exists
to keep the release flow consistent rather than to add a second benchmark engine.

## Metadata

Saved benchmark JSON now carries two categories of metadata:

- Auto-detected driver metadata: Zig version, OS, kernel, architecture, CPU model, CPU thread count, and memory.
- Process metadata: driver label, worker count, config label, and any extra JSON merged via `--meta-file`.

Use the committed metadata files for common contexts:

- `benchmarks/targets/release-baseline.json`
- `benchmarks/targets/ci-smoke.json`

## Scenarios

### Throughput scenarios (all tools)

These measure raw request throughput and run with whichever tool is auto-detected.

| Scenario | Description | Skip condition |
|---|---|---|
| `static-http1` | Static file serving over HTTP/1.1 | — |
| `proxy-http1` | Reverse proxy route over HTTP/1.1 | — |
| `static-http2` | Static file serving over HTTP/2 | Skipped unless tool is `h2load` or `k6` + `--tls` |
| `proxy-http2` | Reverse proxy route over HTTP/2 | Skipped unless tool is `h2load` |
| `static-http3` | Static file serving over HTTP/3 (QUIC) | Skipped unless `h2load` with `--h3` support **and** `--tls` |
| `proxy-http3` | Reverse proxy route over HTTP/3 (QUIC) | Skipped unless `h2load` with `--h3` support **and** `--tls` |
| `keepalive` | Keep-alive connection reuse | — |
| `reload-under-load` | SIGHUP sent mid-run; measures degradation during reload | Requires `wrk` and a PID file |

HTTP/3 scenarios require `h2load` built with QUIC support (`nghttp3` + `ngtcp2`). The runner
detects this at runtime by checking whether `h2load --h3` is recognized; if not, the scenario
prints a skip message and continues. HTTP/3 also requires TLS because QUIC mandates it —
always pass `--tls` (and `--insecure` for self-signed certs) for HTTP/3 runs.

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
--host-header NAME    Override the HTTP Host header / :authority
--driver LABEL        Load-driver label recorded in metadata
--worker-count N      Tardigrade worker count recorded in metadata
--config-label STR    Config/profile label recorded in metadata
--tls                 Use HTTPS
--insecure            Skip TLS certificate verification
--duration SECS       Seconds per scenario (default: 30)
--connections N       Concurrent connections (default: 50)
--threads N           wrk worker threads (default: 4)
--static-path PATH    Path for static-http1 and reload-under-load (default: /health)
--proxy-path PATH     Path for proxy-http1/proxy-http2 (default: /proxy/health)
--keepalive-path PATH Path for keepalive (default: /health)
--h2-path PATH        Path for static-http2 (default: same as --static-path)
--h3-path PATH        Path for static-http3 (default: same as --static-path)
--scenarios LIST      Comma-separated scenario names
--tool TOOL           Force tool: wrk|h2load|fortio|k6
--baseline FILE       Compare against a baseline JSON file
--save FILE           Write results JSON to a file
--meta-file FILE      Merge extra JSON metadata into _meta
--threshold PCT       Regression threshold percentage (default: 10)
```

Exit code 2 indicates at least one scenario regressed beyond the threshold.

## Path and host overrides

Two things commonly invalidate a run if you miss them:

- `proxy-http1` and `proxy-http2` are only meaningful when `--proxy-path` points at a real proxied upstream route.
- If the target config uses `server_name`, send a matching `Host` header with `--host-header` or benchmark via the named hostname instead of by raw IP.

Examples:

```bash
# Named vhost on a remote IP
./benchmarks/run.sh \
  --host 192.168.86.55 \
  --host-header tardigrade-perf \
  --static-path /health \
  --proxy-path /proxy/health

# HTTP/2 proxy route over TLS
./benchmarks/run.sh \
  --host edge.example.test \
  --port 443 \
  --tls \
  --tool h2load \
  --proxy-path /bearclaw/health

# HTTP/2 and HTTP/3 static + proxy over TLS (h2load with QUIC support required for HTTP/3)
./benchmarks/run.sh \
  --host edge.example.test \
  --port 443 \
  --tls \
  --insecure \
  --tool h2load \
  --scenarios static-http2,proxy-http2,static-http3,proxy-http3 \
  --static-path /health \
  --proxy-path /proxy/health
```

## Remote perf target

The current homelab perf target lives on the Proxmox node reachable as `ssh proxmox`.

Current staged shape:

- Proxmox node: `beelink`
- LXC guest: `102 (tardigrade-perf)`
- Guest IP: `192.168.86.55`
- Tardigrade service: `tardigrade-perf.service`
- Stub upstream service: `tardigrade-upstream.service`
- Benchmark routes:
  - `/health` → direct edge return
  - `/proxy/health` → proxied loopback upstream
  - `/proxy/payload-64k.bin` → proxied 64 KiB payload

### Official release baseline environment

The canonical release target is the `tardigrade-perf` guest:

- Proxmox node: `beelink`
- Guest: `LXC 102`
- Guest name: `tardigrade-perf`
- Default worker count: `2`
- Canonical load driver: `wrk` running inside the guest against `127.0.0.1`
- Fallback external path: Jetson or laptop only when you explicitly need that network measurement

Use guest-local loopback runs for canonical performance because they remove
Wi-Fi and LAN noise entirely. Use Jetson or laptop runs only when you
specifically want to measure an external network path.

### Verify the staged target

```bash
ssh proxmox 'pct list'
ssh proxmox 'pct exec 102 -- systemctl status --no-pager tardigrade-perf tardigrade-upstream'
curl -i http://192.168.86.55:8069/health
curl -i http://192.168.86.55:8069/proxy/health
```

### Rebuild the staged target

```bash
ssh proxmox 'pct exec 102 -- bash -lc "
  cd /opt/tardigrade-src &&
  git pull &&
  /opt/zig/zig build -Doptimize=ReleaseFast &&
  systemctl restart tardigrade-perf &&
  systemctl --no-pager --lines=20 status tardigrade-perf
"'
```

### Fallback: run from this laptop only when explicitly requested or when the homelab target is unavailable

```bash
./benchmarks/run.sh \
  --host 192.168.86.55 \
  --port 8069 \
  --tool k6 \
  --duration 30 \
  --connections 50 \
  --static-path /health \
  --proxy-path /proxy/health \
  --keepalive-path /health \
  --save benchmarks/baselines/$(date +%Y%m%d)-homelab.json
```

If the perf guest is switched to a config that declares `server_name tardigrade-perf;`, add `--host-header tardigrade-perf` to every benchmark command.
This laptop path is fallback-only and should not replace the normal homelab run policy.

### Canonical run: inside the container (loopback)

Running `wrk` inside the perf LXC against `127.0.0.1` eliminates all network RTT.
This is the only setup that reveals Tardigrade's actual per-request processing cost.

```bash
ssh proxmox 'pct exec 102 -- bash -c "
  wrk -t2 -c4 -d30s -L http://127.0.0.1:8069/health
  wrk -t2 -c4 -d30s -L http://127.0.0.1:8069/proxy/health
"'
```

Keep connections at or near the worker count (`workers=2` by default on a 2-core LXC)
to avoid queue-saturation inflating p99. The p50 is the honest latency signal.

### Optional: run from the Jetson only when you explicitly want a network-path measurement

The Jetson Orin Nano (`ssh jetson`) is a separate LAN machine with `wrk` built at
`~/tools/wrk/wrk`. This path includes real network effects and is not the
canonical release-baseline path.

Use `benchmarks/jetson-run.sh` — it SSHes to the Jetson for each `wrk` invocation
and parses/saves results locally in the same JSON format as `run.sh`:

```bash
./benchmarks/jetson-run.sh \
  --host 192.168.86.55 \
  --port 8069 \
  --duration 30 \
  --connections 50 \
  --save benchmarks/results/$(date +%Y-%m-%d)/jetson-wrk.json
```

To compare against a previous run:

```bash
./benchmarks/jetson-run.sh \
  --host 192.168.86.55 \
  --port 8069 \
  --duration 30 \
  --connections 50 \
  --baseline benchmarks/results/2026-05-02/jetson-wrk.json \
  --save benchmarks/results/$(date +%Y-%m-%d)/jetson-wrk.json
```

`jetson-run.sh` supports: `static-http1`, `proxy-http1`, `keepalive`. For HTTP/2,
behavioral (k6), or reload-under-load scenarios, use `run.sh` directly.

## Generating a report

`report.sh` reads the JSON produced by `--save` and emits a markdown table:

```bash
# Print to stdout
./benchmarks/report.sh benchmarks/baselines/v0.61.json

# Update the README performance table in-place (between the marker comments)
./benchmarks/report.sh benchmarks/baselines/v0.61.json --update-readme README.md
```

The table includes req/s, p50, p99, error count, tool, version tag, capture date,
driver label, environment label, worker count, and config label.
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
- Record the exact benchmark paths and Host header used, not just the IP/port

Document the test host in each baseline file's `_meta.host` field and merge the
appropriate benchmark-context JSON with `--meta-file`.

## CI integration

The repository also runs a shared-runner smoke test in CI with `30s` per
scenario by default:

```bash
./benchmarks/ci-smoke.sh --save benchmarks/results/ci-smoke.json
```

The smoke run intentionally uses low concurrency, loopback traffic, and generous
minimum req/s floors so only obvious regressions fail the job. It exists as an
automation backstop, not as the default operator benchmark path.

For behavioral correctness in CI, add a k6-only step:

```yaml
- name: k6 behavioral checks
  run: |
    ./benchmarks/run.sh \
      --tool k6 \
      --duration 30 \
      --connections 20 \
      --scenarios auth-enforcement,rate-limit
```

HTTP/2 and HTTP/3 protocol benchmarks are intended for manual regression runs on a
dedicated perf target, not short CI smoke tests. `static-http2`, `proxy-http2`,
`static-http3`, and `proxy-http3` are omitted from the default `--scenarios` list for
this reason. Add them explicitly when running a full protocol comparison:

```bash
./benchmarks/run.sh \
  --tool h2load \
  --tls --insecure \
  --duration 30 \
  --scenarios static-http1,proxy-http1,static-http2,proxy-http2,static-http3,proxy-http3
```

If `h2load` is not available or was not built with QUIC support, the HTTP/2 and HTTP/3
scenarios each print a clear skip message and the runner continues without error.
