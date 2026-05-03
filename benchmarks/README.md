# Tardigrade Benchmarks

Repeatable benchmark and regression harness for Tardigrade.

## Quick start

```bash
# Start a local Tardigrade instance (adjust env as needed)
TARDIGRADE_LISTEN_PORT=8069 ./zig-out/bin/tardigrade &

# Run the default scenario set.
# For honest proxy numbers, point --proxy-path at a real proxied route.
./benchmarks/run.sh --proxy-path /proxy/health

# Save a baseline for the current release
./benchmarks/run.sh --proxy-path /proxy/health --save benchmarks/baselines/$(git describe --tags).json

# Compare a future run against that baseline
./benchmarks/run.sh --proxy-path /proxy/health --baseline benchmarks/baselines/<tag>.json

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
| `proxy-http1` | Reverse proxy route over HTTP/1.1 (default path: `/proxy/health`) |
| `proxy-http2` | Reverse proxy route over HTTP/2 (requires `h2load`, default path: `/proxy/health`) |
| `keepalive` | Keep-alive connection reuse (default path: `/health`) |
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
--host-header NAME    Override the HTTP Host header / :authority
--tls                 Use HTTPS
--insecure            Skip TLS certificate verification
--duration SECS       Seconds per scenario (default: 30)
--connections N       Concurrent connections (default: 50)
--threads N           wrk worker threads (default: 4)
--static-path PATH    Path for static-http1 and reload-under-load (default: /health)
--proxy-path PATH     Path for proxy-http1/proxy-http2 (default: /proxy/health)
--keepalive-path PATH Path for keepalive (default: /health)
--scenarios LIST      Comma-separated scenario names
--tool TOOL           Force tool: wrk|h2load|fortio|k6
--baseline FILE       Compare against a baseline JSON file
--save FILE           Write results JSON to a file
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

### Run from this laptop

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

### Run from inside the container (loopback — most accurate for proxy overhead)

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

### Run from the Jetson (external load driver — preferred for regression tracking)

The Jetson Orin Nano (`ssh jetson`) is a separate LAN machine with `wrk` built at
`~/tools/wrk/wrk`. Using it as the driver avoids contaminating latency numbers with
shared CPU/RAM/scheduler from the same Proxmox host as the target.

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
- Record the exact benchmark paths and Host header used, not just the IP/port

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
