# Tardigrade Benchmarks

Repeatable benchmark and regression harness for Tardigrade.

## Default Policy

Run benchmarks on a dedicated, isolated benchmark target by default.

- Canonical benchmark, regression, and release-baseline runs belong on a stable
  benchmark target, not a shared laptop or CI runner.
- Run the load driver on the same host as Tardigrade against `127.0.0.1` for
  published numbers (eliminates network noise).
- Only run benchmarks on a local laptop when explicitly requested or when a
  dedicated target is unavailable.
- Treat any laptop-local run as fallback data, not as the canonical performance
  result.

## Quick start

```bash
# Capture a release baseline JSON + markdown report
./benchmarks/release-baseline.sh \
  --meta-file benchmarks/targets/release-baseline.json \
  --update-readme README.md \
  -- \
  --host 127.0.0.1 \
  --pid-file /run/tardigrade/tardigrade.pid \
  --proxy-path /proxy/health

# Fallback only: local/shared-runner smoke test
# Use this only when explicitly requested or when a dedicated target is unavailable.
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
- Process metadata: driver label, worker count, config label, process-sampling configuration, and any extra JSON merged via `--meta-file`.

Each scenario entry in the JSON now records:

- `rps`
- `p50_ms`, `p95_ms`, `p99_ms`, and `p999_ms`
- `errors`
- `throughput_mbps` when the selected driver exposes it
- `cpu_pct_avg` and `rss_mb_peak` when the run used `--pid` or `--pid-file`

Use the committed metadata files for common contexts:

- `benchmarks/targets/release-baseline.json`
- `benchmarks/targets/ci-smoke.json`

## Allocation regression benchmark

`zig build bench-allocations` runs an in-process hot-path allocation harness and
prints JSON with `allocations_per_request` and `bytes_allocated_per_request` for
each measured scenario. The same budgets are enforced by `zig build test`, so
allocator regressions fail with the scenario name and the exceeded threshold.

This harness does not replace canonical throughput benchmarks. It avoids live
network timing noise and measures allocator calls around deterministic runtime
helpers that are easy to regress during refactors.

Current debug budgets:

| Scenario | Allocation budget/request | Byte budget/request | Rationale |
|---|---:|---:|---|
| `static-tiny-file-warm` | 14 | 1024 | File-backed warm static responses allocate normalized path metadata, ETag, and Last-Modified strings; file bytes stay out of heap. |
| `static-304-conditional` | 14 | 1024 | Conditional static hits follow the same path and validator allocation shape, but avoid response-body bytes. |
| `proxy-keepalive-warm` | 6 | 512 | Warm proxy keep-alive helper work owns resolved target strings while forwarded header assembly stays stack-backed. |
| `rejected-overload` | 12 | 1024 | This intentionally allocating path builds a structured JSON error and response header copies before closing the request. |

Large streamed proxy-response allocation checks belong with live throughput and
RSS benchmarks because they exercise socket backpressure rather than isolated
helper allocation counts. Use the streaming scenarios below with PID sampling
to compare RSS, p99, throughput, buffered bytes, and CPU.

## Scenarios

### Throughput scenarios (all tools)

These measure raw request throughput and run with whichever tool is auto-detected.

| Scenario | Description | Skip condition |
|---|---|---|
| `static-http1` | Static file serving over HTTP/1.1 | — |
| `proxy-http1` | Reverse proxy route over HTTP/1.1 | — |
| `proxy-payload-64k` | Reverse proxy 64 KiB payload transfer | — |
| `proxy-payload-256k` | Reverse proxy 256 KiB payload transfer | — |
| `proxy-payload-1m` | Reverse proxy 1 MiB payload transfer | Requires benchmark target route and upstream fixture payload |
| `proxy-payload-16m` | Reverse proxy 16 MiB payload transfer | Requires streaming mode for bounded RSS on default proxy caps |
| `proxy-upload-large` | Reverse proxy 1 MiB fixed-length upload | Requires `k6`; use `TARDIGRADE_PROXY_STREAMING_MODE=full` for upload streaming |
| `proxy-slow-client-download` | Reverse proxy download through rate-limited clients | Requires `curl`; use PID sampling to compare bounded RSS |
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
--pid PID             Target Tardigrade process ID for CPU/RSS sampling
--pid-file FILE       File containing the target Tardigrade PID for CPU/RSS sampling
--tls                 Use HTTPS
--insecure            Skip TLS certificate verification
--duration SECS       Seconds per scenario (default: 30)
--connections N       Concurrent connections (default: 50)
--threads N           wrk worker threads (default: 4)
--static-path PATH    Path for static-http1 and reload-under-load (default: /health)
--proxy-path PATH     Path for proxy-http1/proxy-http2 (default: /proxy/health)
--keepalive-path PATH Path for keepalive (default: /health)
--proxy-payload-64k-path PATH  Path for proxy-payload-64k (default: /proxy/payload-64k.bin)
--proxy-payload-256k-path PATH Path for proxy-payload-256k (default: /proxy/payload-256k.bin)
--proxy-payload-1m-path PATH   Path for proxy-payload-1m (default: /proxy/payload-1m.bin)
--proxy-payload-16m-path PATH  Path for proxy-payload-16m (default: /proxy/payload-16m.bin)
--proxy-upload-path PATH       Path for proxy-upload-large (default: /proxy/upload-large)
--proxy-slow-client-path PATH  Path for proxy-slow-client-download (default: /proxy/payload-16m.bin)
--slow-client-limit-rate RATE  curl --limit-rate value for slow clients (default: 1M)
--slow-client-connections N    Concurrent slow clients (default: 4)
--h2-path PATH        Path for static-http2 (default: same as --static-path)
--h3-path PATH        Path for static-http3 (default: same as --static-path)
--scenarios LIST      Comma-separated scenario names
--tool TOOL           Force tool: wrk|h2load|fortio|k6
--baseline FILE       Compare against a baseline JSON file
--save FILE           Write results JSON to a file
--meta-file FILE      Merge extra JSON metadata into _meta
--threshold PCT       Regression threshold percentage (default: 10)
--sample-interval-ms N  CPU/RSS sample interval in milliseconds (default: 500)
--runs N              Repeat each scenario N times; report mean ± stddev (default: 1)
--idle-check          Abort if load average exceeds 0.7× CPU count before starting
```

Exit code `2` indicates at least one scenario regressed beyond the threshold.
Throughput regressions trigger when req/s drops beyond the threshold; latency,
CPU, and RSS regressions trigger when those metrics grow beyond the threshold.

## Path and host overrides

Two things commonly invalidate a run if you miss them:

- `proxy-http1` and `proxy-http2` are only meaningful when `--proxy-path` points at a real proxied upstream route.
- If the target config uses `server_name`, send a matching `Host` header with `--host-header` or benchmark via the named hostname instead of by raw IP.
- For pure throughput/RSS proxy benchmarks, run the target with `TARDIGRADE_RATE_LIMIT_RPS=0`; otherwise the default limiter becomes the bottleneck and 429 responses pollute the results.
- Streaming proxy benchmarks should run with `TARDIGRADE_PROXY_STREAMING_MODE=response` for download cases and `full` for fixed-length upload cases. Keep `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=1` for streaming runs.

Examples:

```bash
# Named vhost target
./benchmarks/run.sh \
  --host benchmark-target.example.test \
  --host-header benchmark-target \
  --static-path /health \
  --proxy-path /proxy/health

# HTTP/2 proxy route over TLS
./benchmarks/run.sh \
  --host edge.example.test \
  --port 443 \
  --tls \
  --tool h2load \
  --proxy-path /proxy/health

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

## Generating a report

`report.sh` reads the JSON produced by `--save` and emits a markdown table:

```bash
# Print to stdout
./benchmarks/report.sh benchmarks/baselines/v0.61.json

# Update the README performance table in-place (between the marker comments)
./benchmarks/report.sh benchmarks/baselines/v0.61.json --update-readme README.md
```

The table includes req/s, p50, p95, p99, p999, error count, throughput, and
sampled CPU/RSS columns when process sampling is enabled. Older baselines remain
readable; missing columns render as `-`.
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

The canonical benchmark target is the **Beelink Mini PC** (4-core Debian LXC).
Use `benchmarks/targets/beelink.json` with `--meta-file` for release baselines.
See that file for hardware details and recommended flags.

## Homelab benchmark workflow (Beelink)

The Beelink is not directly SSH-accessible from the Mac. All commands run through the Blink MCP server. The recommended flow produces a release baseline in ~15 minutes with two tool calls and a wait.

**Prerequisites (already done as of v0.4.5):**
- `h2load` (`nghttp2-client 1.64.0`) is installed. `wrk` is present but **not compiled with TLS** — it cannot target the HTTPS-only port 8443.
- `jq` is installed.
- `blink.toml` has `benchmark` and `benchmark-collect` tagged test blocks. Because `blink.toml` is gitignored, these must be re-added each session. See `BLINK.md § Running benchmarks` for the exact TOML snippet.

**Workflow:**

```
# 1. Deploy the release (skip if already running)
blink_deploy service=tardigrade task=true

# 2. Dispatch benchmark — returns task_id immediately; benchmark runs in background (~10 min)
blink_test service=tardigrade tags=["benchmark"] task=true

# 3. Poll until task is done (or schedule a wakeup and check blink_history after ~12 min)
blink_task_status task_id=<id>

# 4. Collect — test "fails" with JSON = run complete; "passes" with "not-ready" = still running
blink_test service=tardigrade tags=["benchmark-collect"]
```

**Saving the baseline:** copy the JSON from the `message` field in the collect result to `benchmarks/baselines/<tag>.json`. The `_meta.tag` will read `"unknown"` (no `.git` in the extracted dir) — correct it to the release tag before committing.

**Known Beelink-specific quirks:**

- `h2load` connects to self-signed certs without `--insecure` (no flag needed or accepted).
- `p99_ms` will be `null` in all h2load baselines — h2load outputs a CDF table rather than a single p99 value; the run.sh parser does not extract it.
- The `errors` field was always the total request count in baselines before v0.4.5 (parser bug: `grep "failed"` matched the `requests:` summary line before `failed: 0`). Fixed in the same commit as this note. Expect `errors: 0` in all healthy post-fix runs.
- h2load baselines (port 8443, HTTPS) are **not comparable** to wrk baselines (port 8069, HTTP). The v0.32.0-18 and earlier baselines used wrk; use the h2load series (v0.4.5+) for trend comparisons going forward.

## Measurement reliability

A few pitfalls discovered through hard experience (#136):

1. **A dev laptop is not the deploy target.** The same binary measured ~42µs p50
   on an M4 laptop vs ~120µs on the 4-core Beelink. Faster cores flatter every
   number. Always capture canonical numbers on deployment-class hardware.

2. **Load contamination produces phantom results.** On a shared machine, the same
   endpoint measured 38k–195k req/s — a 5× swing — from co-scheduled work alone.
   A periodic `top`/`ps` sampler collapsed throughput ~5× by itself. Use
   `--idle-check` to gate on an idle machine, and `--runs 3` (or more) to expose
   variance. If `rps_stddev > 10% of rps_mean`, treat the run as contaminated.

3. **Report p90/p99/p999, not just p50.** Worker starvation and flow-control
   failures show in the tail; p50 stays flat while p90 climbs 100×.

4. **macOS ≠ Linux for scheduling.** `nice` is ignored on macOS (QoS-based
   scheduling). Priority and scheduler experiments must be validated on Linux.

5. **"req/s" is meaningless without fixed hardware + concurrency.** Record both
   in `_meta`; the `--runs` stddev is the only guard against phantom improvements.

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

## Streaming proxy benchmarks

Issue #139 added explicit scenarios for the streaming reverse-proxy data path.
Use a benchmark config with the fixture upstream routes:

- `/proxy/payload-1m.bin` -> upstream `/payload-1m.bin`
- `/proxy/payload-16m.bin` -> upstream `/payload-16m.bin`
- `/proxy/upload-large` -> upstream `/upload-large`
- `/proxy/payload-16m.bin` for `proxy-slow-client-download`, with `curl`
  enforcing the downstream read rate

Run downloads with process sampling:

```bash
./benchmarks/run.sh \
  --host 127.0.0.1 \
  --pid-file /run/tardigrade/tardigrade.pid \
  --scenarios proxy-http1,proxy-payload-1m,proxy-payload-16m \
  --proxy-path /proxy/health
```

Run the slow-client download benchmark with rate-limited clients:

```bash
./benchmarks/run.sh \
  --host 127.0.0.1 \
  --pid-file /run/tardigrade/tardigrade.pid \
  --scenarios proxy-slow-client-download \
  --slow-client-connections 4 \
  --slow-client-limit-rate 1M
```

Run the fixed-length upload scenario with k6:

```bash
./benchmarks/run.sh \
  --tool k6 \
  --host 127.0.0.1 \
  --pid-file /run/tardigrade/tardigrade.pid \
  --scenarios proxy-upload-large
```

Compare `rps`, `p99_ms`, `throughput_mbps`, `rss_mb_peak`, `cpu_pct_avg`, and
the proxy metrics from `/status/metrics`: `tardigrade_proxy_streaming_requests_total`,
`tardigrade_proxy_buffered_requests_total`, `tardigrade_proxy_buffered_bytes_current`,
`tardigrade_proxy_buffered_bytes_total`, `tardigrade_proxy_client_aborts_total`,
`tardigrade_proxy_upstream_aborts_total`, and `tardigrade_proxy_ttfb_ms_*`.

If `h2load` is not available or was not built with QUIC support, the HTTP/2 and HTTP/3
scenarios each print a clear skip message and the runner continues without error.
