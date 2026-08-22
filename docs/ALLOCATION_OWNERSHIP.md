# Hot-Path Allocation Ownership

Issue #143 reconciles allocation ownership for the general HTTP and reverse-proxy
runtime. The allocation counter harness from issue #155 remains the source of
deterministic hot-path allocation budgets; this note records what owns each
meaningful allocation class, when it may be released, and why the current
measurements do not justify a broad request arena.

## Measured Scenarios

`zig build bench-allocations` on `main` before this audit reported:

| Scenario | Allocations/request | Bytes/request | Peak live bytes |
| --- | ---: | ---: | ---: |
| `static-tiny-file-warm` | 13.00 | 779.00 | 311 |
| `static-304-conditional` | 13.00 | 779.00 | 311 |
| `proxy-keepalive-warm` | 6.00 | 410.00 | 239 |
| `rejected-overload` | 12.00 | 716.00 | 407 |

The audit adds two deterministic harness rows:

- `proxy-header-heavy-response` routes allocation-capable production parsing
  through the counting allocator, then serializes the filtered response through
  caller-owned output. This makes the arena-owned response metadata observable
  instead of relying on an allocator-free serializer alone.
- `mixed-route-selection` covers request-metadata-heavy location matching over
  process/config-owned route blocks. It returns borrowed route slices, but regex
  locations require request-owned scratch. This audit makes that Zig scratch
  allocator-aware and budgeted; POSIX `regcomp` may still allocate through libc
  outside the Zig allocator interface.

The after run reported:

| Scenario | Allocations/request | Bytes/request | Peak live bytes |
| --- | ---: | ---: | ---: |
| `static-tiny-file-warm` | 13.00 | 779.00 | 311 |
| `static-304-conditional` | 13.00 | 779.00 | 311 |
| `proxy-keepalive-warm` | 6.00 | 410.00 | 239 |
| `proxy-header-heavy-response` | 4.00 | 1742.00 | 1742 |
| `mixed-route-selection` | 8.00 | 356.00 | 146 |
| `rejected-overload` | 12.00 | 716.00 | 407 |

For the newly added audit rows, `proxy-header-heavy-response` is comparable to
base when the helper is applied there because it exercises existing buffered
proxy response parsing. `mixed-route-selection` exposed a non-comparable base
instrumentation gap: before this fix, regex matching used
`std.heap.page_allocator`, so the harness could not observe Zig regex scratch at
all. The head row above is the first allocator-visible budget for that route
class; it records the now request-allocator-owned Zig scratch while still
documenting the external libc `regcomp` boundary.

No reusable workspace or pool was introduced, so there is no workspace
high-water mark, fallback count, or retained capacity contract to report.

## Live Evidence

Base and head release binaries were built from `main` and this branch and run on
the same local macOS loopback host with PID sampling. These are local fallback
rows, not canonical release-baseline numbers; they are included to record the
latency/CPU/RSS shape for the ownership audit.

CI-smoke command shape:

```bash
benchmarks/ci-smoke.sh --duration 5 --connections 4 --threads 1 --save <file>
```

| Scenario | Build | req/s | p99 ms | p999 ms | CPU % | Peak RSS MiB | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `static-http1` | base | 38147.35 | 0.284 | 3.228 | 285.11 | 4.94 | 0 |
| `static-http1` | head | 42345.02 | 0.242 | 3.068 | 303.79 | 4.91 | 0 |
| `proxy-http1` | base | 15011.66 | 0.934 | 2.823 | 116.20 | 5.27 | 0 |
| `proxy-http1` | head | 15423.09 | 0.782 | 2.535 | 120.00 | 5.20 | 0 |
| `keepalive` | base | 42553.87 | 0.230 | 3.143 | 302.97 | 5.28 | 0 |
| `keepalive` | head | 39439.34 | 0.233 | 1.872 | 293.77 | 5.20 | 0 |

Large streaming proxy server config:

```nginx
pid /tmp/issue143-<build>/tardi.pid;
listen <port>;
metrics_path /status/metrics;

location = /health {
    return 200 ok;
}

location /proxy/ {
    proxy_pass http://127.0.0.1:<upstream-port>;
    proxy_streaming response;
}
```

Large streaming proxy launch and benchmark shape:

```bash
TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0 \
TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=1 \
./zig-out/bin/tardi run -c /tmp/issue143-<build>/tardigrade.conf &
pid=$!

benchmarks/run.sh --duration 5 --connections 2 --threads 1 \
  --proxy-payload-1m-path /proxy/payload-1m.bin \
  --proxy-slow-client-path /proxy/payload-16m.bin \
  --slow-client-connections 2 \
  --slow-client-limit-rate 2M \
  --scenarios proxy-payload-1m,proxy-slow-client-download \
  --pid "$pid"
```

| Scenario | Build | req/s | p99 ms | p999 ms | CPU % | Peak RSS MiB | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `proxy-payload-1m` | base | 3263.47 | 0.865 | 3.292 | 472341.51 | 5.89 | 2 |
| `proxy-payload-1m` | head | 3265.22 | 0.853 | 2.997 | 395236.62 | 6.14 | 2 |

The 1 MiB row exercises the response-streaming proxy path with PID/RSS
sampling. A single-request metric check against the same config produced
`tardigrade_proxy_streaming_requests_total 1`,
`tardigrade_proxy_buffered_requests_total 0`, and all
`tardigrade_proxy_streaming_fallback_total{reason=...}` counters at `0` for
both base and head, confirming the configured route selected the streaming path.
On this local fallback run, the benchmark driver reported two errors in both
base and head, and the very short 5s macOS CPU sample produced unusable CPU
percentages. The comparable p99/p999, throughput, and RSS rows are still
recorded because they show no branch-specific ownership regression. The
`proxy-slow-client-download` row was attempted with the same config, but the
driver reported only `errors=2` with null latency/CPU/RSS for both builds, so it
is not used as quantitative evidence.

## Ownership Inventory

| Allocation class | Owner | Release/reset boundary | Reuse decision |
| --- | --- | --- | --- |
| Static normalized path, resolved path, cache validators | Request-owned | `StaticServed.deinit` after file response selection/serialization has completed | Direct allocation is retained. Slices are exposed through `StaticServed`, and the current 13 allocations/779 bytes per request stay under the checked budget without a safe common arena boundary for file-backed response metadata. |
| Static file bytes | Request-owned only for buffered static responses; file-backed warm path is OS/file owned | Buffered bodies are freed by `StaticServed.deinit`; file-backed responses close the file after write completion | No broad pooling. The warm tiny-file benchmark keeps file bytes out of heap by requiring `prefer_file_backed`. |
| Proxy target URL and optional query string | Request-owned | Freed before proxy dispatch helper completion, or by the request path before retry/keepalive state is released | Direct allocation is retained. These strings may be needed across retry/error handling for a single request but must not be retained by upstream connection pools. |
| Forwarded request header vector | Worker/request scratch | `stackFallback` storage is released when header assembly returns; heap fallback is freed by `ArrayList.deinit` | Existing bounded stack fallback is the right reuse mechanism. The warm proxy scenario confirms forwarded headers remain stack-backed. |
| Proxy trusted-identity derived header values | Request-owned | Freed with the request's owned header value list after upstream dispatch completes | Direct allocation is retained because values include per-request timestamp/signature material and cannot be shared with connection-owned pools. |
| Mixed route selection and server/location matching | Process/config-owned metadata plus request-owned regex scratch | Matching returns before dispatch; matched route slices remain tied to the config snapshot, while regex pattern/input scratch is freed before match return | Direct request-allocator scratch is retained for regex routes. The `mixed-route-selection` harness row records 8 allocations/356 bytes per request for the representative exact, prefix-priority, regex, and prefix sequence. POSIX `regcomp` remains an external libc allocation boundary; precompiled config-owned regexes are a future targeted optimization if regex-heavy routing becomes material. |
| Buffered proxy response body | Request-owned, with aggregate proxy-buffer accounting | Released after downstream write completion, abort cleanup, or local capacity failure handling | Existing accounting and streaming fallback rules are the safety mechanism. Reusing this memory in a request arena would risk hiding retained bytes from proxy buffer limits. |
| HTTP/1 streaming relay buffer and response-head arena | Request/proxy-attempt-owned | Released when `streamProxyOverTransport` returns after body relay, abort cleanup, or local capacity failure handling | A request workspace must not reset at response-head generation because the relay buffer and parsed head arena live through the full streaming attempt. They may reset after the attempt completes. |
| HTTP/2 stream receive queues and connection backpressure state | Stream/connection-owned | Queue drain, stream close/reset, connection close, or pool teardown | Never point these structures into request-reset memory. They can outlive a request-local header-generation phase and are independently accounted. |
| Upstream connection pool entries | Connection-owned | Pool eviction, stale retry cleanup, or gateway shutdown | Not a request workspace candidate. Idle keepalive connections intentionally outlive individual requests. |
| Overload/error JSON and response headers | Request-owned | Freed after the rejection response is written and the request is closed | Direct allocation is acceptable because this is not a success hot path and produces structured operator/client errors. |
| Security header config, route config, add-header config, Alt-Svc | Process/config-owned | Config snapshot replacement or shutdown | Not reset by requests. Runtime response formatting borrows these immutable slices. |
| HTTP/2 stream queues, HTTP/3/QPACK state, TLS encrypted-stream buffers | Connection/stream-owned | Stream close, connection close, or protocol-specific teardown | Excluded from request arenas. These owners have independent async/backpressure lifetimes. |
| Access log, metrics, and tracing label values | Borrowed/caller-owned or process-owned | Logging/metrics calls complete after response construction but before request storage could be reused | Request memory must remain valid through logging and metrics emission. Long-lived metrics labels must come from process/config-owned constants. |

## Reset Boundary

For request-owned memory, the safe reset point is after all of the following are
complete:

- response bytes that reference the memory have been written or abandoned;
- HTTP/1 streaming proxy attempts have completed body relay/abort cleanup and
  released request-owned relay/head memory;
- H2/H3 streaming state has either taken ownership of its own buffers or has
  been torn down;
- upstream retry/error cleanup has completed;
- access logging, metrics, and tracing callbacks have consumed any borrowed
  request fields;
- the downstream keepalive connection has been parked without retaining request
  slices.

"Application response selected" is not a sufficient reset boundary. The
observable boundary is request lifecycle completion after write, cleanup, and
post-response accounting.

## Strategy

No broad request arena is introduced. The measured direct allocations are small,
already budgeted, and several classes have lifetimes that either cross the write
boundary or are owned by connection/stream state. The existing targeted
mechanisms match the actual owners:

- `stackFallback` for proxy request header scratch;
- fixed, bounded buffer pools for uniform reusable byte buffers;
- proxy buffer accounting for retained body/relay allocations;
- process/config-owned immutable slices for route/security/header policy;
- direct allocations for rare rejection/error payloads and small request-local
  strings.

The benchmark additions in `src/allocation_regression.zig` make header-heavy
proxy response metadata ownership and mixed route selection explicit. Any future
workspace or pool should be added only when a measured scenario shows material
allocator churn and the owner has a single reset boundary.
