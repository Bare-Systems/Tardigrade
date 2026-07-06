# Concurrency, Shared State, and Cache-Locality Audit

This document audits every mutex, atomic, shared queue, and cache-locality concern
in the request handling hot path. It was produced as part of issue #214 and is
intended to be a living reference: update the classification and justification
column whenever a lock's role changes.

---

## Execution model summary

Tardigrade uses a **blocking I/O, thread-per-request** model:

- One event-loop thread accepts connections and dispatches fds to a bounded worker pool.
- Each worker thread owns its request for the full synchronous lifecycle (TLS handshake
  → HTTP parse → proxy/serve → response write).
- Idle keepalive connections are removed from the worker pool and parked in an
  event-monitored registry; workers are only occupied during active request work.

The hot path for a single request therefore runs entirely on one worker thread —
no async hand-offs, no continuation queues. Shared state is only touched at
well-defined call sites (accept, route, upstream select, metrics emit, response).

## I/O abstraction boundary

Tardigrade uses two I/O layers deliberately. The layer is chosen by ownership of
the fd and by whether the code is on the data-plane socket path, not by local
convenience.

### High-level / compatibility I/O

Config parsing, config generation, static-file metadata, cache files, session
and transcript stores, CLI file operations, subprocess spawning, clocks, random
bytes, stdout/stderr writers, and other common utilities should go through
`src/zig_compat.zig` or the `std.Io` APIs it wraps.

`zig_compat.zig` is the compatibility boundary for the pinned Zig compiler. It
absorbs `std.Io` churn and owns the few low-level escape hatches needed to keep
the rest of the codebase small:

- `compat.cwd()`, `compat.openFileAbsolute`, and `compat.createFileAbsolute`
  wrap directory and file operations.
- `compat.NetStream`, `compat.netStreamFromFd`, and the bounded connect helpers
  keep the gateway's socket-facing transport shape stable.
- `compat.Mutex`, `compat.Condition`, clocks, sleeps, env lookup, and writer
  helpers keep high-level modules off raw OS APIs.

New config, static-file, CLI, cache, session, transcript, ACME, and utility code
should not call `std.posix`, `std.c`, or `std.os` directly unless it is adding a
compatibility helper here first.

Known low-level exceptions outside the socket/protocol modules are intentional:
`logger.zig` and `access_log.zig` may use raw stderr writes for last-resort
logging, `access_log.zig` may own its syslog UDP socket, and
`gateway_static_runtime.zig` may own the zero-copy `sendfile` / `socketpair`
path described below.

### Low-level socket / fd I/O

Listener, gateway socket, proxy transport, HTTP/2 transport, FastCGI-style
protocol transport, and HTTP/3/UDP code own raw fds and may use `std.posix` /
`std.c` directly for socket semantics that `std.Io` does not expose stably in
Zig 0.16. This includes:

- `accept`, `poll`, non-blocking toggles, `SO_*TIMEO`, `SO_REUSEADDR`,
  `TCP_NODELAY`, `shutdown`, peer address extraction, and fd close behavior.
- Bounded blocking upstream sockets where timeout behavior depends on
  `SO_RCVTIMEO`, `SO_SNDTIMEO`, and `poll(2)`.
- UDP datagram send/receive and address metadata for the current C-backed
  HTTP/3 path and the future QUIC endpoint abstraction.

The target API layer for gateway/listener/socket code is therefore raw fd
ownership wrapped at protocol boundaries, not ad hoc high-level file/config
helpers. Socket-specific helpers belong in `gateway_connection.zig`,
`gateway_accept.zig`, `gateway_proxy.zig`, the h2 transport, the HTTP/3/UDP
runtime, or `zig_compat.zig` when multiple protocols need the same behavior.

### Static-file fast path

Static-file selection, normalization, metadata, range calculation, and fallback
body reads remain high-level `compat` / `std.Io` work. The plain HTTP file-backed
send path is the intentional exception: `gateway_static_runtime.zig` may use
Linux `sendfile(2)` behind an OS gate and falls back to a portable read/write
loop elsewhere. TLS and compressed responses do not use that zero-copy path.

### Follow-up work

The remaining implementation work is already tracked:

| Area | Issue |
|---|---|
| Shared h1/h2/h3 stream transport boundary | #241 |
| Pure Zig QUIC and C-backend replacement boundary | #242 |
| UDP endpoint and QUIC config model | #248 |
| Pure Zig QUIC / HTTP/3 foundation epic | #240 |

Do not start an `io_uring` or async-runtime rewrite from this boundary. Any new
backend must be benchmark-justified and fit behind the same socket/protocol
ownership rules.

## Pure Zig QUIC / H3 Embedding Target

Pure Zig QUIC/H3 work starts upstream-first. Tardigrade should validate QUIC
transport, stream flow control, QPACK, and proxy retry semantics as an upstream
client before exposing a public downstream HTTP/3 UDP listener. A public listener
adds Alt-Svc rollout, reload behavior, UDP routing, NAT rebinding at the edge,
and load-balancer concerns that are tracked separately.

The target module seams are:

| Seam | Responsibility |
|---|---|
| `src/quic/udp.zig` | HTTP-independent UDP endpoint: send/receive datagrams, local/remote address metadata, ECN, socket buffer tuning, deterministic clock hook, and future batching/GSO/pacing extension points |
| `src/quic/config.zig` | Internal config defaults, validation, and QUIC transport-parameter mapping |
| `src/quic/packet.*` / `connection.*` / `stream.*` | QUIC packet codec, connection state, packet number spaces, DCID routing, timers, loss recovery, stream flow control, close/drain |
| `src/quic/tls_adapter.*` | QUIC TLS 1.3 handshake bytes, transport parameters, traffic secrets, AEAD/header protection, ALPN, certificate state, and key updates |
| `src/http3/` | HTTP/3 frames, control streams, SETTINGS, QPACK, and request/response mapping |
| `src/http/stream_transport.zig` | Gateway-facing h1/h2/h3 stream/proxy contract |

Incoming UDP packets are routed by parsed Destination Connection ID (DCID) to a
connection bucket before HTTP/3 request logic runs. That routing layer owns QUIC
connection/worker ownership; HTTP and gateway request types must not leak into
`src/quic/udp.zig`.

The initial config model is intentionally conservative and defaults off. Only
safe rollout toggles should become operator-facing early; internal transport
defaults can remain private until interop, benchmark, or production evidence says
they need public control.

| Config area | Transport mapping | Default | Exposure |
|---|---|---|---|
| Enable pure Zig QUIC/H3 | none | off | user-facing when implementation exists |
| QUIC version set | version negotiation | QUIC v1, v2-aware but disabled | internal initially |
| Idle timeout | `max_idle_timeout` | 30s | likely user-facing with upstream H3 |
| Active CID limit | `active_connection_id_limit` | 4 | internal initially |
| Max UDP payload | `max_udp_payload_size` | 1200 bytes | user-facing only if MTU tuning is needed |
| Initial connection window | `initial_max_data` | 8 MiB | internal initially |
| Initial stream windows | `initial_max_stream_data_*` | 1 MiB bidi, 256 KiB uni | internal initially |
| Max streams | `initial_max_streams_*` | 100 bidi, 16 uni | internal initially |
| Retry policy | address validation / tokens | off for upstream-first | user-facing for downstream listener work |
| Migration policy | `disable_active_migration` | disabled | user-facing only when downstream listener exists |
| qlog / keylog | debug artifact emission | off | local-debug toggle |
| QPACK | SETTINGS | static-only, zero dynamic capacity | internal until dynamic QPACK lands |

Allocator ownership is per connection. A QUIC connection owns packet/frame/stream
scratch allocations and releases them on close/drain; stream buffers must not be
owned by HTTP request objects. Deterministic timer/clock hooks belong below HTTP
so RTT, PTO, loss recovery, and pacing tests can run without wall-clock sleeps.

---

## Lock inventory

### 1. Worker-pool mutex (`WorkerPool.mutex`) — **WARM path**

| Property | Value |
|---|---|
| Location | `src/http/worker_pool.zig` |
| Protects | `worker_queues`, `active_jobs`, `queued_jobs`, `shutting_down` |
| Taken by | Event-loop thread on `submit`; each worker on loop entry and exit |
| Frequency | Once per connection (submit) + twice per request (before/after handler) |
| Critical section | Short: enqueue one fd, update counter, signal condition variable |

**Justification:** Necessary for the work-stealing dispatch model. The critical
section is O(1) (enqueue + counter update). There is no per-request path through
this lock during active request handling — the worker drops the mutex before
calling the handler and re-acquires only after `handler()` returns.

**Potential improvement (filed as future work):** Per-worker queues already exist
(work-stealing). Replacing the single global mutex with per-worker mutexes would
eliminate submit contention between workers. The condition variable would need to
become per-worker (or remain shared). Only worthwhile if profiling shows submit
queue contention at the target concurrency level.

---

### 2. Metrics mutex (`GatewayState.metrics_mutex`) — **HOT path**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig`, `src/http/metrics.zig` |
| Protects | `GatewayState.metrics` (all counters) |
| Taken by | Every request, on every completed response |
| Frequency | Once per request (in `metricsRecord`); plus latency, error-code updates |
| Critical section | Counter increment(s) on a plain struct of `u64` fields |

**Justification:** Needed because all workers share one `Metrics` struct and Zig
`u64` is not atomically updated on all targets. The critical section is extremely
short (a few field increments with no allocations or I/O).

**Potential improvement:** Replace `u64` fields with `std.atomic.Value(u64)` and
eliminate the mutex entirely. The `Metrics` struct comment says "atomically for
thread-safety readiness" but the struct fields are plain `u64`s guarded by the
external mutex — the readiness is not yet realised. Alternatively, accumulate
deltas in per-worker shadow counters and merge them lazily on the metrics-read
path (the read path already takes the mutex, so merging there is safe and keeps
the hot path lock-free). **This is the highest-priority hot-path lock to remove.**

---

### 3. Config-store mutex (`ReloadableConfigStore.mutex`) — **WARM path**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig` |
| Protects | `current` config version pointer + `retired` list |
| Taken by | Every request at handler entry (`ctx.acquireConfig()`) and exit (`release()`) |
| Frequency | Twice per request |
| Critical section | Ref-count increment/decrement on `ManagedConfigVersion.ref_count` |

**Justification:** Needed to implement a safe RCU-style hot-reload: the event-loop
thread can swap in a new config version while workers hold leases on the old one.
The critical section is a single integer increment; it completes in nanoseconds.

**Potential improvement:** `ref_count` could become a `std.atomic.Value(usize)`,
reducing `acquire`/`release` to a single atomic instruction with no mutex. The
`current` pointer swap during reload requires sequentially-consistent store/load
(or a mutex for the swap itself), but `ref_count` accounting does not. Low
priority: the current lock hold time is already negligible.

---

### 4. Connection-slot mutex (`GatewayState.connection_mutex`) — **COLD/WARM path**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig` |
| Protects | `active_connections_total`, `active_connections_by_ip`, `active_fds`, `fd_to_ip`, `fastcgi_pool`, `mux_subscriptions_by_device` |
| Taken by | Accept-time slot acquisition; connection teardown |
| Frequency | Once per connection (not per request on keepalive) |
| Critical section | HashMap insert/remove + counter update |

**Justification:** HashMap operations are not thread-safe; the mutex is correct.
Per-IP accounting (`active_connections_by_ip`) requires a string-keyed HashMap
which cannot be made lock-free without significant redesign. This lock is warm,
not hot: keepalive connections pay it once at accept and once at close, not once
per request.

---

### 5. Rate-limiter mutex (`GatewayState.rate_limiter_mutex`) — **HOT path (when enabled)**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig`, `src/http/rate_limiter.zig` |
| Protects | `RateLimiter` (token bucket HashMap + last-cleanup timestamp) |
| Taken by | Every request, early in the request handler |
| Frequency | Once per request when rate limiting is enabled |
| Critical section | HashMap lookup + float arithmetic + optional HashMap insert |

**Justification:** The token-bucket HashMap is not thread-safe; the mutex is
necessary. The critical section includes a `std.StringHashMap` lookup which can
allocate (on new descriptor). For deployments with global rate limiting (`/`),
every request contends here.

**Potential improvement:** Shard the token-bucket map by a hash of the descriptor
key, with one mutex per shard. This reduces contention N-fold with N shards.
Alternatively, if per-IP limiting is the common case, maintain per-worker IP
counters and synchronize only on the slow path (first request from an IP, or
periodic flush). Filed as a design candidate — do not implement before benchmarking.

---

### 6. Upstream-selection mutex (`GatewayState.upstream_mutex`) — **HOT path (proxy mode)**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig` |
| Protects | `upstream_rr_index`, `upstream_backup_rr_index`, `lb_random_state`, `upstream_health`, `upstream_active_requests` |
| Taken by | Every proxied request (upstream URL selection) |
| Frequency | Once per request in proxy mode |
| Critical section | Round-robin index read/write + health map lookup + active-request counter update |

**Justification:** The LB state fields (`upstream_rr_index`, `lb_random_state`)
are mutable and shared; the health map is a `StringHashMap` which is not
thread-safe. Correctness requires the mutex.

**Potential improvement:** `upstream_rr_index` could be replaced with
`std.atomic.Value(usize)` using a CAS loop for atomic round-robin, eliminating
the mutex for the common case. Health lookups (`upstream_health`) would still need
the mutex, but health state changes infrequently (only on probe results), so a
separate read/write-lock or seqlock would greatly reduce hot-path contention.
**Second-highest priority after metrics.**

---

### 7. Circuit-breaker mutex (`GatewayState.circuit_mutex`) — **HOT path (when enabled)**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig`, `src/http/circuit_breaker.zig` |
| Protects | `circuit_breaker` state (state machine + failure counters) |
| Taken by | Every request (check) and every upstream response (record) |
| Frequency | 1–2× per proxied request when enabled |
| Critical section | State machine read + conditional transition + counter update |

**Justification:** The circuit-breaker state machine is a shared mutable struct
with non-trivial transition logic. The mutex ensures atomicity of the
check-and-transition. Short critical section.

**Potential improvement:** The open/closed/half-open state could be an atomic
`u8` with CAS-based transition logic. Failure counters could be relaxed atomics.
This would make the check path fully lock-free. Low priority until the circuit
breaker is exercised under sustained load.

---

### 8. Access-log mutex (`access_log.State.mutex`) — **HOT path**

| Property | Value |
|---|---|
| Location | `src/http/access_log.zig` |
| Protects | Global `State.buffer` and `State.line_scratch` |
| Taken by | Every request, at response completion |
| Frequency | Once per request (when access logging is enabled) |
| Critical section | String format + append to buffer; flush when buffer full |

**Justification:** The global `State` is a singleton initialized once; the buffer
must be thread-safe. Without buffering (`buffer_size_bytes == 0`) the critical
section also includes a `write()` syscall to stderr — the most expensive case.

**Potential improvement:** With buffering enabled, the critical section is a
memory copy and a length comparison — low contention. Without buffering, the
`write()` syscall inside the lock is a contention bottleneck: N workers
serialize through a single `write` call. The fix is to format the line under the
lock into a stack buffer, then drop the lock and call `write()` unlocked. Filed
as a design candidate.

---

### 9. Buffer-pool and session-pool mutexes — **WARM path**

| Property | Value |
|---|---|
| Location | `src/http/buffer_pool.zig`, `src/gateway_state.zig` (`ConnectionSessionPool`) |
| Protects | Free-list arrays |
| Taken by | Connection accept and teardown (not per-request on keepalive) |
| Frequency | Once per connection lifecycle |
| Critical section | Array pop/push |

**Justification:** Unavoidable for thread-safe free-list access. The critical
section is O(1) and allocation-free after warm-up. Keepalive connections reuse
their session and buffer across requests, so this lock is not on the per-request
hot path.

---

### 10. Feature-store mutexes (`idempotency_mutex`, `session_mutex`, `proxy_cache_mutex`) — **WARM path (when enabled)**

| Property | Value |
|---|---|
| Location | `src/gateway_state.zig` |
| Protects | `idempotency_store`, `session_store`, `proxy_cache_store` (HashMap-backed) |
| Taken by | Requests that trigger their feature (idempotency key, session cookie, cacheable response) |
| Frequency | 1–2× per feature-enabled request |
| Critical section | HashMap get/put + optional duplication of cached bytes |

**Justification:** Correct. These features are opt-in and only affect requests
that use them. No improvement needed before profiling shows they are hot.

---

### 11. Approval / command / transcript / runtime / reload mutexes — **COLD path**

These mutexes guard BearClaw-specific lifecycle features (command dispatch,
approval flows, transcript recording, runtime config rebinding, reload status).
They are not on the request hot path for standard HTTP traffic.

---

## Atomic operations

| Symbol | Location | Notes |
|---|---|---|
| `in_flight_requests` | `gateway_state.zig` | `fetchAdd`/`fetchSub` with `.acq_rel`; lock-free request-slot accounting. Correct and hot-path safe. |
| `health_probe_running` | `gateway_state.zig` | `bool` flag guarding the one-at-a-time health-probe constraint. Correct. |
| `shutdown_requested` / `reload_requested` / `upgrade_requested` / `reopen_logs_requested` | `http/shutdown.zig` | Signal-handler-safe `seq_cst` atomics. Correct; read on every event-loop tick, not per-request. |
| `dropped_lines` | `http/access_log.zig` | Monotonic counter for dropped log lines. Correct. |

All atomics are correctly classified as lock-free; no improvement needed.

---

## Cache-locality observations

### `GatewayState` struct layout

`GatewayState` is a large struct (~2 KB+ on 64-bit) with 12 mutexes, 14+
HashMaps, and numerous scalar fields. Workers hold a pointer to it; they do not
copy it. Cache lines shared between fields that are co-accessed are:

- **Hot together, different mutexes:** `metrics_mutex` + `metrics` (adjacent in
  declaration order ✓); `rate_limiter_mutex` + `rate_limiter` (adjacent ✓);
  `upstream_mutex` + `upstream_rr_index` + `lb_random_state` (adjacent ✓).
  The pairing of each mutex with its guarded field in a single cache line is
  good — acquiring the lock and reading the field may require only one cache-line
  fetch.

- **False-sharing risk:** All 12 mutexes are declared consecutively at the top of
  the struct. A mutex for an unrelated feature (e.g., `session_mutex`) shares a
  cache line with the hot `metrics_mutex`. When a worker updates metrics, it
  loads and potentially invalidates the cache line that also holds session,
  idempotency, and circuit mutexes — even if those paths are cold. Separating
  hot mutexes (metrics, rate-limiter, upstream) into a `__attribute__((aligned(64)))`
  sub-struct or adding `align(std.atomic.cache_line)` padding would avoid this.

### `Metrics` struct layout

The `Metrics` struct contains ~40 `u64` counters. On a 64-byte cache line,
8 `u64`s fit. `recordRequest` (called on every response) updates
`total_requests`, `status_2xx/3xx/4xx/5xx`, and sometimes `err_*` counters —
these span at least 2–3 cache lines. Under high concurrency this causes cache-line
contention even with a mutex: the writer must dirty and reload multiple lines per
update. Grouping the most-frequently-updated counters (`total_requests`,
status_2xx/5xx, latency buckets) into the first 8 fields and aligning the struct
to a cache line would reduce cache traffic.

### `WorkerPool` — per-worker queues, shared mutex

The per-worker `WorkerQueue` struct contains a `std.Deque(fd_t)`. All queues are
in a contiguous `[]WorkerQueue` slice, so consecutive workers' queues share cache
lines. Under work-stealing, a worker reading its own queue may cause a cache-line
write that invalidates a neighboring worker's read. Padding each `WorkerQueue` to
a cache-line boundary (64 bytes) would isolate per-worker state.

### `ConnectionSession`

Small struct (pending buffer pointer + 3 scalars + 64-byte IP buf = ~88 bytes
on 64-bit). Single-owner after acquire; no sharing until release. No
cache-locality concern.

---

## Prioritized follow-up items

The following improvements are ordered by expected impact at Tardigrade's target
workload (high-throughput reverse proxy, many concurrent keepalive clients). None
should be implemented until a benchmark baseline is in place.

| Priority | Item | Expected impact |
|---|---|---|
| 1 | Replace `Metrics` plain-`u64` fields with `std.atomic.Value(u64)` and remove `metrics_mutex` | Eliminates a mutex taken on every request; reduces latency variance |
| 2 | Atomic round-robin for `upstream_rr_index` (CAS loop) to reduce `upstream_mutex` critical section | Reduces LB-selection contention in high-concurrency proxy mode |
| 3 | Move access-log `write()` syscall outside the lock (format inside, write outside) | Prevents N workers from serializing through a single `write()` in unbuffered mode |
| 4 | Shard the rate-limiter token-bucket HashMap (N shards, N mutexes) | N-fold contention reduction when rate-limiting is enabled |
| 5 | Add cache-line padding to `WorkerQueue` entries | Reduces false-sharing between workers during work-stealing |
| 6 | Separate hot mutexes (metrics, rate-limiter, upstream) from cold ones with alignment padding in `GatewayState` | Reduces cache invalidation between unrelated features |
| 7 | Atomic ref-count for `ReloadableConfigStore` (remove mutex from acquire/release) | Minor; current hold time is already negligible |

---

## How to measure

Before acting on any item above, establish a baseline with:

```bash
./benchmarks/run.sh --scenarios static-http1,proxy-http1,keepalive --save benchmarks/baselines/pre-lock-opt.json
```

Profile with `perf record -g ./zig-out/bin/tardigrade ...` and inspect
`perf report` for lock-related symbols (`__lll_lock_wait`, `futex_wait`, mutex
spin). Each improvement should show a measurable reduction in the benchmark
before being merged.
