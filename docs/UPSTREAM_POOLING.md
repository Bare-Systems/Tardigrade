# Upstream connection pooling (#141)

Status: **Phases 1–3 implemented** (plain-HTTP, TLS, control-plane, FastCGI, and
the streaming path all pool on the manual transport). **Phase 4a** (#147 —
cross-worker reuse analysis + local/cross-worker metrics + benchmark) landed;
see "Cross-worker sharing" below. Later phases tracked in issue #141.

## Why

`std.http.Client` kept upstream connections alive internally but did not expose
the socket fd, so the per-phase upstream timeouts from #196 (`SO_*TIMEO` / `poll`)
could not be enforced. #196 replaced it with a manual transport that owns the
socket — but the first cut sent `Connection: close`, opening a fresh TCP
connection per proxied request. Under load that churn overflows the upstream's
accept backlog (observed as `error.ConnectionFailed` on ~4–5% of requests in the
perf smoke). This module restores connection reuse on top of the manual
transport, so we keep both timeout enforcement **and** keepalive.

## Scope

In scope (Phases 1 / 1b / 1c / 2 / 3):
- Reuse **HTTP/1.1 TCP** upstream connections — **plain HTTP** (Phase 1) and
  **TLS** (Phase 1c) — on the data-plane buffered path (default proxy mode,
  `TARDIGRADE_PROXY_STREAMING_MODE=off`) and the **control-plane** path.
- Reuse upstream connections on the **streaming** proxy path (Phase 3,
  `TARDIGRADE_PROXY_STREAMING_MODE=response|full`), which now uses the same
  manual bounded transport + pool as the buffered path instead of
  `std.http.Client`. The upstream head and body are parsed/relayed with a
  framing-aware streaming reader (Content-Length / chunked / bodiless /
  close-delimited), re-chunked downstream with bounded buffering
  (`TARDIGRADE_PROXY_STREAM_BUFFER_SIZE`, min 16 KiB). Per-phase `poll(2)`
  timeouts are enforced here too, closing the last #196 timeout gap. With this
  `std.http.Client` is retired from the data plane.
- Reuse **FastCGI** connections through the same pool (Phase 2), keyed under a
  `fastcgi:` prefix. The pool stores a `compat.NetStream`, so it holds both the
  data-plane's raw-fd connections and FastCGI's connections uniformly.
- For TLS the pooled entry owns the OpenSSL connection, so the handshake is
  amortized across requests; the key is scheme-prefixed (`http:`/`https:`).
- Per-origin idle pool with idle-timeout, max-lifetime, and max-idle-per-host
  caps; idle reaper on the maintenance tick.
- Safe stale-connection handling: a pooled connection the origin closed while
  idle is retried once on a fresh connection (the request was never delivered).
- Global + per-upstream labelled metrics and a connect-latency histogram
  (Phase 1b).

Deferred (tracked on #141):
- A hard `_MAX_ACTIVE_PER_HOST` cap — `active` is a tracked gauge, but
  enforcement is backpressure that couples with #140.
- SCGI / uWSGI pooling — these are one-request-per-connection protocols (the
  server closes after each response), so they are *not* pooled (Phase 2 did fix
  their transport to raw blocking sockets, so they no longer stall, but each
  request still opens a fresh connection).
- Stale-connection retry on the streaming path is best-effort: a dead pooled
  connection is retried once on a fresh one, but only before any downstream
  byte is written and only for requests without a streaming request body (a
  partially-relayed response cannot be safely replayed).
- Cross-worker connection stealing/sharing (Phase 4 / #147).
- HTTP/2 upstream multiplexing (#145).

## Ownership & concurrency

**Decision: a single shared, mutex-guarded pool** owned by `GatewayState`
(`upstream_pool: UpstreamPool`), mirroring the existing `fastcgi_pool`.

Rationale: the gateway uses a thread-per-connection bounded worker pool, so any
upstream pool is touched by all worker threads. A single mutex around a
`StringHashMap(host → LIFO idle list)` is the simplest correct design and
maximizes reuse under uneven traffic (any worker can reuse any idle connection).

Alternatives considered:
- **Per-worker pools** — no lock, but lower reuse with skewed traffic and more
  idle sockets held open. Reconsider only if the single mutex shows contention
  in Beelink benchmarks (it is taken twice per proxied request: acquire +
  release, both O(1)).
- **Sharded-by-key pools** — a middle ground; revisit if/when contention is
  measured. The map key is the natural shard key.

Cross-worker *sharing/stealing* (Pingora-style) is a deliberate future
extension; the single shared map already gives cross-worker reuse, so stealing
is only about fairness/locality, not correctness.

## Cross-worker sharing (#147)

#147 asks whether idle upstream connections are fragmented across workers (the
Pingora/HAProxy motivation) and to compare local-only, shared-global, sharded,
and stealing designs. The answer for Tardigrade depends on its **hybrid worker
model**:

- **Threads within a process** share one `GatewayState`, hence one
  `UpstreamPool`. A connection parked by thread A is immediately acquirable by
  thread B. This is the **shared global pool** design — no per-worker
  fragmentation.
- **Worker processes** (`TARDIGRADE_MASTER_PROCESS=true` with
  `worker_processes > 1`) each have their own `GatewayState` and therefore their
  own pool. Across *processes* the pool is not shared.

The **default deployment is single-process, multi-threaded**
(`worker_processes = 1`, `worker_threads = 0` → auto = CPU count,
`master_process = false`), so in the common case the pool is already globally
shared and #147's fragmentation problem does not arise.

### Design comparison

| Design | Reuse under skew | Lock cost | Fragmentation | Status in Tardigrade |
|---|---|---|---|---|
| Local-only (per-worker) | Poor — idle sockets trapped per worker | None | High | Rejected |
| **Shared global (one mutex)** | **Best** — any worker reuses any idle conn | One mutex, 2× O(1) per request | None (intra-process) | **Implemented (default)** |
| Sharded shared (mutex per key-shard) | Best | Lower cross-origin contention | None | Documented extension (below) |
| Stealing (thread-local + steal on miss) | Best | Lowest steady-state, complex | None | Not needed (no thread-local tier) |

Because there is no thread-local tier, there is nothing to "steal" — every reuse
already comes from the shared map. We *measure* whether a reuse crossed workers
by stamping each parked connection with the releasing thread id
(`PooledConn.released_by`) and comparing it on `acquire`:
`reused_local_total` vs `reused_cross_worker_total`.

### Measured behaviour

`benchmarks/cross-worker.sh` drives uneven proxy traffic through an N-thread
gateway and scrapes the split. Representative local run (6 worker threads, hot
route, loopback Python upstream):

- **6 upstream connections** opened, **~338k reuses**, reuse ratio **99%**;
- **~48% of reuses were cross-worker** (a connection one thread parked, another
  reclaimed).

This confirms the shared pool reuses idle connections across workers and keeps
the connection count at ~one per active worker rather than multiplying it.
Throughput was flat from 4→8 threads (upstream-bound, not lock-bound), so the
single mutex is **not** a contention bottleneck at this scale — its critical
sections are O(1) (LIFO pop/push + counter bumps).

### Sharded-shared extension (deferred)

If a future Beelink/high-core benchmark shows the single mutex limiting
throughput (flat scaling with idle CPU and high `sys` time on the lock), shard
the pool into `N` stripes, each `{ mutex, StringHashMap }`, mapping
`shard = hash(key) % N`. An origin always lands in one shard, so **all workers
still share that origin's idle connections** — sharding only removes contention
*between* different origins, preserving cross-worker reuse. `aggregateStats`,
`snapshotHosts`, and `reapIdle` would fan out over shards. We do not implement
this now: it is speculative complexity unsupported by measurement.

### Cross-process sharing (deferred, harder)

Sharing idle connections across worker *processes* cannot use a pointer/mutex —
it needs SCM_RIGHTS fd-passing to a broker (a dedicated connection-cache process
or a shared-memory ring with fd transfer). That is a substantial subsystem with
real correctness risk (cross-process socket ownership, lifecycle, shutdown).
Given the default is single-process multi-threaded — where sharing already works
— cross-process sharing is explicitly deferred until multi-process deployments
become common enough to justify it. Per-process pools remain correct (each just
keeps its own keep-alive connections); they are merely less connection-efficient
than a single process with the same total thread count.

## Keying

Key: `"<scheme>:<host>:<port>"` (e.g. `http:127.0.0.1:8080`, `https:api:443`).
The scheme prefix keeps plain and TLS connections to the same origin distinct.
TLS config is global (`cfg.upstream_tls_*`), so all TLS connections to one
origin share config; if per-route TLS config is ever added the key should gain
a TLS/SNI fingerprint (the key is built in one place so that extension is
local).

## Connection lifecycle

```
acquire(key):
  pop an idle PooledConn (LIFO — warmest first)
  drop it if it has aged past idle_timeout_ms or max_lifetime_ms (and keep going)
  → reused connection, or null

(no idle conn) → connectBlockingTcp(host, port)   [counts as "new"]

exchange (keepalive): send the request without Connection: close, read the
  response framed by Content-Length/chunked (never read-until-EOF for a pooled
  conn), and decide reusability:
    reusable  ⇔ HTTP/1.1 AND no `Connection: close` in the response
                AND body was length/chunked/bodiless (definitively framed)
                AND no trailing bytes (socket left in sync)

release(key, conn):  if reusable and under max_idle_per_host and not aged →
  return to the idle list (stamp last_used_ms); else close().

stale retry: if a *reused* connection yields zero response bytes (origin closed
  the idle socket), the request was never delivered → close and retry once on a
  fresh connection, for any method (idempotent by construction).
```

Idle eviction runs in the existing maintenance tick (alongside the parked
downstream-keepalive reaper): connections past `idle_timeout_ms` or
`max_lifetime_ms` are closed. All idle connections are closed on shutdown.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `TARDIGRADE_UPSTREAM_POOL_ENABLED` | `true` | Master switch; `false` reverts to per-request `Connection: close`. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST` | `32` | Max idle connections cached per origin. |
| `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | `90000` | Idle connection is evicted after this long unused. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS` | `0` (unlimited) | Hard cap on total connection age. |

## Metrics

Global (Phase 1):
- `tardigrade_upstream_connections_new_total`
- `tardigrade_upstream_connections_reused_total`
- `tardigrade_upstream_connections_reused_local_total` (Phase 4a / #147 — reuses reclaimed by the parking worker)
- `tardigrade_upstream_connections_reused_cross_worker_total` (Phase 4a / #147 — reuses reclaimed by a different worker)
- `tardigrade_upstream_connections_idle` (gauge)
- `tardigrade_upstream_stale_retries_total`

Per-upstream labelled (`{upstream="host:port"}`, Phase 1b):
- `tardigrade_upstream_pool_connections_new_total`
- `tardigrade_upstream_pool_connections_reused_total`
- `tardigrade_upstream_pool_connections_reused_local_total` (#147)
- `tardigrade_upstream_pool_connections_reused_cross_worker_total` (#147)
- `tardigrade_upstream_pool_connections_idle` (gauge)
- `tardigrade_upstream_pool_connections_active` (gauge — connections checked out)
- `tardigrade_upstream_pool_stale_retries_total`
- `tardigrade_upstream_pool_reuse_ratio` (gauge — `reused / (reused + new)`)

Connect-latency histogram (Phase 1b): `tardigrade_upstream_connect_latency_ms`
(`_bucket`/`_sum`/`_count`).

Still deferred: a hard `_MAX_ACTIVE_PER_HOST` cap (the `active` gauge is
tracked, but enforcement needs backpressure semantics that couple with #140).

## Testing

- Unit: reuse across requests, idle-timeout/lifetime eviction, stale-conn retry,
  reusability decision (Content-Length/chunked vs `Connection: close`/close).
- Local load: `wrk` against `/proxy/health` through the python keep-alive
  fixture must show **zero** upstream `ConnectionFailed` (the regression) and the
  reused-connection counter dominating new connections.
- Reuse-ratio numbers under the canonical workload are captured on the Beelink
  per `benchmarks/README.md` (not in CI).
