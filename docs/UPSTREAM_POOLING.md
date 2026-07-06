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
- Reuse **Unix-socket HTTP** upstream connections (Phase 1d / #239), keyed
  under a `unix:<path>` prefix, on the buffered data-plane and control-plane
  paths. Unix connects are cheap (no handshake, no TIME_WAIT pressure), but
  keep-alive still spares the origin per-request accept/fd churn and brings
  unix upstreams under the same idle/lifetime/active-cap policy and metrics
  as TCP.
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

## HTTP/2 upstream multiplexing (#145, Phase 4b)

HTTP/1.1 pooling above is *one exclusive request per pooled connection*. HTTP/2
instead multiplexes *many concurrent streams over one* origin connection. Because
Tardigrade uses a thread-per-connection blocking model, this needs a different
structure from the h1 pool:

- **`upstream_h2.H2Conn`** — a per-connection actor. A dedicated **reader
  thread** owns every socket read and all HPACK decoding (the HPACK dynamic
  table is connection-wide, so there is exactly one decoder and it needs no
  lock). Worker threads call the blocking `request()`, which allocates a stream
  id, writes HEADERS/DATA under a **write mutex**, and waits on a **per-stream**
  condition variable until the reader marks the stream done or errored.
  - Locking: `write_mutex` serializes socket writes; `state_mutex` (+ conditions)
    guards the streams map, flow-control windows, and connection flags. The two
    are never held simultaneously (update state, release, then write), so there
    is no lock-ordering deadlock. A completing stream is detached from the map
    under the lock before its buffers are moved out, so the reader cannot race
    the hand-off.
  - Per-stream (not broadcast) signaling is essential: an early single-broadcast
    design woke every waiter on every frame (a thundering herd) and collapsed
    throughput under concurrency; per-stream conditions restored it (~25× in a
    32-client benchmark).
- **`upstream_h2.H2ConnPool`** — one connection per origin (keyed `h2:host:port`),
  refcounted so an evicted/dead connection survives until its last in-flight
  request drains. A connection-level failure evicts and retries once.
- Enabled via `TARDIGRADE_UPSTREAM_PROTOCOL=h2|auto` for HTTPS upstreams,
  offered through ALPN; origins that select `http/1.1` fall back to the
  HTTP/1.1 path. `TARDIGRADE_UPSTREAM_PROTOCOL=h2c` (#237) additionally speaks
  **prior-knowledge cleartext h2c** to plain-HTTP upstreams — see below.
- The h2 upstream socket sets **`TCP_NODELAY`**: multiplexing issues many small
  frame writes (HEADERS / WINDOW_UPDATE) whose interaction with the peer's
  delayed ACK otherwise stalls each exchange ~40 ms and trips response timeouts
  under concurrency (measured 24 → 5.4k req/s on loopback once disabled).

### Reset / GOAWAY metrics (Phase 4b PR 3; per-origin since #238)

RST_STREAM and GOAWAY are counted in **persistent per-origin counters**, not per
live connection: each `H2Conn` reader holds pointers to its origin's
`H2OriginCounters` atomics (passed to `H2Conn.init`) and bumps them when it
sees the frame — still *before* publishing the state change the frame causes,
so an observer that sees the state also sees the incremented counter. Both
count **frames received** (protocol-level) — a reset counts even when it
arrives late, for a stream that already completed and left the streams map.
The counter entries outlive connections (created on first h2 connection to an
origin, never removed while the pool lives) because a per-connection count
would be lost when an evicted connection is torn down; cardinality is bounded
by the number of distinct configured origins, like the h1 pool's per-host
stats.

Surfaced two ways:

- **Global (backward-compatible)**: `tardigrade_upstream_h2_stream_resets_total`
  and `…_h2_goaway_total` — now sums over the per-origin counters (identical
  values and still monotonic, since origin entries are never removed).
- **Per-origin (#238)**: `tardigrade_upstream_h2_pool_*{upstream="h2:host:port"}`
  for `connections_active` / `streams_active` (gauges) and
  `stream_resets_total` / `goaway_total` (counters). The `_pool_` name prefix
  mirrors the labelled h1 `tardigrade_upstream_pool_*` series so a label-blind
  `sum()` over the labelled family never double-counts the bare globals; the
  label value is the pool key, matching the scheme-prefixed h1 label
  convention. An origin whose connection was evicted keeps reporting its
  counters with zeroed gauges.

### Idle / lifetime eviction (Phase 4b PR 3)

`H2ConnPool.reapIdle` runs on the gateway maintenance tick (next to
`upstream_pool.reapIdle`) and closes an h2 connection that has **no in-flight
streams** and is either idle past `idle_timeout_ms`, past `max_lifetime_ms`, or
already unhealthy (GOAWAY/errored). It mirrors the h1 reaper but is
refcount-aware:

- The `activeStreamCount() == 0` gate means an actively multiplexing connection
  is never reaped; each connection stamps `last_activity_ms` when a stream starts
  and when one finishes.
- Victims are removed from the map **under** the pool mutex (so no concurrent
  `acquire` can retain one mid-reap), but the final `release` — which may join the
  reader thread in `deinit` — runs **after** the mutex is dropped, so a teardown
  never blocks the pool. Any late request that grabbed a ref before the reap keeps
  its connection alive until it finishes (only the map ref is dropped).
- Timeouts come from the shared `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` /
  `…_MAX_LIFETIME_MS` config (the h2 pool reuses the h1 pool's knobs).

`benchmarks/h1-vs-h2-upstream.sh` drives the same concurrent load through the h1
pool and the h2 multiplexer and reports throughput, latency, and the upstream
connection count (h2 serves the whole load over one connection; h1 opens one per
busy worker).

### Streaming path over h2 (Phase 4b PR 4)

The streaming proxy path (`TARDIGRADE_PROXY_STREAMING_MODE=response|full`) now
multiplexes over the same per-origin h2 connection instead of always speaking
HTTP/1.1. `executeStreamingHttpProxyRequest` routes HTTPS targets through
`streamViaH2Pool` when `TARDIGRADE_UPSTREAM_PROTOCOL=h2|auto`; ALPN `http/1.1`
origins fall back to the h1 streaming relay on that (fresh, unpooled)
connection.

The actor gains a streaming request mode next to the fully-buffered
`request()`:

- **`requestStreaming()`** sends HEADERS(+body) and blocks until the response
  headers are decoded, then returns the stream handle; the relay reads the body
  incrementally with **`readStreamingBody()`** and must call
  **`finishStreaming()`** exactly once (which RST_STREAMs a stream the origin
  had not finished, so an abandoned/aborted relay frees the origin's stream
  slot).
- **Flow control is the crux.** For buffered streams the reader replenishes
  both the connection- and stream-level windows immediately per DATA frame
  (unbounded buffering into the stream's body, acceptable because the whole
  response is size-capped and consumed at once). For streaming streams the
  reader parks DATA in the per-stream buffer and does **not** replenish the
  stream window — only `readStreamingBody` replenishes as the relay drains
  downstream. The advertised initial stream window (1 MiB) therefore *is* the
  bounded per-stream buffer, and a slow downstream client backpressures its own
  stream: the origin stops sending once the un-replenished window is exhausted.
  A peer that overruns the advertised window is failed with
  `Http2FlowControlError` instead of buffering without bound.
- **The connection-level window is always replenished promptly** by the reader
  (and is grown to 8 MiB at connection start), so one slow stream can never
  stall the other streams sharing the connection. Measured: a 10 KB/s
  downstream client mid-transfer did not move the latency of 40 concurrent fast
  requests on the same upstream connection (~7 ms each).
- **Every worker wait is deadline-bounded** even while frames keep flowing for
  *other* streams: a waiter registers a wait deadline on its stream and the
  reader fails the stream with `Http2Timeout` if it passes without progress
  (progress extends the deadline, mirroring the h1 per-read `poll` bound); a
  fully silent connection is already bounded by the reader's frame-read
  deadline. This closes a starvation window the buffered `request()` wait had
  too — a stalled stream on a busy shared connection previously waited
  indefinitely.
- Response **trailers** are decoded (mandatory for connection-wide HPACK
  dynamic-table consistency — skipping a block would corrupt every later
  response on the connection) and then discarded, matching the h1 relay, which
  consumes and drops chunked trailers.
- Failure semantics match the h1 streaming relay: a connection-level failure
  before any downstream byte evicts the connection and retries once; after the
  response head is written downstream, an upstream failure surfaces as an
  aborted relay (truncated chunked body) and evicts the connection only if the
  connection itself died.

Streaming **uploads** (`full` mode with a request body relayed from the client)
stay on the HTTP/1.1 path: the request-body sender currently buffers the body,
and relaying a slow client upload over the shared connection needs an
incremental DATA-send API on the actor. Deferred within #145: streaming
uploads over h2.

## Protocol-agnostic stream transport target (#241)

Future HTTP/3 work should plug into the existing proxy runtime through the
shared contract in `src/http/stream_transport.zig` instead of creating a second
parallel data plane. The contract models the pieces all upstream protocols must
provide:

- request head: method, scheme, authority, path, and request headers;
- request body: none, buffered bytes, or a pull-based streaming source;
- response head before body bytes: status, headers, and protocol metadata;
- response body: pull-based drain plus explicit finish/cancel cleanup;
- transport metadata: `h1` / `h2` / `h3`, connection reuse, and optional stream
  id;
- retry boundary: safe before delivery, maybe-safe after request send but before
  downstream response bytes, and unsafe after response bytes have started
  downstream.

Current paths map to that contract without semantic loss:

| Path | Current entry point | Contract mapping |
|---|---|---|
| h1 buffered | `executeBoundedBufferedHttpProxyRequest` / `exchangeBoundedBufferedHttpRequest` | `RequestBody.buffered`, materialized `ResponseHead` + bounded body; stale pooled close maps to `before_delivery` |
| h1 streaming | `executeStreamingHttpProxyRequest` / `streamProxyOverTransport` | `RequestBody.buffered` or `RequestBody.streaming`; response head is written before pull-draining body; `wrote_downstream` maps to `response_started_downstream` |
| h2 buffered | `upstream_h2.H2Conn.request` | `RequestBody.buffered`, `ResponseHead.meta.protocol = h2`, body materialized under the configured cap |
| h2 streaming | `requestStreaming` / `readStreamingBody` / `finishStreaming` | headers-first `OpenedResponse`, pull body drain, explicit finish that RST_STREAMs abandoned streams |

Retry policy stays in `gateway_proxy_runtime.zig`; transports expose only the
delivery state needed to make the decision. A future h3 adapter should expose
the same shape with `meta.protocol = h3` and a QUIC stream id, while keeping
QUIC connection IDs, packet routing, and flow-control internals below this
boundary.

### Cleartext h2c (#237)

`TARDIGRADE_UPSTREAM_PROTOCOL=h2c` makes plain-HTTP (`http://`) upstreams speak
HTTP/2 with **prior knowledge** (RFC 9113 §3.3): the client preface goes out
immediately on the plain socket — no ALPN, and no HTTP/1.1 `Upgrade: h2c`
dance (deprecated in RFC 9113, costs an extra round trip, and no major proxy
uses it upstream). Because cleartext has no negotiation, this is a separate
explicit opt-in: an h1-only plain origin would break under it, so `h2`/`auto`
never imply it. For HTTPS upstreams `h2c` behaves exactly like `h2` (ALPN with
h1 fallback).

Implementation-wise there is one production connection type for both:
`PooledH2Conn = H2Conn(*UpstreamH2Transport)`, where `UpstreamH2Transport` is
a runtime union over the OpenSSL upstream connection and a plain socket. h2c
connections therefore share the same pool, actor, refcount lifecycle, idle
reaper, buffered/streaming paths, and metrics as TLS h2 — they appear under
`h2c:host:port` keys in the per-origin series and count as `protocol="h2"` in
the protocol/latency metrics (h2c *is* HTTP/2; the transport split is visible
via the key prefix). `Connection: close`-era caveats do not apply; the h1
`.h1` ALPN-fallback arm of `acquire` is unreachable for h2c.

### Upstream latency by protocol

`tardigrade_upstream_request_latency_ms{protocol="h1"|"h2"}` (histogram) records
every *completed* upstream exchange — from starting the exchange on an acquired
connection to the response fully received (buffered) or fully relayed
(streaming) — so h1-pool and h2-multiplexed tail latency can be compared
directly (the "upstream p99 by protocol" acceptance row on #145).

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

This is a focused Phase 4a measurement (uneven hot-route traffic + the
local/cross split), not the full benchmark matrix #147 envisages. Still
outstanding there: many-origins/low-per-origin traffic, one hot origin with many
workers, an upstream-TLS-handshake scenario, and per-request CPU / p99 TTFB /
lock-contention-overhead comparisons (ideally on Beelink hardware, not loopback).
Those are tracked as remaining #147 work, not claimed complete here.

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
| `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` | `0` (unlimited) | **Fail-fast** cap on concurrently checked-out connections per origin (#239): at the cap, requests are rejected with 503 `upstream_saturated` instead of opening more connections. See "Active-cap semantics" below. |
| `TARDIGRADE_UPSTREAM_PROTOCOL` | `http1` | Upstream application protocol: `http1`; `h2`/`auto` (offer h2 via ALPN on HTTPS upstreams, h1 fallback); `h2c` (= `h2` for HTTPS, plus prior-knowledge cleartext h2 to plain-HTTP upstreams — explicit opt-in, see the h2c section). |

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

HTTP/2 upstream (Phase 4b, #145):
- `tardigrade_upstream_protocol_requests_total{protocol="h1"|"h2"}` (PR 1)
- `tardigrade_upstream_h2_connections_active` (gauge — open multiplexing conns; PR 2)
- `tardigrade_upstream_h2_streams_active` (gauge — in-flight streams across conns; PR 2)
- `tardigrade_upstream_h2_stream_resets_total` (counter — RST_STREAM received; PR 3)
- `tardigrade_upstream_h2_goaway_total` (counter — GOAWAY received; PR 3)

The h2 series are pool-global (not `{upstream}`-labelled) since the pool holds one
connection per origin; per-upstream h2 labels are deferred with the multi-origin
h2 work.

Active-cap saturation (#239): `tardigrade_upstream_pool_at_capacity_total`
(`{upstream=...}`-labelled counter of fail-fast rejections).

## Active-cap semantics (#239)

`TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` is enforced **fail-fast**: a
checkout at the cap returns `error.UpstreamAtCapacity`, which the proxy maps
to **503 `upstream_saturated`**. The chosen semantics, out of
queue / fail-fast / backpressure:

- **Fail-fast (chosen).** In the thread-per-connection worker model, blocking
  a worker until a slot frees would let a single slow origin absorb the entire
  worker pool — precisely the upstream-side worker-starvation tail documented
  early on #141. Envoy's circuit-breaker `max_connections` makes the same
  call. Failing fast keeps workers live and pushes the shed decision to the
  client/retry layer.
- **Queueing / watermark backpressure (deferred to #140).** Real queueing
  wants admission control and watermark accounting shared with the downstream
  side; bolting a condvar wait onto the pool would double-book that design.

Enforcement is race-free by construction: `checkout`/`reserveSlot` **reserve**
the active slot under the pool mutex *before* the caller connects (a failed
connect calls `releaseSlot`), so concurrent callers cannot exceed the cap
during their connect/handshake window. Saturation rejections are a *local
policy* decision: they are **not** counted against passive upstream health or
the circuit breaker (a healthy-but-busy origin must not get ejected), and the
buffered path does not burn its retry budget re-hitting the cap. The cap does
not apply to the h2 pool, whose concurrency is bounded per connection by
`MAX_CONCURRENT_STREAMS` (one multiplexed connection per origin).

`benchmarks/upstream-reuse.sh` demonstrates both the reuse ratio and the cap
(503s at saturation, `at_capacity_total`, and a follow-up request confirming
health is untouched).

## Testing

- Unit: reuse across requests, idle-timeout/lifetime eviction, stale-conn retry,
  reusability decision (Content-Length/chunked vs `Connection: close`/close).
- Local load: `wrk` against `/proxy/health` through the python keep-alive
  fixture must show **zero** upstream `ConnectionFailed` (the regression) and the
  reused-connection counter dominating new connections.
- Reuse-ratio numbers under the canonical workload are captured on the Beelink
  per `benchmarks/README.md` (not in CI).
