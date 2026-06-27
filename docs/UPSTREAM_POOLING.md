# Upstream connection pooling (#141)

Status: **Phase 1 implemented** (plain-HTTP keepalive reuse). Later phases tracked
in issue #141.

## Why

`std.http.Client` kept upstream connections alive internally but did not expose
the socket fd, so the per-phase upstream timeouts from #196 (`SO_*TIMEO` / `poll`)
could not be enforced. #196 replaced it with a manual transport that owns the
socket — but the first cut sent `Connection: close`, opening a fresh TCP
connection per proxied request. Under load that churn overflows the upstream's
accept backlog (observed as `error.ConnectionFailed` on ~4–5% of requests in the
perf smoke). This module restores connection reuse on top of the manual
transport, so we keep both timeout enforcement **and** keepalive.

## Scope of Phase 1

In scope:
- Reuse **plain HTTP/1.1 TCP** upstream connections (the data-plane buffered
  path — the default proxy mode, `TARDIGRADE_PROXY_STREAMING_MODE=off`).
- Per-origin idle pool with idle-timeout, max-lifetime, and max-idle-per-host
  caps.
- Safe stale-connection handling: a pooled connection the origin closed while
  idle is retried once on a fresh connection (the request was never delivered).
- Global reuse/new/idle/stale metrics.

Deferred (tracked on #141):
- TLS / mTLS upstream pooling (still `Connection: close`; OpenSSL conn ownership
  in the pool + session reuse is a follow-up).
- Unix-socket pooling (cheap to connect; no TCP handshake to amortize).
- Streaming path (`executeStreamingHttpProxyRequest` still uses
  `std.http.Client`; retiring it is Phase 3, depends on #139).
- Per-upstream **labelled** metrics (`{upstream=...}`). Phase 1 exposes global
  counters; the metrics subsystem is flat today and labelled series are a
  separate addition.
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

## Keying

Phase 1 key: `"<host>:<port>"` for plain HTTP. TLS config is global
(`cfg.upstream_tls_*`), so when TLS pooling lands the key gains a TLS/SNI
fingerprint; the key type is centralized so that extension is local.

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
- `tardigrade_upstream_connections_idle` (gauge)
- `tardigrade_upstream_stale_retries_total`

Per-upstream labelled (`{upstream="host:port"}`, Phase 1b):
- `tardigrade_upstream_pool_connections_new_total`
- `tardigrade_upstream_pool_connections_reused_total`
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
