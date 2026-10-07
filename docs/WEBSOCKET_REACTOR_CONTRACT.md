# WebSocket reactor and ownership contract

This document is the architecture contract for established `proxy_websocket`
tunnels. It records the boundary introduced by #818 and is the reference for
future reactor, handoff, relay, lifecycle, and validation work. It does not
change public WebSocket or configuration behavior.

The scope is an HTTP/1.1 downstream WebSocket upgrade after a valid origin
`101`. HTTP/2 RFC 8441 and HTTP/3 RFC 9220 extended CONNECT are unsupported;
they must remain rejected rather than silently taking a different path.

## Admission remains a worker responsibility

The request worker owns the request until it has completed normal HTTP
admission. Before it creates a `TunnelJob` or contacts the origin, it must:

1. Route to an opt-in `proxy_websocket on` location, then validate the HTTP/1.1
   upgrade request, Origin policy, and 0-RTT policy.
2. Run the existing ACL/geo, rate-limit, `auth required`, `forward_auth`, path,
   trusted-client-IP, forwarding-header, request-ID, tracing, and
   `proxy_set_header` paths.
3. Reserve the process-wide tunnel slot and the two proxy-buffer reservations.
   A capacity failure is a pre-commit 503 and does not open an origin socket.
4. Open a fresh, never-pooled HTTP/1.1 origin connection, send the rewritten
   handshake, and validate the origin's `101` and `Sec-WebSocket-Accept`.

The origin connection is never retried, replayed, mirrored, or returned to an
upstream pool. A non-101 remains an ordinary proxied response. These rules
preserve the #812/#815 security and accounting invariants: no handshake check
or authorization decision moves past admission merely because a connection is
long-lived.

`gateway_proxy_runtime.handleLocationWebSocketProxyPass` is the admission
boundary. It captures the location's reload policy and timeout at admission,
so a later reload cannot change an already-admitted tunnel from `preserve` to
`drain` or vice versa.

## Sharded reactor model

`http.tunnel_reactor.Reactor` starts a fixed number of shards before the
worker pool. A worker chooses the least-loaded shard and hands it an embedded
`http.tunnel_reactor.Job`; the shard owns many jobs and drives each through
the common resumable `http.tunnel.Relay` state machine. There is no
per-tunnel thread.

The readiness implementation is deliberately portable rather than
platform-specific:

| Platform | Socket readiness | Cross-thread wakeup |
| --- | --- | --- |
| Linux | One POSIX `poll()` call per shard over its client and origin sockets | A nonblocking POSIX pipe per shard |
| macOS | The same POSIX `poll()` call and nonblocking pipe | The same one-byte pipe signal |

Each shard waits on its wake-pipe read end plus two descriptors for each owned
tunnel. It wakes only for socket readiness, the earliest tunnel deadline, a
handoff, or `wakeAll()` during reload/shutdown. With no due deadline, it sleeps
indefinitely; the production fallback tick is disabled. `poll()` makes a
wakeup O(tunnels on that shard), an explicit trade-off for a small, portable
implementation. Replacing it with epoll or kqueue is a separate scalability
change, not an implicit behavior change.

The handoff inbox is a mutex-protected intrusive list and the pipe carries a
coalescing wake marker. A full pipe means a marker is already pending, not a
new allocation or a lost job. `wakeAll()` similarly uses a per-shard atomic
broadcast bit. The inbox has no separate operator setting, but it is bounded
by the global tunnel cap: a job gets there only after reserving a tunnel slot.

## Capacity and resource equations

Let:

- `C` = effective `proxy_websocket_max_tunnels` (when configured as `0`, the
  startup default is one quarter of the FD soft limit, capped at 4096);
- `R` = `proxy_websocket_reactor_threads` (configured range 1–64; the automatic
  default is one thread per four CPUs, clamped to 1–4);
- `S_i` = tunnels owned or queued for shard `i`;
- `B` = `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` (at least 16 KiB).

The enforced bounds are:

```text
sum(S_i) <= C                         0 <= S_i <= C
reactor threads = R                    worker-held tunnel threads = 0
tunnel sockets <= 2 * C               reactor wake-pipe FDs = 2 * R
relay payload buffers <= 2 * B * C    poll entries per shard <= 1 + 2 * S_i
queued handoffs across all shards <= C
```

The socket equation excludes listener, worker, and unrelated connection FDs;
operators must leave that headroom when sizing the soft descriptor limit. The
payload equation covers the two fixed relay directions. TLS/session objects,
job metadata, and normal process overhead are additional but do not grow with
the amount of peer data buffered by the relay. The proxy-buffer account
charges the two direction buffers before origin contact, so a stalled reader
backpressures the sender instead of creating an unbounded queue.

An established tunnel still occupies its downstream connection slot and still
contributes to `max_active_connections`; it no longer occupies
`max_in_flight_requests` or a request worker. Its origin counts as in flight
for least-connections balancing for the whole tunnel lifetime.

## Handoff state machine

```text
request worker
  └─ validated + slot/buffers + fresh origin/valid 101 ──> ADMITTED
                                                       │
               101 committed; job prepared; client detached
                                                       v
                                                  TRANSFERRED
                                                       │ submit succeeds
                                                       v
reactor shard ──> ACTIVE ── reload/shutdown deadline ─> DRAINING ─> CLOSED
                    │  │             │                    │
                    │  └ peer EOF/error/timer ────────────┘
                    └ relay has ready bytes or TLS work: take a bounded turn
```

- **ADMITTED:** the worker has passed every gate, acquired the slot and buffer
  reservations, and owns the fresh upgraded origin. It prepares all job-private
  allocations before writing the downstream `101`, so allocation failure still
  rolls back the request path cleanly.
- **TRANSFERRED:** after the `101` is committed, `TunnelJob` holds the origin,
  admission accounting, copied pipelined bytes, and later the config lease and
  detached client. The connection loop calls `attach()` then `submit()`. A
  successful `submit()` is the ownership commit: the job is on exactly one
  shard inbox. A stopped reactor or failed wake leaves ownership with the
  caller; `TunnelJob.submit()` runs that job inline, so it is never dropped.
- **ACTIVE:** the shard adopts the job and invokes its vtable (`fds`,
  `observe`, `advance`, `finish`, `abort`). `Relay.advance()` returns either a
  readiness/deadline description or one terminal close reason.
- **DRAINING:** this is an ownership state, not a new public protocol. A
  drain-mode reload supplies an absolute deadline from the admission
  generation's first supersession stamp; shutdown supplies a drain deadline
  when shutdown begins. The earlier deadline wins. Existing traffic can move
  until then.
- **CLOSED:** `finish` or `abort` runs once. No caller may observe or reuse the
  tunnel afterwards.

## Single-owner cleanup table

| Object | Before transfer | After `submit()` succeeds | Sole close/release path |
| --- | --- | --- | --- |
| Downstream socket / native TLS session / connection slot | Connection loop | `TunnelJob` on the shard (or inline fallback) | `TunnelJob.finishWithStats()` releases the slot while it still owns the FD, then closes/deinitializes it |
| Fresh origin socket / upstream TLS session | Request path, then `TunnelJob` once 101 is committed | `TunnelJob` | `TunnelJob.releaseShared()` calls `UpgradedUpstream.deinit()` |
| Tunnel-cap slot | Request path until handoff commit | `TunnelJob` | `GatewayState.releaseWebSocketTunnel()` in `releaseShared()` |
| Least-connections upstream count | Request path until handoff commit | `TunnelJob` | `GatewayState.recordUpstreamAttemptEnd()` in `releaseShared()` |
| Two relay-buffer reservations | `UpgradedUpstream` | `TunnelJob` through `UpgradedUpstream` | `UpgradedUpstream.deinit()` releases them |
| Admission configuration lease / supersession stamp | Request worker | `TunnelJob` | `ConfigLease.release()` in `releaseShared()` |
| Copied post-upgrade client bytes and access-log snapshot | Request arena/connection loop | `TunnelJob` | Job-owned allocator and arena are freed after the one close log |

This table is the race rule: there is one closing owner for every object.
`discardPrepared()` only frees a job that has not committed shared ownership;
`abandon()` handles a prepared job that cannot receive a detached client;
reactor registry allocation failure calls the job's explicit `abort` callback.
Neither path may close a resource still owned by the request path.

## Relay, TLS, and close semantics

`http.tunnel.Relay` treats the two hops as byte streams and never parses
WebSocket frames. It starts by delivering bytes that arrived after the
downstream request head (the pipelined first WebSocket frame) and bytes that
arrived with the origin `101`, before reading either socket again.

The relay registers read interest only when the corresponding direction buffer
has room and write interest while it has pending plaintext or TLS ciphertext.
On peer EOF it stops further reads, flushes already-read bytes in both
directions for at most `close_flush_timeout_ms`, then closes with `client` or
`upstream`. Idle, lifetime, reload, shutdown, and I/O-error closes use the
bounded taxonomy below.

Native downstream TLS and `wss://` upstream TLS translate TLS
WANT_READ/WANT_WRITE into the same readiness interests. Decrypted input and
queued ciphertext can request an immediate turn even without a new socket
event. Each TLS adapter is capped at eight record-layer drives per endpoint
call; on budget exhaustion it reports `ready_now`, allowing the shard to serve
other tunnels and deadlines before retrying. `Relay.advance()` also caps its
own work at four bidirectional rounds. A TLS peer therefore cannot monopolize
a shard by producing endless internal record-layer progress.

The observable close reasons are `client`, `upstream`, `idle`, `lifetime`,
`reload`, `shutdown`, and `error` (the `client_error` and `upstream_error`
implementation cases are intentionally exported as the bounded `error`
label). The close path writes exactly one access-log record with duration and
directional byte counts.

## Reload, shutdown, and observability

Configuration generations are pinned by `ConfigLease` until their tunnels
finish. A successful reload publishes an admission generation's supersession
stamp once; later reloads cannot extend its drain timeout, and a failed reload
does not start a drain. The main loop calls `Reactor.wakeAll()` immediately
after reload so drain-mode tunnels observe the stamp without waiting for I/O.
`preserve` tunnels retain their admission settings.

At graceful shutdown, the main loop requests shutdown, calls `wakeAll()`,
drains workers, then calls `stopAndJoin()`. No new handoff can be accepted
after stopping; existing jobs continue only to their shutdown deadline, after
which the reactor joins. If reload and shutdown race, `Relay.advance()` closes
at the earlier deadline.

The worker and reactor surfaces are intentionally separate:

- `tardigrade_worker_pool_*` shows normal request-worker pressure.
- `tardigrade_websocket_reactor_threads`, `_tunnels`,
  `_thread_tunnels_max`, `_handoffs_total`, and `_wakeups_total` show shard
  capacity, balance, handoffs, and idle behavior.
- Existing `tardigrade_websocket_tunnels_active`, byte, duration, upgrade, and
  close-reason metrics show the protocol lifecycle.

## Required race and failure behavior

| Scenario | Required outcome |
| --- | --- |
| Preparation allocation failure before 101 | Request path retains every shared object and rolls back; no handoff occurs |
| Client write failure or cancellation after preparation | `abandon()` closes the origin and returns the slot/count once |
| Reactor wake failure before commit | `submit()` rolls inbox bookkeeping back; caller still owns the job |
| Reactor registry OOM after commit | Reactor calls `abort(.upstream_error)`; the job releases everything once |
| Client frames pipelined behind the request head | `initial_to_upstream` delivers them first; they are not parsed as another HTTP request |
| Origin bytes bundled with 101 | `early_upstream_bytes` delivers them first to the client |
| Peer EOF / TLS close | Flush already-read bytes within the close-flush bound, then close once; TLS truncation is treated as stream end for the byte tunnel |
| Upstream connect or invalid 101 | No tunnel transfer; normal bounded gateway error path owns cleanup |
| Reload while idle | `wakeAll()` makes drain-mode jobs derive their fixed reload deadline immediately |
| Simultaneous reload and shutdown | Both deadlines are armed; the earlier one wins and the single job close path runs once |

## Delivery sequence and validation exit criterion

The contract separates the work into interfaces that can be changed and tested
independently:

1. **R2 — reactor foundation:** `http.tunnel_reactor.Reactor`, `Job`, shard
   inbox/wake pipe, snapshots, and fixed-thread tests.
2. **R3 — worker handoff:** `TunnelJob`, `RequestContext.tunnel_handoff`,
   `ServeOutcome.tunnel`, config-lease transfer, and downstream detachment.
3. **R4 — nonblocking relay:** `http.tunnel.Relay`, `AnyEndpoint`, endpoint
   readiness contracts, fixed buffers, and bounded TLS drives.
4. **R5 — lifecycle:** `ReloadDrain`, `wakeAll`, shutdown ordering,
   `stopAndJoin`, close taxonomy, access logging, and metrics overlays.
5. **R6 — focused validation:** reactor unit tests plus live WebSocket
   integration coverage for gates, pipelined bytes, TLS, capacity, reload,
   shutdown, and resource settle.

The pre-reactor baseline was one request worker held for every established
tunnel. The objective exit criterion is encoded by `tests/integration.zig`'s
“proxy_websocket runs hundreds of tunnels on reactor threads while one worker
keeps serving requests” test: with one worker, 300 idle tunnels, and two
reactor threads, it requires all handoffs to appear, requires load to span
both shards, serves 40 unrelated `/healthz` requests with a worst-case latency
below one second, proves tunnel traffic still relays, and waits for tunnel,
reactor-owned, and connection gauges to return to baseline.
`src/http/tunnel_reactor.zig` separately proves up to 1500 tunnels on two
reactor threads, idle timer wakeups without a periodic tick, handoff rollback,
bounded stalled-reader buffering, reload drain, and shutdown join.
