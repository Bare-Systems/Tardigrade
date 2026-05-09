# Agent Guide

Scope: the `Tardigrade` repository.

## Rules

- Keep the core runtime generic.
- Do not add product-specific logic to core.
- Put integrations under `examples/`.
- Keep docs concise and operator-focused.

## Workflow

- Keep active unfinished work in `ROADMAP.md`.
- Update `README.md` for operator-facing behavior.
- Update `BLINK.md` for deployment reality.
- Record notable repo changes in `CHANGELOG.md`.

## Validation

```bash
zig build test
zig build test-integration
```

## Profiling Workflow

Profiling is driven entirely by external tools — no instrumentation is compiled
into the binary by default.

### Build modes for profiling

| Mode | Command | Use case |
|---|---|---|
| Debug (default) | `zig build` | Symbol-rich; slowest; use for sanitizer runs |
| ReleaseSafe | `zig build -Doptimize=ReleaseSafe` | Optimised + safety checks; recommended for profiling |
| ReleaseFast | `zig build -Doptimize=ReleaseFast` | Maximum throughput; use to validate absolute peak performance |

### Quick start

```bash
# Build a profiling binary
./scripts/profile.sh build

# Show CPU profiling instructions for your platform
./scripts/profile.sh cpu-linux   # Linux: perf + flamegraph
./scripts/profile.sh cpu-macos   # macOS: sample / Instruments

# Show memory profiling instructions
./scripts/profile.sh mem-linux   # Valgrind massif or heaptrack
./scripts/profile.sh mem-macos   # leaks or Instruments Allocations
```

### Known hot paths to investigate

- TLS handshake (`SSL_accept`, `SSL_read`, `SSL_write` in OpenSSL)
- Header parsing (`parseHeaders`, `parseRequest` in `src/http/request.zig`)
- Rate-limiter and idempotency lock contention (short critical sections, but
  called on every request)
- Upstream connection establishment (TCP connect + TLS handshake round trip)
- JSON access-log serialisation (`formatEntry` in `access_log.zig`)

### Benchmark + profile workflow

```bash
# Terminal 1 — start server under profiling (Linux example)
zig build -Doptimize=ReleaseSafe
perf record -g -F 997 ./zig-out/bin/tardigrade run &

# Terminal 2 — run load
./benchmarks/run.sh --duration 60 --connections 100

# Back in Terminal 1 — stop and analyse
kill %1
perf report --no-children
```

See `scripts/profile.sh` for full platform-specific instructions.

---

## Event Loop I/O Model

Tardigrade uses a **level-triggered epoll/kqueue** event loop on the listener
socket and a **thread-per-connection blocking I/O** model for each accepted
connection.

### Main event loop thread

- Listener socket is `O_NONBLOCK`; `accept()` is called in a tight loop that
  drains all ready connections before returning to `epoll_wait`/`kevent`.
- Level-triggered mode (no `EPOLLET`) is correct — draining ensures no
  connection is silently dropped.
- The main thread never performs blocking I/O on connection sockets.
- Timer ticks (configurable interval) fire background housekeeping: hot-reload,
  log rotation, proxy-cache maintenance, and active health probes.

### Worker threads

- Each accepted connection is switched to **blocking mode** before dispatch to
  a worker thread.
- Workers perform blocking `read`/`write`/`SSL_read`/`SSL_write` on their
  assigned connection; the event loop is not involved.
- TLS handshake, request parsing, upstream proxying, and response writing are
  all blocking operations inside the worker.

### Background threads

Active health probes (`TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_*`) previously ran
blocking HTTP requests on the main event loop thread. They now run in a
dedicated background thread:
- `GatewayState.health_probe_running` (atomic bool) prevents duplicate batches.
- The probe thread holds a `ConfigLease` for its lifetime so hot-reload cannot
  free the config while probes are in flight.
- DNS resolution (`runDnsDiscoveryRefresh`) also runs its resolver call directly
  in the timer-tick context; the blocking resolve call completes quickly enough
  (typically < 1 ms on LAN) that it does not materially affect accept latency.

### Event loop health metrics

`tardigrade_event_loop_iterations_total` and
`tardigrade_health_probe_runs_total` are exported via the Prometheus metrics
endpoint and can be used to monitor event loop cadence and health-probe activity.

---

## Shared State Inventory

`GatewayState` is a single long-lived struct shared across all worker threads.
Every mutable field that crosses thread boundaries has explicit ownership.

| Field(s) | Guard | Notes |
|---|---|---|
| `rate_limiter` | `rate_limiter_mutex` | Token-bucket per-IP/identity buckets |
| `idempotency_store` | `idempotency_mutex` | Request-ID dedup cache |
| `proxy_cache_store`, `proxy_cache_locks` | `proxy_cache_mutex` | Response cache + per-key write locks |
| `session_store` | `session_mutex` | Session token table |
| `circuit_breaker` | `circuit_mutex` | Per-upstream open/half-open state |
| `command_lifecycle` | `command_mutex` | In-flight command records |
| `approvals` | `approval_mutex` | Pending approval entries |
| `mux_subscriptions_by_device`, `mux_resume_state` | (transcript_mutex / approval_mutex scope) | Mux channel tracking |
| `upstream_health`, `upstream_active_requests`, `upstream_rr_index`, `upstream_backup_rr_index`, `lb_random_state` | `upstream_mutex` | All upstream selection and health state; `lb_random_state` updated only via `lcrngNext` inside `Locked`-suffix helpers |
| `active_connections_total`, `active_connections_by_ip`, `active_fds`, `fd_to_ip` | `connection_mutex` | Per-IP and total connection accounting |
| `metrics` | `metrics_mutex` | Prometheus counters |
| `dns_discovery` | `dns_discovery.mutex` (internal) | DNS resolver state |
| Config pointer | `ReloadableConfigStore.mutex` + ref-counting | Old version kept alive until all in-flight leases are released; no dangling pointer possible |
| `last_reload_ok`, `last_reload_at_ms`, `last_reload_error*` | `reload_mutex` | Hot-reload outcome, queried by admin endpoint |

### Reload safety

`ReloadableConfigStore` uses acquire/release reference counting protected by its
own mutex.  On hot reload: (1) new config is allocated and installed atomically
under the store mutex; (2) the old version is moved to a `retired` list;
(3) when its `ref_count` reaches zero, it is freed.  Workers hold a
`ConfigLease` for the duration of each request so the config pointer cannot be
freed under them, even when repeated reloads arrive.

### PRNG

`lb_random_state` is stepped via the standalone `lcrngNext` pure function (an
LCG with full 2^64 period).  The function is only called from
`nextLbRandomLocked`, which is always reached through callers that hold
`upstream_mutex`, so no atomic operation is required.

---

## HTTP/3 Session Resumption and 0-RTT

HTTP/3 support is gated on the `enable_http3_ngtcp2` build option and requires
ngtcp2 + nghttp3 + an OpenSSL build with QUIC support at link time.

### Session resumption

TLS session tickets are always enabled for HTTP/3 connections
(`TARDIGRADE_TLS_SESSION_TICKETS`, default `true`).  On reconnect, ngtcp2 offers
the stored ticket via ClientHello and the server validates the embedded QUIC
version before accepting it.  Resumption reduces the connection handshake from 1
RTT to 0 RTT for the TLS layer.

### 0-RTT early data

`TARDIGRADE_HTTP3_ENABLE_0RTT` (default `false`) controls whether the server
accepts early data from resuming clients.

- **Default (disabled):** `SSL_CTX_set_max_early_data(ctx, 0)` instructs
  OpenSSL to reject all 0-RTT data.  Clients must complete a full handshake
  before sending requests.
- **Enabled:** the server accepts early-data frames.  Any stream that carries
  `NGTCP2_STREAM_DATA_FLAG_0RTT` data is marked as an early-data stream.  When
  a complete request is assembled from such a stream, Tardigrade checks the HTTP
  method:
  - **Safe methods** (GET, HEAD, OPTIONS, TRACE) are forwarded to the request
    handler normally.
  - **Unsafe methods** (POST, PUT, PATCH, DELETE, CONNECT) are rejected with
    `425 Too Early` without invoking the handler.  This prevents replay attacks
    where a network adversary retransmits 0-RTT packets to trigger side-effecting
    requests.

### Production caveats

- Enable 0-RTT only on services whose GET/HEAD responses are safe to replay
  (e.g. read-only APIs, static files).
- Even safe-method 0-RTT requests are subject to replay by a network attacker.
  Do not process 0-RTT GET requests that carry authentication tokens granting
  write access.
- `warnRiskyConfig` logs a warning when `http3_0rtt_enabled` is true at startup
  and on every config reload.
