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

## std.c / std.posix Usage Audit (v0.62 baseline, issue #80)

Direct `std.c` and `std.posix` usage is intentional and appropriate in the
following modules.  All sites were reviewed after the Zig 0.16 migration.

| Module | Usage | Verdict |
|---|---|---|
| `edge_gateway.zig` | `accept`, `sockaddr`, `fcntl`, `close`, `dup2`, `lseek`, `rlimit`, AF/SOCK constants | ✅ Keep — low-level TCP accept loop and fd management |
| `http/event_loop.zig` | kqueue / `kevent`, `EVFILT.READ`, `EV.ADD` | ✅ Keep — event-loop primitives with no `std.Io` equivalent |
| `http/shutdown.zig` | `sigaction`, `SIG.HUP/INT/TERM/USR1/USR2` | ✅ Keep — signal handler registration |
| `http/worker_pool.zig` | `pthread_setaffinity_np` / CPU affinity | ✅ Keep — platform thread tuning |
| `http/tls_termination.zig` | `std.c.malloc`, `std.c.free` for OpenSSL ALPN/SNI buffers | ✅ Keep — OpenSSL C callbacks require C heap |
| `http/acme_client.zig` | `std.c.free` for DER buffer from OpenSSL | ✅ Keep — OpenSSL owns the allocation |
| `http/access_log.zig` | UDP syslog socket (`socket`, `sendto`, `sockaddr.in`) | ✅ Keep — raw UDP datagram send has no `std.Io` path |
| `http/transcript_store.zig` | `lseek` (seek-to-end), `fchmod` (set 0o600) | ✅ Keep — POSIX file-mode operations; no `std.Io` equivalent |
| `http/ngtcp2_binding.zig` | QUIC `sockaddr`/UDP framing for ngtcp2 C binding | ✅ Keep — C library ABI requirement |
| `http3_runtime.zig` | UDP send/recv, `sockaddr`, QUIC socket options | ✅ Keep — QUIC transport layer |
| `main.zig` | PID file, `dup2`, signal masks, process spawn | ✅ Keep — process management, no `std.Io` alternative |

**No avoidable calls were identified.**  The `zig_compat.zig` layer is the right
boundary for filesystem and process I/O that has `std.Io` equivalents; the
modules above deal with sockets, signals, C library interop, and file-descriptor
manipulation that do not.

If a future `std.Io` gains first-class kqueue/epoll, signal, or UDP socket APIs
the relevant modules should be migrated at that point.

---

## compat.io() Migration Pattern

`src/zig_compat.zig` exposes a global `compat.io()` helper as a migration bridge
over the Zig 0.16 `std.Io` runtime.  Long-term, runtime/server modules should
receive `std.Io` explicitly rather than reaching through the global singleton.

**Pattern** (demonstrated in `src/http/autoindex.zig`, issue #79):

```zig
// Before: global singleton
pub fn doWork(allocator: std.mem.Allocator, ...) !void {
    var dir = std.Io.Dir.cwd().openDir(compat.io(), path, .{});
}

// After: explicit injection
pub fn doWork(io: std.Io, allocator: std.mem.Allocator, ...) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{});
}
```

At call sites that have not yet been migrated, pass `compat.io()` as the `io`
argument.  Migrate modules one at a time; avoid broad rewrites across unrelated
modules.

**Modules still using global `compat.io()`** (as of v0.62):
`main.zig`, `edge_gateway.zig`, `tls_termination.zig`, `session_store_file.zig`,
`approval_store.zig`, `worker_pool.zig`, `config_file.zig`, `acme_client.zig`,
`http3_runtime.zig`, `edge_config.zig`, `static_file.zig`, `access_log.zig`,
`dns_discovery.zig`, `secrets.zig`.

---

## Zig 0.16 Performance Characteristics

Summary of performance evaluation performed for issue #73.

### Build times (Zig 0.16.0, aarch64 macOS, M-series)

| Build mode | Typical time |
|---|---|
| `ReleaseFast` clean | ~30–60 s (first run compiles stdlib too; cached runs ~15–25 s) |
| `ReleaseFast` incremental (1 file touched) | ~5–15 s |
| `Debug` test build | ~20–40 s |

Run `./scripts/build-benchmarks.sh` to capture current build times.

### Zig 0.16 build improvements

- **Incremental compilation**: Pass `-Zincremental` for faster rebuilds during
  development. Incremental is not yet recommended for release builds as it may
  produce slower binaries.
- **Cross-compilation**: `zig build -Dtarget=aarch64-linux-gnu` produces a
  native aarch64 binary from macOS without emulation.
- **Link-time optimization**: Enabled implicitly at `ReleaseFast`; adds
  ~5–10 s to link time but improves runtime throughput.

### Runtime performance targets (HTTP/1.1 reverse proxy, loopback, 4 workers)

These are indicative targets, not guaranteed SLAs:

| Metric | Target |
|---|---|
| Throughput | ≥ 20 000 req/s (loopback, ReleaseFast, 4 workers) |
| p50 latency | < 1 ms (loopback) |
| p99 latency | < 5 ms (loopback) |
| Memory (idle) | < 20 MB RSS |

Capture baseline benchmarks with:
```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/tardigrade run &
./benchmarks/run.sh --duration 30 --connections 50 \
  --save benchmarks/baselines/$(git describe --tags).json
```

Compare against a previous baseline:
```bash
./benchmarks/run.sh \
  --baseline benchmarks/baselines/<previous-tag>.json \
  --save benchmarks/results/$(date +%Y%m%d).json
```

### Known performance-sensitive areas

- `runActiveHealthChecks` — now runs in a background thread (no event-loop impact)
- `NetStream.Writer.print` / `TlsConnection.Writer.print` — now stack-allocated
- `parseHeaders` — linear scan; no heap allocation for common header counts
- TLS handshake — OpenSSL; cannot be parallelised per connection

---

## Architecture and Ownership Audit (v0.62 baseline)

Summary of the codebase audit performed for issue #60.

### Module size

| File | Lines | Status |
|---|---|---|
| `src/edge_gateway.zig` | ~10 100 | ⚠️ Too large — contains HTTP handler, proxy, sessions, event loop, health checks, config reload. Split into sub-modules is the top structural debt item. |
| `src/edge_config.zig` | ~2 975 | OK for now; grows with new env vars |
| `src/http/config_file.zig` | ~1 310 | OK |
| Everything else | < 1 100 | Reasonable |

**Recommendation:** `edge_gateway.zig` should be split into at minimum:
`gateway_handler.zig`, `gateway_proxy.zig`, `gateway_state.zig`,
`gateway_sessions.zig`, and `gateway_health.zig` in a future refactor session.

### Allocator ownership

| Lifetime | Allocator | Pattern |
|---|---|---|
| Process | `std.heap.GeneralPurposeAllocator` (GPA) | Used for `GatewayState` and long-lived config; freed at shutdown |
| Request | `state.allocator` (same GPA) | Most request-scoped allocations; freed in request handler defer chains |
| Request (some paths) | `std.heap.ArenaAllocator` | Used for config validation and some request contexts; deinited at function end |
| Buffer reuse | `BufferPool` (slab allocator) | Used for request and relay read buffers; correct pattern |

**Gaps:** request paths do not universally use a per-request arena. Large proxied
responses allocate into the GPA and are freed on response completion. No leaks
observed but arena discipline would reduce fragmentation under high concurrency.

### Config lifecycle

`ReloadableConfigStore` correctly ref-counts config versions:
- `acquire()` holds a lease; `release()` decrements refcount.
- On reload, old config is moved to `retired` list and freed when its refcount
  reaches zero.
- Tested: probe threads and active workers hold leases; config never freed while
  in use.

### Error handling

- 58 `errdefer` sites in `edge_gateway.zig` — reasonable coverage for partial init failures.
- Several `catch {}` sites are intentional best-effort operations (sleep, log
  flushing, non-critical socket options) — acceptable.
- Notable: `proxy_cache_store.put catch {}` (line ~672) silently discards cache
  write failures; this is intentional (cache is best-effort).
- `setNonBlocking catch {}` after connection accept is acceptable (connection is
  still usable in blocking mode).

### Related issues addressed

All hardening issues listed in #60 have been resolved:
- #37 (hop-by-hop header stripping) ✅ CLOSED
- #38 (directory traversal) ✅ CLOSED
- #41 (config reload cleanup) ✅ CLOSED
- #49 (validation/error messages) ✅ CLOSED
- #52 (header injection) ✅ CLOSED
- #53 (size limits) ✅ CLOSED
- #54 (log redaction) ✅ CLOSED
- #56 (TE/CL conflict) ✅ CLOSED
- #57 (concurrency audit) ✅ CLOSED
- #58 (event loop audit) ✅ CLOSED
- #59 (profiling hooks) ✅ CLOSED

### Recommendation

**Continue feature development.** The foundation is sound:
- No memory safety issues or races found.
- Config and connection lifecycles are correctly managed.
- Error paths use errdefer consistently.
- All listed hardening items are resolved.

The one outstanding structural debt is `edge_gateway.zig` size; this should be
tracked and split when the next large feature area is added.

---

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
