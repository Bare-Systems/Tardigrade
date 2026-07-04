# Timeout policy (#171)

Every timeout Tardigrade enforces (or knowingly does not), audited against
current `main`. Each class lists its knob, default, the mechanism that
enforces it, what the caller observes on expiry, and honest status. The June
2026 audit on #171 predates the #196/#141/#145 transport rework — several of
its gaps have since closed; this document is the refreshed source of truth.

Statuses: ✅ enforced · 🟡 partial (enforced with documented holes) ·
⬜ missing (documented gap, tracked follow-up).

## Model

Two principles, from the #196/#141 arc:

1. **Own the fd.** Every data-plane transport is a plain blocking socket
   owned by Tardigrade (no `std.http.Client`), so per-phase deadlines are
   enforceable with `SO_RCVTIMEO`/`SO_SNDTIMEO` plus `poll(2)` where the
   socket option is unreliable (AF_INET reads — poll is authoritative there).
2. **Phase, not request.** Deadlines bound *phases* (connect, handshake,
   header read, per-read progress, write), so a legitimately slow-but-moving
   transfer is never killed by a total-time guess. The optional
   whole-request wall clock (`REQUEST_TOTAL`) layers on top, cooperatively.

## Downstream (client side)

| Class | Knob (`TARDIGRADE_…`) | Default | Enforcement | On expiry | Status |
|---|---|---|---|---|---|
| TLS handshake | `TLS_HANDSHAKE_TIMEOUT_MS` | 5000 | `SO_RCVTIMEO`+`SO_SNDTIMEO` set before `SSL_accept` (#138) | connection closed, warn log | ✅ |
| PROXY-protocol preface | — (rides the handshake/header phase) | — | preface parsed under the already-installed socket timeouts | connection closed | 🟡 no dedicated knob; bounded by the surrounding phase |
| Request header read | `HEADER_TIMEOUT_MS` | 10000 | `SO_RCVTIMEO` during head read (#138) | connection closed (slowloris protection) | ✅ |
| Request body read | `BODY_TIMEOUT_MS` | 0 (off) | `SO_RCVTIMEO` switched after head on the streaming-fallback path (#138) | read fails → 4xx/close | 🟡 the buffered single-read path deliberately stays on the header timeout (splitting that read would weaken slowloris protection) |
| Downstream response write | `DOWNSTREAM_WRITE_TIMEOUT_MS` | 30000 | `SO_SNDTIMEO` for the whole response phase (#138) | write fails → connection closed, distinct from upstream errors | ✅ |
| Keep-alive idle | `KEEP_ALIVE_TIMEOUT_MS` | 5000 | parked-connection reaper on the maintenance tick + socket timeouts | parked connection closed | ✅ |
| Request total wall clock | `REQUEST_TOTAL_TIMEOUT_MS` | 0 (off) | cooperative lifecycle checkpoints; shrinks upstream phase budgets via `effectiveTimeoutMs` | 504 `upstream_timeout` at the next checkpoint | 🟡 not observed inside every blocking syscall — a phase deadline fires first in practice |
| WebSocket idle | `WEBSOCKET_IDLE_TIMEOUT_MS` | 30000 | relay loop idle check | connection closed | ✅ |
| SSE idle | `SSE_IDLE_TIMEOUT_MS` | 30000 | send-loop idle check | stream ended | ✅ |
| HTTP/2 downstream per-stream phases | — | — | lifecycle checkpoint at stream start only | — | ⬜ frame-level per-stream deadlines need downstream-h2 work; connection inherits socket timeouts only |
| HTTP/3 / QUIC | — | (idle hardcoded in `ngtcp2_binding`) | QUIC transport internal | — | ⬜ experimental; not yet mapped to this policy |

## Upstream (origin side)

| Class | Knob (`TARDIGRADE_…`) | Default | Enforcement | On expiry | Status |
|---|---|---|---|---|---|
| TCP connect | `UPSTREAM_CONNECT_TIMEOUT_MS` | 5000 | **non-blocking connect + `poll` + `SO_ERROR`** (`compat.connectBoundedTcp`, #171) on the buffered, streaming, h2, and h2c paths | `error.Timeout` → 504 `upstream_timeout` | ✅ *(new — previously the knob bounded only handshake/write; a SYN-blackholed origin stalled a worker for the kernel's ~2 min limit)* |
| Upstream TLS handshake | bounded by `UPSTREAM_RESPONSE_TIMEOUT_MS` (falls back to `UPSTREAM_TIMEOUT_MS`) | — | `SO_RCVTIMEO`/`SO_SNDTIMEO` set before `UpstreamTlsConn.connect`: h1 paths since #196/#232, **h2/h2c pool since #171**. The h2 pool takes two distinct deadlines — `UPSTREAM_CONNECT_TIMEOUT_MS` for the TCP connect, the response deadline for the handshake/reads — so the connect claim above is literally true | handshake error → 502 | ✅ *(the h2 pool previously handshook with no deadline — a TCP-accepting-but-silent origin hung the worker)* |
| Request send + response wait (per attempt) | `UPSTREAM_TIMEOUT_MS` | 10000 | `SO_*TIMEO` + authoritative `poll(2)` per read (#196) on buffered/streaming/control-plane/unix; h2: connection deadline + per-stream wait deadlines with progress extension (#259) | `error.Timeout` → 504 | ✅ |
| First-byte / response head | `UPSTREAM_RESPONSE_TIMEOUT_MS` | 0 (falls back to `UPSTREAM_TIMEOUT_MS`) | separate `SO_RCVTIMEO`/poll deadline after the request is written | 504 | ✅ |
| Read idle mid-body | (same knobs) | — | per-read poll deadline (h1 streaming/buffered); h2 reader frame deadline + no-progress sweep | 504 / aborted relay after first byte | ✅ |
| Retry wall-clock budget | `UPSTREAM_TIMEOUT_BUDGET_MS` | 0 (off) | checked between attempts in the retry loop | `error.Timeout` → 504 | ✅ |
| FastCGI exchange | `UPSTREAM_TIMEOUT_MS` | 10000 | `SO_*TIMEO` on the leased connection before the exchange (#171) | exchange error → 502, conn not pooled | ✅ *(new — the exchange previously had **no deadline at all**: a hung php-fpm pinned the worker indefinitely)* |
| SCGI / uWSGI exchange | `UPSTREAM_TIMEOUT_MS` | 10000 | `SO_*TIMEO` set in `execute()` (#171) | 502 | ✅ *(new — same unbounded-exchange gap as FastCGI)* |
| FastCGI/SCGI/uWSGI TCP connect | — | — | blocking `connect()` | kernel limit | ⬜ not yet routed through `connectBoundedTcp` (endpoints are typically local/unix; follow-up) |
| Active health probes | `UPSTREAM_PROBE_TIMEOUT_MS` (alias `UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS`) | 2000 | raw probes with `SO_RCVTIMEO`, unix + TCP (#138) | probe fails → backend marked | ✅ |
| Pool idle / lifetime | `UPSTREAM_POOL_IDLE_TIMEOUT_MS` / `…_MAX_LIFETIME_MS` | 90000 / 0 | maintenance-tick reapers (h1 + h2 pools) | idle conn closed | ✅ (housekeeping, not a request deadline) |
| Passive-health / breaker windows | `UPSTREAM_FAIL_TIMEOUT_MS`, `CB_TIMEOUT_MS` | 10000 / 30000 | policy timers | backend skipped / breaker half-open | ✅ (policy windows, not I/O deadlines) |
| Mail/memcached protocol proxies | — (hardcoded) | 10000 / 2000 | `SO_*TIMEO` after connect | 502 | 🟡 bounded but not configurable |

## Lifecycle / operations

| Class | Knob (`TARDIGRADE_…`) | Default | Enforcement | Semantics | Status |
|---|---|---|---|---|---|
| Shutdown drain | `SHUTDOWN_DRAIN_TIMEOUT_MS` | 30000 | worker-pool drain deadline | **soft cap**: queued work is drained/abandoned by the deadline, but active handlers finish naturally (their own phase timeouts bound them) | 🟡 semantics documented here; a hard process cap is a #169-adjacent decision |
| Reload drain | (same machinery) | — | as above | as above | 🟡 |
| OCSP refresh | `TLS_OCSP_REFRESH_TIMEOUT_MS` | 10000 | bounded fetch | stale staple kept | ✅ |
| TLS session cache lifetime | `TLS_SESSION_TIMEOUT_SECONDS` | 300 | OpenSSL session cache | session renegotiated | ✅ (cache lifetime, not an I/O deadline) |

## Error / observability conventions

- **Timeout classes map to two statuses**: downstream phase expiry closes the
  connection (the client is the offender; there is no one to send a status
  to in the slowloris case), upstream phase expiry maps to **504
  `upstream_timeout`** (`error.Timeout`/`error.WouldBlock`), and non-timeout
  upstream failures map to **502 `upstream_error`**. Saturation (`#239`
  active cap) is deliberately distinct: **503 `upstream_saturated`**, no
  health impact.
- Upstream timeouts count toward passive health / the circuit breaker;
  downstream write timeouts do not (client's fault, not the origin's).
- Config validation warns on inconsistent relationships
  (`upstream_timeout_budget_ms < upstream_timeout_ms`,
  `request_total_timeout_ms < upstream_timeout_budget_ms`).

## Known gaps (tracked)

1. **Request-total wall clock is cooperative** — enforced at checkpoints and
   by shrinking phase budgets, not inside every blocking syscall.
2. **Downstream HTTP/2 and HTTP/3 per-stream phase deadlines** — need
   frame-level deadline tracking; out of scope until that work is scheduled.
3. **FastCGI/SCGI/uWSGI TCP connect** is still a blocking `connect()`
   (exchange itself is now bounded).
4. **Shutdown drain is a soft cap** by design; revisit with #169.
