# Tardigrade — Upgrade Roadmap

This document tracks work needed to close the gap between the current implementation and a
production-grade nginx replacement. Items are drawn from a full codebase audit conducted
March 2026. The structure mirrors PLAN.md: each phase lists specific tasks with acceptance
criteria, resolved notes, and relevant source file references.

Status key:
- `[ ]` not started
- `[~]` partial / skeletal implementation exists
- `[x]` complete

---

## UPGRADE 1: Test Infrastructure

Priority: CRITICAL — must be done before adding new features

No integration tests exist. The 13 unit tests that do exist cover only utility functions.
Every feature added without integration tests creates undetectable regression risk.

### 1.0 Test Harness

- [ ] Create a `tests/` integration test runner that boots a real Tardigrade process
      with a test config, sends real HTTP requests, and asserts responses
- [ ] Use a loopback upstream (tiny Zig or shell HTTP echo server) to validate proxy paths
- [ ] Add a `build.zig` step `zig build test-integration` that runs the full suite
- [ ] Add a CI workflow (GitHub Actions) that runs unit + integration tests on every push

### 1.1 Core Gateway Integration Tests

- [ ] `GET /health` returns `200` with valid JSON body
- [ ] `POST /v1/chat` without auth returns `401` stable error envelope
- [ ] `POST /v1/chat` with valid bearer token proxies to upstream and returns response
- [ ] `POST /v1/chat` with invalid JSON body returns `400` stable error envelope
- [ ] `X-Correlation-ID` from request is echoed in response headers
- [ ] `X-Correlation-ID` is generated when absent from request
- [ ] `GET /metrics` returns Prometheus-format text output

### 1.2 Auth Pipeline Integration Tests

- [ ] Bearer token SHA-256 hash is checked against allowlist; mismatched token → 401
- [ ] JWT RS256/HS256 token validation succeeds with valid signature
- [ ] JWT with expired `exp` claim returns `401`
- [ ] JWT with wrong `iss` claim returns `401`
- [ ] Device auth (`X-Device-ID` + `X-Device-Signature`) validates against registered device
- [ ] Session token created via `POST /v1/sessions` is accepted on subsequent `POST /v1/chat`
- [ ] Revoked session token is rejected (`DELETE /v1/sessions` then `POST /v1/chat`)

### 1.3 Rate Limiter Integration Tests

- [ ] Burst beyond configured limit returns `429` with `Retry-After` header
- [ ] Rate limit resets after token-bucket refill window
- [ ] Per-IP limit does not bleed across different source IPs

### 1.4 Proxy & Cache Integration Tests

- [ ] Reverse proxy forwards headers and body to upstream correctly
- [ ] `Cache-Control: no-store` upstream response is not cached
- [ ] Cacheable response is replayed from cache on second request (no upstream hit)
- [ ] `stale-while-revalidate` serves stale + triggers background revalidation
- [ ] Proxy correctly follows a single upstream redirect and returns final response
- [ ] Upstream 5xx triggers retry up to configured `proxy_next_upstream_tries`

### 1.5 TLS Integration Tests

- [ ] TLS handshake completes with test self-signed cert
- [ ] SNI routing selects correct certificate for multi-cert configurations
- [ ] mTLS rejects client with unrecognised CA
- [ ] `Connection: close` is sent on TLS shutdown when graceful drain is active

### 1.6 Config Hot-Reload Tests

- [ ] Sending SIGHUP while under load does not drop in-flight requests
- [ ] After SIGHUP, new upstream pool URL takes effect for subsequent requests
- [ ] After SIGHUP, new rate limit value is enforced

### 1.7 Graceful Shutdown Tests

- [ ] In-flight request completes before worker exits
- [ ] Keep-alive connections receive `Connection: close` before shutdown
- [ ] Server exits cleanly within configured drain timeout with no open fd leaks

### 1.8 Concurrency / Load Tests

- [ ] 100 concurrent connections all receive correct responses with no data corruption
- [ ] Worker pool under saturation queues and processes connections in order
- [ ] GatewayState mutex contention does not cause deadlock under concurrent auth + rate check

---

## UPGRADE 2: Active Upstream Health Checks

Priority: HIGH — passive-only failure tracking is unsafe for production

Current state: upstream health is tracked only by passive failure counting
(`src/edge_gateway.zig`). A backend can be completely down and Tardigrade will not
discover it until live traffic starts failing.

### 2.0 Active Health Check Engine

- [ ] Add `HealthChecker` struct to `src/http/health_checker.zig`
- [ ] Configurable per-upstream: `health_check_path`, `health_check_interval_ms`,
      `health_check_timeout_ms`, `health_check_success_status` (default: 200–299)
- [ ] Dedicated timer-driven goroutine/thread (or reuse `TimerManager`) probes each upstream
- [ ] On consecutive failures (configurable `health_check_threshold`): mark upstream `down`
      and stop routing traffic to it immediately
- [ ] On consecutive successes after being `down`: mark `up` and re-enable routing
- [ ] Active health state is reflected in `GET /metrics` and `GET /health` responses

### 2.1 Config Integration

- [ ] `TARDIGRADE_UPSTREAM_HEALTH_PATH` — path to probe (default: `/health`)
- [ ] `TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS` — probe period (default: 10000)
- [ ] `TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS` — per-probe timeout (default: 2000)
- [ ] `TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD` — failures before marking down (default: 3)
- [ ] Hot-reload (SIGHUP) picks up changed health check config without restart

### 2.2 Tests

- [ ] Integration test: upstream that returns 503 is marked down after threshold failures
- [ ] Integration test: traffic is not routed to downed upstream
- [ ] Integration test: upstream recovery marks it back up after threshold successes
- [ ] Unit test: `HealthChecker` state machine transitions (up → down → half-open → up)

---

## UPGRADE 3: HTTP/3 via ngtcp2

Priority: HIGH

Current state: `src/http/quic.zig` (166 lines) and `src/http/qpack.zig` (96 lines) are
packet-parsing stubs. No handshake, no stream multiplexing, no congestion control.
These files will be replaced by a proper C binding to ngtcp2 + nghttp3.

### 3.0 ngtcp2 C Library Integration

- [ ] Add ngtcp2 and nghttp3 as build dependencies (system libs or vendored under `vendor/`)
- [ ] Add linker flags for `libngtcp2`, `libngtcp2_crypto_openssl`, `libnghttp3` in `build.zig`
- [ ] Create `src/http/ngtcp2_binding.zig` — thin Zig wrapper over the ngtcp2 C API
      covering: connection creation, packet read/write, stream open/close, crypto init
- [ ] Create `src/http/http3_handler.zig` — maps HTTP/3 stream events to Tardigrade
      `Request`/`Response` types (reusing existing structs)

### 3.1 QUIC Transport

- [ ] TLS 1.3 crypto handshake via ngtcp2_crypto_openssl (reuse existing OpenSSL context)
- [ ] UDP socket listener on configurable port (`TARDIGRADE_QUIC_PORT`, default: 443 UDP)
- [ ] Connection migration support (client IP change handling)
- [ ] Streams: bidirectional request/response, server-initiated push
- [ ] Flow control: per-stream and connection-level credit management
- [ ] Congestion control: cubic (ngtcp2 default) — no custom implementation needed
- [ ] Loss detection and packet retransmission (handled by ngtcp2 internally)
- [ ] 0-RTT early data for repeat clients
- [ ] `Alt-Svc: h3=":443"` header injected on HTTP/1.1 and HTTP/2 responses to advertise QUIC

### 3.2 HTTP/3 Layer (nghttp3)

- [ ] QPACK header compression/decompression via nghttp3
- [ ] HTTP/3 request framing (HEADERS, DATA frames)
- [ ] Server push over HTTP/3 streams
- [ ] `handleHttp3Connection()` function in `edge_gateway.zig` that mirrors
      the existing `handleHttp2Connection()` structure

### 3.3 Remove / Archive Old Stubs

- [ ] Archive `src/http/quic.zig` → `src/http/quic_stub.zig` with a comment
      explaining it was superseded by ngtcp2 binding
- [ ] Remove `src/http/qpack.zig` (nghttp3 owns QPACK now)

### 3.4 Tests

- [ ] Integration test: HTTP/3 GET request over loopback UDP completes successfully
- [ ] Integration test: concurrent HTTP/3 streams on one connection return independent responses
- [ ] Integration test: `Alt-Svc` header present on HTTP/1.1 response
- [ ] Integration test: 0-RTT session resumption completes without full handshake round-trip

---

## UPGRADE 4: FastCGI, SCGI, uWSGI — Full Protocol Implementation

Priority: HIGH

Current state: `src/http/fastcgi.zig`, `src/http/scgi.zig`, `src/http/uwsgi.zig` build
request envelopes but contain no response parsing or protocol state machines.
Requests sent to PHP-FPM or other backends via these protocols currently hang or corrupt.

### 4.0 FastCGI

- [ ] Full FastCGI record framing: FCGI_BEGIN_REQUEST, FCGI_PARAMS, FCGI_STDIN,
      FCGI_STDOUT, FCGI_STDERR, FCGI_END_REQUEST record types
- [ ] Multiplexed request IDs (single upstream connection can carry multiple requests)
- [ ] FCGI_PARAMS encoding: CGI environment variables from HTTP request
      (REQUEST_METHOD, CONTENT_TYPE, CONTENT_LENGTH, PATH_INFO, QUERY_STRING,
      REMOTE_ADDR, SERVER_NAME, SCRIPT_FILENAME, etc.)
- [ ] FCGI_STDOUT response parsing: split HTTP headers from body, map to Tardigrade response
- [ ] FCGI_STDERR capture and structured logging at WARN level
- [ ] FCGI_END_REQUEST app status check: non-zero → 502
- [ ] Connection reuse: FastCGI connection pool per upstream socket path / host:port
- [ ] File: update `src/http/fastcgi.zig` in-place (replace envelope-only code)

### 4.1 SCGI

- [ ] Full SCGI netstring request encoding with all CGI environment variables
- [ ] SCGI response parsing: HTTP/1.x status line + headers + body
- [ ] Map response to Tardigrade `Response` type
- [ ] File: update `src/http/scgi.zig` in-place

### 4.2 uWSGI

- [ ] Full uWSGI packet framing: modifier1=0 (WSGI), modifier2=0, vars array
- [ ] uWSGI response parsing: raw HTTP response unwrapping
- [ ] Chunked transfer support for streaming uWSGI responses
- [ ] File: update `src/http/uwsgi.zig` in-place

### 4.3 Config Integration

- [ ] `fastcgi_pass`, `scgi_pass`, `uwsgi_pass` directives in config file parser
- [ ] `fastcgi_param` directive for custom CGI variable injection
- [ ] `fastcgi_index` directive (default index file for directory requests)

### 4.4 Tests

- [ ] Integration test: FastCGI request to a real PHP-FPM socket returns parsed response
- [ ] Integration test: FastCGI STDERR output is logged without crashing
- [ ] Integration test: SCGI request to a Python SCGI server returns correct body
- [ ] Integration test: uWSGI request returns correct response with chunked body
- [ ] Unit test: FastCGI record encoder produces correct byte layout (compare with known-good fixture)
- [ ] Unit test: FastCGI response parser correctly splits headers from body across multiple STDOUT records

---

## UPGRADE 5: Rewrite Engine

Priority: MEDIUM

Current state: `src/http/rewrite.zig` (121 lines) matches regex patterns but has no
capture group substitution, no rewrite flags, and no break/last/redirect/permanent semantics.

### 5.0 Full Rewrite Semantics

- [ ] Capture group substitution: `$1`, `$2`, ... in replacement strings
- [ ] Named capture groups: `(?P<name>...)` → `$name` in replacement
- [ ] Rewrite flags: `last` (restart location matching), `break` (stop rewriting, continue),
      `redirect` (302), `permanent` (301)
- [ ] Rewrite chaining: multiple rules evaluated in order until first match
- [ ] Return directive: `return 301 https://example.com$request_uri`
- [ ] Conditionals: `if ($variable ~* pattern)` block support

### 5.1 Config Integration

- [ ] `rewrite` directive in `config_file.zig` parser
- [ ] `return` directive in location blocks
- [ ] `if` block parsing with variable expressions (`$http_host`, `$request_uri`, `$args`)

### 5.2 Tests

- [ ] Unit test: simple rewrite `/old/(.*)` → `/new/$1` produces correct URL
- [ ] Unit test: `redirect` flag returns 302 with correct `Location` header
- [ ] Unit test: `permanent` flag returns 301
- [ ] Unit test: `last` flag causes location re-match from top
- [ ] Unit test: multiple rules — first match wins, subsequent rules skipped
- [ ] Integration test: request to `/old/page` is rewritten to `/new/page` transparently

---

## UPGRADE 6: General-Purpose Location Block Routing

Priority: MEDIUM

Current state: `edge_gateway.zig` uses hardcoded route matching
(`/v1/chat`, `/v1/commands`, `/v1/sessions`, etc.) instead of a configurable routing table.
This makes Tardigrade useful only as the Bare Labs gateway, not as a general nginx replacement.

### 6.0 Location Block Data Model

- [ ] `LocationBlock` struct: match type (prefix, exact, regex, case-insensitive regex),
      pattern, priority, and action (proxy_pass, fastcgi_pass, return, rewrite, static root)
- [ ] Location match precedence following nginx rules:
      exact (`=`) > longest prefix (`^~`) > regex (first match) > prefix (longest match)
- [ ] Location blocks loaded from config file at startup and on SIGHUP

### 6.1 Config File Integration

- [ ] `location` block parsing in `config_file.zig`
- [ ] `proxy_pass` directive inside location blocks
- [ ] `root`, `alias` directives for static file roots
- [ ] `index` directive (directory index files)
- [ ] `try_files` directive

### 6.2 Router Integration in edge_gateway.zig

- [ ] Replace hardcoded route chains in `handleConnection()` with a lookup into the
      loaded `LocationBlock` table
- [ ] Preserve existing `/v1/chat`, `/v1/commands` etc. as default location blocks
      auto-injected when gateway-mode env vars are present
- [ ] `matchLocation(request_uri) LocationBlock` function — testable in isolation

### 6.3 Tests

- [ ] Unit test: exact match `= /health` takes priority over prefix match `/heal`
- [ ] Unit test: regex match `/api/(.*)` routes correctly
- [ ] Integration test: config with three location blocks routes requests to correct upstreams
- [ ] Integration test: SIGHUP with updated location blocks takes effect for new requests

---

## UPGRADE 7: Static File Serving in Gateway Path

Priority: MEDIUM

Current state: static file serving (MIME types, directory index, range requests) exists
in utility modules but is not wired into `edge_gateway.zig`'s `handleConnection()` path.
The main connection handler proxies everything — it cannot serve local files.

### 7.0 Static File Handler

- [ ] `serveStaticFile(allocator, root, uri_path, request, response)` function in
      `src/http/static_file.zig`
- [ ] MIME type detection (reuse existing table)
- [ ] `Last-Modified` and `If-Modified-Since` conditional GET (304)
- [ ] `ETag` generation and `If-None-Match` check (304)
- [ ] Range request support (reuse `src/http/range.zig`)
- [ ] Directory index: check for `index.html` / `index.htm` before directory listing
- [ ] `autoindex on/off` config toggle
- [ ] Sendfile-style zero-copy on Linux (`sendfile(2)`) for large files
- [ ] Path traversal sanitisation: reject any resolved path that escapes `root`

### 7.1 Integration into handleConnection()

- [ ] When a `LocationBlock` has `root` set, dispatch to `serveStaticFile()`
- [ ] Correct `Content-Type`, `Content-Length`, `Accept-Ranges` headers

### 7.2 Tests

- [ ] Unit test: path traversal `/../../../etc/passwd` is rejected with 403
- [ ] Unit test: MIME type for `.wasm` file is `application/wasm`
- [ ] Integration test: `GET /index.html` serves correct file contents
- [ ] Integration test: `GET /` with no index file and `autoindex on` returns directory listing
- [ ] Integration test: `If-Modified-Since` matching file mtime returns 304
- [ ] Integration test: `Range: bytes=0-999` returns correct partial content with 206

---

## UPGRADE 8: Custom Error Pages

Priority: MEDIUM

Current state: all error responses are JSON API envelopes. There is no mechanism to
serve a custom HTML error page configured in the location block.

### 8.0 Error Page Handler

- [ ] `error_page` directive in config file: `error_page 404 /errors/404.html`
- [ ] Support multiple status codes per directive: `error_page 500 502 503 504 /50x.html`
- [ ] `error_page` can redirect to an absolute URI: `error_page 404 https://example.com/missing`
- [ ] Internally, error page is served via `serveStaticFile()` — reuses MIME type and
      caching headers
- [ ] Error page overrides JSON envelope for non-API routes (detected by `Accept` header)
- [ ] API routes (`/v1/...`) always use JSON error envelope regardless of `error_page` config

### 8.1 Tests

- [ ] Integration test: 404 on a static root with `error_page 404 /errors/404.html`
      returns the HTML file with status 404
- [ ] Integration test: API route 404 still returns JSON envelope even with `error_page` set

---

## UPGRADE 9: handleConnection() Refactor

Priority: MEDIUM

Current state: `handleConnection()` in `edge_gateway.zig` is 1,674 lines handling
request parsing, middleware, routing, proxying, WebSocket, SSE, and all backend protocol
stubs in a single function. This is a maintenance and correctness risk.

### 9.0 Split into Focused Handlers

- [ ] Extract `runMiddlewarePipeline(ctx)` — auth, rate limit, request limits, policy eval
- [ ] Extract `routeRequest(ctx, location)` — dispatches to correct backend handler
- [ ] Extract `handleProxyRequest(ctx, upstream)` — HTTP proxy with retry and caching
- [ ] Extract `handleWebSocketUpgrade(ctx)` — WebSocket handshake and proxy loop
- [ ] Extract `handleSseStream(ctx)` — SSE connection lifecycle
- [ ] Extract `handleStaticFile(ctx, root)` — delegates to `serveStaticFile()`
- [ ] `handleConnection()` becomes: parse request → run middleware → match location → route

### 9.1 GatewayState Mutex Partitioning

- [ ] Replace single `GatewayState.mutex` with per-subsystem locks:
  - `rate_limiter_mutex` — guards `RateLimiter`
  - `session_mutex` — guards `SessionStore`
  - `metrics_mutex` — guards `Metrics`
  - `upstream_mutex` — guards upstream health state
  - `command_mutex` — guards command lifecycle map
- [ ] Alternatively: make `RateLimiter` and `Metrics` lock-free using atomic operations
      where update semantics allow it (counters, gauges)

### 9.2 Per-Request Arena Allocator

- [ ] Verify every code path through `handleConnection()` and its extracted functions
      frees all allocations on both success and error return
- [ ] Use a single `ArenaAllocator` per request, freed unconditionally at connection handler exit
- [ ] Add compile-time check or Valgrind/ASAN run to confirm no leaks across request paths

### 9.3 Tests (regression guards before and after refactor)

- [ ] All existing unit tests pass unchanged after refactor
- [ ] All integration tests from UPGRADE 1 pass after refactor
- [ ] No performance regression: benchmark `wrk` before and after at 1k req/s

---

## UPGRADE 10: Config System Hardening

Priority: MEDIUM

### 10.0 Config Validation

- [ ] On startup, validate all referenced file paths exist (cert, key, error page roots)
- [ ] Validate upstream URLs are well-formed
- [ ] Validate port numbers are in range
- [ ] Validate that env var overrides do not conflict with file config (warn, don't crash)
- [ ] On SIGHUP, validate new config before applying — roll back if invalid

### 10.1 Log Rotation

Resolved: size-based log rotation implemented in `src/main.zig` (`rotateLogFiles`).
`TARDIGRADE_ERROR_LOG_PATH`, `TARDIGRADE_LOG_ROTATE_MAX_BYTES`, and
`TARDIGRADE_LOG_ROTATE_MAX_FILES` env vars control the behaviour.
Generation shifting (`error.log` → `error.log.1` → ...) and trim are tested.

- [x] Max log file size + automatic rotation when size exceeded (configurable)
- [x] Generation retention control (`TARDIGRADE_LOG_ROTATE_MAX_FILES`)
- [ ] On `SIGUSR1`: close and reopen log file (standard log rotation signal for external rotators like logrotate)

### 10.2 Virtual Hosts (Server Blocks)

- [ ] `server { server_name ...; ... }` blocks in config parsed by `config_file.zig`
- [ ] On incoming connection, match `Host` header to correct `ServerBlock`
- [ ] Each `ServerBlock` has its own location table, upstream pool, and TLS config
- [ ] Default server block for unmatched hosts

### 10.3 Tests

- [ ] Unit test: config with missing cert path fails validation with clear error
- [ ] Integration test: SIGHUP with invalid config does not disrupt in-flight requests
- [ ] Integration test: two virtual hosts on same port route to separate upstreams

---

## UPGRADE 11: Mail Proxy

Priority: LOW

Current state: `handleMailProxyRoute()` is called in `edge_gateway.zig` but no protocol
implementation exists. This is a stub.

### 11.0 SMTP Proxy

- [ ] TCP stream relay for SMTP (port 25 / 587 / 465)
- [ ] STARTTLS upgrade support
- [ ] Auth header injection for upstream relay
- [ ] `smtp_pass` config directive

### 11.1 IMAP Proxy

- [ ] TCP stream relay for IMAP (port 143 / 993)
- [ ] STARTTLS support
- [ ] `imap_pass` config directive

### 11.2 POP3 Proxy

- [ ] TCP stream relay for POP3 (port 110 / 995)
- [ ] `pop3_pass` config directive

### 11.3 Tests

- [ ] Integration test: SMTP relay forwards EHLO and DATA through to test upstream
- [ ] Integration test: IMAP LOGIN command is proxied and response returned to client

---

## UPGRADE 12: Approval Workflow Hardening

Priority: MEDIUM

Current state: approval workflows (`POST /v1/approvals/request`, `POST /v1/approvals/respond`,
`GET /v1/approvals/status`) were added in Phase 14 and are functional but in-memory only.
Approval state is process-local and lost on restart or worker respawn.

### 12.0 Persistent Approval Store

- [ ] Persist approval entries to disk (JSON file or SQLite via `TARDIGRADE_APPROVAL_STORE_PATH`)
- [ ] On startup, load existing pending/escalated approvals from store (resume across restarts)
- [ ] Atomic write-on-change (write to `.tmp` then rename) to prevent corrupt state on crash
- [ ] Worker processes in master-worker mode must share approval state via the master process
      (IPC or shared file) — currently each worker has its own in-memory map

### 12.1 Approval TTL & Escalation

- [ ] Configurable default approval TTL (`TARDIGRADE_APPROVAL_TTL_MS`, default: 300000)
- [ ] Escalation target: configurable webhook URL or SSE topic to notify on escalation
      (`TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK`)
- [ ] Escalation fires an HTTP POST with the approval snapshot JSON to the webhook URL
- [ ] Expired approvals are pruned from the store after a configurable retention window

### 12.2 Security

- [ ] Approval tokens must be single-use for `respond` — once decided, token is locked
- [ ] Rate limit `POST /v1/approvals/request` per identity (prevent approval flood)
- [ ] `actor` field in respond endpoint must be an authenticated identity, not free-form string

### 12.3 Tests

- [ ] Integration test: approval token created → responded → status reflects decision
- [ ] Integration test: pending approval auto-escalates after TTL expires
- [ ] Integration test: responding twice to the same token returns 409
- [ ] Integration test: unauthenticated `POST /v1/approvals/respond` returns 401
- [ ] Integration test: approval store survives process restart (persistent store)
- [ ] Integration test: route gated by approval policy returns 202 with approval token,
      then proceeds after approval is granted

---

## UPGRADE 13: WebSocket Multiplexing Hardening

Priority: MEDIUM

Current state: `/v1/ws/mux` was added in Phase 14. It supports named channels,
event pub/sub, and async command push over a single WebSocket connection.
Per-device topic namespacing is enforced. However, there are several production gaps.

### 13.0 Backpressure & Flow Control

- [ ] Detect slow mux clients: if the write buffer for a client grows beyond a configurable
      threshold (`TARDIGRADE_MUX_WRITE_BUFFER_MAX`), drop the oldest frames and send
      a `{"type":"overflow","dropped":N}` frame to the client
- [ ] Per-channel subscription limit per device
      (`TARDIGRADE_MUX_MAX_CHANNELS_PER_DEVICE`, default: 50)

### 13.1 Reconnect & State Recovery

- [ ] `Last-Event-ID`-style resume for mux channels: client can reconnect and receive
      missed events since a given sequence ID (reuse `event_hub.zig` replay logic)
- [ ] Channel state is preserved for a configurable grace period after disconnect
      (`TARDIGRADE_MUX_RECONNECT_GRACE_MS`, default: 30000)

### 13.2 Observability

- [ ] Active mux connection count exposed in `GET /metrics`
- [ ] Per-device channel subscription count exposed in `GET /metrics`
- [ ] Mux frame errors (parse failures, oversized payloads) counted in metrics

### 13.3 Tests

- [ ] Integration test: client subscribes to a channel, event is published, frame received
- [ ] Integration test: client sends command via mux channel, async update frame returned
- [ ] Integration test: per-device topic isolation — device A cannot receive device B events
- [ ] Integration test: unauthenticated connection to `/v1/ws/mux` returns 401
- [ ] Integration test: missing `X-Device-ID` returns 400
- [ ] Integration test: slow client overflow drops frames and sends overflow notice
- [ ] Integration test: reconnecting client with sequence ID receives missed events

---

## Upgrade Priority Summary

| # | Upgrade | Priority | Effort |
|---|---------|----------|--------|
| 1 | Test infrastructure + integration tests | CRITICAL | High |
| 2 | Active health checks | HIGH | Medium |
| 3 | HTTP/3 via ngtcp2 | HIGH | High |
| 4 | FastCGI / SCGI / uWSGI full protocols | HIGH | High |
| 5 | Rewrite engine | MEDIUM | Medium |
| 6 | General-purpose location routing | MEDIUM | Medium |
| 7 | Static file serving in gateway path | MEDIUM | Medium |
| 8 | Custom error pages | MEDIUM | Low |
| 9 | handleConnection() refactor + mutex split | MEDIUM | Medium |
| 10 | Config system hardening | MEDIUM | Medium |
| 11 | Mail proxy | LOW | High |
| 12 | Approval workflow hardening (persistence, escalation webhook, security) | MEDIUM | Medium |
| 13 | WebSocket mux hardening (backpressure, reconnect, observability) | MEDIUM | Medium |

Recommended sequencing:
1. UPGRADE 1 (tests) first — no new features without a regression net
2. UPGRADE 9 (refactor) before adding more to edge_gateway.zig
3. UPGRADE 2 + 7 + 8 in parallel (independent modules)
4. UPGRADE 4 (FastCGI/SCGI/uWSGI) once refactor is done
5. UPGRADE 6 (location routing) enables 5 + 7 + 8 to work generically
6. UPGRADE 3 (HTTP/3) as a standalone track after the above stabilise
7. UPGRADE 12 + 13 once the test suite from UPGRADE 1 covers the approval and mux paths
8. UPGRADE 10 + 11 last
