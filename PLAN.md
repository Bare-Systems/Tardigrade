# Tardigrade - Zig nginx Replacement

## Project Vision

Build a high-performance HTTP server in Zig as a complete replacement for nginx while also acting as the secure gateway and runtime edge for Bare Labs services.

The project has two parallel goals:

1. nginx parity — full high-performance HTTP server functionality
2. Agent Gateway — a secure edge gateway for BearClaw and Panda clients

Tardigrade should eventually function as:

- HTTP server
- reverse proxy
- API gateway
- event stream broker
- TLS termination point
- Bare Labs service mesh edge

## Updated Architecture Role

Panda (iOS app)
      |
      | HTTPS / WebSocket / SSE
      v
Tardigrade (gateway / runtime edge)
      |
      v
BearClaw
      |
      |- Koala
      |- Polar
      |- Kodiak
      |- Ursa
      |- Bear Arms

Responsibilities:

Component | Responsibility
---|---
Panda | client UI / secure device
Tardigrade | secure gateway + runtime
BearClaw | agent brain
Other services | internal tools

## COMPLETE NGINX FEATURE PARITY ROADMAP

Keep the existing roadmap content, but reorganize phases so a gateway MVP happens early.

## PHASE 0: Gateway Foundations (NEW)
Priority: CRITICAL

These features allow Tardigrade to become the Panda/BearClaw gateway early.

### 0.0 Remote BearClaw MVP Track (NEW)
- [x] edge runtime config (`listen_host`, `listen_port`, `tls_cert_path`, `tls_key_path`, `upstream_base_url`)
- [x] `GET /health` gateway status route
- [x] authenticated `POST /v1/chat` route
- [x] static bearer token auth with SHA-256 token hash allowlist
- [x] JSON request validation for `{ "message": "..." }`
- [x] request forwarding to BearClaw `http://127.0.0.1:8080/v1/chat`
- [x] `X-Correlation-ID` propagation downstream and in responses
- [x] stable API error mapping (`unauthorized`, `invalid_request`, `rate_limited`, `tool_unavailable`, `upstream_timeout`, `internal_error`) with `request_id`
- [x] structured audit logging (`route`, `status`, `auth_ok`, `correlation_id`, `latency_ms`)
- [x] publish Linux binary artifact to GitHub Releases (`tardigrade-linux-x86_64.tar.gz`)
- [x] document release download/install path in README (`releases/latest/download`)
- [x] native HTTPS socket termination in Zig runtime

Resolved: native TLS termination implemented via OpenSSL-backed server handshake in `src/http/tls_termination.zig` and integrated into worker connection handling in `src/edge_gateway.zig`. When `TARDIGRADE_TLS_CERT_PATH` and `TARDIGRADE_TLS_KEY_PATH` are set, accepted sockets perform TLS handshake before HTTP parsing.

### 0.1 Identity & Authentication
- [x] Bearer token authentication
- [ ] Device identity registration
- [ ] Public/private key device authentication
- [x] Auth middleware pipeline
- [x] Request auth context propagation
- [x] Token validation hooks
- [ ] Token expiration / refresh logic

Resolved: Auth middleware pipeline implemented via `RequestContext` in `src/http/request_context.zig`. Auth identity (token hash) is propagated through the request context and included in structured audit logs.

Resolved: HTTP bearer token parsing/validation is implemented in `src/http/auth.zig`, including an optional validation hook callback for pluggable token verification.
Decision: core HTTP layer validates RFC6750-style token shape and delegates token trust decisions to caller-provided hooks to keep auth-provider logic decoupled.

### 0.2 Session Management
- [x] Session token issuance
- [x] Session storage abstraction
- [x] Device session tracking
- [x] Revocation support

Resolved: Session management implemented in `src/http/session.zig`. In-memory session store with cryptographic token generation (32 bytes / 256 bits), per-identity revocation, device ID tracking, idle TTL expiry, and max-session enforcement. Gateway endpoints: POST /v1/sessions (create), DELETE /v1/sessions (revoke), GET /v1/sessions (list). Sessions accepted as auth alternative to bearer tokens on /v1/chat.

### 0.3 API Gateway Core
- [x] JSON request validation
- [x] API version routing
- [x] Correlation IDs
- [x] Idempotency key support
- [x] Request metadata injection

Resolved: `X-Correlation-ID` propagation is implemented for static-file and parse-error responses.
Decision: trust and echo only safe token-style incoming IDs; generate `tg-<timestamp>-<random-hex>` when missing/invalid.

Resolved: API version routing implemented in `src/http/api_router.zig`. Parses `/v<N>/...` paths and validates against supported version allowlist.
Resolved: Idempotency key support implemented in `src/http/idempotency.zig` with in-memory TTL cache and replay headers.
Resolved: Request metadata injection handled by `RequestContext` which captures client IP, API version, identity, and timing.

### 0.4 Agent Command Routing
- [x] structured command routing
- [x] upstream request envelope
- [x] authenticated request forwarding
- [x] request auditing

Resolved: Command routing implemented in `src/http/command.zig`. Structured command envelope with typed commands (chat, tool.list, tool.run, status), params validation, and inline idempotency key support. Gateway `POST /v1/commands` endpoint wraps commands in upstream envelope with identity, correlation ID, client IP, API version, and timestamp context. Structured `CommandAudit` log for every command.

## PHASE 1: Core HTTP Server Foundation

### 1.1 HTTP/1.1 Protocol Compliance
- [x] Full request parser (method, URI, version, headers, body)
- [x] Request line parsing with proper validation
- [x] Header parsing (case-insensitive, multi-line values)
- [x] Request body handling (Content-Length, chunked)
- [x] Response builder with status codes (1xx-5xx)
- [x] Proper header generation (Date, Server, Content-Length, etc.)
- [x] Connection: keep-alive / close handling
- [x] HTTP method support: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS

### 1.2 Static File Serving
- [x] MIME type detection (50+ common types)
- [x] Directory index (index.html, index.htm)
 - [x] Directory listing (autoindex)
- [x] Range requests (partial content, byte ranges)
 - [x] Last-Modified and If-Modified-Since

### 1.3 Error pages
- [x] Custom error pages (400, 401, 403, 404, 500, 502, 503, 504)
- [x] Error logging with levels
- [x] Graceful error responses

Resolved: custom error pages implemented and samples added under `public/errors/`. Error logging with severity levels via structured logger (see 1.4). Graceful error responses via API error envelope with request_id.

### 1.4 Basic Logging
- [x] Access log (combined format)
- [x] Error log with severity levels
- [x] Timestamps and request IDs
- [ ] Log rotation support

Resolved: Structured JSON logger implemented in `src/http/logger.zig`. Configurable severity levels (DEBUG/INFO/WARN/ERROR) via `TARDIGRADE_LOG_LEVEL` env var. JSON output to stderr with ISO 8601 timestamps, correlation IDs, and component names. Gateway uses structured logger for all startup and request-level logging.

## PHASE 2: Async I/O & Performance

### 2.1 Event Loop
- [x] epoll (Linux) / kqueue (macOS/BSD) abstraction
- [x] Non-blocking socket I/O
- [x] Event-driven connection handling
- [x] Timer management for timeouts

Resolved (incremental): Event loop foundation implemented in `src/http/event_loop.zig` with runtime backend selection (`epoll` on Linux, `kqueue` on macOS/BSD), readable-fd registration, and timeout-based waits. Gateway listener in `src/edge_gateway.zig` now runs non-blocking and accepts connections from event notifications rather than blocking `accept()`.
Decision: for compatibility with current request parser/proxy path, accepted client sockets are switched back to blocking mode before `handleConnection`; full non-blocking per-connection read/write state machines are deferred to 2.2/2.3.
Resolved: Timer manager (`TimerManager`) now drives periodic loop ticks for timeout/housekeeping hooks and keeps graceful shutdown responsive even when no new clients connect.

### 2.2 Connection Management
- [x] Connection pooling
- [x] Keep-alive with configurable timeout
- [x] Request pipelining
- [x] Connection limits per IP
- [x] Graceful connection draining

Resolved (incremental): worker connection handlers now borrow/release `ConnectionSession` state from a shared thread-safe session pool (`ConnectionSessionPool`) instead of stack-local one-off session state. Pool size is configurable via `TARDIGRADE_CONNECTION_POOL_SIZE`.
Resolved (incremental): listener accept path now enforces active per-IP connection slots with fd-to-ip lifecycle tracking. Limit is configured via `TARDIGRADE_MAX_CONNECTIONS_PER_IP` (0 = disabled).
Decision: connection limits are enforced before worker queue dispatch; rejected sockets are closed immediately to keep worker capacity available for accepted clients.
Resolved (incremental): worker connection handlers now serve multiple sequential requests on the same client socket when `Connection: keep-alive` is allowed. Idle keep-alive timeout and max requests per connection are configurable via `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` and `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION`.
Resolved (incremental): request pipelining boundary handling is now supported via per-connection pending-byte carry-over. Extra bytes beyond the first parsed request are preserved and consumed by subsequent request iterations on the same connection.
Resolved: graceful connection draining is now explicit at shutdown: the listener stops accepting new sockets, the worker pool drains queued/in-flight connection work before join, and in-flight keep-alive responses switch to `Connection: close` once shutdown is requested.

### 2.3 Worker Model
- [x] Multi-threaded worker pool
- [x] Thread-safe shared state
- [x] Work stealing / load balancing between workers
- [x] Graceful shutdown with connection draining

Resolved (incremental): Connection handling is now dispatched from the listener event loop into a fixed-size worker thread pool (`src/http/worker_pool.zig`). Accepted sockets are queued with bounded capacity and processed by workers so blocking upstream calls no longer stall the listener loop.
Decision: shared mutable runtime components (rate limiter, idempotency cache, session store, circuit breaker, metrics) are synchronized behind gateway state locks to preserve existing behavior while enabling concurrent request execution.
Resolved: worker queueing now uses per-worker queues with least-loaded submit selection and worker-side stealing when local queues are empty. This provides basic load balancing and reduces head-of-line blocking from single-queue dispatch contention.
Resolved: worker shutdown now supports graceful draining; when drain mode is enabled, pool shutdown waits for queued and in-flight connection jobs to finish before joining worker threads.

### 2.4 Memory Management
- [x] Arena allocators for request scope
- [x] Buffer pooling
- [x] Zero-copy where possible
- [x] Memory limits per connection

Resolved (incremental): request handling path now uses a request-scoped arena allocator in `src/edge_gateway.zig`, reducing allocator churn and centralizing per-request memory cleanup at end-of-request.
Resolved: shared thread-safe byte buffer pools are now used for both request read buffers and proxy relay buffers (`src/http/buffer_pool.zig`, integrated in gateway state), reducing allocation churn on hot connection/proxy paths.
Resolved: per-connection memory budgets are now enforced via `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES`; oversized request/proxy buffering paths are bounded to this cap.
Decision: zero-copy is applied where practical in current architecture by relaying upstream stream chunks directly from pooled relay buffers to downstream writers without intermediate heap copies.

## PHASE 3: Configuration System

### 3.1 Configuration File Parser
- [ ] keep-alive integration tests (low priority)
- [ ] nginx-like syntax OR YAML/TOML
- [ ] Include directive for modular configs
- [ ] Variable interpolation
- [ ] Syntax validation with helpful errors

### 3.2 Core Directives
- [ ] worker_processes
- [ ] worker_connections
- [ ] error_log
- [ ] pid file
- [ ] user/group (privilege dropping)

### 3.3 HTTP Block Directives
- [ ] server blocks (virtual hosts)
- [ ] listen (address:port, ssl, http2)
- [ ] server_name (wildcards, regex)
- [ ] root / alias
- [ ] location blocks (prefix, exact, regex)
- [ ] try_files
- [ ] return / rewrite
- [ ] if conditionals (limited)

### 3.4 Hot Reload
- [ ] SIGHUP configuration reload
- [ ] Zero-downtime reload
- [ ] Configuration validation before apply

### 3.5 Secret Management (NEW)
- [ ] encrypted secret storage
- [ ] environment overrides
- [ ] runtime secret reload
- [ ] key rotation support

Secrets may include:

- TLS keys
- auth signing keys
- upstream API credentials
- service tokens

## PHASE 4: Reverse Proxy

### 4.1 Basic Proxying
- [x] proxy_pass directive
- [x] Backend connection pooling
- [x] Request/response streaming
- [x] Header manipulation (add, remove, modify)
- [x] X-Forwarded-For, X-Real-IP
- [x] X-Forwarded-Proto, X-Forwarded-Host
- [x] Host header rewriting

Resolved (incremental): Gateway upstream proxy calls now flow through a shared proxy request helper that rewrites/augments forwarding headers (`X-Forwarded-*`, `X-Real-IP`) and rewrites `Host` to upstream authority.
Resolved: basic proxy_pass-style routing now supports config-driven targets for `/v1/chat` and `/v1/commands` subpaths via `TARDIGRADE_PROXY_PASS_CHAT` and `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` (absolute URL or path mode).
Resolved (incremental): `/v1/chat` and `/v1/commands` now support streamed relay for successful upstream responses via chunked downstream writes, avoiding full buffering on the hot path.
Resolved: upstream requests now use a shared `std.http.Client` in gateway state with keep-alive enabled, allowing backend connection reuse across requests.
Resolved (incremental): added optional full-status streaming mode via `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` to relay non-200 upstream responses directly when desired.
Resolved (incremental): buffered proxy responses now preserve upstream `Content-Type` and `Content-Disposition` metadata for successful upstream responses, reducing streamed vs buffered response behavior drift.
Decision: default behavior still maps non-200 upstream errors into stable gateway error envelopes; full-status passthrough streaming is opt-in to preserve compatibility.

### 4.2 Upstream Management
- [ ] upstream blocks
- [x] Multiple backend servers
- [ ] Server weights
- [ ] Backup servers
- [x] max_fails / fail_timeout

Resolved (incremental): edge config now supports multiple upstream base URLs via `TARDIGRADE_UPSTREAM_BASE_URLS` (comma-separated), enabling multi-backend proxy target selection at runtime.
Resolved (incremental): passive-failure upstream controls added via `TARDIGRADE_UPSTREAM_MAX_FAILS` and `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS`.

### 4.3 Load Balancing Algorithms
- [x] Round-robin (default)
- [ ] Least connections
- [ ] IP hash (session persistence)
- [ ] Generic hash
- [ ] Random with two choices

Resolved (incremental): proxy upstream base URL selection now uses round-robin rotation per request across configured upstream base URLs.

### 4.4 Health Checks
- [x] Passive health checks (mark failed on errors)
- [ ] Active health checks (periodic probes)
- [ ] Configurable thresholds
- [ ] Slow start for recovered servers

Resolved (incremental): proxy path now tracks upstream failures and marks backends temporarily unhealthy after configured failure thresholds; round-robin selection skips unhealthy upstreams until fail-timeout expires.

### 4.5 Proxy Protocol Support
- [ ] Protocol v1 and v2
- [ ] Extracting real client IP

### 4.6 Service Trust Model (NEW)
- [ ] trusted upstream configuration
- [ ] signed upstream headers
- [ ] auth context forwarding
- [ ] upstream identity verification

### 4.7 Unix Socket Upstreams (NEW)
- [ ] unix domain socket backends
- [ ] local IPC routing
- [ ] socket-based load balancing

## PHASE 5: Caching

### 5.1 Proxy Cache
- [ ] proxy_cache_path (disk-based)
- [ ] Cache key configuration
- [ ] Cache validity rules
- [ ] Cache bypass conditions
- [ ] Cache purging

### 5.2 Advanced Caching
- [ ] Stale content serving (stale-while-revalidate)
- [ ] Cache locking (single request populates)
- [ ] Background cache updates
- [ ] Cache manager process
- [ ] Memory + disk tiered caching

### 5.3 Browser Caching
- [x] Expires header
- [x] Cache-Control header
- [x] ETag/Last-Modified validation

Resolved: Cache-Control and Expires headers implemented in `src/http/cache_control.zig`. CachePolicy struct with directives (max-age, public, private, no-cache, no-store, must-revalidate, immutable). Preset policies for static assets, APIs, and no-caching. MIME-type based policy selection. ETag/Last-Modified already implemented in earlier phases.

## PHASE 6: Security Features

### 6.1 Access Control
- [x] allow/deny directives (IP-based)
- [x] CIDR notation support
- [ ] Geo-based blocking (via external data)

Resolved: IP access control implemented in `src/http/access_control.zig`. Supports allow/deny rules with CIDR notation (IPv4 and IPv6). First-match-wins evaluation order. Configurable via `TARDIGRADE_ACCESS_CONTROL` env var (e.g. `"allow 10.0.0.0/8, deny 0.0.0.0/0"`). Applied before rate limiting in the gateway pipeline.

### 6.2 Rate Limiting
- [x] limit_req (request rate)
- [ ] limit_conn (connection count)
- [x] Configurable zones and keys
- [x] Burst handling
- [x] Custom rejection responses

Resolved: Token-bucket rate limiter implemented in `src/http/rate_limiter.zig`. Per-IP tracking with configurable RPS and burst. Returns 429 with stable API error envelope.

### 6.3 Authentication
- [x] HTTP Basic Auth
- [ ] Auth request (subrequest-based)
- [ ] JWT validation (optional module)

Resolved: HTTP Basic Auth implemented in `src/http/basic_auth.zig`. Parses `Authorization: Basic <base64>` headers, decodes credentials, and verifies against SHA-256 hashes of "user:password" strings. Configured via `TARDIGRADE_BASIC_AUTH_HASHES` env var. Integrated as fallback auth method after bearer token in the gateway pipeline.

### 6.4 Request Validation
- [x] Request body size limits (client_max_body_size)
- [x] Header count/size limits
- [x] URI length limits
- [x] Timeout enforcement (client_body_timeout, etc.)

Resolved: Request validation limits enforced in gateway pipeline via `src/http/request_limits.zig`. Body size (413), URI length (414), and header count (400) validated after parsing. Configurable via env vars: `TARDIGRADE_MAX_BODY_SIZE`, `TARDIGRADE_MAX_URI_LENGTH`, `TARDIGRADE_MAX_HEADER_COUNT`, `TARDIGRADE_MAX_HEADER_SIZE`.
Resolved (incremental): socket-level timeout enforcement is now active in `src/edge_gateway.zig`. Accepted client sockets apply configured header timeout (`TARDIGRADE_HEADER_TIMEOUT_MS`) and upstream proxy sockets apply `TARDIGRADE_UPSTREAM_TIMEOUT_MS` for send/receive operations.

### 6.5 Security Headers
- [ ] add_header directive
- [x] X-Frame-Options
- [x] X-Content-Type-Options
- [x] Content-Security-Policy
- [x] Strict-Transport-Security

Resolved: Security headers middleware implemented in `src/http/security_headers.zig` with default secure and API presets. Also adds Referrer-Policy, Permissions-Policy, and X-XSS-Protection.

### 6.6 Policy Engine (NEW)
- [ ] route-level policy evaluation
- [ ] device-based restrictions
- [ ] per-user scopes
- [ ] approval-required routes
- [ ] time-based policy rules

## PHASE 7: TLS / SSL

### 7.1 Basic TLS
- [ ] TLS termination
- [ ] Certificate and key loading
- [ ] TLS 1.2 / 1.3 support
- [ ] Cipher suite configuration
- [ ] Protocol version selection

### 7.2 Advanced TLS
- [ ] SNI (Server Name Indication)
- [ ] Multiple certificates per server
- [ ] Session resumption (session cache)
- [ ] Session tickets
- [ ] OCSP stapling

### 7.3 Client Certificates
- [ ] Client certificate verification
- [ ] Certificate chain validation
- [ ] CRL checking

### 7.4 Certificate Management
- [ ] Dynamic certificate loading
- [ ] ACME/Let's Encrypt integration (optional)

## PHASE 8: HTTP/2 & HTTP/3

### 8.1 HTTP/2
- [ ] HPACK header compression
- [ ] Stream multiplexing
- [ ] Server push
- [ ] Priority handling
- [ ] Flow control
- [ ] HTTP/2 to HTTP/1.1 backend translation

### 8.2 HTTP/3 (QUIC)
- [ ] QUIC protocol implementation
- [ ] 0-RTT connection establishment
- [ ] Connection migration
- [ ] QPACK header compression

## PHASE 9: WebSocket & Event Streaming

### 9.1 WebSocket Proxying
- [ ] upgrade handling
- [ ] bidirectional proxying
- [ ] wss support

### 9.2 WebSocket Runtime
- [ ] ping/pong
- [ ] idle timeout
- [ ] load balancing

### 9.3 Server-Sent Events (NEW)
- [ ] SSE protocol support
- [ ] long-lived stream connections
- [ ] reconnect tokens
- [ ] stream backpressure

### 9.4 Event Fanout (NEW)
- [ ] event broadcast to subscribers
- [ ] topic-based subscriptions
- [ ] event buffering
- [ ] slow client protection

## PHASE 10: Compression

### 10.1 Response Compression
- [x] gzip compression
- [ ] gzip_static (pre-compressed files)
- [ ] Brotli compression
- [x] Compression level configuration
- [x] MIME type filtering
- [x] Minimum size threshold

Resolved: Gzip response compression implemented in `src/http/compression.zig`. One-shot compression with MIME-type filtering (text/*, JSON, XML, JS, SVG, WASM), configurable min size (default 256 bytes), and compression level. Applied to proxy response paths in the gateway. Configurable via `TARDIGRADE_COMPRESSION_ENABLED` and `TARDIGRADE_COMPRESSION_MIN_SIZE`.

### 10.2 Decompression
- [ ] gunzip for backends that don't support it

## PHASE 11: Advanced Features

### 11.1 URL Rewriting
- [ ] rewrite directive (regex-based)
- [ ] Rewrite flags (last, break, redirect, permanent)
- [ ] return directive
- [ ] Conditional rewriting

### 11.2 Request Processing
- [ ] Sub-requests
- [ ] Internal redirects
- [ ] Named locations
- [ ] Mirror requests

### 11.3 Backend Protocols
- [ ] FastCGI proxy
- [ ] uWSGI proxy
- [ ] SCGI proxy
- [ ] gRPC proxy
- [ ] Memcached integration

### 11.4 Mail Proxy (Optional)
- [ ] SMTP proxy
- [ ] IMAP proxy
- [ ] POP3 proxy

### 11.5 TCP/UDP Proxy (Stream Module)
- [ ] Generic TCP proxying
- [ ] UDP proxying
- [ ] Stream SSL termination

## PHASE 12: Observability

### 12.1 Logging
- [ ] Custom log formats
- [ ] Conditional logging
- [ ] JSON log format
- [ ] Access log buffering
- [ ] Syslog integration

### 12.2 Metrics
- [x] Stub status endpoint
- [ ] Connection statistics
- [x] Request statistics
- [ ] Upstream health status
- [x] Prometheus metrics export (optional)

Resolved: `GET /metrics` endpoint added to gateway. `Metrics` struct in `src/http/metrics.zig` tracks total requests and status class counts (2xx/3xx/4xx/5xx) with uptime. All gateway response paths record metrics automatically. `GET /metrics/prometheus` endpoint added returning Prometheus text exposition format (v0.0.4).

### 12.3 Debugging
- [x] Debug logging
- [x] Request tracing
- [ ] Error categorization

Resolved: Structured access log implemented in `src/http/access_log.zig`. `AccessLogEntry` emits a `"type":"access"` JSON line to stderr per completed request with method, path, status, latency, client IP, correlation ID, identity, and user agent fields. The `logAccess()` helper in the gateway replaces all 35 `ctx.auditLog()` key=value callsites with structured JSON output suitable for log aggregation.

### 12.4 Admin API
- [ ] route inspection
- [ ] active connections
- [ ] stream status
- [ ] upstream health
- [ ] loaded certificates
- [ ] auth/device registry

## PHASE 13: Production Hardening

### 13.1 Process Management
- [ ] Master/worker process model
- [x] Graceful shutdown (SIGTERM/SIGQUIT)
- [ ] Binary upgrade (SIGUSR2)
- [ ] Worker process recycling
- [ ] CPU affinity

Resolved: Graceful shutdown implemented in `src/http/shutdown.zig`. SIGTERM and SIGINT handlers set a global atomic flag. With the Phase 2.1 event loop, the listener no longer blocks indefinitely in `accept()`, so shutdown is serviced on the next event-loop tick even when the server is idle.

### 13.2 Resource Limits
- [ ] File descriptor limits
- [ ] Worker connection limits
- [ ] Memory limits
- [ ] Request queue limits

### 13.3 Privilege Management
- [ ] Run as unprivileged user
- [ ] Privilege dropping after bind
- [ ] Chroot support (optional)

### 13.4 Resilience Features
- [x] circuit breakers
- [x] retry policies
- [x] timeout budgets
- [ ] overload protection
- [ ] request queue management

Resolved: Upstream circuit breaker implemented in `src/http/circuit_breaker.zig`. Three-state machine (closed/open/half-open) with configurable failure threshold (`TARDIGRADE_CB_THRESHOLD`, default 0 = disabled), recovery timeout (`TARDIGRADE_CB_TIMEOUT_MS`, default 30 s), and probe success count. Applied to `/v1/chat` and `/v1/commands` proxy calls; returns 503 `upstream_unavailable` when circuit is open. Circuit breaker state logged on failure and at startup.
Resolved (incremental): upstream retry policy added for proxy requests. `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` controls attempt count (minimum 1); with multiple configured upstream base URLs, retries rotate across upstream targets.
Resolved (incremental): request-level upstream timeout budgets added via `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS`; retry attempts now share a single total timeout budget to prevent runaway cumulative wait time.

## PHASE 14: Real-Time Messaging Gateway

This phase enables Tardigrade to function as the BearClaw gateway.

### 14.1 Command Protocol
- [ ] structured command envelopes
- [ ] command lifecycle tracking
- [ ] async command completion

### 14.2 Stream Multiplexing
- [ ] multiplex multiple streams
- [ ] command + event streams
- [ ] per-device stream isolation

### 14.3 Approval Workflows
- [ ] approval request routing
- [ ] approval response handling
- [ ] timeout escalation

## IMPLEMENTATION PRIORITY ORDER

Tier 1: Gateway MVP

1. HTTP parser
2. Response builder
3. Async I/O
4. TLS termination
5. Reverse proxy
6. WebSocket support
7. Authentication middleware
8. Basic configuration
9. Request size limits
10. Connection timeouts

At this stage iOS -> Tardigrade -> BearClaw communication works.

Tier 2: Production Gateway

11. Logging
12. Request IDs
13. device identity
14. policy engine
15. SSE streaming
16. admin API
17. graceful shutdown

Tier 3: Nginx Parity Core

18. full config system
19. virtual hosts
20. location routing
21. upstream pools
22. load balancing
23. caching

Tier 4: Security & Performance

24. rate limiting
25. connection limits
26. security headers
27. compression
28. circuit breakers

Tier 5: Advanced Protocols

29. HTTP/2
30. HTTP/3
31. advanced proxy protocols
