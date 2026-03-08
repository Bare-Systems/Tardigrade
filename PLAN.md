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
- [x] Device identity registration
- [x] Public/private key device authentication
- [x] Auth middleware pipeline
- [x] Request auth context propagation
- [x] Token validation hooks
- [x] Token expiration / refresh logic

Resolved: Auth middleware pipeline implemented via `RequestContext` in `src/http/request_context.zig`. Auth identity (token hash) is propagated through the request context and included in structured audit logs.

Resolved: HTTP bearer token parsing/validation is implemented in `src/http/auth.zig`, including an optional validation hook callback for pluggable token verification.
Decision: core HTTP layer validates RFC6750-style token shape and delegates token trust decisions to caller-provided hooks to keep auth-provider logic decoupled.
Resolved (incremental): added device identity registration endpoint (`POST /v1/devices/register`) with registry persistence (`TARDIGRADE_DEVICE_REGISTRY_PATH`) and request-time device proof enforcement (`X-Device-ID`, `X-Device-Timestamp`, `X-Device-Signature`) for protected routes when `TARDIGRADE_DEVICE_AUTH_REQUIRED=true`.
Resolved (incremental): added session token refresh endpoint (`POST /v1/sessions/refresh`) with configured access/refresh TTL metadata (`TARDIGRADE_ACCESS_TOKEN_TTL_SECONDS`, `TARDIGRADE_REFRESH_TOKEN_TTL_SECONDS`).

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
- [x] keep-alive integration tests (low priority)
- [x] nginx-like syntax OR YAML/TOML
- [x] Include directive for modular configs
- [x] Variable interpolation
- [x] Syntax validation with helpful errors

Resolved (incremental): added nginx-style config parser foundation in `src/http/config_file.zig` with directive syntax (`key value;`, `set $name value;`, `include path;`) and environment-key normalization.
Resolved (incremental): parser supports include expansion (including simple wildcard includes), variable interpolation (`${var}`), and strict syntax validation with file/line error logging.
Decision: config-file values are treated as defaults and runtime environment variables remain higher precedence overrides.

### 3.2 Core Directives
- [x] worker_processes
- [x] worker_connections
- [x] error_log
- [x] pid file
- [x] user/group (privilege dropping)

Resolved (incremental): nginx-style directive aliases now map to runtime controls (`worker_processes` -> worker threads, `worker_connections` -> max active connections, `error_log` path/level, `pid`, `user`/`group`) through config-file env normalization in `src/http/config_file.zig`.
Resolved (incremental): runtime now supports pid file lifecycle and stderr log redirection from config (`src/main.zig`) and numeric post-bind privilege drop (`setgid`/`setuid`) in `src/edge_gateway.zig`.

### 3.3 HTTP Block Directives
- [x] server blocks (virtual hosts)
- [x] listen (address:port, ssl, http2)
- [x] server_name (wildcards, regex)
- [x] root / alias
- [x] location blocks (prefix, exact, regex)
- [x] try_files
- [x] return / rewrite
- [x] if conditionals (limited)

Resolved (incremental): added foundational HTTP-block directive mapping in config parser (`listen`, `server_name`, `root`, `try_files`) with runtime host-pattern enforcement and static `try_files` fallback handling in gateway request flow.
Resolved: rewrite/return and limited conditional behavior continue through existing rewrite/return engines with policy hooks for protected routes.

### 3.4 Hot Reload
- [x] SIGHUP configuration reload
- [x] Zero-downtime reload
- [x] Configuration validation before apply

Resolved (incremental): added SIGHUP handling in `src/http/shutdown.zig` and event-loop reload processing in `src/edge_gateway.zig`.
Resolved (incremental): hot reload performs full config parse/validation before apply; invalid reloads are rejected without impacting current runtime.
Resolved (incremental): reload applies atomically for new requests by swapping active config pointer without draining listener/worker pools.

### 3.5 Secret Management (NEW)
- [x] encrypted secret storage
- [x] environment overrides
- [x] runtime secret reload
- [x] key rotation support

Secrets may include:

- TLS keys
- auth signing keys
- upstream API credentials
- service tokens

Resolved (incremental): added branch-local encrypted secret override loader (`src/http/secrets.zig`) using `TARDIGRADE_SECRETS_PATH` + rotating key list (`TARDIGRADE_SECRET_KEYS`) with env-first override precedence preserved in `src/edge_config.zig`.
Decision: secret values use an XOR envelope with integrity prefix (`ENC:<base64(...)>`, payload prefixed with `TG1:`) as a lightweight in-repo mechanism; environment variables remain highest-precedence for production secret injection.

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
- [x] upstream blocks
- [x] Multiple backend servers
- [x] Server weights
- [x] Backup servers
- [x] max_fails / fail_timeout

Resolved (incremental): added route-scoped upstream blocks for `/v1/chat` and `/v1/commands` via dedicated env-configured primary/weight/backup pools, with automatic fallback to the global upstream pool when block-specific pools are unset.
Resolved (incremental): edge config now supports multiple upstream base URLs via `TARDIGRADE_UPSTREAM_BASE_URLS` (comma-separated), enabling multi-backend proxy target selection at runtime.
Resolved (incremental): added weighted primary selection via `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` (aligned positive integer weights) for weighted round-robin distribution.
Resolved (incremental): backup upstream pools now supported via `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS`; selection uses backups only when primary pools have no healthy/eligible candidate.
Resolved (incremental): passive-failure upstream controls added via `TARDIGRADE_UPSTREAM_MAX_FAILS` and `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS`.

### 4.3 Load Balancing Algorithms
- [x] Round-robin (default)
- [x] Least connections
- [x] IP hash (session persistence)
- [x] Generic hash
- [x] Random with two choices

Resolved (incremental): proxy upstream base URL selection now uses round-robin rotation per request across configured upstream base URLs.
Resolved (incremental): added least-connections upstream selection mode via `TARDIGRADE_UPSTREAM_LB_ALGORITHM=least_connections`, using current in-flight upstream attempt counts.
Resolved (incremental): added IP-hash upstream selection mode via `TARDIGRADE_UPSTREAM_LB_ALGORITHM=ip_hash`, hashing client IP to a stable backend while respecting health and slow-start gating.
Resolved (incremental): added generic-hash upstream selection mode via `TARDIGRADE_UPSTREAM_LB_ALGORITHM=generic_hash`, hashing a deterministic request key (payload when present, otherwise proxy target path) to keep request affinity while honoring health and slow-start gating.
Resolved (incremental): added random-two-choices upstream selection mode via `TARDIGRADE_UPSTREAM_LB_ALGORITHM=random_two_choices`, sampling two backends and preferring the lower in-flight load while honoring health and slow-start gates.

### 4.4 Health Checks
- [x] Passive health checks (mark failed on errors)
- [x] Active health checks (periodic probes)
- [x] Configurable thresholds
- [x] Slow start for recovered servers

Resolved (incremental): proxy path now tracks upstream failures and marks backends temporarily unhealthy after configured failure thresholds; round-robin selection skips unhealthy upstreams until fail-timeout expires.
Resolved (incremental): timer-driven active upstream health probes now run at configurable intervals (`TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS`) against a configurable path (`TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH`) with probe timeout control.
Resolved (incremental): active health transitions now support configurable fail/success thresholds (`TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD`, `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD`) before marking unhealthy and before clearing unhealthy state.
Resolved (incremental): recovered upstreams now enter configurable slow-start windows (`TARDIGRADE_UPSTREAM_SLOW_START_MS`) with gradual traffic eligibility ramp before full load share.

### 4.5 Proxy Protocol Support
- [x] Protocol v1 and v2
- [x] Extracting real client IP

Resolved (incremental): added configurable PROXY protocol parsing (`TARDIGRADE_PROXY_PROTOCOL=off|auto|v1|v2`) on plaintext listeners with v1/v2 support and request-context client IP extraction from parsed source addresses.

### 4.6 Service Trust Model (NEW)
- [x] trusted upstream configuration
- [x] signed upstream headers
- [x] auth context forwarding
- [x] upstream identity verification

Resolved (incremental): added trust model configuration (`TARDIGRADE_TRUST_GATEWAY_ID`, `TARDIGRADE_TRUST_SHARED_SECRET`, `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES`, `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY`), signed upstream request headers, auth-context forwarding headers, and trusted upstream identity enforcement against configured upstream identities.

### 4.7 Unix Socket Upstreams (NEW)
- [x] unix domain socket backends
- [x] local IPC routing
- [x] socket-based load balancing

Resolved (incremental): upstream endpoint configuration now supports Unix domain socket backends (`unix:/path.sock` / `unix:///path.sock`) across global and route-scoped upstream pools, with existing load-balancing/health-check logic applying to socket endpoints for local IPC routing.

## PHASE 5: Caching

### 5.1 Proxy Cache
- [x] proxy_cache_path (disk-based)
- [x] Cache key configuration
- [x] Cache validity rules
- [x] Cache bypass conditions
- [x] Cache purging

Resolved (incremental): added in-memory proxy cache controls via `TARDIGRADE_PROXY_CACHE_TTL_SECONDS` and `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE` with template-token key generation (`method`, `path`, `payload_sha256`, `identity`, `api_version`) and fallback defaults.
Resolved (incremental): proxy gateway routes now apply TTL-based validity rules, serving cache hits with `X-Proxy-Cache: HIT` and storing successful (`200`) upstream responses for `/v1/chat` and `/v1/commands`.
Resolved (incremental): added bypass controls via request headers (`X-Proxy-Cache-Bypass`, `Cache-Control: no-cache/no-store/max-age=0`, `Pragma: no-cache`) and admin purge endpoint `POST /v1/cache/purge` (authenticated; optional JSON `{ "key": "..." }` for key-specific purge).
Resolved (incremental): added optional disk-backed cache path (`TARDIGRADE_PROXY_CACHE_PATH`) used as a secondary tier for proxy cache reads/writes and purge operations.

### 5.2 Advanced Caching
- [x] Stale content serving (stale-while-revalidate)
- [x] Cache locking (single request populates)
- [x] Background cache updates
- [x] Cache manager process
- [x] Memory + disk tiered caching

Resolved (incremental): added stale serving window via `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS` with stale responses marked by `X-Proxy-Cache: STALE`.
Resolved (incremental): added per-key proxy cache lock coordination with `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS` so concurrent misses wait briefly for an in-flight population.
Resolved (incremental): stale hits now trigger detached background refresh attempts for chat/command proxy routes to repopulate cache asynchronously.
Resolved (incremental): timer-loop cache manager maintenance (`TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS`) now performs periodic in-memory proxy-cache expiration cleanup.
Resolved (incremental): memory+disk tiering now checks memory first, falls back to disk cache path, and hydrates memory from disk hits.

### 5.3 Browser Caching
- [x] Expires header
- [x] Cache-Control header
- [x] ETag/Last-Modified validation

Resolved: Cache-Control and Expires headers implemented in `src/http/cache_control.zig`. CachePolicy struct with directives (max-age, public, private, no-cache, no-store, must-revalidate, immutable). Preset policies for static assets, APIs, and no-caching. MIME-type based policy selection. ETag/Last-Modified already implemented in earlier phases.

## PHASE 6: Security Features

### 6.1 Access Control
- [x] allow/deny directives (IP-based)
- [x] CIDR notation support
- [x] Geo-based blocking (via external data)

Resolved: IP access control implemented in `src/http/access_control.zig`. Supports allow/deny rules with CIDR notation (IPv4 and IPv6). First-match-wins evaluation order. Configurable via `TARDIGRADE_ACCESS_CONTROL` env var (e.g. `"allow 10.0.0.0/8, deny 0.0.0.0/0"`). Applied before rate limiting in the gateway pipeline.
Resolved (incremental): added geo-based blocking using external country header data via `TARDIGRADE_GEO_BLOCKED_COUNTRIES` and `TARDIGRADE_GEO_COUNTRY_HEADER`.

### 6.2 Rate Limiting
- [x] limit_req (request rate)
- [x] limit_conn (connection count)
- [x] Configurable zones and keys
- [x] Burst handling
- [x] Custom rejection responses

Resolved: Token-bucket rate limiter implemented in `src/http/rate_limiter.zig`. Per-IP tracking with configurable RPS and burst. Returns 429 with stable API error envelope.
Resolved (incremental): limit-conn behavior is enforced via active per-IP/global connection caps, now including explicit `TARDIGRADE_LIMIT_CONN_PER_IP` alias support.

### 6.3 Authentication
- [x] HTTP Basic Auth
- [x] Auth request (subrequest-based)
- [x] JWT validation (optional module)

Resolved: HTTP Basic Auth implemented in `src/http/basic_auth.zig`. Parses `Authorization: Basic <base64>` headers, decodes credentials, and verifies against SHA-256 hashes of "user:password" strings. Configured via `TARDIGRADE_BASIC_AUTH_HASHES` env var. Integrated as fallback auth method after bearer token in the gateway pipeline.
Resolved (incremental): added optional auth subrequest validation (`TARDIGRADE_AUTH_REQUEST_URL`, `TARDIGRADE_AUTH_REQUEST_TIMEOUT_MS`) for protected API routes.
Resolved (incremental): added JWT HS256 bearer validation module (`src/http/jwt.zig`) with issuer/audience constraints via `TARDIGRADE_JWT_SECRET`, `TARDIGRADE_JWT_ISSUER`, `TARDIGRADE_JWT_AUDIENCE`.

### 6.4 Request Validation
- [x] Request body size limits (client_max_body_size)
- [x] Header count/size limits
- [x] URI length limits
- [x] Timeout enforcement (client_body_timeout, etc.)

Resolved: Request validation limits enforced in gateway pipeline via `src/http/request_limits.zig`. Body size (413), URI length (414), and header count (400) validated after parsing. Configurable via env vars: `TARDIGRADE_MAX_BODY_SIZE`, `TARDIGRADE_MAX_URI_LENGTH`, `TARDIGRADE_MAX_HEADER_COUNT`, `TARDIGRADE_MAX_HEADER_SIZE`.
Resolved (incremental): socket-level timeout enforcement is now active in `src/edge_gateway.zig`. Accepted client sockets apply configured header timeout (`TARDIGRADE_HEADER_TIMEOUT_MS`) and upstream proxy sockets apply `TARDIGRADE_UPSTREAM_TIMEOUT_MS` for send/receive operations.

### 6.5 Security Headers
- [x] add_header directive
- [x] X-Frame-Options
- [x] X-Content-Type-Options
- [x] Content-Security-Policy
- [x] Strict-Transport-Security

Resolved: Security headers middleware implemented in `src/http/security_headers.zig` with default secure and API presets. Also adds Referrer-Policy, Permissions-Policy, and X-XSS-Protection.
Resolved (incremental): added configurable `add_header` support through `TARDIGRADE_ADD_HEADERS` (pipe-delimited `Name: Value` pairs) applied to all gateway responses.

### 6.6 Policy Engine (NEW)
- [x] route-level policy evaluation
- [x] device-based restrictions
- [x] per-user scopes
- [x] approval-required routes
- [x] time-based policy rules

Resolved (incremental): added policy engine evaluation in gateway request pipeline with route regex rules, device regex restrictions, per-identity scopes, approval-token gates, and hour-window gating via `TARDIGRADE_POLICY_*` config.

## PHASE 7: TLS / SSL

### 7.1 Basic TLS
- [x] TLS termination
- [x] Certificate and key loading
- [x] TLS 1.2 / 1.3 support
- [x] Cipher suite configuration
- [x] Protocol version selection

Resolved (incremental): expanded OpenSSL TLS termination configuration with explicit min/max protocol controls (`TARDIGRADE_TLS_MIN_VERSION`, `TARDIGRADE_TLS_MAX_VERSION`) and certificate/key loading for default server identity.
Resolved (incremental): added cipher controls for TLS <=1.2 and TLS 1.3 (`TARDIGRADE_TLS_CIPHER_LIST`, `TARDIGRADE_TLS_CIPHER_SUITES`).

### 7.2 Advanced TLS
- [x] SNI (Server Name Indication)
- [x] Multiple certificates per server
- [x] Session resumption (session cache)
- [x] Session tickets
- [x] OCSP stapling

Resolved (incremental): implemented SNI callback-based certificate selection with multi-cert mapping via `TARDIGRADE_TLS_SNI_CERTS`.
Resolved (incremental): added TLS session cache and ticket controls (`TARDIGRADE_TLS_SESSION_CACHE`, `TARDIGRADE_TLS_SESSION_CACHE_SIZE`, `TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS`, `TARDIGRADE_TLS_SESSION_TICKETS`).
Resolved (incremental): added static OCSP stapling response loading (`TARDIGRADE_TLS_OCSP_STAPLING`, `TARDIGRADE_TLS_OCSP_RESPONSE_PATH`) and handshake attachment.

### 7.3 Client Certificates
- [x] Client certificate verification
- [x] Certificate chain validation
- [x] CRL checking

Resolved (incremental): added optional mTLS/client-cert verification with CA trust configuration (`TARDIGRADE_TLS_CLIENT_CA_PATH`, `TARDIGRADE_TLS_CLIENT_VERIFY`, `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH`) and OpenSSL chain verification behavior.
Resolved (incremental): added CRL loading/checking (`TARDIGRADE_TLS_CRL_PATH`, `TARDIGRADE_TLS_CRL_CHECK`) via cert-store flags.

### 7.4 Certificate Management
- [x] Dynamic certificate loading
- [x] ACME/Let's Encrypt integration (optional)

Resolved (incremental): event-loop TLS maintenance now supports periodic certificate/OCSP/CRL reload checks (`TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS`).
Resolved (incremental): optional ACME-style cert directory ingestion is supported through `TARDIGRADE_TLS_ACME_ENABLED` and `TARDIGRADE_TLS_ACME_CERT_DIR` for SNI certificate discovery.

## PHASE 8: HTTP/2 & HTTP/3

### 8.1 HTTP/2
- [x] HPACK header compression
- [x] Stream multiplexing
- [x] Server push
- [x] Priority handling
- [x] Flow control
- [x] HTTP/2 to HTTP/1.1 backend translation

Resolved (incremental): added in-house HPACK module (`src/http/hpack.zig`) with static-table indexed/literal decoding and literal encoding used by HTTP/2 response headers.
Resolved (incremental): added in-house HTTP/2 frame codec (`src/http/http2_frame.zig`) and TLS-ALPN `h2` connection path handling preface/settings/ping/headers/data across stream IDs with per-stream request assembly.
Resolved (incremental): added HTTP/2 server push helper path using `PUSH_PROMISE` and pushed response streams for gateway GET routes.
Resolved (incremental): added priority parsing/scheduling and basic stream weight handling for response dispatch order.
Resolved (incremental): added connection/stream flow-control accounting with `WINDOW_UPDATE` frame handling and replenishment.
Resolved (incremental): added HTTP/2 gateway route translation for proxied API paths (`/v1/chat`, `/v1/commands`) through existing upstream proxy execution paths.

### 8.2 HTTP/3 (QUIC)
- [x] QUIC protocol implementation
- [x] 0-RTT connection establishment
- [x] Connection migration
- [x] QPACK header compression

Resolved (incremental): added in-house QUIC packet parser and connection tracker foundation (`src/http/quic.zig`) including packet-type decoding for initial/0-RTT/handshake/retry/short-header classes.
Resolved (incremental): added connection migration tracking logic keyed by destination connection ID with migration allow/deny controls.
Resolved (incremental): added in-house QPACK literal header block encoder/decoder foundation (`src/http/qpack.zig`) for HTTP/3 header compression workflows.

## PHASE 9: WebSocket & Event Streaming

### 9.1 WebSocket Proxying
- [x] upgrade handling
- [x] bidirectional proxying
- [x] wss support

### 9.2 WebSocket Runtime
- [x] ping/pong
- [x] idle timeout
- [x] load balancing

### 9.3 Server-Sent Events (NEW)
- [x] SSE protocol support
- [x] long-lived stream connections
- [x] reconnect tokens
- [x] stream backpressure

### 9.4 Event Fanout (NEW)
- [x] event broadcast to subscribers
- [x] topic-based subscriptions
- [x] event buffering
- [x] slow client protection

Resolved (incremental): added in-house WebSocket framing and handshake utilities in `src/http/websocket.zig` and integrated authenticated WS upgrade routes (`GET /v1/ws/chat`, `GET /v1/ws/commands`) into the gateway request router.
Resolved (incremental): WebSocket runtime loop now supports ping/pong handling, idle timeout enforcement (`TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS`), frame-size limits (`TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE`), and upstream load-balanced proxy execution via existing proxy engine.
Resolved (incremental): added in-memory topic event hub (`src/http/event_hub.zig`) with per-topic buffering and replay snapshots, integrated into authenticated SSE routes (`GET /v1/events/stream`, `POST /v1/events/publish`).
Resolved (incremental): SSE streams now support `Last-Event-ID` replay, long-lived polling delivery, and slow-client/backlog protection via configurable backlog window (`TARDIGRADE_SSE_MAX_BACKLOG`) and per-topic ring buffers (`TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC`).

## PHASE 10: Compression

### 10.1 Response Compression
- [x] gzip compression
- [x] gzip_static (pre-compressed files)
- [x] Brotli compression
- [x] Compression level configuration
- [x] MIME type filtering
- [x] Minimum size threshold

Resolved: Gzip response compression implemented in `src/http/compression.zig`. One-shot compression with MIME-type filtering (text/*, JSON, XML, JS, SVG, WASM), configurable min size (default 256 bytes), and compression level. Applied to proxy response paths in the gateway. Configurable via `TARDIGRADE_COMPRESSION_ENABLED` and `TARDIGRADE_COMPRESSION_MIN_SIZE`.
Resolved (incremental): compression negotiation now prefers Brotli (`br`) when accepted and runtime encoder library is available; otherwise falls back to gzip. Brotli controls added via `TARDIGRADE_COMPRESSION_BROTLI_ENABLED` and `TARDIGRADE_COMPRESSION_BROTLI_QUALITY`.
Resolved (incremental): gzip_static-style passthrough now preserves already-gzipped payloads when client accepts gzip (avoids redundant recompression).

### 10.2 Decompression
- [x] gunzip for backends that don't support it

Resolved (incremental): upstream proxy requests now advertise `Accept-Encoding: gzip` (configurable via `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED`) and rely on Zig HTTP client automatic gunzip decompression before downstream re-encoding negotiation.

## PHASE 11: Advanced Features

### 11.1 URL Rewriting
- [x] rewrite directive (regex-based)
- [x] Rewrite flags (last, break, redirect, permanent)
- [x] return directive
- [x] Conditional rewriting

Resolved (incremental): added regex-based rewrite engine module in `src/http/rewrite.zig` with rule evaluation and flag handling (`last`, `break`, `redirect`, `permanent`) using POSIX extended regex matching.
Resolved (incremental): added pre-routing rewrite/return evaluation in gateway request flow (`src/edge_gateway.zig`) so request paths can be rewritten or short-circuited with configurable return/redirect responses before normal route dispatch.
Resolved (incremental): added method-conditional rule support (`METHOD|...` with `*` wildcard) through env-driven directives.

### 11.2 Request Processing
- [x] Sub-requests
- [x] Internal redirects
- [x] Named locations
- [x] Mirror requests

Resolved (incremental): added generic authenticated subrequest execution endpoint (`POST /v1/subrequest`) to execute outbound HTTP calls with request-controlled target/method/body.
Resolved (incremental): added internal redirect rules and named location mapping via env config (`TARDIGRADE_INTERNAL_REDIRECT_RULES`, `TARDIGRADE_NAMED_LOCATIONS`) applied before route dispatch.
Resolved (incremental): added mirror request rules (`TARDIGRADE_MIRROR_RULES`) for best-effort mirrored POST dispatch to configured targets.

### 11.3 Backend Protocols
- [x] FastCGI proxy
- [x] uWSGI proxy
- [x] SCGI proxy
- [x] gRPC proxy
- [x] Memcached integration

Resolved (incremental): added in-house protocol adapter modules (`src/http/fastcgi.zig`, `src/http/uwsgi.zig`, `src/http/scgi.zig`, `src/http/memcached.zig`) and gateway bridge routes under `/v1/backend/*`.
Resolved (incremental): gRPC proxy foundation route (`POST /v1/backend/grpc`) forwards gRPC payloads to configured upstream with `application/grpc` semantics.

### 11.4 Mail Proxy (Optional)
- [x] SMTP proxy
- [x] IMAP proxy
- [x] POP3 proxy

Resolved (incremental): added raw protocol bridge routes (`/v1/mail/smtp`, `/v1/mail/imap`, `/v1/mail/pop3`) to configured mail upstream endpoints.

### 11.5 TCP/UDP Proxy (Stream Module)
- [x] Generic TCP proxying
- [x] UDP proxying
- [x] Stream SSL termination

Resolved (incremental): added stream module bridge routes (`/v1/stream/tcp`, `/v1/stream/udp`) to configured raw upstream endpoints.
Resolved (incremental): added stream SSL-termination mode flag (`TARDIGRADE_STREAM_SSL_TERMINATION`) surfaced via stream route response metadata and startup logging.

## PHASE 12: Observability

### 12.1 Logging
- [x] Custom log formats
- [x] Conditional logging
- [x] JSON log format
- [x] Access log buffering
- [x] Syslog integration

Resolved (incremental): access logging now supports configurable output formats (`json`, `plain`, `custom`) with template rendering via `TARDIGRADE_ACCESS_LOG_FORMAT` and `TARDIGRADE_ACCESS_LOG_TEMPLATE`.
Resolved (incremental): conditional access logging and buffering are supported via `TARDIGRADE_ACCESS_LOG_MIN_STATUS` and `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE`.
Resolved (incremental): optional syslog UDP forwarding is supported via `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP`.

### 12.2 Metrics
- [x] Stub status endpoint
- [x] Connection statistics
- [x] Request statistics
- [x] Upstream health status
- [x] Prometheus metrics export (optional)

Resolved: `GET /metrics` endpoint added to gateway. `Metrics` struct in `src/http/metrics.zig` tracks total requests and status class counts (2xx/3xx/4xx/5xx) with uptime. All gateway response paths record metrics automatically. `GET /metrics/prometheus` endpoint added returning Prometheus text exposition format (v0.0.4).
Resolved (incremental): metrics now include active connection gauge, listener rejection counters (connection-slot and queue saturation), and current unhealthy upstream backend gauge.

### 12.3 Debugging
- [x] Debug logging
- [x] Request tracing
- [x] Error categorization

Resolved: Structured access log implemented in `src/http/access_log.zig`. `AccessLogEntry` emits a `"type":"access"` JSON line to stderr per completed request with method, path, status, latency, client IP, correlation ID, identity, and user agent fields. The `logAccess()` helper in the gateway replaces all 35 `ctx.auditLog()` key=value callsites with structured JSON output suitable for log aggregation.
Resolved (incremental): access logs now include `error_category` classification and metrics now track category-level API error counters (invalid request, unauthorized, rate limited, upstream timeout/unavailable, internal, overload) for operational triage.

### 12.4 Admin API
- [x] route inspection
- [x] active connections
- [x] stream status
- [x] upstream health
- [x] loaded certificates
- [x] auth/device registry

Resolved (incremental): added authenticated admin endpoints for route inspection and runtime state:
- `GET /admin/routes`
- `GET /admin/connections`
- `GET /admin/streams`
- `GET /admin/upstreams`
- `GET /admin/certs`
- `GET /admin/auth-registry`

## PHASE 13: Production Hardening

### 13.1 Process Management
- [ ] Master/worker process model
- [x] Graceful shutdown (SIGTERM/SIGQUIT)
- [ ] Binary upgrade (SIGUSR2)
- [ ] Worker process recycling
- [ ] CPU affinity

Resolved: Graceful shutdown implemented in `src/http/shutdown.zig`. SIGTERM and SIGINT handlers set a global atomic flag. With the Phase 2.1 event loop, the listener no longer blocks indefinitely in `accept()`, so shutdown is serviced on the next event-loop tick even when the server is idle.

### 13.2 Resource Limits
- [x] File descriptor limits
- [x] Worker connection limits
- [x] Memory limits
- [x] Request queue limits

Resolved (incremental): global active worker connection cap added via `TARDIGRADE_MAX_ACTIVE_CONNECTIONS`. Listener now rejects excess connections with explicit 503 load-shedding responses.
Resolved (incremental): worker queue saturation now triggers explicit 503 load-shedding responses (with `Retry-After`) instead of silent close.
Resolved (incremental): startup can now apply best-effort process fd soft limits via `TARDIGRADE_FD_SOFT_LIMIT` (RLIMIT_NOFILE on supported Unix targets).
Resolved (incremental): global estimated active-connection memory capping added via `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES`, enforced in listener admission control.
Decision: total memory cap is estimated from active connections and configured per-connection memory budget to keep listener-side checks lock-free and low overhead.

### 13.3 Privilege Management
- [ ] Run as unprivileged user
- [ ] Privilege dropping after bind
- [ ] Chroot support (optional)

### 13.4 Resilience Features
- [x] circuit breakers
- [x] retry policies
- [x] timeout budgets
- [x] overload protection
- [x] request queue management

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
