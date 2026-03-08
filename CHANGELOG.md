
# Changelog

## [0.27.0] - 2026-03-xx

### Added
- Phase 2.2 request pipelining boundary support (`src/edge_gateway.zig`):
  - Added per-connection pending buffer/session state for keep-alive request loops.
  - HTTP parser `bytes_consumed` is now used to preserve unread bytes for subsequent requests on the same socket.
  - Added request-boundary helper tests for pipelined and body-length-delimited requests.
- Phase 2.2 connection pooling + graceful draining completion (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - Added thread-safe `ConnectionSessionPool` used by workers to reuse connection session objects across accepted sockets.
  - Added `TARDIGRADE_CONNECTION_POOL_SIZE` to bound cached connection-session objects.
  - Gateway shutdown now explicitly drains active/queued connection work before worker join, and keep-alive responses switch to `Connection: close` during drain.
  - Added unit coverage for connection-session pool reuse/reset behavior.
- Phase 2.3 work stealing / load balancing (`src/http/worker_pool.zig`):
  - Replaced the single shared queue with per-worker queues.
  - Listener submit path now chooses the least-loaded worker queue.
  - Workers now steal queued sockets from peer queues when local queues are empty.
  - Added unit coverage for queue selection and stealing behavior.
- Phase 2.4 memory management completion (`src/http/buffer_pool.zig`, `src/edge_gateway.zig`, `src/edge_config.zig`):
  - Added thread-safe reusable fixed-size buffer pool module and integrated request + proxy relay buffer pools in gateway state.
  - Added `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` and enforced buffer/read caps on connection and buffered upstream paths.
  - Request/session handling now acquires request buffers from a pool and releases them on connection teardown.
  - Proxy non-200 mapped responses now drain upstream bodies without full buffering.
- Phase 4.1 streaming proxy extension (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - Added `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` to optionally stream non-200 upstream responses directly.
  - Streamed-status circuit breaker accounting now treats 5xx responses as failures.
- Phase 4.1 buffered proxy metadata preservation (`src/edge_gateway.zig`):
  - Buffered success responses now retain upstream `Content-Type` and `Content-Disposition` values.
  - Successful buffered proxy responses are no longer always forced to JSON content type.
  - Reduced streamed vs buffered response mismatch for proxy paths when idempotency requires buffered handling.
- Phase 4.2/4.3 upstream multi-backend round-robin foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_BASE_URLS` (comma-separated) for configuring multiple upstream base URLs.
  - Proxy target resolution now selects upstream base URLs via round-robin across configured backends.
  - Added deterministic unit coverage for upstream base URL round-robin selection.
- Phase 13.4 retry policy foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` (minimum 1) for proxy upstream retries.
  - Proxy execution now retries failed attempts and rotates upstream base URL selection between attempts.
- Phase 4.2/4.4 passive upstream health tracking (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_MAX_FAILS` and `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS`.
  - Backends are marked temporarily unhealthy after threshold failures and skipped by round-robin selection until cooldown expires.
  - Retry + backend rotation now records upstream success/failure outcomes for passive failover decisions.
- Phase 13.4 timeout budget foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` for total upstream retry-window timeout budgeting.
  - Proxy retry attempts now enforce a shared per-request timeout budget, not only per-attempt socket timeouts.
- Phase 13 overload protection + request queue management (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` global active-connection cap.
  - Listener now sends explicit `503 Service Unavailable` load-shedding responses when over global/per-IP limits or when worker queue submission is full.
  - Queue/connection rejections now use `Retry-After: 1` to signal transient overload.
- Phase 13.2 resource limit controls (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_FD_SOFT_LIMIT` (best-effort RLIMIT_NOFILE soft-limit application on startup).
  - Added `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` global estimated memory admission cap.
  - Listener admission now rejects new connections with 503 when projected active-connection memory budget would be exceeded.
- Metrics observability expansion (`src/http/metrics.zig`, `src/edge_gateway.zig`):
  - Added active connection gauge and listener rejection counters (connection-slot and queue saturation).
  - Added upstream unhealthy backend gauge derived from passive health tracking state.
  - Extended `/metrics` JSON and `/metrics/prometheus` output to include the new operational metrics.
- Phase 4.4 active upstream health checks (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added periodic active probe controls: `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS`, `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH`, and `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_TIMEOUT_MS`.
  - Event-loop timer ticks now run active health probes across configured upstreams.
  - Active probe outcomes now feed existing passive-health failover tracking.
- Phase 4.4 configurable health thresholds (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD` and `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD`.
  - Active probe failures/successes now use configurable consecutive-threshold transitions for unhealthy/healthy state changes.
- Phase 4.4 slow-start for recovered upstreams (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_SLOW_START_MS` for recovered-backend traffic ramp windows.
  - Upstream selection now applies gradual eligibility during slow-start instead of immediate full-load routing after recovery.

## [0.26.0] - 2026-03-xx

### Added
- Phase 2.4 request arena allocation (`src/edge_gateway.zig`):
  - Request processing now uses a request-scoped arena allocator instead of a per-request general-purpose allocator.
  - Per-request temporary allocations are reclaimed in one step at request completion.

## [0.25.0] - 2026-03-xx

### Added
- Phase 2.2 keep-alive connection reuse (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - Worker connection handlers now support sequential multi-request processing per client socket.
  - Responses now honor parsed request keep-alive behavior (`Connection: keep-alive`/`close`).
  - Added `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` for idle keep-alive socket timeout.
  - Added `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` to bound requests served per connection.

## [0.24.0] - 2026-03-xx

### Added
- Socket timeout enforcement (`src/edge_gateway.zig`):
  - Accepted client sockets now apply configured request header timeout via `TARDIGRADE_HEADER_TIMEOUT_MS`.
  - Upstream proxy sockets now apply configured send/receive timeout via `TARDIGRADE_UPSTREAM_TIMEOUT_MS`.
  - Timeout settings are applied with POSIX socket timeout options on both client and upstream paths.

## [0.23.0] - 2026-03-xx

### Added
- Phase 4.1 proxy_pass directive foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_PROXY_PASS_CHAT` for `/v1/chat` upstream target selection.
  - Added `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` for `/v1/commands` command upstream path prefixing.
  - Proxy target resolver supports absolute URL mode and relative-path mode (joined with `TARDIGRADE_UPSTREAM_BASE_URL`).
  - Added target resolution helper coverage for path joining and absolute/relative routing behavior.

## [0.22.0] - 2026-03-xx

### Added
- Phase 4.1 backend connection pooling (`src/edge_gateway.zig`):
  - Gateway state now owns a shared upstream `std.http.Client`.
  - Upstream proxy execution path now opens requests through the shared client with `keep_alive = true`.
  - Upstream connections can now be reused across requests via the client connection pool instead of one-client-per-request teardown.

## [0.21.0] - 2026-03-xx

### Added
- Phase 4.1 streaming proxy increment (`src/edge_gateway.zig`):
  - New upstream execution path that can stream successful (200) upstream responses directly to downstream clients using chunked transfer encoding.
  - Shared streaming response header writer for propagated content-type/disposition, correlation ID, and security headers.
  - `/v1/chat` and `/v1/commands` now attempt streamed relay when idempotency replay storage is not required; non-200 responses still use buffered mapping path.

## [0.20.0] - 2026-03-xx

### Added
- Native HTTPS/TLS termination (`src/http/tls_termination.zig`, `src/edge_gateway.zig`, `build.zig`):
  - OpenSSL-backed TLS server context with certificate/private-key loading from configured PEM files.
  - Worker connection path now performs TLS handshake (`SSL_accept`) when TLS cert/key are configured.
  - HTTP request parsing/response writing now supports both plain TCP streams and TLS-wrapped streams.
  - Build linked with `ssl`/`crypto` system libraries for executable and tests.

## [0.19.0] - 2026-03-xx

### Added
- Phase 2.2 per-IP connection limiting (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - New `TARDIGRADE_MAX_CONNECTIONS_PER_IP` runtime setting (default disabled).
  - Listener accept path now enforces active connection slots per client IP before queueing to workers.
  - Connection slot lifecycle is tracked by fd and released on worker completion or queue submission failure.
  - Supports IPv4 and IPv6 client keying in the connection tracker.

## [0.18.0] - 2026-03-xx

### Added
- Phase 2.3 graceful worker draining (`src/http/worker_pool.zig`):
  - Worker pool now tracks in-flight jobs and blocks shutdown until queued + active work drains when requested.
  - Added worker completion signaling for coordinated shutdown waits.
  - Added unit test verifying `shutdownAndJoin(true)` waits for in-flight work completion.

## [0.17.0] - 2026-03-xx

### Added
- Phase 4.1 reverse proxy header foundation (`src/edge_gateway.zig`):
  - Unified JSON proxy request path shared by `/v1/chat` and `/v1/commands`.
  - Forwarded client headers added on upstream calls: `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`.
  - `Host` header rewriting to upstream authority derived from `upstream_base_url`.
  - Helper coverage for forwarded-for composition and upstream host parsing.

## [0.16.0] - 2026-03-xx

### Added
- Phase 2.3 worker model foundation (`src/http/worker_pool.zig`, `src/edge_gateway.zig`):
  - Fixed-size worker thread pool for accepted connection handling with bounded queue backpressure.
  - Event-loop accept path now dispatches sockets to worker threads instead of processing inline on the listener thread.
  - Thread-safe shared gateway state access for rate limiting, sessions, idempotency, circuit breaker, and metrics via synchronized state helpers.
  - Configurable worker settings via `TARDIGRADE_WORKER_THREADS` (default auto) and `TARDIGRADE_WORKER_QUEUE_SIZE` (default 1024).
  - Worker pool unit test covering queue submission/processing.

## [0.15.0] - 2026-03-xx

### Added
- Phase 2.1 async event loop foundation (`src/http/event_loop.zig`, `src/edge_gateway.zig`):
  - Cross-platform event loop abstraction with `epoll` (Linux) and `kqueue` (macOS/BSD) backends.
  - Non-blocking listening socket registration and event-driven accept handling in the gateway runtime.
  - Timer manager for periodic event-loop ticks and responsive shutdown checks without blocking in `accept()`.
  - Gateway startup now logs the selected event loop backend.
  - Unit tests for backend selection and timer tick behavior.

## [0.14.0] - 2026-03-07

### Added
- Circuit breaker for upstream resilience (`src/http/circuit_breaker.zig`):
  - Three-state machine: closed → open → half-open with configurable failure threshold and recovery timeout.
  - `tryAcquire()` allows requests through when closed or half-open (with side-effect transition from open after timeout).
  - `recordSuccess()` / `recordFailure()` update state; half-open closes on configured success count.
  - Disabled when `threshold = 0` (default); configure via `TARDIGRADE_CB_THRESHOLD` and `TARDIGRADE_CB_TIMEOUT_MS`.
  - Applied to both `/v1/chat` and `/v1/commands` upstream proxy calls; returns 503 when circuit is open.
- Prometheus metrics format (`src/http/metrics.zig`):
  - `toPrometheus()` method emits Prometheus text exposition format with `# HELP` and `# TYPE` annotations.
  - `GET /metrics/prometheus` endpoint returns `text/plain; version=0.0.4; charset=utf-8` (no auth required).
- Structured access log (`src/http/access_log.zig`):
  - `AccessLogEntry` struct emits a `"type":"access"` JSON line to stderr for every completed request.
  - Fields: method, path, status, latency_ms, client_ip, correlation_id, identity, user_agent, bytes_sent.
  - Replaces `ctx.auditLog()` key=value format at all 35 gateway callsites with the new `logAccess()` helper.
  - Machine-parseable by log shippers (Loki, Fluentd, etc.).

### Changed
- Edge config extended with `cb_threshold` and `cb_timeout_ms` fields.
- Gateway startup logs circuit breaker state on boot.
- All 35 gateway audit log points now emit structured JSON access log entries.

## [0.13.0] - 2026-03-07

### Added
- Gzip response compression (`src/http/compression.zig`):
  - `compressResponse()` for one-shot gzip compression with MIME-type and size filtering.
  - MIME allowlist: `text/*`, `application/json`, `application/xml`, `application/javascript`, `image/svg+xml`, `application/wasm`.
  - Default minimum size threshold of 256 bytes (configurable via `TARDIGRADE_COMPRESSION_MIN_SIZE`).
  - Only applies compressed body when result is smaller than original.
  - Enabled by default; disable via `TARDIGRADE_COMPRESSION_ENABLED=false`.
  - Applied to `/v1/chat` and `/v1/commands` proxy responses; sets `Content-Encoding: gzip` when used.
- Metrics endpoint (`src/http/metrics.zig`):
  - `Metrics` struct tracking total requests, status class counts (2xx/3xx/4xx/5xx), and uptime.
  - `GET /metrics` endpoint returns JSON metrics (no auth required).
  - All gateway response paths (success and error) record request status.
- Graceful shutdown (`src/http/shutdown.zig`):
  - SIGTERM and SIGINT signal handlers set a global shutdown flag.
  - Accept loop exits cleanly after current connection when flag is set.
  - `installSignalHandlers()` called at gateway startup.

### Changed
- Edge config extended with `compression_enabled` and `compression_min_size` fields.
- Gateway startup logs compression and signal handler status.
- `sendApiError` records every error response in metrics automatically.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.12.0] - 2026-03-07

### Added
- HTTP Basic Auth (`src/http/basic_auth.zig`):
  - Parse `Authorization: Basic <base64>` headers.
  - Base64 decode to extract username:password.
  - Verify credentials against SHA-256 hash list of "user:password" strings.
  - Configurable via `TARDIGRADE_BASIC_AUTH_HASHES` env var.
  - Falls back from bearer token auth automatically.
- Structured JSON logger (`src/http/logger.zig`):
  - Severity levels: DEBUG, INFO, WARN, ERROR.
  - JSON-structured output to stderr with ISO 8601 timestamps.
  - Per-request correlation ID in log entries.
  - Configurable minimum level via `TARDIGRADE_LOG_LEVEL` env var.
- Browser caching headers (`src/http/cache_control.zig`):
  - `CachePolicy` struct with Cache-Control directives (max-age, public, private, no-cache, no-store, must-revalidate, immutable).
  - Preset policies: `no_caching`, `static_immutable`, `static_default`, `api_default`.
  - MIME-type based policy selection via `policyForMimeType()`.
  - Expires header generation from max-age offset.
- Request validation enforcement in gateway (Phase 6.4):
  - Header count and header size validation functions in `request_limits.zig`.
  - Gateway pipeline enforces body size (413), URI length (414), and header count (400) limits.
  - Configurable via env vars: `TARDIGRADE_MAX_BODY_SIZE`, `TARDIGRADE_MAX_URI_LENGTH`, `TARDIGRADE_MAX_HEADER_COUNT`, `TARDIGRADE_MAX_HEADER_SIZE`, `TARDIGRADE_BODY_TIMEOUT_MS`, `TARDIGRADE_HEADER_TIMEOUT_MS`.

### Changed
- Gateway startup and request handling now use structured JSON logger.
- Edge config extended with `request_limits`, `basic_auth_hashes`, and `log_level` fields.
- `authorizeRequest` now tries bearer token first, then falls back to HTTP Basic Auth.

## [0.11.0] - 2026-03-xx

### Added
- IP access control (`src/http/access_control.zig`):
  - Allow/deny rules with CIDR notation support (IPv4 and IPv6).
  - First-match-wins evaluation order (nginx-style).
  - IPv4 and IPv6 address parsing with full CIDR prefix matching.
  - Configurable via `TARDIGRADE_ACCESS_CONTROL` env var.
  - Example: `"allow 10.0.0.0/8, deny 0.0.0.0/0"`.

### Changed
- Edge gateway applies IP access control before rate limiting (returns 403 Forbidden).
- Edge config extended with `access_control_rules` field.

## [0.10.0] - 2026-03-xx

### Added
- Structured command routing (`src/http/command.zig`):
  - Command envelope format with typed commands (`chat`, `tool.list`, `tool.run`, `status`).
  - Params validation (must be JSON object, max 128KB).
  - Inline idempotency key support within command envelope.
  - Upstream envelope builder that wraps params with gateway context (identity, correlation ID, client IP, API version, timestamp).
  - Structured `CommandAudit` logging per command.
- Gateway `POST /v1/commands` endpoint:
  - Accepts bearer token or session token auth.
  - Parses command envelope and routes to appropriate upstream path.
  - Idempotency support (inline key or header-based).
  - Full upstream error mapping and structured audit.

### Changed
- Edge gateway extended with `proxyCommand` for command-specific upstream forwarding.

## [0.9.0] - 2026-03-xx

### Added
- Session management system (`src/http/session.zig`):
  - Cryptographic session token generation (32 bytes / 256 bits entropy, hex-encoded).
  - In-memory session store with per-identity tracking, device ID support, and idle TTL expiry.
  - Session revocation (single token or all sessions for an identity).
  - Max concurrent session enforcement via `TARDIGRADE_SESSION_MAX` env var (default 1000).
  - Session TTL via `TARDIGRADE_SESSION_TTL` env var (default 3600s).
  - Automatic cleanup of expired sessions.
- Gateway session endpoints:
  - `POST /v1/sessions` — create session (requires bearer auth, optional `X-Device-ID`).
  - `DELETE /v1/sessions` — revoke session (requires `X-Session-Token`).
  - `GET /v1/sessions` — list active sessions for identity (requires bearer auth).
- Session-based auth as alternative to bearer tokens on `POST /v1/chat`.

### Changed
- Edge config extended with `session_ttl_seconds` and `session_max` fields.
- Gateway state now includes optional `SessionStore`.

## [0.8.0] - 2026-03-xx

### Added
- Token-bucket rate limiter per client IP (`src/http/rate_limiter.zig`):
  - Configurable requests-per-second and burst capacity via `TARDIGRADE_RATE_LIMIT_RPS` and `TARDIGRADE_RATE_LIMIT_BURST` env vars.
  - Automatic stale bucket cleanup (5-minute idle expiry).
  - Returns 429 Too Many Requests when exceeded.
- Security headers middleware (`src/http/security_headers.zig`):
  - X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security, Referrer-Policy, Permissions-Policy, X-XSS-Protection.
  - Default secure and API presets; configurable via `TARDIGRADE_SECURITY_HEADERS` env var.
  - Applied to all gateway responses including error responses.
- Request context and auth context propagation (`src/http/request_context.zig`):
  - Per-request context struct carrying identity, timing, client IP, API version, and idempotency key.
  - Client IP extraction from X-Forwarded-For, X-Real-IP, or connection default.
  - Structured audit logging with identity and API version fields.
- API version routing (`src/http/api_router.zig`):
  - Parses `/v<N>/...` paths and extracts version number and sub-route.
  - Supported version allowlist (v1, v2).
  - Rejects unsupported API versions with 400 error.
  - Edge gateway now uses version-aware route matching.
- Idempotency key support (`src/http/idempotency.zig`):
  - Parses and validates `Idempotency-Key` header.
  - In-memory cache with configurable TTL (default 300s) via `TARDIGRADE_IDEMPOTENCY_TTL`.
  - Replays cached responses for duplicate POST requests with `X-Idempotent-Replayed: true` header.
  - Automatic expired entry cleanup.

### Changed
- Edge gateway refactored to use middleware pipeline:
  - Rate limiting applied before route dispatch.
  - Security headers applied to all responses.
  - Request context propagated through handler chain.
  - Auth result now includes token hash for identity tracking.
- Edge config extended with rate limiting, security headers, and idempotency settings.

# [0.7.0] - unreleased

### Added
- sendfile() zero-copy optimization for static file serving (in progress)
- Remote BearClaw gateway MVP edge path:
  - New edge config loader (`src/edge_config.zig`) with `listen_host`, `listen_port`, `tls_cert_path`, `tls_key_path`, `upstream_base_url`, auth token hashes.
  - New edge runtime (`src/edge_gateway.zig`) with `GET /health` and authenticated `POST /v1/chat`.
  - Static bearer token auth using SHA-256 hash allowlist.
  - Request validation and stable API error envelopes with `request_id`.
  - Upstream forwarding to BearClaw with `X-Correlation-ID` propagation.
  - Structured audit logs for route/status/auth/correlation/latency.
- Correlation ID support via `X-Correlation-ID` header:
  - Echoes valid client-provided IDs in responses.
  - Generates `tg-<timestamp>-<random>` IDs when missing or invalid.
  - Applies to static-file and parse-error responses.
- Bearer authorization helpers via `src/http/auth.zig`:
  - Parses `Authorization: Bearer <token>` headers case-insensitively.
  - Validates bearer token character set and length.
  - Supports optional token validation hook callbacks for pluggable auth providers.

# [0.6.0] - 2026-01-29

### Added
- Content-Encoding negotiation for static file serving:
  - Parses `Accept-Encoding` header and negotiates supported encodings.
  - Responds with `identity` (no compression) for supported requests.
  - Returns `406 Not Acceptable` for requests with only unsupported encodings (e.g., `br`, `deflate`).
  - Lays groundwork for future gzip support.
  - Comprehensive tests for Accept-Encoding negotiation in `src/http/content_encoding_test.zig`.

## [0.5.0] - 2026-01-30

### Added

- Add `Last-Modified` header for static files and support `If-Modified-Since` (returns 304 Not Modified when appropriate).
- Add robust HTTP-date parser supporting RFC1123, RFC850, and asctime formats for conditional GET handling.
- Add directory autoindex (directory listing) for directories without index files.
 - Add `ETag` header for static files and support `If-None-Match` (returns 304 Not Modified when matching). ETag is generated from file size and mtime to avoid costly content hashing.

## [0.4.1] - 2026-01-27

### Added
- Custom error pages (public/errors/*.html)
  - Serve `public/errors/<status>.html` when present for 400, 401, 403, 404, 500, 502, 503, 504
  - Fall back to short plain-text responses when no custom page exists
  - Sample custom pages added for 404 and 500 in `public/errors/`

### Changed
- Bumped `Server` identification to `tardigrade/0.4.1` in responses

## [0.4.0] - 2026-01-27

### Added
- Directory index support (index.html, index.htm)
  - Requests to directories automatically serve index.html or index.htm
  - Directories without trailing slash get 301 redirect (e.g., /docs → /docs/)
  - Returns 404 if no index file exists in the directory

### Changed
- Refactored `serveFile` into smaller functions for clarity
- Fixed keep-alive socket timeout to use POSIX `setsockopt` (macOS/Linux compatible)

## [0.3.0] - 2026-01-27

### Added
- HTTP Response builder module (`src/http/response.zig`)
  - Builder pattern for constructing HTTP responses
  - Auto-generated Date header (RFC 7231 format)
  - Auto-generated Server header (tardigrade/0.3.0)
  - Auto-calculated Content-Length
  - Convenience constructors for common responses (ok, notFound, redirect, etc.)
- HTTP Status code module (`src/http/status.zig`)
  - All standard HTTP status codes (1xx-5xx)
  - Status code to reason phrase mapping
  - Helper methods (isSuccess, isError, isRedirection, etc.)

### Changed
- Refactored main.zig to use Response builder
- All responses now include Date and Server headers
- Method Not Allowed (405) responses now include Allow header

## [0.2.0] - 2026-01-26

### Added
- HTTP/1.1 request parser with full RFC compliance
  - Method parsing (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE)
  - URI parsing with path and query string separation
  - HTTP version parsing (HTTP/1.0, HTTP/1.1)
  - Header parsing (case-insensitive, whitespace trimming)
  - Request body handling with Content-Length
- MIME type detection for 30+ file types
- Proper HTTP error responses (400, 404, 405, 413, 414, 431, 500, 501, 505)
- HEAD request support
- Path traversal protection
- Structured logging with std.log

### Changed
- Refactored main.zig to use new modular HTTP parser
- Improved response headers (Content-Length, Content-Type, Connection)

## [0.1.0] - 2025-05-28

### Added
- Initial HTTP server implementation
- Static file serving from `public/` directory
- Basic GET request handling
- Listens on port 8069
- 404 response for missing files
- 405 response for non-GET methods
