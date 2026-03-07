
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
