# Changelog

All notable user-facing changes to Tardigrade are documented here.

## [Unreleased]

### Added
- TLS 1.0 and 1.1 are now explicitly rejected at config validation; only TLS 1.2 and 1.3 are accepted.
- Added `TARDIGRADE_HSTS_ENABLED`, `TARDIGRADE_HSTS_MAX_AGE`, `TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS`, and `TARDIGRADE_HSTS_PRELOAD` config options. HSTS is emitted only on HTTPS responses and only when TLS is configured.
- Enabled `TCP_NODELAY` on accepted connections to remove keep-alive latency spikes.
- Added a remote benchmark driver and documented the dedicated performance-target workflow.
- Added a file-backed plain-HTTP static response path with unit and integration coverage for full-file and range handling.

### Changed
- Simplified the root docs into a smaller public-facing set: `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, and the example deployment bundle.
- Updated the benchmark runner to support explicit host and route overrides for named-vhost and proxied-route testing.

### Fixed
- CI now installs OpenSSL development headers explicitly and enforces formatting consistently.
- Proxy requests now strip RFC hop-by-hop headers, including headers named by the incoming `Connection` field, before forwarding to upstreams.
- Static file serving now rejects percent-encoded traversal, separator-variant traversal, and symlink escapes outside the configured root.
- Rate limiting now resolves authenticated identity before middleware enforcement so JWT, bearer, and session traffic do not share an IP-only bucket.
- Hot reload now retires superseded configs after in-flight requests complete so repeated reloads do not accumulate stale config allocations.
- Request IDs now accept `X-Request-ID` input, echo both request-id headers on responses, propagate upstream, and enrich JSON access logs with upstream address, upstream status, and response byte counts.

## [0.62.0] - 2026-04-24

### Added
- Added per-location auth controls in config files and env-driven location blocks.
- Added identity-aware rate limiting, sticky upstream affinity, transcript browsing, and DNS-based upstream discovery.
- Added a benchmark harness, native package scaffolding, Kubernetes packaging, release checksum verification, trace-context propagation, reload-status reporting, and a public security policy.

### Changed
- Improved reload-status tracking and clarified which operational endpoints are built in versus operator-configured.

### Fixed
- Stripped inbound `X-Tardigrade-*` headers before proxying so clients cannot forge asserted identity headers.
- Corrected routing and auth behavior on prefixed API mounts and fixed root-doc endpoint descriptions.

## [0.32.0] - 2026-03-xx

### Added
- Added HS256 JWT auth support with asserted identity headers for upstream services.
- Added automated release tagging, published multi-platform release assets, and embedded release versions in the binary.
- Expanded the example deployment bundle with clearer edge-contract documentation.

### Changed
- Stopped tracking repo-local deployment notes and local-only runtime files in the public tree.

### Fixed
- Fixed prefixed API auth and routing behavior, including correct `401` versus `403` handling.

## [0.31.0] - 2026-03-xx

### Added
- Reworked the integration harness around generic server boots and example-driven fixtures.
- Refreshed the public documentation set and isolated integration-specific guidance under `examples/`.
- Added persisted approval workflows, escalation hooks, mux replay support, overflow handling, and channel-cap controls.

### Fixed
- Fixed config-driven proxy routing precedence, upstream redirect transparency, and mounted-path proxy behavior.

## [0.30.0] - 2026-03-xx

### Added
- Added the first full live integration suite covering proxying, TLS, auth, reloads, shutdown, and concurrency behavior.
- Added active upstream health checks and the first opt-in HTTP/3 runtime path with live QUIC test coverage.
- Added FastCGI, SCGI, uWSGI, and mail-relay bridge support, plus rewrite, `return`, and `location` routing foundations.

### Fixed
- Fixed QUIC/TLS bootstrap issues, backend protocol parsing, and several integration-harness stability problems.

## [0.29.0] - 2026-03-08

### Added
- Added authenticated WebSocket and SSE streaming support.
- Added Brotli and gzip response compression improvements.
- Added nginx-style config parsing, hot reload, secret management, and device/session policy controls.
- Added async command lifecycle handling, multiplexed streams, approval workflows, richer access logging, and admin observability endpoints.

## [0.28.0] - 2026-03-07

### Added
- Added proxy caching with purge, stale serving, and configurable cache keys.
- Added JWT validation, auth subrequests, geo blocking, and response-header controls.
- Added expanded TLS features including SNI, mTLS, OCSP stapling, session resumption, and dynamic reload checks.
- Added HTTP/2 foundations, richer upstream load-balancing modes, active/passive health tracking, PROXY protocol support, trusted-upstream signing, and Unix-socket upstreams.

## [0.27.0] - 2026-03-07

### Added
- Added keep-alive request reuse, request pipelining support, and graceful connection draining.
- Added worker-queue load balancing, work stealing, reusable connection state, and tighter memory controls.
- Added upstream retries, timeout budgets, overload shedding, operational metrics, and multiple load-balancing strategies.

## [0.26.0] - 2026-03-07

### Added
- Switched request processing to a request-scoped arena allocator to reduce per-request allocation overhead.

## [0.25.0] - 2026-03-07

### Added
- Added configurable keep-alive connection reuse and max-requests-per-connection limits.

## [0.24.0] - 2026-03-07

### Added
- Added configurable socket timeouts for request headers and upstream send/receive operations.

## [0.23.0] - 2026-03-07

### Added
- Added the initial `proxy_pass` routing model for chat and command upstreams.

## [0.22.0] - 2026-03-07

### Added
- Added shared upstream HTTP client pooling so proxied requests can reuse backend connections.

## [0.21.0] - 2026-03-07

### Added
- Added streamed upstream response forwarding for successful proxy responses.

## [0.20.0] - 2026-03-07

### Added
- Added native HTTPS/TLS termination backed by OpenSSL.

## [0.19.0] - 2026-03-07

### Added
- Added per-IP active connection limiting for inbound client traffic.

## [0.18.0] - 2026-03-07

### Added
- Added graceful worker draining so queued and in-flight work completes during shutdown.

## [0.17.0] - 2026-03-07

### Added
- Added standard forwarded upstream headers and upstream `Host` rewriting for proxy requests.

## [0.16.0] - 2026-03-07

### Added
- Added a fixed-size worker thread pool with bounded queue backpressure.

## [0.15.0] - 2026-03-07

### Added
- Added the cross-platform async event-loop foundation with non-blocking accept handling and timer ticks.

## [0.14.0] - 2026-03-07

### Added
- Added an upstream circuit breaker, Prometheus metrics output, and structured JSON access logs.

## [0.13.0] - 2026-03-07

### Added
- Added gzip response compression, JSON metrics output, and graceful shutdown signal handling.

## [0.12.0] - 2026-03-07

### Added
- Added HTTP Basic Auth support, structured JSON logging, browser cache-control helpers, and request-size/header validation.

## [0.11.0] - 2026-03-xx

### Added
- Added CIDR-based IP allow and deny rules.

## [0.10.0] - 2026-03-xx

### Added
- Added structured command routing, command-specific proxying, and command audit logging.

## [0.9.0] - 2026-03-xx

### Added
- Added session creation, listing, revocation, expiry, and session-token auth support.

## [0.8.0] - 2026-03-xx

### Added
- Added token-bucket rate limiting, security headers, request-context propagation, API version routing, and idempotency-key replay support.

## [0.7.0] - unreleased

### Added
- Introduced the authenticated edge gateway MVP with config loading, bearer auth, correlation IDs, request validation, and upstream proxying.

## [0.6.0] - 2026-01-29

### Added
- Added `Accept-Encoding` negotiation groundwork for static responses.

## [0.5.0] - 2026-01-30

### Added
- Added `Last-Modified`, `ETag`, conditional requests, and directory autoindex support for static files.

## [0.4.1] - 2026-01-27

### Added
- Added custom error pages for common client and server error responses.

### Changed
- Updated the reported server version string.

## [0.4.0] - 2026-01-27

### Added
- Added directory index resolution and trailing-slash redirects for directory requests.

### Fixed
- Fixed keep-alive timeout handling across macOS and Linux.

## [0.3.0] - 2026-01-27

### Added
- Added reusable HTTP response-builder and status-code modules.

### Changed
- Standardized `Date`, `Server`, and `Allow` response headers.

## [0.2.0] - 2026-01-26

### Added
- Added a modular HTTP/1.1 parser with HEAD support, MIME detection, robust error handling, and path-traversal protection.

## [0.1.0] - 2025-05-28

### Added
- Initial HTTP server with static file serving and basic GET request handling.
