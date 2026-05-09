# Changelog

All notable user-facing changes to Tardigrade are documented here.

## [Unreleased]

### Added
- Added `TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY` (default `true`) — when enabled, only idempotent HTTP methods (GET, HEAD, PUT, DELETE, OPTIONS, TRACE) are retried on connection failure or 5xx; POST and PATCH are never retried. Added `TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS` (default 5 000 ms) as a separate connect-phase timeout applied to upstream sockets before the first send. `handleLocationProxyPass` (the general HTTP proxy path) now retries with the same attempt/budget logic as the JSON proxy path.
- Added 22 unit tests covering `range.zig` (open-ended range, clamping, reversed range, multi-range, `formatContentRange`), `etag.zig` (determinism, wildcard, list matching), and `static_file.zig` (206 partial content with exact body and `Content-Range`, suffix range, 416 for unsatisfiable range, 304 for matching `If-None-Match`, wildcard `If-None-Match`, non-matching `If-None-Match`, `If-Modified-Since` cache hit and miss, conditional-takes-precedence-over-range per RFC 9110 §13.1, and large-file 512 KB body integrity). Removed two orphaned test files that referenced non-existent APIs.
- Added `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` config option (default 30 000 ms). On SIGTERM/SIGINT, tardigrade now waits up to this timeout for in-flight requests to finish before force-closing queued connections. Setting it to 0 reverts to immediate close behavior.
- TLS 1.0 and 1.1 are now explicitly rejected at config validation; only TLS 1.2 and 1.3 are accepted.
- Added `TARDIGRADE_HSTS_ENABLED`, `TARDIGRADE_HSTS_MAX_AGE`, `TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS`, and `TARDIGRADE_HSTS_PRELOAD` config options. HSTS is emitted only on HTTPS responses and only when TLS is configured.
- Enabled `TCP_NODELAY` on accepted connections to remove keep-alive latency spikes.
- Added a remote benchmark driver and documented the dedicated performance-target workflow.
- Added a file-backed plain-HTTP static response path with unit and integration coverage for full-file and range handling.
- Added a configurable Prometheus metrics endpoint with optional auth gating and integration coverage for counter growth.

### Added
- Added `static-http2`, `static-http3`, and `proxy-http3` benchmark scenarios to `benchmarks/run.sh`. `static-http2` uses `h2load` (cleartext HTTP/2) or `k6` over TLS; `static-http3` and `proxy-http3` use `h2load --h3` and require TLS — both print a clear skip message when `h2load` lacks QUIC support or TLS is absent. Added `--h2-path` and `--h3-path` path overrides. The metadata block now records `h2_path` and `h3_path`. Updated `benchmarks/README.md` with a skip-condition table, tool capability notes, and example commands for HTTP/2 and HTTP/3 protocol runs.
- Improved config validation and added `warnRiskyConfig`: `validate()` now rejects mismatched TLS cert/key pairs, `tls_client_verify` without a CA path, `otel_sample_rate` outside 0–100, `compression_brotli_quality` outside 0–11, and `upstream_retry_attempts` of 0. A new `warnRiskyConfig` function logs operator warnings for insecure defaults such as disabled upstream TLS verification, disabled rate limiting, 0-RTT HTTP/3, ACME enabled with no domains, TLS without HSTS, and an ignored client CA path. Both `tardigrade validate` and `tardigrade run` now surface these warnings at startup and on reload. Added 5 unit tests covering the new validation helpers.
- Added unit tests covering `main.zig` core helpers: `parsePid`, `readPidFromFile`, `rotateLogFiles`, `parseCliCommand`, and `writeStarterConfig`; fixed `readPidFromFile` to use `allocRemaining` instead of `readAlloc` so it correctly reads pid files shorter than the buffer size.
- Added 14 unit tests covering `zig_compat.zig` compat functions (timestamp, random, stringify, fixedBufferStream, trimRight, fmtSliceHexLower, DirCompat file I/O), `http2_frame` writeSettings/writeSettingsAck/writeGoaway encoding, and `access_log` formatEntry JSON output including null upstream_status handling.

### Changed
- Modernized `build.zig` for Zig 0.16: removed boilerplate comments, extracted `configureSsl` helper to deduplicate OpenSSL/HTTP3 library setup across exe and test targets, removed unused `Io` import. Expanded `CONTRIBUTING.md` with a build-option table and common workflow examples.
- Replaced deprecated `std.fs.path.*` module access with `std.Io.Dir.path.*`; updated deprecated `std.Io.File.CreateFlags`/`OpenFlags` parameter types to `std.Io.Dir.CreateFileOptions`/`OpenFileOptions` across main.zig and filesystem helpers.
- Replaced deprecated `std.mem.indexOf*` and `std.mem.lastIndexOf*` family with the Zig 0.16 `find*` equivalents across 33 source files (256 call sites).
- Replaced deprecated `std.ArrayListUnmanaged` with `std.ArrayList` in config file parser; threaded explicit allocator through `http2_frame.writeSettings` and `writePushPromise` to remove hardcoded `page_allocator` usage.
- Simplified the root docs into a smaller public-facing set: `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, and the example deployment bundle.
- Updated the benchmark runner to support explicit host and route overrides for named-vhost and proxied-route testing.
- Pinned the repository, CI workflows, and homelab deploy build script to Zig `0.16.0` as the first step of the Zig 0.16 migration.
- Completed the Zig 0.16.0 upgrade: migrated all `std.http.Client` call sites from `open()`/`send()`/`wait()` to `request()`/`sendBodyComplete()`/`receiveHead()`, replaced `std.json.stringify` with `std.json.Stringify.valueAlloc`, resolved all `ArrayList`/`Managed` type mismatches across `fastcgi`, `scgi`, `uwsgi`, and `http3_session`, replaced `accept4` with `accept`+`fcntl` for macOS compatibility, and fixed `UnixAddress.init` error propagation. All 357 tests pass on Zig 0.16.0.

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
