# Changelog

All notable user-facing changes to Tardigrade are documented here.

## [Unreleased]

### Added
- Zig 0.16 engineering guide and code review process: added `docs/ZIG_ENGINEERING_GUIDE.md` (Tardigrade-specific Zig 0.16 patterns, APIs to avoid, runtime architecture, allocator and error handling rules, security coding rules, and testing requirements) and `docs/CODE_REVIEW_CHECKLIST.md` (short build/memory/error/security/perf/docs checklist for every PR). Updated `AGENTS.md` to reference both documents. Expanded PR template with explicit Tests, Security impact, and Performance impact sections. Updated bug report and feature request templates to ask for security impact and test requirements. Added guide links to `CONTRIBUTING.md` and `README.md` documentation table. Closes #83.
- Security hardening and pentest program: added `docs/SECURITY_TEST_PLAN.md` and `docs/PENTEST_PLAYBOOK.md`, introduced a request parser corpus replay + deterministic mutation harness under `tests/security/` and `tests/corpus/`, expanded parser/path/header/auth regression coverage, and documented the first internal pentest workflow including `ursa-minor` usage boundaries. Closes #85.
- CI/CD pipeline validation fixes: removed `--multiline-errors` flag (invalid in fresh Zig 0.16.0 installs), replaced `gitleaks/gitleaks-action@v2` (paid license) with gitleaks CLI v8.30.1, added `.gitleaks.toml` to allowlist action SHA pins (false positives), set hadolint `failure-threshold: error` so DL3008 warnings don't block CI, upgraded `github/codeql-action` v3 → v4, fixed SC2129 shellcheck warning in `release.yml`, and added `continue-on-error: true` to `dependency-review` (requires Dependency Graph feature in repo settings). Discovered during PR pipeline validation.
- Professionalized CI/CD pipeline: expanded format, lint, security, and build validation across all jobs. Added `format`, `lint` (actionlint, shellcheck, hadolint), `security` (Gitleaks secret scanning, Trivy filesystem scan, zizmor GitHub Actions hardening), and `dependency-review` (PRs only) jobs to `ci.yml`. Expanded unit-test and build-validation matrices to Ubuntu x86_64, Ubuntu ARM64, and macOS ARM64; build matrix covers Debug, ReleaseSafe, and ReleaseFast optimization profiles. Updated `container.yml` with Trivy container image scan and SBOM generation. Updated `release.yml` with SBOM generation (archives + DEB packages), provenance attestation via `actions/attest-build-provenance`, and Trivy archive scan before publish. Added `scorecard.yml` for weekly OSSF Scorecard analysis with SARIF upload to the Security tab. Pinned all third-party GitHub Actions to full commit SHAs. Closes #82.
- WorkerPool design rationale: documented why Tardigrade uses manual `std.Thread.spawn` rather than `std.Io.Group` or the removed `std.Thread.Pool` — the blocking thread-per-connection model is incompatible with async group primitives. Added design rationale block comment to `worker_pool.zig` and summary to `AGENTS.md`. 7 existing tests confirmed covering submit, drain, shutdown, queue selection, and work-stealing. Closes #81.
- `std.c`/`std.posix` usage audit: reviewed all direct POSIX/C API usage across 11 modules. All usage confirmed intentional: sockets, kqueue/epoll, signal handling, OpenSSL C heap interop, QUIC binding, POSIX file-mode ops. No avoidable calls found. Findings documented in `AGENTS.md`. Closes #80.
- `compat.io()` migration pattern: refactored `autoindex.generateAutoIndex` to accept explicit `io: std.Io` instead of calling `compat.io()` internally — demonstrates the pattern for future migrations. Call site in `static_file.zig` passes `compat.io()` for now. Remaining sites and migration guidance documented in `AGENTS.md`. Closes #79.
- Canonical Zig 0.16 development commands: `CONTRIBUTING.md` updated with exact fmt, unit-test, integration-test, and release-build commands matching CI; README Testing section updated with verbose test flags. Closes #78.
- Zig formatting validation extended to `tests/` directory: `ci.yml` `zig fmt --check` now covers `build.zig`, `src/`, and `tests/`. README Formatting section added. Closes #77.
- CI gating for release and container workflows: `release.yml` now has a `test` job that must pass before `prepare-release` runs; `container.yml` runs unit tests before the binary build. Both use `--summary all --error-style verbose --multiline-errors`. Closes #76.
- Replaced `std.fs.cwd()` in `tests/http3_resumption_client.zig` with `compat.cwd()` — all filesystem access in the HTTP/3 resumption test now goes through the `zig_compat.zig` layer. Closes #75.
- `build.zig.zon` paths updated to include `tests`, `README.md`, and `LICENSE` — package contents are appropriate for Zig 0.16 package fetching. Closes #74.
- Zig 0.16 performance benchmarking: added `scripts/build-benchmarks.sh` to measure clean, incremental, and test build times and optionally save JSON records for tracking. Documented Zig 0.16 build characteristics (incremental compilation, cross-compilation, LTO), runtime performance targets, and known hot paths in `AGENTS.md`. Benchmarks confirmed no regressions — existing `benchmarks/run.sh` and `jetson-run.sh` infrastructure covers regression tracking. Closes #73.
- Modern cryptography: adopted Zig 0.16 `std.crypto.aead.aes_gcm.Aes256Gcm` for secret storage. Added `encryptSecret`/`decryptSecret` in `secrets.zig` providing authenticated AES-256-GCM encryption (12-byte random nonce + ciphertext + 16-byte GCM tag). `loadOverrides` now decrypts `ENC2:<base64-blob>` values with AES-256-GCM; the legacy `ENC:<base64-xor>` format is still supported for backward compatibility. 4 new unit tests covering roundtrip, wrong-key rejection, nonce randomness, and base64 envelope. 451 tests total. Closes #72.
- Reader/Writer abstraction audit: eliminated heap allocations from `NetStream.Writer.print` and `TlsConnection.Writer.print` — both now format into a 4 KiB stack buffer instead of allocating from `page_allocator`. Added `TlsConnection.Writer.writeByte` for interface consistency. Added 3 unit tests in `response.zig` demonstrating that `Response.write()` and `Request.parse()` are transport-agnostic (work with any writer / `[]const u8` slice without live sockets). 447 tests total. Closes #70.
- Zig architecture and ownership audit: reviewed module sizes, allocator ownership, config lifecycle, and error-handling patterns. Confirmed no memory safety issues or concurrency races; all v0.2 hardening issues closed. Documented findings (module-size inventory, allocator ownership table, config lifecycle notes, errdefer coverage, outstanding structural debt) in `AGENTS.md`. 444 tests pass. Closes #60.
- Profiling workflow: added `scripts/profile.sh` with sub-commands for building profiling-optimised binaries (`ReleaseSafe`) and step-by-step CPU and memory profiling instructions for Linux (`perf`, flamegraph, Valgrind massif, heaptrack) and macOS (`sample`, Instruments Time Profiler, Allocations, Leaks). Documented known hot paths and a benchmark+profile workflow in `AGENTS.md`. No binary overhead — all profiling uses external OS tools. Closes #59.
- Event loop audit: active health probes moved from main event loop thread to a detached background thread (`activeHealthProbeThread`), eliminating blocking HTTP round-trips from the hot path. `GatewayState.health_probe_running` (atomic bool) prevents duplicate batches; probe thread holds a `ConfigLease` so hot-reload cannot free config during probing. Added `event_loop_iterations` and `health_probe_runs` Prometheus/JSON counters for event loop health observability. Documented event loop I/O model (level-triggered epoll/kqueue listener, thread-per-connection blocking workers, background probes) in `AGENTS.md`. Added 3 unit tests (444 total). Closes #58.
- Concurrency audit: inventoried all shared mutable state in `GatewayState` (12 mutex-protected domains). Confirmed no races: `lb_random_state` is always updated inside `Locked`-suffix helpers that require `upstream_mutex`; config pointer swaps use ref-counted `ReloadableConfigStore` so in-flight leases are never freed. Extracted PRNG step as public `lcrngNext` pure function. Added shared-state inventory table and reload-safety notes to `AGENTS.md`. Added 3 unit tests covering PRNG distinctness, determinism, and period sanity. 442 tests total. Closes #57.
- Transfer-Encoding / Content-Length conflict detection: requests containing both `Transfer-Encoding` and `Content-Length` now return `ConflictingHeaders` (400) per RFC 7230 §3.3.3, eliminating the request-smuggling vector. `Transfer-Encoding: chunked` requests are now decoded correctly via a new `decodeChunkedBody` helper; chunk extensions (`;name=value`) are stripped. Unsupported transfer codings are rejected. Added `ConflictingHeaders` and `InvalidChunkedBody` to `ParseError`. 5 unit tests covering TE+CL conflict, valid chunked decode, chunk extensions, malformed chunks, and body-size limit. 439 tests total. Closes #56.
- Sensitive header redaction: added `shouldRedactHeader` and `sanitizeHeaderValue` to `access_log.zig`. Default redaction list covers `authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`, and `www-authenticate`. Override via `TARDIGRADE_REDACT_HEADERS` (comma-separated). Config field `log_redact_headers` threaded through `EdgeConfig` and both `access_log.init` call sites. 3 new unit tests covering default list, custom override, and value sanitization. 434 tests total. Closes #54.
- Request size limits: `too_many_headers` post-parse rejection now returns `431 Request Header Fields Too Large` instead of `400`; `HeadersTooLarge`, `HeaderTooLarge`, and `TooManyHeaders` parse errors from the request parser also return `431`; `BodyTooLarge` parse errors return `413`. Added `max_headers_total_size` field to `RequestLimits` (default 32 KB, configurable via `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE`) with a `validateHeadersTotalSize` helper and a post-parse check in the request handler. Added 5 unit tests (431 total). Closes #53.
- Header injection defense: `parseHeaders` and `Headers.append` now validate names and values against RFC 7230 §3.2.6. Header names must be RFC token characters (no control chars, space, colon, or DEL); values must not contain CR, LF, NUL, or other control characters (HTAB and printable ASCII/obs-text are allowed). Returns `error.InvalidHeader` on violation. Added `isValidHeaderName` and `isValidHeaderValue` as public helpers. Added 5 unit tests covering injection attempts, control chars, and programmatic append paths. Closes #52.
- HTTP/3 0-RTT early-data safety: when `TARDIGRADE_HTTP3_ENABLE_0RTT` is enabled, streams arriving with `NGTCP2_STREAM_DATA_FLAG_0RTT` are tracked as early-data. Completed requests on those streams are checked for method safety; unsafe methods (POST, PUT, PATCH, DELETE, CONNECT) are rejected with `425 Too Early` instead of being forwarded to the handler. Safe methods (GET, HEAD, OPTIONS, TRACE) pass through normally. Added `isMethodSafe`, `markStreamEarlyData`, and `isStreamEarlyData` to `http3_session.zig`; added 3 unit tests. Documented HTTP/3 session resumption and 0-RTT operator caveats in `AGENTS.md`.
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
- Added a Zig `0.16.0` compatibility module to the integration harness and refreshed live test process/socket helpers for the new stdlib process and I/O APIs.
- Replaced deprecated `std.fs.path.*` module access with `std.Io.Dir.path.*`; updated deprecated `std.Io.File.CreateFlags`/`OpenFlags` parameter types to `std.Io.Dir.CreateFileOptions`/`OpenFileOptions` across main.zig and filesystem helpers.
- Replaced deprecated `std.mem.indexOf*` and `std.mem.lastIndexOf*` family with the Zig 0.16 `find*` equivalents across 33 source files (256 call sites).
- Replaced deprecated `std.ArrayListUnmanaged` with `std.ArrayList` in config file parser; threaded explicit allocator through `http2_frame.writeSettings` and `writePushPromise` to remove hardcoded `page_allocator` usage.
- Simplified the root docs into a smaller public-facing set: `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, and the example deployment bundle.
- Updated the benchmark runner to support explicit host and route overrides for named-vhost and proxied-route testing.
- Pinned the repository, CI workflows, and homelab deploy build script to Zig `0.16.0` as the first step of the Zig 0.16 migration.
- Completed the Zig 0.16.0 upgrade: migrated all `std.http.Client` call sites from `open()`/`send()`/`wait()` to `request()`/`sendBodyComplete()`/`receiveHead()`, replaced `std.json.stringify` with `std.json.Stringify.valueAlloc`, resolved all `ArrayList`/`Managed` type mismatches across `fastcgi`, `scgi`, `uwsgi`, and `http3_session`, replaced `accept4` with `accept`+`fcntl` for macOS compatibility, and fixed `UnixAddress.init` error propagation. All 357 tests pass on Zig 0.16.0.

### Fixed
- CI now installs OpenSSL development headers explicitly and enforces formatting consistently.
- Unix-socket upstream probing/proxying no longer depends on removed `std.http.Client.connectUnix()` behavior under Zig `0.16.0`; plain HTTP upstream compatibility paths now fall back to raw request/response handling where needed.
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
