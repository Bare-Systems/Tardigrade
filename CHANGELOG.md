
# Changelog

## [Unreleased]

### Added
- Multi-arch Linux release packaging:
  - GitHub Actions now builds and validates `tardigrade-linux-aarch64` alongside the existing `tardigrade-linux-x86_64` release artifact.
  - The release installer now resolves the correct Linux asset name for both `x86_64` and `aarch64` hosts.
- Sticky upstream affinity at the edge:
  - Relative `proxy_pass` locations and load-balanced API proxy routes now issue per-location HMAC-signed sticky cookies so repeat requests stay pinned to the same healthy upstream.
  - Tampered affinity cookies are ignored, unhealthy cookie targets are remapped to a healthy backend, and refreshed cookies are reissued with `HttpOnly`, `Secure`, and `SameSite=Lax`.
  - Added integration coverage for sticky pinning, tampered-cookie rejection, and unhealthy-backend remapping.
- Identity-aware rate limiting:
  - Authenticated BearClaw API traffic now rate-limits on asserted identity descriptors instead of collapsing all users behind the same client IP.
  - Limiter buckets now expire after an idle TTL so stale descriptors are evicted automatically.
  - Added shared-NAT coverage proving two JWT-authenticated users on the same IP are rate-limited independently.
- BearClaw transcript browser support at the edge:
  - Added authenticated `GET /bearclaw/transcripts` and `GET /bearclaw/transcripts/:id` endpoints so BearClawWeb can browse edge transcripts without reading the NDJSON file directly.
  - Transcript persistence now tightens the NDJSON file to owner-only permissions and redacts raw bearer token / JWT values before write.
  - Added coverage for transcript persistence, transcript browser responses, and the failure mode where a bad transcript path logs a warning while the proxied request still succeeds.

### Fixed
- BearClaw route returning 404 (#21):
  - The `/bearclaw/` location block was present in the live conf but the deployed binary had a stub `isProtectedAuthRequestRoute` that returned `false` for all paths, letting unauthenticated requests through to `/bearclaw/v1/*`. The correct implementation (protecting `/bearclaw/v1/*`, `/bearclaw/transcripts`, and direct `/v1/*` / `/transcripts` paths) has been in source since v1.22 and is now deployed.
  - Removed the `patch-source-and-rebuild` and `deploy-compiled-binary` hack verify tests that worked around the stale binary.
  - Fixed the `bearclaw-upstream-configured` verify test to check for the `/bearclaw/` location block rather than a hardcoded absolute upstream URL that was never written to the conf.

### Changed
- `blink.toml`: renamed the legacy `health_check.insecure` key to `tls_insecure = true` (Blink Sprint D flipped the HTTP adapter to TLS-verify-by-default). Behaviour is unchanged — Tardigrade's `https://127.0.0.1:8443/health` probe continues to skip TLS verification for the self-signed edge cert, but the flag name now matches Blink's new schema and surfaces as a visible warning in `blink plan`.

## [0.32.0] - 2026-03-xx

### Added
- Identity unification for the BearClaw edge:
  - Added HS256 JWT auth support (`TARDIGRADE_JWT_SECRET`, `TARDIGRADE_JWT_ISSUER`, `TARDIGRADE_JWT_AUDIENCE`) so BearClawWeb can authenticate operator requests through Tardigrade without sharing a static bearer token per user.
  - JWT-authenticated requests now project `X-Tardigrade-User-ID`, `X-Tardigrade-Device-ID`, and `X-Tardigrade-Scopes` to upstreams alongside `X-Tardigrade-Auth-Identity`.
  - Added integration coverage for `/bearclaw/v1/chat` with a BearClawWeb-style JWT and asserted-header forwarding.
- GitHub Actions release pipeline hardening:
  - CI now validates Tardigrade on both pull requests and `main` pushes so release-facing breakage is caught before packaging.
  - Release automation now reads the top semantic version from `CHANGELOG.md`, creates the matching Git tag on `main`, and publishes GitHub releases automatically.
  - Release assets now include Linux x86_64, macOS x86_64, and macOS arm64 archives plus a SHA-256 checksum manifest.
  - Release builds now embed the published semantic version into the Tardigrade binary and server header instead of shipping the stale hard-coded version string.
- TLS unit-test fixture tracking:
  - Added explicit `.gitignore` exceptions for the embedded TLS test private keys so CI sees the same fixture set as local development.
- BearClaw edge contract documentation:
  - Expanded `examples/bearclaw/tardigrade.env.example` with explicit notes for public ports, BearClaw mount paths, bearer token hashing, session/device/transcript persistence, and forwarded upstream headers.
  - Added a canonical BearClaw edge contract section to `AGENTS.md` covering the live path, required headers, token-hash procedure, persistence file shapes, and header forwarding expectations.

### Changed
- Ignored the repository-root `blink.toml` and `BLINK.md` and stopped tracking them so homelab-specific Blink targets and operator notes stay local-only.

### Fixed
- BearClaw edge auth and routing:
  - Protected `/bearclaw/v1/*` the same way as direct `/v1/*` routes while keeping `/bearclaw/health` public through the prefixed proxy mount.
  - Distinguished missing credentials (`401`) from invalid bearer tokens (`403`) at the edge gateway.
  - Added integration coverage proving `/bearclaw/health` rewrites to upstream `/health`, unauthenticated `/bearclaw/v1/chat` is rejected, invalid bearer tokens return `403`, and valid bearer requests proxy through to `/v1/chat`.

## [0.31.0] - 2026-03-xx

### Added
- Integration harness cleanup:
  - Split `tests/integration.zig` into explicit generic-server boots and optional BearClaw-profile boots sourced from `examples/bearclaw/`.
  - Added fixture generation from the BearClaw example config/env, layered config support, and deterministic harness-owned port/log overrides.
  - BearClaw-profile boots now default to HTTP for generic app-fixture tests and only enable fixture TLS when a test explicitly requests TLS/HTTP3 behavior.
  - Removed the deleted built-in application-surface assumptions from the live integration target by trimming the suite down to generic config-defined routing, reload, and static-file cases; removed product-surface tests are now skipped instead of failing against the generic core.
  - `zig build test` and `zig build test-integration` are green again after the harness split.
- Documentation refresh:
  - Reworked the top of `README.md` into a centered project header with navigation links, badges,
    and a clearer summary of Tardigrade’s server and gateway roles.
  - Added `CONTRIBUTING.md` with the repo’s actual upgrade-driven workflow, testing commands,
    and documentation expectations.
  - Removed product-specific naming from the root docs and added an isolated example deployment
    bundle under `examples/` for the application-specific gateway setup.
- Upgrade 12 approval workflow hardening:
  - Added `src/http/approval_store.zig` with atomic JSON-file persistence (`persist` + `load`)
    and a best-effort escalation webhook (`fireWebhook` via `std.http.Client`).
  - Added four new env-driven config fields: `TARDIGRADE_APPROVAL_STORE_PATH`,
    `TARDIGRADE_APPROVAL_TTL_MS`, `TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK`, and
    `TARDIGRADE_APPROVAL_MAX_PENDING_PER_IDENTITY`.
  - Pending approvals are now persisted on create/decide and reloaded on startup; decided
    entries older than one hour are pruned on load.
  - Added per-identity pending-approval rate limiting: exceeding the configured cap returns
    429 Too Many Requests on both HTTP/1.1 and HTTP/3 paths.
  - Expired approvals auto-escalate to `"escalated"` status; escalation webhook fires
    outside the approval mutex for best-effort delivery.
  - Added integration tests covering the full approval round-trip, double-respond conflict
    (409), per-identity rate limiting (429), and store persistence across server restart.
- Upgrade 13 mux observability and channel-cap hardening:
  - Added mux metrics for active mux websocket connections, total active mux subscriptions,
    per-device mux channel counts, and mux frame errors.
  - Added `TARDIGRADE_MUX_MAX_CHANNELS_PER_DEVICE` and enforced per-device channel caps in
    `/v1/ws/mux`.
  - Added live integration coverage proving mux metrics update while a socket is open, invalid
    mux frames increment the error counter, and a second subscription is rejected when the
    per-device cap is set to `1`.
  - Wired mux channel polling into the live websocket loop so subscribed event frames and async
    command lifecycle updates are actually emitted over `/v1/ws/mux`.
  - Added live mux integration coverage for unauthorized `401`, missing `X-Device-ID` `400`,
    subscribe-plus-publish event delivery, and async `command.update` delivery.
  - Added live two-client mux isolation coverage proving device A cannot receive events
    published onto device B’s namespaced topic, even when both subscribe to the same logical
    channel name.
  - Added `TARDIGRADE_MUX_WRITE_BUFFER_MAX` and a bounded per-socket mux pending-frame queue;
    when queued mux event/update frames exceed the configured byte budget, the oldest queued
    frames are dropped and an explicit `{"type":"overflow","dropped":N}` notice is sent.
  - Added live overflow coverage proving queued mux event delivery drops older frames and emits
    the overflow notice once the bounded write buffer is exceeded.
  - Added `last_event_id` replay on mux `subscribe` plus `TARDIGRADE_MUX_RECONNECT_GRACE_MS`
    state restoration, allowing a reconnecting device to replay missed mux events either
    explicitly by sequence ID or implicitly by reconnecting within the grace window.
  - Added live replay coverage for explicit `last_event_id` resume and reconnect-within-grace
    delivery of missed mux events.

### Fixed
- Config-driven reverse-proxy routing and header transparency:
  - Removed the remaining implicit operator-route handlers so `/health`, `/status`, and metrics paths are only served when config routes them.
  - Fixed mounted split-upstream location proxying so exact and more-specific `/ursa/...` routes can win over the generic mount while still stripping the mount prefix before proxying upstream.
  - Preserved upstream redirect `Location` headers and stopped auto-following proxy redirects, keeping upstream status, headers, and body intact for config-driven proxy locations.

## [0.30.0] - 2026-03-xx

### Added
- Completed the remaining Upgrade 11.0 SMTP auth relay slice by injecting `X-Tardigrade-Auth-Identity` into relayed SMTP `DATA` message headers for authenticated requests, with integration coverage against the test upstream.
- Added live IMAP and POP3 mail-relay coverage, proving `imap_pass` and `pop3_pass` relay LOGIN/USER/PASS command traffic through the existing raw mail proxy path.
- Added IMAP STARTTLS upstream support for `imap_pass starttls://...`, including a live integration harness; on macOS the harness is currently skipped because the local Zig test runner intermittently disconnects before the STARTTLS exchange even though the relay path works in direct manual repros.
- Upgrade 1 integration-test harness foundation:
  - Added a live-process `tests/integration.zig` suite that boots Tardigrade with deterministic env config.
  - Added a loopback upstream test server to exercise real proxy requests over TCP.
  - Added `zig build test-integration` and CI coverage for unit + integration test runs.
  - Added coverage for `/metrics` Prometheus output and moved JSON metrics output to `/metrics/json` while preserving `/metrics/prometheus`.
  - Added integration coverage for JWT, device auth, session lifecycle, rate limiting, proxy cache stale refresh, hot reload, and graceful shutdown flows.
  - Added integration coverage for proxy forwarding fidelity, upstream `Cache-Control: no-store` cache bypass, and upstream 5xx retry handling.
  - Added integration coverage for single-hop upstream redirect following and `Connection: close` on keep-alive responses during graceful shutdown.
  - Added TLS integration coverage for self-signed HTTPS health checks and mTLS rejection of clients signed by an untrusted CA.
  - Added TLS graceful-drain coverage that verifies in-flight HTTPS responses switch to `Connection: close` during shutdown.
  - Added SNI integration coverage that verifies `sni.integration.test` presents the configured alternate certificate while unknown hostnames keep the default certificate.
  - Added concurrency integration coverage for 100 parallel chat requests and worker-queue saturation with queue-rejection metrics.
  - Added concurrent mixed bearer-auth and session-auth chat coverage to prove auth-plus-rate-limit contention does not deadlock the shared gateway state path.
  - Added graceful-shutdown exit coverage that verifies the gateway process exits promptly after drain, closes the listener, and logs shutdown completion.
  - Added saturation-ordering coverage that verifies a single-worker queue drains accepted `/v1/chat` requests in the same order they were admitted.
- Upgrade 2 active upstream health-check foundation:
  - Added `src/http/health_checker.zig` with explicit up/down/half-open transition logic and unit coverage.
  - Added integration coverage for active probe down detection, rerouting away from failed upstreams, recovery after probe successes, and degraded `/health` reporting.
  - Added Upgrade 2 env aliases for upstream probe settings on top of the existing active-probe settings.
  - Added active probe success-status config with a default range plus exact upstream URL overrides for non-2xx health endpoints.
- Upgrade 3 HTTP/3 ngtcp2/nghttp3 foundation:
  - Added opt-in build wiring for `ngtcp2`, `ngtcp2_crypto_ossl`, and `nghttp3` via `-Denable-http3-ngtcp2=true`.
  - Added `src/http/ngtcp2_binding.zig` as a compile-safe ngtcp2/nghttp3 wrapper seam gated by build options.
  - Added `src/http/http3_handler.zig` with initial `Alt-Svc` formatting and pseudo-header-to-request mapping helpers.
  - Added HTTP/3 stream-assembly helpers in `src/http/http3_session.zig` for split HEADERS/DATA accumulation and response header-block encoding.
  - Added a compile-safe nghttp3 server-session wrapper in `src/http/http3_session.zig` with control/QPACK stream binding and response-submission plumbing.
  - Added `TARDIGRADE_QUIC_PORT` config support and `src/http/http3_runtime.zig` as the first UDP listener/bootstrap path for future ngtcp2 packet handling.
  - Added HTTP/1.1 `Alt-Svc` advertisement for configured HTTP/3 endpoints and integration coverage for that header on `/health`.
  - Added initial QUIC datagram parsing and connection-ID tracking in the HTTP/3 runtime as groundwork for real migration handling.
  - Added TLS cert/key/version plumbing from gateway config into the HTTP/3 bootstrap seam, plus a warning when HTTP/3 is enabled without TLS material.
  - Added one-time QUIC bootstrap server state in the HTTP/3 runtime so datagrams are handled against persistent bootstrap state instead of reinitializing per packet.
  - Added a first QUIC-specific OpenSSL TLS context setup path in the ngtcp2 binding seam, including TLS 1.3 enforcement and cert/key loading.
  - Added `/health` reporting for HTTP/3 configuration state and QUIC port, plus integration coverage for the incomplete-TLS QUIC configuration case.
  - Added native ngtcp2 server-connection creation for Initial packets, real `ngtcp2_conn_read_pkt` processing, and HTTP/3 runtime snapshot surfacing for handshake/read state on `/health`.
  - Added HTTP/3-enabled unit coverage for native packet-read state tracking in `src/http/ngtcp2_binding.zig`.
  - Added guarded QUIC packet output attempts via `ngtcp2_conn_write_pkt` after successful packet ingest, plus `/health` surfacing for emitted packet and byte counts.
  - Verified the opt-in HTTP/3 build path against installed `libngtcp2`, `libngtcp2_crypto_ossl`, and `libnghttp3` system packages.
  - Added per-connection nghttp3 session ownership in the ngtcp2 binding, including QUIC stream-data callbacks, stream-close cleanup, and `/health` surfacing for received HTTP/3 stream bytes and completed request assemblies.
  - Added HTTP/3 runtime fixes for stable thread lifetime, correct nonblocking UDP setup, TLS 1.3 QUIC bootstrap, ALPN `h3` selection, Initial-packet acceptance gating, and timer-driven ngtcp2 expiry handling.
  - Added HTTP/3 diagnostics surfacing for ngtcp2 error names on `/health` and in runtime logs while driving live `curl --http3-only` handshake probes.
  - Added pending ngtcp2 write flushing after QUIC reads and expiry ticks so the runtime drains all immediately available handshake output instead of stopping after the first send attempt.
  - Added live QUIC-handshake alignment with the upstream ngtcp2 server by passing the client packet SCID into `ngtcp2_conn_server_new`, seeding a real server transport-parameter set, enabling QUIC TLS early data, and using stricter `h3` ALPN selection.
  - Added the first live HTTP/3 loopback integration test using Homebrew `curl --http3-only`, verifying `/health` completes successfully over QUIC.
  - Added a gateway-owned HTTP/3 request-dispatch seam so ngtcp2/nghttp3 can hand completed requests back to edge logic instead of hardcoding the transport response in the binding layer.
  - Added HTTP/3 response-body streaming via an nghttp3 data reader for gateway-owned responses, and extended the loopback QUIC integration test to assert the real `/health` JSON body.
  - Added gateway-backed HTTP/3 dispatch for `/metrics`, `/metrics/json`, and `/metrics/prometheus`, plus live QUIC integration coverage for Prometheus metrics over HTTP/3.
  - Added HTTP/3 concurrent-stream integration coverage proving one QUIC connection can serve independent `/health` and `/metrics/json` responses in parallel.
  - Added authenticated `/admin/routes` coverage over HTTP/3, exercising header propagation and bearer-token authorization on the gateway-backed QUIC path.
  - Added dynamic `/admin/connections` coverage over HTTP/3 so the gateway-backed QUIC path now serves live admin state in addition to static admin metadata.
  - Added `/admin/upstreams` coverage over HTTP/3 so the gateway-backed QUIC path can serve dynamic upstream-state JSON on authenticated admin routes.
  - Added a dedicated `handleHttp3Connection()` gateway entry point so HTTP/3 route dispatch now lives behind a stable edge-gateway function instead of directly inside the ngtcp2 callback adapter.
  - Added gateway-backed `/v1/chat` handling over HTTP/3, with live QUIC coverage for both unauthorized and successful proxied chat requests.
  - Added gateway-backed `/v1/commands` handling over HTTP/3, with live QUIC coverage for both unauthorized and successful proxied command requests.
  - Added gateway-backed `/v1/commands/status` handling over HTTP/3, with live QUIC coverage for authenticated lifecycle snapshot reads after command execution.
  - Added gateway-backed approvals workflow handling over HTTP/3, with live QUIC coverage for request, respond, and status operations.
  - Added gateway-backed `/v1/sessions` handling over HTTP/3, with live QUIC coverage for session creation, listing, and revocation.
  - Added gateway-backed `/v1/cache/purge` handling over HTTP/3, with live QUIC coverage that purges an existing proxy-cache entry and forces the next upstream fetch to miss.
  - Added gateway-backed `/v1/devices/register` handling over HTTP/3, with live QUIC coverage for authenticated device registration.
  - Added gateway-backed `/v1/sessions/refresh` handling over HTTP/3, with live QUIC coverage for session-token refresh and rotated token headers.
  - Archived the old QUIC parser/tracker stub as `src/http/quic_stub.zig` and repointed live HTTP/3 imports at that explicit stub name now that real transport ownership lives in `ngtcp2_binding.zig`.
  - Removed the old standalone `src/http/qpack.zig` stub by inlining the remaining literal header-block helper into `src/http/http3_session.zig` and repointing HTTP/3 handler code at the session-layer types.
  - Added a dedicated HTTP/3 resumption harness (`tests/http3_resumption_client.zig`) that drives the upstream ngtcp2/OpenSSL `osslclient` with TLS session and QUIC transport-parameter reuse to prove 0-RTT over the live Tardigrade QUIC listener.
  - Started Upgrade 4 FastCGI protocol implementation by replacing the envelope-only FastCGI bridge with full record framing, CGI env construction, response parsing, and end-to-end integration coverage against an in-repo FastCGI mock server.
  - Added FastCGI upstream connection reuse with a per-endpoint keep-conn socket pool and integration coverage proving sequential requests reuse the same backend connection.
  - Added FastCGI request-ID tracking on reused backend sockets, including target-request response parsing and integration coverage that verifies request IDs advance across a reused FastCGI connection.
  - Completed Upgrade 4.1 SCGI by replacing the request-only stub with full SCGI CGI-env encoding, parsed response handling, and end-to-end integration coverage against an in-repo SCGI mock server.
  - Started Upgrade 4.2 uWSGI by replacing the request-only stub with full variable-packet encoding, parsed response handling, and end-to-end integration coverage against an in-repo uWSGI mock server.
  - Completed the remaining Upgrade 4.2 chunked uWSGI response path by decoding upstream `Transfer-Encoding: chunked` bodies before mapping them back into normal gateway responses, with live integration coverage.
  - Completed Upgrade 4.3 backend protocol config integration by wiring `fastcgi_pass`, `scgi_pass`, `uwsgi_pass`, `fastcgi_param`, and `fastcgi_index` through the config-file parser, runtime config, and FastCGI execution path.
  - Added a real PHP-FPM integration test that boots a private `php-fpm` instance on a Unix socket and proves `/v1/backend/fastcgi` returns a parsed live FastCGI response.
  - Added capture-substitution rewrite support (`$1`, `$2`, ...) plus rewrite unit/integration coverage for `last`, `break`, `redirect`, `permanent`, and transparent path rewrites.
  - Added `rewrite` directive parsing in `src/http/config_file.zig`, with config-driven integration coverage for transparent rewrites.
  - Added `return` directive parsing and redirect semantics, including `$request_uri` expansion and config-driven integration coverage for `return 301 https://example.com$request_uri`.
  - Added named capture substitution support in rewrite patterns, translating `(?P<name>...)` groups into POSIX-regex captures internally and expanding `$name` in replacements.
  - Added the first conditional rewrite/return support for inline `if (...)` directives with `$http_host`, `$request_uri`, and `$args` matching, including case-insensitive `~*` conditions.
  - Added the Upgrade 6 location-router foundation with a standalone nginx-style location matcher, `LocationBlock` runtime data model, serialized `TARDIGRADE_LOCATION_BLOCKS` loading, and unit coverage for exact/prefix/regex precedence.
  - Added `location { ... }` block parsing in `src/http/config_file.zig`, including `proxy_pass`, `fastcgi_pass`, `root`, `alias`, `index`, `try_files`, `return`, and `rewrite` serialization into the new location-table config path.
  - Added the first live location-dispatch hook in `src/edge_gateway.zig`, routing configured `location` blocks before the legacy hardcoded chain and adding integration coverage for three-block routing plus SIGHUP location reload.
  - Added synthesized built-in location blocks for the core gateway routes (`/health`, metrics, admin metadata, `/v1/chat`, `/v1/commands`, `/v1/commands/status`) so configured and built-in routes now share the same matcher table during the Upgrade 6 migration.
  - Added direct matcher-backed execution for simple built-in HTTP/1 routes (health, metrics, and admin metadata) plus an HTTP/3 location-matcher entry point with live QUIC coverage for configured `location`-block proxy routing.
  - Added shared matcher-backed dispatch for `/v1/devices/register`, `/v1/sessions`, `/v1/sessions/refresh`, and `/v1/cache/purge` so those endpoints now execute through the same built-in location table on both HTTP/1 and HTTP/3.
  - Added shared matcher-backed dispatch for `/v1/commands/status` and the approvals routes (`/v1/approvals/request`, `/v1/approvals/respond`, `/v1/approvals/status`) so those endpoints now execute through the same built-in location table on both HTTP/1 and HTTP/3.
  - Added shared bearer-or-session identity resolution for `/v1/chat` and `/v1/commands`, so the remaining HTTP/1 and HTTP/3 route splits now differ mainly in execution behavior instead of auth/control-flow logic.
  - Added shared request-preparation helpers for `/v1/chat` and `/v1/commands`, so both HTTP/1 and HTTP/3 now reuse the same auth/content-type/body parsing and upstream payload construction before diverging into protocol-specific execution paths.
  - Added direct matcher-backed execution for `/v1/chat` and `/v1/commands` on both HTTP/1 and HTTP/3, including shared prep-error mapping and shared buffered upstream-result normalization while preserving the existing HTTP/1 cache/idempotency/circuit-breaker behavior.
  - Started Upgrade 7 static-file serving by adding `src/http/static_file.zig` and `src/http/range.zig`, wiring shared static-file handling into both HTTP/1 and HTTP/3 location-root handlers, and adding unit coverage for traversal rejection and `.wasm` MIME detection plus live integration coverage for serving `/index.html` from a configured static root.
  - Extended the static-file integration coverage to verify `If-Modified-Since` returns `304 Not Modified` and `Range: bytes=0-3` returns `206 Partial Content` with the expected `Content-Range`.
  - Added `autoindex on/off` config support for location-root static routes and live integration coverage for directory listing when no index file exists.
  - Completed Upgrade 8 custom error pages by adding location-level `error_page` directive parsing, multiple-status mappings, static-root error-page serving through the shared static-file module, absolute-URI redirect targets, and integration coverage for static HTML 404 pages while preserving JSON API 404 envelopes on `/v1/...`.
  - Started Upgrade 9 `handleConnection()` refactoring by extracting the pre-routing middleware/guard path (geo blocking, request limits, API version/policy checks, ACL, idempotency capture, and rate limiting) into a dedicated `runMiddlewarePipeline()` helper while keeping the full integration suite green.
  - Continued Upgrade 9 by centralizing matcher-backed HTTP/1 route handoff in `routeRequest()`, removing duplicated health/metrics/admin branches from `handleConnection()`, and preserving the static-root fallback to built-in routes such as `/health`.
  - Continued Upgrade 9 by extracting the shared chat/commands upstream execution core into `handleProxyRequest()`, centralizing circuit-open handling, `proxyJsonExecute` dispatch, and buffered result normalization while keeping route-specific cache, idempotency, and command-lifecycle behavior unchanged.
  - Continued Upgrade 9 by extracting the HTTP/1 WebSocket upgrade path into `handleWebSocketUpgrade()`, centralizing route detection, auth/session fallback, handshake validation, handshake writes, and stream-count bookkeeping for `/v1/ws/...`.
  - Continued Upgrade 9 by extracting the SSE stream lifecycle into `handleSseStream()`, centralizing `/v1/events/stream` route detection, shared realtime auth, topic and `Last-Event-ID` parsing, stream-count bookkeeping, and the long-lived `keep_alive = false` transition.
  - Continued Upgrade 9 by extracting the SSE publish path into `handleSsePublish()`, centralizing `/v1/events/publish` route detection, realtime feature gating, event-hub publication, and accepted-response generation.
  - Continued Upgrade 9 by collapsing the remaining duplicated device/session/cache/command-status/approvals HTTP/1 branches onto the shared builtin dispatcher, removing a second implementation from `handleConnection()` and preserving clean `404` JSON behavior for unknown `/v1/...` routes.
  - Continued Upgrade 9 by extracting the remaining subrequest/backend/mail/stream protocol tail into `handleBackendProtocolTail()`, removing another large inline branch cluster from `handleConnection()` while preserving FastCGI/uWSGI/SCGI/gRPC/memcached/mail/TCP/UDP route status behavior.
  - Continued Upgrade 9 by collapsing the remaining inline `/v1/chat` and `/v1/commands` HTTP/1 bodies onto the shared builtin dispatcher, leaving `handleConnection()` much closer to parse -> middleware -> match -> route.
  - Continued Upgrade 9 by moving the remaining post-middleware route/helper ladder into `routeRequest()`, so configured locations, built-in API tails, WebSocket/SSE paths, and backend protocol bridges are routed from one place instead of being retried inline in `handleConnection()`.
  - Completed the Upgrade 9 routing-shape refactor by folding the final `try_files` / `404` fallback into `routeRequest()`, so `handleConnection()` now hands off to one terminal routing path after parsing, rewrites, mirrors, and middleware.
  - Completed Upgrade 9.1 by replacing the single `GatewayState` mutex with narrower subsystem locks for connection bookkeeping, rate limiting, idempotency, proxy cache, sessions, commands, approvals, circuit-breaker state, metrics, upstream health/load-balancing state, and hot-reload runtime fields.
  - Advanced Upgrade 9.2 by auditing request-arena lifetimes through `handleConnection()` and its extracted helpers, moving detached async command jobs onto `GatewayState.allocator`, and adding a regression test that proves copied job inputs survive request-arena teardown.
  - Closed the non-benchmark portion of Upgrade 9.3 by re-running `zig build test` and `zig build test-integration` after the refactor work and marking the unit/integration regression guard items complete.
  - Closed the remaining Upgrade 9.3 benchmark item by installing `wrk` locally and recording a current `/health` throughput run at roughly 29.8k requests/sec on the refactored gateway path.
  - Started Upgrade 10.0 by adding `edge_config.validate()`, wiring config validation into startup and SIGHUP reload, and rejecting invalid ports, malformed upstream endpoints, missing TLS assets, and missing location error-page roots before live config activation.
  - Completed the remaining Upgrade 10.0 conflict-warning item by detecting env-vs-file override mismatches at the `envOrDefault()` merge boundary and logging a warning while preserving env precedence.
  - Completed Upgrade 10.1 by adding SIGUSR1 log-reopen handling, flushing buffered access logs before reopen, and reopening the configured stderr log file from both the worker event loop and the master supervision loop.
  - Started Upgrade 10.2 virtual hosts by parsing `server { ... }` blocks from config files, selecting per-host server-block overlays from the incoming `Host` header on both HTTP/1 and HTTP/3 dispatch paths, honoring a default server block for unmatched hosts, mapping server-block TLS cert/key pairs into the listener's default and SNI cert configuration, and adding integration coverage for both multi-host routing and config-driven SNI certificate selection.
  - Added the remaining Upgrade 10.3 validation and reload regression coverage with a missing-TLS-cert validation test and an integration test proving invalid SIGHUP reloads are rejected without disrupting in-flight requests.
  - Started Upgrade 11.0 mail proxying by adding `smtp_pass` config parsing and a real raw-TCP SMTP relay integration test that proves `EHLO` and `DATA` are forwarded to a loopback upstream and the upstream SMTP reply is returned to the client.
  - Extended Upgrade 11.0 SMTP proxying with explicit `starttls://` / `tls://` upstream schemes, gateway-managed STARTTLS negotiation, validation for secure mail upstream endpoints, and integration coverage that proves the relay upgrades before forwarding the SMTP payload.
  - The new SMTP STARTTLS integration harness is currently skipped on macOS because the external local helper is unstable under the Zig test runner there, although the relay path is manually verified end to end.

### Fixed
- Upgrade 1 integration hardening in the live gateway path:
  - Rebuilt rate limiter and proxy cache runtime state during SIGHUP reload so new limits apply immediately.
  - Buffered cacheable upstream success responses so `/v1/chat` and `/v1/commands` can be cached and revalidated correctly.
  - Fixed proxy cache lock handling, response body ownership, and detached refresh-thread lifetime issues uncovered by the integration suite.
  - Fixed single-upstream retry budgeting so configured retry attempts are honored even without multiple upstream URLs.
  - Fixed proxy cache writes to respect upstream `Cache-Control: no-store`.
  - Fixed the integration request builder so explicit `Host` headers are preserved in end-to-end proxy tests.
  - Fixed proxied upstream requests to follow a single redirect deterministically instead of timing out in the client path.
  - Fixed the TLS integration probe path to force HTTP/1.1 so TLS tests are not blocked by the separate HTTP/2 Huffman decoder gap.
  - Fixed the TLS drain harness to use an asynchronously spawned `curl` subprocess from the main test thread, avoiding the Zig/macOS threaded child-process crash.
  - Restored OpenSSL SNI callback registration through `SSL_CTX_callback_ctrl`/`SSL_CTX_ctrl` and fixed a TLS handshake deadlock by not holding the TLS state mutex across `SSL_accept()`.
  - Fixed connection-session cleanup to release request buffers back to the pool during shutdown and zero-initialize reused sessions.
  - Fixed the contention test harness to use bounded socket timeouts instead of concurrent `curl` subprocess fan-out, which was unstable on macOS under threaded Zig tests.
  - Fixed the worker-pool own-queue pop path to preserve FIFO drain order under saturation instead of reversing requests with LIFO `pop()`.
  - Fixed active upstream health routing so a backend stays out of rotation until recovery probes succeed, instead of becoming eligible again solely because the passive fail-time window elapsed.
  - Fixed the TLS SNI maintenance path to own its static SNI spec slice instead of retaining a pointer to the caller's freed temporary allocation.
  - Fixed the HTTP/3 server-connection bootstrap to use the correct peer CID semantics for `ngtcp2_conn_server_new`; live `curl --http3-only` probes now complete the local QUIC/TLS handshake instead of stalling after the first server Initial packet.
  - Fixed the HTTP/3 post-handshake path to reuse existing native connections for repeated Initial packets and to submit a minimal live response over nghttp3/QUIC without freeing header buffers too early.
  - Fixed the HTTP/3 response path to advance nghttp3 body write offsets correctly and widened QUIC curl timeouts in the integration harness so live `/health` probes stop flaking under the test runner.
  - Fixed the integration curl helper to retain generated header arguments until `Child.run()` completes; the previous lifetime bug could crash tests that passed custom headers to curl.
  - Fixed several integration-suite stability issues uncovered while expanding HTTP/3 coverage:
    - added explicit HTTPS-side `http3_status=configured` readiness checks before QUIC probes,
    - widened HTTP/3 curl retry timing in the live QUIC tests,
    - refreshed device-auth timestamps/signatures per request in the device/session integration test,
    - reduced the mixed auth/rate contention fan-out and widened its timeout to avoid scheduler-noise failures in the full suite.
  - Fixed QUIC TLS bootstrap to align more closely with the upstream ngtcp2/OpenSSL server defaults for TLS 1.3 early data, including server-only TLS context creation, certificate-chain loading, explicit TLS 1.3 ciphersuite/group defaults, and session-ticket reuse.
  - Fixed HTTP/3 resumption observability by replacing the dead libcurl-based 0-RTT probe with the real ngtcp2/OpenSSL client path and by counting coalesced Initial + 0-RTT packets correctly in `src/http/quic_stub.zig`.
  - Fixed `/v1/backend/fastcgi` to return parsed FastCGI responses instead of raw protocol bytes, log FastCGI `STDERR` at WARN level, and map non-zero `FCGI_END_REQUEST` app status to `502`.
  - Fixed the FastCGI backend route to honor configured `root`, `fastcgi_param`, and `fastcgi_index` defaults while still allowing request-header overrides for script metadata during targeted protocol tests.
  - Fixed the integration HTTP response reader to stop waiting for EOF when a `Content-Length` header is present, which removed a graceful-shutdown suite failure under the longer backend/rewrite test matrix.
  - Fixed integration startup readiness to allow tests to declare a non-200 ready status, which is required for full-gateway redirect configurations such as top-level `return 301`.
  - Fixed the integration shutdown response reader to tolerate peer resets after partial response bytes and added failure-safe child cleanup in the inflight shutdown tests.

## [0.29.0] - 2026-03-08

### Added
- Phase 9 WebSocket + SSE/event-streaming foundation (`src/http/websocket.zig`, `src/http/event_hub.zig`, `src/edge_config.zig`, `src/edge_gateway.zig`, `src/http.zig`):
  - Added authenticated WebSocket upgrade routes for `/v1/ws/chat` and `/v1/ws/commands` with in-house RFC6455 handshake/framing.
  - Added WebSocket ping/pong handling, idle timeout, frame-size caps, and upstream proxy forwarding via existing load-balanced upstream execution.
  - Added authenticated SSE publish/stream routes (`POST /v1/events/publish`, `GET /v1/events/stream`) with `Last-Event-ID` replay support.
  - Added in-memory topic event hub buffering and slow-client backlog protection controls.
  - Added new runtime config env vars: `TARDIGRADE_WEBSOCKET_*` and `TARDIGRADE_SSE_*`.
- Phase 10 compression completion increment (`src/http/compression.zig`, `src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added response encoding negotiation for `br` and `gzip` with Brotli-preferred selection when supported by clients.
  - Added runtime Brotli compression support via dynamic encoder library loading (`TARDIGRADE_COMPRESSION_BROTLI_ENABLED`, `TARDIGRADE_COMPRESSION_BROTLI_QUALITY`).
  - Added gzip_static-style passthrough for already-gzipped payloads to avoid redundant recompression.
  - Added upstream gunzip path by advertising `Accept-Encoding: gzip` on proxy requests (`TARDIGRADE_UPSTREAM_GUNZIP_ENABLED`) and reusing Zig client automatic decompression.
- Phase 11.1 URL rewriting foundation (`src/http/rewrite.zig`, `src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added regex-based rewrite rule engine with support for `last`, `break`, `redirect`, and `permanent` flags.
  - Added regex-based return directives for short-circuit responses before normal route dispatch.
  - Added method-conditional rewrite/return matching (`METHOD` or `*`) and new env directives `TARDIGRADE_REWRITE_RULES` / `TARDIGRADE_RETURN_RULES`.
- Phase 11 request-processing and protocol-bridge completion increment (`src/edge_config.zig`, `src/edge_gateway.zig`, `src/http/fastcgi.zig`, `src/http/uwsgi.zig`, `src/http/scgi.zig`, `src/http/memcached.zig`):
  - Added subrequest endpoint (`POST /v1/subrequest`), internal redirect rules, named location mapping, and mirror request rules.
  - Added backend bridge routes for FastCGI, uWSGI, SCGI, gRPC, and Memcached under `/v1/backend/*`.
  - Added optional mail proxy bridge routes for SMTP/IMAP/POP3 under `/v1/mail/*`.
  - Added stream-module bridge routes for TCP/UDP under `/v1/stream/*` and stream SSL-termination mode flag/config.
- Phase 12 observability completion increment (`src/http/access_log.zig`, `src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added configurable access log formats (`json`, `plain`, `custom`) with template rendering and conditional status-based filtering.
  - Added access log buffering and optional syslog UDP forwarding.
  - Added authenticated admin API endpoints for routes, connections, streams, upstream health, loaded cert config, and auth/session registry visibility.
- Phase 3.1/3.4 configuration parser + hot reload foundation (`src/http/config_file.zig`, `src/edge_config.zig`, `src/http/shutdown.zig`, `src/edge_gateway.zig`):
  - Added nginx-style config-file parsing with `include`, `set $var`, interpolation, and directive-to-env normalization.
  - Added `TARDIGRADE_CONFIG_PATH` support with env-overrides-file precedence.
  - Added SIGHUP-triggered zero-downtime config hot reload with validate-before-apply semantics.
- Phase 3.2/3.3 config directive expansion (`src/http/config_file.zig`, `src/edge_config.zig`, `src/main.zig`, `src/edge_gateway.zig`):
  - Added core directive aliases for `worker_processes`, `worker_connections`, `error_log`, `pid`, and `user/group`.
  - Added HTTP-style directive aliases for `listen`, `server_name`, `root`, and `try_files` with runtime host matching and static try-files fallback.
  - Added pid-file lifecycle support, stderr log redirection, and numeric post-bind privilege dropping controls.
- Phase 3.5 secret-management foundation (`src/http/secrets.zig`, `src/edge_config.zig`, `src/http.zig`):
  - Added secret file override loading via `TARDIGRADE_SECRETS_PATH` and rotating key support via `TARDIGRADE_SECRET_KEYS`.
  - Added encrypted secret envelope decoding (`ENC:<base64>` with keyed envelope validation) and preserved env-first override precedence.
- Phase 0.1 and 6.6 identity/policy completion increment (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added authenticated device identity registration (`POST /v1/devices/register`) backed by registry persistence.
  - Added device proof enforcement on protected routes (`X-Device-ID`, `X-Device-Timestamp`, `X-Device-Signature`) when enabled.
  - Added session token refresh route (`POST /v1/sessions/refresh`) and policy engine enforcement (`TARDIGRADE_POLICY_*`) for route scope/device/approval/time windows.
- Phase 13.1/13.3 process and privilege hardening increment (`src/main.zig`, `src/http/shutdown.zig`, `src/edge_gateway.zig`, `src/edge_config.zig`, `src/http/config_file.zig`):
  - Added master/worker process supervision mode with worker respawn (`TARDIGRADE_MASTER_PROCESS`, `TARDIGRADE_WORKER_PROCESSES`).
  - Added SIGUSR2 binary-upgrade signaling and replacement-master spawn path (`TARDIGRADE_BINARY_UPGRADE`).
  - Added worker recycle timer and Linux CPU affinity pinning controls (`TARDIGRADE_WORKER_RECYCLE_SECONDS`, `TARDIGRADE_WORKER_CPU_AFFINITY`).
  - Added privilege hardening controls: strict unprivileged-mode enforcement and optional chroot after bind (`TARDIGRADE_REQUIRE_UNPRIVILEGED_USER`, `TARDIGRADE_CHROOT_DIR`).
- Phase 14.1 command protocol completion increment (`src/http/command.zig`, `src/edge_gateway.zig`):
  - Added command envelope support for `command_id` and `async` mode.
  - Added in-memory command lifecycle tracking (`pending`, `running`, `completed`, `failed`) keyed by `command_id`.
  - Added async command submission (`POST /v1/commands` -> `202 Accepted`) and lifecycle polling endpoint (`GET /v1/commands/status?command_id=...`).
- Phase 14.2 stream multiplexing completion increment (`src/edge_gateway.zig`):
  - Added authenticated multiplexed WebSocket route `GET /v1/ws/mux` with channel-based envelopes (`subscribe`, `unsubscribe`, `publish`, `command`) over a single socket.
  - Added multiplexed event and command channels, including async command lifecycle push updates (`command.update`) alongside event topic updates.
  - Added per-device stream isolation for mux event channels by requiring `X-Device-ID` and namespacing topics as `device/<device_id>/<topic>`.
- Phase 14.3 approval workflow completion increment (`src/edge_gateway.zig`):
  - Added approval request routing endpoint `POST /v1/approvals/request` to mint route-bound approval tokens for approval-gated policy paths.
  - Added approval response/status handling via `POST /v1/approvals/respond` and `GET /v1/approvals/status`, including explicit `approved|denied|pending` lifecycle states.
  - Added timeout escalation behavior for pending approvals, with policy enforcement rejecting escalated or invalid approval tokens.
- Phase 1.4 log rotation completion increment (`src/main.zig`):
  - Added startup log rotation support for file-backed stderr logging configured by `TARDIGRADE_ERROR_LOG_PATH`.
  - Added size and retention controls via `TARDIGRADE_LOG_ROTATE_MAX_BYTES` and `TARDIGRADE_LOG_ROTATE_MAX_FILES`.

## [0.28.0] - 2026-03-07

### Added
- Phase 5.1 proxy cache key + validity foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_PROXY_CACHE_TTL_SECONDS` and `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE`.
  - Added template-driven proxy cache key generation with token support for method/path/payload hash/identity/API version.
  - Added TTL-backed in-memory cache reads/writes for successful `/v1/chat` and `/v1/commands` proxy responses with `X-Proxy-Cache: HIT` on cache hits.
- Phase 5 proxy cache completion (`src/edge_config.zig`, `src/edge_gateway.zig`, `src/http/idempotency.zig`):
  - Added `TARDIGRADE_PROXY_CACHE_PATH` disk-backed cache tier, stale-serving controls, cache-lock timeout, and cache-manager interval configuration.
  - Added cache bypass controls (`X-Proxy-Cache-Bypass`, cache-control pragma/no-cache directives) and authenticated cache purge endpoint `POST /v1/cache/purge`.
  - Added stale cache responses (`X-Proxy-Cache: STALE`) with detached background refresh for chat/command routes plus periodic cache-manager expiration cleanup.
- Phase 6 security completion increment (`src/edge_config.zig`, `src/edge_gateway.zig`, `src/http/jwt.zig`):
  - Added geo blocking via external country header data (`TARDIGRADE_GEO_BLOCKED_COUNTRIES`, `TARDIGRADE_GEO_COUNTRY_HEADER`).
  - Added explicit `limit_conn` alias env support (`TARDIGRADE_LIMIT_CONN_PER_IP`) on top of existing per-IP/global connection enforcement.
  - Added auth subrequest checks (`TARDIGRADE_AUTH_REQUEST_URL`, `TARDIGRADE_AUTH_REQUEST_TIMEOUT_MS`) for protected API routes.
  - Added optional JWT HS256 bearer validation with issuer/audience constraints (`TARDIGRADE_JWT_SECRET`, `TARDIGRADE_JWT_ISSUER`, `TARDIGRADE_JWT_AUDIENCE`).
  - Added configurable `add_header` directive support via `TARDIGRADE_ADD_HEADERS` applied to all gateway responses.
- Phase 7 TLS/SSL completion increment (`src/http/tls_termination.zig`, `src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added protocol and cipher controls (`TARDIGRADE_TLS_MIN_VERSION`, `TARDIGRADE_TLS_MAX_VERSION`, `TARDIGRADE_TLS_CIPHER_LIST`, `TARDIGRADE_TLS_CIPHER_SUITES`).
  - Added SNI multi-certificate support (`TARDIGRADE_TLS_SNI_CERTS`) and optional ACME-style certificate directory discovery.
  - Added session resumption controls (session cache and session tickets) and static OCSP stapling support.
  - Added mTLS and chain/CRL verification controls (`TARDIGRADE_TLS_CLIENT_*`, `TARDIGRADE_TLS_CRL_*`).
  - Added timer-driven dynamic TLS asset reload checks (`TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS`).
- Phase 8 HTTP/2 foundation increment (`src/http/hpack.zig`, `src/http/http2_frame.zig`, `src/edge_gateway.zig`, `src/http/tls_termination.zig`):
  - Added in-house HPACK encoder/decoder primitives for HTTP/2 header block handling.
  - Added in-house HTTP/2 frame parsing/serialization utilities (SETTINGS, PING, HEADERS, DATA, GOAWAY helpers).
  - Added ALPN `h2` negotiation support on TLS connections (`TARDIGRADE_HTTP2_ENABLED`).
  - Added HTTP/2 connection handling loop with stream-scoped request assembly and basic gateway response routing for health/metrics endpoints.
- Phase 8 completion increment (`src/http/http2_frame.zig`, `src/edge_gateway.zig`, `src/http/quic.zig`, `src/http/qpack.zig`, `src/edge_config.zig`):
  - Added HTTP/2 priority parsing/scheduling, flow-control window update handling, and server push helper support.
  - Added HTTP/2 route translation for proxied gateway API streams (`/v1/chat`, `/v1/commands`) via existing upstream execution paths.
  - Added in-house QUIC packet parsing and connection migration tracking foundations (`src/http/quic.zig`) with 0-RTT packet-type handling.
  - Added in-house QPACK literal header block encoder/decoder foundations (`src/http/qpack.zig`).
  - Added HTTP/3 foundation configuration flags (`TARDIGRADE_HTTP3_*`) for runtime behavior control.

## [0.27.0] - 2026-03-07

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
  - Added periodic active probe controls: `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS`, `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH`, and `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS`.
  - Event-loop timer ticks now run active health probes across configured upstreams.
  - Active probe outcomes now feed existing passive-health failover tracking.
- Phase 4.4 configurable health thresholds (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD` and `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD`.
  - Active probe failures/successes now use configurable consecutive-threshold transitions for unhealthy/healthy state changes.
- Phase 4.4 slow-start for recovered upstreams (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_SLOW_START_MS` for recovered-backend traffic ramp windows.
  - Upstream selection now applies gradual eligibility during slow-start instead of immediate full-load routing after recovery.
- Error categorization telemetry (`src/http/metrics.zig`, `src/http/access_log.zig`, `src/edge_gateway.zig`):
  - Access logs now emit `error_category` for non-success outcomes.
  - Added category-level API error counters (invalid request, unauthorized, rate-limited, upstream timeout/unavailable, internal, overload).
  - Overload shedding and API error paths now increment categorized metrics for triage.
- Phase 4.3 least-connections load balancing (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_LB_ALGORITHM` with `round_robin` and `least_connections` modes.
  - Added per-upstream in-flight attempt tracking and least-loaded upstream selection.
  - Least-connections selection is integrated with health/slow-start filters.
- Phase 4.3 IP-hash load balancing (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Extended `TARDIGRADE_UPSTREAM_LB_ALGORITHM` with `ip_hash` mode.
  - Added client-IP hash upstream selection for stable backend affinity across requests.
  - IP-hash selection is integrated with health/slow-start filters and falls back cleanly when candidates are unavailable.
- Phase 4.3 random-two-choices load balancing (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Extended `TARDIGRADE_UPSTREAM_LB_ALGORITHM` with `random_two_choices` mode.
  - Added power-of-two-choices backend selection that samples two random backends and chooses the lower in-flight load.
  - Random-two-choices selection is integrated with health/slow-start filters and fallback behavior.
- Phase 4.3 generic-hash load balancing (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Extended `TARDIGRADE_UPSTREAM_LB_ALGORITHM` with `generic_hash` mode.
  - Added deterministic hash-based backend selection using a request hash key (payload when present, otherwise proxy target path).
  - Generic-hash selection is integrated with health/slow-start filters and fallback behavior.
- Phase 4.2 backup upstream failover (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` for configuring backup backend pools.
  - Upstream selection now falls back to backup servers only when primaries have no healthy/eligible candidate.
  - Active health probes now include configured backup servers.
- Phase 4.2 weighted primary upstream selection (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` for aligned positive integer primary-backend weights.
  - Primary round-robin selection now supports weighted ticketing for uneven traffic distribution.
  - Added validation for invalid weight configs and weighted-selection unit coverage.
- Phase 4.2 route-scoped upstream blocks (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added dedicated chat/commands upstream block env settings for primary, weighted, and backup pools.
  - Proxy execution now chooses upstream pools by route scope and falls back to global upstream pool when route-specific pools are unset.
  - Active health probes now include configured route-scoped upstream block backends.
- Phase 4.5 proxy protocol foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_PROXY_PROTOCOL` (`off|auto|v1|v2`) for PROXY header parsing on plaintext listeners.
  - Added v1/v2 PROXY header parsing and request-context client IP extraction from parsed source addresses.
  - Added parser coverage for v1, v2, and auto-mode no-header behavior.
- Phase 4.6 service trust model foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added trusted-upstream configuration env vars for gateway identity, shared secret, strict trust enforcement, and trusted upstream identity allowlists.
  - Upstream proxy requests now include signed trust headers and forwarded auth context metadata.
  - Upstream target selection now enforces trusted identity matching when configured, with explicit `upstream_untrusted` error mapping.
- Phase 4.7 unix socket upstream routing (`src/edge_gateway.zig`, `README.md`):
  - Added unix upstream endpoint support via `unix:/path.sock` and `unix:///path.sock` syntax in configured upstream pools.
  - Proxy request execution now uses `std.http.Client.connectUnix` when unix upstream endpoints are selected.
  - Active health probing and load-balanced endpoint selection now apply to unix socket backends for local IPC routing.

## [0.26.0] - 2026-03-07

### Added
- Phase 2.4 request arena allocation (`src/edge_gateway.zig`):
  - Request processing now uses a request-scoped arena allocator instead of a per-request general-purpose allocator.
  - Per-request temporary allocations are reclaimed in one step at request completion.

## [0.25.0] - 2026-03-07

### Added
- Phase 2.2 keep-alive connection reuse (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - Worker connection handlers now support sequential multi-request processing per client socket.
  - Responses now honor parsed request keep-alive behavior (`Connection: keep-alive`/`close`).
  - Added `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` for idle keep-alive socket timeout.
  - Added `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` to bound requests served per connection.

## [0.24.0] - 2026-03-07

### Added
- Socket timeout enforcement (`src/edge_gateway.zig`):
  - Accepted client sockets now apply configured request header timeout via `TARDIGRADE_HEADER_TIMEOUT_MS`.
  - Upstream proxy sockets now apply configured send/receive timeout via `TARDIGRADE_UPSTREAM_TIMEOUT_MS`.
  - Timeout settings are applied with POSIX socket timeout options on both client and upstream paths.

## [0.23.0] - 2026-03-07

### Added
- Phase 4.1 proxy_pass directive foundation (`src/edge_config.zig`, `src/edge_gateway.zig`):
  - Added `TARDIGRADE_PROXY_PASS_CHAT` for `/v1/chat` upstream target selection.
  - Added `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` for `/v1/commands` command upstream path prefixing.
  - Proxy target resolver supports absolute URL mode and relative-path mode (joined with `TARDIGRADE_UPSTREAM_BASE_URL`).
  - Added target resolution helper coverage for path joining and absolute/relative routing behavior.

## [0.22.0] - 2026-03-07

### Added
- Phase 4.1 backend connection pooling (`src/edge_gateway.zig`):
  - Gateway state now owns a shared upstream `std.http.Client`.
  - Upstream proxy execution path now opens requests through the shared client with `keep_alive = true`.
  - Upstream connections can now be reused across requests via the client connection pool instead of one-client-per-request teardown.

## [0.21.0] - 2026-03-07

### Added
- Phase 4.1 streaming proxy increment (`src/edge_gateway.zig`):
  - New upstream execution path that can stream successful (200) upstream responses directly to downstream clients using chunked transfer encoding.
  - Shared streaming response header writer for propagated content-type/disposition, correlation ID, and security headers.
  - `/v1/chat` and `/v1/commands` now attempt streamed relay when idempotency replay storage is not required; non-200 responses still use buffered mapping path.

## [0.20.0] - 2026-03-07

### Added
- Native HTTPS/TLS termination (`src/http/tls_termination.zig`, `src/edge_gateway.zig`, `build.zig`):
  - OpenSSL-backed TLS server context with certificate/private-key loading from configured PEM files.
  - Worker connection path now performs TLS handshake (`SSL_accept`) when TLS cert/key are configured.
  - HTTP request parsing/response writing now supports both plain TCP streams and TLS-wrapped streams.
  - Build linked with `ssl`/`crypto` system libraries for executable and tests.

## [0.19.0] - 2026-03-07

### Added
- Phase 2.2 per-IP connection limiting (`src/edge_gateway.zig`, `src/edge_config.zig`):
  - New `TARDIGRADE_MAX_CONNECTIONS_PER_IP` runtime setting (default disabled).
  - Listener accept path now enforces active connection slots per client IP before queueing to workers.
  - Connection slot lifecycle is tracked by fd and released on worker completion or queue submission failure.
  - Supports IPv4 and IPv6 client keying in the connection tracker.

## [0.18.0] - 2026-03-07

### Added
- Phase 2.3 graceful worker draining (`src/http/worker_pool.zig`):
  - Worker pool now tracks in-flight jobs and blocks shutdown until queued + active work drains when requested.
  - Added worker completion signaling for coordinated shutdown waits.
  - Added unit test verifying `shutdownAndJoin(true)` waits for in-flight work completion.

## [0.17.0] - 2026-03-07

### Added
- Phase 4.1 reverse proxy header foundation (`src/edge_gateway.zig`):
  - Unified JSON proxy request path shared by `/v1/chat` and `/v1/commands`.
  - Forwarded client headers added on upstream calls: `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`.
  - `Host` header rewriting to upstream authority derived from `upstream_base_url`.
  - Helper coverage for forwarded-for composition and upstream host parsing.

## [0.16.0] - 2026-03-07

### Added
- Phase 2.3 worker model foundation (`src/http/worker_pool.zig`, `src/edge_gateway.zig`):
  - Fixed-size worker thread pool for accepted connection handling with bounded queue backpressure.
  - Event-loop accept path now dispatches sockets to worker threads instead of processing inline on the listener thread.
  - Thread-safe shared gateway state access for rate limiting, sessions, idempotency, circuit breaker, and metrics via synchronized state helpers.
  - Configurable worker settings via `TARDIGRADE_WORKER_THREADS` (default auto) and `TARDIGRADE_WORKER_QUEUE_SIZE` (default 1024).
  - Worker pool unit test covering queue submission/processing.

## [0.15.0] - 2026-03-07

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
- Remote authenticated gateway MVP edge path:
  - New edge config loader (`src/edge_config.zig`) with `listen_host`, `listen_port`, `tls_cert_path`, `tls_key_path`, `upstream_base_url`, auth token hashes.
  - New edge runtime (`src/edge_gateway.zig`) with `GET /health` and authenticated `POST /v1/chat`.
  - Static bearer token auth using SHA-256 hash allowlist.
  - Request validation and stable API error envelopes with `request_id`.
  - Upstream forwarding with `X-Correlation-ID` propagation.
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
