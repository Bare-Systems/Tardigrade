# Tardigrade Support Matrix

This document defines the official Core v1 support contract for Tardigrade.

Core v1 is intentionally narrow: a host-native Zig edge server and reverse
proxy with stable HTTP/1.1, HTTP/2, and HTTP/3/QUIC downstream serving plus
predictable operator behavior. Features outside that core may exist in-tree and
may be useful, but they are not part of the stable support promise unless they
are explicitly listed as `stable` here.

## Maturity Levels

### `stable`

A feature is `stable` only when it is part of Tardigrade's public operator
identity and all of the following are true:

- public docs describe how operators use it
- unit coverage exists for the core logic
- integration coverage exists for the live gateway path
- negative/security tests exist where relevant
- the config surface is explicit
- release validation is expected to exercise it

### `experimental`

`experimental` features are visible and may be useful, but they are not part of
the Core v1 compatibility promise.

- breaking changes are allowed
- docs must call out the status clearly
- security, performance, or deployment caveats may still be open

### `adapter`

`adapter` features are protocol bridges or integrations that extend the server
but are not part of Tardigrade's core identity.

### `internal`

`internal` features are implementation details or Bare Systems example-specific
surfaces that should not be marketed as generic operator-facing capabilities.

## Stable Core v1

| Feature | Representative surface | Maturity | Notes |
| --- | --- | --- | --- |
| HTTP/1.1 request parsing and response writing | `src/http.zig` core exports: `method`, `version`, `headers`, `request`, `response`, `status` | `stable` | This is the default runtime contract and the primary benchmark/release path. |
| HTTP/2 downstream serving | `listen ... http2`, `TARDIGRADE_HTTP2_ENABLED`, native TLS ALPN `h2`, `hpack`, `http2_frame` | `stable` | Stable for downstream TLS/ALPN `h2` static serving, reverse proxying, HEAD/POST behavior, multiplexing, flow control, malformed-frame/HPACK failure scope, reload/shutdown/GOAWAY/RST behavior, and bounded resource-settle behavior. Downstream plaintext h2c is not supported; HTTP/2-only downstream listeners require TLS. Promotion evidence is mapped in [HTTP2_HTTP3_STABLE_PROMOTION_389.md](HTTP2_HTTP3_STABLE_PROMOTION_389.md). |
| HTTP/3 / QUIC downstream serving | `TARDIGRADE_HTTP3_ENABLED`, `TARDIGRADE_QUIC_PORT`, `TARDIGRADE_HTTP3_ALT_SVC`, `http3_handler`, `http3_session`, `http3_runtime`, `quic`, `http3` | `stable` | Stable for the native Zig QUIC/H3 backend with QUIC v1/TLS 1.3/ALPN `h3`, static serving, reverse proxying, Alt-Svc enable/withdraw behavior, independent ngtcp2/GnuTLS and aioquic black-box validation, cancellation/recovery, GOAWAY/drain, production soak/resource-settle evidence, and controlled-host performance baseline. Requires a reachable UDP listener, compatible TLS identity, and deployment support for the documented listener/restart/drain limits. Promotion evidence is mapped in [HTTP2_HTTP3_STABLE_PROMOTION_389.md](HTTP2_HTTP3_STABLE_PROMOTION_389.md). |
| Static file serving | `static_file`, `autoindex`, `etag`, `range` | `stable` | Covered by public docs and integration tests for path normalization, ranges, cache validation, and symlink safety. |
| Reverse proxying and config-driven routing | `location_router`, `rewrite`, `request_context`, `config_file`; README `server` / `location` examples; `TARDIGRADE_PROXY_STREAMING_MODE` | `stable` | Core reverse-proxy path, route matching, and opt-in bounded streaming policy are part of the product identity across the documented stable downstream protocols. |
| Downstream mTLS (client-certificate authentication) | `TARDIGRADE_TLS_CLIENT_VERIFY`, `_OPTIONAL`, `_CA_PATH`, `_VERIFY_DEPTH`, `webpki_verifier` | `experimental` | #763: native TLS 1.3 `CertificateRequest`/client-certificate flight on HTTP/1.1 and HTTP/2 over TCP **and HTTP/3 over QUIC**; required and optional modes, pure-Zig path validation with `clientAuth` EKU and the same trust/depth semantics on every protocol, atomic CA-bundle rotation on reload (one shared trust store; each QUIC connection pins the generation it handshook with), verified identity asserted upstream as `X-Tardigrade-Client-Cert-*` with inbound `X-Tardigrade-*` stripped. Client auth forces full handshakes (no PSK resumption, so no 0-RTT) on every protocol. HTTP/3 evidence: real-UDP runtime tests (valid required/optional, missing, malformed, tampered, expired, not-yet-valid, wrong-CA, wrong-EKU), gateway-level identity-propagation tests, `fuzz: TLS protocol:` client-chain/identity targets, and an external-client interop run of the real gateway against aioquic (`scripts/interop/run-h3-mtls-interop.sh`, CI job `h3-mtls-interop`). Not supported: per-SNI-server-block trust, revocation (CRL/OCSP), certificate-aware routing/`forward_auth`/FastCGI (all separate follow-ups). HTTP/1.1 and HTTP/2 independent-client interop (OpenSSL `s_client`, curl) is not yet recorded, hence `experimental`. |
| TLS termination | `tls_termination` | `stable` | Core public edge capability with operator docs, config knobs, release validation, and ALPN coverage for HTTP/1.1 and HTTP/2. |
| Config loading and validation | `config_file`; `tardi check`; README config examples | `stable` | Part of the operator workflow and startup contract. |
| Hot reload and graceful drain | runtime reload path, drain behavior, `shutdown` | `stable` | Public CLI/runtime behavior; documented and integration-tested. |
| Access logging and request IDs | `access_log`, `correlation_id` | `stable` | Public operational surface used in README and integration coverage. |
| Prometheus metrics endpoint | `metrics` | `stable` | Public operator docs and integration coverage exist for `/status/metrics`. |
| Request limits | `request_limits` | `stable` | Explicit operator-facing guardrail in the main gateway path. |
| Rate limiting | `rate_limiter` | `stable` | Publicly documented operational control in the main HTTP path. |
| Upstream health checks and basic load balancing | `health_checker`, `circuit_breaker` | `stable` | Part of the generic reverse-proxy behavior and covered by integration scenarios. |

## Experimental Features

| Feature | Representative surface | Maturity | Why it is not Core v1 |
| --- | --- | --- | --- |
| Early-data replay handling across H1/H2/H3 | `early_data`, `request_context`, `edge_gateway` H1/H2 preflight/deferral, `http3_runtime` compatibility gate | `experimental` | Current scope: #367 HTTP-level policy, H2 safe deferral, and bounded observability (metrics/access logs). Out of scope here: #366 transport-carrier internals. |
| Native TLS/QUIC 0-RTT anti-replay store | `early_data_replay`, `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE`/`_MAX_ENTRIES`, `edge_gateway` composition | `experimental` | #368: a process-local, bounded, mutex-guarded store providing at-most-once 0-RTT claim acceptance per Tardigrade process (not cluster-wide — see docs/OBSERVABILITY.md). Safe default is `disabled`; a distributed backend is defined by contract but not yet implemented. |
| WebSocket relaying through `proxy_pass` | location `proxy_websocket*` directives, `proxy_websocket_max_tunnels`, `websocket` handshake helpers, `tunnel` relay | `experimental` | #812: opt-in per location; HTTP/1.1 downstream only (`ws://` and native-TLS `wss://`), `ws://`/`wss://` origins. Handshakes pass every gate (rate limits, ACLs, `auth required`, `forward_auth`, Origin allowlist, 0-RTT 425) before a fresh, never-pooled upstream connection is opened; the origin's 101 must carry the matching `Sec-WebSocket-Accept`. Tunnels are bounded (one fixed buffer per direction charged to the proxy-buffer limits, idle timeout, optional lifetime, per-process cap with a clean 503) and drain within the shutdown window. Hot reload behavior is configurable (`proxy_websocket_reload preserve|drain`, top-level default with per-location override, fixed at admission): `preserve` keeps open tunnels under their admission configuration even if their location changes, `drain` closes them within `proxy_websocket_reload_timeout_ms` of the first superseding reload. Integration-tested for echo, fragments, ping/pong, large messages, both close directions, pipelined first frames, gate denials, refused/invalid 101s, idle, cap, shutdown drain, reload preserve/drain (removed locations, failed reloads, repeated reloads, per-location overrides, shutdown interplay, native TLS), TLS on both hops, and a connect/close soak. HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220) extended CONNECT are not supported and not advertised. Established tunnels run on a fixed pool of reactor threads rather than one request worker each (#818); integration-tested with hundreds of idle tunnels on one worker while ordinary requests stay fast, and unit-tested with 1500 tunnels on two reactor threads. Not yet validated against independent WebSocket clients/servers or under a long-duration soak (#762). |
| Server-sent events through the streaming proxy | `proxy_streaming response`, `TARDIGRADE_PROXY_STREAMING_MODE` | `experimental` | Rides the stable streaming reverse proxy: events are flushed as they arrive, a slow client is bounded by the relay buffer, and the origin's close ends the client response cleanly (integration-tested). Kept experimental for long-lived streams because graceful shutdown does not end an open stream before the upstream response timeout (#762). |
| ACME automation | `acme_client` | `internal` | Production native builds reject `TARDIGRADE_TLS_ACME_ENABLED` deterministically; the in-tree client surface is reserved for a future native implementation and is not usable as an operator feature today. |
| Auth and identity extensions | `auth`, `basic_auth`, `jwt`, `access_control` | `experimental` | Operators can use these paths, but they are not the defining Core v1 server contract. |
| External auth subrequests (`forward_auth`) | `gateway_forward_auth`, location `forward_auth*` directives | `experimental` | #761: per-location allow/deny/redirect/challenge with fail-closed timeouts, spoof-proof header propagation and bounded bodies; integration-tested on H1 (buffered and streamed proxy, static), H2 (proxy, static) and, in the external-client H3 interop job, H3 proxy; unit-tested at H1/H2/H3 dispatch including resumed H2 0-RTT. SSE is covered as a streamed proxy response; WebSocket handshakes on `proxy_websocket` locations run `forward_auth` before the upstream is contacted, and its client headers decorate the relayed 101 (#812). Known gap: HTTP/2 does not run `rewrite` actions for forward_auth locations (404, fail closed) while HTTP/1.1 and HTTP/3 re-authorize every rewrite hop (#814). Experimental until validated against oauth2-proxy/Authelia in a real deployment. |
| Session and device-oriented auth flows | `session`, `session_store_file`, device-registry env/example surface | `experimental` | Publicly visible in the BearClaw example, but still example-scoped rather than generic Core v1. |
| Response transformation and policy extras | `compression`, `cache_control`, `security_headers` | `experimental` | Useful knobs exist, but they are not yet positioned as part of the stable support promise. |
| DNS-driven upstream discovery (A/AAAA and SRV) | `dns_discovery` | `experimental` | In-tree and tested, but dependent on deployment assumptions beyond the narrow Core v1 story. |

## Adapters

| Feature | Representative surface | Maturity | Notes |
| --- | --- | --- | --- |
| FastCGI | `fastcgi` | `adapter` | Protocol bridge, not core server identity. |
| uWSGI | `uwsgi` | `adapter` | Protocol bridge, not core server identity. |
| SCGI | `scgi` | `adapter` | Protocol bridge, not core server identity. |
| Memcached proxying helpers | `memcached` | `adapter` | Integration helper, not core edge-server identity. |

## Internal Surfaces

| Feature | Representative surface | Maturity | Notes |
| --- | --- | --- | --- |
| Runtime internals | `event_loop`, `worker_pool`, `buffer_pool`, `logger` | `internal` | Important implementation details, but not public product features. |
| Retired realtime endpoint leftovers | `event_hub`, mux counters in `metrics`, `TARDIGRADE_WEBSOCKET_*` / `TARDIGRADE_SSE_*` settings | `internal` | The built-in WebSocket/SSE endpoints were removed with the BearClaw product surface. These settings are parsed but have no effect and are being retired; use `proxy_websocket` and streamed SSE proxying instead. |
| Product/example-specific workflow surfaces | `api_router`, `command`, `idempotency`, `approval_store`, `transcript_store` | `internal` | Useful for Bare Systems examples and product flows, not part of the generic Tardigrade marketing contract. |
| Shared-trust plumbing | `secrets`, asserted `X-Tardigrade-*` identity headers, trace propagation helpers | `internal` | Needed by some deployments, but should not be treated as a generic Core v1 promise. |

## Example Policy

Anything under `examples/` may demonstrate `stable`, `experimental`, `adapter`,
or `internal` surfaces in one place. Example docs must call that out clearly and
must not imply that non-`stable` features are part of the Core v1 support
promise.

For copy/paste-runnable configuration files covering common stable and
experimental deployments, see the [examples directory](../examples/README.md).

## Maintenance Rule

When public behavior changes:

- update this matrix before or alongside the code/docs change
- declare the target maturity level in the issue, PR, or commit rationale
- avoid describing a feature as production-ready unless it is `stable` here
