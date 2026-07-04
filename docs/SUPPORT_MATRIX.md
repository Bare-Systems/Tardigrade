# Tardigrade Support Matrix

This document defines the official Core v1 support contract for Tardigrade.

Core v1 is intentionally narrow: a host-native Zig HTTP/1.1 edge server and
reverse proxy with predictable operator behavior. Features outside that core may
exist in-tree and may be useful, but they are not part of the stable support
promise unless they are explicitly listed as `stable` here.

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
| Static file serving | `static_file`, `autoindex`, `etag`, `range` | `stable` | Covered by public docs and integration tests for path normalization, ranges, cache validation, and symlink safety. |
| Reverse proxying and config-driven routing | `location_router`, `rewrite`, `request_context`, `config_file`; README `server` / `location` examples; `TARDIGRADE_PROXY_STREAMING_MODE` | `stable` | Core HTTP/1.1 reverse-proxy path, route matching, and opt-in bounded streaming policy are part of the product identity. |
| TLS termination | `tls_termination` | `stable` | Core public edge capability with operator docs, config knobs, and release validation. |
| Config loading and validation | `config_file`; `tardigrade check`; README config examples | `stable` | Part of the operator workflow and startup contract. |
| Hot reload and graceful drain | runtime reload path, drain behavior, `shutdown` | `stable` | Public CLI/runtime behavior; documented and integration-tested. |
| Access logging and request IDs | `access_log`, `correlation_id` | `stable` | Public operational surface used in README and integration coverage. |
| Prometheus metrics endpoint | `metrics` | `stable` | Public operator docs and integration coverage exist for `/status/metrics`. |
| Request limits | `request_limits` | `stable` | Explicit operator-facing guardrail in the main gateway path. |
| Rate limiting | `rate_limiter` | `stable` | Publicly documented operational control in the main HTTP path. |
| Upstream health checks and basic load balancing | `health_checker`, `circuit_breaker` | `stable` | Part of the generic reverse-proxy behavior and covered by integration scenarios. |

## Experimental Features

| Feature | Representative surface | Maturity | Why it is not Core v1 |
| --- | --- | --- | --- |
| HTTP/2 | `tls_termination` HTTP/2 path, `hpack`, `http2_frame` | `experimental` | Present in-tree, but not documented or release-gated at the same level as the HTTP/1.1 core. |
| HTTP/3 / QUIC | `http3_handler`, `http3_session`, `http3_runtime`, `ngtcp2_binding`, `quic_stub` | `experimental` | Requires extra build/runtime assumptions and is not part of the default host-native release contract. |
| WebSocket, SSE, and mux realtime paths | `websocket`, `event_hub`, mux counters in `metrics` | `experimental` | Integration coverage exists, but the public operator docs are still example-scoped rather than Core v1. |
| ACME automation | `acme_client` | `experimental` | Useful feature surface, but not part of the stable release/install promise yet. |
| Auth and identity extensions | `auth`, `basic_auth`, `jwt`, `access_control` | `experimental` | Operators can use these paths, but they are not the defining Core v1 server contract. |
| Session and device-oriented auth flows | `session`, `session_store_file`, device-registry env/example surface | `experimental` | Publicly visible in the BearClaw example, but still example-scoped rather than generic Core v1. |
| Response transformation and policy extras | `compression`, `cache_control`, `security_headers` | `experimental` | Useful knobs exist, but they are not yet positioned as part of the stable support promise. |
| DNS-driven upstream discovery | `dns_discovery` | `experimental` | In-tree and tested, but dependent on deployment assumptions beyond the narrow Core v1 story. |

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
| Product/example-specific workflow surfaces | `api_router`, `command`, `idempotency`, `approval_store`, `transcript_store` | `internal` | Useful for Bare Systems examples and product flows, not part of the generic Tardigrade marketing contract. |
| Shared-trust plumbing | `secrets`, asserted `X-Tardigrade-*` identity headers, trace propagation helpers | `internal` | Needed by some deployments, but should not be treated as a generic Core v1 promise. |

## Example Policy

Anything under `examples/` may demonstrate `stable`, `experimental`, `adapter`,
or `internal` surfaces in one place. Example docs must call that out clearly and
must not imply that non-`stable` features are part of the Core v1 support
promise.

## Maintenance Rule

When public behavior changes:

- update this matrix before or alongside the code/docs change
- declare the target maturity level in the issue, PR, or commit rationale
- avoid describing a feature as production-ready unless it is `stable` here
