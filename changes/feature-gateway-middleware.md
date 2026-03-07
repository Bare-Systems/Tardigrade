# Feature: Gateway Middleware Pipeline

**Status**: done
**Branch**: `feat/gateway-middleware`
**Version**: 0.8.0

## Scope

Add five middleware modules to the gateway and integrate them into the edge request pipeline:

1. **Rate Limiter** — token-bucket per-IP rate limiting
2. **Security Headers** — standard browser security headers
3. **Request Context** — per-request auth/identity/timing propagation
4. **API Version Router** — `/v<N>/...` path parsing and version validation
5. **Idempotency Key** — duplicate request detection and response replay

## Files Added

| File | Purpose |
|------|---------|
| `src/http/rate_limiter.zig` | Token-bucket rate limiter with stale cleanup |
| `src/http/security_headers.zig` | Configurable security header presets |
| `src/http/request_context.zig` | Request context struct + client IP extraction |
| `src/http/api_router.zig` | Versioned path parser + route matcher |
| `src/http/idempotency.zig` | Idempotency key store with TTL |

## Files Changed

| File | Change |
|------|--------|
| `src/http.zig` | Register five new submodules |
| `src/edge_config.zig` | Add `rate_limit_rps`, `rate_limit_burst`, `security_headers_enabled`, `idempotency_ttl_seconds` fields + env loading |
| `src/edge_gateway.zig` | Refactor to use `GatewayState`, apply rate limiting before routing, use `RequestContext` for audit, apply security headers to all responses, support idempotency replay |
| `CHANGELOG.md` | Add 0.8.0 entry |
| `PLAN.md` | Check off Phase 0.1, 0.3, 6.2, 6.5 items |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_RATE_LIMIT_RPS` | `10` | Requests per second per client IP (0 = disabled) |
| `TARDIGRADE_RATE_LIMIT_BURST` | `20` | Maximum burst capacity |
| `TARDIGRADE_SECURITY_HEADERS` | `true` | Enable security response headers |
| `TARDIGRADE_IDEMPOTENCY_TTL` | `300` | Idempotency cache TTL in seconds (0 = disabled) |

## Tests Added

- `rate_limiter.zig`: burst allows, burst exhaustion, independent key tracking, header formatting
- `security_headers.zig`: default preset applies all headers, API preset skips frame/CSP
- `request_context.zig`: timing/identity tracking, API version/idempotency setters, X-Forwarded-For/X-Real-IP/default IP extraction
- `api_router.zig`: version extraction, multi-digit version, non-versioned rejection, bare version, route matching, version allowlist
- `idempotency.zig`: key validation, header extraction, store put/get, unknown key returns null

## Acceptance Criteria

- [x] Rate limiter rejects with 429 when burst exhausted
- [x] Security headers appear on all gateway responses
- [x] Request context propagates identity through audit logs
- [x] `/v1/chat` routes correctly via version router
- [x] Unsupported API versions return 400
- [x] Duplicate idempotent requests return cached response with `X-Idempotent-Replayed: true`
- [x] All 76 tests pass (`zig build test`)
