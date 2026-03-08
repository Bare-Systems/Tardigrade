# Feature: Phase 6 Security Completion

Status: done

## Scope
Complete remaining Phase 6 items: geo blocking, connection-count limiting alignment, auth subrequest checks, JWT validation, and add_header support.

## What Was Added
- Geo-based blocking (external data):
  - `TARDIGRADE_GEO_BLOCKED_COUNTRIES`
  - `TARDIGRADE_GEO_COUNTRY_HEADER`
  - Gateway now denies requests with blocked country header values.
- `limit_conn` completion increment:
  - Added `TARDIGRADE_LIMIT_CONN_PER_IP` as explicit alias to per-IP connection limiting.
  - Existing active connection accounting paths continue to enforce per-IP/global caps.
- Auth request (subrequest-based):
  - Added `TARDIGRADE_AUTH_REQUEST_URL` and `TARDIGRADE_AUTH_REQUEST_TIMEOUT_MS` config.
  - Protected API routes now perform auth subrequest checks when configured.
- JWT validation (optional):
  - Added `src/http/jwt.zig` module for HS256 bearer JWT validation.
  - Added optional issuer/audience enforcement via `TARDIGRADE_JWT_ISSUER` and `TARDIGRADE_JWT_AUDIENCE`.
  - Integrated JWT into auth flow before token-hash/basic fallbacks.
- `add_header` directive support:
  - Added `TARDIGRADE_ADD_HEADERS` parser (`Name: Value|Name2: Value2`).
  - Custom headers are now applied with security headers to all gateway responses.

## Files Changed
- `src/edge_config.zig`
- `src/edge_gateway.zig`
- `src/http/jwt.zig`
- `src/http.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests Added/Changed
- Added JWT module unit coverage (`src/http/jwt.zig`) for valid signature and invalid-signature behavior.
- Full suite run:
  - `zig build test` (pass)

## Notes
- Geo blocking relies on upstream/CDN-provided country header data.
- Auth subrequest support is optional and only active when `TARDIGRADE_AUTH_REQUEST_URL` is configured.
