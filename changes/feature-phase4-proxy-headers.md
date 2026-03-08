# Feature: Proxy Header Rewriting Foundation (Phase 4.1)

## Scope
Strengthen reverse-proxy behavior by centralizing upstream proxy request construction and adding canonical forwarding/header-rewrite behavior needed for gateway deployments.

## What was added
- Unified proxy request helper in `src/edge_gateway.zig`:
  - `proxyJsonRequest(...)` now backs both `/v1/chat` and `/v1/commands` upstream calls.
  - Existing `proxyChat` and `proxyCommand` now delegate to this shared path.
- Forwarding header logic:
  - `X-Forwarded-For` composed from incoming chain + current client IP.
  - `X-Real-IP` set from resolved client IP.
  - `X-Forwarded-Proto` set from gateway runtime context (`http`/`https` based on TLS config presence).
  - `X-Forwarded-Host` propagated from incoming `Host` when present.
- `Host` header rewriting:
  - Upstream `Host` derived from `upstream_base_url` authority and applied on proxied requests.
- Helper utilities/tests:
  - `buildForwardedFor(...)` helper.
  - `parseUpstreamHost(...)` helper.
  - Unit tests for both helpers.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Added tests:
  - `buildForwardedFor appends client ip`
  - `parseUpstreamHost extracts authority`
- Full suite run: `zig build test` (pass).

## Decisions
- Kept current in-memory upstream response buffering to avoid behavioral regressions while rolling in header/path improvements.
- Deferred true request/response streaming proxying to the next 4.1 increment because it is tightly coupled with remaining async per-connection state-machine work.

## Status: done
