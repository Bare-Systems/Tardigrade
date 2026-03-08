# Feature: Backend Connection Pooling (Phase 4.1)

## Scope
Enable reusable upstream connections so reverse-proxy traffic does not recreate a new HTTP client/connection stack per request.

## What was added
- `src/edge_gateway.zig`:
  - Added shared upstream `std.http.Client` to gateway state.
  - Upstream proxy execution now uses the shared client for `open()`/request lifecycle.
  - Enabled keep-alive on upstream requests (`keep_alive = true`) to allow connection pool reuse.
- State lifecycle:
  - Shared upstream client is deinitialized during gateway state cleanup.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Full suite run: `zig build test` (pass).

## Status: done
