# Feature: Socket Timeout Enforcement (Phase 6.4 follow-up)

## Scope
Activate runtime timeout enforcement for configured request/upstream timeouts that were previously configured but not enforced.

## What was added
- `src/edge_gateway.zig`:
  - Added `setSocketTimeoutMs(...)` helper using socket timeout options.
  - Accepted client sockets now apply header timeout when `TARDIGRADE_HEADER_TIMEOUT_MS > 0`.
  - Upstream proxy sockets now apply send/receive timeouts from `TARDIGRADE_UPSTREAM_TIMEOUT_MS`.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Full suite run: `zig build test` (pass).

## Status: done
