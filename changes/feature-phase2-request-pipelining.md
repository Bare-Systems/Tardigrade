# Feature: Request Pipelining Boundary Handling (Phase 2.2)

## Scope
Add basic pipelining support so additional bytes received after the first HTTP request on a keep-alive connection are not discarded.

## What was added
- `src/edge_gateway.zig`:
  - Added per-connection session state (`ConnectionSession`) with pending buffer + pending length.
  - `handleConnection` now consumes parser `bytes_consumed` and retains any unread bytes for the next request iteration.
  - `readHttpRequest` now accepts existing pending bytes and returns once a complete first request is present.
  - Added request-boundary helper `firstRequestCompleteLen(...)`.
- Keep-alive worker loops now pass shared connection session state between iterations.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Added tests for pipelined request boundary detection and body completeness handling.
- Full suite run: `zig build test` (pass).

## Status: done
