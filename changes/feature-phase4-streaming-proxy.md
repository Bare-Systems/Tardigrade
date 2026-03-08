# Feature: Streaming Upstream Relay (Phase 4.1)

## Scope
Introduce streaming proxy behavior for successful upstream responses so gateway hot paths do not always buffer full upstream payloads in memory.

## What was added
- `src/edge_gateway.zig`:
  - Added `proxyJsonExecute(...)` execution path:
    - Performs upstream request.
    - Streams successful (`200`) responses directly to clients using chunked transfer encoding.
    - Falls back to buffered response for non-200 paths.
  - Added streaming response helpers:
    - `writeStreamedUpstreamResponse(...)`
    - `writeChunk(...)`
    - `writeSecurityHeaders(...)`
  - Integrated into `/v1/chat` and `/v1/commands` handlers.
    - Streaming enabled when idempotency storage/replay semantics are not required.
    - Existing error mapping/compression/idempotency behavior preserved in buffered fallback paths.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Full suite run: `zig build test` (pass).

## Decisions
- Streamed only successful upstream responses first to avoid breaking stable error envelope mapping and idempotency replay behavior.
- Retained buffered fallback for non-200 and idempotency-cached paths.

## Status: done
