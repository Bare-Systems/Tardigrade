# Feature: Request-Scoped Arena Allocator (Phase 2.4)

## Scope
Reduce request-path allocation overhead by using a request-scoped arena allocator for gateway request processing.

## What was added
- `src/edge_gateway.zig`:
  - Replaced per-request `GeneralPurposeAllocator` in `handleConnection` with `ArenaAllocator`.
  - Request temporary allocations are now reclaimed in a single deinit at end-of-request.

## Files changed
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Full suite run: `zig build test` (pass).

## Status: done
