# Feature: Keep-Alive Timeout + Connection Reuse (Phase 2.2)

## Scope
Enable sequential keep-alive request handling on a single client connection with configurable idle timeout and connection request limits.

## What was added
- `src/edge_gateway.zig`:
  - Worker handlers now process multiple requests per accepted connection until close conditions are met.
  - Per-request keep-alive decision now controls response `Connection` header behavior.
  - Idle socket timeout for client connections now prefers keep-alive timeout config.
  - Added max-requests-per-connection enforcement to bound long-lived client sockets.
- `src/edge_config.zig`:
  - Added `keep_alive_timeout_ms` (`TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS`, default `5000`).
  - Added `max_requests_per_connection` (`TARDIGRADE_MAX_REQUESTS_PER_CONNECTION`, default `100`).
- `README.md` updated with new keep-alive env vars.

## Files changed
- `src/edge_gateway.zig`
- `src/edge_config.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Full suite run: `zig build test` (pass).

## Notes
- This increment handles sequential keep-alive reuse.
- Full pipelined request processing remains open under Phase 2.2 request pipelining.

## Status: done
