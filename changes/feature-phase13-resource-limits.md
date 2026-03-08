# Feature: Resource Limit Controls (Phase 13.2)

## Scope
Implement file descriptor and memory-related resource controls in the runtime admission/startup path.

## What Was Added
- Added `TARDIGRADE_FD_SOFT_LIMIT` in `src/edge_config.zig`.
- Added startup fd soft-limit application in `src/edge_gateway.zig` using `setrlimit(RLIMIT_NOFILE)` on supported Unix platforms.
- Added `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` in `src/edge_config.zig`.
- Added listener admission check in `src/edge_gateway.zig` that rejects new clients with explicit 503 when projected active-connection memory estimate exceeds configured cap.

## Tests Added/Changed
- Existing gateway test config literals updated with new fields.
- Full suite run with `zig build test` after changes.

## Status
- done

## Notes / Decisions
- FD soft-limit setting is best-effort and non-fatal; startup continues on unsupported/permission-limited environments.
- Global memory limit uses an estimate based on active connections and per-connection memory budget to keep admission checks lightweight.
