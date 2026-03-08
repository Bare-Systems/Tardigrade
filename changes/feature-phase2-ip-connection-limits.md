# Feature: Per-IP Connection Limits (Phase 2.2)

## Scope
Add active per-IP connection limiting to the event-loop accept path so individual clients cannot consume all worker capacity.

## What was added
- Gateway state connection tracker in `src/edge_gateway.zig`:
  - Active connection counts by IP.
  - fd -> IP association for deterministic release on worker completion.
- Listener accept enforcement:
  - Before dispatching to worker pool, accepted sockets must acquire a per-IP connection slot.
  - Rejected sockets are closed immediately when the IP has reached its configured cap.
- Worker lifecycle release:
  - Connection slot is released when worker finishes processing (or if queue submission fails).
- New config in `src/edge_config.zig`:
  - `max_connections_per_ip` (`TARDIGRADE_MAX_CONNECTIONS_PER_IP`, default `0` disabled).
- IPv4/IPv6 keying:
  - Connection tracking supports both IPv4 and IPv6 client address families.

## Files changed
- `src/edge_gateway.zig`
- `src/edge_config.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Existing suite run: `zig build test` (pass).

## Status: done
