# Feature: Active Upstream Health Checks (Phase 4.4)

## Scope
Add periodic active upstream probing and integrate probe outcomes with existing passive failover state.

## What Was Added
- Added active health-check config in `src/edge_config.zig`:
  - `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS`
  - `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH`
  - `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_TIMEOUT_MS`
- Added timer-driven probe execution in `src/edge_gateway.zig`:
  - `runActiveHealthChecks()` invoked from event-loop timer ticks
  - per-upstream GET probe requests using a dedicated probe HTTP client
  - configurable probe URL path joining and timeout
- Probe outcomes now call existing `recordUpstreamSuccess` / `recordUpstreamFailure` so active checks affect backend availability.

## Tests Added/Changed
- Added unit test `buildHealthProbeUrl joins base and probe path` in `src/edge_gateway.zig`.
- Existing edge/gateway test config literals updated with new active-health fields.
- Full suite run via `zig build test`.

## Status
- done

## Notes / Decisions
- Active health checks currently require passive thresholds (`TARDIGRADE_UPSTREAM_MAX_FAILS`) to be meaningful, since unhealthy state transitions are threshold-based.
- Probe execution is best-effort and non-fatal; probe failures only affect upstream health scoring.
