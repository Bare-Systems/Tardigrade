# Feature: Configurable Active Health Thresholds (Phase 4.4)

## Scope
Add configurable consecutive failure/success thresholds for active health probes before upstream state transitions occur.

## What Was Added
- Added new config in `src/edge_config.zig`:
  - `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD`
  - `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD`
- Extended upstream health state in `src/edge_gateway.zig` with probe streak counters.
- Added `recordActiveProbeResult()` to apply threshold-based transitions:
  - fail streak threshold -> mark backend unhealthy
  - success streak threshold -> clear unhealthy state
- Active health probe path now uses threshold-based outcome recording.

## Tests Added/Changed
- Existing edge gateway test config literals updated with new active-threshold fields.
- Full suite run via `zig build test`.

## Status
- done

## Notes / Decisions
- Threshold defaults are both `1` to preserve existing immediate transition behavior.
- Passive and active health signals now coexist; active probes can recover backends without waiting for passive timeout expiry when success thresholds are met.
