# Feature: Slow Start for Recovered Upstreams (Phase 4.4)

## Scope
Add gradual traffic ramping for recovered upstreams so they do not receive full load immediately after recovery.

## What Was Added
- Added `TARDIGRADE_UPSTREAM_SLOW_START_MS` in `src/edge_config.zig`.
- Extended upstream health state in `src/edge_gateway.zig` with `slow_start_until_ms` tracking.
- Updated upstream selection to apply slow-start eligibility gating during recovery windows.
- Integrated slow-start activation when unhealthy state clears (active success-threshold recovery and timeout-based recovery paths).

## Tests Added/Changed
- Existing edge gateway test config literals updated for new `upstream_slow_start_ms` field.
- Full suite run via `zig build test`.

## Status
- done

## Notes / Decisions
- Slow start is a gradual eligibility ramp (selection probability increases over the configured window), with fallback to healthy-backend selection if no candidate passes the ramp gate.
- Setting `TARDIGRADE_UPSTREAM_SLOW_START_MS=0` preserves previous immediate-routing behavior.
