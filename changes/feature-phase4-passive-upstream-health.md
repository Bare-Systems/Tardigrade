# Feature: Passive Upstream Health + Failover (Phase 4.2/4.4)

## Scope
Add passive upstream failure tracking so round-robin backend selection can avoid repeatedly sending requests to recently failing backends.

## What Was Added
- Added new upstream health settings in `src/edge_config.zig`:
  - `TARDIGRADE_UPSTREAM_MAX_FAILS`
  - `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS`
- Added upstream health tracking in gateway state (`src/edge_gateway.zig`):
  - per-upstream failure counts
  - temporary unhealthy windows
  - health reset on success/cooldown expiry
- Updated upstream selection to skip unhealthy backends when alternatives exist.
- Wired proxy execution retry loop to record upstream success/failure outcomes.

## Tests Added/Changed
- Existing unit test suite run after upstream health/refactor changes (`zig build test`).
- Existing upstream round-robin test remains green.

## Status
- done

## Notes / Decisions
- This is passive health only (failure-observation-based), not active probe-based health checks.
- If all configured backends are unhealthy, selection still probes in round-robin order to allow recovery.
