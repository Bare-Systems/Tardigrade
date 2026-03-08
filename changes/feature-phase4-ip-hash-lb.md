# feature-phase4-ip-hash-lb

## Scope
Add Phase 4.3 IP-hash load balancing so proxy upstream selection can keep client IP affinity while still honoring existing health and slow-start controls.

## What changed
- Added `ip_hash` to `UpstreamLbAlgorithm` parsing in `src/edge_config.zig`.
- Extended upstream selection in `src/edge_gateway.zig`:
  - `nextUpstreamBaseUrl` now receives `client_ip`.
  - Added `ipHashIndex` helper using Wyhash over client IP.
  - Added `selectIpHashUpstreamLocked` with two-pass eligibility:
    1. healthy + slow-start-eligible
    2. healthy fallback when slow-start excludes all
  - Added startup log line for `ip_hash` when configured.
- Updated docs and roadmap tracking:
  - `README.md` env var support list
  - `PLAN.md` Phase 4.3 item + resolution note
  - `CHANGELOG.md` unreleased entry

## Tests added/changed
- No new dedicated unit tests in this increment.
- Regression coverage validated by running existing full test suite (`zig build test`).

## Status
done
