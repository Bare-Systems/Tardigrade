# feature-phase4-generic-hash-lb

## Scope
Add Phase 4.3 generic-hash load balancing mode for multi-upstream proxy routing.

## What changed
- Added `generic_hash` to `UpstreamLbAlgorithm` parsing in `src/edge_config.zig`.
- Extended upstream selection in `src/edge_gateway.zig`:
  - `nextUpstreamBaseUrl` now accepts a deterministic hash key in addition to client IP.
  - Added `selectGenericHashUpstreamLocked` for hash-based backend selection.
  - Selection applies two-pass eligibility: healthy + slow-start first, then healthy fallback.
- Proxy execution now computes a deterministic hash key per request:
  - Uses request payload when present.
  - Falls back to proxy target path when payload is empty.
- Added startup logging for `generic_hash` mode.
- Updated docs and roadmap tracking:
  - `README.md` env var support list
  - `PLAN.md` Phase 4.3 item + resolution note
  - `CHANGELOG.md` unreleased entry

## Tests added/changed
- Extended algorithm parsing coverage in `src/edge_config.zig` to include `generic_hash`.
- Full regression suite run via `zig build test`.

## Status
done
