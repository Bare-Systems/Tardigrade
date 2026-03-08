# feature-phase4-upstream-weights

## Scope
Add Phase 4.2 weighted primary upstream routing for multi-backend proxy deployments.

## What changed
- Added `upstream_base_url_weights` to edge config (`src/edge_config.zig`).
- Added env var `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS`.
  - Parsed as comma-separated positive integers.
  - Validation enforces count alignment with `TARDIGRADE_UPSTREAM_BASE_URLS` when weights are configured.
- Added weighted routing helpers in `src/edge_gateway.zig`:
  - weighted slot count computation
  - weighted ticket-to-index mapping
  - weighted round-robin selector
- Primary round-robin routing now uses weighted ticketing for backend selection.
- Primary fallback path now uses weighted selection when probing primaries after backup fallback.
- Added startup log visibility when server weights are configured.
- Updated docs/plan/changelog tracking.

## Tests added/changed
- `src/edge_config.zig`: added CSV parse test coverage for upstream weight parsing.
- `src/edge_gateway.zig`: added weighted selector behavior test (`selectUpstreamBaseUrlWeighted honors configured weights`).
- Full regression suite run via `zig build test`.

## Status
done
