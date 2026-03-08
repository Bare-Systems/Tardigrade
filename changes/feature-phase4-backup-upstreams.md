# feature-phase4-backup-upstreams

## Scope
Add Phase 4.2 backup upstream support so traffic can fail over to a backup pool when primary upstreams are unavailable.

## What changed
- Added `upstream_backup_base_urls` to edge config (`src/edge_config.zig`).
- Added env var `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` (comma-separated).
- Gateway upstream selection (`src/edge_gateway.zig`) now:
  - Keeps primary selection behavior per LB algorithm.
  - Falls back to backup upstreams only when primaries have no healthy/eligible candidate.
  - Uses a dedicated backup round-robin index for backup pool fallback ordering.
- Active health checks now probe backup upstreams in addition to primaries.
- Upstream retry attempt cap now includes backup upstream count when multiple upstream pools are configured.
- Added startup log visibility for backup pool count.
- Updated docs/roadmap/changelog entries.

## Tests added/changed
- No dedicated new unit tests for this increment.
- Full regression suite run via `zig build test`.

## Status
done
