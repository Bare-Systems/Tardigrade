# Feature: Multi-Upstream Round-Robin Foundation (Phase 4.2/4.3)

## Scope
Add foundational multi-backend upstream support and default round-robin load balancing for proxy targets.

## What Was Added
- Added `TARDIGRADE_UPSTREAM_BASE_URLS` in `src/edge_config.zig`:
  - comma-separated upstream base URLs
  - compatible fallback to single `TARDIGRADE_UPSTREAM_BASE_URL`
- Added gateway-side round-robin upstream selection in `src/edge_gateway.zig`.
- Updated proxy target resolution to use per-request selected upstream base URL.
- Added startup logging when multi-upstream round-robin mode is active.

## Tests Added/Changed
- Added unit test in `src/edge_gateway.zig`:
  - `selectUpstreamBaseUrl round-robins across configured bases`
- Existing proxy target resolution tests updated for new resolver signature.

## Status
- done

## Notes / Decisions
- This increment provides only default round-robin across configured base URLs.
- Weighted routing, passive/active health checks, and failover tuning remain future work under Phase 4.2/4.3.
