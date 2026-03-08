# Feature: Least-Connections Upstream Load Balancing (Phase 4.3)

## Scope
Add least-connections upstream selection as a configurable alternative to round-robin.

## What Was Added
- Added upstream load-balancer algorithm config in `src/edge_config.zig`:
  - `TARDIGRADE_UPSTREAM_LB_ALGORITHM`
  - supported values: `round_robin`, `least_connections`
- Added per-upstream in-flight attempt tracking in `src/edge_gateway.zig`.
- Updated upstream selection to choose least-loaded healthy backend when `least_connections` is enabled.
- Integrated least-connections with existing health and slow-start eligibility checks.

## Tests Added/Changed
- Existing edge-gateway test config literals updated with `upstream_lb_algorithm` field.
- Full suite run via `zig build test`.

## Status
- done

## Notes / Decisions
- In-flight load is tracked at proxy-attempt granularity and decremented on attempt completion.
- When no eligible backend passes least-connections filters, selection falls back to existing round-robin behavior.
