# Feature: Timeout Budgets for Upstream Retries (Phase 13.4)

## Scope
Add total timeout budgeting across upstream retry attempts so end-to-end proxy wait time is bounded per request.

## What Was Added
- Added `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` config in `src/edge_config.zig`.
- Updated proxy retry execution in `src/edge_gateway.zig`:
  - tracks per-request start time
  - computes remaining budget before each attempt
  - caps each attempt socket timeout to remaining budget
  - returns timeout immediately when budget is exhausted
- Startup logging now reports timeout-budget enablement.

## Tests Added/Changed
- Existing test suite run (`zig build test`) after retry-path timeout-budget changes.
- Existing edge-gateway tests updated for new config field literals.

## Status
- done

## Notes / Decisions
- Budgeting is optional (`0` disables it) to preserve backward compatibility.
- Per-attempt timeout (`TARDIGRADE_UPSTREAM_TIMEOUT_MS`) still applies but is bounded by remaining total budget when both are set.
