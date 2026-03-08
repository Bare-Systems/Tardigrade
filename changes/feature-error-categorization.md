# Feature: Error Categorization Telemetry (Phase 12.3)

## Scope
Add structured error categorization in logs and metrics to improve operational triage.

## What Was Added
- Access logs now include `error_category` in `src/http/access_log.zig`.
- Added status-to-category mapping in gateway (`classifyErrorCategory`) and wired it in `logAccess()`.
- Extended metrics in `src/http/metrics.zig` with error-category counters:
  - invalid_request
  - unauthorized
  - rate_limited
  - upstream_timeout
  - upstream_unavailable
  - internal_error
  - overload
- Wired categorized metric increments in `src/edge_gateway.zig`:
  - `sendApiError` paths
  - listener overload rejection paths

## Tests Added/Changed
- Added `classifyErrorCategory maps statuses` test in `src/edge_gateway.zig`.
- Extended metrics unit tests for new category counters and output fields.
- Access log tests updated for new `error_category` field.

## Status
- done

## Notes / Decisions
- Category mapping is intentionally coarse and status-driven for stability.
- Fine-grained subcategory taxonomy can be layered later without breaking current counters.
