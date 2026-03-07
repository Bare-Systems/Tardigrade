# Feature: Overload Protection + Request Queue Management (Phase 13)

## Scope
Add explicit overload controls and queue-pressure handling in the listener/accept path.

## What Was Added
- Added `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` in `src/edge_config.zig`.
- Gateway connection slot tracking now enforces:
  - per-IP active caps (existing)
  - global active connection cap (new)
- Accept path now performs explicit load shedding with `503 Service Unavailable` + `Retry-After: 1` when:
  - global connection cap is exceeded
  - per-IP cap is exceeded
  - worker queue submission fails due saturation
- Added `rejectOverloadedClient()` helper for consistent overload responses.

## Tests Added/Changed
- Existing unit test suite run after gateway slot-management changes (`zig build test`).
- Existing config test literals updated for new `EdgeConfig.max_active_connections` field.

## Status
- done

## Notes / Decisions
- Overload responses are emitted directly from accept/listener path as best-effort writes.
- This keeps worker capacity available for accepted requests and provides clients a clear retry signal.
