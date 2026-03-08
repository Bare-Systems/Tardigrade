# Feature: Retry Policy Foundation (Phase 13.4)

## Scope
Add a basic configurable retry policy for upstream proxy calls to improve resilience against transient upstream failures.

## What Was Added
- Added `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` config in `src/edge_config.zig` (minimum value `1`).
- Refactored proxy execution in `src/edge_gateway.zig`:
  - added attempt loop in `proxyJsonExecute`
  - moved single-attempt logic into `proxyJsonExecuteSingleAttempt`
  - retries now rotate upstream base URL selection when multiple upstreams are configured
- Added startup logging for configured retry attempts.

## Tests Added/Changed
- Existing unit suite run after retry logic refactor (`zig build test`).
- Existing edge-gateway proxy unit tests continue to pass.

## Status
- done

## Notes / Decisions
- Retry behavior currently targets transport/attempt-level failures and is intentionally simple.
- Response-status-based retry rules (for selected 5xx/429 classes) are deferred to a future resilience pass.
