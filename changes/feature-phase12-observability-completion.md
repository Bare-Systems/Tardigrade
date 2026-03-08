# Feature: Phase 12 Observability Completion

## Scope
Complete Phase 12 logging and admin API items:
- Logging format controls, conditional logging, buffering, and syslog forwarding.
- Admin API endpoints for runtime/service introspection.

## What Was Added
- `src/http/access_log.zig`:
  - Added access-log runtime config with output formats: `json`, `plain`, `custom`.
  - Added custom template rendering for access log lines.
  - Added status-threshold conditional logging.
  - Added buffered access log flushing.
  - Added optional syslog UDP forwarding.
- `src/edge_config.zig`:
  - Added logging env config:
    - `TARDIGRADE_ACCESS_LOG_FORMAT`
    - `TARDIGRADE_ACCESS_LOG_TEMPLATE`
    - `TARDIGRADE_ACCESS_LOG_MIN_STATUS`
    - `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE`
    - `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP`
- `src/edge_gateway.zig`:
  - Initializes/deinitializes configured access logging runtime.
  - Added authenticated admin endpoints:
    - `GET /admin/routes`
    - `GET /admin/connections`
    - `GET /admin/streams`
    - `GET /admin/upstreams`
    - `GET /admin/certs`
    - `GET /admin/auth-registry`
  - Added stream counters and upstream-health JSON snapshot helpers for admin responses.

## Tests Added/Changed
- Updated access log module tests for format parsing and non-panicking emits.
- Existing full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Admin API responses expose configured/aggregated runtime state, not full historical event storage.
- Syslog forwarding is UDP-based best effort to keep hot-path overhead low.
