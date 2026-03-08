# Feature: Connection + Upstream Health Metrics Expansion

## Scope
Expose the new runtime hardening behavior in operational metrics so queue pressure and passive upstream health are visible.

## What Was Added
- Extended `src/http/metrics.zig` with:
  - `active_connections` gauge
  - `connection_rejections` counter
  - `queue_rejections` counter
  - `upstream_unhealthy_backends` gauge
- Updated metrics JSON and Prometheus formatters to emit these values.
- Wired gateway hooks in `src/edge_gateway.zig`:
  - connection-slot rejection increments
  - queue saturation rejection increments
  - active connection gauge updates on acquire/release
  - upstream unhealthy gauge updates from passive health state transitions

## Tests Added/Changed
- Added/updated metrics unit assertions in `src/http/metrics.zig` for new counters/gauges and output formats.
- Full suite run via `zig build test`.

## Status
- done

## Notes / Decisions
- Upstream unhealthy gauge is derived from current passive-health windows (`unhealthy_until_ms > now`) and updates on health transitions.
- This keeps metric update overhead low while reflecting real-time failover state.
