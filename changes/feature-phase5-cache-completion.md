# Feature: Phase 5 Cache Completion

Status: done

## Scope
Complete remaining Phase 5 cache work across proxy cache and advanced cache behaviors.

## What Was Added
- Phase 5.1 completion:
  - Added proxy cache bypass conditions in gateway request handling:
    - `X-Proxy-Cache-Bypass: true|1|yes`
    - `Cache-Control: no-cache|no-store|max-age=0`
    - `Pragma: no-cache`
  - Added authenticated purge endpoint:
    - `POST /v1/cache/purge`
    - Optional JSON body `{ "key": "..." }` for key-only purge
    - No body purges all cache entries
  - Added optional disk cache tier path:
    - `TARDIGRADE_PROXY_CACHE_PATH`
- Phase 5.2 completion:
  - Added stale-while-revalidate window:
    - `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS`
    - stale hits return `X-Proxy-Cache: STALE`
  - Added cache locking/wait controls:
    - `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS`
    - per-key lock map to reduce duplicate population on misses
  - Added background cache refresh:
    - stale hits spawn detached refresh workers for chat/command routes
  - Added cache manager maintenance:
    - `TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS`
    - periodic timer-driven cleanup of expired in-memory entries
  - Added memory+disk tiered cache behavior:
    - memory lookup first, disk fallback second
    - disk hit hydrates in-memory cache
- Extended idempotency store cache primitive with:
  - stale-capable lookup (`getWithStale`)
  - public delete/clear/cleanup methods for cache management lifecycle

## Files Changed
- `src/edge_config.zig`
- `src/edge_gateway.zig`
- `src/http/idempotency.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests Added/Changed
- Existing suite retained and expanded by code-path coverage in gateway tests and cache key tests.
- Full suite run:
  - `zig build test` (pass)

## Acceptance
- Proxy cache supports TTL + stale serving + lock coordination.
- Cache bypass and purge are available for operations.
- Background refresh and maintenance behaviors are active.
- Disk tier and memory tier can be used together via config.
