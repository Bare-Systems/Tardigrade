# Feature: Phase 5.1 Proxy Cache Foundation

Status: done

## Scope
Implement the first Phase 5 proxy-caching increment in the edge gateway by adding cache key configuration and basic cache validity behavior.

## What Was Added
- Config additions in `src/edge_config.zig`:
  - `proxy_cache_ttl_seconds` (`TARDIGRADE_PROXY_CACHE_TTL_SECONDS`, default `0`)
  - `proxy_cache_key_template` (`TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE`, default `method:path:payload_sha256`)
- Gateway cache integration in `src/edge_gateway.zig`:
  - Added proxy-cache store lifecycle to gateway state.
  - Added template-based cache key builder supporting tokens:
    - `method`
    - `path`
    - `payload_sha256`
    - `identity`
    - `api_version`
  - Added cache read path for `/v1/chat` and `/v1/commands` responses.
  - Added cache write path for successful (`200`) upstream responses.
  - Added `X-Proxy-Cache: HIT` header for cache hits.
- Documentation updates:
  - `README.md` env var docs.
  - `PLAN.md` Phase 5.1 checkbox/progress updates.
  - `CHANGELOG.md` new branch section entry.

## Tests Added/Changed
- Added unit tests in `src/edge_gateway.zig`:
  - `buildProxyCacheKey supports template tokens`
  - `buildProxyCacheKey falls back for unknown template tokens`
- Full suite run:
  - `zig build test` (pass)

## Notes
- This increment uses in-memory TTL caching (not disk-based cache path yet).
- Cache bypass rules, purging, and advanced stale/lock/tiered behavior remain for subsequent Phase 5 tasks.
