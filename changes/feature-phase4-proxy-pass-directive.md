# Feature: proxy_pass Directive Foundation (Phase 4.1)

## Scope
Add config-driven proxy target routing so `/v1/chat` and `/v1/commands` can be directed to explicit upstream targets without hardcoded path assumptions.

## What was added
- Config additions in `src/edge_config.zig`:
  - `proxy_pass_chat` (`TARDIGRADE_PROXY_PASS_CHAT`, default `/v1/chat`)
  - `proxy_pass_commands_prefix` (`TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX`, default empty)
- Gateway proxy target resolution in `src/edge_gateway.zig`:
  - `resolveProxyTarget(...)` supports:
    - Absolute URL mode (`http://...` / `https://...`)
    - Relative-path mode joined to `TARDIGRADE_UPSTREAM_BASE_URL`
  - `combineProxyTarget(...)` normalizes prefix + suffix joining for command subpaths.
- Route wiring:
  - `/v1/chat` now routes through `proxy_pass_chat`.
  - `/v1/commands` command upstream paths now route through `proxy_pass_commands_prefix + command upstream suffix`.
- Cleanup:
  - Removed obsolete one-shot proxy helper code paths superseded by the unified executor.

## Files changed
- `src/edge_config.zig`
- `src/edge_gateway.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- Added tests for proxy target joining/resolution helpers.
- Full suite run: `zig build test` (pass).

## Status: done
