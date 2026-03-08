# feature-phase4-upstream-blocks

## Scope
Complete Phase 4.2 upstream blocks by adding route-scoped upstream pool configuration for `/v1/chat` and `/v1/commands`.

## What changed
- Added route-scoped upstream configuration fields in `src/edge_config.zig`:
  - `upstream_chat_base_urls`, `upstream_chat_base_url_weights`, `upstream_chat_backup_base_urls`
  - `upstream_commands_base_urls`, `upstream_commands_base_url_weights`, `upstream_commands_backup_base_urls`
- Added environment variables:
  - `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS`
  - `TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS`
  - `TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS`
  - `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS`
  - `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS`
  - `TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS`
- Added per-scope upstream pool resolution in `src/edge_gateway.zig`:
  - `/v1/chat` and `/v1/commands` requests now select upstreams from their own configured blocks.
  - Route blocks fall back to the global upstream pool when route-specific pools are not configured.
- Integrated scoped pools with existing LB logic (round-robin/weighted, least-connections, ip-hash, generic-hash, random-two-choices), retries, and backup failover.
- Active health checks now probe route-scoped block upstreams and backups in addition to global upstreams.
- Startup logs now report enabled `chat` and `commands` upstream blocks.

## Tests added/changed
- Existing full test suite run: `zig build test`.
- Updated test config literals in `src/edge_gateway.zig` for the expanded `EdgeConfig` shape.

## Status
done
