# Feature: Phase 3.1 + 3.4 Config Parser & Hot Reload Foundation

## Scope
Implement foundational config-file parsing and hot reload on top of the existing env-based runtime configuration.

## What Was Added
- New module `src/http/config_file.zig`:
  - nginx-style directive parser for statements ending in `;`
  - directive forms:
    - `key value;`
    - `set $name value;`
    - `include path;` (supports simple wildcard include patterns)
  - variable interpolation using `${var}`
  - normalization of directive keys into `TARDIGRADE_*` env-style keys
  - strict syntax validation with file/line error logging on parse failures
- `src/edge_config.zig` integration:
  - Added pre-load config-file override ingestion using `TARDIGRADE_CONFIG_PATH`
  - Maintains precedence: real environment variables override config-file values
- `src/http/shutdown.zig`:
  - Added reload flag/state and SIGHUP signal handling
- `src/edge_gateway.zig`:
  - Added event-loop hot reload path triggered by consumed SIGHUP requests
  - Reload behavior:
    - parse/validate new config first
    - apply atomically for new requests by swapping active config pointer
    - retain current config on validation/load failure
    - no listener/worker shutdown during reload

## Tests Added/Changed
- New unit tests in `src/http/config_file.zig` for key normalization and interpolation.
- New shutdown test coverage for reload flag consume behavior.
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Config-file values are defaults; env vars remain highest precedence to preserve existing deployment behavior.
- Reload uses validate-before-apply semantics and a zero-downtime pointer swap strategy for request handlers.
