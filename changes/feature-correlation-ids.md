# Feature: Correlation IDs

## Overview

Implement response-level correlation IDs for gateway observability under Phase 0.3.

## Scope

- Add `src/http/correlation_id.zig` with:
  - validation for safe incoming correlation IDs
  - generation fallback for missing/invalid IDs
  - request-header extraction helper
- Export correlation helpers from `src/http.zig`.
- Wire `X-Correlation-ID` into `src/main.zig` response paths:
  - static file responses (200/304/404/406/500 and redirects)
  - parse error responses
- Keep behavior deterministic and backward-compatible for non-correlation headers.

## Files changed

- `src/http/correlation_id.zig` (new)
- `src/http.zig`
- `src/main.zig`
- `src/content_encoding_test.zig`
- `src/stream_etag_test.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed

- Added unit tests in `src/http/correlation_id.zig`:
  - accepts valid token IDs
  - reuses valid incoming `X-Correlation-ID`
  - generates fallback IDs for invalid input
- Added integration-style tests in `src/content_encoding_test.zig`:
  - echoes a valid incoming correlation ID
  - generates a valid `tg-...` correlation ID when request value is invalid
- Updated existing `serveFileContent` test call sites for new optional correlation-id parameter.

## Verification

- `zig build test` fails in this sandbox unless cache dirs are workspace-local.
- Passed with:
  - `ZIG_LIB_DIR=/opt/homebrew/Cellar/zig/0.14.1/lib/zig zig build test --global-cache-dir .zig-cache/global --cache-dir .zig-cache`
  - `ZIG_LIB_DIR=/opt/homebrew/Cellar/zig/0.14.1/lib/zig zig test src/main.zig --cache-dir .zig-cache --global-cache-dir .zig-cache/global`

## Status

Done.
