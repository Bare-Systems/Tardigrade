# Feature: Custom Error Pages

Status: done

## Scope

- Implement Upgrade 8 custom error pages for location-backed static routes
- Keep API routes on the existing JSON error envelope
- Reuse the shared static-file module instead of adding a second file-serving path

## What Changed

- Extended the location runtime model in `src/http/location_router.zig` with per-location `error_page` rules
- Extended `src/http/config_file.zig` to parse:
  - `error_page 404 /errors/404.html`
  - `error_page 500 502 503 504 /50x.html`
  - `error_page 404 https://example.com/missing`
- Added parallel serialized config wiring through:
  - `TARDIGRADE_LOCATION_ERROR_PAGES`
  - `src/edge_config.zig` runtime parsing/apply logic
- Updated the shared static handlers in `src/edge_gateway.zig` so:
  - non-API requests with explicit HTML-style `Accept` headers can resolve configured custom error pages
  - local error-page targets are served via `src/http/static_file.zig`
  - absolute URI targets return `302 Found` redirects
  - `/v1/...` routes keep their JSON error envelopes regardless of `error_page`

## Tests

- Added config parser coverage in `src/http/config_file.zig` for `error_page` serialization
- Added runtime parsing coverage in `src/edge_config.zig` for applying location error-page rules
- Added integration coverage in `tests/integration.zig` for:
  - static 404 returning configured HTML error page with status 404
  - API 404 still returning JSON even when `error_page` is configured on `/`

## Notes

- Custom error pages are intentionally gated by explicit HTML-ish `Accept` headers.
- This prevents internal readiness checks and API-style callers with no `Accept` header from being silently converted to HTML responses.
