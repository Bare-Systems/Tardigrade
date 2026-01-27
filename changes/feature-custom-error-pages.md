# Feature: Custom Error Pages

Overview

Add support for custom error pages for common HTTP error responses (400, 401, 403, 404, 500, 502, 503, 504). The server should allow serving user-provided HTML files for each status code and fall back to a built-in short response if no custom page exists.

Scope

- Expose a configuration point (initially simple: look for files under `public/errors/` named `400.html`, `401.html`, etc.).
- Update the response builder to prefer serving custom error pages when generating error responses.
- Ensure Content-Type and Content-Length are set correctly for custom error pages.
- Maintain existing behavior for non-HTML error responses and for requests that do not have an associated custom page.

Files to modify

- `src/http/response.zig` — add helpers to load and send custom error pages
- `src/main.zig` — small wiring if necessary for config path
- `public/errors/` — sample example files for testing (added under `public/errors/` in the repo)

Testing plan

- Unit tests for `response` helper to ensure it returns correct `Content-Type` and `Content-Length` when a custom page exists and when it doesn't.
- Integration test: start server, curl `/nonexistent` and assert `404` body matches `public/errors/404.html` when present.
- Manual testing instructions included in this doc.

Acceptance criteria

- Requests that trigger listed error statuses serve `public/errors/<status>.html` when that file exists.
- If custom page is absent, server returns the existing short error response body and proper headers.
- No panics or crashes when serving custom pages.

Manual test commands

```bash
# start the server
zig build run &
# create a custom 404
cat > public/errors/404.html <<'HTML'
<html><body><h1>Custom 404</h1></body></html>
HTML
# verify
curl -i http://localhost:8069/nonexistent
```

Notes

This initial implementation will be file-based (static `public/errors/`). Future work can add configurable locations and templating.
