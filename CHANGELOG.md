
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

# [0.7.0] - unreleased

### Added
- sendfile() zero-copy optimization for static file serving (in progress)

# [0.6.0] - 2026-01-29

### Added
- Content-Encoding negotiation for static file serving:
  - Parses `Accept-Encoding` header and negotiates supported encodings.
  - Responds with `identity` (no compression) for supported requests.
  - Returns `406 Not Acceptable` for requests with only unsupported encodings (e.g., `br`, `deflate`).
  - Lays groundwork for future gzip support.
  - Comprehensive tests for Accept-Encoding negotiation in `src/http/content_encoding_test.zig`.

## [0.5.0] - 2026-01-30

### Added

- Add `Last-Modified` header for static files and support `If-Modified-Since` (returns 304 Not Modified when appropriate).
- Add robust HTTP-date parser supporting RFC1123, RFC850, and asctime formats for conditional GET handling.
- Add directory autoindex (directory listing) for directories without index files.
 - Add `ETag` header for static files and support `If-None-Match` (returns 304 Not Modified when matching). ETag is generated from file size and mtime to avoid costly content hashing.

## [0.4.1] - 2026-01-27

### Added
- Custom error pages (public/errors/*.html)
  - Serve `public/errors/<status>.html` when present for 400, 401, 403, 404, 500, 502, 503, 504
  - Fall back to short plain-text responses when no custom page exists
  - Sample custom pages added for 404 and 500 in `public/errors/`

### Changed
- Bumped `Server` identification to `tardigrade/0.4.1` in responses

## [0.4.0] - 2026-01-27

### Added
- Directory index support (index.html, index.htm)
  - Requests to directories automatically serve index.html or index.htm
  - Directories without trailing slash get 301 redirect (e.g., /docs → /docs/)
  - Returns 404 if no index file exists in the directory

### Changed
- Refactored `serveFile` into smaller functions for clarity
- Fixed keep-alive socket timeout to use POSIX `setsockopt` (macOS/Linux compatible)

## [0.3.0] - 2026-01-27

### Added
- HTTP Response builder module (`src/http/response.zig`)
  - Builder pattern for constructing HTTP responses
  - Auto-generated Date header (RFC 7231 format)
  - Auto-generated Server header (tardigrade/0.3.0)
  - Auto-calculated Content-Length
  - Convenience constructors for common responses (ok, notFound, redirect, etc.)
- HTTP Status code module (`src/http/status.zig`)
  - All standard HTTP status codes (1xx-5xx)
  - Status code to reason phrase mapping
  - Helper methods (isSuccess, isError, isRedirection, etc.)

### Changed
- Refactored main.zig to use Response builder
- All responses now include Date and Server headers
- Method Not Allowed (405) responses now include Allow header

## [0.2.0] - 2026-01-26

### Added
- HTTP/1.1 request parser with full RFC compliance
  - Method parsing (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE)
  - URI parsing with path and query string separation
  - HTTP version parsing (HTTP/1.0, HTTP/1.1)
  - Header parsing (case-insensitive, whitespace trimming)
  - Request body handling with Content-Length
- MIME type detection for 30+ file types
- Proper HTTP error responses (400, 404, 405, 413, 414, 431, 500, 501, 505)
- HEAD request support
- Path traversal protection
- Structured logging with std.log

### Changed
- Refactored main.zig to use new modular HTTP parser
- Improved response headers (Content-Length, Content-Type, Connection)

## [0.1.0] - 2025-05-28

### Added
- Initial HTTP server implementation
- Static file serving from `public/` directory
- Basic GET request handling
- Listens on port 8069
- 404 response for missing files
- 405 response for non-GET methods
