# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
