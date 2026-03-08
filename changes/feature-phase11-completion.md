# Feature: Phase 11 Completion (Advanced Features)

## Scope
Complete Phase 11 work across request processing, backend protocol bridges, optional mail proxying, and stream module proxy routes.

## What Was Added
- URL rewrite foundation was expanded and integrated as pre-routing behavior:
  - regex rewrite rules + flags
  - regex return directives
  - method-conditional matching
- Request processing enhancements in gateway:
  - generic subrequest endpoint: `POST /v1/subrequest`
  - internal redirect rules + named location mapping
  - mirror rule dispatch for best-effort mirrored requests
- Backend protocol bridge modules added:
  - `src/http/fastcgi.zig`
  - `src/http/uwsgi.zig`
  - `src/http/scgi.zig`
  - `src/http/memcached.zig`
- Backend bridge routes added:
  - `/v1/backend/fastcgi`
  - `/v1/backend/uwsgi`
  - `/v1/backend/scgi`
  - `/v1/backend/grpc`
  - `/v1/backend/memcached`
- Optional mail proxy bridge routes:
  - `/v1/mail/smtp`
  - `/v1/mail/imap`
  - `/v1/mail/pop3`
- Stream module bridge routes:
  - `/v1/stream/tcp`
  - `/v1/stream/udp`
  - stream SSL termination mode flag exposed via `TARDIGRADE_STREAM_SSL_TERMINATION`
- Config/env additions in `src/edge_config.zig` for all new rule sets and upstream endpoints.

## Tests Added/Changed
- New module tests for FastCGI/uWSGI/SCGI/Memcached helpers.
- New config parser tests for:
  - internal redirect rules
  - named locations
  - mirror rules
- Existing full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Backend protocol and mail/stream routes are delivered as bridge foundations using direct endpoint forwarding and protocol packet builders.
- gRPC route is implemented as binary HTTP bridge foundation (`application/grpc`) against configured upstream URL.
