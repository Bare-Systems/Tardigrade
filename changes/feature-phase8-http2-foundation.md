# Feature: Phase 8 HTTP/2 Foundation (In-house HPACK + Framing)

Status: done

## Scope
Implement an in-house HTTP/2 foundation path (TLS ALPN only) with custom HPACK and frame codec modules, and integrate it into the gateway connection loop.

## What Was Added
- New in-house HPACK module (`src/http/hpack.zig`):
  - Static table support
  - Indexed/literal decode path
  - Literal header block encode path
  - Integer/string HPACK helpers
- New in-house HTTP/2 frame module (`src/http/http2_frame.zig`):
  - Frame header parse/serialize
  - SETTINGS + ACK helpers
  - PING ACK helper
  - GOAWAY helper
- TLS ALPN integration (`src/http/tls_termination.zig`):
  - ALPN server selection (`h2` / `http/1.1`)
  - Negotiated protocol inspection API on TLS connection
- Gateway HTTP/2 path (`src/edge_gateway.zig`):
  - `h2` connection dispatch after TLS handshake
  - HTTP/2 preface verification
  - SETTINGS exchange and PING handling
  - HEADERS/DATA parsing with per-stream request assembly
  - HPACK-encoded response HEADERS + DATA writes
  - Basic route support for `/health`, `/metrics`, `/metrics/prometheus`
- Config support:
  - `TARDIGRADE_HTTP2_ENABLED` (default `true`)

## Files Changed
- `src/http/hpack.zig`
- `src/http/http2_frame.zig`
- `src/http/tls_termination.zig`
- `src/http.zig`
- `src/edge_gateway.zig`
- `src/edge_config.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests Added/Changed
- Added HPACK unit tests.
- Added HTTP/2 frame codec unit tests.
- Full suite run:
  - `zig build test` (pass)

## Notes
- This increment is HTTP/2-only over TLS ALPN and intentionally does not include QUIC/HTTP/3.
- Server push, priority, full flow-control behavior, and HTTP/2-to-HTTP/1 backend translation are left for subsequent Phase 8 increments.
