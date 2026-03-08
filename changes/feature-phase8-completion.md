# Feature: Phase 8 Completion (HTTP/2 + HTTP/3 Foundations)

Status: done

## Scope
Complete remaining Phase 8 roadmap items after the initial HTTP/2 foundation by adding HTTP/2 runtime behaviors (push, priority, flow control, translation) and HTTP/3/QUIC + QPACK foundations.

## What Was Added
- HTTP/2 runtime completion in gateway:
  - Priority parsing and weight-based ready-stream scheduling.
  - Connection/stream flow-control tracking with `WINDOW_UPDATE` handling.
  - Server push support with `PUSH_PROMISE` and pushed response streams.
  - HTTP/2 to HTTP/1.1 backend translation for `/v1/chat` and `/v1/commands` via existing upstream proxy execution paths.
- HTTP/2 frame utilities extended:
  - `PRIORITY` parser.
  - `WINDOW_UPDATE` parser + writer.
  - `PUSH_PROMISE` writer.
- HTTP/3/QUIC foundations:
  - New QUIC packet parser (`src/http/quic.zig`) supporting packet-type classification including 0-RTT.
  - Connection migration tracker keyed by destination connection ID.
  - Runtime HTTP/3 config flags (`TARDIGRADE_HTTP3_*`).
- QPACK foundations:
  - New literal header block encoder/decoder (`src/http/qpack.zig`).

## Files Changed
- `src/edge_gateway.zig`
- `src/http/http2_frame.zig`
- `src/http/quic.zig`
- `src/http/qpack.zig`
- `src/edge_config.zig`
- `src/http.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests Added/Changed
- Added QUIC parser + migration tracker tests.
- Added QPACK literal block encode/decode test.
- Full suite run:
  - `zig build test` (pass)

## Notes
- HTTP/3 implementation in this increment is a foundation layer (packet parsing, migration tracking, and QPACK codec primitives), not a full QUIC transport stack.
