# Feature: Phase 14.2 Stream Multiplexing

## Scope
Complete stream multiplexing items: multiple logical streams per socket, mixed command+event streaming, and per-device event isolation.

## What Was Added
- `src/edge_gateway.zig`:
  - Added authenticated multiplexed WebSocket route:
    - `GET /v1/ws/mux`
  - Added mux channel model supporting multiple named channels on one socket:
    - event channels via `subscribe` / `unsubscribe`
    - event publish via `publish`
    - command channels via `command` envelopes
  - Added event-channel polling and push frames over WebSocket:
    - `{"type":"event","channel":"...","topic":"...","id":...,"payload":...}`
  - Added command lifecycle push frames over WebSocket for async commands:
    - `{"type":"command.update","channel":"...","command_id":"...","status":"..."...}`
  - Added per-device mux isolation:
    - requires `X-Device-ID` on `/v1/ws/mux`
    - event topics are namespaced to `device/<device_id>/<topic>`
  - Added admin route listing update to include `/v1/ws/mux`.

## Tests Added/Changed
- Added/updated in-file coverage in `src/edge_gateway.zig`:
  - topic/device segment validation coverage for mux topic safety constraints.
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Mux command execution reuses existing command parsing and upstream execution paths to preserve current auth, auditing, and error behavior.
- Non-string publish payloads are JSON-serialized before event-bus publication so mux clients can send object/array payload bodies directly.
