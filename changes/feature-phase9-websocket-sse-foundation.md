# Feature: Phase 9 WebSocket + SSE Foundation

## Scope
Implement Phase 9 runtime streaming capabilities in the edge gateway:
- WebSocket upgrade/proxy routes for chat and commands.
- SSE publish/stream routes backed by in-memory topic fanout.
- Runtime/config integration and tests for new parsing helpers.

## What Was Added
- New HTTP modules:
  - `src/http/websocket.zig`:
    - Upgrade detection, accept-key generation, server handshake writer.
    - Basic frame read/write helpers (mask handling + payload cap enforcement).
  - `src/http/event_hub.zig`:
    - Thread-safe topic event hub with per-topic ring buffering.
    - Publish, replay snapshot (`since id`), oldest-id lookup for backlog protection.
- Gateway integration in `src/edge_gateway.zig`:
  - Added gateway state `event_hub` lifecycle management.
  - Added authenticated WebSocket routes:
    - `GET /v1/ws/chat`
    - `GET /v1/ws/commands`
  - Added WebSocket runtime behavior:
    - ping/pong handling
    - idle timeout handling
    - frame-size enforcement
    - upstream proxy forwarding using existing load-balanced proxy path
  - Added authenticated SSE routes:
    - `GET /v1/events/stream?topic=...`
    - `POST /v1/events/publish?topic=...`
  - Added SSE replay (`Last-Event-ID`) and backlog/slow-client protection.
  - Added query/header parsing helpers for topic and last-event-id.
- Config wiring in `src/edge_config.zig`:
  - `TARDIGRADE_WEBSOCKET_ENABLED`
  - `TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS`
  - `TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE`
  - `TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS`
  - `TARDIGRADE_SSE_ENABLED`
  - `TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC`
  - `TARDIGRADE_SSE_POLL_INTERVAL_MS`
  - `TARDIGRADE_SSE_MAX_BACKLOG`
  - `TARDIGRADE_SSE_IDLE_TIMEOUT_MS`
- Exported new modules via `src/http.zig`.

## Tests Added/Changed
- Added websocket module unit test for deterministic `Sec-WebSocket-Accept` generation.
- Added event hub unit test for publish/replay behavior.
- Added gateway helper tests:
  - query param extraction
  - last-event-id parsing
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- WebSocket proxy forwarding reuses the existing proxy execution path, inheriting route-scoped upstream selection and load-balancing behavior.
- SSE fanout uses an in-memory ring buffer per topic for deterministic replay/backlog bounds without introducing persistent storage in this phase.
