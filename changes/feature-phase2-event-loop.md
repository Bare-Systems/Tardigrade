# Feature: Async Event Loop Foundation (Phase 2.1)

## Scope
Replace the blocking gateway `accept()` loop with a cross-platform event loop foundation and timer-driven waits so listener I/O is non-blocking and shutdown responsiveness is no longer tied to new incoming connections.

## What was added
- New module `src/http/event_loop.zig`:
  - `EventLoop` abstraction with backend selection:
    - `epoll` on Linux.
    - `kqueue` on macOS/BSD targets.
  - Readable-FD registration (`addReadFd`) and `wait(...)` API returning normalized events.
  - `TimerManager` for periodic tick scheduling (`msUntilNextTick`, `consumeTick`).
  - `monotonicMs()` helper for event-loop timing.
- Gateway runtime integration in `src/edge_gateway.zig`:
  - Listening socket switched to non-blocking mode.
  - Accept path now driven by event-loop readiness instead of blocking `server.accept()`.
  - New `acceptReadyConnections(...)` helper drains all pending accepts per readiness notification.
  - Event-loop timeout/tick hook added for future timeout and housekeeping work.
  - Startup log now includes selected event loop backend (`epoll`/`kqueue`).
- Module export in `src/http.zig` as `http.event_loop`.

## Files changed
- `src/http/event_loop.zig` (new)
- `src/http.zig`
- `src/edge_gateway.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- New unit tests in `src/http/event_loop.zig`:
  - Backend detection matches current target OS.
  - Timer manager tick cadence behavior.
- Full suite run: `zig build test` (pass).

## Decisions
- Accepted client sockets are converted back to blocking mode before `handleConnection`.
- Rationale: preserve current request parsing and upstream proxy behavior while introducing event-loop listener infrastructure first.
- Follow-up in Phase 2.2/2.3: move per-connection read/write paths to fully non-blocking state machines and worker-driven concurrency.

## Status: done
