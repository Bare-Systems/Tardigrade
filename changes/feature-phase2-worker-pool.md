# Feature: Worker Pool Concurrency (Phase 2.3)

## Scope
Add a multi-threaded worker model so accepted connections are processed concurrently by worker threads, while preserving existing gateway behavior and protecting shared mutable state.

## What was added
- New worker pool module `src/http/worker_pool.zig`:
  - Fixed-size worker thread pool.
  - Bounded in-memory queue for accepted sockets.
  - Condition-variable based worker wakeup.
  - Graceful shutdown/join semantics with optional queue draining.
- Gateway runtime integration in `src/edge_gateway.zig`:
  - Event-loop accept thread now enqueues accepted sockets into worker pool.
  - Worker callback handles per-connection processing and response path.
  - Listener thread remains focused on accept/event loop progress.
- Thread-safe shared state synchronization in `GatewayState` (`src/edge_gateway.zig`):
  - Locked helpers for rate limiting, sessions, idempotency, metrics, and circuit breaker.
  - Cached idempotency responses are copied per-request to avoid cross-thread lifetime hazards.
- Config additions in `src/edge_config.zig`:
  - `worker_threads` (`TARDIGRADE_WORKER_THREADS`, default `0` = auto CPU count).
  - `worker_queue_size` (`TARDIGRADE_WORKER_QUEUE_SIZE`, default `1024`).
- Module export in `src/http.zig` as `http.worker_pool`.

## Files changed
- `src/http/worker_pool.zig` (new)
- `src/edge_gateway.zig`
- `src/edge_config.zig`
- `src/http.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- New `worker_pool` unit test validating queued work execution.
- Full test suite run: `zig build test` (pass).

## Decisions
- Kept the existing request/response handling logic and moved concurrency to connection dispatch first.
- Chose synchronized shared-state wrappers as the safest incremental step before deeper subsystem refactors.
- Left work-stealing and connection-draining semantics for follow-up work in remaining Phase 2.3 items.

## Status: done
