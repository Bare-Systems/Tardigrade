# Feature: Worker Pool Graceful Draining (Phase 2.3)

## Scope
Complete the Phase 2.3 graceful shutdown/draining item by ensuring worker shutdown can wait for queued and in-flight connection jobs to complete.

## What was added
- Updated `src/http/worker_pool.zig`:
  - Added in-flight job tracking (`active_jobs`).
  - `shutdownAndJoin(true)` now waits for queue + active job count to reach zero before joining worker threads.
  - Worker completion now signals the condition variable to unblock drain waiters.
- Added unit test:
  - `worker pool shutdown drains in-flight work` verifies drain-mode shutdown waits for a running job to complete.

## Files changed
- `src/http/worker_pool.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed
- New worker pool drain behavior test.
- Full suite run: `zig build test` (pass).

## Status: done
