# Feature: Worker Work Stealing + Load Balancing (Phase 2.3)

## Scope
Implement the remaining Phase 2.3 worker scheduling item by replacing single-queue dispatch with a worker-aware queueing policy.

## What Was Added
- Refactored `src/http/worker_pool.zig` to use per-worker connection queues.
- Submit path now picks the least-loaded worker queue under lock.
- Worker loops now process local queue items first and steal work from peer queues when idle.
- Queue capacity enforcement now tracks total queued jobs across all worker queues.
- Graceful shutdown draining and non-draining semantics were preserved with the new queue model.

## Tests Added/Changed
- Added unit test: `worker pool queue selection prefers least-loaded worker queue`.
- Added unit test: `worker pool popWorkLocked steals from peer queue`.
- Existing worker pool processing + drain tests continue to pass under the new scheduler.

## Status
- done

## Notes / Decisions
- Stealing takes the oldest available item from a victim queue (`orderedRemove(0)`), while local workers pop from their own queue tail; this keeps implementation simple while reducing idle worker time.
- Dispatch starts search from a rotating index to avoid always preferring worker 0 when queue depths are equal.
