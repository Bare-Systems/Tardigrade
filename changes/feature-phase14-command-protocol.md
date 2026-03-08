# Feature: Phase 14.1 Command Protocol

## Scope
Complete command protocol items: structured command envelopes, lifecycle tracking, and async command completion.

## What Was Added
- `src/http/command.zig`:
  - Extended command payload parser to support optional `command_id` and `async` fields.
  - Upstream envelope builder now emits `command_id` for cross-system lifecycle correlation.
- `src/edge_gateway.zig`:
  - Added in-memory command lifecycle state map with status transitions: `pending`, `running`, `completed`, `failed`.
  - Added async command execution path for `POST /v1/commands`:
    - when `async=true`, returns `202 Accepted` with `command_id` and status URL.
    - executes upstream command in detached background worker thread.
  - Added lifecycle polling endpoint:
    - `GET /v1/commands/status?command_id=...`
  - Lifecycle is updated for sync and async command flows.

## Tests Added/Changed
- Updated command module tests for new envelope fields (`command_id`, `async`).
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Lifecycle storage is in-memory and process-local by design for this increment.
- Async execution uses existing proxy execution path in buffered mode to preserve upstream behavior and error mapping consistency.
