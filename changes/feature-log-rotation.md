# Feature: Log Rotation Support (Phase 1.4)

## Scope
Add log rotation support for file-backed error logging.

## What Was Added
- `src/main.zig`:
  - Added startup log rotation when `TARDIGRADE_ERROR_LOG_PATH` is configured and log size exceeds `TARDIGRADE_LOG_ROTATE_MAX_BYTES`.
  - Added retention generation control via `TARDIGRADE_LOG_ROTATE_MAX_FILES`.
  - Added `rotateLogFiles` helper that shifts `error.log` -> `error.log.1` -> ... and trims oldest generation.

## Tests Added/Changed
- Added tests for generation shifting and `max_files=0` delete behavior.
- Full suite run: `zig build test` (passing).

## Status
- done
