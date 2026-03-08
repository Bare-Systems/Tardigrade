# Feature: Phase 13.1 + 13.3 Process and Privilege Hardening

## Scope
Complete process-management and privilege-management hardening items from the roadmap.

## What Was Added
- Process management (13.1):
  - Added master/worker process mode in `src/main.zig` controlled by:
    - `TARDIGRADE_MASTER_PROCESS`
    - `TARDIGRADE_WORKER_PROCESSES` (`0` uses CPU count)
  - Master process now supervises worker child processes and respawns exited workers.
  - Added SIGUSR2 upgrade signaling support in `src/http/shutdown.zig` and master upgrade spawn flow in `src/main.zig` (`TARDIGRADE_BINARY_UPGRADE`).
  - Added worker recycle timer support (`TARDIGRADE_WORKER_RECYCLE_SECONDS`).
  - Added Linux worker CPU affinity pinning (`TARDIGRADE_WORKER_CPU_AFFINITY`).
- Privilege management (13.3):
  - Extended runtime privilege application in `src/edge_gateway.zig`:
    - optional chroot after bind (`TARDIGRADE_CHROOT_DIR`)
    - existing uid/gid drop (`TARDIGRADE_RUN_USER`, `TARDIGRADE_RUN_GROUP`)
    - strict unprivileged enforcement (`TARDIGRADE_REQUIRE_UNPRIVILEGED_USER`)
- Config/runtime wiring:
  - Added new config fields and env parsing in `src/edge_config.zig`.
  - Updated nginx-style config alias mapping in `src/http/config_file.zig` for `worker_processes` to process-count config.

## Tests Added/Changed
- Added SIGUSR2/upgrade flag unit coverage in `src/http/shutdown.zig`.
- Existing full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Master/worker supervision uses process-level fan-out in `main` and keeps gateway worker-thread pool behavior per process unchanged.
- Upgrade flow is a safe spawn-and-drain foundation (replacement master spawn + graceful worker shutdown trigger), not fd-passing hot swap.
