# Feature: Phase 14.3 Approval Workflows

## Scope
Complete approval workflow items: approval request routing, approval response handling, and timeout escalation.

## What Was Added
- `src/edge_gateway.zig`:
  - Added approval request endpoint:
    - `POST /v1/approvals/request`
  - Added approval decision endpoint:
    - `POST /v1/approvals/respond`
  - Added approval status endpoint:
    - `GET /v1/approvals/status?approval_token=...`
  - Added in-memory approval store keyed by `approval_token`.
  - Added policy integration so approval-required routes now validate token state (`approved`, `pending`, `denied`, `escalated`) instead of only checking header presence.
  - Added timeout escalation: pending approvals auto-transition to `escalated` after timeout.

## Tests Added/Changed
- Added helper-level tests in `src/edge_gateway.zig`:
  - approval rule requirement detection
  - approval request parsing
  - approval response parsing
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Approval entries are currently in-memory and process-local, matching existing lifecycle/state stores in this phase.
- Approval routes are exempted from approval-policy recursion to avoid deadlock when approval gating is enabled broadly.
