# Feature: Buffered Proxy Metadata Preservation (Phase 4.1)

## Scope
Reduce semantic drift between streamed and buffered proxy responses by preserving upstream response metadata in buffered success paths.

## What Was Added
- Extended `ProxyResult` in `src/edge_gateway.zig` to include:
  - `content_type`
  - `content_disposition`
- Updated buffered `/v1/chat` and `/v1/commands` response handling to:
  - preserve upstream content type for successful upstream responses
  - propagate upstream `Content-Disposition` when present
- Kept existing non-200 mapping behavior intact for compatibility.

## Tests Added/Changed
- Existing test suite run (`zig build test`) after gateway proxy-path changes.
- No new proxy integration test harness exists yet; behavior validated by unit test suite + compile-time checks.

## Status
- done

## Notes / Decisions
- Upstream metadata is only propagated for successful buffered responses; mapped error responses continue to use gateway-owned JSON envelopes.
- This keeps current API contract stable while making buffered paths closer to true reverse-proxy behavior.
