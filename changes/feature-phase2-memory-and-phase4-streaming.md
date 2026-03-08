# Feature: Phase 2.4 Memory Management + Phase 4.1 Streaming Extension

## Scope
Complete remaining Phase 2.4 memory management items and ship an additional Phase 4.1 proxy streaming increment.

## What Was Added
- Added `src/http/buffer_pool.zig` with a thread-safe fixed-size `BufferPool`.
- Integrated gateway-level buffer pools:
  - request read buffers (`MAX_REQUEST_SIZE`)
  - proxy relay buffers (`16 KiB`)
- Refactored connection session state to borrow request buffers from pool and return them at connection teardown.
- Added `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` for per-connection memory caps.
- Enforced connection memory cap during request read/parse and buffered upstream read paths.
- Optimized non-200 upstream handling when error mapping is used by draining upstream bodies without storing full payloads.
- Added `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` (opt-in) to stream non-200 upstream responses directly.
- Updated streamed response circuit-breaker accounting to treat streamed 5xx as failures.

## Tests Added/Changed
- Added unit test in `src/http/buffer_pool.zig`:
  - `buffer pool reuses buffers`
- Existing suite validates gateway/proxy behavior with new config fields wired into test config literals.

## Status
- done

## Notes / Decisions
- Default behavior remains compatibility-first: non-200 upstream responses are still mapped into stable gateway error envelopes unless all-status streaming is explicitly enabled.
- Zero-copy is applied where practical by relaying proxy stream chunks directly from pooled buffers to downstream writer paths.
