# Feature: Phase 10 Compression Completion

## Scope
Complete remaining Phase 10 compression/decompression items:
- Brotli response compression support.
- gzip_static-style handling for precompressed payloads.
- gunzip path for upstream responses in proxy flows.

## What Was Added
- Updated `src/http/compression.zig`:
  - Added response encoding negotiation (`br`/`gzip`) from `Accept-Encoding` with quality (`q=`) support.
  - Added `Encoding` enum and encoding-aware `CompressionResult`.
  - Added Brotli compression using runtime dynamic library loading (`libbrotlienc`) so builds do not require hard link-time dependency.
  - Added gzip_static-style passthrough for payloads already gzip-encoded (gzip magic bytes), avoiding redundant recompression.
- Updated config and gateway wiring:
  - `src/edge_config.zig`:
    - `TARDIGRADE_COMPRESSION_BROTLI_ENABLED`
    - `TARDIGRADE_COMPRESSION_BROTLI_QUALITY`
    - `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED`
  - `src/edge_gateway.zig`:
    - Compression config now includes Brotli toggles/quality.
    - Downstream `Content-Encoding` now reflects negotiated encoding (`br` or `gzip`).
    - Upstream proxy requests optionally advertise `Accept-Encoding: gzip, identity` for gunzip workflow.

## Tests Added/Changed
- Extended compression unit tests in `src/http/compression.zig`:
  - encoding negotiation preference/quality behavior
  - encoding metadata on compressed outputs
  - gzip precompressed passthrough behavior
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Brotli support is runtime-optional: if encoder library is unavailable, compression automatically falls back to gzip without breaking request handling.
- Upstream gunzip leverages Zig `std.http.Client` automatic decompression semantics for gzip-encoded responses.
