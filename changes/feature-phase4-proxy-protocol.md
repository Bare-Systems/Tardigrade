# feature-phase4-proxy-protocol

## Scope
Implement Phase 4.5 proxy protocol support with real client IP extraction.

## What changed
- Added `ProxyProtocolMode` in `src/edge_config.zig` with env parsing from `TARDIGRADE_PROXY_PROTOCOL`:
  - supported modes: `off`, `auto`, `v1`, `v2`
- Extended connection session state in `src/edge_gateway.zig` to track one-time proxy preface parse and parsed client IP.
- Added PROXY parser logic in gateway:
  - v1 text header parsing (`PROXY TCP4/TCP6 ...`)
  - v2 binary signature/header parsing with TCP IPv4/IPv6 source extraction
  - mode handling for strict (`v1`/`v2`) and optional (`auto`) parsing
- Wired parser into plaintext connection handling before HTTP request parsing.
- Request context client IP fallback now uses parsed PROXY source IP when present.
- Added startup log visibility for proxy protocol mode.

## Tests added/changed
- `src/edge_config.zig`: `parse proxy protocol mode aliases`
- `src/edge_gateway.zig`:
  - `parse proxy protocol v1 header extracts source ip`
  - `parse proxy protocol auto mode ignores non-proxy preface`
  - `parse proxy protocol v2 header extracts source ip`
- Full regression suite run via `zig build test`.

## Status
done
