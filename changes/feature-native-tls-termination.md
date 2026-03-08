# Feature: Native TLS Termination (Phase 0.0)

## Scope
Finalize the deferred native HTTPS/TLS termination item by adding in-process TLS handshake/transport support for gateway connections when certificate and key paths are configured.

## What was added
- New TLS module `src/http/tls_termination.zig`:
  - OpenSSL-backed `TlsTerminator` for TLS server context creation.
  - Certificate/private-key PEM loading and key/cert validation.
  - `TlsConnection` wrapper with `read` and writer support (`SSL_read` / `SSL_write`).
- Gateway integration in `src/edge_gateway.zig`:
  - TLS context initialized at startup when cert/key paths are configured.
  - Worker connection handling now performs TLS handshake before request processing.
  - Request handling path generalized to support both plain sockets and TLS-wrapped connections.
- Build updates in `build.zig`:
  - Link `libssl` + `libcrypto` and libc for executable and unit tests.
- Docs/plan updates:
  - `PLAN.md` marks native TLS termination complete.
  - `README.md` TLS env vars updated to indicate runtime enablement semantics.

## Files changed
- `src/http/tls_termination.zig` (new)
- `src/edge_gateway.zig`
- `src/http.zig`
- `build.zig`
- `PLAN.md`
- `README.md`
- `CHANGELOG.md`

## Tests added/changed
- Added TLS module sanity test (`openssl init`).
- Full suite run: `zig build test` (pass).

## Notes
- TLS is enabled when both `TARDIGRADE_TLS_CERT_PATH` and `TARDIGRADE_TLS_KEY_PATH` are set and valid PEM files.
- If TLS is not configured, gateway continues serving plain HTTP behavior.

## Status: done
