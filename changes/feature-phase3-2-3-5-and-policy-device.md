# Feature: Phase 3.2/3.3/3.5 + Phase 0.1 + Phase 6.6 Increment

## Scope
Implement core config directives, HTTP-block directive foundations, secret-management foundations, identity enhancements, and policy-engine enforcement.

## What Was Added
- Core directives and runtime behavior:
  - Config aliases for `worker_processes`, `worker_connections`, `error_log`, `pid`, and `user/group`.
  - Runtime pid-file lifecycle and stderr log redirection in `src/main.zig`.
  - Numeric post-bind privilege drop (`setgid`/`setuid`) in `src/edge_gateway.zig`.
- HTTP block directive foundation:
  - Config aliases for `listen`, `server_name`, `root`, and `try_files`.
  - Runtime server-name host matching and `try_files` static fallback path.
- Secret management foundation:
  - New module `src/http/secrets.zig` with `TARDIGRADE_SECRETS_PATH` and rotating `TARDIGRADE_SECRET_KEYS` support.
  - Encrypted `ENC:<base64>` secret envelope decoding with keyed validation prefix.
  - Integrated secret-file overrides in `src/edge_config.zig` with env > config-file > secrets > default precedence.
- Identity/auth expansion:
  - `POST /v1/devices/register` device identity registration endpoint.
  - Device proof header validation for protected routes when enabled.
  - `POST /v1/sessions/refresh` token rotation endpoint with access/refresh TTL metadata.
- Policy engine:
  - Route policy evaluation for required scopes, approval token gates, time-window rules, and device regex restrictions.

## Tests Added/Changed
- Added `src/http/secrets.zig` unit coverage for encrypted envelope decryption with key rotation list.
- Added `src/http/config_file.zig` coverage for `listen` directive mapping.
- Added keep-alive pipelining boundary cleanup test in `src/edge_gateway.zig`.
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Device request proof uses deterministic SHA-256 over registered key + request tuple for lightweight branch-local key-auth foundation.
- Secret envelope uses a lightweight XOR mechanism with validation prefix (`TG1:`) to enable key rotation flow without external KMS dependency.
