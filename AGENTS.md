# Tardigrade Agent Guide

Scope: the `Tardigrade` repository.

## Purpose

Tardigrade is the BareSystems edge gateway and reverse proxy.

## Workflow

- Keep active unfinished work in the workspace root `ROADMAP.md`.
- Keep operator-facing behavior documented in `README.md`.
- Keep deployment reality documented in `BLINK.md`.
- Record notable repo changes in `CHANGELOG.md`.

## BearClaw Edge Contract

Use `examples/bearclaw/tardigrade.conf` plus `examples/bearclaw/tardigrade.env.example`
as the canonical BearClaw-facing edge shape.

- Public edge port: `443` with TLS enabled.
- Private BearClaw upstream: loopback HTTP via `TARDIGRADE_UPSTREAM_BASE_URL`
  and `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS`, typically `http://127.0.0.1:8080`.
- Public base paths:
  - `GET /health` returns the edge health response.
  - `POST /v1/chat` proxies directly to BearClaw `/v1/chat`.
  - `POST /v1/commands` proxies directly to BearClaw `/v1/commands`.
  - `GET /bearclaw/health` strips the `/bearclaw` mount and proxies to upstream
    `/health` without bearer auth.
  - `/bearclaw/v1/*` strips the `/bearclaw` mount and proxies to upstream
    `/v1/*` with bearer auth enforced at Tardigrade.
- Required auth headers:
  - Protected API requests use `Authorization: Bearer <raw-token>`.
  - BearClawWeb can also send HS256 JWT bearer tokens with `sub`, `scope`, and
    optional `device_id` claims when `TARDIGRADE_JWT_SECRET` is configured.
  - Session-authenticated requests use `X-Session-Token: <64-lowercase-hex>`.
  - Device-authenticated requests use `X-Device-ID`, `X-Device-Timestamp`, and
    `X-Device-Signature`.
- Bearer token hashing:
  - `TARDIGRADE_AUTH_TOKEN_HASHES` stores lowercase SHA-256 hashes of the raw
    bearer tokens, never the raw tokens themselves.
  - macOS / BSD example: `printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}'`
  - Linux example: `printf '%s' "$TOKEN" | sha256sum | awk '{print $1}'`
- Session persistence:
  - `TARDIGRADE_SESSION_STORE_PATH` is a Tardigrade-managed JSON file.
  - The stored shape is `{ "version": 1, "entries": [...] }` where each entry
    contains the session token, identity, client IP, optional device ID,
    creation timestamp, last activity timestamp, and revoked flag.
  - `TARDIGRADE_SESSION_TTL_SECONDS` is the idle timeout; the BearClaw example
    defaults to `3600`.
- Device registry:
  - `TARDIGRADE_DEVICE_REGISTRY_PATH` is a line-oriented file, not JSON.
  - Each line is `device_id|public_key`.
  - Treat it as a secret-bearing credential registry owned by the Tardigrade
    service account with restrictive filesystem permissions.
- Transcript persistence:
  - `TARDIGRADE_TRANSCRIPT_STORE_PATH` is an append-only NDJSON file.
  - Each line records `ts_ms`, `scope`, `route`, `correlation_id`, `identity`,
    `client_ip`, `upstream_url`, request body, response status,
    response content type, and response body.
  - Transcript files can contain token hashes, request payloads, and model
    output; keep them outside the web root and lock permissions down to the
    Tardigrade operator account.
- Upstream header forwarding:
  - Tardigrade forwards `X-Correlation-ID`, `X-Forwarded-For`, `X-Real-IP`,
    `X-Forwarded-Proto`, and `X-Forwarded-Host` to BearClaw.
  - When auth is resolved, it also forwards `X-Tardigrade-Auth-Identity`.
  - JWT-authenticated requests additionally forward `X-Tardigrade-User-ID`,
    `X-Tardigrade-Device-ID`, and `X-Tardigrade-Scopes`.
  - When API versioning is active, it forwards `X-Tardigrade-Api-Version`.

## Validation

```bash
zig build test
zig build test-integration
```
