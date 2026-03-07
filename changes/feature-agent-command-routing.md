# Feature: Agent Command Routing

**Branch:** `feat/agent-command-routing`
**Version:** 0.10.0
**Status:** done

## Scope

Implement Phase 0.4 from PLAN.md: structured command routing, upstream request envelope, authenticated request forwarding, and request auditing.

## Files Changed

- `src/http/command.zig` — **NEW** — Command types, envelope parsing, upstream envelope builder, audit struct.
- `src/http.zig` — Added `command` module re-export.
- `src/edge_gateway.zig` — Added `POST /v1/commands` endpoint and `proxyCommand` function.

## Design Decisions

- **Command types:** Enum with string mapping (`chat`, `tool.list`, `tool.run`, `status`). Each type maps to a specific upstream path.
- **Envelope format:** `{"command": "<type>", "params": {...}, "idempotency_key": "optional"}`. Params must be a JSON object, forwarded as-is to upstream.
- **Upstream envelope:** Wraps params with context block containing correlation_id, identity, client_ip, api_version, timestamp. Upstream receives full context without needing to parse auth headers.
- **Auth:** Reuses the same bearer-or-session fallback pattern from `/v1/chat`.
- **Idempotency:** Supports both inline `idempotency_key` in the envelope and the `Idempotency-Key` header; inline takes precedence.

## Tests Added

In `src/http/command.zig`:
- `CommandType fromString valid`
- `CommandType fromString unknown`
- `CommandType upstreamPath`
- `parseCommand valid chat`
- `parseCommand with idempotency key`
- `parseCommand missing command field`
- `parseCommand unknown command`
- `parseCommand missing params`
- `parseCommand params not object`
- `parseCommand invalid json`
- `buildUpstreamEnvelope produces valid JSON`
- `buildUpstreamEnvelope null api_version`
- `CommandType toString roundtrip`

## Acceptance Criteria

- [x] Typed command enum with string conversion and upstream path mapping
- [x] Command envelope parsing with validation
- [x] Upstream envelope with full gateway context
- [x] Gateway POST /v1/commands endpoint with auth
- [x] Idempotency support (inline + header)
- [x] Structured command audit logging
- [x] All tests pass (`zig build test`)
