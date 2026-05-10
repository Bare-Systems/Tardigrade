# Security Test Plan

Tardigrade is a public-edge service that terminates TLS, parses untrusted HTTP
input, enforces auth, and proxies to internal upstreams. Security validation is
a release gate, not a best-effort activity.

## Threat Model To Coverage Map

### Path and filesystem safety

- Unit coverage lives in `src/http/static_file.zig`.
- Focus areas: traversal, percent-encoded traversal, double-encoded traversal,
  backslash traversal, symlink escape, alias/root interaction, autoindex safety.
- Integration coverage lives in `tests/integration.zig` for live static serving
  and top-level `try_files`.

### Request parser abuse

- Unit coverage lives in `src/http/request.zig` and `src/http/headers.zig`.
- Focus areas: duplicate `Content-Length`, `Transfer-Encoding` conflicts,
  malformed chunked bodies, premature EOF, oversized request lines, header line
  limits, aggregate header limits, header-count limits, obs-fold rejection.
- Live edge coverage lives in `tests/integration.zig` to verify malformed input
  is rejected before routing or proxying.

### Header injection and response splitting

- Unit coverage lives in `src/http/headers.zig`.
- Focus areas: control characters in names/values, CRLF injection, obs-fold,
  log-poisoning-safe header validation.
- Integration coverage verifies hop-by-hop stripping and upstream header
  sanitization.

### Auth, sessions, rate limiting, and approval policy

- Unit coverage lives in `src/http/auth.zig`, `src/http/session.zig`, and
  `src/edge_gateway.zig`.
- Integration coverage lives in `tests/integration.zig`.
- Focus areas: protected-route bypass, malformed bearer input, invalid JWT
  signature, malformed session token input, asserted-identity rate limiting,
  approval-management route bypass from recursive approval checks.

### Corpus and fuzz-style replay

- Corpus files live under `tests/corpus/http/request/`.
- The replay and deterministic mutation harness lives in
  `tests/security/request_parser_corpus.zig`.
- This harness is the v1 seed corpus for future true fuzzing. It replays known
  malicious inputs and applies small deterministic byte mutations to verify that
  the parser fails safely.

## Commands

Use the repo-pinned Zig toolchain, not the shell default `zig`.

```bash
# Unit + parser/path/auth hardening coverage
./.zig-toolchain/0.16.0/zig-aarch64-macos-0.16.0/zig build test

# Seed corpus replay + deterministic mutation pass
./.zig-toolchain/0.16.0/zig-aarch64-macos-0.16.0/zig build test-security-corpus

# Live-process integration coverage
./.zig-toolchain/0.16.0/zig-aarch64-macos-0.16.0/zig build test-integration
```

## Release Gate

Do not ship a wider public distribution unless all of the following are true:

- `zig build test` passes with the pinned Zig `0.16.0` toolchain.
- `zig build test-security-corpus` passes with the pinned Zig `0.16.0`
  toolchain.
- `zig build test-integration` passes, or any environment-specific skip is
  explicitly documented in the release notes.
- The first internal pentest playbook has been executed against a local or
  isolated non-public target and the sanitized result has been recorded in
  `docs/PENTEST_PLAYBOOK.md`.
- Public-edge behavior changes update tests and operator-facing docs.

## Current Gaps And Follow-Up

- HTTP/2, HTTP/3, WebSocket, SSE, FastCGI, SCGI, and uWSGI malicious-input
  coverage is still narrower than HTTP/1.1 parser coverage.
- The corpus harness is a deterministic mutation entrypoint, not a full
  coverage-guided fuzz target.
- Security replay and fuzz-style runs are manual today; moving them into
  scheduled CI or nightly automation remains follow-up work.
