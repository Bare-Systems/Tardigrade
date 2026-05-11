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

### Gaps Identified in Pass 8 (2026-05-10, tardigrade-perf)

**F-01 — HTTP method enforcement (WSTG-CONF-06, ASVS-13.2.1)**
All HTTP verbs accepted on direct routes (`location = /health`). No gateway-level
method restriction today. Fix: add `allowed_methods` directive to config DSL;
add corpus cases for OPTIONS/TRACE/PUT/DELETE on direct routes expecting 405.

**F-02 — Upstream Server header passthrough (WSTG-INFO-02, ASVS-14.3.3)**
Proxy responses include upstream `Server` header alongside Tardigrade's own.
Fix: strip upstream `Server` (and `X-Powered-By`) in the proxy response path.
Add `proxy_hide_header` or equivalent; unit-test that upstream headers are
scrubbed before `writeSecurityHeaders()` fires.

**F-03 — Missing Host header not rejected (WSTG-CONF-07, ASVS-14.5.1)**
HTTP/1.1 requests with no `Host` header should be rejected with 400. Currently
accepted. Fix: add explicit check in the request parser or router; add corpus
case `no-host-http1.1.txt`.

**F-04 — Client-controlled X-Request-ID / X-Correlation-ID (WSTG-INPV-11, ASVS-7.1.1)**
Client-supplied `X-Request-ID` / `X-Correlation-ID` are reflected verbatim in
response and access log. Enables log poisoning and trace-ID spoofing. Fix:
validate format against `^tg-[0-9]+-[0-9a-f]+$` or always generate fresh IDs
ignoring client input; sanitize log values for non-printable characters.

**F-05 — TLS pass still pending**
The homelab edge at `192.168.86.53:8443` (Tardigrade with real TLS) has not yet
been probed with `tls_scan`. Run a dedicated TLS engagement against that surface.

**F-06 — Auth enforcement pass still pending**
`/bearclaw/v1/*` requires Bearer per blink.toml verify tests. Auth bypass,
malformed bearer, token replay, and method-change bypass have not been probed
against the live edge.

**F-07 — Static file serving via catch-all `location /` non-functional**
Files in `/opt/tardigrade/public` return 404 despite `root` directive in
`location /`. Investigate whether this is a static-serving bug or intentional;
add integration test for static root fallback.
