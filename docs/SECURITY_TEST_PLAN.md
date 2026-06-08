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

### Resolved Gaps (issue #174)

**F-01 — HTTP method enforcement (WSTG-CONF-06, ASVS-13.2.1)** ✅ RESOLVED
`TRACE` is rejected globally with 405 in `edge_gateway.zig` before any
location block is consulted. The `return_response` action additionally rejects
non-GET/HEAD methods on non-redirect static-return directives with 405
(ASVS-14.5.1). Corpus case `trace_method.http` documents the expected
behavior.

**F-02 — Upstream Server header passthrough (WSTG-INFO-02, ASVS-14.3.3)** ✅ RESOLVED
`shouldSkipUpstreamResponseHeader()` in `gateway_proxy.zig` strips upstream
`Server` and `X-Powered-By` headers. Tardigrade emits its own `Server:
tardigrade` header. Covered by unit tests in `gateway_proxy.zig`.

**F-03 — Missing Host header not rejected (WSTG-CONF-07, ASVS-14.5.1)** ✅ RESOLVED
HTTP/1.1 requests missing `Host` are rejected with `400 Bad Request` in
`edge_gateway.zig` before routing or proxying. HTTP/1.0 is exempt per RFC
1945. Corpus case `no_host_http11.http` documents parser acceptance; gateway
enforcement is tested via unit conditions in `edge_gateway.zig`.

**F-04 — Client-controlled X-Request-ID / X-Correlation-ID (WSTG-INPV-11, ASVS-7.1.1)** ✅ RESOLVED
`fromHeadersOrGenerate()` in `src/http/correlation_id.zig` validates incoming
IDs against the `tg-<decimal>-<lowercase-hex>` format. Arbitrary client values
are discarded and a fresh ID is generated. Covered by unit tests in
`correlation_id.zig`.

### Open Gaps

**F-05 — TLS surface pass still pending**
A dedicated TLS engagement against a Tardigrade instance with real TLS has not
yet been completed with `tls_scan`. Run against an isolated lab target.

**F-06 — Auth enforcement pass still pending**
Bearer auth bypass, malformed bearer, token replay, and method-change bypass
have not been probed against a live edge with auth configured.

**F-07 — Static file serving via catch-all `location /` non-functional**
Files in a configured `doc_root` return 404 despite `root` directive in
`location /`. Investigate whether this is a static-serving bug or intentional;
add integration test for static root fallback.

## Proxy Security Behavior Reference

See `docs/PROXY_SECURITY.md` for the authoritative description of Tardigrade's
intended behavior at each HTTP proxy trust boundary, including:

- Hop-by-hop header stripping (request and response directions)
- Connection header token handling (RFC 7230 §6.1)
- TE/CL conflict and duplicate Content-Length rejection
- Header casing normalization and validation rules
- Absolute-form vs origin-form URI handling
- X-Forwarded-* trust boundary and safe deployment requirements
- Host header enforcement (HTTP/1.1)
- Body size and header size/count limits
- Malformed upstream response handling
- Directory traversal protection for static serving
- TRACE method rejection (XST defense)
- Correlation ID validation (log poisoning defense)
- X-Tardigrade-* asserted identity header stripping
