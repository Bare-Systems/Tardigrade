# Contributing

## Reporting bugs and requesting features

GitHub Issues is the public intake path for Tardigrade bug reports and
feature requests — anyone is welcome to open one. When you open a new issue,
please pick the template that fits:

- **Bug Report** — something is broken or behaving unexpectedly.
- **Feature Request** — propose a new capability or improvement.

A few things to keep in mind:

- **Security vulnerabilities do not go here.** Please follow
  [SECURITY.md](SECURITY.md) instead of opening a public issue, so the report
  isn't visible before a fix is available.
- **Questions and support requests** are welcome as issues too (there isn't a
  separate chat/forum yet) — use whichever template is the closest fit, or
  the Feature Request template if it's more of a "how do I..." than a bug.
- **Never include secrets** in a public report — private keys, certificates
  with sensitive identity information, tokens, credentials, production
  secrets, or unredacted private configuration. Sanitize config excerpts and
  logs before pasting them.

## Before You Start

Read the review checklist before making changes:

- **[docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md)** — short checklist to complete
  before submitting a PR.

## Expectations

- Keep the core runtime generic.
- Avoid product-specific shortcuts.
- Keep changes focused and minimal.
- Update docs when behavior changes.

## Development commands

Use Zig `0.16.0` for all local builds and validation.

```bash
# Format check (matches CI)
zig fmt --check build.zig src/ tests/

# Unit tests (matches CI)
zig build test --summary all --error-style verbose

# Stable Web PKI differential corpus (requires OpenSSL and Go)
zig build test-pki-differential --summary all --error-style verbose

# Full core + extended PKI corpus used by the scheduled/manual CI job
zig build test-pki-differential-extended --summary all --error-style verbose

# Offline PKI mismatch-minimization tests (also run under `zig build test`);
# verifies the reducer and regenerates every promoted seed byte-for-byte
zig build test-pki-reduce --summary all --error-style verbose

# Integration tests — builds and drives a live tardigrade process against
# mock upstreams; requires system OpenSSL. Not required for most contributions.
zig build test-integration

# Failure-mode / chaos suite — a filtered view of the integration harness that
# exercises broken origins and clients (see "Failure-mode harness" below).
zig build test-failure

# Pure-Zig QUIC/HTTP-3 package unit tests (no system libraries). Also run under
# `zig build test`.
zig build test-quic

# Release-mode build
zig build -Doptimize=ReleaseFast
```

The PKI differential harness invokes OpenSSL and Go as argv-spawned child
processes. Stable corpus runs enforce a 10 second per-validator deadline with
bounded stdout/stderr capture; the extended target uses a separately bounded
30 second deadline for larger hostile-corpus cases. Child timeouts, crashes,
launch failures, malformed validator output, or output-limit violations are
harness failures, not ordinary certificate rejections. The Go crypto/x509
oracle is built once as a test helper and invoked directly; use
`zig build -Dgo-bin=/path/to/go test-pki-differential` when a non-default Go
tool is required.

## Failure-mode harness

`zig build test-failure` runs the production-safety suite defined in
`tests/integration.zig` (the `failure:`-prefixed tests). It reuses the live
`tardigrade` process harness and mock origins to intentionally break connections
and services, then asserts the gateway fails safely: a defined status code (or
connection close), no starved worker, no leaked client connections (a bounded
`tardigrade_active_connections` gauge), and the relevant metrics/log signals.

Covered failure modes:

- Origin down before connect, or accepting-but-never-responding (bounded 5xx).
- Origin closing mid-response (buffered path returns 502 rather than a truncated
  body; streaming aborts are asserted separately).
- Origin returning malformed response headers (bounded 5xx, never passed
  through as success).
- Client aborting mid-upload and mid-download (worker recovers; downstream
  aborts are recorded via `tardigrade_proxy_client_aborts_total`).
- Malformed and stalled downstream TLS handshakes (rejected and logged without
  wedging the listener; stalls bounded by `TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS`).
  Requires `curl` for the valid-TLS control request.
- Access-log sink unreachable (requests still succeed).
- Metrics endpoint scraped under concurrent proxy load.

Reload-during-active-streams and graceful-shutdown-under-load are covered by the
`#170` tests in the same file. The suite is part of `test-integration`, so CI
running `zig build test-integration` also runs it; use `zig build test-failure`
locally to iterate on just these scenarios. Run a single scenario with a name
filter, e.g. `zig build test-integration -- --test-filter "failure: client abort"`.

## Build options

| Flag | Default | Purpose |
|---|---|---|
| `-Doptimize=ReleaseFast` | `Debug` | Production-speed build |
| `-Doptimize=ReleaseSafe` | `Debug` | Release with safety checks |
| `-Dstatic-executable=true` | `false` | Fully static binary |
| `-Dprefer-static-system-libs=true` | `false` | Prefer static OpenSSL/crypto |
| `-Drequire-static-system-libs=true` | `false` | Fail if static libs are unavailable |
| `-Dversion=x.y.z` | `dev` | Embed a version string in the binary |

## Common workflows

```bash
# Debug build and run
zig build run

# Release build
zig build -Doptimize=ReleaseFast

# Static binary (Linux, requires static OpenSSL)
zig build -Dstatic-executable=true -Drequire-static-system-libs=true

# Run a specific test by name filter
zig build test -- --test-filter "jwt"

# Per-test timeout (Zig build-runner flag)
zig build test --test-timeout 10s
```

### HTTP/3

HTTP/3 is served by the native Zig QUIC/H3 stack in `src/quic/` and
`src/http3/` (#240/#328). It needs **no HTTP/3 system libraries** and is
always compiled; the listener activates at runtime with `--http3` plus a
QUIC-compatible TLS identity (Ed25519 or ECDSA P-256 certificate). The stack
is unit- and integration-tested via `zig build test-quic`, and validated
against external implementations (ngtcp2/nghttp3, quiche, aioquic — run as
separate processes) via `scripts/interop/run-interop.sh`. Rollback path for
the pre-native C-backed implementation is past tagged releases, not a build
flag.

## Formatting

Run `zig fmt` before committing:

```bash
zig fmt src/ tests/ build.zig
```
