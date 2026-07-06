# Contributing

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

# Integration tests — builds and drives a live tardigrade process against
# mock upstreams; requires system OpenSSL. Not required for most contributions.
zig build test-integration

# Failure-mode / chaos suite — a filtered view of the integration harness that
# exercises broken origins and clients (see "Failure-mode harness" below).
zig build test-failure

# Release-mode build
zig build -Doptimize=ReleaseFast
```

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
| `-Denable-http3-ngtcp2=true` | `false` | Enable experimental HTTP/3 ngtcp2/nghttp3 system-library integration; requires the ngtcp2/nghttp3/ngtcp2_crypto_ossl system libraries |
| `-Dversion=x.y.z` | `dev` | Embed a version string in the binary |
| `-Dhttp3-osslclient-path=<path>` | auto-detect | Path to osslclient for 0-RTT tests |

## Common workflows

```bash
# Debug build and run
zig build run

# Release build
zig build -Doptimize=ReleaseFast

# Static binary (Linux, requires static OpenSSL)
zig build -Dstatic-executable=true -Drequire-static-system-libs=true

# Build with HTTP/3 support (requires system ngtcp2/nghttp3 libraries)
zig build -Denable-http3-ngtcp2=true

# Run a specific test by name filter
zig build test -- --test-filter "jwt"

# Per-test timeout (build runner flag, not a build.zig option)
zig build test -- --test-timeout-ns 10000000000
```

HTTP/3-enabled validation is currently a manual/local build step rather than a
required CI job because the Ubuntu runner image does not consistently provide
the `ngtcp2` OpenSSL backend development package.

## Formatting

Run `zig fmt` before committing:

```bash
zig fmt src/ tests/ build.zig
```
