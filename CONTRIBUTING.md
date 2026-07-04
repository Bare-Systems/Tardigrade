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

# Integration tests — requires a running tardigrade instance and system OpenSSL
# (see tests/README.md for setup). Not required for most contributions.
zig build test-integration

# Release-mode build
zig build -Doptimize=ReleaseFast
```

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

## Formatting

Run `zig fmt` before committing:

```bash
zig fmt src/ tests/ build.zig
```
