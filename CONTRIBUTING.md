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

- **[docs/CI.md](docs/CI.md)** — smoke vs full CI modes, changelog-driven selection, and
  manual `gh workflow run ci.yml -f mode=full`
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

# Bounded fast developer/agent gate -- use this for ordinary edit/test/review
# iteration instead of the full `test` above (see "Test performance" below)
zig build test-fast --summary all --error-style verbose

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

## Test performance

**Agent/local iteration runs `zig build test-fast`, not `zig build test`.**
The default `test` step is the complete, unfiltered gate (28 run artifacts,
~4,850 test cases as of #944) and CI still runs it in full; it is not a fast
edit/test/review loop. Don't wait on or repeatedly re-run the full `zig build
test` locally -- use `test-fast` below, and treat independently-running CI as
the evidence for the full suite once it finishes.

```bash
# Bounded fast developer/agent gate: targets <2 minutes warm-cache (see the
# reference baseline below). Omits four targets that each have their own
# dedicated step and still run under the default `test`/CI; see their
# reasons at each target's definition in build.zig.
zig build test-fast --summary all --error-style verbose

# Same, with a hard per-test ceiling so a newly-introduced hang fails
# immediately instead of spinning:
zig build test-fast --summary all --test-timeout 30s
```

### Baseline (#944)

Measured 2026-10-20 on the reference machine: Apple M4, 10 cores, macOS
Darwin 25.3.0, Zig 0.16.0, `-Doptimize=Debug` (the default), warm
`.zig-cache` (no recompilation; every number below is pure test-run wall
time). These are real measurements on one machine, not promises for every
machine -- a slower CI runner or a cold cache will be higher; see the
acceptance note in #944.

| Run | Wall clock |
| --- | --- |
| `zig build test` (full, unfiltered) | ~100-120s |
| `zig build test-fast` | ~95-120s (observed across repeated runs; system load/thermal throttling noise, not a regression) |

Per-run-artifact breakdown of `zig build test`, slowest first (28 run
artifacts total; this is every one that took at least a few seconds):

| Test target | Tests | Wall time | Notes |
| --- | --- | --- | --- |
| `exe_unit_tests` (the `src/main.zig` tree) | 1,980 | ~60s | Large by count (~30ms/test average), not by any single pathological case. |
| `crypto_mod` tests (`test-crypto`'s core) | 59 | ~58s | Dominated by one case (below). |
| `tls13_backend_tests.zig` (`test-tls`'s record-mode handshake suite) | 283 | ~46s | Dominated by one case (below). |
| `quic_h3_udp_smoke.zig` (real-socket UDP smoke, part of `test-quic`) | 24 | ~11s | Real loopback sockets + poll(2) timers; previously found unreliable under sandboxed/CI environments. |
| `tls_core` tests (`test-tls`'s main suite) | 755 | ~11s | Large by count, unremarkable average. |
| `session_cache.zig` + `session_cache_persistence.zig` | 494 | ~14s combined | |

Two single test cases account for **~42s** of the full suite's wall time by
themselves -- RSA-3072/4096 key generation and signing, which is inherently
expensive arithmetic (large-modulus `std.crypto.ff` modular exponentiation)
that gets no optimization in a Debug build:

- `crypto/rsa.zig`: `"RSA-3072 and RSA-4096 private keys sign messages the
  native verifier accepts"` -- **~21s** alone (confirmed via a temporary
  `-Dcrypto-test-filter`-equivalent rebuild isolating just this case).
- `tls/tls13_backend_tests.zig`: `"#335 RSA-3072 and RSA-4096
  CertificateVerify signatures fit the TLS engine buffer"` -- **~21s** alone,
  via the same large keygen+sign path reached through a real TLS handshake.
- A second, smaller contributor in `crypto/rsa.zig`: `"RSA private-key DER
  rejects every component mutation that breaks a required relationship"` --
  **~11s** (7 full-modulus validations against a 2048-bit key per mutation
  case).

These are genuine correctness regressions, not spins or bugs, so they are not
deleted. `zig build test-fast` sets `TARDIGRADE_TEST_FAST=1`, which the first
two tests above check (via `std.c.getenv`, matching the existing
`TARDIGRADE_SOAK_HEAVY` convention in `tests/http3_soak.zig`) to skip just
themselves; every other invocation -- `zig build test`, `zig build
test-crypto`, `zig build test-tls`, CI -- leaves the variable unset and still
runs them. `test-fast` also omits, entirely (each already has its own
dedicated/standalone step, unaffected, and the default `test` step still runs
all four):

- `test-quic`'s real-socket UDP smoke (`quic_h3_udp_smoke.zig`, ~11s) --
  sandbox/CI-unreliable per the note above.
- The H3 soak (`tests/http3_soak.zig`) -- an explicit soak workload, not a
  bounded regression test.
- `test-crypto-openssl` -- spawns a real `openssl`/EVP-oracle subprocess per
  case; differential/interop tooling, not a pure-Zig regression.
- `test-crypto-bench`'s correctness smoke -- a benchmark workload's sanity
  check, not a regression test; `bench-crypto` runs the full suite.

### Running one named test without the whole population

```bash
# Select a single named test/subsystem from exe_unit_tests (the src/main.zig
# test tree, ~2000 cases) without compiling a second test runner and without
# running the rest of the population:
zig build test-exe-filtered -Dexe-test-filter="jwt"
```

`-Dexe-test-filter` is required for this step -- omitting it fails the build
rather than silently running (or silently skipping) everything. A filter that
matches zero named tests also fails the build, via a small checked-in static
check (`scripts/check_exe_test_filter_matches.zig`): Zig's own test filtering
has no "zero tests matched" failure mode on its own (`src/main.zig`'s always-
present unnamed `refAllDecls` smoke test still runs and still reports
success), so a stale or typo'd filter would otherwise pass silently.

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
filter, e.g. `zig build test-integration -Dintegration-test-filter="failure: client abort"`.

## Build options

| Flag | Default | Purpose |
|---|---|---|
| `-Doptimize=ReleaseFast` | `Debug` | Production-speed build |
| `-Doptimize=ReleaseSafe` | `Debug` | Release with safety checks |
| `-Dstatic-executable=true` | `false` | Fully static binary |
| `-Dprefer-static-system-libs=true` | `false` | Prefer static linkage for test-only system-library oracle helpers |
| `-Drequire-static-system-libs=true` | `false` | Fail if those requested static test-helper libraries are unavailable |
| `-Dversion=x.y.z` | `dev` | Embed a version string in the binary |

## Common workflows

```bash
# Debug build and run
zig build run

# Release build
zig build -Doptimize=ReleaseFast

# Static production binary (Linux; no OpenSSL dependency)
zig build -Dstatic-executable=true -Drequire-static-system-libs=true

# Run a single named test/subsystem out of exe_unit_tests (the src/main.zig
# test tree) without running the whole ~2000-case population (#944). Note:
# `zig build test -- --test-filter ...` does *not* do this -- `--` arguments
# are only forwarded to `zig build run`, not to any test step.
zig build test-exe-filtered -Dexe-test-filter="jwt"

# Per-test timeout (Zig build-runner flag): bounds every test in whichever
# step(s) you run, terminating (not hanging) one that spins past the deadline.
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
