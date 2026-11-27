# CI: smoke vs full validation

CI runs in exactly **two modes**. `CHANGELOG.md` picks the mode automatically,
so ordinary unreleased work gets fast feedback and promoting a numbered
release runs the complete suite. There is no third tier and no label-driven
policy. (#944 added `zig build test-fast` as a bounded *local/agent*
iteration target -- see CONTRIBUTING.md's "Test performance" section; #945
wired it, and a curated live-process integration subset, into smoke mode
itself -- see "What each mode runs" below.)

## Mode selection

`scripts/ci-mode.sh --base <ref> --head <ref> [--override auto|smoke|full]`
prints `smoke` or `full` (diagnostics on stderr, exit 2 on any error). It uses
only git, never the GitHub API, and runs identically locally.

| Event | Result |
| --- | --- |
| PR, no changelog change / edits only under `## [Unreleased]` | `smoke` |
| PR adds a numbered heading, e.g. `## [0.7.4] - YYYY-MM-DD`, not present at the merge base | `full` |
| PR changes the top release to an untagged version | `full` (retries an interrupted release promotion) |
| Push to `main` | same comparison, `before` vs `after`; release promotion = `full` |
| `workflow_dispatch` `mode=smoke` / `mode=full` | that mode, on any ref |
| `workflow_dispatch` `mode=auto` | same detector against `origin/main` |
| Scheduled weekly run (`schedule`, Thursday 03:11 UTC on `main`) | always `full` (#945) -- independent of changelog state, so an unreleased `main` still gets periodic full-mode regression coverage between numbered releases |

The comparison is the changelog at the **merge base** versus at head, so a
release that landed on `main` after the PR branched is not counted as new,
pre-existing numbered sections and a retained empty `[Unreleased]` heading
never trigger `full`, and re-dating an existing section does not either. The
sole retry exception is changing the top release to a version without its
`vX.Y.Z` tag, which intentionally reruns the missed release promotion.
Ambiguous input (unresolvable refs, shallow clone, missing/empty/heading-less
changelog, invalid `--override`) **fails the run** instead of guessing
`smoke`. Try it locally:

```bash
scripts/ci-mode.sh --base origin/main --head HEAD
```

Tests for the detector and the required-result gate:

```bash
scripts/test-ci-mode.sh
```

## What each mode runs

**Smoke** (every PR / push without a release promotion): format, lint
(actionlint, shellcheck, detector tests), production dependency audit (Linux),
Linux `zig build test-fast` (#944's bounded gate, not the full unit suite) +
hostile-HTTP corpus + `tardi init` validation, Linux native-TLS-listener
integration, the **curated** live-process integration subset
(`test-integration-smoke`: startup/health, proxy round-trip, auth-denied
origin side effect, invalid config/reload, auth-gated cache isolation, one
native H1/H2/TLS boundary case) instead of the full suite, the dedicated
#863 real-process H2 transport validation gate (`test-integration-h2-transport-smoke
-Dh2-test-hook` -- long-lived sessions, REST load, fault injection, and
resource settle, with its evidence JSON uploaded as the
`h2-transport-validation` artifact; `-Dh2-test-hook` compiles its test-only
session-attach hook into the binary and is never set for release builds),
the focused ACME-experimental issuance case
(`test-integration-acme-smoke`) instead of its full matrix, example-config
validation, and Security (gitleaks, Trivy, zizmor) plus Dependency review on
PRs (#945).

**Full** = smoke, but with `test`/`test-integration`/
`test-integration -Dacme-experimental` run unfiltered instead of the smoke
subsets above, plus everything else: unit / native-TLS tests on
`ubuntu-24.04-arm` and `macos-15`, appliance-profile tests (all OSes), the
Debug/ReleaseSafe/ReleaseFast build matrix, macOS binary audit, PKI
differential, packaging (DEB/RPM/Docker/install), Homebrew formula smoke,
performance smoke, crypto benchmarks, H3 resumption/0-RTT peer interop, the
TLS interop/conformance matrix, Linux/Darwin release-smoke, and the native TLS
reuse soak. Full also now runs unattended once a week against `main` (see
"Mode selection" above), not only at release promotion or explicit dispatch.

`ci.yml` calls the substantive jobs from `linux-release-smoke.yml`,
`darwin-release-smoke.yml`, and `native-tls-reuse-soak.yml` in full mode, so
their success is required by `CI result`. Those workflows retain their PR path
filters and manual dispatches for focused standalone runs. Scheduled and
manual-only workflows (`h3-benchmark`, `pki-differential`, `resumption-soak`,
`rtt-streaming-regression`, `tls-conformance-full`, `public-homebrew-smoke`,
`scorecard`) are unchanged. Separately, `release.yml` validates the recorded
CI decision and auto-promotes only a successful **push-originated** full CI
release promotion on `main`; a valid smoke decision cleanly skips publication,
and a manual smoke CI run cannot publish artifacts.

## Required check

Require exactly one status in branch protection: **`CI result`** (job
`ci-result` of workflow `CI`). `scripts/ci-gate.sh` makes it pass only when
every smoke job succeeded and, in full mode, every full-only job succeeded too;
in smoke mode the full-only jobs are expected to be skipped. A failed, cancelled
or missing job, or a skipped full-only job in full mode, fails it.

**Owner action (repo settings, cannot be done from a PR):** in the `main`
branch protection / ruleset, remove the old per-job required checks
(`Format`, `Lint`, `Test (…)`, `Test appliance profile (…)`, `Build (…, …)`,
`Production dependency audit (Linux)`, etc.) and require `CI result` only.
Job names such as `Test (${{ matrix.os }})` no longer exist for every OS in
smoke mode, so leaving them required would block PRs forever.

## Manual runs

```bash
gh workflow run ci.yml --ref <branch> -f mode=full     # full validation, no changelog edit needed
gh workflow run ci.yml --ref <branch> -f mode=smoke
gh workflow run ci.yml --ref <branch> -f mode=auto
```

The full dispatch calls every full suite listed above. Obsolete runs of the
same ref are cancelled (`cancel-in-progress`).

## Zig toolchain provisioning

All workflows that build from source use the shared composite action
`.github/actions/setup-zig`. It restores the **complete official Zig 0.16.0
distribution archive** before installation. The archive contains the compiler,
standard library, headers, and runtime files; caching only the executable would
not provide a working toolchain. Keeping the upstream `.tar.xz` avoids expanding
and recompressing thousands of files in the Actions cache. Existing compilation
caches (`.zig-cache` and `~/.cache/zig`) remain separate.

The exact cache key is
`zig-toolchain-v1-<version>-<runner.os>-<runner.arch>`, with no prefix matches or
cross-platform restores. Linux and macOS support both x86_64 and ARM64. The
installer verifies **every** archive, including restored cache hits, against the
reviewed SHA-256 pins in `scripts/zig-checksums.txt`, sourced from the
[official Zig download index](https://ziglang.org/download/index.json).
It extracts into a temporary directory, checks `zig version`, then replaces the
installation and adds it to PATH. Re-extraction also repairs missing or modified
files from an earlier local installation. Downloads are bounded by connection,
transfer, and low-speed timeouts, with one retry per source. Partial downloads
and failed extractions are cleaned up. A corrupt cached archive is discarded and
downloaded again; if an immutable Actions cache entry is corrupt, delete that
specific key in GitHub's cache UI to prevent repeated downloads.

### Fallback mirrors and Cloudflare R2

Set the repository Actions **variable** `ZIG_DOWNLOAD_MIRRORS` to one HTTPS base
URL per line, or supply the composite action's `mirrors` input. The installer
tries `https://ziglang.org/download` first, then the configured mirrors in order
after a failed download or checksum mismatch. Every source uses the same pinned
checksum; no checksum is downloaded at runtime. A mirror must serve unmodified
official archives at `BASE_URL/VERSION/ARCHIVE`, for example:

```text
https://zig-mirror.example.com/0.16.0/zig-aarch64-macos-0.16.0.tar.xz
```

A public Cloudflare R2 bucket URL (`https://<bucket-public-id>.r2.dev`) or an R2
custom domain works with this layout. Upload the official archives under the
`0.16.0/` prefix and configure the base URL without the version or filename.
No mirror is enabled by default; CI does not need bucket credentials.

Local and Docker callers retain the existing interface and installation layout:

```bash
zig_dir=$(sh scripts/install-zig.sh 0.16.0) # default: .zig/0.16.0/zig-<target>-0.16.0
export PATH="$zig_dir:$PATH"
# Optional: ZIG_DOWNLOAD_MIRRORS=https://zig-mirror.example.com
# Optional install root: sh scripts/install-zig.sh 0.16.0 /opt/zig
```

The archive is retained under `<install-root>/downloads/` for verified offline
reuse. New versions require reviewed checksum pins before they can be installed.

### Provisioning benchmarks

Every invocation of the composite action reports `cold-cache` (Actions cache
miss) or `warm-cache` (exact hit), platform, and elapsed seconds in the job log
and step summary. Its `seconds` and `cache-hit` outputs are available to callers.
The timer includes cache restore, checksum verification, extraction, version
check, PATH setup, and cache save on a miss; it excludes later compilation and
tests. Saving immediately after installation makes the toolchain reusable even
when a later validation step fails. No benchmark jobs or matrix legs are added.

To collect hosted cold/warm measurements, dispatch the existing full CI workflow
on the same ref twice and compare the setup summaries on the same platform. An
exact key must be absent for the first run to be cold; cache scope and concurrent
jobs may produce a mixture of hits and misses. Full CI covers Linux x86_64/ARM64
and macOS ARM64; its Darwin release-smoke matrix also covers Intel macOS. The
warm-cache target is **under 15 seconds**, subject to runner/cache service
performance; the timing is reported rather than used as a flaky validation gate.

For an isolated local measurement with a fresh temporary install root:

```bash
python3 scripts/benchmark-zig-provisioning.py --warm-runs 3
python3 scripts/test-install-zig.py # offline regression tests, also in CI's lint job
```

Measured on 2026-11-27, macOS Darwin 25.3.0 ARM64, Zig 0.16.0:

| Scope | Cold | Warm samples | Warm median |
| --- | --- | --- | --- |
| Local installer, official download | 11.802s | 6.326s, 6.168s, 6.120s | 6.168s |

The local benchmark includes download on the cold run and SHA-256 verification,
extraction, and version check on every run. It excludes GitHub cache transfer and
step scheduling, so these numbers do **not** establish hosted runner latency.
Hosted cold/warm results remain to be collected after the action runs in GitHub.

## Cost comparison (PR touching `src/`)

| Run | Approx. jobs/legs | Result | Wall clock | Billed runner minutes |
| --- | --- | --- | --- | --- |
| [Before: heavyweight PR CI 36211172700](https://github.com/Bare-Systems/Tardigrade/actions/runs/36211172700) | ~38, including standalone heavy workflows | success | 32m05s | unavailable |
| [After: smoke PR CI 37506992600](https://github.com/Bare-Systems/Tardigrade/actions/runs/37506992600) | 11 + 2 mode jobs | success | 12m14s | unavailable |
| [Manual full run 37503993443](https://github.com/Bare-Systems/Tardigrade/actions/runs/37503993443) | ~41, including full matrix/reusable heavy workflows | failed | 18m41s | unavailable |

The full run launched and completed every full-only/reusable release-smoke and
soak suite, but its aggregate failed because the existing best-effort native-H2
integration test did not complete a request; this is not a passing full-mode
baseline. GitHub's run-timing API returned zero billed milliseconds for both
runs, so billed minutes were not available. Repeat the full measurement after
that unrelated integration failure is green before treating it as release
evidence.

The representative smoke path is 19m51s faster than the pre-change PR run,
or about **62% less wall-clock time**. Smoke omits cross-OS/arch legs, the
9-way build matrix, packaging, interop, and performance checks; full includes
them.

### #945: smoke-mode `test` / `test-integration` reduction

The table above measures whole-workflow wall clock; it predates #945's
changes to what the `test`, `integration-test`, and
`acme-experimental-integration` jobs run *inside* smoke mode. Local
reference-machine measurements (same machine/config as CONTRIBUTING.md's
"Test performance" baseline: Apple M4, 10 cores, macOS Darwin 25.3.0, Zig
0.16.0, `-Doptimize=Debug`, warm `.zig-cache`) for the two biggest smoke-mode
changes:

| Step | Before (unfiltered) | After (smoke target) |
| --- | --- | --- |
| Unit tests | `zig build test`: ~100-120s | `zig build test-fast`: ~95-120s (#944; unchanged by #945) |
| Live-process integration | `zig build test-integration`: ~4m20s warm | `zig build test-integration-smoke`: ~9.5s warm |

These are local wall-clock numbers, not a re-run of the GitHub Actions
workflow above; they demonstrate the magnitude of the per-job reduction
`test-integration-smoke` exists to produce, not a new whole-workflow
after-measurement. Re-measure the full workflow wall clock the same way the
table above was built once this PR lands on a representative PR, rather than
trusting these local numbers as CI evidence.

## Failure-behaviour checks

`scripts/test-ci-mode.sh` exercises the gate with a failing smoke job (fails), a
failing full-only job (fails), full-only jobs skipped in smoke (passes), and a
skipped full-only job in full mode (fails).
