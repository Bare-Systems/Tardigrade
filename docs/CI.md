# CI: smoke vs full validation

CI runs in exactly **two modes**. `CHANGELOG.md` picks the mode automatically,
so ordinary unreleased work gets fast feedback and promoting a numbered
release runs the complete suite. There is no third tier and no label-driven
policy.

## Mode selection

`scripts/ci-mode.sh --base <ref> --head <ref> [--override auto|smoke|full]`
prints `smoke` or `full` (diagnostics on stderr, exit 2 on any error). It uses
only git, never the GitHub API, and runs identically locally.

| Event | Result |
| --- | --- |
| PR, no changelog change / edits only under `## [Unreleased]` | `smoke` |
| PR adds a numbered heading, e.g. `## [0.7.4] - YYYY-MM-DD`, not present at the merge base | `full` |
| Push to `main` | same comparison, `before` vs `after`; release promotion = `full` |
| `workflow_dispatch` `mode=smoke` / `mode=full` | that mode, on any ref |
| `workflow_dispatch` `mode=auto` | same detector against `origin/main` |

The comparison is the changelog at the **merge base** versus at head, so a
release that landed on `main` after the PR branched is not counted as new,
pre-existing numbered sections and a retained empty `[Unreleased]` heading
never trigger `full`, and re-dating an existing section does not either.
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
Linux unit tests + hostile-HTTP corpus + `tardi init` validation, Linux
native-TLS-listener integration, the default-profile live-process integration
suite (`Integration tests`), example-config validation, and Security
(gitleaks, Trivy, zizmor) plus Dependency review on PRs.

**Full** = smoke, plus everything else: unit / native-TLS tests on
`ubuntu-24.04-arm` and `macos-14`, appliance-profile tests (all OSes), the
Debug/ReleaseSafe/ReleaseFast build matrix, macOS binary audit, PKI
differential, packaging (DEB/RPM/Docker/install), Homebrew formula smoke,
performance smoke, crypto benchmarks, H3 resumption/0-RTT peer interop, the
TLS interop/conformance matrix, Linux/Darwin release-smoke, and the native TLS
reuse soak.

`ci.yml` calls the substantive jobs from `linux-release-smoke.yml`,
`darwin-release-smoke.yml`, and `native-tls-reuse-soak.yml` in full mode, so
their success is required by `CI result`. Those workflows retain their PR path
filters and manual dispatches for focused standalone runs. Scheduled and
manual-only workflows (`h3-benchmark`, `pki-differential`, `resumption-soak`,
`rtt-streaming-regression`, `tls-conformance-full`, `public-homebrew-smoke`,
`scorecard`, `release`) are unchanged. `release.yml` auto-promotes only a
successful **push-originated** full CI release promotion on `main`; a manual
smoke CI run cannot publish artifacts.

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

## Cost comparison (PR touching `src/`)

| Run | Result | Wall clock | Billed runner minutes |
| --- | --- | --- | --- |
| [Smoke PR run 37504003444](https://github.com/Bare-Systems/Tardigrade/actions/runs/37504003444) | success | 8m07s | unavailable |
| [Manual full run 37503993443](https://github.com/Bare-Systems/Tardigrade/actions/runs/37503993443) | failed | 18m41s | unavailable |

The full run launched and completed every full-only/reusable release-smoke and
soak suite, but its aggregate failed because the existing best-effort native-H2
integration test did not complete a request; this is not a passing full-mode
baseline. GitHub's run-timing API returned zero billed milliseconds for both
runs, so billed minutes were not available. Repeat the full measurement after
that unrelated integration failure is green before treating it as release
evidence.

The workflow definitions contain approximately 11 smoke jobs (plus two trivial
mode jobs) and approximately 41 full jobs including matrix legs and release
smoke workflows. Smoke omits cross-OS/arch legs, the 9-way build matrix,
packaging, interop, and performance checks; full includes them.

## Failure-behaviour checks

`scripts/test-ci-mode.sh` exercises the gate with a failing smoke job (fails), a
failing full-only job (fails), full-only jobs skipped in smoke (passes), and a
skipped full-only job in full mode (fails).
