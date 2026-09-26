# Release Checklist

Use this checklist before tagging and distributing a Tardigrade release.

## Gate Cadence

Use the existing commands and workflows in this section; do not add duplicate
release gates for the same evidence.

### Required Per PR

- `zig fmt --check build.zig src/ tests/`
- `zig build test --summary all --error-style verbose`
- `zig build test-security-corpus --summary all --error-style verbose` on the
  Ubuntu unit-test leg
- `zig build test-integration -Dtls-profile=appliance --summary all
  --error-style verbose` on the Linux appliance-profile legs
- CI packaging smokes: `./scripts/test-install.sh`,
  `./scripts/test-deb-package.sh`, `./scripts/test-rpm-package.sh`,
  `./scripts/test-docker-image.sh`, and generated/local Homebrew formula
  smoke through `./scripts/test-homebrew-formula.sh`
- Reduced TLS conformance in `ci.yml`: `scripts/interop/run-tls-interop.sh
  --profile ci`
- Deterministic lifecycle/reload/resource regressions already wired through
  unit, integration, native TLS reuse, resumption/restart, and release-sweep
  harness owners. Keep longer torture or soak runs manual unless the owning
  workflow documents a scheduled cadence.

### Required On Main

- CI runs in smoke or full mode chosen from `CHANGELOG.md`; a new numbered
  release heading selects **full** (see [CI.md](CI.md)). Require only the
  `CI result` check in branch protection.
- The unprofiled Linux integration job (`zig build test-integration --summary
  all`) runs in both modes.
- `.github/workflows/release.yml` is triggered after successful `main` CI or
  by manual dispatch, and it skips publication if the selected tag already
  exists for another commit.

### Required For Release Candidate

- `.github/workflows/release.yml` must build Linux and Darwin archives from
  the selected release SHA with `-Dcpu=baseline`, the default general native
  TLS profile, and Linux `*-linux-gnu.2.28` targets.
- The same workflow must package DEB/RPM assets from those audited release
  binaries, verify native dependency inventories, generate checksums/SBOMs,
  and attest provenance.
- The `verify-linux-archive` job must execute the exact
  `tardigrade-linux-x86_64.tar.gz` candidate on `ubuntu:22.04` and
  `rockylinux:9` before publication.
- Render the Homebrew formula from the release tag, validate it with
  `ruby -c`, run the release-backed Homebrew formula smoke, and update the
  public tap only after the referenced release assets are visible.
- For any HTTP/2 or HTTP/3 release behavior change, run the #677 release
  sweep (`scripts/run-http-release-sweep.sh` and
  `scripts/http-release-blackbox-677.sh`) against a release candidate or
  installed artifact. This is correctness/release evidence, not #389
  performance or stable-promotion ownership.
- For any HTTP/2 or HTTP/3 support-status change, update
  [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md), reconcile the operator limitations in
  [CONFIGURATION.md](CONFIGURATION.md) and [HTTP3_ROLLOUT.md](HTTP3_ROLLOUT.md),
  and retain the promotion evidence map following
  [HTTP2_HTTP3_STABLE_PROMOTION_389.md](HTTP2_HTTP3_STABLE_PROMOTION_389.md).
- Run the full TLS conformance/interop matrix
  (`scripts/interop/run-tls-interop.sh --profile full`) with OpenSSL and
  GnuTLS peer tooling installed, or use the manual
  `TLS conformance/interop hardening (full profile)` workflow for the release
  candidate SHA. Record zero FAIL and zero unexplained SKIP rows following
  [TLS_INTEROP_HARDENING_674.md](TLS_INTEROP_HARDENING_674.md).

### Post-Release Smoke

- After publishing, run the black-box public tap smoke with
  `./scripts/test-public-homebrew-tap.sh --install-mode qualified
  --expected-version X.Y.Z` and `./scripts/test-public-homebrew-tap.sh
  --install-mode tap-short --expected-version X.Y.Z`, or run the manual
  `Public Homebrew Smoke` workflow with the expected version input.
- Exercise `scripts/install.sh` against the published release on each newly
  supported platform or whenever install behavior changes.

### Scheduled / Weekly

- `Public Homebrew Smoke` runs weekly across macOS Intel, macOS Apple Silicon,
  Linux x86_64, Linux arm64, and both supported install modes.
- `TLS conformance/interop hardening (full profile)` runs weekly and manually.
  It runs the full OpenSSL + GnuTLS matrix plus the pinned external H3 peer and
  requires zero FAIL and zero unexplained SKIP.
- `Resumption interop/restart/soak (heavy)` runs weekly and manually. It
  scales the existing resumption, restart, and soak case-ID suite with
  `TARDIGRADE_SOAK_HEAVY=1`.

### Manual Security Evidence

- Repeat F-05 live native TLS evidence when the listener, TLS defaults,
  certificate loading, ALPN behavior, or scanner-facing TLS surface changes.
  Record sanitized results following
  [F05_LIVE_TLS_SURFACE_672.md](F05_LIVE_TLS_SURFACE_672.md).
- Repeat F-06 auth/framing evidence when request parsing, proxy framing,
  auth/session enforcement, trusted identity handling, or hostile upstream
  response handling changes. Keep the exact-byte harness and upstream-hit-log
  assertions authoritative.
- Scanner or pentest findings are triage inputs. Close actionable findings
  only after they become deterministic Tardigrade regressions or are explicitly
  dispositioned.

### Manual / On-Demand Deep Campaign

- #675 owns the sustained coverage-guided fuzz campaign. Until it completes or
  is explicitly dispositioned, keep deterministic seed/corpus replay in normal
  CI, keep 10M/50M fuzz campaigns manual/on-demand, and keep 100M+/1G
  saturation follow-up manual unless measured cost/effectiveness justifies a
  scheduled subset.
- After #675 records real runtime/effectiveness data, update this section with
  any selected scheduled 10M/50M fuzz targets and leave 100M+/1G runs
  manual/on-demand by default.
- Do not add #593/Proxmox competitive-performance rows to normal
  hardening/release CI. Performance baselines remain under the performance
  section and their owning issues.

## Hardening Evidence Convention

Each durable release, hardening, fuzz, interop, or pentest evidence record
should identify:

- release tag or candidate id
- source commit SHA
- artifact or package path
- artifact SHA-256 where applicable
- Tardigrade version, profile, and backend
- OS and architecture
- Zig version
- external peer or tool versions
- exact command
- PASS / FAIL / SKIP plus reason
- finding, fix issue, or PR

Sensitive material must not be published: private keys, TLS keylogs or traffic
secrets, ticket keys, reusable session material, production auth tokens, and
customer traffic stay out of public docs and committed artifacts. Sanitized
synthetic transcripts, hashes, versions, counters, public certificate metadata,
and bounded resource samples are acceptable. Large raw output can remain in
Actions artifacts, issue attachments, or release artifacts; do not commit bulky
transient evidence solely for archival purposes.

## Build and Validation

- [ ] `zig fmt --check build.zig src/ tests/`
- [ ] `zig build test --summary all --error-style verbose`
- [ ] `zig build test-security-corpus --summary all --error-style verbose`
- [ ] `zig build test-integration --summary all --error-style verbose`
- [ ] For any HTTP/2 or HTTP/3 support-status change, complete the closeout
      evidence contract in
      [HTTP2_HTTP3_STABLE_PROMOTION_389.md](HTTP2_HTTP3_STABLE_PROMOTION_389.md)
      and, for HTTP/3 specifically,
      [HTTP3_VALIDATION_EVIDENCE.md](HTTP3_VALIDATION_EVIDENCE.md)
- [ ] Run the full TLS conformance/interop matrix
      (`scripts/interop/run-tls-interop.sh --profile full`) with both OpenSSL
      and GnuTLS peer tooling installed and record a fresh hardening result
      for zero unexplained FAIL/SKIP rows, following the pattern in
      [TLS_INTEROP_HARDENING_674.md](TLS_INTEROP_HARDENING_674.md)

## Performance

- [ ] Capture the release baseline JSON with `./benchmarks/release-baseline.sh` on a stable, dedicated benchmark target, including the default `64 KiB` and `256 KiB` payload scenarios
- [ ] For HTTP/3 release evidence, run the existing H3 matrix on a dedicated
      host with a genuinely QUIC-capable client and retain the client
      capability proof, scenario-local QUIC deltas, soak results, and interop
      rerun summary
- [ ] Compare against the previous saved baseline JSON
- [ ] Generate the markdown report for the new baseline
- [ ] Refresh the generated benchmark report block in `benchmarks/README.md` from the saved baseline data
- [ ] If a dedicated target was unavailable and a local fallback run was used, record that exception explicitly and do not treat it as the canonical release number
- [ ] Record any known benchmark caveats in the release notes

## Artifacts

- [ ] Confirm `scripts/release-metadata.sh` resolves the intended tag/version
- [ ] Update `docs/SUPPORT_MATRIX.md` when public behavior or maturity claims changed
- [ ] Run `./scripts/test-install.sh` against a ReleaseFast native build (`-Dtls-profile=general`, the default)
- [ ] Render the Homebrew formula from this release tag with
      `./scripts/update-homebrew-formula.sh --tag <tag>`,
      run `ruby -c packaging/homebrew/tardigrade.rb`, and run
      `./scripts/test-homebrew-release-formula.sh` plus
      `./scripts/test-homebrew-formula.sh` on each Homebrew environment the
      release honestly supports
- [ ] Run `./scripts/test-deb-package.sh` on a Linux host with Docker
- [ ] Run `./scripts/test-rpm-package.sh` on a Linux host with Docker
- [ ] Verify release packaging paths and checksums, including the Linux
      (`tardigrade-linux-x86_64.tar.gz`, `tardigrade-linux-aarch64.tar.gz`) and
      Darwin (`tardigrade-darwin-x86_64.tar.gz`,
      `tardigrade-darwin-arm64.tar.gz`) archives plus published `.deb`/`.rpm`
      assets
- [ ] Verify every published archive's `dependency-inventory-*.json` reports
      `profile=general` (or `appliance`), `reported_backend=native`,
      `links_openssl=false`, `status=pass`, and no dynamic dependency outside
      the documented OS/runtime substrate allowlist
- [ ] Verify published DEB/RPM/container metadata does not declare or install a
      foreign product implementation dependency for Tardigrade runtime behavior
- [ ] Copy the rendered Homebrew formula into `Bare-Systems/homebrew-tap` with
      `--tap-dir`, review the tap diff, and publish it only after the
      referenced release assets are visible and the install smoke passes.
      `homebrew-tap/README.md` is tap-owned; update it only when public
      support policy or install instructions change.
- [ ] After the public tap update is pushed, run the black-box public-tap smoke
      with `./scripts/test-public-homebrew-tap.sh --install-mode qualified --expected-version X.Y.Z`
      and `./scripts/test-public-homebrew-tap.sh --install-mode tap-short --expected-version X.Y.Z`,
      or run the manual `Public Homebrew Smoke` workflow with the expected
      version input.
- [ ] Verify both Darwin archives have matching SPDX SBOMs and
      `dependency-inventory-*.json` artifacts, and verify archive provenance
      with `gh attestation verify <archive> --repo Bare-Systems/Tardigrade`
- [ ] On the first release containing #463, exercise `scripts/install.sh`
      against the published release on Intel and Apple Silicon macOS **with no
      OpenSSL installed on the host** (no shipping profile links it after
      #649), then verify `tardi version`,
      the `tardigrade -> tardi` compatibility alias, and a minimal real
      startup/request path from the installed artifact
- [ ] Close #463 only after the first published Darwin assets, checksums,
      inventories, SBOMs, attestations, native-only linkage, installer path,
      alias, and runtime smoke all verify on both macOS architectures
- [ ] Note any Homebrew platform limitation in the release notes; do not
      advertise macOS Homebrew until the published release includes Darwin
      archives and the tap formula references their real checksums
- [ ] Confirm changelog entries for operator-visible changes are complete

## Branch Hygiene

- [ ] After each PR merges (squash merge is standard for this repo), delete its head branch. Prefer enabling "Automatically delete head branches" in repo settings so this happens without a manual step.
- [ ] Periodically (at least once per release cycle), diff open remote branches against merged PRs and closed issues; delete or archive any branch whose work already landed on `main` or was abandoned in favor of a different branch.
- [ ] Never delete a branch backing an open PR, or the branch currently checked out for active work.
