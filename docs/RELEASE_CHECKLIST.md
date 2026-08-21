# Release Checklist

Use this checklist before tagging and distributing a Tardigrade release.

## Build and Validation

- [ ] `zig fmt --check build.zig src/ tests/`
- [ ] `zig build test --summary all --error-style verbose`
- [ ] `zig build test-integration`
- [ ] For any HTTP/3 support-status change, complete the closeout evidence
      contract in [HTTP3_VALIDATION_EVIDENCE.md](HTTP3_VALIDATION_EVIDENCE.md)

## Performance

- [ ] Capture the release baseline JSON with `./benchmarks/release-baseline.sh` on a stable, dedicated benchmark target, including the default `64 KiB` and `256 KiB` payload scenarios
- [ ] For HTTP/3 release evidence, run the existing H3 matrix on a dedicated
      host with a genuinely QUIC-capable client and retain the client
      capability proof, scenario-local QUIC deltas, soak results, and interop
      rerun summary
- [ ] Compare against the previous saved baseline JSON
- [ ] Generate the markdown report for the new baseline
- [ ] Refresh the README benchmark report block from the saved baseline data
- [ ] If a dedicated target was unavailable and a local fallback run was used, record that exception explicitly and do not treat it as the canonical release number
- [ ] Record any known benchmark caveats in the release notes

## Artifacts

- [ ] Confirm `scripts/release-metadata.sh` resolves the intended tag/version
- [ ] Update `docs/SUPPORT_MATRIX.md` when public behavior or maturity claims changed
- [ ] Run `./scripts/test-install.sh` against a ReleaseFast build
- [ ] Run `./scripts/test-deb-package.sh` on a Linux host with Docker
- [ ] Run `./scripts/test-rpm-package.sh` on a Linux host with Docker
- [ ] Verify release packaging paths and checksums, including the Linux
      (`tardigrade-linux-x86_64.tar.gz`, `tardigrade-linux-aarch64.tar.gz`) and
      Darwin (`tardigrade-darwin-x86_64.tar.gz`,
      `tardigrade-darwin-arm64.tar.gz`) archives plus published `.deb`/`.rpm`
      assets
- [ ] Verify both Darwin archives have matching SPDX SBOMs and
      `dependency-inventory-*.json` artifacts, and verify archive provenance
      with `gh attestation verify <archive> --repo Bare-Systems/Tardigrade`
- [ ] On the first release containing #463, exercise `scripts/install.sh`
      against the published release on Intel and Apple Silicon macOS with
      Homebrew `openssl@3` installed, then close #463 if the release assets,
      checksums, inventories, SBOMs, and attestations are all correct
- [ ] Note in the release that Homebrew tap publication and launchd lifecycle
      validation are separate from the raw Darwin archives until #466/#467
      close
- [ ] Confirm changelog entries for operator-visible changes are complete

## Branch Hygiene

- [ ] After each PR merges (squash merge is standard for this repo), delete its head branch. Prefer enabling "Automatically delete head branches" in repo settings so this happens without a manual step.
- [ ] Periodically (at least once per release cycle), diff open remote branches against merged PRs and closed issues; delete or archive any branch whose work already landed on `main` or was abandoned in favor of a different branch.
- [ ] Never delete a branch backing an open PR, or the branch currently checked out for active work.
