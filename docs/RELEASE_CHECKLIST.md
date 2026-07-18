# Release Checklist

Use this checklist before tagging and distributing a Tardigrade release.

## Build and Validation

- [ ] `zig fmt --check build.zig src/ tests/`
- [ ] `zig build test --summary all --error-style verbose`
- [ ] `zig build test-integration`

## Performance

- [ ] Capture the release baseline JSON with `./benchmarks/release-baseline.sh` on a stable, dedicated benchmark target, including the default `64 KiB` and `256 KiB` payload scenarios
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
- [ ] Verify release packaging paths and checksums, including the published
      `.deb`/`.rpm` assets
- [ ] Note in the release that Homebrew and launchd are not published release
      assets; the Linux `.tar.gz` archives, `.deb`/`.rpm` packages, `install.sh`,
      and checksums are
- [ ] Confirm changelog entries for operator-visible changes are complete

## Branch Hygiene

- [ ] After each PR merges (squash merge is standard for this repo), delete its head branch. Prefer enabling "Automatically delete head branches" in repo settings so this happens without a manual step.
- [ ] Periodically (at least once per release cycle), diff open remote branches against merged PRs and closed issues; delete or archive any branch whose work already landed on `main` or was abandoned in favor of a different branch.
- [ ] Never delete a branch backing an open PR, or the branch currently checked out for active work.
