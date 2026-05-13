# Release Checklist

Use this checklist before tagging and distributing a Tardigrade release.

## Build and Validation

- [ ] `zig fmt --check build.zig src/ tests/`
- [ ] `zig build test --summary all --error-style verbose`
- [ ] `zig build test-integration`

## Performance

- [ ] Capture the release baseline JSON with `./benchmarks/release-baseline.sh` on the homelab perf target, including the default `64 KiB` and `256 KiB` payload scenarios
- [ ] Compare against the previous saved baseline JSON
- [ ] Generate the markdown report for the new baseline
- [ ] Refresh the README benchmark report block from the saved baseline data
- [ ] If the homelab target was unavailable and a local fallback run was used, record that exception explicitly and do not treat it as the canonical release number
- [ ] Record any known benchmark caveats in the release notes

## Artifacts

- [ ] Confirm `scripts/release-metadata.sh` resolves the intended tag/version
- [ ] Verify release packaging paths and checksums
- [ ] Confirm changelog entries for operator-visible changes are complete
