# Upgrades

## Current Priority

1. GitHub Actions reliability and release automation
   - Ensure `CI` validates both unit and integration paths on pull requests and `main`.
   - Publish versioned GitHub releases directly from the top `CHANGELOG.md` entry on `main`.
   - Ship downloadable release archives for Linux x86_64, macOS x86_64, and macOS arm64 with checksums.

## Decisions

- Release source of truth: `CHANGELOG.md`
  - The top semantic-version heading is the release version. This keeps branch planning, release notes, and published tags aligned instead of maintaining a separate version file just for GitHub Actions.
- Tag creation point: `main` push
  - The release workflow creates the missing `vX.Y.Z` tag only when that version is not already tagged. If the tag already points at an older commit, the workflow skips publishing to avoid silently rewriting an existing release.
- Release packaging format: `.tar.gz`
  - The existing installer already downloads `tardigrade-<platform>.tar.gz`, so the workflow keeps that archive format and adds a checksum manifest instead of forcing an installer-breaking format change.
- Embedded runtime version: build-time injection
  - Release builds pass the semantic version into Zig build options so `tardigrade version` and the `Server` header match the published release, while local development builds default to `dev`.
