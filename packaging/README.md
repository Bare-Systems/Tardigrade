# Tardigrade Packaging

Native packaging artifacts for Tardigrade. See the [main README](../README.md#install)
for the quick-start install path; this document covers every packaging
format in detail, including what is actually built and published today
versus what is a local-build-only tool.

## Current status

| Format | Status | Notes |
| --- | --- | --- |
| Linux release archives (`.tar.gz`, x86_64/aarch64) | **Supported, published** | Built and attached to every GitHub release by `.github/workflows/release.yml`, alongside `install.sh`, `tardigrade-checksums.txt`, and per-arch SPDX SBOMs. |
| macOS release archives (`.tar.gz`, darwin x86_64/arm64) | **Planned, not published** | CI builds and tests Tardigrade on `macos-14`, but the release workflow's build matrix only packages Linux. `install.sh` and the Homebrew formula already expect `tardigrade-darwin-*.tar.gz` assets that do not yet exist. |
| DEB (`packaging/deb/build.sh`) | **Supported as a local builder, not published** | Produces a working `.deb` from a pre-built binary; smoke-tested on every PR/push via the `packaging-smoke` CI job (`scripts/test-deb-package.sh`). No `.deb` is attached to GitHub releases. |
| RPM (`packaging/rpm/build.sh`) | **Supported as a local builder, not published** | Same status as DEB: builds and smoke-tests cleanly (`scripts/test-rpm-package.sh`), not published as a release asset. |
| systemd unit (`packaging/systemd/tardigrade.service`) | **Supported** | Installed and exercised end-to-end by both the DEB and RPM smoke tests. |
| launchd plist (`packaging/launchd/io.baresystems.tardigrade.plist`) | **Unverified template** | Ships as a template for macOS host-native installs; there is no macOS packaging pipeline or smoke test exercising it. |
| Homebrew (`packaging/homebrew/tardigrade.rb`) | **Formula present, tap not published, macOS blocked** | The `on_linux` blocks can resolve once real release checksums are filled in; the `on_macos` blocks cannot resolve until macOS archives are published (see above). No `Bare-Systems/homebrew-tap` repo exists yet. |
| Docker / OCI image | **Not implemented** | No `Dockerfile` or container-publishing workflow exists in this repository. |

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

This currently only resolves for Linux (`x86_64`/`aarch64`); see "Current status" above.

## DEB (Debian / Ubuntu)

Build a `.deb` package from a pre-built binary:

```bash
# 1. Build the binary first (cross-compile for the target arch as needed)
zig build -Doptimize=ReleaseFast

# 2. Build the DEB
./packaging/deb/build.sh --version 0.50 --arch amd64

# Output: dist/tardigrade_0.50_amd64.deb
```

Install:
```bash
sudo apt install ./dist/tardigrade_0.50_amd64.deb
sudo systemctl enable --now tardigrade
```

The DEB package:
- Installs the binary to `/usr/bin/tardi`
- Installs a starter config at `/etc/tardigrade/tardigrade.conf`
- Creates a `tardigrade` system user
- Installs a systemd service unit at `/lib/systemd/system/tardigrade.service`
- Installs an env config template at `/etc/tardigrade/tardigrade.env` (mode 0640, owned by `root:tardigrade`)
- Installs a logrotate config at `/etc/logrotate.d/tardigrade`
- Creates `/var/lib/tardigrade` for the service working directory

## RPM (RHEL / Fedora / AlmaLinux)

```bash
# 1. Install prerequisites
dnf install rpm-build

# 2. Build the binary
zig build -Doptimize=ReleaseFast

# 3. Build the RPM
./packaging/rpm/build.sh --version 0.50

# Output: dist/tardigrade-0.50-1.x86_64.rpm
```

Install:
```bash
sudo rpm -i dist/tardigrade-0.50-1.x86_64.rpm
sudo systemctl enable --now tardigrade
```

## Homebrew (macOS and Linux)

The `on_macos` blocks in this formula cannot resolve today: the release
workflow does not build or publish `tardigrade-darwin-*.tar.gz` archives (see
"Current status" above). The `on_linux` blocks reference archives that are
published, so a Linux install can work once real checksums are filled in.

The formula at `packaging/homebrew/tardigrade.rb` can be installed locally:

```bash
brew install --formula packaging/homebrew/tardigrade.rb
```

To use the formula via a Homebrew tap:

```bash
brew tap Bare-Systems/tap
brew install tardigrade
```

> **Note**: The tap at `Bare-Systems/homebrew-tap` is not yet published. The formula is included here as the canonical source. Copy it to `Formula/tardigrade.rb` in the tap repo and update the `sha256` values from the release checksums file on each release.

### Updating the formula for a new release

1. Download the release checksums: `tardigrade-checksums.txt` from the release page.
2. Update `version` in the formula.
3. Replace the four `REPLACE_WITH_ACTUAL_SHA256_*` placeholders with the SHA-256 values from the checksums file.
4. Commit and push the formula to the tap repo.

## Service files

Pre-built service files for host-native installs:

| File | Purpose |
|---|---|
| [`systemd/tardigrade.service`](systemd/tardigrade.service) | systemd service unit (Linux) |
| [`launchd/io.baresystems.tardigrade.plist`](launchd/io.baresystems.tardigrade.plist) | launchd plist (macOS) — unverified, no macOS packaging pipeline exists yet |

## Related docs

- [Main README — Install](../README.md#install)
- [Release checklist](../docs/RELEASE_CHECKLIST.md)
- [Support matrix](../docs/SUPPORT_MATRIX.md)
