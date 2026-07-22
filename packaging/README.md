# Tardigrade Packaging

Native packaging artifacts for Tardigrade. See the [main README](../README.md#install)
for the quick-start install path; this document covers every packaging
format in detail, including what is actually built and published today
versus what is a local-build-only tool.

## Current status

| Format | Status | Notes |
| --- | --- | --- |
| Linux release archives (`.tar.gz`, x86_64/aarch64) | **Supported, published** | Built and attached to every GitHub release by `.github/workflows/release.yml`, alongside `install.sh`, `tardigrade-checksums.txt`, and per-arch SPDX SBOMs. |
| macOS release archives (`.tar.gz`, darwin x86_64/arm64) | **Supported, published** | Built natively on `macos-15-intel` (x86_64) and `macos-15` (arm64) runners by the same release workflow, and attached to every GitHub release with per-arch SPDX SBOMs, dependency inventories, checksum entries, and provenance attestations. Requires `brew install openssl@3` on the host at runtime — see the Homebrew section below. |
| DEB (`packaging/deb/build.sh`) | **Supported, published** | Built for `amd64`/`arm64` from the same release binaries as the `.tar.gz` archives and attached to every GitHub release; also usable as a local builder (`packaging/deb/build.sh`). Smoke-tested on every PR/push via the `packaging-smoke` CI job (`scripts/test-deb-package.sh`). |
| RPM (`packaging/rpm/build.sh`) | **Supported, published** | Same treatment as DEB, for `x86_64`/`aarch64`. Smoke-tested via `scripts/test-rpm-package.sh`. Built from the same Ubuntu-runner binary as the archives — see the glibc compatibility note below if targeting an older RHEL-family release. |
| systemd unit (`packaging/systemd/tardigrade.service`) | **Supported** | Installed and exercised end-to-end by both the DEB and RPM smoke tests. |
| launchd plist (`packaging/launchd/io.baresystems.tardigrade.plist`) | **Unverified template** | Ships as a template for macOS host-native installs; the release workflow now publishes native Darwin archives, but nothing installs or smoke-tests this plist yet. |
| Homebrew (`packaging/homebrew/tardigrade.rb`) | **Formula present, not installable** | The release workflow now produces archive filenames that match what the `on_macos` blocks expect (`tardigrade-darwin-x86_64.tar.gz`, `tardigrade-darwin-arm64.tar.gz`), but the checked-in formula's *generated URLs* remain invalid: `version "0.50"` constructs a `v0.50` release URL rather than `v0.5.0`, the `sha256` values are still `REPLACE_WITH_ACTUAL_SHA256_*` placeholders, and the formula does not declare a Homebrew `openssl@3` dependency (required at runtime by the `general`-profile binary). Fixing the version/checksums/dependency and publishing to a tap are tracked separately in #466. No `Bare-Systems/homebrew-tap` repo exists yet. |
| Docker / OCI image | **Not implemented** | No `Dockerfile` or container-publishing workflow exists in this repository. |

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

This resolves for Linux (`x86_64`/`aarch64`) and macOS (`x86_64`/`arm64`); see
"Current status" above. On macOS, install the runtime OpenSSL dependency
first: `brew install openssl@3`.

## DEB (Debian / Ubuntu)

### Install from a release (recommended)

Every GitHub release publishes `tardigrade_<version>_amd64.deb` and
`tardigrade_<version>_arm64.deb` alongside the `.tar.gz` archives and
`tardigrade-checksums.txt`:

```bash
version=0.5.0   # match the release tag, without the leading "v"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade_${version}_amd64.deb"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-checksums.txt"
sha256sum --ignore-missing -c tardigrade-checksums.txt

sudo apt install ./tardigrade_${version}_amd64.deb
sudo systemctl enable --now tardigrade
```

Use `tardigrade_<version>_arm64.deb` on `arm64`/`aarch64` hosts.

### Build locally

Building your own `.deb` from a pre-built binary is still supported — useful
for architectures the release workflow doesn't cover, or a custom build:

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

### Install from a release (recommended)

Every GitHub release publishes `tardigrade-<version>-1.x86_64.rpm` and
`tardigrade-<version>-1.aarch64.rpm` alongside the `.tar.gz` archives and
`tardigrade-checksums.txt`:

```bash
version=0.5.0   # match the release tag, without the leading "v"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-${version}-1.x86_64.rpm"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-checksums.txt"
sha256sum --ignore-missing -c tardigrade-checksums.txt

sudo dnf install ./tardigrade-${version}-1.x86_64.rpm
sudo systemctl enable --now tardigrade
```

Use `tardigrade-<version>-1.aarch64.rpm` on `aarch64` hosts. `rpm -i` works
identically to `dnf install` for a local file.

> **glibc compatibility note**: the published `.rpm` is built from the same
> binary as the Linux `.tar.gz` archives, compiled on the `ubuntu-latest` /
> `ubuntu-24.04-arm` GitHub-hosted runners. It links dynamically against that
> runner's glibc. This is fine for current Fedora and RHEL 10+ family
> distros; it may be *too new* for RHEL 9 / Rocky 9 / AlmaLinux 9 (glibc
> 2.34), which would need a binary built on a matching older glibc. If that
> matters for your target, build locally instead (below) on a host with a
> compatible glibc.

### Build locally

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

Like the DEB package, the RPM installs a starter
`/etc/tardigrade/tardigrade.conf` and creates `/var/lib/tardigrade` (the
systemd unit's `WorkingDirectory`) on install, so `systemctl enable --now
tardigrade` works immediately after a fresh install.

## Upgrading

For both DEB and RPM installs, validate the new config before reloading or
restarting the service, so a bad edit surfaces before the running process is
affected:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
sudo systemctl reload tardigrade   # or: restart, if reload is insufficient
```

- DEB upgrades (`sudo apt install ./new-package.deb`) preserve
  `/etc/tardigrade/tardigrade.conf` and `/etc/tardigrade/tardigrade.env` as
  declared in `DEBIAN/conffiles`; `dpkg`/`apt` will prompt on conflicting
  local edits rather than silently overwriting them.
- RPM upgrades (`sudo rpm -U` or `dnf upgrade`) preserve
  `/etc/tardigrade/tardigrade.env` and `/etc/tardigrade/tardigrade.conf` via
  `%config(noreplace)`; an upgrade with local edits saves the new packaged
  version alongside as `.rpmnew` rather than overwriting your changes.
- For the plain release archive / `install.sh` path, replace the `tardi`
  binary, then run `tardi check <config>` against the existing config before
  restarting whatever process supervisor you are using.

## Homebrew (macOS and Linux)

The release workflow now builds and publishes `tardigrade-darwin-x86_64.tar.gz`
and `tardigrade-darwin-arm64.tar.gz` — the exact archive filenames the
`on_macos` blocks expect (see "Current status" above). That does **not**
mean the formula's generated URLs resolve, though: the formula is
**not installable yet**, because:

- `version "0.50"` constructs the release URL `.../v0.50/...`, not
  `.../v0.5.0/...` — it does not match this project's `vMAJOR.MINOR.PATCH`
  tag format.
- All four `sha256` values are still `REPLACE_WITH_ACTUAL_SHA256_*`
  placeholders.
- The formula does not declare a Homebrew `openssl@3` dependency, even
  though the `general`-profile binary it installs links OpenSSL at runtime.

Fixing the version string, filling in real checksums per release, declaring
the `openssl@3` dependency, and publishing to a tap are all tracked
separately in #466 and are out of scope for the archive pipeline itself.

The formula at `packaging/homebrew/tardigrade.rb` can be installed locally
once #466 lands:

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

## macOS Gatekeeper / unsigned binary note

The Darwin archives are **not code-signed, hardened-runtime, or notarized**.
`tardi`/`tardigrade` extracted from `tardigrade-darwin-x86_64.tar.gz` or
`tardigrade-darwin-arm64.tar.gz` will carry a `com.apple.quarantine` extended
attribute if downloaded through a browser (curl/`install.sh` downloads are
not quarantined), and Gatekeeper will refuse to run a quarantined,
unsigned binary by default. If you hit that, either download via
`install.sh`/`curl` (recommended) or clear the attribute yourself after
verifying the checksum:

```bash
xattr -d com.apple.quarantine ./tardi
```

This is a known, intentional distribution gap for the initial archives — see
"Out of scope" in #463. Code signing, hardened runtime, and notarization are
not yet implemented and would need a separate issue before Gatekeeper
behavior can be part of the supported install contract.

## Service files

Pre-built service files for host-native installs:

| File | Purpose |
|---|---|
| [`systemd/tardigrade.service`](systemd/tardigrade.service) | systemd service unit (Linux) |
| [`launchd/io.baresystems.tardigrade.plist`](launchd/io.baresystems.tardigrade.plist) | launchd plist (macOS) — unverified; the release workflow now publishes native Darwin archives, but nothing installs or smoke-tests this plist yet |

## Related docs

- [Main README — Install](../README.md#install)
- [Release checklist](../docs/RELEASE_CHECKLIST.md)
- [Support matrix](../docs/SUPPORT_MATRIX.md)
