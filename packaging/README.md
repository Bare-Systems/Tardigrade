# Tardigrade Packaging

Native packaging artifacts for Tardigrade. See the [main README](../README.md#install)
for the quick-start install path; this document covers every packaging
format in detail, including what is actually built and published today
versus what is a local-build-only tool.

## Current status

| Format | Status | Notes |
| --- | --- | --- |
| Linux release archives (`.tar.gz`, x86_64/aarch64) | **Supported, published** | Built and attached to every GitHub release by `.github/workflows/release.yml`, alongside `install.sh`, `tardigrade-checksums.txt`, and per-arch SPDX SBOMs. |
| macOS release archives (`.tar.gz`, darwin x86_64/arm64) | **Implemented in #476; awaiting first release** | #476 adds `macos-15-intel` and `macos-15` release rows for `tardigrade-darwin-x86_64.tar.gz` and `tardigrade-darwin-arm64.tar.gz`, using the same archive/SBOM/inventory/provenance pipeline as Linux. A dedicated PR smoke runs native build, architecture, linkage-audit, packaging, extraction, and `tardi version` checks on both architectures. The currently published latest release still predates #476, so these assets are not public until the first intentional release containing it. |
| DEB (`packaging/deb/build.sh`) | **Supported, published** | Built for `amd64`/`arm64` from the same release binaries as the `.tar.gz` archives and attached to every GitHub release; also usable as a local builder (`packaging/deb/build.sh`). Smoke-tested on every PR/push via the `packaging-smoke` CI job (`scripts/test-deb-package.sh`). |
| RPM (`packaging/rpm/build.sh`) | **Supported, published** | Same treatment as DEB, for `x86_64`/`aarch64`. Smoke-tested via `scripts/test-rpm-package.sh`. Built from the same Ubuntu-runner binary as the archives — see the glibc compatibility note below if targeting an older RHEL-family release. |
| systemd unit (`packaging/systemd/tardigrade.service`) | **Supported** | Installed and structurally validated (unit file text/layout, permissions) by both the DEB and RPM smoke tests. Neither test boots systemd or exercises a real start/status/reload/stop lifecycle — see [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md#the-systemd-units-pidcontrol-path-contract) for the unit contract these assertions check. |
| launchd plist (`packaging/launchd/io.baresystems.tardigrade.plist`) | **Unverified template** | The Darwin archive pipeline does not install or exercise launchd. #467 owns a real macOS `launchctl` bootstrap/health/bootout smoke and the final `tardi`/compatibility-alias service contract. |
| Homebrew (`packaging/homebrew/tardigrade.rb`) | **Formula present; public tap exists but is not usable yet** | `Bare-Systems/homebrew-tap` exists, but #466 owns seeding/automating it. The checked-in formula is not currently installable: its release version is stale, SHA-256 values are placeholders, and the macOS runtime dependency still needs to be represented truthfully. #476 only supplies the Darwin archive filenames the future formula will consume. |
| Docker / OCI image | **Local build supported, not published** | Root [`Dockerfile`](../Dockerfile) and [`compose.yaml`](../compose.yaml) build a runtime image locally; smoke-tested via `scripts/test-docker-image.sh` in the `packaging-smoke` CI job. No registry-published image or container-publishing workflow exists. See [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the full workflow. |

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

The currently published latest release resolves only for Linux
(`x86_64`/`aarch64`). After the first release containing #476, the same script
will also resolve native Intel and Apple Silicon macOS archives. The release
checklist requires verifying those first published Darwin assets before #463
closes.

Published general-profile Darwin binaries link Homebrew OpenSSL 3 at runtime.
Install it first:

```bash
brew install openssl@3
```

### macOS Gatekeeper / unsigned binary note

The initial Darwin archives are unsigned and not notarized. Command-line
installation from GitHub Releases is supported once the first #476 release is
published, but a browser-downloaded archive may carry Apple's quarantine
attribute and trigger Gatekeeper. Signing/notarization is a separate future
distribution concern; do not describe these archives as notarized.

If an operator intentionally downloaded the official archive and Gatekeeper
blocks the extracted binary because of quarantine, inspect the attribute first
and remove it only from that trusted extracted binary when appropriate:

```bash
xattr -l ./tardi
xattr -d com.apple.quarantine ./tardi
```

Do not apply recursive quarantine removal to unrelated files.

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
`/etc/tardigrade/tardigrade.conf`, creates `/var/lib/tardigrade` (the
systemd unit's `WorkingDirectory`), creates a `tardigrade`-owned
`/var/log/tardigrade`, and installs the same SIGUSR1-reopen logrotate
policy at `/etc/logrotate.d/tardigrade`, so `systemctl enable --now
tardigrade` works immediately after a fresh install.

## Docker (local build)

There is no published Bare Systems container image. The root
[`Dockerfile`](../Dockerfile) and [`compose.yaml`](../compose.yaml) support
building and running Tardigrade in a container locally:

```bash
docker compose build
docker compose up -d
```

The image is a multi-stage build (Zig toolchain in the build stage only, a
minimal `tardi` + OpenSSL/CA-certificates runtime in the final stage) that
runs as a non-root `tardigrade` user. See
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the complete Docker workflow
— build, config validation, start, reload, and graceful stop — alongside the
equivalent systemd path.

## Upgrading

After a package (or standalone binary) upgrade, use `systemctl restart`, not
`systemctl reload`:

```bash
sudo apt install ./new-package.deb   # or: dnf upgrade / rpm -U for RPM
sudo systemctl restart tardigrade
```

`systemctl reload` sends `SIGHUP`, which republishes the *existing running
process's* config — it does not exec the newly installed `tardi` binary, so
a package/binary upgrade needs a restart to actually take effect. Reserve
`reload` for edits to reloadable values in `tardigrade.conf` where neither
the binary nor `/etc/tardigrade/tardigrade.env` changed; env-file edits also
always require a restart (`SIGHUP` cannot change an already-running
process's environment). See
[docs/DEPLOYMENT.md#commands](../docs/DEPLOYMENT.md#commands) and
[docs/RELOAD_SHUTDOWN.md](../docs/RELOAD_SHUTDOWN.md) for the exact
reload/restart boundary, and why the standalone `tardi check` shown there
isn't a complete pre-flight check on its own (it doesn't load
`tardigrade.env`).

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

PR #476 supplies the Darwin **archive filenames** the formula is intended to
consume after the first release containing that change. That does not make the
current formula installable by itself.

The checked-in `packaging/homebrew/tardigrade.rb` still needs #466 to reconcile
its release version, replace placeholder checksums with values from one real
release, declare/handle the macOS OpenSSL runtime dependency correctly, and
publish/synchronize the formula into the existing public
`Bare-Systems/homebrew-tap` repository. Do not advertise the tap as a working
install path until #466's smoke succeeds.

The intended eventual public shape is:

```bash
brew tap Bare-Systems/tap
brew install tardigrade

tardi version
```

Use #466 as the source of truth for formula ownership and release-to-tap update
automation. Do not maintain two hand-edited canonical formulas.

## Service files

Pre-built service files for host-native installs:

| File | Purpose |
|---|---|
| [`systemd/tardigrade.service`](systemd/tardigrade.service) | systemd service unit (Linux) |
| [`launchd/io.baresystems.tardigrade.plist`](launchd/io.baresystems.tardigrade.plist) | launchd plist (macOS) — archive publication is handled by #476; real launchd lifecycle validation remains #467 |

## Related docs

- [Main README — Install](../README.md#install)
- [Production deployment guide](../docs/DEPLOYMENT.md)
- [Release checklist](../docs/RELEASE_CHECKLIST.md)
- [Support matrix](../docs/SUPPORT_MATRIX.md)
