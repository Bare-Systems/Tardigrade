# Tardigrade Packaging

Native packaging artifacts for Tardigrade.

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | bash
```

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
- Installs the binary to `/usr/bin/tardigrade`
- Creates a `tardigrade` system user
- Installs a systemd service unit at `/lib/systemd/system/tardigrade.service`
- Installs an env config template at `/etc/tardigrade/tardigrade.env` (mode 0640, owned by `root:tardigrade`)
- Installs a logrotate config at `/etc/logrotate.d/tardigrade`

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
| [`launchd/io.baresystems.tardigrade.plist`](launchd/io.baresystems.tardigrade.plist) | launchd plist (macOS) |

## Kubernetes

See [`kubernetes/`](kubernetes/) for the Helm chart and deployment guide.
