#!/usr/bin/env sh

set -eu

REPO="${TARDIGRADE_REPO:-Bare-Systems/Tardigrade}"
VERSION="${TARDIGRADE_VERSION:-latest}"
INSTALL_DIR="${TARDIGRADE_INSTALL_DIR:-$HOME/.local/bin}"
RELEASE_BASE_URL="${TARDIGRADE_RELEASE_BASE_URL:-https://github.com/$REPO/releases}"
DRY_RUN=0
stage_binary=""
stage_alias=""
tmpdir=""

usage() {
  cat <<'EOF'
Usage: install.sh [--dir <install-dir>] [--version <tag>] [--dry-run]

Environment:
  TARDIGRADE_INSTALL_DIR  Override the install directory
  TARDIGRADE_VERSION      Override the release tag (default: latest)
  TARDIGRADE_REPO         Override the GitHub repo (default: Bare-Systems/Tardigrade)
  TARDIGRADE_RELEASE_BASE_URL  Override the release base URL
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)
      shift
      [ "$#" -gt 0 ] || {
        echo "missing value for --dir" >&2
        exit 1
      }
      INSTALL_DIR="$1"
      ;;
    --version)
      shift
      [ "$#" -gt 0 ] || {
        echo "missing value for --version" >&2
        exit 1
      }
      VERSION="$1"
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

cleanup() {
  if [ -n "${tmpdir:-}" ]; then
    rm -rf "$tmpdir"
  fi
  if [ -n "${stage_binary:-}" ]; then
    rm -f "$stage_binary"
  fi
  if [ -n "${stage_alias:-}" ]; then
    rm -f "$stage_alias"
  fi
}

trap cleanup EXIT INT TERM

detect_platform() {
  os="${TARDIGRADE_TEST_UNAME_S:-$(uname -s)}"
  arch="${TARDIGRADE_TEST_UNAME_M:-$(uname -m)}"

  case "$os/$arch" in
    Linux/x86_64|Linux/amd64)
      printf '%s\n' "linux-x86_64"
      return
      ;;
    Linux/arm64|Linux/aarch64)
      printf '%s\n' "linux-aarch64"
      return
      ;;
    Darwin/x86_64|Darwin/amd64)
      printf '%s\n' "darwin-x86_64"
      return
      ;;
    Darwin/arm64|Darwin/aarch64)
      printf '%s\n' "darwin-arm64"
      return
      ;;
    Linux/*)
      echo "unsupported architecture: $arch" >&2
      exit 1
      ;;
    Darwin/*)
      echo "unsupported architecture: $arch" >&2
      exit 1
      ;;
    *)
      echo "unsupported operating system: $os" >&2
      exit 1
      ;;
  esac
}

download_url_for() {
  platform="$1"
  asset="tardigrade-${platform}.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    printf '%s/latest/download/%s\n' "$RELEASE_BASE_URL" "$asset"
  else
    printf '%s/download/%s/%s\n' "$RELEASE_BASE_URL" "$VERSION" "$asset"
  fi
}

download_file() {
  url="$1"
  out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$out" "$url"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi

  echo "curl or wget is required to download Tardigrade" >&2
  exit 1
}

install_binary() {
  src="$1"
  dst="$2"

  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dst"
    return
  fi

  cp "$src" "$dst"
  chmod 0755 "$dst"
}

install_alias() {
  src="$1"
  link_target="$2"
  alias_path="$3"

  rm -f "$alias_path"
  if ln -s "$link_target" "$alias_path" 2>/dev/null; then
    return
  fi

  cp "$src" "$alias_path"
  chmod 0755 "$alias_path"
}

checksum_url_for() {
  if [ "$VERSION" = "latest" ]; then
    printf '%s/latest/download/tardigrade-checksums.txt\n' "$RELEASE_BASE_URL"
  else
    printf '%s/download/%s/tardigrade-checksums.txt\n' "$RELEASE_BASE_URL" "$VERSION"
  fi
}

verify_checksum() {
  archive="$1"
  checksums="$2"
  asset_name="$3"
  expected="$(awk -v target="$asset_name" '
    {
      count = split($2, parts, "/");
      if (parts[count] == target) {
        print $1;
        exit;
      }
    }
  ' "$checksums")"
  if [ -z "$expected" ]; then
    echo "missing checksum entry for $asset_name" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  else
    echo "sha256sum or shasum is required to verify Tardigrade releases" >&2
    exit 1
  fi
  if [ "$actual" != "$expected" ]; then
    printf 'checksum mismatch for %s\n  expected: %s\n  got:      %s\n' \
      "$asset_name" "$expected" "$actual" >&2
    exit 1
  fi
}

platform="$(detect_platform)"
asset_url="$(download_url_for "$platform")"
checksum_url="$(checksum_url_for)"

if [ "$DRY_RUN" -eq 1 ]; then
  printf 'install_dir=%s\n' "$INSTALL_DIR"
  printf 'download_url=%s\n' "$asset_url"
  printf 'checksum_url=%s\n' "$checksum_url"
  exit 0
fi

tmpdir="$(mktemp -d)"

archive_path="$tmpdir/tardigrade.tar.gz"
checksums_path="$tmpdir/tardigrade-checksums.txt"
asset_name="$(basename "$asset_url")"

download_file "$asset_url" "$archive_path"
download_file "$checksum_url" "$checksums_path"
verify_checksum "$archive_path" "$checksums_path" "$asset_name"

tar -xzf "$archive_path" -C "$tmpdir"
[ -f "$tmpdir/tardi" ] || {
  echo "release archive did not contain a tardi binary" >&2
  exit 1
}

mkdir -p "$INSTALL_DIR"
stage_binary="$INSTALL_DIR/.tardi.$$"
stage_alias="$INSTALL_DIR/.tardigrade.$$"
install_binary "$tmpdir/tardi" "$stage_binary"
install_alias "$stage_binary" "tardi" "$stage_alias"
mv -f "$stage_binary" "$INSTALL_DIR/tardi"
stage_binary=""
mv -f "$stage_alias" "$INSTALL_DIR/tardigrade"
stage_alias=""

printf 'Installed tardi to %s/tardi\n' "$INSTALL_DIR"
printf 'Installed compatibility alias to %s/tardigrade\n' "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    printf 'Add %s to PATH to invoke tardi directly.\n' "$INSTALL_DIR"
    ;;
esac
