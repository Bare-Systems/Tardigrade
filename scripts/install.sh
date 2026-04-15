#!/usr/bin/env sh

set -eu

REPO="${TARDIGRADE_REPO:-Bare-Systems/Tardigrade}"
VERSION="${TARDIGRADE_VERSION:-latest}"
INSTALL_DIR="${TARDIGRADE_INSTALL_DIR:-$HOME/.local/bin}"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: install.sh [--dir <install-dir>] [--version <tag>] [--dry-run]

Environment:
  TARDIGRADE_INSTALL_DIR  Override the install directory
  TARDIGRADE_VERSION      Override the release tag (default: latest)
  TARDIGRADE_REPO         Override the GitHub repo (default: Bare-Systems/Tardigrade)
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

detect_platform() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *)
      echo "unsupported operating system: $os" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)
      echo "unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  printf '%s-%s\n' "$os" "$arch"
}

download_url_for() {
  platform="$1"
  asset="tardigrade-${platform}.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$asset"
  else
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$VERSION" "$asset"
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
  target="$1"
  alias_path="$2"

  rm -f "$alias_path"
  if ln -s "$target" "$alias_path" 2>/dev/null; then
    return
  fi

  cp "$target" "$alias_path"
  chmod 0755 "$alias_path"
}

platform="$(detect_platform)"
asset_url="$(download_url_for "$platform")"

if [ "$DRY_RUN" -eq 1 ]; then
  printf 'install_dir=%s\n' "$INSTALL_DIR"
  printf 'download_url=%s\n' "$asset_url"
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

archive_path="$tmpdir/tardigrade.tar.gz"
download_file "$asset_url" "$archive_path"
tar -xzf "$archive_path" -C "$tmpdir"

mkdir -p "$INSTALL_DIR"
install_binary "$tmpdir/tardigrade" "$INSTALL_DIR/tardigrade"
install_alias "$INSTALL_DIR/tardigrade" "$INSTALL_DIR/tardi"

printf 'Installed tardigrade to %s/tardigrade\n' "$INSTALL_DIR"
printf 'Installed alias to %s/tardi\n' "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    printf 'Add %s to PATH to invoke tardigrade directly.\n' "$INSTALL_DIR"
    ;;
esac
