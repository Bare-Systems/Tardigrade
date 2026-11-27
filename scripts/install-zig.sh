#!/bin/sh
set -eu

# --print-cache-path resolves the exact distribution archive without I/O so CI
# can restore it before installation. The normal stdout contract is unchanged.
print_cache_path=false
if [ "${1:-}" = "--print-cache-path" ]; then
  print_cache_path=true
  shift
fi
version="${1:-0.16.0}"
install_root="${2:-$PWD/.zig}"
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

case "$install_root" in
  /*) ;;
  *) install_root="$PWD/$install_root" ;;
esac

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux) zig_os="linux" ;;
  Darwin) zig_os="macos" ;;
  *)
    echo "unsupported operating system: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) zig_arch="x86_64" ;;
  arm64|aarch64) zig_arch="aarch64" ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

zig_dir="$install_root/$version"
zig_target="$zig_arch-$zig_os"
zig_bin_dir="$zig_dir/zig-$zig_target-$version"
archive="zig-$zig_target-$version.tar.xz"
archive_path="$install_root/downloads/$archive"
expected_sha256=$(awk -v archive="$archive" '$2 == archive { print $1 }' "$script_dir/zig-checksums.txt")
if [ "${#expected_sha256}" -ne 64 ]; then
  echo "no pinned Zig checksum for $version ($zig_target)" >&2
  exit 1
fi

if "$print_cache_path"; then
  printf '%s\n' "$archive_path"
  exit 0
fi

verify_archive() {
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256=$(sha256sum "$1" | awk '{print $1}')
  else
    actual_sha256=$(shasum -a 256 "$1" | awk '{print $1}')
  fi
  [ "$actual_sha256" = "$expected_sha256" ]
}

mkdir -p "$zig_dir" "$install_root/downloads"
# Stage on the destination filesystem, and publish only verified downloads and
# complete extractions. An interrupted download/extraction is never reused.
tmp_dir=$(mktemp -d "$zig_dir/.install-XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT
trap 'exit 1' INT TERM

if [ -f "$archive_path" ] && ! verify_archive "$archive_path"; then
  echo "discarding Zig archive with invalid SHA-256: $archive_path" >&2
  rm -f "$archive_path"
fi

if [ ! -f "$archive_path" ]; then
  # Mirrors (including public Cloudflare R2 buckets/custom domains) must expose
  # BASE_URL/VERSION/ARCHIVE. One HTTPS base URL per line, official source first.
  printf '%s\n' 'https://ziglang.org/download' "${ZIG_DOWNLOAD_MIRRORS:-}" |
    while IFS= read -r base_url; do
      case "$base_url" in
        '') continue ;;
        https://*) ;;
        *) echo "Zig mirror must use HTTPS: $base_url" >&2; continue ;;
      esac
      echo "downloading Zig $version ($zig_target) from ${base_url%/}" >&2
      if curl --fail --location --silent --show-error \
        --proto '=https' --proto-redir '=https' \
        --connect-timeout 5 --max-time 45 --speed-limit 1024 --speed-time 15 \
        --retry 1 --retry-delay 1 --retry-max-time 50 \
        "${base_url%/}/$version/$archive" -o "$tmp_dir/$archive"; then
        if verify_archive "$tmp_dir/$archive"; then
          mv "$tmp_dir/$archive" "$archive_path"
          break
        fi
        echo "Zig archive SHA-256 mismatch from ${base_url%/}" >&2
      fi
      rm -f "$tmp_dir/$archive"
    done
  if [ ! -f "$archive_path" ]; then
    echo "could not download a checksum-verified Zig $version distribution" >&2
    exit 1
  fi
fi

# Re-extract even on cache hits: every installed byte comes from the pinned
# official archive, including lib/, headers, and runtime files, not just zig.
tar -xJf "$archive_path" -C "$tmp_dir"
staged_bin_dir="$tmp_dir/zig-$zig_target-$version"
if [ ! -d "$staged_bin_dir/lib" ] || [ "$("$staged_bin_dir/zig" version)" != "$version" ]; then
  echo "invalid Zig $version distribution" >&2
  exit 1
fi
rm -rf "$zig_bin_dir"
mv "$staged_bin_dir" "$zig_bin_dir"

printf '%s\n' "$zig_bin_dir"

if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$zig_bin_dir" >> "$GITHUB_PATH"
fi
