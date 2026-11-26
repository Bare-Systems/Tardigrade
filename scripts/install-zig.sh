#!/bin/sh
set -eu

version="${1:-0.16.0}"
install_root="${2:-$PWD/.zig}"

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
zig_bin="$zig_bin_dir/zig"

if [ ! -x "$zig_bin" ]; then
  archive="zig-$zig_target-$version.tar.xz"
  url="https://ziglang.org/download/$version/$archive"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  mkdir -p "$zig_dir"
  # Bound every attempt so a stalled mirror connection cannot consume a CI
  # job's whole time limit: three attempts plus backoff stay under 8 minutes,
  # inside the shortest (10 minute) job that runs this script.  A shell loop
  # rather than `--retry`, so --max-time stalls are retried on old curls too.
  attempt=1
  max_attempts=3
  until curl -fsSL \
    --connect-timeout 20 \
    --speed-limit 102400 --speed-time 30 \
    --max-time 150 \
    "$url" -o "$tmp_dir/$archive"; do
    rm -f "$tmp_dir/$archive"
    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "failed to download $url after $max_attempts attempts" >&2
      exit 1
    fi
    echo "download attempt $attempt of $max_attempts failed; retrying" >&2
    sleep $((attempt * 5))
    attempt=$((attempt + 1))
  done
  tar -xJf "$tmp_dir/$archive" -C "$zig_dir"
fi

printf '%s\n' "$zig_bin_dir"

if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$zig_bin_dir" >> "$GITHUB_PATH"
fi
