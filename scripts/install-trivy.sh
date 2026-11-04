#!/usr/bin/env bash
# Install the pinned Trivy binary without relying on get.trivy.dev.
#
# The Trivy GitHub Action's installer uses get.trivy.dev, whose DNS is not
# always available on GitHub-hosted runners. Download the immutable release
# asset directly from GitHub and verify its published SHA-256 instead.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 INSTALL_DIRECTORY" >&2
  exit 2
fi

readonly trivy_version="0.70.0"
readonly archive_name="trivy_${trivy_version}_Linux-64bit.tar.gz"
readonly archive_sha256="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
readonly archive_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/${archive_name}"

install_directory="$1"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

mkdir -p "$install_directory"
archive_path="$temporary_directory/$archive_name"

curl --fail --location --silent --show-error \
  --retry 4 --retry-all-errors --connect-timeout 15 \
  --output "$archive_path" "$archive_url"
if command -v shasum >/dev/null; then
  actual_sha256="$(shasum --algorithm 256 "$archive_path" | awk '{print $1}')"
elif command -v sha256sum >/dev/null; then
  actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
else
  echo "neither shasum nor sha256sum is available" >&2
  exit 1
fi
test "$actual_sha256" = "$archive_sha256"
tar --extract --gzip --file "$archive_path" --directory "$install_directory" trivy
chmod 0755 "$install_directory/trivy"
