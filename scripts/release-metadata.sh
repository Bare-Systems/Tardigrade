#!/usr/bin/env sh

set -eu

usage() {
  cat <<'EOF'
Usage: release-metadata.sh <version|tag|notes> [CHANGELOG.md]
EOF
}

command_name="${1:-}"
changelog_path="${2:-CHANGELOG.md}"

if [ -z "$command_name" ]; then
  usage >&2
  exit 1
fi

top_version() {
  awk '
    /^## \[[0-9]+\.[0-9]+\.[0-9]+\] - / {
      line = $0
      sub(/^## \[/, "", line)
      sub(/\].*$/, "", line)
      print line
      exit
    }
  ' "$changelog_path"
}

top_notes() {
  awk '
    /^## \[[0-9]+\.[0-9]+\.[0-9]+\] - / {
      if (seen) exit
      seen = 1
    }
    seen { print }
  ' "$changelog_path"
}

case "$command_name" in
  version)
    version="$(top_version)"
    [ -n "$version" ] || {
      echo "No semantic version heading found in $changelog_path" >&2
      exit 1
    }
    printf '%s\n' "$version"
    ;;
  tag)
    version="$(top_version)"
    [ -n "$version" ] || {
      echo "No semantic version heading found in $changelog_path" >&2
      exit 1
    }
    printf 'v%s\n' "$version"
    ;;
  notes)
    top_notes
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
