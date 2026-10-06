#!/usr/bin/env bash
# Select the CI validation mode: `smoke` or `full` (#806).
#
#   scripts/ci-mode.sh --base <ref> --head <ref> [--override auto|smoke|full]
#                      [--changelog <path>]
#
# Prints exactly one word, `smoke` or `full`, on stdout. Diagnostics go to
# stderr. Exit status: 0 on success, 2 on any usage/input/detection error
# (callers must treat that as a failed run, never as a silent `smoke`).
#
# Rule (override=auto): the mode is `full` iff the changelog at <head>
# contains a numbered release heading (`## [X.Y.Z] - ...`) that is absent from
# the changelog at the merge base of <base> and <head>. This deliberately
# matches scripts/release-metadata.sh; prerelease and malformed headings are
# rejected instead of selecting a release which that script cannot publish.
# Edits under `## [Unreleased]`, pre-existing release sections and a retained
# empty `[Unreleased]` heading never select `full`. `--override smoke|full`
# returns that mode without reading git or the changelog.
#
# Pure git + POSIX text tools; no GitHub API. Works locally and in Actions.
set -euo pipefail

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2
}

die() {
  echo "ci-mode: $*" >&2
  exit 2
}

base=""
head=""
override="auto"
changelog="CHANGELOG.md"

while [ $# -gt 0 ]; do
  case "$1" in
    --base) [ $# -ge 2 ] || die "--base needs a value"; base="$2"; shift 2 ;;
    --head) [ $# -ge 2 ] || die "--head needs a value"; head="$2"; shift 2 ;;
    --override) [ $# -ge 2 ] || die "--override needs a value"; override="$2"; shift 2 ;;
    --changelog) [ $# -ge 2 ] || die "--changelog needs a value"; changelog="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

case "$override" in
  smoke | full)
    echo "ci-mode: manual override -> $override" >&2
    echo "$override"
    exit 0
    ;;
  auto) ;;
  *) die "invalid --override '$override' (expected auto, smoke or full)" ;;
esac

[ -n "$base" ] || die "--base is required when --override is auto"
[ -n "$head" ] || die "--head is required when --override is auto"

git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

base_sha=$(git rev-parse --verify --quiet "$base^{commit}") ||
  die "cannot resolve base ref '$base' (shallow checkout? use fetch-depth: 0)"
head_sha=$(git rev-parse --verify --quiet "$head^{commit}") ||
  die "cannot resolve head ref '$head'"
merge_base=$(git merge-base "$base_sha" "$head_sha") ||
  die "no merge base between '$base' and '$head' (shallow checkout? use fetch-depth: 0)"

# Read each changelog exactly once. In particular, do not use `git show | grep
# -q`: grep may exit after a matching early heading and make git fail with
# SIGPIPE under pipefail when CHANGELOG.md is large.
read_changelog() {
  local rev="$1" content
  content=$(git show "$rev:$changelog" 2>/dev/null) ||
    die "cannot read $changelog at $rev"
  [ -n "$content" ] || die "$changelog at $rev is empty"
  printf '%s\n' "$content"
}

validate_changelog() {
  local rev="$1" content="$2" invalid
  if ! grep -Eq '^## \[Unreleased\]$|^## \[[0-9]+\.[0-9]+\.[0-9]+\] - ' <<<"$content"; then
    die "$changelog at $rev has no [Unreleased] or valid numbered release heading"
  fi

  # Keep this contract in lockstep with release-metadata.sh. A heading that
  # starts like a release but is not a plain X.Y.Z heading with ` - ` is not a
  # release candidate this repository can safely publish.
  invalid=$(printf '%s\n' "$content" | sed -n -E \
    '/^## \[[0-9]+\.[0-9]+\.[0-9]+/ { /^## \[[0-9]+\.[0-9]+\.[0-9]+\] - /!p; }')
  [ -z "$invalid" ] || die "$changelog at $rev has unsupported release heading: $invalid"
}

# Numbered release headings, one version per line, sorted and unique.
release_versions() {
  local content="$1"
  printf '%s\n' "$content" |
    sed -n -E 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - .*/\1/p' |
    sort -u
}

base_content=$(read_changelog "$merge_base")
head_content=$(read_changelog "$head_sha")
validate_changelog "$merge_base" "$base_content"
validate_changelog "$head_sha" "$head_content"
base_versions=$(release_versions "$base_content")
head_versions=$(release_versions "$head_content")

new_versions=$(comm -13 <(printf '%s\n' "$base_versions") <(printf '%s\n' "$head_versions") | sed '/^$/d')

if [ -n "$new_versions" ]; then
  echo "ci-mode: new release heading(s): $(echo "$new_versions" | tr '\n' ' ')-> full" >&2
  echo full
else
  echo "ci-mode: no new numbered release heading -> smoke" >&2
  echo smoke
fi
