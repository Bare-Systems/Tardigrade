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
# contains a numbered release heading (`## [X.Y.Z]`, optional -prerelease)
# that is absent from the changelog at the merge base of <base> and <head>.
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

# Numbered release headings, one version per line, sorted and unique.
release_versions() {
  local rev="$1" content
  content=$(git show "$rev:$changelog" 2>/dev/null) ||
    die "cannot read $changelog at $rev"
  [ -n "$content" ] || die "$changelog at $rev is empty"
  printf '%s\n' "$content" |
    sed -n -E 's/^## \[([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)\].*/\1/p' |
    sort -u
}

base_versions=$(release_versions "$merge_base")
head_versions=$(release_versions "$head_sha")

# The changelog must at least keep its Unreleased heading or a numbered
# release; anything else is ambiguous input.
if ! git show "$head_sha:$changelog" | grep -Eq '^## \[(Unreleased|[0-9]+\.[0-9]+\.[0-9]+)'; then
  die "$changelog at $head has no '## [Unreleased]' or numbered release heading"
fi

new_versions=$(comm -13 <(printf '%s\n' "$base_versions") <(printf '%s\n' "$head_versions") | sed '/^$/d')

if [ -n "$new_versions" ]; then
  echo "ci-mode: new release heading(s): $(echo "$new_versions" | tr '\n' ' ')-> full" >&2
  echo full
else
  echo "ci-mode: no new numbered release heading -> smoke" >&2
  echo smoke
fi
