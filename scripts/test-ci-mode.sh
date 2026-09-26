#!/usr/bin/env bash
# Regression tests for scripts/ci-mode.sh and scripts/ci-gate.sh (#806).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mode_sh="$here/ci-mode.sh"
gate_sh="$here/ci-gate.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0
failed=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failed=$((failed + 1)); echo "FAIL $1: $2"; }

repo="$work/repo"
git init -q "$repo"
git -C "$repo" config user.email ci@example.invalid
git -C "$repo" config user.name ci
git -C "$repo" config commit.gpgsign false

commit() { git -C "$repo" add -A && git -C "$repo" commit -q -m "$1" && git -C "$repo" rev-parse HEAD; }

write_changelog() { # $1 = unreleased body, $2.. = extra release headings
  local body="$1"; shift
  {
    printf '# Changelog\n\n## [Unreleased]\n\n%s\n' "$body"
    for v in "$@"; do printf '\n## [%s] - 2026-01-01\n\n- note\n' "$v"; done
  } >"$repo/CHANGELOG.md"
}

# expect <name> <expected-mode|error> <args...>
expect() {
  local name="$1" want="$2"; shift 2
  local out rc=0
  out=$(cd "$repo" && "$mode_sh" "$@" 2>"$work/stderr") || rc=$?
  if [ "$want" = "error" ]; then
    if [ "$rc" -eq 2 ] && [ -z "$out" ]; then ok "$name"; else bad "$name" "rc=$rc out='$out'"; fi
  elif [ "$rc" -eq 0 ] && [ "$out" = "$want" ]; then ok "$name"; else bad "$name" "rc=$rc out='$out' want=$want ($(cat "$work/stderr"))"; fi
}

write_changelog "" 0.7.2 0.7.3
echo a >"$repo/a.txt"
base=$(commit base)

# unrelated change, changelog untouched
echo b >"$repo/a.txt"; head=$(commit unrelated)
expect "no changelog change" smoke --base "$base" --head "$head"

# edit under [Unreleased]
write_changelog "- **fix**: thing" 0.7.2 0.7.3; head=$(commit unreleased)
expect "entries added under [Unreleased]" smoke --base "$base" --head "$head"

# historical numbered sections pre-exist and are reworded (not new)
sed -i.bak 's/^## \[0.7.2\] - 2026-01-01/## [0.7.2] - 2026-02-02/' "$repo/CHANGELOG.md"; rm -f "$repo/CHANGELOG.md.bak"
head=$(commit redate)
expect "historical section edited/re-dated" smoke --base "$base" --head "$head"

# promotion: new numbered release with an empty [Unreleased] retained above it
write_changelog "" 0.7.4 0.7.3 0.7.2; head=$(commit promote)
expect "new release, empty [Unreleased] retained" full --base "$base" --head "$head"

# promotion with a prerelease suffix
write_changelog "" 0.8.0-rc.1 0.7.3 0.7.2; head=$(commit promote-rc)
expect "new prerelease heading" full --base "$base" --head "$head"

# promotion by push-style before/after (base is the immediately preceding commit)
write_changelog "" 0.7.4 0.7.3 0.7.2; prev=$(commit promote-again 2>/dev/null || git -C "$repo" rev-parse HEAD)
write_changelog "- later fix" 0.7.4 0.7.3 0.7.2; after=$(commit later)
expect "push after promotion (release already in before)" smoke --base "$prev" --head "$after"

# merge-base semantics: main advanced with a release, the PR branch did not
git -C "$repo" checkout -q -b main-line "$base"
write_changelog "" 0.7.9 0.7.3 0.7.2; main_tip=$(commit main-release)
git -C "$repo" checkout -q -b pr-branch "$base"
echo z >"$repo/b.txt"; pr_tip=$(commit pr-work)
expect "release only on base branch is not new for the PR" smoke --base "$main_tip" --head "$pr_tip"
git -C "$repo" checkout -q main-line

# manual overrides need no refs
expect "override full" full --override full
expect "override smoke" smoke --override smoke
expect "override full ignores refs" full --override full --base nope --head nope

# malformed / missing input
expect "invalid override" error --override medium
expect "auto without refs" error
expect "auto missing head" error --base "$base"
expect "unresolvable base" error --base does-not-exist --head "$head"
git -C "$repo" rm -q CHANGELOG.md; nochange=$(commit rm-changelog)
expect "missing changelog at head" error --base "$base" --head "$nochange"
printf 'not a changelog\n' >"$repo/CHANGELOG.md"; junk=$(commit junk-changelog)
expect "changelog without headings" error --base "$base" --head "$junk"
expect "unknown argument" error --frobnicate
git -C "$repo" checkout -q -b nochange-line "$nochange"
write_changelog "" 0.7.4 0.7.3; restored=$(commit restore-changelog)
expect "missing changelog at base" error --base "$nochange" --head "$restored"

# ── ci-gate.sh ──
needs() { printf '%s' "$1" >"$work/needs.json"; }
gate() { SMOKE_JOBS="format test" FULL_JOBS="build perf" OPTIONAL_JOBS="depreview" "$gate_sh" "$@" >"$work/gate.out" 2>&1; }
expect_gate() { # name want(0|1) mode json
  local rc=0; needs "$4"; gate "$3" "$work/needs.json" || rc=$?
  if [ "$rc" -eq "$2" ]; then ok "$1"; else bad "$1" "rc=$rc want=$2: $(cat "$work/gate.out")"; fi
}
S='"format":{"result":"success"},"test":{"result":"success"},"depreview":{"result":"skipped"}'
expect_gate "gate smoke passes, full jobs skipped" 0 smoke "{$S,\"build\":{\"result\":\"skipped\"},\"perf\":{\"result\":\"skipped\"}}"
expect_gate "gate smoke fails on failing smoke job" 1 smoke "{\"format\":{\"result\":\"failure\"},\"test\":{\"result\":\"success\"},\"depreview\":{\"result\":\"success\"},\"build\":{\"result\":\"skipped\"},\"perf\":{\"result\":\"skipped\"}}"
expect_gate "gate full passes when all succeed" 0 full "{$S,\"build\":{\"result\":\"success\"},\"perf\":{\"result\":\"success\"}}"
expect_gate "gate full fails on failing full-only job" 1 full "{$S,\"build\":{\"result\":\"success\"},\"perf\":{\"result\":\"failure\"}}"
expect_gate "gate full fails when a full job was skipped" 1 full "{$S,\"build\":{\"result\":\"success\"},\"perf\":{\"result\":\"skipped\"}}"
expect_gate "gate fails on cancelled smoke job" 1 smoke "{\"format\":{\"result\":\"cancelled\"},\"test\":{\"result\":\"success\"},\"depreview\":{\"result\":\"skipped\"}}"
expect_gate "gate fails on a missing job" 1 smoke "{\"format\":{\"result\":\"success\"},\"depreview\":{\"result\":\"skipped\"}}"
expect_gate "gate fails when optional job fails" 1 smoke "{\"format\":{\"result\":\"success\"},\"test\":{\"result\":\"success\"},\"depreview\":{\"result\":\"failure\"}}"
expect_gate "gate rejects invalid mode" 1 medium "{$S}"

echo "ci-mode tests: $pass passed, $failed failed"
[ "$failed" -eq 0 ]
