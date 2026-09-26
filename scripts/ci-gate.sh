#!/usr/bin/env bash
# Single stable required-check logic for .github/workflows/ci.yml (#806).
#
#   scripts/ci-gate.sh <smoke|full> <needs.json>
#
# <needs.json> is the `toJSON(needs)` object of the gate job. Job ids listed
# in SMOKE_JOBS must have succeeded in either mode; FULL_JOBS must have
# succeeded in `full` mode and are ignored (they are skipped) in `smoke`.
# OPTIONAL_JOBS may be `skipped` (event-dependent) but never failed/cancelled.
# Exit 0 = pass, 1 = fail.
set -euo pipefail

SMOKE_JOBS="${SMOKE_JOBS:-}"
FULL_JOBS="${FULL_JOBS:-}"
OPTIONAL_JOBS="${OPTIONAL_JOBS:-}"

mode="${1:-}"
needs_file="${2:-}"
case "$mode" in smoke | full) ;; *)
  echo "ci-gate: mode must be smoke or full (got '$mode')" >&2
  exit 1
  ;;
esac
[ -r "$needs_file" ] || { echo "ci-gate: cannot read needs file '$needs_file'" >&2; exit 1; }

result_of() {
  jq -r --arg j "$1" '.[$j].result // "missing"' "$needs_file"
}

fail=0
check() {
  local job="$1" allowed="$2" result
  result=$(result_of "$job")
  case " $allowed " in
    *" $result "*) echo "ok   $job: $result" ;;
    *) echo "FAIL $job: $result (allowed: $allowed)"; fail=1 ;;
  esac
}

for j in $SMOKE_JOBS; do check "$j" "success"; done
for j in $OPTIONAL_JOBS; do check "$j" "success skipped"; done
if [ "$mode" = "full" ]; then
  for j in $FULL_JOBS; do check "$j" "success"; done
else
  for j in $FULL_JOBS; do
    r=$(result_of "$j")
    # A full-only job that ran and failed in smoke mode is a workflow bug.
    case "$r" in failure | cancelled) echo "FAIL $j: $r (unexpected in smoke)"; fail=1 ;; *) echo "skip $j: $r (full-only)" ;; esac
  done
fi

[ "$fail" -eq 0 ] && echo "ci-gate: $mode mode PASSED" || echo "ci-gate: $mode mode FAILED"
exit "$fail"
