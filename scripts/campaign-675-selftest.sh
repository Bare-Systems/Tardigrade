#!/usr/bin/env bash
# Deterministic validation of the #675 release baseline and row-outcome logic.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
E="$TMP/epoch"; mkdir -p "$E"
# shellcheck source=/dev/null
eval "$(sed -n '/^family_target_count()/,/^}/p;/^row_passed()/,/^}/p;/^watchdog_for()/,/^}/p' scripts/campaign-675-driver.sh)"

fails=0
check() { # name expected_rc actual_rc
  if [[ "$2" == "$3" ]]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s (want rc=%s got rc=%s)\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
mkrow() { # rid rc records...
  local rid="$1" rc="$2"; shift 2
  mkdir -p "$E/$rid"; echo "$rc" > "$E/$rid/collect.rc"; : > "$E/$rid/manifest.jsonl"
  for st in "$@"; do printf '{"status":"%s"}\n' "$st" >> "$E/$rid/manifest.jsonl"; done
}

# THE REGRESSION: family row, 3 targets passed then one failed.
mkrow mixed 1 pass pass pass fail
row_passed mixed 1 tls-record; check "family row with a later FAIL is not a pass" 1 $?

# Complete tier-1 family row (tls-record has 6 targets).
mkrow full 0 pass pass pass pass pass pass
row_passed full 1 tls-record; check "complete family row passes" 0 $?

# Truncated family row: all passes, but fewer than the family's targets, and no
# failure record -- the case a status-only check cannot see.
mkrow short 0 pass pass pass
row_passed short 1 tls-record; check "truncated family row is not a pass" 1 $?

# Tier-2 single-target rows.
mkrow t2ok 0 pass;  row_passed t2ok 2 quic; check "tier-2 single pass" 0 $?
mkrow t2bad 1 fail; row_passed t2bad 2 quic; check "tier-2 fail" 1 $?

# Non-zero collect exit overrides an all-pass manifest.
mkrow rcbad 1 pass pass pass pass pass pass
row_passed rcbad 1 tls-record; check "nonzero collect rc overrides manifest" 1 $?

# Missing collect.rc (pre-fix row) must not count.
mkdir -p "$E/norc"; printf '{"status":"pass"}\n' > "$E/norc/manifest.jsonl"
row_passed norc 2 quic; check "missing collect.rc is not a pass" 1 $?

# No manifest at all.
mkrow nomani 0; rm -f "$E/nomani/manifest.jsonl"
row_passed nomani 2 quic; check "no manifest is not a pass" 1 $?

# Watchdog bounds must exceed the slowest measured legitimate run per budget.
w10=$(watchdog_for 10M); w50=$(watchdog_for 50M); w100=$(watchdog_for 100M)
if [[ "$w10" -gt 13320 && "$w10" -lt 86400 ]]; then printf '  ok   10M watchdog %ss brackets the 3.7h legit max\n' "$w10"; else printf '  FAIL 10M watchdog %s\n' "$w10"; fails=$((fails+1)); fi
if [[ "$w50" -gt 84240 ]]; then printf '  ok   50M watchdog %ss exceeds the 23.4h legit max\n' "$w50"; else printf '  FAIL 50M watchdog %s\n' "$w50"; fails=$((fails+1)); fi
if [[ "$w100" -gt "$w50" ]]; then printf '  ok   100M watchdog %ss exceeds 50M\n' "$w100"; else printf '  FAIL 100M watchdog %s\n' "$w100"; fails=$((fails+1)); fi

echo

# Release-baseline tests use a shell-local Git double. They prove the reseat
# flow only consults the requested immutable tag; no network, Proxmox host, or
# current branch is involved.
# shellcheck source=/dev/null
source scripts/campaign-675-reseat.sh
RELEASE_TMP="$TMP/release"
mkdir -p "$RELEASE_TMP"
printf 'row_id\ttier\tfamily\ttarget\tbudget\nsmoke\t2\tquic\tfuzz: packet parser preserves bounded slice and progress invariants\t50M\n' > "$RELEASE_TMP/rows.tsv"
export CAMPAIGN_675_EVIDENCE_ROOT="$RELEASE_TMP/evidence"
export CAMPAIGN_675_ACTIVE_STATE="$RELEASE_TMP/evidence/campaign-675-active.env"
export CAMPAIGN_675_ROW_PLAN="$RELEASE_TMP/rows.tsv"
export CAMPAIGN_675_GIT_REMOTE="test-origin"
export CAMPAIGN_675_NO_START=true
MOCK_TAG="v9.9.9"
MOCK_SHA="1111111111111111111111111111111111111111"
MOCK_MAIN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GIT_CALLS=()
# shellcheck disable=SC2329 # invoked indirectly by campaign_675_reseat_main
git() {
  GIT_CALLS+=("$*")
  local ref="${!#}"
  case "$1" in
    fetch) return 0 ;;
    rev-parse)
      if [[ "$ref" == "refs/tags/$MOCK_TAG" || "$ref" == "$MOCK_TAG^{commit}" ]]; then
        [[ "$ref" == "$MOCK_TAG^{commit}" ]] && printf '%s\n' "$MOCK_SHA"
        return 0
      fi
      if [[ "$ref" == "refs/remotes/test-origin/main" ]]; then
        printf '%s\n' "$MOCK_MAIN"
        return 0
      fi
      return 1
      ;;
    *) return 1 ;;
  esac
}

campaign_675_reseat_main >/dev/null 2>&1
check "reseat requires a release argument" 64 $?
campaign_675_reseat_main v9.9.8 >/dev/null 2>&1
check "reseat rejects a nonexistent release tag" 1 $?
campaign_675_reseat_main "$MOCK_TAG" >/dev/null 2>&1
check "reseat establishes a resolved release baseline" 0 $?

STATE="$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG/campaign.env"
ACTIVE="$CAMPAIGN_675_ACTIVE_STATE"
if [[ "$(grep '^RELEASE_TAG=' "$STATE")" == "RELEASE_TAG=$MOCK_TAG" ]]; then check "campaign state records the requested release" 0 0; else check "campaign state records the requested release" 0 1; fi
if [[ "$(grep '^SOURCE_SHA=' "$STATE")" == "SOURCE_SHA=$MOCK_SHA" ]]; then check "campaign state records the resolved tag commit" 0 0; else check "campaign state records the resolved tag commit" 0 1; fi
if [[ -f "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG/rows.tsv" ]]; then check "campaign directory receives a fresh row plan" 0 0; else check "campaign directory receives a fresh row plan" 0 1; fi
if [[ "$(grep '^CAMPAIGN_STATE=' "$ACTIVE")" == "CAMPAIGN_STATE=$STATE" ]]; then check "active state points to the release baseline" 0 0; else check "active state points to the release baseline" 0 1; fi

first_state="$(cksum "$STATE")"
MOCK_MAIN="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
campaign_675_reseat_main "$MOCK_TAG" >/dev/null 2>&1
check "repeating a release invocation is idempotent" 0 $?
if [[ "$(cksum "$STATE")" == "$first_state" ]]; then check "main movement cannot change the tag baseline" 0 0; else check "main movement cannot change the tag baseline" 0 1; fi
printf '%s\n' "${GIT_CALLS[@]}" | grep -q 'origin/main'
check "release resolution never consults origin/main" 1 $?

MOCK_TAG="v9.9.8"
MOCK_SHA="2222222222222222222222222222222222222222"
mkdir -p "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG"
printf 'RELEASE_TAG=%s\nSOURCE_SHA=%s\nCAMPAIGN_DIR=%s\n' "$MOCK_TAG" "3333333333333333333333333333333333333333" "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG" > "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG/campaign.env"
campaign_675_reseat_main "$MOCK_TAG" >/dev/null 2>&1
check "existing campaign identity mismatch is refused" 1 $?

if rg -n -e 'EPOCH_SHA=|campaign-675-[0-9a-f]{8}|origin/main' \
  scripts/campaign-675-driver.sh scripts/campaign-675-reseat.sh \
  scripts/campaign-675-supervisor.sh scripts/campaign-675-watchdog.sh >/dev/null; then
  check "helpers contain no hardcoded moving campaign identity" 0 1
else
  check "helpers contain no hardcoded moving campaign identity" 0 0
fi

echo
if [[ "$fails" -eq 0 ]]; then
  echo "campaign self-test: ALL PASS"
  exit 0
fi
echo "campaign self-test: $fails FAILED"
exit 1
