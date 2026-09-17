#!/usr/bin/env bash
# Deterministic validation of the #675 release baseline and row-outcome logic.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
E="$TMP/epoch"; mkdir -p "$E"
SHA="1111111111111111111111111111111111111111"
printf 'RELEASE_TAG=v9.9.9\nSOURCE_SHA=%s\n' "$SHA" > "$E/campaign.env"
cat > "$E/rows.tsv" <<'EOF'
row_id	tier	family	target	budget
full	1	tls-record	-	10M
mixed	1	tls-record	-	10M
short	1	tls-record	-	10M
rcbad	1	tls-record	-	10M
t2ok	2	quic	fuzz: packet parser preserves bounded slice and progress invariants	50M
t2wrong	2	quic	fuzz: packet parser preserves bounded slice and progress invariants	50M
t2bad	2	quic	fuzz: packet parser preserves bounded slice and progress invariants	50M
finding	2	quic	fuzz: packet parser preserves bounded slice and progress invariants	50M
crash-window	2	quic	fuzz: packet parser preserves bounded slice and progress invariants	50M
t2-tls-21	2	tls-record	fuzz: TLS record: codec fragmentation, coalescing, and sink saturation preserve exact consumption	10M
t2-tls-22	2	tls-record	fuzz: TLS record: encrypted stream cleanup preserves root errors across alerts and epoch transitions	10M
EOF
# shellcheck source=/dev/null
source scripts/campaign-675-row-state.sh
watchdog_for() {
  case "$1" in
    *G) echo 250000 ;;
    100M) echo 198000 ;;
    50M) echo 108000 ;;
    10M) echo 21600 ;;
    *) echo 108000 ;;
  esac
}

fails=0
check() { # name expected_rc actual_rc
  if [[ "$2" == "$3" ]]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s (want rc=%s got rc=%s)\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
mkrow() { # rid rc records... (status records use the row's canonical identity)
  local rid="$1" rc="$2"; shift 2
  mkdir -p "$E/$rid"; echo "$rc" > "$E/$rid/collect.rc"; printf 'remote_exit_code=%s\n' "$rc" > "$E/$rid/guest-state.env"; : > "$E/$rid/manifest.jsonl"
  local family target budget step
  family="$(awk -F '\t' -v r="$rid" '$1 == r { print $3; exit }' "$E/rows.tsv")"
  target="$(awk -F '\t' -v r="$rid" '$1 == r { print $4; exit }' "$E/rows.tsv")"
  budget="$(awk -F '\t' -v r="$rid" '$1 == r { print $5; exit }' "$E/rows.tsv")"
  case "$family" in quic) step=test-quic ;; tls-record) step=test-tls-record-fuzz ;; esac
  for st in "$@"; do printf '{"source_commit_sha":"%s","build_step":"%s","filter":"%s","budget_mutations":%s,"status":"%s"}\n' "$SHA" "$step" "$target" "${budget/M/000000}" "$st" >> "$E/$rid/manifest.jsonl"; done
}

# THE REGRESSION: family row, 3 targets passed then one failed.
mkrow mixed 1 pass fail
campaign_675_row_passed "$E" mixed 1 tls-record; check "driver and watchdog reject a family row with a later FAIL" 1 $?

# Complete tier-1 family row (the frozen plan supplies the expected targets).
mkrow full 0
while IFS=$'\t' read -r _ tier family target budget; do
  [[ "$tier" == 2 && "$family" == tls-record ]] || continue
  printf '{"source_commit_sha":"%s","build_step":"test-tls-record-fuzz","filter":"%s","budget_mutations":10000000,"status":"pass"}\n' "$SHA" "$target" >> "$E/full/manifest.jsonl"
done < "$E/rows.tsv"
campaign_675_row_passed "$E" full 1 tls-record; check "complete family row passes" 0 $?
printf '{"source_commit_sha":"%s","build_step":"test-tls-record-fuzz","filter":"fuzz: TLS record: codec fragmentation, coalescing, and sink saturation preserve exact consumption","budget_mutations":10000000,"status":"interrupted"}\n' "$SHA" >> "$E/full/manifest.jsonl"
campaign_675_row_passed "$E" full 1 tls-record; check "old interrupted evidence does not poison a canonical pass" 0 $?

# Truncated family row: all passes, but fewer than the family's targets, and no
# failure record -- the case a status-only check cannot see.
mkrow short 0 pass
campaign_675_row_passed "$E" short 1 tls-record; check "driver and watchdog reject a truncated family row" 1 $?

# Tier-2 single-target rows.
mkrow t2ok 0 pass;  campaign_675_row_passed "$E" t2ok 2 quic; check "tier-2 single pass" 0 $?
printf '{"source_commit_sha":"%s","build_step":"test-quic","filter":"fuzz: packet parser preserves bounded slice and progress invariants","budget_mutations":50000000,"status":"interrupted"}\n' "$SHA" >> "$E/t2ok/manifest.jsonl"
campaign_675_row_passed "$E" t2ok 2 quic; check "retry evidence remains append-only without blocking completion" 0 $?
mkrow t2wrong 0 pass
sed -i.bak "s/\"source_commit_sha\":\"$SHA\"/\"source_commit_sha\":\"2222222222222222222222222222222222222222\"/" "$E/t2wrong/manifest.jsonl"; rm -f "$E/t2wrong/manifest.jsonl.bak"
campaign_675_row_passed "$E" t2wrong 2 quic; check "wrong release SHA cannot satisfy a row" 1 $?
printf '{"source_commit_sha":"%s","build_step":"wrong-step","filter":"fuzz: packet parser preserves bounded slice and progress invariants","budget_mutations":50000000,"status":"pass"}\n' "$SHA" > "$E/identity.jsonl"
campaign_675_manifest_has_pass "$E/identity.jsonl" "$SHA" test-quic 'fuzz: packet parser preserves bounded slice and progress invariants' 50000000; check "wrong build step cannot satisfy a row" 1 $?
printf '{"source_commit_sha":"%s","build_step":"test-quic","filter":"wrong filter","budget_mutations":50000000,"status":"pass"}\n' "$SHA" > "$E/identity.jsonl"
campaign_675_manifest_has_pass "$E/identity.jsonl" "$SHA" test-quic 'fuzz: packet parser preserves bounded slice and progress invariants' 50000000; check "wrong target filter cannot satisfy a row" 1 $?
printf '{"source_commit_sha":"%s","build_step":"test-quic","filter":"fuzz: packet parser preserves bounded slice and progress invariants","budget_mutations":49999999,"status":"pass"}\n' "$SHA" > "$E/identity.jsonl"
campaign_675_manifest_has_pass "$E/identity.jsonl" "$SHA" test-quic 'fuzz: packet parser preserves bounded slice and progress invariants' 50000000; check "undersized budget cannot satisfy a row" 1 $?
mkrow t2bad 1 fail; campaign_675_row_passed "$E" t2bad 2 quic; check "tier-2 fail" 1 $?

# Non-zero collect exit overrides an all-pass manifest.
mkrow rcbad 1 pass
campaign_675_row_passed "$E" rcbad 1 tls-record; check "nonzero collect rc overrides manifest" 1 $?

# Missing collect.rc (pre-fix row) must not count.
mkdir -p "$E/norc"; printf '{"status":"pass"}\n' > "$E/norc/manifest.jsonl"
campaign_675_row_passed "$E" norc 2 quic; check "missing collect.rc is not a pass" 1 $?

# No manifest at all.
mkrow nomani 0; rm -f "$E/nomani/manifest.jsonl"
campaign_675_row_passed "$E" nomani 2 quic; check "no manifest is not a pass" 1 $?

# Crash window regression: a prior collector has copied and verified both
# archives, then vanished after remote-stage cleanup but before its old caller
# wrote collect.rc. Recovery is entirely local and never reattaches to PVE.
mkdir -p "$E/crash-window/archive"
printf 'payload\n' > "$E/crash-window/archive/evidence"
printf '{"source_commit_sha":"%s","build_step":"test-quic","filter":"fuzz: packet parser preserves bounded slice and progress invariants","budget_mutations":50000000,"status":"pass"}\n' "$SHA" > "$E/crash-window/archive/manifest.jsonl"
printf 'remote_exit_code=0\n' > "$E/crash-window/guest-state.env"
printf 'REMOTE_STAGE=/tmp/tardigrade-proxmox-fuzz-deleted\n' > "$E/crash-window/async.env"
cp "$E/crash-window/archive/manifest.jsonl" "$E/crash-window/manifest.jsonl"
tar -C "$E/crash-window/archive" -czf "$E/crash-window/guest-fuzz-artifacts.tgz" evidence manifest.jsonl
tar -C "$E/crash-window/archive" -czf "$E/crash-window/proxmox-metadata.tgz" evidence
campaign_675_recover_collected_row "$E/crash-window"; check "crash-window local evidence is recovered without REMOTE_STAGE" 0 $?
if [[ -f "$E/crash-window/evidence" ]]; then check "recovery restores a partially extracted evidence tree" 0 0; else check "recovery restores a partially extracted evidence tree" 0 1; fi
campaign_675_row_passed "$E" crash-window 2 quic; check "recovered crash-window row is classified locally" 0 $?

mkrow finding 2 fail
if [[ "$(campaign_675_row_disposition "$E" finding 2 quic)" == pending_finding ]]; then check "untriaged finding halts the campaign" 0 0; else check "untriaged finding halts the campaign" 0 1; fi
printf 'DISPOSITION=dispositioned_finding\nISSUE=#776\nFIX_COMMIT=deadbeef\nVERIFICATION=zig-build-test\n' > "$E/finding/disposition.env"
if [[ "$(campaign_675_row_disposition "$E" finding 2 quic)" == dispositioned_finding ]]; then check "triaged finding is durably accounted" 0 0; else check "triaged finding is durably accounted" 0 1; fi
printf 'DISPOSITION=dispositioned_finding\nISSUE=#675\nFIX_COMMIT=deadbeef\nVERIFICATION=zig-build-test\n' > "$E/finding/disposition.env"
if [[ "$(campaign_675_row_disposition "$E" finding 2 quic)" == pending_finding ]]; then check "epic issue cannot disposition a focused finding" 0 0; else check "epic issue cannot disposition a focused finding" 0 1; fi
printf 'DISPOSITION=dispositioned_finding\nISSUE=#776\n' > "$E/finding/disposition.env"
if [[ "$(campaign_675_row_disposition "$E" finding 2 quic)" == pending_finding ]]; then check "disposition requires fix and verification" 0 0; else check "disposition requires fix and verification" 0 1; fi

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
RELEASE_PLAN=$'row_id\ttier\tfamily\ttarget\tbudget\nrelease-smoke\t2\tquic\tfuzz: packet parser preserves bounded slice and progress invariants\t50M\n'
printf 'row_id\ttier\tfamily\ttarget\tbudget\ncontroller-only\t2\tquic\tfuzz: different controller target\t1K\n' > "$RELEASE_TMP/rows.tsv"
export CAMPAIGN_675_EVIDENCE_ROOT="$RELEASE_TMP/evidence"
export CAMPAIGN_675_ACTIVE_STATE="$RELEASE_TMP/evidence/campaign-675-active.env"
export CAMPAIGN_675_GIT_REMOTE="test-origin"
export CAMPAIGN_675_NO_START=true
MOCK_TAG="v9.9.9"
MOCK_SHA="1111111111111111111111111111111111111111"
MOCK_MAIN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GIT_CALLS=()
# shellcheck disable=SC2317,SC2329 # test double is invoked indirectly by campaign_675_reseat_main
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
    show)
      [[ "$ref" == "$MOCK_SHA:scripts/campaign-675-rows.tsv" ]] || return 1
      printf '%s' "$RELEASE_PLAN"
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
if [[ "$(cat "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG/rows.tsv")" == "${RELEASE_PLAN%$'\n'}" ]]; then check "campaign directory receives the selected release row plan" 0 0; else check "campaign directory receives the selected release row plan" 0 1; fi
if [[ "$(grep '^CAMPAIGN_STATE=' "$ACTIVE")" == "CAMPAIGN_STATE=$STATE" ]]; then check "active state points to the release baseline" 0 0; else check "active state points to the release baseline" 0 1; fi

first_state="$(cksum "$STATE")"
MOCK_MAIN="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
printf 'row_id\ttier\tfamily\ttarget\tbudget\ncontroller-mutated\t2\tquic\tfuzz: another target\t1K\n' > "$RELEASE_TMP/rows.tsv"
campaign_675_reseat_main "$MOCK_TAG" >/dev/null 2>&1
check "repeating a release invocation is idempotent" 0 $?
if [[ "$(cksum "$STATE")" == "$first_state" ]]; then check "main movement cannot change the tag baseline" 0 0; else check "main movement cannot change the tag baseline" 0 1; fi
if [[ "$(cat "$CAMPAIGN_675_EVIDENCE_ROOT/campaign-675-$MOCK_TAG/rows.tsv")" == "${RELEASE_PLAN%$'\n'}" ]]; then check "controller row-plan mutation cannot change the tag baseline" 0 0; else check "controller row-plan mutation cannot change the tag baseline" 0 1; fi
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
