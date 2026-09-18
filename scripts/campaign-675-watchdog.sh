#!/usr/bin/env bash
# Every-2h health check for the #675 campaign. Self-heals an unexpectedly dead
# supervisor while rows remain; findings are recorded, never a reason to stop.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
if [[ "$#" -gt 1 ]]; then
  printf 'usage: scripts/campaign-675-watchdog.sh [campaign-state]\n' >&2
  exit 64
fi
# shellcheck source=scripts/campaign-675-state.sh
source scripts/campaign-675-state.sh
# shellcheck source=scripts/campaign-675-row-state.sh
source scripts/campaign-675-row-state.sh
campaign_675_load_state "${1:-}" || {
  printf 'campaign-675-watchdog: no valid immutable campaign state\n' >&2
  exit 1
}

E="$CAMPAIGN_DIR"
LOG="$E/driver.log"
STATUS="$E/STATUS.txt"
now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# Count ROWS that passed, not manifest RECORDS. A tier-1 family row emits one
# record per target in the family (t1-01 alone emitted 5), so counting records
# overstated progress -- it reported 10/62 when 6 rows had passed. Row ids come
# from rows.tsv so sibling dirs (preflight/, findings/, runs/) are never counted.
passed=0; findings=0; accounted=0; pending_findings=0
while IFS=$'\t' read -r rid tier family _rest; do
  [[ "$rid" == "row_id" || -z "$rid" ]] && continue
  disposition="$(campaign_675_row_disposition "$E" "$rid" "$tier" "$family")"
  [[ "$disposition" == pass ]] && { passed=$((passed+1)); accounted=$((accounted+1)); }
  [[ "$disposition" == dispositioned_finding ]] && { findings=$((findings+1)); accounted=$((accounted+1)); }
  [[ "$disposition" == pending_finding ]] && pending_findings=$((pending_findings+1))
done < "$E/rows.tsv"
total=$(( $(wc -l < "$E/rows.tsv" 2>/dev/null || echo 1) - 1 ))
alive=no; pgrep -f "campaign-675-supervisor.sh $CAMPAIGN_STATE" >/dev/null && alive=yes
last_evt=$(grep -E "PASS|FINDING|FATAL|START|COMPLETE|INCOMPLETE|EXHAUSTED" "$LOG" 2>/dev/null | tail -1)
# Findings never halt the queue: rows that are neither accounted nor pending
# are the only work left for the driver.
unfinished=$((total - accounted - pending_findings))
# findings.tsv is written by the driver; findings-issues.tsv by the scheduled
# campaign check once it has filed (or linked) a GitHub issue for a finding.
findings_logged=0; findings_unfiled=0
if [[ -f "$E/findings.tsv" ]]; then
  findings_logged=$(awk 'NR > 1' "$E/findings.tsv" | wc -l | tr -d ' ')
  findings_unfiled=$(awk -F '\t' 'FNR == NR { if (FNR > 1) filed[$1] = 1; next } FNR > 1 && !($8 in filed)' \
    "$E/findings-issues.tsv" "$E/findings.tsv" 2>/dev/null | wc -l | tr -d ' ')
  [[ -f "$E/findings-issues.tsv" ]] || findings_unfiled="$findings_logged"
fi
# Staleness must measure DRIVER progress, not file mtime: this watchdog appends
# to the same log every 2h, so mtime always looked fresh and the check could
# never fire. Use the timestamp of the last real driver event instead.
last_drv=$(grep -E "PASS|FINDING|FATAL|START|COMPLETE|INCOMPLETE|EXHAUSTED" "$LOG" 2>/dev/null | tail -1 | awk '{print $1}')
if [[ -n "$last_drv" ]]; then
  last_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$last_drv" +%s 2>/dev/null || echo 0)
else
  last_s=0
fi
if [[ "$last_s" -gt 0 ]]; then age_h=$(( ( $(date +%s) - last_s ) / 3600 )); else age_h=0; fi
# A negative age means the timestamp parse went wrong; treat as unknown (0)
# rather than reporting nonsense that would also defeat the staleness check.
[[ "$age_h" -lt 0 ]] && age_h=0

{
  echo "checked_utc=$(now)"
  echo "rows_passed=$passed/$total"
  echo "rows_dispositioned_findings=$findings"
  echo "rows_accounted=$accounted/$total"
  echo "supervisor_alive=$alive"
  echo "rows_pending_findings=$pending_findings"
  echo "rows_unfinished=$unfinished"
  echo "findings_logged=$findings_logged"
  echo "findings_without_issue=$findings_unfiled"
  echo "hours_since_last_driver_event=$age_h"
  echo "last_event=$last_evt"
} > "$STATUS"

# The driver logs only at row start/end, so "no driver event" is normal for the
# whole duration of a long row. A flat 6h threshold falsely flagged the 50M H3
# row (legitimately ~23h) as stale at hour 9. Staleness is now measured against
# the in-flight row's own watchdog bound: warn only once it has exceeded what a
# legitimate run of that budget could take.
cur_budget=$(grep -E "START" "$LOG" 2>/dev/null | tail -1 | grep -o 'budget=[0-9]*[MG]' | cut -d= -f2)
case "$cur_budget" in
  10M) stale_h=6 ;; 50M) stale_h=30 ;; 100M) stale_h=55 ;; *G) stale_h=70 ;; *) stale_h=30 ;;
esac
action="none"
if [[ "$alive" == no && "$unfinished" -eq 0 ]]; then
  action="queue exhausted ($pending_findings pending findings); nothing to restart"
elif [[ "$alive" == no ]]; then
  nohup caffeinate -i -s scripts/campaign-675-supervisor.sh "$CAMPAIGN_STATE" >/dev/null 2>&1 &
  action="supervisor was dead; restarted"
elif [[ "$alive" == yes && "$age_h" -ge "$stale_h" ]]; then
  action="WARNING stale: no driver progress for ${age_h}h (row budget ${cur_budget:-?} bound ${stale_h}h)"
fi
echo "action=$action" >> "$STATUS"
printf '%s WATCHDOG passed=%s findings=%s accounted=%s/%s pending=%s unfiled=%s alive=%s age=%sh action=%s\n' \
  "$(now)" "$passed" "$findings" "$accounted" "$total" "$pending_findings" "$findings_unfiled" "$alive" "$age_h" "$action" >> "$LOG"
