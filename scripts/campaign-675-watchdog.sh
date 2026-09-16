#!/usr/bin/env bash
# Every-2h health check for the #675 campaign. Self-heals an unexpectedly dead
# supervisor; deliberately does NOT restart one that stopped on a finding.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
E=artifacts/hardening/fuzz/campaign-675-1c7b51b7
LOG="$E/driver.log"
STATUS="$E/STATUS.txt"
now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# Count ROWS that passed, not manifest RECORDS. A tier-1 family row emits one
# record per target in the family (t1-01 alone emitted 5), so counting records
# overstated progress -- it reported 10/62 when 6 rows had passed. Row ids come
# from rows.tsv so sibling dirs (preflight/, findings/, runs/) are never counted.
passed=0
while IFS=$'\t' read -r rid _rest; do
  [[ "$rid" == "row_id" || -z "$rid" ]] && continue
  if find "$E/$rid" -name manifest.jsonl -exec grep -l '"status":"pass"' {} \; 2>/dev/null | grep -q .; then
    passed=$((passed+1))
  fi
done < "$E/rows.tsv"
total=$(( $(wc -l < "$E/rows.tsv" 2>/dev/null || echo 1) - 1 ))
alive=no; pgrep -f "campaign-675-supervisor.sh" >/dev/null && alive=yes
last_evt=$(grep -E "PASS|STOP:|FATAL|START|COMPLETE|INCOMPLETE" "$LOG" 2>/dev/null | tail -1)
# A finding (STOP) is terminal until a human triages it.
halted=no
grep -q "STOP:" <<<"$last_evt" && halted=yes
grep -qE "triage required" <<<"$(tail -3 "$LOG" 2>/dev/null)" && halted=yes
# Staleness must measure DRIVER progress, not file mtime: this watchdog appends
# to the same log every 2h, so mtime always looked fresh and the check could
# never fire. Use the timestamp of the last real driver event instead.
last_drv=$(grep -E "PASS|STOP:|FATAL|START|COMPLETE|INCOMPLETE" "$LOG" 2>/dev/null | tail -1 | awk '{print $1}')
if [[ -n "$last_drv" ]]; then
  last_s=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$last_drv" +%s 2>/dev/null || echo 0)
else
  last_s=0
fi
if [[ "$last_s" -gt 0 ]]; then age_h=$(( ( $(date +%s) - last_s ) / 3600 )); else age_h=0; fi

{
  echo "checked_utc=$(now)"
  echo "rows_passed=$passed/$total"
  echo "supervisor_alive=$alive"
  echo "halted_on_finding=$halted"
  echo "hours_since_last_driver_event=$age_h"
  echo "last_event=$last_evt"
} > "$STATUS"

action="none"
if [[ "$halted" == yes ]]; then
  action="HALTED ON FINDING - human triage required, not restarting"
elif [[ "$alive" == no && "$passed" -lt "$total" ]]; then
  nohup caffeinate -i -s scripts/campaign-675-supervisor.sh >/dev/null 2>&1 &
  action="supervisor was dead; restarted"
elif [[ "$age_h" -ge 6 && "$alive" == yes ]]; then
  action="WARNING stale: no driver progress for ${age_h}h"
fi
echo "action=$action" >> "$STATUS"
printf '%s WATCHDOG passed=%s/%s alive=%s halted=%s age=%sh action=%s\n' \
  "$(now)" "$passed" "$total" "$alive" "$halted" "$age_h" "$action" >> "$LOG"
