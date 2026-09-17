#!/usr/bin/env bash
# Autonomous serial driver for the #675 campaign. Detached; survives the
# controlling session exiting. Runs ONE row at a time per #675, stops dead on
# the first non-pass per the stop-on-finding rule, and never destroys evidence.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

if [[ "$#" -gt 1 ]]; then
  printf 'usage: scripts/campaign-675-driver.sh [campaign-state]\n' >&2
  exit 64
fi
# shellcheck source=scripts/campaign-675-state.sh
source scripts/campaign-675-state.sh
# shellcheck source=scripts/campaign-675-row-state.sh
source scripts/campaign-675-row-state.sh
campaign_675_load_state "${1:-}" || {
  printf 'campaign-675-driver: no valid immutable campaign state\n' >&2
  exit 1
}

E="$CAMPAIGN_DIR"
PVE=root@192.168.86.50
IMAGE=/var/lib/vz/template/cache/debian-13-genericcloud-amd64-fuzz.qcow2
IMAGE_SHA=85a969b7e99d7c817414136033df18c58d5c45ac8d27bb36e8ccb67173d2d4e3
ZIG_SHA=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
LOG="$E/driver.log"

# Budget-aware watchdog. A blanket 250000s (69.4h) let a genuinely hung target
# grind for 23h+ without tripping anything -- the tls-record cleanup oracle,
# whose sibling finishes the same 10M budget in 64 minutes. These bounds sit
# above the slowest LEGITIMATE run measured for each budget class (10M family
# rows 0.9-3.7h; 50M H3 conn-state 23.4h) with real margin, so a severe
# regression surfaces in hours instead of days without false-positiving a slow
# but honest row.
watchdog_for() {
  case "$1" in
    *G) echo 250000 ;;
    100M) echo 198000 ;;
    50M) echo 108000 ;;
    10M) echo 21600 ;;
    *) echo 108000 ;;
  esac
}

say() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"; }

wait_for_row() {                      # $1 = row dir
  local stage; stage="$(grep -E '^REMOTE_STAGE=' "$1/async.env" 2>/dev/null | cut -d= -f2- | tr -d "'")"
  [[ -n "$stage" ]] || { say "ERROR no REMOTE_STAGE in $1/async.env"; return 1; }
  while ! ssh -n -o ConnectTimeout=20 "$PVE" "test -f '$stage/guest-state.env'" 2>/dev/null; do sleep 120; done
}

say "=== driver start, release $RELEASE_TAG @ $SOURCE_SHA ==="
mapfile -t QUEUE < "$E/rows.tsv"
say "queue loaded: $(( ${#QUEUE[@]} - 1 )) rows"
for line in "${QUEUE[@]}"; do
  IFS=$'\t' read -r rid tier family target budget <<<"$line"
  [[ "$rid" == "row_id" || -z "$rid" ]] && continue
  if campaign_675_row_passed "$E" "$rid" "$tier" "$family"; then say "SKIP $rid (already passed)"; continue; fi

  collected=no
  if campaign_675_row_collected "$E/$rid" || campaign_675_recover_collected_row "$E/$rid"; then
    # Do not reattach to a remote stage that successful collection has already
    # removed. This also repairs rows from the old caller-side-marker window.
    say "RECOVER $rid (verified local collection)"
    collected=yes
  elif [[ -f "$E/$rid/async.env" ]]; then
    say "RESUME $rid (already launched) - waiting"
  else
    [[ -z "$budget" ]] && { say "FATAL malformed queue row: $rid (budget empty)"; exit 1; }
  say "START $rid tier=$tier family=$family budget=$budget target=${target:-<family>}"
    args=(--start --target "$PVE" --bind "" --vm-image "$IMAGE"
          --vm-image-sha256 "$IMAGE_SHA" --zig-sha256 "$ZIG_SHA"
          --memory 6144 --vcpus 3 --tardigrade-ref "$SOURCE_SHA"
          --tier "$tier" --family "$family" --budget "$budget"
          --watchdog "$(watchdog_for "$budget")" --out-dir "$E/$rid")
    # rows.tsv uses "-" for a family-wide row: an EMPTY column cannot be used,
    # because TAB is an IFS whitespace char and `read` collapses adjacent tabs,
    # which silently shifted budget into target and broke every tier-1 row.
    [[ "$target" != "-" && -n "$target" ]] && args+=(--campaign-target "$target")
    if ! scripts/run-proxmox-fuzz-campaign.sh "${args[@]}" >>"$LOG" 2>&1; then
      say "FATAL launch failed for $rid - stopping"; exit 1
    fi
  fi

  if [[ "$collected" == no ]]; then
    wait_for_row "$E/$rid" || { say "FATAL cannot wait on $rid - stopping"; exit 1; }
    # Collect with retries. A transient SSH/network blip must NOT be mistaken for
    # a failed row: without this, one dropped packet during --collect halts the
    # whole campaign for however long nobody is watching.
    for attempt in 1 2 3 4 5; do
      say "COLLECT $rid (attempt $attempt)"
      scripts/run-proxmox-fuzz-campaign.sh --collect --out-dir "$E/$rid" >>"$LOG" 2>&1
      if campaign_675_row_collected "$E/$rid"; then break; fi
      # Distinguish "row genuinely did not pass" from "collection did not happen".
      if find "$E/$rid" -name manifest.jsonl -print -quit 2>/dev/null | grep -q .; then
        say "collected evidence lacks a durable result - not retrying"; break
      fi
      say "collection produced no manifest; retrying in 120s"
      sleep 120
    done
  fi
  runs="$(find "$E/$rid" -name stderr.log -exec grep -ho 'Runs: [0-9]* -> [0-9]*' {} \; 2>/dev/null | tail -1)"
  if campaign_675_row_passed "$E" "$rid" "$tier" "$family"; then
    say "PASS $rid  ${runs:-<no Runs line>}"
  else
    st="$(find "$E/$rid" -name manifest.jsonl -exec grep -ho '"status":"[a-z_]*"' {} \; 2>/dev/null | tail -1)"
    say "STOP: $rid did not pass (${st:-unknown}) ${runs:-}. Per #675 stop-on-finding, launching nothing further."
    say "Evidence left intact under $E/$rid. Triage required."
    exit 2
  fi
done
# Only claim completion if every queued row actually passed. The previous
# version logged "ALL ROWS COMPLETE" after one row because ssh inside the
# while-read loop consumed the rest of rows.tsv from stdin -- a false
# success, which is worse than a crash.
passed=0; total=0
for line in "${QUEUE[@]}"; do
  IFS=$'\t' read -r rid tier family _ _ <<<"$line"
  [[ "$rid" == "row_id" || -z "$rid" ]] && continue
  total=$((total+1)); campaign_675_row_passed "$E" "$rid" "$tier" "$family" && passed=$((passed+1))
done
if [[ "$passed" -eq "$total" ]]; then
  say "=== ALL ROWS COMPLETE ($passed/$total) ==="
else
  say "=== DRIVER EXITED WITH $passed/$total ROWS PASSED - INCOMPLETE ==="; exit 3
fi
