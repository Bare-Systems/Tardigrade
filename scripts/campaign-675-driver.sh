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
RUNNER="${CAMPAIGN_675_RUNNER:-scripts/run-proxmox-fuzz-campaign.sh}"

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
  disposition="$(campaign_675_row_disposition "$E" "$rid" "$tier" "$family")"
  if [[ "$disposition" == pass ]]; then say "SKIP $rid (already passed)"; continue; fi
  if [[ "$disposition" == dispositioned_finding ]]; then say "ACCOUNTED FINDING $rid"; continue; fi
  if [[ "$disposition" == pending_finding ]]; then
    say "STOP: $rid is a pending finding. Triage and write disposition.env before continuing."
    exit 2
  fi

  row_root="$E/$rid"
  row_dir="$row_root"
  current_attempt="$row_root/current-attempt"
  collected=no
  if [[ -f "$current_attempt" ]]; then
    candidate="$(cat "$current_attempt")"
    if [[ -f "$candidate/async.env" ]] && ! campaign_675_row_collected "$candidate"; then
      row_dir="$candidate"
      say "RESUME $rid (attempt $(basename "$row_dir") already launched) - waiting"
    else
      rm -f "$current_attempt"
    fi
  fi
  if [[ "$row_dir" == "$row_root" ]] && (campaign_675_row_collected "$row_root" || campaign_675_recover_collected_row "$row_root"); then
    # Do not reattach to a remote stage that successful collection has already
    # removed. This also repairs rows from the old caller-side-marker window.
    if [[ "$disposition" == interrupted ]]; then
      row_dir="$row_root/attempts/$(date -u '+%Y%m%dT%H%M%SZ')-$$-$RANDOM"
      mkdir -p "$row_dir" || exit 1
      printf '%s\n' "$row_dir" > "$current_attempt"
      say "RETRY $rid (preserved interrupted evidence; new attempt $(basename "$row_dir"))"
    else
      say "RECOVER $rid (verified local collection)"
      collected=yes
    fi
  elif [[ -f "$row_dir/async.env" ]]; then
    say "RESUME $rid (already launched) - waiting"
  else
    [[ -z "$budget" ]] && { say "FATAL malformed queue row: $rid (budget empty)"; exit 1; }
  say "START $rid tier=$tier family=$family budget=$budget target=${target:-<family>}"
    args=(--start --target "$PVE" --bind "" --vm-image "$IMAGE"
          --vm-image-sha256 "$IMAGE_SHA" --zig-sha256 "$ZIG_SHA"
          --memory 6144 --vcpus 3 --tardigrade-ref "$SOURCE_SHA"
          --release-tag "$RELEASE_TAG"
          --tier "$tier" --family "$family" --budget "$budget"
          --watchdog "$(watchdog_for "$budget")" --out-dir "$row_dir")
    # rows.tsv uses "-" for a family-wide row: an EMPTY column cannot be used,
    # because TAB is an IFS whitespace char and `read` collapses adjacent tabs,
    # which silently shifted budget into target and broke every tier-1 row.
    [[ "$target" != "-" && -n "$target" ]] && args+=(--campaign-target "$target")
    if ! "$RUNNER" "${args[@]}" >>"$LOG" 2>&1; then
      say "FATAL launch failed for $rid - stopping"; exit 1
    fi
  fi

  if [[ "$collected" == no ]]; then
    wait_for_row "$row_dir" || { say "FATAL cannot wait on $rid - stopping"; exit 1; }
    # Collect with retries. A transient SSH/network blip must NOT be mistaken for
    # a failed row: without this, one dropped packet during --collect halts the
    # whole campaign for however long nobody is watching.
    for attempt in 1 2 3 4 5; do
      say "COLLECT $rid (attempt $attempt)"
      "$RUNNER" --collect --out-dir "$row_dir" >>"$LOG" 2>&1
      if campaign_675_row_collected "$row_dir"; then break; fi
      say "collection is not durable; retrying this exact attempt in 120s"
      sleep 120
    done
  fi
  if ! campaign_675_row_collected "$row_dir"; then
    say "collection not durable for $rid; preserving current-attempt for resume"
    exit 1
  fi
  [[ -f "$current_attempt" && "$(cat "$current_attempt")" == "$row_dir" ]] && rm -f "$current_attempt"
  runs="$(find "$E/$rid" -name stderr.log -exec grep -ho 'Runs: [0-9]* -> [0-9]*' {} \; 2>/dev/null | tail -1)"
  post="$(campaign_675_row_disposition "$E" "$rid" "$tier" "$family")"
  case "$post" in
    pass)
      say "PASS $rid  ${runs:-<no Runs line>}"
      ;;
    dispositioned_finding)
      say "ACCOUNTED FINDING $rid"
      ;;
    interrupted)
      say "RETRY $rid after preserved interruption"
      exec "$0" "$CAMPAIGN_STATE"
      ;;
    pending_finding)
      st="$(find "$E/$rid" -name manifest.jsonl -exec grep -ho '"status":"[a-z_]*"' {} \; 2>/dev/null | tail -1)"
      say "STOP: $rid produced a durable finding (${st:-unknown}) ${runs:-}. Triage required."
      say "Evidence left intact under $E/$rid."
      exit 2
      ;;
    *)
      say "FATAL unknown row disposition '$post' for $rid"
      exit 1
      ;;
  esac
done
# Only claim completion if every queued row actually passed. The previous
# version logged "ALL ROWS COMPLETE" after one row because ssh inside the
# while-read loop consumed the rest of rows.tsv from stdin -- a false
# success, which is worse than a crash.
passed=0; findings=0; total=0; accounted=0
for line in "${QUEUE[@]}"; do
  IFS=$'\t' read -r rid tier family _ _ <<<"$line"
  [[ "$rid" == "row_id" || -z "$rid" ]] && continue
  total=$((total+1))
  disposition="$(campaign_675_row_disposition "$E" "$rid" "$tier" "$family")"
  [[ "$disposition" == pass ]] && { passed=$((passed+1)); accounted=$((accounted+1)); }
  [[ "$disposition" == dispositioned_finding ]] && { findings=$((findings+1)); accounted=$((accounted+1)); }
done
if [[ "$accounted" -eq "$total" ]]; then
  say "=== ALL ROWS ACCOUNTED ($passed pass, $findings dispositioned findings; $total total) ==="
else
  say "=== DRIVER EXITED WITH $accounted/$total ROWS ACCOUNTED - INCOMPLETE ==="; exit 3
fi
