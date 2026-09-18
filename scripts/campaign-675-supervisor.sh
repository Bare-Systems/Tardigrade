#!/usr/bin/env bash
# Keeps the #675 driver alive across unexpected deaths (crash, OOM, killed
# shell) WITHOUT defeating the stop-on-finding rule.
#
# Driver exit codes:
#   0 -> all rows complete        -> supervisor exits, done.
#   4 -> queue exhausted; only    -> supervisor exits. Findings never stop
#        pending findings remain     the queue: the driver records each one in
#                                    findings.tsv and moves to the next row.
#   * -> unexpected death         -> restart (the driver is resumable: it skips
#                                    passed rows and re-attaches to a launched one).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
if [[ "$#" -gt 1 ]]; then
  printf 'usage: scripts/campaign-675-supervisor.sh [campaign-state]\n' >&2
  exit 64
fi
# shellcheck source=scripts/campaign-675-state.sh
source scripts/campaign-675-state.sh
campaign_675_load_state "${1:-}" || {
  printf 'campaign-675-supervisor: no valid immutable campaign state\n' >&2
  exit 1
}

LOG="$CAMPAIGN_DIR/driver.log"
say() { printf '%s SUPERVISOR %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >>"$LOG"; }
say "started for release $RELEASE_TAG @ $SOURCE_SHA"
while true; do
  scripts/campaign-675-driver.sh "$CAMPAIGN_STATE"
  rc=$?
  case "$rc" in
    0) say "driver reported all rows complete; supervisor exiting"; exit 0 ;;
    4) say "queue exhausted with pending findings (see findings.tsv); supervisor exiting"; exit 4 ;;
    3) say "driver exited incomplete (queue not finished); restarting in 30s"; sleep 30 ;;
    *) say "driver died unexpectedly (rc=$rc); restarting in 60s"; sleep 60 ;;
  esac
done
