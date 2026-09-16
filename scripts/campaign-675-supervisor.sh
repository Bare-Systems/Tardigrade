#!/usr/bin/env bash
# Keeps the #675 driver alive across unexpected deaths (crash, OOM, killed
# shell) WITHOUT defeating the stop-on-finding rule.
#
# Driver exit codes:
#   0 -> all rows complete        -> supervisor exits, done.
#   2 -> a row did not pass       -> STOP. #675 requires triage before more
#                                    rows; restarting would trample it.
#   * -> unexpected death         -> restart (the driver is resumable: it skips
#                                    passed rows and re-attaches to a launched one).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
LOG=artifacts/hardening/fuzz/campaign-675-92dc8a4a/driver.log
say() { printf '%s SUPERVISOR %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >>"$LOG"; }
say "started"
while true; do
  scripts/campaign-675-driver.sh
  rc=$?
  case "$rc" in
    0) say "driver reported all rows complete; supervisor exiting"; exit 0 ;;
    2) say "driver stopped on a non-passing row; NOT restarting (triage required)"; exit 2 ;;
    3) say "driver exited incomplete (queue not finished); restarting in 30s"; sleep 30 ;;
    *) say "driver died unexpectedly (rc=$rc); restarting in 60s"; sleep 60 ;;
  esac
done
