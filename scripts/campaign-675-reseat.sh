#!/usr/bin/env bash
# Re-seat the #675 campaign onto whatever `main` currently is.
#
# Restarting is routine: fuzzing exists to find bugs, fixes land, the SHA moves.
# This makes that a one-command operation instead of a manual teardown dance.
# Idempotent - a no-op when main has not moved (unless --force).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
FORCE=false; [[ "${1:-}" == "--force" ]] && FORCE=true
PVE=root@192.168.86.50
PLIST="$HOME/Library/LaunchAgents/com.jaruso.tardigrade.campaign675.watchdog.plist"
say() { printf '%s reseat: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

git fetch origin --quiet || { say "FATAL git fetch failed"; exit 1; }
NEW=$(git rev-parse origin/main); SHORT=${NEW:0:8}
CUR=$(grep -m1 '^EPOCH_SHA=' scripts/campaign-675-driver.sh | cut -d= -f2)
if [[ "$NEW" == "$CUR" && "$FORCE" != true ]]; then say "main unchanged ($SHORT); nothing to do"; exit 0; fi
say "re-seating: ${CUR:0:8} -> $SHORT"

say "stopping driver/supervisor"
pkill -f campaign-675-supervisor.sh 2>/dev/null; pkill -f campaign-675-driver.sh 2>/dev/null; sleep 3

# Tear down any fuzz guest. --skiplock is required: a running guest refuses a
# plain stop, and a running guest refuses destroy.
for id in $(ssh -n -o ConnectTimeout=20 "$PVE" 'qm list | awk "/tardigrade-fuzz/{print \$1}"' 2>/dev/null); do
  say "destroying guest $id"
  ssh -n -o ConnectTimeout=20 "$PVE" "pkill -f orchestrate.sh; qm stop $id --skiplock 1 >/dev/null 2>&1; sleep 10; qm destroy $id --purge" >/dev/null 2>&1
done

say "checking out main @ $SHORT"
if ! git checkout main --quiet; then say "FATAL checkout failed"; exit 1; fi
if ! git reset --hard "$NEW" --quiet; then say "FATAL reset failed"; exit 1; fi

E="artifacts/hardening/fuzz/campaign-675-$SHORT"
mkdir -p "$E"
# Carry the row plan forward; regenerate only if it is missing.
PREV=""
for d in artifacts/hardening/fuzz/campaign-675-*/; do
  [[ -d "$d" && "$d" != *"$SHORT"* && -f "$d/rows.tsv" ]] || continue
  [[ -z "$PREV" || "$d" -nt "$PREV" ]] && PREV="$d"
done
[[ -f "$E/rows.tsv" ]] || cp "$PREV/rows.tsv" "$E/rows.tsv" 2>/dev/null
[[ -f "$E/rows.tsv" ]] || { say "FATAL no rows.tsv to carry forward"; exit 1; }
say "queue: $(( $(wc -l < "$E/rows.tsv") - 1 )) rows"

for f in scripts/campaign-675-driver.sh scripts/campaign-675-supervisor.sh scripts/campaign-675-watchdog.sh; do
  sed -i '' "s|campaign-675-[0-9a-f]\{8\}|campaign-675-$SHORT|g; s|EPOCH_SHA=[0-9a-f]*|EPOCH_SHA=$NEW|g" "$f"
done
sed -i '' "s|campaign-675-[0-9a-f]\{8\}|campaign-675-$SHORT|g" "$PLIST" 2>/dev/null
launchctl unload "$PLIST" 2>/dev/null; launchctl load "$PLIST" 2>/dev/null
say "watchdog repointed"

nohup caffeinate -i -s scripts/campaign-675-supervisor.sh >/dev/null 2>&1 &
sleep 5
say "campaign restarted on $SHORT (supervisor pid $!)"
say "log: $E/driver.log"
