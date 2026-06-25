#!/usr/bin/env bash
# Push a new benchmark baseline to the GitHub wiki Benchmark-History page.
#
# Usage:
#   ./benchmarks/update-wiki.sh <baseline.json> [--prev <prev-baseline.json>]
#
# What it does:
#   1. Clones the wiki into a temp dir
#   2. Generates a markdown report section from the baseline JSON
#   3. Prepends the new release section into Benchmark-History.md
#   4. Updates the summary table row
#   5. Commits and pushes
#
# Prerequisites: jq, git, report.sh, gh (for auth)
#
# The wiki repo is inferred from the current repo's GitHub remote.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_SH="$SCRIPT_DIR/report.sh"

# ── Args ──────────────────────────────────────────────────────────────────────
BASELINE_FILE=""
PREV_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prev) PREV_FILE="$2"; shift 2 ;;
        --help)
            grep '^#' "$0" | head -20 | sed 's/^# \?//'
            exit 0
            ;;
        -*)  echo "Unknown option: $1" >&2; exit 1 ;;
        *)   BASELINE_FILE="$1"; shift ;;
    esac
done

if [[ -z "$BASELINE_FILE" ]]; then
    echo "Usage: $0 <baseline.json> [--prev <prev-baseline.json>]" >&2
    exit 1
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Baseline file not found: $BASELINE_FILE" >&2
    exit 1
fi

# Auto-detect previous baseline if not specified
if [[ -z "$PREV_FILE" ]]; then
    PREV_FILE=$(ls -t "$SCRIPT_DIR/baselines/"*.json 2>/dev/null | grep -v "$(basename "$BASELINE_FILE")" | head -1 || true)
fi

# ── Extract metadata ──────────────────────────────────────────────────────────
TAG=$(jq -r '._meta.tag // "unknown"' "$BASELINE_FILE")
DATE=$(jq -r '._meta.timestamp // ""' "$BASELINE_FILE" | cut -c1-10)
TOOL=$(jq -r '._meta.tool // "unknown"' "$BASELINE_FILE")
CONN=$(jq -r '._meta.connections // "?"' "$BASELINE_FILE")
RUNS=$(jq -r '._meta.runs // 1' "$BASELINE_FILE")
DUR=$(jq  -r '._meta.duration_s // 30' "$BASELINE_FILE")
ENV=$(jq  -r '._meta.environment.cpu_model // ""' "$BASELINE_FILE")

get_scenario() {
    local field=$1 scenario=$2
    jq -r --arg s "$scenario" --arg f "$field" '.[$s][$f] // "—"' "$BASELINE_FILE"
}

fmt_rps() {
    local v; v=$(get_scenario rps "$1")
    [[ "$v" == "—" ]] && echo "—" && return
    printf "%'.0f" "$v"
}
fmt_stddev() {
    local v; v=$(get_scenario rps_stddev "$1")
    [[ "$v" == "—" || "$v" == "0" ]] && echo "" && return
    printf " ±%.0f" "$v"
}
fmt_errors() {
    get_scenario errors "$1"
}

STATIC_RPS=$(fmt_rps static-http1)
STATIC_SD=$(fmt_stddev static-http1)
PROXY_RPS=$(fmt_rps proxy-http1)
PROXY_SD=$(fmt_stddev proxy-http1)
KA_RPS=$(fmt_rps keepalive)
KA_SD=$(fmt_stddev keepalive)
ERRORS=$(fmt_errors static-http1)

# ── Infer wiki remote ─────────────────────────────────────────────────────────
REMOTE_URL=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo "")
if [[ -z "$REMOTE_URL" ]]; then
    echo "Could not determine git remote. Run from inside the Tardigrade repo." >&2
    exit 1
fi

# Convert https://github.com/Org/Repo.git  →  https://github.com/Org/Repo.wiki.git
WIKI_URL="${REMOTE_URL%.git}.wiki.git"

# ── Clone wiki into temp dir ──────────────────────────────────────────────────
WIKI_DIR=$(mktemp -d /tmp/tardigrade-wiki-XXXX)
trap 'rm -rf "$WIKI_DIR"' EXIT

echo "Cloning wiki from $WIKI_URL ..."
git clone --quiet "$WIKI_URL" "$WIKI_DIR"

HISTORY_FILE="$WIKI_DIR/Benchmark-History.md"

if [[ ! -f "$HISTORY_FILE" ]]; then
    echo "Benchmark-History.md not found in wiki — was the page created?" >&2
    exit 1
fi

# ── Generate the new release section ─────────────────────────────────────────
NEW_SECTION=$(cat <<SECTION

---

## ${TAG}

*${DATE} · ${TOOL} · https://127.0.0.1:8443 · ${RUNS} runs × ${DUR}s × ${CONN} connections · ${ENV}*

$(bash "$REPORT_SH" "$BASELINE_FILE" ${PREV_FILE:+--compare "$PREV_FILE"})
SECTION
)

# ── Update summary table ──────────────────────────────────────────────────────
# Insert a new row after the header rows (| Release | ... | and | --- | ... |)
PREV_TAG=""
[[ -n "$PREV_FILE" ]] && PREV_TAG=$(jq -r '._meta.tag // "unknown"' "$PREV_FILE")

NEW_ROW="| [${TAG}](#${TAG//.}) | ${DATE} | ${TOOL} | ${CONN} | ${STATIC_RPS}${STATIC_SD} | ${PROXY_RPS}${PROXY_SD} | ${KA_RPS}${KA_SD} | ${ERRORS} |"

# Check if this tag already has a row (update vs insert)
if grep -q "\[${TAG}\]" "$HISTORY_FILE" 2>/dev/null; then
    echo "Tag ${TAG} already in summary table — skipping row insert (section will still be prepended)."
else
    # Insert after the header separator row (| --- | ... |)
    awk -v row="$NEW_ROW" '
        /^\| --- \|/ && !inserted {
            print; print row; inserted=1; next
        }
        { print }
    ' "$HISTORY_FILE" > "${HISTORY_FILE}.tmp" && mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"
fi

# ── Prepend the new section before the first "---" divider ───────────────────
# (i.e., before the first existing release section)
awk -v section="$NEW_SECTION" '
    /^---$/ && !inserted {
        print section
        inserted = 1
    }
    { print }
' "$HISTORY_FILE" > "${HISTORY_FILE}.tmp" && mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"

# ── Commit and push ───────────────────────────────────────────────────────────
cd "$WIKI_DIR"
git add Benchmark-History.md
git diff --cached --quiet && { echo "No changes to wiki — already up to date."; exit 0; }

git commit -m "Benchmark History: add ${TAG} baseline (${DATE})"
git push

echo ""
echo "Wiki updated: https://github.com/Bare-Systems/Tardigrade/wiki/Benchmark-History"
