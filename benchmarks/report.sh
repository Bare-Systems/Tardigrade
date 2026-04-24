#!/usr/bin/env bash
# Generate a markdown performance report from a benchmarks/run.sh JSON results file.
#
# Usage:
#   ./benchmarks/report.sh <results.json>                            # print to stdout
#   ./benchmarks/report.sh <results.json> --update-readme <file>    # update README in-place
#
# The README update mode replaces content between:
#   <!-- BENCHMARK_REPORT_START --> and <!-- BENCHMARK_REPORT_END -->
#
# Prerequisites: jq

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
RESULTS_FILE=""
UPDATE_README=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-readme) UPDATE_README="$2"; shift 2 ;;
        --help)
            sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1
            exit 0
            ;;
        -*)  echo "Unknown option: $1" >&2; exit 1 ;;
        *)   RESULTS_FILE="$1"; shift ;;
    esac
done

if [[ -z "$RESULTS_FILE" ]]; then
    echo "Usage: $0 <results.json> [--update-readme <readme.md>]" >&2
    exit 1
fi

if [[ ! -f "$RESULTS_FILE" ]]; then
    echo "Results file not found: $RESULTS_FILE" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "jq is required but not installed." >&2
    exit 1
fi

# ── Extract metadata ──────────────────────────────────────────────────────────
meta_tag=$(jq -r '._meta.tag       // "unknown"' "$RESULTS_FILE")
meta_ts=$(jq  -r '._meta.timestamp // "unknown"' "$RESULTS_FILE")
meta_tool=$(jq -r '._meta.tool     // "unknown"' "$RESULTS_FILE")
meta_host=$(jq -r '._meta.host     // "unknown"' "$RESULTS_FILE")
meta_dur=$(jq  -r '._meta.duration_s // "?"'     "$RESULTS_FILE")
meta_conn=$(jq -r '._meta.connections // "?"'    "$RESULTS_FILE")

# ── Build markdown table ──────────────────────────────────────────────────────
build_table() {
    local header
    header="| Scenario | req/s | p50 (ms) | p99 (ms) | Errors |"$'\n'
    header+="| --- | ---: | ---: | ---: | ---: |"

    local rows=""
    while IFS= read -r scenario; do
        [[ "$scenario" == "_meta" ]] && continue
        local rps p50 p99 errors
        rps=$(jq    -r --arg s "$scenario" '.[$s].rps    // 0' "$RESULTS_FILE" | awk '{printf "%\x27.0f", $1}')
        p50=$(jq    -r --arg s "$scenario" '.[$s].p50_ms // 0' "$RESULTS_FILE" | awk '{printf "%.1f", $1}')
        p99=$(jq    -r --arg s "$scenario" '.[$s].p99_ms // 0' "$RESULTS_FILE" | awk '{printf "%.1f", $1}')
        errors=$(jq -r --arg s "$scenario" '.[$s].errors // 0' "$RESULTS_FILE")
        rows+=$'\n'"| \`${scenario}\` | ${rps} | ${p50} | ${p99} | ${errors} |"
    done < <(jq -r 'keys[]' "$RESULTS_FILE" | sort)

    printf '%s%s\n' "$header" "$rows"
}

# ── Compose full report block ─────────────────────────────────────────────────
build_report() {
    local table; table=$(build_table)
    local date_part="${meta_ts%%T*}"   # YYYY-MM-DD

    cat <<EOF
${table}

> **${meta_tag}** · ${date_part} · tool: \`${meta_tool}\` · ${meta_conn} connections · ${meta_dur}s per scenario · host: \`${meta_host}\`
>
> Run \`./benchmarks/run.sh --save benchmarks/baselines/\$(git describe --tags).json\` then \`./benchmarks/report.sh <file> --update-readme README.md\` to refresh this table.
EOF
}

REPORT=$(build_report)

# ── Output ────────────────────────────────────────────────────────────────────
if [[ -z "$UPDATE_README" ]]; then
    echo "$REPORT"
    exit 0
fi

if [[ ! -f "$UPDATE_README" ]]; then
    echo "README file not found: $UPDATE_README" >&2
    exit 1
fi

# Write the replacement to a temp file so awk can read it with getline —
# passing multi-line strings via awk -v is not portable (fails on BSD awk).
rep_tmp=$(mktemp /tmp/tardi-report-XXXX.md)
printf '%s\n' "$REPORT" > "$rep_tmp"

awk \
    -v repfile="$rep_tmp" \
    '
    /<!-- BENCHMARK_REPORT_START -->/ {
        print
        while ((getline line < repfile) > 0) print line
        in_block = 1
        next
    }
    /<!-- BENCHMARK_REPORT_END -->/ {
        in_block = 0
    }
    !in_block { print }
    ' "$UPDATE_README" > "${UPDATE_README}.tmp" \
    && mv "${UPDATE_README}.tmp" "$UPDATE_README"
rm -f "$rep_tmp"

echo "Updated: $UPDATE_README"
