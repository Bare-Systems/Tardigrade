#!/usr/bin/env bash
# Generate a markdown performance report from a benchmarks/run.sh JSON results file.
#
# Usage:
#   ./benchmarks/report.sh <results.json>                              # print to stdout
#   ./benchmarks/report.sh <results.json> --compare <baseline.json>   # add Δ column vs baseline
#   ./benchmarks/report.sh <results.json> --update-readme <file>      # update README in-place
#
# The README update mode replaces content between:
#   <!-- BENCHMARK_REPORT_START --> and <!-- BENCHMARK_REPORT_END -->
#
# Prerequisites: jq

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
RESULTS_FILE=""
UPDATE_README=""
COMPARE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-readme) UPDATE_README="$2"; shift 2 ;;
        --compare)       COMPARE_FILE="$2";  shift 2 ;;
        --help)
            sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1
            exit 0
            ;;
        -*)  echo "Unknown option: $1" >&2; exit 1 ;;
        *)   RESULTS_FILE="$1"; shift ;;
    esac
done

if [[ -z "$RESULTS_FILE" ]]; then
    echo "Usage: $0 <results.json> [--compare <baseline.json>] [--update-readme <readme.md>]" >&2
    exit 1
fi

if [[ ! -f "$RESULTS_FILE" ]]; then
    echo "Results file not found: $RESULTS_FILE" >&2
    exit 1
fi

if [[ -n "$COMPARE_FILE" && ! -f "$COMPARE_FILE" ]]; then
    echo "Baseline file not found: $COMPARE_FILE" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "jq is required but not installed." >&2
    exit 1
fi

# ── Extract metadata ──────────────────────────────────────────────────────────
meta_tag=$(jq    -r '._meta.tag              // "unknown"' "$RESULTS_FILE")
meta_ts=$(jq     -r '._meta.timestamp        // "unknown"' "$RESULTS_FILE")
meta_tool=$(jq   -r '._meta.tool             // "unknown"' "$RESULTS_FILE")
meta_host=$(jq   -r '._meta.host             // "unknown"' "$RESULTS_FILE")
meta_driver=$(jq -r '._meta.driver           // "unknown"' "$RESULTS_FILE")
meta_env=$(jq    -r '._meta.environment_name // "unknown"' "$RESULTS_FILE")
meta_workers=$(jq -r '._meta.worker_count    // "?"'       "$RESULTS_FILE")
meta_config=$(jq -r '._meta.config_label     // "unknown"' "$RESULTS_FILE")
meta_dur=$(jq    -r '._meta.duration_s       // "?"'       "$RESULTS_FILE")
meta_conn=$(jq   -r '._meta.connections      // "?"'       "$RESULTS_FILE")

cmp_tag=""
if [[ -n "$COMPARE_FILE" ]]; then
    cmp_tag=$(jq -r '._meta.tag // "unknown"' "$COMPARE_FILE")
fi

# ── Delta formatting ──────────────────────────────────────────────────────────
# Returns "+X.X%" / "-X.X%" with a warning emoji on regressions > 5%.
format_delta() {
    local cur=$1 prev=$2
    # Both must be non-zero numbers
    if [[ "$prev" == "null" || "$prev" == "0" || "$cur" == "null" || "$cur" == "0" ]]; then
        echo "n/a"
        return
    fi
    awk -v cur="$cur" -v prev="$prev" 'BEGIN {
        pct = (cur - prev) / prev * 100
        sign = (pct >= 0) ? "+" : ""
        badge = (pct < -5) ? " ⚠️" : ""
        printf "%s%.1f%%%s\n", sign, pct, badge
    }'
}

# ── Build markdown table ──────────────────────────────────────────────────────
build_table() {
    local has_compare=0
    [[ -n "$COMPARE_FILE" ]] && has_compare=1

    local header
    if [[ $has_compare -eq 1 ]]; then
        header="| Scenario | req/s | Δ vs ${cmp_tag} | p50 (ms) | p95 (ms) | p99 (ms) | p999 (ms) | CPU % | Peak RSS (MiB) | MB/s | Errors |"$'\n'
        header+="| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    else
        header="| Scenario | req/s | p50 (ms) | p95 (ms) | p99 (ms) | p999 (ms) | CPU % | Peak RSS (MiB) | MB/s | Errors |"$'\n'
        header+="| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    fi

    local rows=""
    while IFS= read -r scenario; do
        [[ "$scenario" == "_meta" ]] && continue
        local rps p50 p95 p99 p999 errors tput tput_raw cpu cpu_raw rss rss_raw
        rps=$(jq      -r --arg s "$scenario" '.[$s].rps            // 0'      "$RESULTS_FILE" | awk '{printf "%\x27.0f", $1}')
        rps_raw=$(jq  -r --arg s "$scenario" '.[$s].rps            // 0'      "$RESULTS_FILE")
        p50=$(jq      -r --arg s "$scenario" '.[$s].p50_ms         // 0'      "$RESULTS_FILE" | awk '{printf "%.1f", $1}')
        p95=$(jq      -r --arg s "$scenario" '.[$s].p95_ms         // "null"' "$RESULTS_FILE")
        p99=$(jq      -r --arg s "$scenario" '.[$s].p99_ms         // 0'      "$RESULTS_FILE" | awk '{printf "%.1f", $1}')
        p999=$(jq     -r --arg s "$scenario" '.[$s].p999_ms        // "null"' "$RESULTS_FILE")
        errors=$(jq   -r --arg s "$scenario" '.[$s].errors         // 0'      "$RESULTS_FILE")
        tput_raw=$(jq -r --arg s "$scenario" '.[$s].throughput_mbps // "null"' "$RESULTS_FILE")
        cpu_raw=$(jq  -r --arg s "$scenario" '.[$s].cpu_pct_avg    // "null"' "$RESULTS_FILE")
        rss_raw=$(jq  -r --arg s "$scenario" '.[$s].rss_mb_peak    // "null"' "$RESULTS_FILE")

        if [[ "$p95"  == "null" ]]; then p95="-";  else p95=$(echo  "$p95"  | awk '{printf "%.1f", $1}'); fi
        if [[ "$p999" == "null" ]]; then p999="-"; else p999=$(echo "$p999" | awk '{printf "%.1f", $1}'); fi
        if [[ "$tput_raw" == "null" ]]; then tput="-"; else tput=$(echo "$tput_raw" | awk '{printf "%.1f", $1}'); fi
        if [[ "$cpu_raw"  == "null" ]]; then cpu="-";  else cpu=$(echo  "$cpu_raw"  | awk '{printf "%.1f", $1}'); fi
        if [[ "$rss_raw"  == "null" ]]; then rss="-";  else rss=$(echo  "$rss_raw"  | awk '{printf "%.1f", $1}'); fi

        if [[ $has_compare -eq 1 ]]; then
            prev_rps=$(jq -r --arg s "$scenario" '.[$s].rps // "null"' "$COMPARE_FILE")
            delta=$(format_delta "$rps_raw" "$prev_rps")
            rows+=$'\n'"| \`${scenario}\` | ${rps} | ${delta} | ${p50} | ${p95} | ${p99} | ${p999} | ${cpu} | ${rss} | ${tput} | ${errors} |"
        else
            rows+=$'\n'"| \`${scenario}\` | ${rps} | ${p50} | ${p95} | ${p99} | ${p999} | ${cpu} | ${rss} | ${tput} | ${errors} |"
        fi
    done < <(jq -r 'keys[]' "$RESULTS_FILE" | sort)

    printf '%s%s\n' "$header" "$rows"
}

# ── Compose full report block ─────────────────────────────────────────────────
build_report() {
    local table; table=$(build_table)
    local date_part="${meta_ts%%T*}"   # YYYY-MM-DD
    local compare_note=""
    if [[ -n "$COMPARE_FILE" ]]; then
        compare_note=$'\n'"$(printf '> Δ column compares req/s against **%s** baseline. ⚠️ = regression > 5%%.' "$cmp_tag")"
    fi

    cat <<EOF
${table}

> **${meta_tag}** · ${date_part} · tool: \`${meta_tool}\` · ${meta_conn} connections · ${meta_dur}s per scenario · host: \`${meta_host}\`
> driver: \`${meta_driver}\` · env: \`${meta_env}\` · workers: \`${meta_workers}\` · config: \`${meta_config}\`
> CPU/RSS columns are sampled from the target Tardigrade process only when the run used \`--pid\` or \`--pid-file\`; otherwise they remain \`-\`.${compare_note}
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
