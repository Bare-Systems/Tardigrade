#!/usr/bin/env bash
# Capture a release baseline JSON, optionally compare it to the previous saved
# baseline, and emit a markdown report. Intended for a dedicated benchmark target;
# do not substitute a laptop-local run unless a dedicated target is unavailable.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
TAG="$(git -C "${REPO_ROOT}" describe --tags --always 2>/dev/null || echo unknown)"
META_FILE="${BENCH_DIR}/targets/release-baseline.json"
BASELINE_FILE=""
README_FILE=""
REPORT_FILE=""
RUN_ARGS=()
HAS_SCENARIOS_OVERRIDE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)           TAG="$2";            shift 2 ;;
        --meta-file)     META_FILE="$2";      shift 2 ;;
        --baseline)      BASELINE_FILE="$2";  shift 2 ;;
        --update-readme) README_FILE="$2";    shift 2 ;;
        --report-file)   REPORT_FILE="$2";    shift 2 ;;
        --scenarios)
            HAS_SCENARIOS_OVERRIDE=true
            RUN_ARGS+=("$1" "$2")
            shift 2
            ;;
        --help)
            cat <<'EOF'
Usage:
  ./benchmarks/release-baseline.sh [options] [-- <extra run.sh args>]

Options:
  --tag TAG             Output file tag (default: current git describe)
  --meta-file FILE      Metadata JSON merged into _meta
  --baseline FILE       Previous baseline JSON for comparison
  --update-readme FILE  Refresh the README benchmark report block
  --report-file FILE    Output markdown report path
  --help                Show this help and exit

Any arguments after `--` are passed directly to benchmarks/run.sh.
EOF
            exit 0
            ;;
        --)
            shift
            RUN_ARGS+=("$@")
            break
            ;;
        *)
            if [[ "$1" == "--scenarios" ]]; then
                HAS_SCENARIOS_OVERRIDE=true
            fi
            RUN_ARGS+=("$1")
            shift
            ;;
    esac
done

SAVE_FILE="${BENCH_DIR}/baselines/${TAG}.json"
REPORT_FILE="${REPORT_FILE:-${BENCH_DIR}/baselines/${TAG}.md}"

cmd=(
    "${BENCH_DIR}/run.sh"
    --meta-file "${META_FILE}"
    --save "${SAVE_FILE}"
)

if ! $HAS_SCENARIOS_OVERRIDE; then
    cmd+=(
        --scenarios "static-http1,proxy-http1,proxy-payload-64k,proxy-payload-256k,keepalive"
    )
fi

if [[ -n "${BASELINE_FILE}" ]]; then
    cmd+=(--baseline "${BASELINE_FILE}")
fi

cmd+=("${RUN_ARGS[@]}")
"${cmd[@]}"

"${BENCH_DIR}/report.sh" "${SAVE_FILE}" > "${REPORT_FILE}"
echo "Wrote report: ${REPORT_FILE}"

if [[ -n "${README_FILE}" ]]; then
    "${BENCH_DIR}/report.sh" "${SAVE_FILE}" --update-readme "${README_FILE}"
fi
