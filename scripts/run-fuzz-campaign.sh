#!/usr/bin/env bash
# Resumable orchestrator for Tardigrade's existing Zig fuzz build steps.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

EXPECTED_ZIG_VERSION="${EXPECTED_ZIG_VERSION:-0.16.0}"

tier=""
family=""
target=""
budget=""
output=""
source_sha=""
resume=false
list=false
noncanonical_smoke=false
skip_preflight=false
watchdog_seconds=""

usage() {
  cat <<'EOF'
Usage: scripts/run-fuzz-campaign.sh [OPTIONS]

Runs one existing Zig fuzz family/target at a time and preserves append-only
campaign evidence. This script does not implement fuzzing semantics.

Required for execution:
  --tier 1|2|3
  --family tls-protocol|tls-record|tls-resumption|pki|crypto|quic
  --output DIR

Target selection:
  --target NAME          Exact `test "fuzz: ..."` name. Required for Tier 2/3.
                         Omit for Tier 1 family-wide rows.
  --budget N|K|M|G       Mutation budget. Defaults: Tier 1=10M, Tier 2=50M,
                         Tier 3=100M.

Evidence and safety:
  --source-sha SHA       Refuse canonical runs unless HEAD matches SHA.
  --resume              Skip a row only when manifest proves same SHA, step,
                         filter, same-or-greater budget, and status pass.
  --noncanonical-smoke  Allow dirty worktrees and mark evidence non-canonical.
  --skip-preflight      Only with --noncanonical-smoke; useful for cheap script
                         validation and smoke budgets.
  --watchdog SECONDS    Bound one fuzz process; expiry records possible_hang.

Discovery:
  --list                Print current family/target registry and exit.
  --help                Show this help.

Examples:
  scripts/run-fuzz-campaign.sh --list
  scripts/run-fuzz-campaign.sh --tier 1 --family quic --output artifacts/hardening/fuzz/smoke --noncanonical-smoke --budget 1K --skip-preflight
  scripts/run-fuzz-campaign.sh --family quic --target 'fuzz: packet parser preserves bounded slice and progress invariants' --budget 50M --output artifacts/hardening/fuzz/<campaign-id>
EOF
}

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

json_escape() {
  awk 'BEGIN {
    s = ARGV[1]; ARGV[1] = "";
    gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/,"\\t",s);
    gsub(/\r/,"\\r",s); gsub(/\n/,"\\n",s);
    printf "%s", s
  }' "$1"
}

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//; s/-+/-/g'
}

budget_to_mutations() {
  local value="$1" number suffix multiplier
  [[ "$value" =~ ^[0-9]+[KkMmGg]?$ ]] || die "invalid budget: $value"
  number="${value%[KkMmGg]}"
  suffix="${value#"$number"}"
  multiplier=1
  case "$suffix" in
    K|k) multiplier=1000 ;;
    M|m) multiplier=1000000 ;;
    G|g) multiplier=1000000000 ;;
  esac
  awk -v n="$number" -v m="$multiplier" 'BEGIN { printf "%.0f\n", n * m }'
}

family_step() {
  case "$1" in
    tls-protocol) echo "test-tls-protocol-fuzz" ;;
    tls-record) echo "test-tls-record-fuzz" ;;
    tls-resumption) echo "test-tls-resumption-fuzz" ;;
    pki) echo "test-pki-fuzz" ;;
    crypto) echo "test-crypto-provider-fuzz" ;;
    quic) echo "test-quic" ;;
    *) die "unknown family: $1" ;;
  esac
}

family_filter_option() {
  case "$1" in
    tls-protocol) echo "-Dtls-protocol-test-filter=$2" ;;
    tls-record) echo "-Dtls-record-test-filter=$2" ;;
    tls-resumption) echo "-Dtls-resumption-test-filter=$2" ;;
    pki) echo "-Dpki-test-filter=$2" ;;
    crypto) echo "-Dcrypto-test-filter=$2" ;;
    quic) echo "-Dquic-test-filter=$2" ;;
    *) die "unknown family: $1" ;;
  esac
}

target_family() {
  local path="$1" name="$2"
  case "$name" in
    "fuzz: TLS protocol:"*) echo "tls-protocol"; return ;;
    "fuzz: TLS record:"*) echo "tls-record"; return ;;
    "fuzz: TLS resumption:"*) echo "tls-resumption"; return ;;
    "fuzz: PKI:"*) echo "pki"; return ;;
  esac
  case "$path" in
    tests/crypto_provider_fuzz.zig) echo "crypto" ;;
    src/quic/*|src/http3/*) echo "quic" ;;
    *) return 1 ;;
  esac
}

discover_targets() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git grep -n 'test "fuzz:' -- src tests
  elif command -v rg >/dev/null 2>&1; then
    rg -n 'test "fuzz:' src tests
  else
    grep -R -n 'test "fuzz:' src tests
  fi | while IFS=: read -r path line rest; do
    name="$(printf '%s\n' "$rest" | sed -n 's/.*test "\(fuzz: [^"]*\)".*/\1/p')"
    [[ -n "$name" ]] || continue
    fam="$(target_family "$path" "$name" 2>/dev/null || true)"
    [[ -n "${fam:-}" ]] || continue
    printf '%s\t%s\t%s\t%s\n' "$fam" "$(family_step "$fam")" "$name" "$path:$line"
  done | sort -u
}

git_head_value() {
  if git rev-parse HEAD >/dev/null 2>&1; then
    git rev-parse HEAD
  elif [[ -n "$source_sha" ]]; then
    printf '%s\n' "$source_sha"
  else
    die "not a Git checkout; pass --source-sha when running from a source archive"
  fi
}

git_status_short_value() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git status --short
  else
    printf '%s\n' "source archive: no git worktree status available"
  fi
}

target_selects_current_fuzz() {
  local fam="$1" name="$2"
  discover_targets | awk -F '\t' -v f="$fam" -v n="$name" '
    $1 == f && $3 == n {
      count += 1
      selected = selected $3 "\n"
    }
    END {
      if (count == 1) exit 0
      if (count == 0) {
        printf "no current fuzz target selected by filter: %s\n", n > "/dev/stderr"
      } else {
        printf "ambiguous fuzz filter selects %d targets:\n%s", count, selected > "/dev/stderr"
      }
      exit 1
    }'
}

resume_has_pass() {
  local manifest="$1" sha="$2" step="$3" filter="$4" min_budget="$5"
  [[ -f "$manifest" ]] || return 1
  awk -v sha="$sha" -v step="$step" -v filter="$filter" -v min_budget="$min_budget" '
    $0 ~ "\"source_commit_sha\":\"" sha "\"" &&
    $0 ~ "\"build_step\":\"" step "\"" &&
    $0 ~ "\"filter\":\"" filter "\"" &&
    $0 ~ "\"status\":\"pass\"" {
      line = $0
      sub(/^.*"budget_mutations":/, "", line)
      sub(/[^0-9].*$/, "", line)
      if (line + 0 >= min_budget + 0) found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$manifest"
}

capture_environment() {
  local file="$1"
  {
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'git_head=%s\n' "$(git_head_value)"
    printf 'git_status_short<<EOF\n'; git_status_short_value; printf 'EOF\n'
    printf 'zig_version=%s\n' "$(zig version 2>/dev/null || true)"
    printf 'uname=%s\n' "$(uname -a)"
    printf 'os_arch=%s/%s\n' "$(uname -s)" "$(uname -m)"
    if command -v lscpu >/dev/null 2>&1; then
      printf 'lscpu<<EOF\n'; lscpu 2>&1 || true; printf 'EOF\n'
    fi
    if [[ -r /proc/meminfo ]]; then
      printf 'proc_meminfo<<EOF\n'; cat /proc/meminfo; printf 'EOF\n'
    fi
    if command -v sysctl >/dev/null 2>&1; then
      printf 'sysctl_cpu_mem<<EOF\n'
      sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>&1 || true
      printf 'EOF\n'
    fi
  } >"$file"
}

cpu_identity() {
  local cpu=""
  if command -v lscpu >/dev/null 2>&1; then
    cpu="$(lscpu 2>/dev/null | awk -F ': +' '/Model name:/ { print $2; exit }')"
  fi
  if [[ -z "$cpu" && -r /proc/cpuinfo ]]; then
    cpu="$(awk -F ': +' '/model name/ { print $2; exit }' /proc/cpuinfo)"
  fi
  if [[ -z "$cpu" ]] && command -v sysctl >/dev/null 2>&1; then
    cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
  fi
  if [[ -z "$cpu" ]]; then
    cpu="unknown"
  fi
  printf '%s\n' "$cpu"
}

run_preflight() {
  local dir="$1"
  mkdir -p "$dir"
  capture_environment "$dir/environment.txt"
  {
    printf '%s\n' 'zig fmt --check build.zig src/ tests/'
    zig fmt --check build.zig src/ tests/
  } >"$dir/01-zig-fmt.log" 2>&1
  {
    printf '%s\n' 'zig build test --summary all --error-style verbose'
    zig build test --summary all --error-style verbose
  } >"$dir/02-zig-build-test.log" 2>&1
  {
    printf '%s\n' 'zig build test-security-corpus --summary all --error-style verbose'
    zig build test-security-corpus --summary all --error-style verbose
  } >"$dir/03-security-corpus.log" 2>&1
  {
    printf '%s\n' 'zig build test-integration --summary all --error-style verbose'
    zig build test-integration --summary all --error-style verbose
  } >"$dir/04-integration.log" 2>&1
}

ensure_campaign_metadata() {
  local canonical_json="$1"
  local created_utc metadata_tmp targets_tmp environment_tmp
  created_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  mkdir -p "$output"
  if [[ -f "$output/campaign.json" ]]; then
    grep -F "\"source_commit_sha\":\"$head_sha\"" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different source SHA"
    grep -F "\"canonical\":$canonical_json" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different canonical/smoke mode"
    grep -F "\"expected_zig_version\":\"$EXPECTED_ZIG_VERSION\"" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different Zig version"
  else
    metadata_tmp="$(mktemp "${output}/campaign.json.tmp.XXXXXX")"
    cat >"$metadata_tmp" <<EOF
{"campaign_id":"$(json_escape "$campaign_id")","source_commit_sha":"$head_sha","canonical":$canonical_json,"expected_zig_version":"$(json_escape "$EXPECTED_ZIG_VERSION")","created_utc":"$created_utc"}
EOF
    mv "$metadata_tmp" "$output/campaign.json"
  fi

  if [[ ! -f "$output/targets.tsv" ]]; then
    targets_tmp="$(mktemp "${output}/targets.tsv.tmp.XXXXXX")"
    discover_targets >"$targets_tmp"
    mv "$targets_tmp" "$output/targets.tsv"
  fi

  if [[ ! -f "$output/environment.txt" ]]; then
    environment_tmp="$(mktemp "${output}/environment.txt.tmp.XXXXXX")"
    capture_environment "$environment_tmp"
    mv "$environment_tmp" "$output/environment.txt"
  fi
}

ensure_preflight() {
  local preflight_root="$output/preflight" preflight_attempt
  if $skip_preflight; then
    say "==> skipping deterministic preflight for non-canonical smoke"
    return
  fi
  mkdir -p "$preflight_root/attempts"
  if [[ -f "$preflight_root/complete" ]]; then
    say "==> reusing retained deterministic preflight evidence"
    return
  fi

  preflight_attempt="$preflight_root/attempts/$(date -u '+%Y%m%dT%H%M%SZ')-$$"
  say "==> running deterministic preflight"
  run_preflight "$preflight_attempt"
  printf '%s\n' "$preflight_attempt" >"$preflight_root/complete"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --family) family="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --budget) budget="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --source-sha) source_sha="$2"; shift 2 ;;
    --watchdog) watchdog_seconds="$2"; shift 2 ;;
    --resume) resume=true; shift ;;
    --list) list=true; shift ;;
    --noncanonical-smoke) noncanonical_smoke=true; shift ;;
    --skip-preflight) skip_preflight=true; shift ;;
    --help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if $list; then
  discover_targets
  exit 0
fi

[[ -n "$tier" ]] || tier=2
case "$tier" in 1|2|3) ;; *) die "--tier must be 1, 2, or 3" ;; esac
[[ -n "$family" ]] || die "--family is required"
step="$(family_step "$family")"
[[ -n "$output" ]] || die "--output is required"

if [[ -z "$budget" ]]; then
  case "$tier" in
    1) budget=10M ;;
    2) budget=50M ;;
    3) budget=100M ;;
  esac
fi
budget_mutations="$(budget_to_mutations "$budget")"
[[ -z "$watchdog_seconds" || "$watchdog_seconds" =~ ^[0-9]+$ ]] || die "--watchdog must be seconds"

if [[ "$tier" != 1 && -z "$target" ]]; then
  die "--target is required for Tier $tier"
fi
if [[ -n "$target" ]] && ! target_selects_current_fuzz "$family" "$target"; then
  die "target filter is not a unique current $family fuzz target: $target"
fi
if $skip_preflight && ! $noncanonical_smoke; then
  die "--skip-preflight is only allowed with --noncanonical-smoke"
fi

head_sha="$(git_head_value)"
if [[ -n "$source_sha" && "$source_sha" != "$head_sha" ]]; then
  die "requested source SHA $source_sha does not match checked-out HEAD $head_sha"
fi
if [[ "$(zig version 2>/dev/null || true)" != "$EXPECTED_ZIG_VERSION" ]]; then
  die "expected Zig $EXPECTED_ZIG_VERSION; found $(zig version 2>/dev/null || echo unavailable)"
fi
if ! $noncanonical_smoke && git rev-parse --git-dir >/dev/null 2>&1 && [[ -n "$(git status --short)" ]]; then
  git status --short >&2
  die "canonical campaign requires a clean worktree; pass --noncanonical-smoke for setup smoke evidence"
fi

campaign_id="$(basename "$output")"
canonical_json="$($noncanonical_smoke && echo false || echo true)"
ensure_campaign_metadata "$canonical_json"
mkdir -p "$output/preflight" "$output/runs" "$output/findings"

ensure_preflight

crash_hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# $1=dir $2=crash_input_path_or_empty $3=crashing_test_name_or_empty.
# Reads $family/$step/$filter/$head_sha/$status/$exit_code/$target/
# $command_file/$stdout_log/$stderr_log from the calling run_one_attempt
# invocation via bash's dynamic scoping (they're all `local` there, but
# still visible down the call stack while it's running). Prints the
# crash's sha256 (or nothing) on stdout for the caller to capture.
write_finding() {
  local dir="$1" crash_input="$2" test_name="$3" sha=""
  mkdir -p "$dir"
  cp "$command_file" "$dir/command.txt"
  cp "$stdout_log" "$dir/stdout.log"
  cp "$stderr_log" "$dir/stderr.log"
  if [[ -n "$crash_input" && -s "$crash_input" ]]; then
    cp "$crash_input" "$dir/crash-input.bin"
    if command -v sha256sum >/dev/null 2>&1; then
      sha="$(sha256sum "$dir/crash-input.bin" | awk '{print $1}')"
    else
      sha="$(shasum -a 256 "$dir/crash-input.bin" | awk '{print $1}')"
    fi
  fi
  if [[ -d .zig-cache ]]; then
    tar -czf "$dir/zig-cache-preserved.tgz" .zig-cache 2>/dev/null || true
  fi
  {
    printf 'family=%s\n' "$family"
    printf 'build_step=%s\n' "$step"
    printf 'filter=%s\n' "$filter"
    if [[ -n "$test_name" ]]; then printf 'crashing_test=%s\n' "$test_name"; fi
    printf 'source_commit_sha=%s\n' "$head_sha"
    printf 'status=%s\n' "$status"
    printf 'exit_code=%s\n' "$exit_code"
    printf 'replay_command='
    printf '%q ' zig build "$step" --summary all --error-style verbose "$(family_filter_option "$family" "$target")"
    printf '\n'
    if [[ -n "$sha" ]]; then
      printf 'crash_input_sha256=%s\n' "$sha"
      printf 'note=%s\n' 'crash-input.bin holds the exact saved fuzz input byte-for-byte; .zig-cache state was preserved alongside it.'
    else
      printf 'note=%s\n' 'Exact Zig crash input path was not inferred automatically; complete logs and .zig-cache state were preserved for deliberate recovery.'
    fi
  } >"$dir/provenance.txt"
  printf '%s' "$sha"
}

# $1=finding_dir_or_empty $2=finding_sha_json. Reads the rest
# ($started_utc/$ended_utc/$elapsed/$execs_per_sec/$status/$exit_code/
# $stdout_log/$stderr_log, plus $family/$step/$filter/$budget/
# $budget_mutations/$head_sha) from run_one_attempt via dynamic scoping.
append_manifest_line() {
  local fdir="$1" fsha="$2" finding_path_json="null"
  if [[ -n "$fdir" ]]; then finding_path_json="\"$(json_escape "$fdir")\""; fi
  printf '{"campaign_id":"%s","started_utc":"%s","ended_utc":"%s","source_commit_sha":"%s","zig_version":"%s","os_arch":"%s/%s","cpu":"%s","family":"%s","build_step":"%s","filter":"%s","budget":"%s","budget_mutations":%s,"optimize":"ReleaseFast","elapsed_seconds":%s,"executions_per_second":%s,"status":"%s","exit_code":%s,"finding_path":%s,"finding_sha256":%s,"stdout_path":"%s","stderr_path":"%s"}\n' \
    "$(json_escape "$campaign_id")" "$started_utc" "$ended_utc" "$head_sha" "$(json_escape "$(zig version)")" "$(json_escape "$(uname -s)")" "$(json_escape "$(uname -m)")" \
    "$(json_escape "$(cpu_identity)")" \
    "$(json_escape "$family")" "$(json_escape "$step")" "$(json_escape "$filter")" "$(json_escape "$budget")" "$budget_mutations" "$elapsed" "$execs_per_sec" "$status" "$exit_code" \
    "$finding_path_json" "$fsha" "$(json_escape "$stdout_log")" "$(json_escape "$stderr_log")" >>"$manifest"
}

# Tier 1 "family-wide" rows historically ran every one of a family's fuzz
# tests concurrently within one `zig build --fuzz` invocation (no
# --target), sharing one combined budget. That has real problems: Zig
# saves each crash to one fixed shared path (.zig-cache/f/crash, no
# per-test subdirectory), so when more than one target crashes in the
# same run, a later crash silently overwrites an earlier one's saved
# bytes -- examining the log/cache only after the whole process exits
# recovers nothing but the LAST crash (#675 campaign finding: a QUIC
# family-wide run found two distinct crashes; only one survived
# collection). Polling for new crashes DURING the run doesn't reliably
# fix this either: a child process's stdout/stderr default to fully
# buffered once redirected to a file, so a "test '...'; input saved to
# '...'" line can sit unflushed for tens of seconds, and by the time a
# batch of such lines does flush, the crash file has already cycled
# through every target in that batch but the last.
#
# run_one_attempt runs exactly ONE target (never the ambiguous
# "<family>" filter) and preserves its own dedicated finding/manifest
# line, identical in shape to an explicit Tier 2/3 --target run. A
# family-wide row (no --target given) discovers every current target in
# the family below and calls this once per target, sequentially, each
# at the row's full budget, stopping at the first non-pass so the
# campaign's existing "a failure stops new rows by default until
# triage" rule still applies. This makes the crash-collision problem
# structurally impossible -- each invocation has its own Zig process
# and therefore its own exclusive lifetime for the shared crash-file
# path -- rather than something a watcher has to race.
run_one_attempt() {
  local target="$1"
  local filter="$target"
  local run_key
  run_key="${family}__$(slugify "$target")__${budget}"

  if $resume && resume_has_pass "$manifest" "$head_sha" "$step" "$filter" "$budget_mutations"; then
    say "==> resume: existing same-SHA pass satisfies $family $filter >= $budget"
    return 0
  fi

  local attempt_id run_dir stdout_log stderr_log command_file result_file finding_dir
  attempt_id="$(date -u '+%Y%m%dT%H%M%SZ')-$$-$RANDOM"
  run_dir="$output/runs/$run_key/attempts/$attempt_id"
  mkdir -p "$run_dir"
  stdout_log="$run_dir/stdout.log"
  stderr_log="$run_dir/stderr.log"
  command_file="$run_dir/command.txt"
  result_file="$run_dir/result.json"
  finding_dir="$output/findings/${family}__$(slugify "$filter")/$attempt_id"

  local cmd=(zig build "$step" -Doptimize=ReleaseFast "--fuzz=$budget" --summary all --error-style verbose "$(family_filter_option "$family" "$target")")
  printf '%q ' "${cmd[@]}" >"$command_file"
  printf '\n' >>"$command_file"

  say "==> running ${cmd[*]}"
  local started_utc start_epoch interrupted child_pid
  started_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  start_epoch="$(date +%s)"
  interrupted=false
  child_pid=""

  # Defense in depth, not the primary mechanism now that each attempt is
  # single-target: a filtered build step can still in principle match
  # more than one `test "fuzz: ..."` block, though
  # target_selects_current_fuzz already rejects an ambiguous filter at
  # the top of the script. Polls the crash file's CONTENT HASH directly
  # rather than the log text, since the file is a direct, unbuffered
  # write while the log can sit unflushed for a long time.
  local crash_snapshots_dir crash_file crash_watch_last_hash crash_watch_stop crash_watcher_pid
  crash_snapshots_dir="$run_dir/crash-snapshots"
  mkdir -p "$crash_snapshots_dir"
  crash_file=".zig-cache/f/crash"
  # A crash file left over from an earlier attempt (a retry reusing
  # .zig-cache, or a kept failed VM) must not be attributed to THIS
  # attempt: starting the watcher before the new Zig process means it
  # would otherwise hash/copy that stale file on its very first poll and
  # force an otherwise-clean target to status=fail. Clearing it here
  # (after the PREVIOUS attempt already preserved whatever it needed)
  # makes any later appearance at this path unambiguously this attempt's.
  rm -f "$crash_file"
  crash_watch_last_hash=""
  snapshot_new_crashes() {
    local h next idx test_name
    if [[ ! -s "$crash_file" ]]; then
      return 0
    fi
    h="$(crash_hash_of "$crash_file" 2>/dev/null || true)"
    if [[ -z "$h" || "$h" == "$crash_watch_last_hash" ]]; then
      return 0
    fi
    crash_watch_last_hash="$h"
    next=$(($(find "$crash_snapshots_dir" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l) + 1))
    idx="$(printf '%03d' "$next")"
    cp "$crash_file" "$crash_snapshots_dir/$idx.bin"
    test_name="$(grep -Eho "error: test '[^']+'.*input saved to '[^']+'" "$stdout_log" "$stderr_log" 2>/dev/null | tail -1 | sed -E "s/^error: test '([^']+)'.*/\1/" || true)"
    printf '%s\n' "${test_name:-$target}" >"$crash_snapshots_dir/$idx.test-name.txt"
    return 0
  }
  # crash_watch_last_hash is a plain shell variable, not a file: the loop
  # below runs in a backgrounded subshell (a separate process), so its
  # updates to that variable are invisible to this parent shell. Calling
  # snapshot_new_crashes a second time from the parent after the
  # subshell exits would see the parent's original (empty) hash and
  # treat an already-captured crash as new again, writing a duplicate
  # snapshot/finding for the same crash. The fix is to never call it
  # from two different processes: the loop checks the stop flag AFTER
  # each snapshot attempt (not before), so stopping it still guarantees
  # one last check happens -- inside the same process that owns the
  # hash state -- instead of needing a separate final call out here.
  crash_watch_stop="$run_dir/.crash-watch-stop"
  rm -f "$crash_watch_stop"
  (
    while :; do
      snapshot_new_crashes
      [[ -f "$crash_watch_stop" ]] && break
      sleep 0.1
    done
  ) &
  crash_watcher_pid=$!

  terminate_child() {
    if [[ -n "$child_pid" ]]; then
      if command -v pkill >/dev/null 2>&1; then
        pkill -TERM -P "$child_pid" 2>/dev/null || true
      fi
      kill -TERM "$child_pid" 2>/dev/null || true
    fi
  }
  on_interrupt() {
    interrupted=true
    terminate_child
  }
  trap on_interrupt INT TERM
  set +e
  # A child process's stdout/stderr default to fully buffered (not
  # line-buffered) as soon as they're redirected to a file instead of a
  # TTY. `stdbuf` forces line buffering on both streams; it ships with
  # GNU coreutils (present on the Linux campaign hosts) but not on
  # macOS, so this degrades gracefully to unbuffered-until-exit there.
  local line_buffered_cmd=("${cmd[@]}")
  if command -v stdbuf >/dev/null 2>&1; then
    line_buffered_cmd=(stdbuf -oL -eL "${cmd[@]}")
  fi
  local exit_code
  if [[ -n "$watchdog_seconds" ]]; then
    command -v timeout >/dev/null 2>&1 || die "--watchdog requires the timeout command"
    timeout "$watchdog_seconds" "${line_buffered_cmd[@]}" >"$stdout_log" 2>"$stderr_log" &
  else
    "${line_buffered_cmd[@]}" >"$stdout_log" 2>"$stderr_log" &
  fi
  child_pid=$!
  wait "$child_pid"
  exit_code=$?
  if $interrupted || [[ "$exit_code" -eq 130 || "$exit_code" -eq 143 ]]; then
    terminate_child
    wait "$child_pid" >/dev/null 2>&1 || true
  fi
  child_pid=""
  set -e
  trap - INT TERM

  touch "$crash_watch_stop"
  wait "$crash_watcher_pid" 2>/dev/null || true
  rm -f "$crash_watch_stop"

  local end_epoch ended_utc elapsed
  end_epoch="$(date +%s)"
  ended_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  elapsed=$((end_epoch - start_epoch))

  local status="pass"
  if $interrupted; then
    status="interrupted"
  elif [[ "$exit_code" -eq 124 ]]; then
    status="possible_hang"
  elif [[ "$exit_code" -eq 130 || "$exit_code" -eq 143 ]]; then
    status="interrupted"
  elif [[ "$exit_code" -ne 0 ]]; then
    status="fail"
  fi

  local crash_snapshot_count
  crash_snapshot_count="$(find "$crash_snapshots_dir" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$crash_snapshot_count" -eq 0 ]]; then
    rmdir "$crash_snapshots_dir" 2>/dev/null || true
  fi

  # `zig build --fuzz` exits 0 even when the fuzzer finds a failing input
  # (it saves the input and stops the session early), so a fuzz finding
  # must be detected from the run output, never from the exit code alone.
  local fuzz_crash_input=""
  if [[ "$crash_snapshot_count" -eq 0 ]]; then
    fuzz_crash_input="$(grep -Eho "input saved to '[^']+'" "$stdout_log" "$stderr_log" 2>/dev/null | tail -1 | sed -E "s/^input saved to '([^']+)'\$/\1/" || true)"
  fi
  if [[ "$status" == "pass" && ( "$crash_snapshot_count" -gt 0 || -n "$fuzz_crash_input" ) ]]; then
    status="fail"
  fi

  local execs_per_sec
  execs_per_sec="$(grep -Eho '[0-9]+(\.[0-9]+)?[[:space:]]+(exec|execs|executions)/s(ec)?' "$stdout_log" "$stderr_log" 2>/dev/null | tail -1 | awk '{print $1}' || true)"
  if [[ -z "$execs_per_sec" ]]; then
    execs_per_sec="null"
  else
    execs_per_sec="\"$(json_escape "$execs_per_sec")\""
  fi

  cat >"$result_file" <<EOF2
{"status":"$status","exit_code":$exit_code,"started_utc":"$started_utc","ended_utc":"$ended_utc","elapsed_seconds":$elapsed}
EOF2

  local finding_sha finding_sha_json
  if [[ "$crash_snapshot_count" -gt 0 ]]; then
    local i idx snap_bin snap_name_file snap_test_name finding_slug this_finding_dir
    i=1
    while [[ "$i" -le "$crash_snapshot_count" ]]; do
      idx="$(printf '%03d' "$i")"
      snap_bin="$crash_snapshots_dir/$idx.bin"
      snap_name_file="$crash_snapshots_dir/$idx.test-name.txt"
      snap_test_name=""
      if [[ -f "$snap_name_file" ]]; then snap_test_name="$(cat "$snap_name_file")"; fi
      finding_slug="${snap_test_name:-$filter}"
      this_finding_dir="$output/findings/${family}__$(slugify "$finding_slug")/${attempt_id}-${idx}"
      finding_sha="$(write_finding "$this_finding_dir" "$snap_bin" "$snap_test_name")"
      finding_sha_json="null"
      if [[ -n "$finding_sha" ]]; then finding_sha_json="\"$(json_escape "$finding_sha")\""; fi
      append_manifest_line "$this_finding_dir" "$finding_sha_json"
      say "==> $status: finding $i/$crash_snapshot_count (${snap_test_name:-unknown test}) preserved under $this_finding_dir"
      i=$((i + 1))
    done
  elif [[ "$status" != "pass" ]]; then
    finding_sha="$(write_finding "$finding_dir" "$fuzz_crash_input" "")"
    finding_sha_json="null"
    if [[ -n "$finding_sha" ]]; then finding_sha_json="\"$(json_escape "$finding_sha")\""; fi
    append_manifest_line "$finding_dir" "$finding_sha_json"
    say "==> $status: preserved logs/state under $finding_dir"
  else
    append_manifest_line "" "null"
  fi

  if [[ "$status" != "pass" ]]; then
    if [[ "$exit_code" -ne 0 ]]; then
      return "$exit_code"
    fi
    return 1
  fi
  say "==> pass ($target): evidence appended to $manifest"
  return 0
}

manifest="$output/manifest.jsonl"

if [[ -n "$target" ]]; then
  set +e
  run_one_attempt "$target"
  rc=$?
  set -e
  exit "$rc"
fi

found_any=false
while IFS= read -r discovered_target; do
  [[ -n "$discovered_target" ]] || continue
  found_any=true
  set +e
  run_one_attempt "$discovered_target"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    exit "$rc"
  fi
done < <(discover_targets | awk -F '\t' -v f="$family" '$1 == f { print $3 }')

if ! $found_any; then
  die "no current fuzz targets discovered for family: $family"
fi
say "==> pass: every discovered $family target passed at budget $budget"
