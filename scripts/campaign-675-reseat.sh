#!/usr/bin/env bash
# Establish the immutable published-release baseline for the #675 campaign.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

say() { printf '%s campaign-675: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
usage() { printf 'usage: scripts/campaign-675-reseat.sh <release-version>\n' >&2; }

state_value() {
  local state_file="$1" key="$2"
  local -a lines=()
  mapfile -t lines < <(grep -E "^${key}=" "$state_file" 2>/dev/null || true)
  [[ "${#lines[@]}" -eq 1 ]] || return 1
  printf '%s\n' "${lines[0]#*=}"
}

plan_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

freeze_target_registry() { # $1 source SHA, $2 output file
  local source_sha="$1" output="$2" source_dir
  source_dir="$(mktemp -d)" || return 1
  # The target lister itself is part of the release contract: it carries that
  # release's family-to-build-step mapping, so never recreate it from the
  # moving controller checkout.
  if ! git archive --format=tar "$source_sha" | tar -x -C "$source_dir" ||
    ! (cd "$source_dir" && scripts/run-fuzz-campaign.sh --list) | awk -F '\t' 'NF >= 3 { print $1 "\t" $2 "\t" $3 }' | sort -u > "$output" ||
    [[ ! -s "$output" ]]; then
    rm -rf "$source_dir"
    return 1
  fi
  rm -rf "$source_dir"
}

write_campaign_state() {
  local state_file="$1" release_tag="$2" source_sha="$3" campaign_dir="$4" plan_sha="$5" target_sha="$6"
  local temp
  temp="$(mktemp "$campaign_dir/.campaign.env.XXXXXX")" || return 1
  {
    printf 'RELEASE_TAG=%s\n' "$release_tag"
    printf 'SOURCE_SHA=%s\n' "$source_sha"
    printf 'CAMPAIGN_DIR=%s\n' "$campaign_dir"
    printf 'ROW_PLAN_SHA256=%s\n' "$plan_sha"
    printf 'TARGET_REGISTRY_SHA256=%s\n' "$target_sha"
  } > "$temp" || { rm -f "$temp"; return 1; }
  mv -f "$temp" "$state_file"
}

write_active_state() {
  local active_state="$1" campaign_state="$2"
  local temp
  temp="$(mktemp "${active_state}.XXXXXX")" || return 1
  printf 'CAMPAIGN_STATE=%s\n' "$campaign_state" > "$temp" || { rm -f "$temp"; return 1; }
  mv -f "$temp" "$active_state"
}

campaign_675_reseat_main() {
  if [[ "$#" -ne 1 ]]; then
    usage
    return 64
  fi

  local release_tag="$1"
  if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z]+)*$ ]]; then
    say "FATAL invalid release version '$release_tag'"
    usage
    return 64
  fi

  local evidence_root="${CAMPAIGN_675_EVIDENCE_ROOT:-artifacts/hardening/fuzz}"
  local git_remote="${CAMPAIGN_675_GIT_REMOTE:-origin}"
  local campaign_dir="$evidence_root/campaign-675-$release_tag"
  local campaign_state="$campaign_dir/campaign.env"
  local active_state="${CAMPAIGN_675_ACTIVE_STATE:-$evidence_root/campaign-675-active.env}"
  local source_sha old_active old_release old_sha old_dir old_plan_sha old_target_sha plan_sha target_sha row_plan_tmp targets_tmp

  git fetch "$git_remote" --tags --quiet || { say "FATAL unable to fetch tags from $git_remote"; return 1; }
  git rev-parse --verify --quiet "refs/tags/$release_tag" >/dev/null || {
    say "FATAL release tag '$release_tag' does not exist"
    return 1
  }
  source_sha="$(git rev-parse --verify "$release_tag^{commit}" 2>/dev/null)" || {
    say "FATAL release tag '$release_tag' does not resolve to a commit"
    return 1
  }
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    say "FATAL release tag '$release_tag' resolved to an invalid commit"
    return 1
  }

  if [[ -e "$campaign_dir" ]]; then
    [[ -f "$campaign_state" ]] || {
      say "FATAL existing campaign directory lacks immutable campaign.env: $campaign_dir"
      return 1
    }
    old_release="$(state_value "$campaign_state" RELEASE_TAG)" || old_release=""
    old_sha="$(state_value "$campaign_state" SOURCE_SHA)" || old_sha=""
    old_dir="$(state_value "$campaign_state" CAMPAIGN_DIR)" || old_dir=""
    old_plan_sha="$(state_value "$campaign_state" ROW_PLAN_SHA256)" || old_plan_sha=""
    old_target_sha="$(state_value "$campaign_state" TARGET_REGISTRY_SHA256)" || old_target_sha=""
    if [[ "$old_release" != "$release_tag" || "$old_sha" != "$source_sha" || "$old_dir" != "$campaign_dir" ]]; then
      say "FATAL campaign identity mismatch in $campaign_dir (recorded $old_release ${old_sha:-<missing>})"
      return 1
    fi
    [[ -f "$campaign_dir/rows.tsv" ]] || {
      say "FATAL existing campaign baseline lacks rows.tsv: $campaign_dir"
      return 1
    }
    plan_sha="$(plan_sha256 "$campaign_dir/rows.tsv")" || return 1
    [[ "$old_plan_sha" == "$plan_sha" ]] || {
      say "FATAL frozen row-plan hash mismatch in $campaign_dir"
      return 1
    }
    [[ -f "$campaign_dir/targets.tsv" ]] || { say "FATAL existing campaign baseline lacks targets.tsv: $campaign_dir"; return 1; }
    target_sha="$(plan_sha256 "$campaign_dir/targets.tsv")" || return 1
    [[ "$old_target_sha" == "$target_sha" ]] || { say "FATAL frozen target-registry hash mismatch in $campaign_dir"; return 1; }
    say "release baseline already established: $release_tag @ $source_sha"
  else
    mkdir -p "$campaign_dir" || return 1
    row_plan_tmp="$campaign_dir/.rows.tsv.$$"
    git show "$source_sha:scripts/campaign-675-rows.tsv" > "$row_plan_tmp" || {
      rm -f "$row_plan_tmp"
      say "FATAL selected release lacks scripts/campaign-675-rows.tsv"
      return 1
    }
    mv -f "$row_plan_tmp" "$campaign_dir/rows.tsv" || return 1
    targets_tmp="$campaign_dir/.targets.tsv.$$"
    freeze_target_registry "$source_sha" "$targets_tmp" || { rm -f "$targets_tmp"; say "FATAL unable to derive selected release target registry"; return 1; }
    mv -f "$targets_tmp" "$campaign_dir/targets.tsv" || return 1
    plan_sha="$(plan_sha256 "$campaign_dir/rows.tsv")" || return 1
    target_sha="$(plan_sha256 "$campaign_dir/targets.tsv")" || return 1
    write_campaign_state "$campaign_state" "$release_tag" "$source_sha" "$campaign_dir" "$plan_sha" "$target_sha" || {
      say "FATAL unable to write campaign state"
      return 1
    }
    say "release baseline established: $release_tag @ $source_sha"
  fi

  if [[ -f "$active_state" ]]; then
    old_active="$(state_value "$active_state" CAMPAIGN_STATE)" || old_active=""
    if [[ -n "$old_active" && "$old_active" != "$campaign_state" ]] && pgrep -f 'campaign-675-supervisor.sh' >/dev/null 2>&1; then
      say "FATAL another #675 supervisor is active; refusing to repoint its release baseline"
      return 1
    fi
  fi
  write_active_state "$active_state" "$campaign_state" || { say "FATAL unable to write active campaign state"; return 1; }

  if [[ "${CAMPAIGN_675_NO_START:-false}" == true ]]; then
    say "baseline ready without supervisor start: $campaign_state"
    return 0
  fi
  if pgrep -f "campaign-675-supervisor.sh $campaign_state" >/dev/null 2>&1; then
    say "supervisor already running for $release_tag"
    return 0
  fi
  nohup caffeinate -i -s scripts/campaign-675-supervisor.sh "$campaign_state" >/dev/null 2>&1 &
  say "campaign started for $release_tag @ $source_sha (supervisor pid $!)"
  say "evidence: $campaign_dir"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  campaign_675_reseat_main "$@"
fi
