#!/usr/bin/env bash
# Shared immutable-release state loader for the #675 campaign helpers.

campaign_675_state_value() {
  local state_file="$1" key="$2"
  local -a lines=()
  mapfile -t lines < <(grep -E "^${key}=" "$state_file" 2>/dev/null || true)
  [[ "${#lines[@]}" -eq 1 ]] || return 1
  printf '%s\n' "${lines[0]#*=}"
}

# Load either a direct campaign state path ($1) or the active-state pointer.
# No release identity is implied by the fallback: the pointer is only written
# by `campaign-675-reseat.sh <release-tag>` after that tag is resolved.
campaign_675_load_state() {
  [[ "$#" -le 1 ]] || return 1

  local evidence_root="${CAMPAIGN_675_EVIDENCE_ROOT:-artifacts/hardening/fuzz}"
  local state_file="${1:-}"
  if [[ -z "$state_file" ]]; then
    local active_state="${CAMPAIGN_675_ACTIVE_STATE:-$evidence_root/campaign-675-active.env}"
    state_file="$(campaign_675_state_value "$active_state" CAMPAIGN_STATE)" || return 1
  fi

  local release_tag source_sha campaign_dir row_plan_sha
  release_tag="$(campaign_675_state_value "$state_file" RELEASE_TAG)" || return 1
  source_sha="$(campaign_675_state_value "$state_file" SOURCE_SHA)" || return 1
  campaign_dir="$(campaign_675_state_value "$state_file" CAMPAIGN_DIR)" || return 1
  row_plan_sha="$(campaign_675_state_value "$state_file" ROW_PLAN_SHA256)" || return 1

  [[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z]+)*$ ]] || return 1
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$row_plan_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$campaign_dir" == "$evidence_root/campaign-675-$release_tag" ]] || return 1
  [[ "$state_file" == "$campaign_dir/campaign.env" ]] || return 1
  [[ -f "$campaign_dir/rows.tsv" ]] || return 1
  [[ "$(shasum -a 256 "$campaign_dir/rows.tsv" | awk '{print $1}')" == "$row_plan_sha" ]] || return 1

  RELEASE_TAG="$release_tag"
  SOURCE_SHA="$source_sha"
  CAMPAIGN_DIR="$campaign_dir"
  CAMPAIGN_STATE="$state_file"
  ROW_PLAN_SHA256="$row_plan_sha"
  export RELEASE_TAG SOURCE_SHA CAMPAIGN_DIR CAMPAIGN_STATE ROW_PLAN_SHA256
}
