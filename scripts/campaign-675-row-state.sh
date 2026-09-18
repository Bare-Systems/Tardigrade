#!/usr/bin/env bash
# Shared durable row-completion contract for the #675 driver and watchdog.

campaign_675_family_step() {
  case "$1" in
    tls-protocol) echo test-tls-protocol-fuzz ;;
    tls-record) echo test-tls-record-fuzz ;;
    tls-resumption) echo test-tls-resumption-fuzz ;;
    pki) echo test-pki-fuzz ;;
    crypto) echo test-crypto-provider-fuzz ;;
    quic) echo test-quic ;;
    *) return 1 ;;
  esac
}

campaign_675_budget_mutations() {
  local budget="$1" n unit
  [[ "$budget" =~ ^([0-9]+)([KMG])$ ]] || return 1
  n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
  case "$unit" in K) echo $((n * 1000)) ;; M) echo $((n * 1000000)) ;; G) echo $((n * 1000000000)) ;; esac
}

# Keep this deliberately equivalent to run-fuzz-campaign.sh: append-only
# manifests are evidence, so a single matching PASS satisfies one frozen
# target even if earlier attempts for that target were interrupted or failed.
campaign_675_manifest_has_pass() {
  local manifest="$1" release="$2" sha="$3" step="$4" filter="$5" min_budget="$6"
  [[ -f "$manifest" ]] || return 1
  awk -v release="$release" -v sha="$sha" -v step="$step" -v filter="$filter" -v min_budget="$min_budget" '
    $0 ~ "\"release_tag\":\"" release "\"" &&
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

campaign_675_manifest_is_collected() {
  local row_dir="$1" manifest="$2" dir
  dir="$(dirname "$manifest")"
  while [[ "$dir" == "$row_dir" || "$dir" == "$row_dir"/* ]]; do
    if [[ -f "$dir/guest-state.env" ]]; then
      [[ -f "$dir/collect.rc" && "$(cat "$dir/collect.rc" 2>/dev/null || true)" == 0 ]] && return 0
      return 1
    fi
    [[ "$dir" == "$row_dir" ]] && return 1
    dir="$(dirname "$dir")"
  done
  return 1
}

campaign_675_manifest_attempt_is_collected() {
  local row_dir="$1" manifest="$2" dir
  dir="$(dirname "$manifest")"
  while [[ "$dir" == "$row_dir" || "$dir" == "$row_dir"/* ]]; do
    if [[ -f "$dir/guest-state.env" ]]; then
      [[ -f "$dir/collect.rc" ]] && return 0
      return 1
    fi
    [[ "$dir" == "$row_dir" ]] && return 1
    dir="$(dirname "$dir")"
  done
  return 1
}

campaign_675_row_has_durable_finding() {
  local row_dir="$1" manifest
  while IFS= read -r -d '' manifest; do
    campaign_675_manifest_attempt_is_collected "$row_dir" "$manifest" || continue
    grep -qE '"status":"(fail|possible_hang)"' "$manifest" && return 0
  done < <(find "$row_dir" -name manifest.jsonl -print0 2>/dev/null)
  return 1
}

# A row is collected only after the collector has verified local artifacts and
# atomically recorded the remote campaign exit code.  The guest state and
# manifest make a stale or hand-written sidecar insufficient on its own.
campaign_675_row_collected() {
  local row_dir="$1"
  local collect_file attempt_dir
  while IFS= read -r collect_file; do
    attempt_dir="$(dirname "$collect_file")"
    [[ -f "$attempt_dir/guest-state.env" ]] || continue
    find "$attempt_dir" -path "$attempt_dir/attempts" -prune -o -name manifest.jsonl -print -quit 2>/dev/null | grep -q . && return 0
  done < <(find "$row_dir" -name collect.rc -type f -print 2>/dev/null)
  return 1
}

campaign_675_write_collect_result() {
  local row_dir="$1" status="$2" tmp
  tmp="$row_dir/.collect.rc.$$"
  [[ "$status" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$status" > "$tmp" || return 1
  mv -f "$tmp" "$row_dir/collect.rc"
}

# Recover the one pre-marker crash window: the collector may already have
# copied and verified evidence, while a host crash prevented its caller from
# recording collect.rc and the collector removed REMOTE_STAGE.  Recheck the
# local archives and re-run the collector's evidence checks before deriving the
# result from guest-state.env.
campaign_675_recover_collected_row() {
  local row_dir="$1" status
  campaign_675_row_collected "$row_dir" && return 0
  [[ -f "$row_dir/guest-state.env" && -s "$row_dir/guest-fuzz-artifacts.tgz" && -s "$row_dir/proxmox-metadata.tgz" ]] || return 1
  tar -tzf "$row_dir/guest-fuzz-artifacts.tgz" >/dev/null 2>&1 || return 1
  tar -tzf "$row_dir/proxmox-metadata.tgz" >/dev/null 2>&1 || return 1
  # A previous host death can leave only the first archive member extracted.
  # Re-extraction is idempotent and is the only source trusted for recovery.
  tar -xzf "$row_dir/guest-fuzz-artifacts.tgz" -C "$row_dir" || return 1
  status="$(awk -F= '$1 == "remote_exit_code" { if (++count == 1) value = $2 } END { if (count == 1 && value ~ /^[0-9]+$/) print value }' "$row_dir/guest-state.env")"
  [[ -n "$status" ]] || return 1
  find "$row_dir" -name manifest.jsonl -print -quit 2>/dev/null | grep -q . || return 1
  if find "$row_dir" -name provenance.txt -print -quit 2>/dev/null | grep -q . &&
    find "$row_dir" -name provenance.txt -exec grep -qE '^(preserved_archive|finding_preservation)=FAILED$' {} + 2>/dev/null; then
    return 1
  fi
  if find "$row_dir" -name manifest.jsonl -exec grep -q '"preservation_status":"failed"' {} + 2>/dev/null; then
    return 1
  fi
  if [[ "$status" != 0 ]]; then
    if find "$row_dir" -name manifest.jsonl -exec grep -qE '"status":"(fail|possible_hang)"' {} + 2>/dev/null; then
      find "$row_dir" -name manifest.jsonl -exec grep -qE '"status":"(fail|possible_hang)".*"preservation_status":"ok"' {} + 2>/dev/null || return 1
    elif ! find "$row_dir" -name manifest.jsonl -exec grep -q '"status":"interrupted"' {} + 2>/dev/null; then
      return 1
    fi
  fi
  campaign_675_write_collect_result "$row_dir" "$status"
}

# A row passes only when collection was durable and every target frozen in its
# row plan has an existential matching PASS for this release identity.
campaign_675_row_passed() {
  local evidence_root="$1" rid="$2" tier="${3:-}" family="${4:-}" source_sha release_tag budget record frozen_family frozen_step frozen_target expected=() manifests=() matched
  campaign_675_row_collected "$evidence_root/$rid" || return 1
  source_sha="$(awk -F= '$1 == "SOURCE_SHA" { if (++n == 1) print $2 }' "$evidence_root/campaign.env")"
  release_tag="$(awk -F= '$1 == "RELEASE_TAG" { if (++n == 1) print $2 }' "$evidence_root/campaign.env")"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ && "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || return 1
  budget="$(awk -F '\t' -v r="$rid" '$1 == r { if (++n == 1) print $5 }' "$evidence_root/rows.tsv")"
  [[ -n "$budget" ]] || return 1
  budget="$(campaign_675_budget_mutations "$budget")" || return 1
  if [[ "$tier" == "1" ]]; then
    mapfile -t expected < <(awk -F '\t' -v f="$family" '$1 == f { print $1 "\t" $2 "\t" $3 }' "$evidence_root/targets.tsv" | sort -u)
  else
    target="$(awk -F '\t' -v r="$rid" '$1 == r && $4 != "-" { print $4 }' "$evidence_root/rows.tsv")"
    [[ -n "$target" ]] || return 1
    mapfile -t expected < <(awk -F '\t' -v f="$family" -v t="$target" '$1 == f && $3 == t { print $1 "\t" $2 "\t" $3 }' "$evidence_root/targets.tsv" | sort -u)
  fi
  [[ "${#expected[@]}" -gt 0 ]] || return 1
  mapfile -d '' -t manifests < <(find "$evidence_root/$rid" -name manifest.jsonl -print0)
  for record in "${expected[@]}"; do
    IFS=$'\t' read -r frozen_family frozen_step frozen_target <<< "$record"
    [[ "$frozen_family" == "$family" && -n "$frozen_step" && -n "$frozen_target" ]] || return 1
    matched=false
    for manifest in "${manifests[@]}"; do
      if campaign_675_manifest_is_collected "$evidence_root/$rid" "$manifest" &&
        campaign_675_manifest_has_pass "$manifest" "$release_tag" "$source_sha" "$frozen_step" "$frozen_target" "$budget"; then matched=true; break; fi
    done
    [[ "$matched" == true ]] || return 1
  done
}

# Durable campaign disposition. A collected non-pass remains a hard stop until
# human triage records the issue, fix, and verification in this row directory.
campaign_675_row_disposition() {
  local evidence_root="$1" rid="$2" tier="$3" family="$4" row_dir issue
  row_dir="$evidence_root/$rid"
  if campaign_675_row_has_durable_finding "$row_dir"; then
      if [[ "$(awk -F= '$1 == "DISPOSITION" { print $2 }' "$row_dir/disposition.env" 2>/dev/null)" == dispositioned_finding ]] &&
        [[ "$(grep -cE '^ISSUE=.+' "$row_dir/disposition.env" 2>/dev/null)" == 1 ]] &&
        [[ "$(grep -cE '^FIX_COMMIT=.+' "$row_dir/disposition.env" 2>/dev/null)" == 1 ]] &&
        [[ "$(grep -cE '^VERIFICATION=.+' "$row_dir/disposition.env" 2>/dev/null)" == 1 ]]; then
        issue="$(awk -F= '$1 == "ISSUE" { print $2 }' "$row_dir/disposition.env")"
        [[ "$issue" != '#675' && "$issue" != */issues/675 ]] || { printf 'pending_finding\n'; return; }
        printf 'dispositioned_finding\n'; return
      fi
      printf 'pending_finding\n'; return
  fi
  if campaign_675_row_passed "$evidence_root" "$rid" "$tier" "$family"; then
    printf 'pass\n'; return
  fi
  printf 'interrupted\n'
}
