#!/usr/bin/env bash
# Shared durable row-completion contract for the #675 driver and watchdog.

campaign_675_family_target_count() {
  case "$1" in
    crypto) echo 6 ;; pki) echo 7 ;; quic) echo 20 ;;
    tls-protocol) echo 5 ;; tls-record) echo 6 ;; tls-resumption) echo 11 ;;
    *) echo 0 ;;
  esac
}

# A row is collected only after the collector has verified local artifacts and
# atomically recorded the remote campaign exit code.  The guest state and
# manifest make a stale or hand-written sidecar insufficient on its own.
campaign_675_row_collected() {
  local row_dir="$1"
  [[ -f "$row_dir/collect.rc" && -f "$row_dir/guest-state.env" ]] || return 1
  find "$row_dir" -name manifest.jsonl -print -quit 2>/dev/null | grep -q .
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
# local archives and manifest before deriving the result from guest-state.env.
campaign_675_recover_collected_row() {
  local row_dir="$1" status
  campaign_675_row_collected "$row_dir" && return 0
  [[ -f "$row_dir/guest-state.env" && -s "$row_dir/guest-fuzz-artifacts.tgz" && -s "$row_dir/proxmox-metadata.tgz" ]] || return 1
  find "$row_dir" -name manifest.jsonl -print -quit 2>/dev/null | grep -q . || return 1
  tar -tzf "$row_dir/guest-fuzz-artifacts.tgz" >/dev/null 2>&1 || return 1
  tar -tzf "$row_dir/proxmox-metadata.tgz" >/dev/null 2>&1 || return 1
  status="$(awk -F= '$1 == "remote_exit_code" { if (++count == 1) value = $2 } END { if (count == 1 && value ~ /^[0-9]+$/) print value }' "$row_dir/guest-state.env")"
  [[ -n "$status" ]] || return 1
  campaign_675_write_collect_result "$row_dir" "$status"
}

# A row passes only when collection was durable, every manifest record passed,
# and a Tier-1 family has complete target coverage.
campaign_675_row_passed() {
  local evidence_root="$1" rid="$2" tier="${3:-}" family="${4:-}" rc pass_n bad_n want
  campaign_675_row_collected "$evidence_root/$rid" || return 1
  rc="$(cat "$evidence_root/$rid/collect.rc" 2>/dev/null || echo missing)"
  [[ "$rc" == "0" ]] || return 1
  bad_n=$(find "$evidence_root/$rid" -name manifest.jsonl -exec grep -ho '"status":"[a-z_]*"' {} + 2>/dev/null | grep -cv '"status":"pass"')
  [[ "$bad_n" -eq 0 ]] || return 1
  pass_n=$(find "$evidence_root/$rid" -name manifest.jsonl -exec grep -ho '"status":"pass"' {} + 2>/dev/null | wc -l | tr -d ' ')
  [[ "$pass_n" -ge 1 ]] || return 1
  if [[ "$tier" == "1" ]]; then
    want=$(campaign_675_family_target_count "$family")
    [[ "$want" -eq 0 || "$pass_n" -eq "$want" ]] || return 1
  fi
}

# Durable campaign disposition. A collected non-pass remains a hard stop until
# human triage records the issue, fix, and verification in this row directory.
campaign_675_row_disposition() {
  local evidence_root="$1" rid="$2" tier="$3" family="$4" row_dir
  row_dir="$evidence_root/$rid"
  if campaign_675_row_passed "$evidence_root" "$rid" "$tier" "$family"; then
    printf 'pass\n'; return
  fi
  if campaign_675_row_collected "$row_dir"; then
    if find "$row_dir" -name manifest.jsonl -exec grep -qE '"status":"(fail|possible_hang)"' {} + 2>/dev/null; then
      if [[ "$(awk -F= '$1 == "DISPOSITION" { print $2 }' "$row_dir/disposition.env" 2>/dev/null)" == dispositioned_finding ]] &&
        grep -qE '^ISSUE=.+|^FIX_COMMIT=.+|^VERIFICATION=.+' "$row_dir/disposition.env" 2>/dev/null; then
        printf 'dispositioned_finding\n'; return
      fi
      printf 'pending_finding\n'; return
    fi
  fi
  printf 'interrupted\n'
}
