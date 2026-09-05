#!/usr/bin/env bash
# Disposable Proxmox KVM wrapper for scripts/run-fuzz-campaign.sh.
#
# `--start` packages the source, stages it on the Proxmox host, and launches
# the full VM lifecycle (create guest, install Zig, run the fuzz campaign,
# collect evidence, decide the guest's fate) DETACHED on the Proxmox host via
# setsid+nohup, then returns in seconds. It does not hold an SSH session open
# for a row's full multi-hour duration.
#
# `--collect --out-dir DIR` reconnects later — a cheap, short SSH round trip
# — to check whether the detached job has finished. If not, it reports
# status and exits 2 without touching anything. Once finished, it pulls
# evidence back, verifies it locally, and destroys/keeps the guest exactly as
# `--start` would have decided synchronously.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"

PROXMOX_SSH_TARGET="${PROXMOX_SSH_TARGET:-root@10.250.250.2}"
PROXMOX_SSH_BIND="${PROXMOX_SSH_BIND:-10.250.250.1}"
PROXMOX_VM_ID="${PROXMOX_VM_ID:-}"
PROXMOX_VM_NAME="${PROXMOX_VM_NAME:-tardigrade-fuzz-${timestamp}}"
PROXMOX_VM_IMAGE="${PROXMOX_VM_IMAGE:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
PROXMOX_STORAGE="${PROXMOX_STORAGE:-}"
PROXMOX_BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
PROXMOX_VM_IP="${PROXMOX_VM_IP:-dhcp}"
PROXMOX_VM_GATEWAY="${PROXMOX_VM_GATEWAY:-}"
PROXMOX_SNIPPETS_STORAGE="${PROXMOX_SNIPPETS_STORAGE:-}"
PROXMOX_VCPUS="${PROXMOX_VCPUS:-4}"
PROXMOX_MEMORY_MB="${PROXMOX_MEMORY_MB:-8192}"
PROXMOX_DISK_GB="${PROXMOX_DISK_GB:-32}"
TARDIGRADE_REF="${TARDIGRADE_REF:-HEAD}"
ZIG_VERSION="${ZIG_VERSION:-0.16.0}"
CAMPAIGN_TIER="${CAMPAIGN_TIER:-1}"
CAMPAIGN_FAMILY="${CAMPAIGN_FAMILY:-quic}"
CAMPAIGN_TARGET="${CAMPAIGN_TARGET:-}"
CAMPAIGN_BUDGET="${CAMPAIGN_BUDGET:-1K}"
CAMPAIGN_WATCHDOG="${CAMPAIGN_WATCHDOG:-}"
CAMPAIGN_NONCANONICAL=false
CAMPAIGN_SKIP_PREFLIGHT=false
LOCAL_OUT_DIR="${LOCAL_OUT_DIR:-$repo/artifacts/hardening/fuzz/proxmox-${timestamp}}"
REMOTE_STAGE="${REMOTE_STAGE:-/tmp/tardigrade-proxmox-fuzz-${timestamp}}"
KEEP_GUEST=false
KEEP_ON_FAILURE=true
MODE=""

usage() {
  cat <<'EOF'
Usage:
  scripts/run-proxmox-fuzz-campaign.sh --start [OPTIONS]
  scripts/run-proxmox-fuzz-campaign.sh --collect --out-dir DIR

--start launches the full VM lifecycle (create, install Zig, run the fuzz
campaign, collect evidence, decide guest fate) DETACHED on the Proxmox host
and returns in seconds. --collect reconnects later (a cheap, short SSH round
trip) to check whether the detached job has finished: not yet -> prints
status and exits 2 without touching anything; finished -> pulls evidence
back, verifies it locally, and destroys/keeps the guest.

Proxmox:
  --target SSH_TARGET       Proxmox SSH target
  --bind ADDRESS            Local SSH bind address; "" disables binding
  --vm-id ID                VMID (default: pvesh /cluster/nextid)
  --name NAME               VM name
  --vm-image PATH|URL       Debian cloud image
  --storage NAME            Proxmox image storage
  --bridge NAME             Network bridge
  --ip CIDR|dhcp            Guest IP config
  --gateway IP              Static gateway for CIDR IPs
  --snippets-storage NAME   Storage for cloud-init snippets
  --vcpus N                 vCPU count
  --memory MB               Memory
  --disk GB                 Root disk size

Campaign (only meaningful with --start):
  --tardigrade-ref REF      Local ref to resolve and archive
  --zig-version VERSION     Expected Zig version
  --tier 1|2|3
  --family FAMILY
  --campaign-target NAME    Exact fuzz target filter
  --budget N|K|M|G
  --watchdog SECONDS        Bound one fuzz process; expiry records possible_hang
                            instead of running unbounded
  --noncanonical-smoke      Pass through to local runner
  --skip-preflight          Pass through only with --noncanonical-smoke

Evidence:
  --out-dir DIR             Local artifact destination. --start records the
                             remote connection here for a later --collect;
                             --collect reads it back and requires this flag.

Lifecycle:
  --keep-guest              Always keep VM
  --destroy-on-failure      Destroy VM after failed campaign once artifacts copy
                            succeeds. Default keeps it for debugging.
  --help                    Show this help.
EOF
}

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --start) MODE="start"; shift ;;
    --collect) MODE="collect"; shift ;;
    --target) PROXMOX_SSH_TARGET="$2"; shift 2 ;;
    --bind) PROXMOX_SSH_BIND="$2"; shift 2 ;;
    --vm-id) PROXMOX_VM_ID="$2"; shift 2 ;;
    --name) PROXMOX_VM_NAME="$2"; shift 2 ;;
    --vm-image) PROXMOX_VM_IMAGE="$2"; shift 2 ;;
    --storage) PROXMOX_STORAGE="$2"; shift 2 ;;
    --bridge) PROXMOX_BRIDGE="$2"; shift 2 ;;
    --ip) PROXMOX_VM_IP="$2"; shift 2 ;;
    --gateway) PROXMOX_VM_GATEWAY="$2"; shift 2 ;;
    --snippets-storage) PROXMOX_SNIPPETS_STORAGE="$2"; shift 2 ;;
    --vcpus) PROXMOX_VCPUS="$2"; shift 2 ;;
    --memory) PROXMOX_MEMORY_MB="$2"; shift 2 ;;
    --disk) PROXMOX_DISK_GB="$2"; shift 2 ;;
    --tardigrade-ref) TARDIGRADE_REF="$2"; shift 2 ;;
    --zig-version) ZIG_VERSION="$2"; shift 2 ;;
    --tier) CAMPAIGN_TIER="$2"; shift 2 ;;
    --family) CAMPAIGN_FAMILY="$2"; shift 2 ;;
    --campaign-target) CAMPAIGN_TARGET="$2"; shift 2 ;;
    --budget) CAMPAIGN_BUDGET="$2"; shift 2 ;;
    --watchdog) CAMPAIGN_WATCHDOG="$2"; shift 2 ;;
    --noncanonical-smoke) CAMPAIGN_NONCANONICAL=true; shift ;;
    --skip-preflight) CAMPAIGN_SKIP_PREFLIGHT=true; shift ;;
    --out-dir) LOCAL_OUT_DIR="$2"; shift 2 ;;
    --keep-guest) KEEP_GUEST=true; shift ;;
    --destroy-on-failure) KEEP_ON_FAILURE=false; shift ;;
    --help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$MODE" == "start" || "$MODE" == "collect" ]] || die "pass exactly one of --start or --collect (see --help)"

build_ssh_opts() {
  ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=20)
  scp_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6)
  if [[ -n "$PROXMOX_SSH_BIND" ]]; then
    ssh_opts+=(-b "$PROXMOX_SSH_BIND")
    scp_opts+=(-o "BindAddress=${PROXMOX_SSH_BIND}")
  fi
}

ssh_pve() {
  # shellcheck disable=SC2029 # helper intentionally executes caller-supplied remote commands on the configured Proxmox host.
  ssh "${ssh_opts[@]}" "$PROXMOX_SSH_TARGET" "$@"
}
scp_to_pve() { scp "${scp_opts[@]}" "$1" "${PROXMOX_SSH_TARGET}:$2"; }
scp_from_pve() { scp "${scp_opts[@]}" "${PROXMOX_SSH_TARGET}:$1" "$2"; }
# Large pulls (the multi-hundred-MB fuzz artifact tarball) over a link that
# resets mid-transfer need rsync's --partial resume, not scp: an interrupted
# scp of a 500MB+ tarball starts over from zero every retry and can fail
# indefinitely on a flaky link, while rsync picks up where it left off
# (#675 campaign finding: a raw scp of the same tarball reset twice in a
# row after 26+ minutes at 270/544MB; rsync --partial completed the
# identical transfer in ~14 minutes on the same link).
rsync_from_pve() {
  local ssh_cmd="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6"
  [[ -n "$PROXMOX_SSH_BIND" ]] && ssh_cmd+=" -b $(printf '%q' "$PROXMOX_SSH_BIND")"
  rsync -e "$ssh_cmd" --partial "${PROXMOX_SSH_TARGET}:$1" "$2"
}
write_param() { printf '%s=' "$1" >>"$params_file"; printf '%q\n' "$2" >>"$params_file"; }

if [[ "$MODE" == "collect" ]]; then
  [[ -n "$LOCAL_OUT_DIR" ]] || die "--out-dir is required for --collect"
  async_state="$LOCAL_OUT_DIR/async.env"
  [[ -f "$async_state" ]] || die "no async start recorded at $async_state; run --start first"
  # REMOTE_STAGE/PROXMOX_SSH_TARGET/PROXMOX_SSH_BIND identify the exact
  # remote job --start launched; the saved state is authoritative over
  # whatever these flags default to on this invocation.
  # shellcheck source=/dev/null
  source "$async_state"
  build_ssh_opts

  case "$REMOTE_STAGE" in
    /tmp/tardigrade-proxmox-fuzz-*|/var/lib/vz/tmp/tardigrade-proxmox-fuzz-*) ;;
    *) die "unsafe REMOTE_STAGE recorded in $async_state" ;;
  esac

  if ! ssh_pve "test -f $(printf '%q' "$REMOTE_STAGE/orchestrate.done")"; then
    say "==> still running (started ${started_utc:-unknown})"
    ssh_pve "tail -n 20 $(printf '%q' "$REMOTE_STAGE/orchestrate.log") 2>/dev/null" || true
    exit 2
  fi

  say "==> detached job finished; collecting evidence"
  artifact_tgz="$LOCAL_OUT_DIR/guest-fuzz-artifacts.tgz"
  metadata_tgz="$LOCAL_OUT_DIR/proxmox-metadata.tgz"
  remote_state_file="$LOCAL_OUT_DIR/guest-state.env"

  # Deliberately NOT removing $artifact_tgz here: it's the one large
  # (multi-hundred-MB) pull, and rsync's --partial (see rsync_from_pve)
  # only has something to resume from if a prior --collect attempt's
  # partial download survives to the next one on the same flaky link
  # (#675 campaign finding).
  rm -f "$metadata_tgz" "$remote_state_file"
  scp_from_pve "$REMOTE_STAGE/guest-state.env" "$remote_state_file"
  guest_id=""
  guest_allocated=false
  guest_reachable=false
  remote_exit_code=1
  # shellcheck source=/dev/null
  source "$remote_state_file"
  remote_status="$remote_exit_code"

  local_collection_ok=false
  if [[ "${guest_allocated:-false}" == true && "${guest_reachable:-false}" == true ]]; then
    if rsync_from_pve "$REMOTE_STAGE/artifacts.tgz" "$artifact_tgz" &&
      scp_from_pve "$REMOTE_STAGE/proxmox-metadata.tgz" "$metadata_tgz" &&
      [[ -s "$artifact_tgz" ]] &&
      tar -tzf "$artifact_tgz" >/dev/null &&
      tar -xzf "$artifact_tgz" -C "$LOCAL_OUT_DIR"; then
      local_collection_ok=true
    fi
  fi

  destroy_guest=false
  if [[ "${guest_allocated:-false}" == true && "$local_collection_ok" == true && "$KEEP_GUEST" != true ]]; then
    if [[ "$remote_status" -eq 0 || "$KEEP_ON_FAILURE" != true ]]; then
      destroy_guest=true
    fi
  fi

  if [[ "$destroy_guest" == true ]]; then
    say "==> destroying VM $guest_id after verified local artifact collection"
    ssh_pve "qm stop $(printf '%q' "$guest_id") >/dev/null 2>&1 || true; qm destroy $(printf '%q' "$guest_id") --purge >/dev/null 2>&1 || true"
  else
    if [[ "${guest_allocated:-false}" == true ]]; then
      say "==> kept VM $guest_id for inspection"
    fi
  fi

  if [[ "$local_collection_ok" == true ]]; then
    # REMOTE_STAGE (source.tgz, orchestrate logs, and the collected
    # artifacts.tgz — potentially hundreds of MB, since it includes the
    # whole guest .zig-cache) is redundant once evidence is verified
    # locally. /tmp on the Proxmox host is a small tmpfs; leaving every
    # row's stage directory behind exhausts it within a handful of rows
    # (observed directly: a 22h possible_hang row's real evidence was
    # lost to "No space left on device" mid-collection before this
    # cleanup existed).
    ssh_pve "rm -rf $(printf '%q' "$REMOTE_STAGE")" || true
  fi
  [[ "$local_collection_ok" == true ]] || die "artifact collection failed before verified local copy; VM was left intact when allocated"
  say "==> artifacts collected in $LOCAL_OUT_DIR"
  exit "$remote_status"
fi

# MODE == start
build_ssh_opts

case "$REMOTE_STAGE" in
  /tmp/tardigrade-proxmox-fuzz-*|/var/lib/vz/tmp/tardigrade-proxmox-fuzz-*) ;;
  *) die "unsafe REMOTE_STAGE" ;;
esac
[[ "$PROXMOX_VCPUS $PROXMOX_MEMORY_MB $PROXMOX_DISK_GB" =~ ^[0-9]+[[:space:]][0-9]+[[:space:]][0-9]+$ ]] || die "vcpus, memory, and disk must be positive integers"

mkdir -p "$LOCAL_OUT_DIR"
src_tgz="$LOCAL_OUT_DIR/source.tgz"
src_sha="$LOCAL_OUT_DIR/source.tgz.sha256"
params_file="$LOCAL_OUT_DIR/campaign.env"

TARDIGRADE_SHA="$(git rev-parse "${TARDIGRADE_REF}^{commit}")"
say "==> packaging source from ${TARDIGRADE_REF} (${TARDIGRADE_SHA})"
git archive --format=tar "$TARDIGRADE_SHA" | gzip -n >"$src_tgz"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$src_tgz" | awk '{ print $1 "  source.tgz" }' >"$src_sha"
else
  shasum -a 256 "$src_tgz" | awk '{ print $1 "  source.tgz" }' >"$src_sha"
fi

: >"$params_file"
write_param PROXMOX_VM_ID "$PROXMOX_VM_ID"
write_param PROXMOX_VM_NAME "$PROXMOX_VM_NAME"
write_param PROXMOX_VM_IMAGE "$PROXMOX_VM_IMAGE"
write_param PROXMOX_STORAGE "$PROXMOX_STORAGE"
write_param PROXMOX_BRIDGE "$PROXMOX_BRIDGE"
write_param PROXMOX_VM_IP "$PROXMOX_VM_IP"
write_param PROXMOX_VM_GATEWAY "$PROXMOX_VM_GATEWAY"
write_param PROXMOX_SNIPPETS_STORAGE "$PROXMOX_SNIPPETS_STORAGE"
write_param PROXMOX_VCPUS "$PROXMOX_VCPUS"
write_param PROXMOX_MEMORY_MB "$PROXMOX_MEMORY_MB"
write_param PROXMOX_DISK_GB "$PROXMOX_DISK_GB"
write_param TARDIGRADE_SHA "$TARDIGRADE_SHA"
write_param ZIG_VERSION "$ZIG_VERSION"
write_param CAMPAIGN_TIER "$CAMPAIGN_TIER"
write_param CAMPAIGN_FAMILY "$CAMPAIGN_FAMILY"
write_param CAMPAIGN_TARGET "$CAMPAIGN_TARGET"
write_param CAMPAIGN_BUDGET "$CAMPAIGN_BUDGET"
write_param CAMPAIGN_WATCHDOG "$CAMPAIGN_WATCHDOG"
write_param CAMPAIGN_NONCANONICAL "$CAMPAIGN_NONCANONICAL"
write_param CAMPAIGN_SKIP_PREFLIGHT "$CAMPAIGN_SKIP_PREFLIGHT"
write_param KEEP_GUEST "$KEEP_GUEST"
write_param KEEP_ON_FAILURE "$KEEP_ON_FAILURE"

say "==> staging fuzz campaign inputs on $PROXMOX_SSH_TARGET"
ssh_pve "rm -rf $(printf '%q' "$REMOTE_STAGE") && mkdir -p $(printf '%q' "$REMOTE_STAGE")"
scp_to_pve "$src_tgz" "$REMOTE_STAGE/source.tgz"
scp_to_pve "$src_sha" "$REMOTE_STAGE/source.tgz.sha256"
scp_to_pve "$params_file" "$REMOTE_STAGE/campaign.env"

say "==> staging orchestration script on $PROXMOX_SSH_TARGET"
ssh_pve "cat > $(printf '%q' "$REMOTE_STAGE/orchestrate.sh")" <<'REMOTE'
set -euo pipefail

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

source "$REMOTE_STAGE/campaign.env"
guest_id="$PROXMOX_VM_ID"
guest_allocated=false
guest_reachable=false
guest_ip=""
guest_ssh_key="$REMOTE_STAGE/vm_ssh_key"
artifact_tgz="$REMOTE_STAGE/artifacts.tgz"
state_file="$REMOTE_STAGE/guest-state.env"
cloud_init_snippet_path=""

require_tool() { command -v "$1" >/dev/null 2>&1 || die "$1 not found on Proxmox host"; }
next_guest_id() {
  if [[ -n "$guest_id" ]]; then printf '%s\n' "$guest_id"; else pvesh get /cluster/nextid; fi
}
storage_with_images() {
  if [[ -n "$PROXMOX_STORAGE" ]]; then printf '%s\n' "$PROXMOX_STORAGE"; return; fi
  pvesm status -content images 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1; exit }'
}
run_guest() {
  # This SSH hop (Proxmox host -> guest VM) is now the only connection that
  # needs to survive a row's full duration, and it runs entirely on the
  # Proxmox host itself (a persistent server), not the controlling Mac.
  # Keepalives still guard against idle-timeout teardown regardless.
  ssh -n -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=20 "root@$guest_ip" "$1"
}
push_guest() {
  scp -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$1" "root@$guest_ip:$2"
}
pull_guest() {
  scp -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$guest_ip:$1" "$2"
}
discover_vm_ip_from_neighbors() {
  local mac tap
  mac="$(qm config "$guest_id" | awk -F '[=,]' '/^net0:/ { print tolower($2); exit }')"
  [[ -n "$mac" ]] || return 1
  tap="tap${guest_id}i0"
  ip neigh show 2>/dev/null | awk -v mac="$mac" -v tap="$tap" 'tolower($0) ~ mac && $0 ~ tap { print $1; exit }'
}
write_state() {
  {
    printf 'guest_id='; printf '%q\n' "$guest_id"
    printf 'guest_allocated='; printf '%q\n' "$guest_allocated"
    printf 'guest_reachable='; printf '%q\n' "$guest_reachable"
    printf 'guest_ip='; printf '%q\n' "$guest_ip"
    printf 'remote_artifact_tgz='; printf '%q\n' "$artifact_tgz"
    printf 'remote_metadata_tgz='; printf '%q\n' "$REMOTE_STAGE/proxmox-metadata.tgz"
    printf 'remote_exit_code='; printf '%q\n' "$status"
  } >"$state_file"
}
collect_artifacts() {
  [[ "$guest_reachable" == true ]] || return 1
  run_guest 'tar -C /work -czf /root/tardigrade-fuzz-artifacts.tgz Tardigrade/artifacts Tardigrade/.zig-cache 2>/dev/null || tar -C /work -czf /root/tardigrade-fuzz-artifacts.tgz Tardigrade/artifacts'
  pull_guest /root/tardigrade-fuzz-artifacts.tgz "$artifact_tgz"
  [[ -s "$artifact_tgz" ]]
  qm config "$guest_id" >"$REMOTE_STAGE/guest-config.txt" 2>&1 || true
  {
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'vm_id=%s\n' "$guest_id"
    printf 'vm_name=%s\n' "$PROXMOX_VM_NAME"
    printf 'guest_ip=%s\n' "$guest_ip"
    printf 'tardigrade_sha=%s\n' "$TARDIGRADE_SHA"
    printf 'source_archive_sha256=%s\n' "$(awk '{print $1}' "$REMOTE_STAGE/source.tgz.sha256")"
    printf 'pveversion<<EOF\n'; pveversion -v 2>&1 || true; printf 'EOF\n'
    printf 'host_uname<<EOF\n'; uname -a; printf 'EOF\n'
    printf 'host_lscpu<<EOF\n'; lscpu 2>&1 || true; printf 'EOF\n'
  } >"$REMOTE_STAGE/proxmox-host-metadata.txt"
  tar -C "$REMOTE_STAGE" -czf "$REMOTE_STAGE/proxmox-metadata.tgz" proxmox-host-metadata.txt guest-config.txt 2>/dev/null || true
}
cleanup() {
  status=$?
  collection_ok=false
  if [[ "$guest_allocated" == true ]]; then
    if collect_artifacts; then
      collection_ok=true
    else
      say "==> artifact collection failed; keeping VM $guest_id" >&2
      status=1
    fi
    say "==> staged artifacts on Proxmox for VM $guest_id; local caller owns verified collection before teardown"
  fi
  write_state
  [[ -n "$cloud_init_snippet_path" ]] && rm -f "$cloud_init_snippet_path" >/dev/null 2>&1 || true
  # Sole completion signal a detached --start caller polls for via
  # --collect. Written strictly after write_state so a poller that
  # observes this file can trust guest-state.env is already complete.
  touch "$REMOTE_STAGE/orchestrate.done"
  exit "$status"
}
trap cleanup EXIT INT TERM

require_tool qm
require_tool pvesm
require_tool pvesh
require_tool ssh-keygen
require_tool curl

guest_id="$(next_guest_id)"
[[ "$guest_id" =~ ^[0-9]+$ ]] || die "invalid VM id: $guest_id"
qm status "$guest_id" >/dev/null 2>&1 && die "VM $guest_id already exists"
storage="$(storage_with_images)"
[[ -n "$storage" ]] || die "no active Proxmox storage with images content found"

ssh-keygen -q -t ed25519 -N '' -f "$guest_ssh_key"
image_path="$REMOTE_STAGE/base.qcow2"
if [[ "$PROXMOX_VM_IMAGE" =~ ^https?:// ]]; then
  curl -fsSL "$PROXMOX_VM_IMAGE" -o "$image_path"
else
  image_path="$PROXMOX_VM_IMAGE"
fi

snippets_storage="$PROXMOX_SNIPPETS_STORAGE"
if [[ -z "$snippets_storage" ]]; then
  snippets_storage="$(pvesm status -content snippets 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1; exit }')"
fi
[[ -n "$snippets_storage" ]] || die "no snippets storage found; pass --snippets-storage"
cloud_init_snippet_path="$(pvesm path "${snippets_storage}:snippets/tardigrade-fuzz-${guest_id}.yml" 2>/dev/null || true)"
[[ -n "$cloud_init_snippet_path" ]] || die "cannot resolve snippets storage path"
mkdir -p "$(dirname "$cloud_init_snippet_path")"
cat >"$cloud_init_snippet_path" <<CLOUDINIT
#cloud-config
disable_root: false
ssh_authorized_keys:
  - $(cat "$guest_ssh_key.pub")
package_update: true
packages:
  - bash
  - ca-certificates
  - curl
  - git
  - libssl-dev
  - openssl
  - qemu-guest-agent
  - tar
  - xz-utils
  - build-essential
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
CLOUDINIT
snippet_ref="${snippets_storage}:snippets/$(basename "$cloud_init_snippet_path")"

say "==> creating VM $guest_id ($PROXMOX_VM_NAME)"
qm create "$guest_id" --name "$PROXMOX_VM_NAME" --cores "$PROXMOX_VCPUS" --memory "$PROXMOX_MEMORY_MB" \
  --net0 "virtio,bridge=${PROXMOX_BRIDGE}" --ostype l26 --agent enabled=1 --serial0 socket --vga serial0
guest_allocated=true
qm importdisk "$guest_id" "$image_path" "$storage" >/dev/null
disk_ref="$(qm config "$guest_id" | awk -F ': ' '/unused[0-9]+:/ { print $2; exit }')"
qm set "$guest_id" --scsihw virtio-scsi-pci --scsi0 "$disk_ref" >/dev/null
qm resize "$guest_id" scsi0 "${PROXMOX_DISK_GB}G" >/dev/null
qm set "$guest_id" --boot order=scsi0 --ide2 "${storage}:cloudinit" --ciuser root --sshkeys "$guest_ssh_key.pub" --cicustom "user=${snippet_ref}" >/dev/null
if [[ "$PROXMOX_VM_IP" == dhcp ]]; then
  qm set "$guest_id" --ipconfig0 ip=dhcp >/dev/null
else
  [[ -n "$PROXMOX_VM_GATEWAY" ]] || die "--gateway is required with a static --ip"
  qm set "$guest_id" --ipconfig0 "ip=${PROXMOX_VM_IP},gw=${PROXMOX_VM_GATEWAY}" >/dev/null
fi
qm start "$guest_id" >/dev/null

say "==> waiting for VM SSH"
reachable=false
for _ in $(seq 1 180); do
  if [[ "$PROXMOX_VM_IP" != dhcp ]]; then
    guest_ip="${PROXMOX_VM_IP%%/*}"
  elif qm agent "$guest_id" ping >/dev/null 2>&1; then
    guest_ip="$(qm guest cmd "$guest_id" network-get-interfaces 2>/dev/null | grep -Eo '"ip-address"[[:space:]]*:[[:space:]]*"([0-9]{1,3}\.){3}[0-9]{1,3}"' | sed -E 's/.*"([^"]+)"/\1/' | grep -v '^127\.' | head -1 || true)"
  else
    guest_ip="$(discover_vm_ip_from_neighbors || true)"
  fi
  if [[ -n "$guest_ip" ]] && run_guest 'true' >/dev/null 2>&1; then
    reachable=true
    guest_reachable=true
    break
  fi
  sleep 2
done
[[ "$reachable" == true ]] || die "VM SSH did not become reachable"

say "==> installing Zig $ZIG_VERSION and source"
push_guest "$REMOTE_STAGE/source.tgz" /root/source.tgz
push_guest "$REMOTE_STAGE/source.tgz.sha256" /root/source.tgz.sha256
run_guest "set -euo pipefail
mkdir -p /work/Tardigrade /opt/zig
cd /root && sha256sum -c source.tgz.sha256
tar -C /work/Tardigrade -xzf /root/source.tgz
curl -fsSL https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz | tar -C /opt/zig --strip-components=1 -xJ
ln -sf /opt/zig/zig /usr/local/bin/zig
cd /work/Tardigrade
test \"\$(zig version)\" = \"$ZIG_VERSION\"
"

guest_output="/work/Tardigrade/artifacts/hardening/fuzz/proxmox-${guest_id}-${CAMPAIGN_TIER}-${CAMPAIGN_FAMILY}"
runner_cmd=(scripts/run-fuzz-campaign.sh --tier "$CAMPAIGN_TIER" --family "$CAMPAIGN_FAMILY" --budget "$CAMPAIGN_BUDGET" --output "$guest_output" --source-sha "$TARDIGRADE_SHA")
if [[ -n "$CAMPAIGN_TARGET" ]]; then runner_cmd+=(--target "$CAMPAIGN_TARGET"); fi
if [[ -n "$CAMPAIGN_WATCHDOG" ]]; then runner_cmd+=(--watchdog "$CAMPAIGN_WATCHDOG"); fi
if [[ "$CAMPAIGN_NONCANONICAL" == true ]]; then runner_cmd+=(--noncanonical-smoke); fi
if [[ "$CAMPAIGN_SKIP_PREFLIGHT" == true ]]; then runner_cmd+=(--skip-preflight); fi

printf '%q ' "${runner_cmd[@]}" >"$REMOTE_STAGE/guest-command.txt"
say "==> running fuzz campaign in VM"
run_guest "cd /work/Tardigrade && $(cat "$REMOTE_STAGE/guest-command.txt")"
REMOTE

say "==> launching detached fuzz campaign lifecycle on $PROXMOX_SSH_TARGET"
# `cd X && setsid ... &` keeps the remote shell blocked in do_wait() even
# after disown (observed directly: a `cd dir && cmd &` background job holds
# the ssh channel open for the child's full runtime, while `cd dir; cmd &`
# with cd as its own statement detaches in ~1s). Keep `cd` a separate
# statement so this call returns immediately instead of blocking for the
# row's full duration.
ssh_pve "cd $(printf '%q' "$REMOTE_STAGE") || exit 1; REMOTE_STAGE=$(printf '%q' "$REMOTE_STAGE") setsid nohup bash orchestrate.sh >orchestrate.log 2>&1 </dev/null & disown; sleep 1; echo launched"

{
  printf 'REMOTE_STAGE=%s\n' "$(printf '%q' "$REMOTE_STAGE")"
  printf 'PROXMOX_SSH_TARGET=%s\n' "$(printf '%q' "$PROXMOX_SSH_TARGET")"
  printf 'PROXMOX_SSH_BIND=%s\n' "$(printf '%q' "$PROXMOX_SSH_BIND")"
  printf 'TARDIGRADE_SHA=%s\n' "$(printf '%q' "$TARDIGRADE_SHA")"
  printf 'KEEP_GUEST=%s\n' "$(printf '%q' "$KEEP_GUEST")"
  printf 'KEEP_ON_FAILURE=%s\n' "$(printf '%q' "$KEEP_ON_FAILURE")"
  printf 'started_utc=%s\n' "$(printf '%q' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")"
} >"$LOCAL_OUT_DIR/async.env"

say "==> launched; connection closed. poll with:"
say "    scripts/run-proxmox-fuzz-campaign.sh --collect --out-dir $LOCAL_OUT_DIR"
