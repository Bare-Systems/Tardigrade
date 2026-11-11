#!/usr/bin/env bash
# Independent local-CA shipping-gateway ACME acceptance harness (#941).
#
# Drives the real `tardi run` binary (built with `-Dacme-experimental`,
# general TLS profile) through a genuinely independent RFC 8555 server --
# the upstream Pebble test CA, pinned by digest and run as a *separate
# process* (a Docker container) -- rather than any in-tree Zig CA logic.
# `src/acme/fake_ca.zig` and `src/acme/live_ca_server.zig` are never used
# here: those back the existing component/composition suites
# (`src/acme/orders_tests.zig`, `src/acme/live_http01_tests.zig`,
# `tests/integration.zig`'s `acme-experimental` cases), which this harness
# is deliberately independent evidence *on top of*, not a replacement for.
#
# Pebble's own HTTP-01 validation connection reaches a small logging/holding
# TCP proxy ("the tap") in front of the real shipping
# `acme_http01_listener.Listener`, not the listener directly: the listener
# always binds loopback-only, and the tap is the only part of this harness
# that needs to be reachable from inside the Pebble container. On Linux,
# Docker's `--add-host NAME:host-gateway` resolves to the bridge's own
# address as seen by the container, which a loopback-only process cannot
# receive; the tap instead binds the Docker bridge network's host-side
# gateway IP, and Pebble's hosts are mapped to that same address. On
# Darwin, Docker Desktop's VM makes `host-gateway` reach the host's real
# loopback services directly, so the tap binds 127.0.0.1 and `host-gateway`
# is used as before. No DNS server, no `pebble-challtestsrv`, and no code
# sharing with the system under test.
#
# Modes: a3, a4, a5, a6, all. Only `a3` is implemented today (#941's
# agreed first increment); `a4`/`a5`/`a6` are explicit, non-silent
# "not yet available" gates -- running them (directly or via `all`)
# reports FAIL and exits nonzero rather than reporting a false pass or
# being silently skipped. See `docs/ACME_AUTOMATIC_HTTPS.md` and the
# tracking issues (#833 a3, #834 a4, #835 a5, #940 a6, #837 release gate)
# for what each mode is meant to eventually cover; the top of this file's
# companion PR description records exactly what #941 deferred out of this
# first increment (CI wiring, the full adversarial/fault-injection matrix,
# multi-renewal A5 evidence, and TLS-ALPN-01 A6). This PR intentionally
# does not close #941 -- see the PR body for the reconciled scope.
#
# usage: scripts/interop/run-acme-local-ca.sh <a3|a4|a5|a6|all>
#   TARDI_BIN                 gateway binary (default zig-out/bin/tardi;
#                              must be built with -Dacme-experimental)
#   PEBBLE_IMAGE               pinned Pebble image reference (default below)
#   ACME_INTEROP_RESULTS_DIR   where JSON/JUnit evidence is written
#                              (default <repo>/.zig-cache/acme-interop)
#   KEEP_LOGS=1                keep the per-run work directory (container
#                              logs, gateway logs, state dir, fetched CA
#                              material) instead of deleting it on exit
set -u

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
tardi="${TARDI_BIN:-$root/zig-out/bin/tardi}"
# Pinned by digest (letsencrypt/pebble, pulled 2026-11-11); override
# deliberately, not casually, and record why in the commit/PR that does.
pebble_image="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef}"
results_dir="${ACME_INTEROP_RESULTS_DIR:-$root/.zig-cache/acme-interop}"

mode="${1:-}"
case "$mode" in
  a3 | a4 | a5 | a6 | all) ;;
  *)
    echo "usage: $0 <a3|a4|a5|a6|all>" >&2
    exit 2
    ;;
esac

# Every local probe must stay hermetic even when HTTPS_PROXY/ALL_PROXY is
# set in the calling environment (CI runners and developer shells both do
# this sometimes): curl can otherwise route a `.test` hostname through an
# unrelated proxy instead of dialing 127.0.0.1 directly, producing a false
# timeout that has nothing to do with the behavior under test.
curl() { command curl --noproxy '*' "$@"; }

# timeout(1) is absent on stock macOS; fall back to a perl alarm (matches
# run-h1-h2-mtls-interop.sh's own helper).
with_timeout() {
  if command -v timeout >/dev/null 2>&1; then timeout "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$@"
  else local s="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; fi
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
}

# Script-scoped (not `local`, since `cleanup` below runs from the top-level
# EXIT trap, after any mode function has already returned): the active a3
# work dir, Pebble container name, and the gateway/tap PIDs, if any are
# currently up.
a3_work=""
a3_pebble_name=""
a3_tardi_pid=""
a3_tap_pid=""
cleanup() {
  [ -n "$a3_tardi_pid" ] && kill "$a3_tardi_pid" 2>/dev/null
  [ -n "$a3_tap_pid" ] && kill "$a3_tap_pid" 2>/dev/null
  [ -n "$a3_pebble_name" ] && docker rm -f "$a3_pebble_name" >/dev/null 2>&1
  wait 2>/dev/null
  if [ -n "$a3_work" ]; then
    if [ "${KEEP_LOGS:-0}" = 1 ]; then echo "a3 work dir kept: $a3_work"; else rm -rf "$a3_work"; fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pass=0
fail=0
declare -a result_rows=() # "name\toutcome\tdetail"
ok() {
  pass=$((pass + 1))
  echo "PASS $1"
  result_rows+=("$1"$'\t'"pass"$'\t'"")
}
bad() {
  fail=$((fail + 1))
  echo "FAIL $1: ${2:-}"
  result_rows+=("$1"$'\t'"fail"$'\t'"${2:-}")
}
skip_mode() {
  fail=$((fail + 1))
  echo "FAIL $1: $2"
  result_rows+=("$1"$'\t'"fail"$'\t'"$2")
}

write_results() {
  mkdir -p "$results_dir"
  local sha zig_v os_name started_at outcome
  sha="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
  zig_v="$(zig version 2>/dev/null || echo unknown)"
  os_name="$(uname -sm)"
  started_at="$1"
  outcome="pass"
  [ "$fail" -gt 0 ] && outcome="fail"

  local json="$results_dir/$mode-results.json"
  local junit="$results_dir/$mode-results.junit.xml"
  {
    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "mode": "%s",\n' "$mode"
    printf '  "outcome": "%s",\n' "$outcome"
    printf '  "source_sha": "%s",\n' "$sha"
    printf '  "pebble_image": "%s",\n' "$pebble_image"
    printf '  "zig_version": "%s",\n' "$zig_v"
    printf '  "os": "%s",\n' "$os_name"
    printf '  "started_at": "%s",\n' "$started_at"
    printf '  "pass": %d,\n' "$pass"
    printf '  "fail": %d,\n' "$fail"
    printf '  "cases": [\n'
    local i=0 n=${#result_rows[@]}
    for row in "${result_rows[@]+"${result_rows[@]}"}"; do
      i=$((i + 1))
      local name status detail
      IFS=$'\t' read -r name status detail <<<"$row"
      printf '    {"name": %s, "status": %s, "detail": %s}' \
        "$(printf '%s' "$name" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "$detail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
      [ "$i" -lt "$n" ] && printf ',\n' || printf '\n'
    done
    printf '  ]\n'
    printf '}\n'
  } >"$json"

  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuite name="acme-local-ca.%s" tests="%d" failures="%d">\n' "$mode" "$((pass + fail))" "$fail"
    for row in "${result_rows[@]+"${result_rows[@]}"}"; do
      local name status detail
      IFS=$'\t' read -r name status detail <<<"$row"
      local esc_name esc_detail
      esc_name="$(printf '%s' "$name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')"
      esc_detail="$(printf '%s' "$detail" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
      if [ "$status" = fail ]; then
        printf '  <testcase name="%s"><failure>%s</failure></testcase>\n' "$esc_name" "$esc_detail"
      else
        printf '  <testcase name="%s"/>\n' "$esc_name"
      fi
    done
    printf '</testsuite>\n'
  } >"$junit"

  echo "evidence: $json"
  echo "evidence: $junit"
}

# ---------------------------------------------------------------- a3 mode --
# #833's acceptance: a local independent ACME test server completes
# HTTP-01 end-to-end issuance through the shipping `tardi` gateway, with
# multi-host isolation, no residue after cleanup, and (since A4/#884 are
# already merged ahead of this harness) the issued certificate actually
# served over a real TLS 1.3 connection selected by SNI.
run_a3() {
  for bin in docker openssl curl python3 git; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      skip_mode "a3: prerequisites" "required tool '$bin' not found on PATH"
      return
    fi
  done
  if ! docker info >/dev/null 2>&1; then
    skip_mode "a3: prerequisites" "docker daemon not reachable (docker info failed)"
    return
  fi

  local work
  work="$(mktemp -d)"
  a3_work="$work"
  a3_pebble_name="tardi-acme-pebble-$$"
  local pebble_name="$a3_pebble_name"

  # --- build (or verify) the exact shipping binary under test ------------
  # An executable bit alone proves nothing about which commit or build
  # options produced it: whatever happened to sit at zig-out/bin/tardi (or
  # wherever TARDI_BIN points) could be stale, or built without
  # -Dacme-experimental, while this JSON evidence still records the
  # current `git rev-parse HEAD`. The default path always rebuilds from
  # the current worktree; a TARDI_BIN override is assumed to be a
  # deliberately prepared artifact, so it skips the rebuild but is still
  # required to prove its own commit/acme-experimental provenance below.
  if [ -z "${TARDI_BIN:-}" ]; then
    if ! (cd "$root" && zig build -Dacme-experimental) >"$work/build.log" 2>&1; then
      bad "a3: prerequisites" "zig build -Dacme-experimental failed: $(tail -20 "$work/build.log")"
      return
    fi
  fi
  if [ ! -x "$tardi" ]; then
    bad "a3: prerequisites" "gateway binary not found/executable at $tardi -- build with: zig build -Dacme-experimental"
    return
  fi
  local head_sha version_out
  head_sha="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
  version_out="$("$tardi" version 2>/dev/null)"
  case "$version_out" in
    *"commit=${head_sha}"*"acme-experimental=true"*) ;;
    *)
      bad "a3: prerequisites" "$tardi does not prove it was built from this commit with -Dacme-experimental (tardi version: '${version_out}'; expected commit=${head_sha} and acme-experimental=true); set TARDI_BIN to a binary built from this exact commit with -Dacme-experimental, or unset TARDI_BIN to let this harness build one"
      return
      ;;
  esac
  ok "a3: the gateway binary under test is independently confirmed to be built from this exact commit with -Dacme-experimental"

  local h1=tardigrade-acme-a3-one.test
  local h2=tardigrade-acme-a3-two.test
  local unmanaged=tardigrade-acme-a3-unmanaged.test

  # --- figure out an address the Pebble container can actually reach -----
  # On Linux, `--add-host NAME:host-gateway` resolves (from inside the
  # container) to the bridge's own gateway address, not the host's loopback
  # interface; a listener bound only to 127.0.0.1 on the host is therefore
  # unreachable from the container even though `curl https://127.0.0.1/...`
  # on the host itself works fine. Bind the tap -- the only thing the
  # container actually dials -- to that bridge gateway IP instead, and map
  # both Pebble hostnames to the same address.
  local http01_bind_host="127.0.0.1"
  local kernel
  kernel="$(uname -s)"
  if [ "$kernel" = "Linux" ]; then
    http01_bind_host="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>"$work/docker-net.log")"
    if [ -z "$http01_bind_host" ]; then
      bad "a3: prerequisites" "could not determine the Docker bridge network's gateway IP: $(cat "$work/docker-net.log")"
      return
    fi
  fi
  local -a pebble_add_host_args
  if [ "$kernel" = "Linux" ]; then
    pebble_add_host_args=(--add-host "${h1}:${http01_bind_host}" --add-host "${h2}:${http01_bind_host}")
  else
    pebble_add_host_args=(--add-host "${h1}:host-gateway" --add-host "${h2}:host-gateway")
  fi

  # --- stand up the independent CA as a separate process ------------------
  local extract_cid
  extract_cid="$(docker create "$pebble_image" 2>"$work/pebble-pull.log")"
  if [ -z "$extract_cid" ]; then
    bad "a3: pebble image" "docker create failed: $(cat "$work/pebble-pull.log")"
    return
  fi
  docker cp "$extract_cid:/test" "$work/pebble-root" >/dev/null 2>&1
  docker rm "$extract_cid" >/dev/null 2>&1
  if [ ! -f "$work/pebble-root/config/pebble-config.json" ]; then
    bad "a3: pebble image" "could not extract test/config/pebble-config.json from $pebble_image"
    return
  fi

  local http01_port http01_tardi_port pebble_dir_port pebble_mgmt_port main_port
  http01_port="$(free_port)"        # what Pebble is told to dial (the tap)
  http01_tardi_port="$(free_port)"  # what the shipping listener actually binds
  pebble_dir_port="$(free_port)"
  pebble_mgmt_port="$(free_port)"
  main_port="$(free_port)"

  # Only the HTTP-01 validation port is overridden: Pebble is told to make
  # every HTTP-01 validation connection to this port (not real port 80),
  # which the logging/holding tap below binds on the host.
  python3 - "$work/pebble-root/config/pebble-config.json" "$http01_port" <<'PY'
import json, sys
path, port = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    cfg = json.load(f)
cfg["pebble"]["httpPort"] = port
with open(path, "w") as f:
    json.dump(cfg, f)
PY

  # --- the tap: a small logging/holding reverse proxy in front of the real
  # listener. It captures the Host and path (hence the real issued token)
  # of every HTTP-01 validation request Pebble actually makes, and -- for
  # the very first request to the primary host -- holds it open (bounded by
  # a 10s safety timeout) until this script releases it, giving the checks
  # below a deterministic, non-racy window to probe the real listener
  # directly with the real token while the CA is still waiting on it.
  local tap_log="$work/http01-tap.log" tap_ready="$work/http01-tap-ready" tap_release="$work/http01-tap-release"
  : >"$tap_log"
  python3 - "$http01_bind_host" "$http01_port" "$http01_tardi_port" "$tap_log" "$h1" "$tap_ready" "$tap_release" \
    >"$work/tap.out" 2>"$work/tap.err" <<'PY' &
import http.server, os, socket, sys, time

listen_host, listen_port, backend_port, log_path, hold_host, ready_path, release_path = sys.argv[1:8]
listen_port = int(listen_port)
backend_port = int(backend_port)
held_once = [False]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host_hdr = self.headers.get("Host", "")
        # Pebble includes the (non-default) validation port in its Host
        # header, e.g. "name.test:59758"; only the hostname identifies
        # which managed name this validation request is for.
        host_only = host_hdr.split(":", 1)[0]
        with open(log_path, "a") as f:
            f.write(f"{host_hdr}\t{self.path}\n")
        if (
            host_only == hold_host
            and not held_once[0]
            and self.path.startswith("/.well-known/acme-challenge/")
        ):
            held_once[0] = True
            with open(ready_path, "w") as f:
                f.write(f"{host_only}\t{self.path}\n")
            deadline = time.time() + 10
            while time.time() < deadline and not os.path.exists(release_path):
                time.sleep(0.02)
        self._forward(host_hdr)

    def _forward(self, host_hdr):
        try:
            s = socket.create_connection(("127.0.0.1", backend_port), timeout=5)
        except OSError as e:
            body = f"tap: backend unreachable: {e}".encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            s.sendall(
                f"GET {self.path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode()
            )
            s.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            code = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            code = 502
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer.allow_reuse_address = True
srv = http.server.ThreadingHTTPServer((listen_host, listen_port), Handler)
srv.serve_forever()
PY
  a3_tap_pid=$!

  local tap_wait_i=0 tap_up=0
  while [ "$tap_wait_i" -lt 40 ]; do
    if python3 -c "import socket; socket.create_connection(('${http01_bind_host}', ${http01_port}), timeout=0.2).close()" 2>/dev/null; then
      tap_up=1
      break
    fi
    kill -0 "$a3_tap_pid" 2>/dev/null || break
    tap_wait_i=$((tap_wait_i + 1)); sleep 0.25
  done
  if [ "$tap_up" -ne 1 ]; then
    bad "a3: prerequisites" "the HTTP-01 logging tap never started listening on ${http01_bind_host}:${http01_port}: $(cat "$work/tap.err" 2>/dev/null)"
    return
  fi

  if ! docker run -d --name "$pebble_name" \
    -p "127.0.0.1:${pebble_dir_port}:14000" \
    -p "127.0.0.1:${pebble_mgmt_port}:15000" \
    "${pebble_add_host_args[@]}" \
    -v "$work/pebble-root:/test:ro" \
    -e PEBBLE_VA_NOSLEEP=1 \
    "$pebble_image" -config /test/config/pebble-config.json \
    >"$work/pebble-run.log" 2>&1; then
    bad "a3: pebble startup" "docker run failed: $(cat "$work/pebble-run.log")"
    return
  fi

  local minica="$work/pebble-root/certs/pebble.minica.pem"
  local i=0 pebble_ready=0
  while [ "$i" -lt 60 ]; do
    if curl -s --cacert "$minica" --max-time 2 "https://127.0.0.1:${pebble_dir_port}/dir" >"$work/pebble-dir.json" 2>/dev/null \
      && grep -q '"newOrder"' "$work/pebble-dir.json"; then
      pebble_ready=1
      break
    fi
    docker inspect -f '{{.State.Running}}' "$pebble_name" 2>/dev/null | grep -q true || break
    i=$((i + 1)); sleep 0.25
  done
  if [ "$pebble_ready" -ne 1 ]; then
    bad "a3: independent CA process became ready" "Pebble never served a valid ACME directory; $(docker logs "$pebble_name" 2>&1 | tail -5)"
    return
  fi
  ok "a3: independent Pebble CA process is up and serving a real ACME directory over TLS"

  curl -s --cacert "$minica" --max-time 2 "https://127.0.0.1:${pebble_mgmt_port}/roots/0" -o "$work/pebble-issuing-root.pem" 2>/dev/null
  if ! openssl x509 -in "$work/pebble-issuing-root.pem" -noout 2>/dev/null; then
    bad "a3: fetched the independent CA's issuing root" "GET /roots/0 did not return a parseable certificate"
    return
  fi
  ok "a3: fetched the independent CA's real issuing root certificate over its management API"

  # --- launch the shipping native gateway with ACME enabled --------------
  local state_dir="$work/state"
  mkdir -p "$state_dir"
  cat >"$work/a3.conf" <<CONF
pid $work/a3.pid;
location = /healthz {
    return 200 "acme-a3-ok";
}
CONF

  start_tardi() {
    TARDIGRADE_CONFIG_PATH="$work/a3.conf" \
    TARDIGRADE_LISTEN_HOST=127.0.0.1 TARDIGRADE_LISTEN_PORT="$main_port" \
    TARDIGRADE_WORKER_THREADS=1 \
    TARDIGRADE_ERROR_LOG_PATH="$work/tardi.log" \
    TARDIGRADE_TLS_AUTOMATIC_HTTPS=true \
    TARDIGRADE_TLS_ACME_AGREE_TOS=true \
    TARDIGRADE_TLS_ACME_STATE_DIR="$state_dir" \
    TARDIGRADE_TLS_ACME_DOMAINS="${h1},${h2}" \
    TARDIGRADE_TLS_ACME_DIRECTORY_URL="https://127.0.0.1:${pebble_dir_port}/dir" \
    TARDIGRADE_TLS_ACME_CA_BUNDLE_PATH="$minica" \
    TARDIGRADE_TLS_ACME_HTTP01_LISTEN="127.0.0.1:${http01_tardi_port}" \
    "$tardi" >"$work/tardi.out" 2>&1 &
    a3_tardi_pid=$!
  }

  start_tardi

  # chain_for HOST -> writes PEM cert blocks served for that SNI to
  # $work/chain-<host>-N.pem (leaf is N=0), for independent openssl
  # verification (never the production ACME client).
  chain_for() {
    local sni="$1" prefix="$2"
    with_timeout 8 openssl s_client -connect "127.0.0.1:${main_port}" -servername "$sni" \
      -alpn http/1.1 -showcerts </dev/null >"$work/${prefix}.raw" 2>"$work/${prefix}.err"
    python3 - "$work/${prefix}.raw" "$work/${prefix}" <<'PY'
import re, sys
data = open(sys.argv[1]).read()
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
for i, b in enumerate(blocks):
    open(f"{sys.argv[2]}-{i}.pem", "w").write(b + "\n")
print(len(blocks))
PY
  }

  wait_served() {
    local host="$1" deadline_s="$2" started
    started="$(date +%s)"
    while true; do
      if curl -s --fail --cacert "$work/pebble-issuing-root.pem" --resolve "${host}:${main_port}:127.0.0.1" \
        --max-time 3 "https://${host}:${main_port}/healthz" -o "$work/served-$host.out" 2>/dev/null \
        && [ "$(cat "$work/served-$host.out" 2>/dev/null)" = acme-a3-ok ]; then
        return 0
      fi
      kill -0 "$a3_tardi_pid" 2>/dev/null || return 1
      [ $(( $(date +%s) - started )) -ge "$deadline_s" ] && return 1
      sleep 0.5
    done
  }

  # --- observe the CA's *real* validation request for h1, with it still
  # held open at the tap, and independently probe the real listener with
  # the actual token/Host before letting the CA's own validation proceed.
  # This is the only thing in this harness that both (a) proves the CA
  # container's request genuinely reached the host-bound listener over the
  # Docker bridge, and (b) gives the challenge Host/token/cleanup checks
  # below something real to check, instead of an invented token that would
  # 404 regardless of whether cleanup actually happened.
  local tap_wait_i2=0 tap_ready_seen=0
  while [ "$tap_wait_i2" -lt 160 ]; do
    [ -s "$tap_ready" ] && { tap_ready_seen=1; break; }
    kill -0 "$a3_tardi_pid" 2>/dev/null || break
    tap_wait_i2=$((tap_wait_i2 + 1)); sleep 0.25
  done
  if [ "$tap_ready_seen" -ne 1 ]; then
    docker logs "$pebble_name" >"$work/pebble.log" 2>&1
    bad "a3: real independent-CA HTTP-01 issuance served through the shipping gateway" \
      "the independent CA never attempted a real HTTP-01 validation request against the host-bound listener within 40s; tardi: $(tail -5 "$work/tardi.log" 2>/dev/null); pebble: $(tail -5 "$work/pebble.log" 2>/dev/null)"
    return
  fi

  local real_host real_path real_token
  IFS=$'\t' read -r real_host real_path <"$tap_ready"
  real_token="${real_path##*/}"

  if [ "$real_host" = "$h1" ]; then
    ok "a3: the independent CA's own real HTTP-01 validation request is independently observed reaching the host-bound listener for $h1 over the Docker bridge"
  else
    bad "a3: the independent CA's own real HTTP-01 validation request is independently observed reaching the host-bound listener for $h1 over the Docker bridge" \
      "captured validation request was for host '$real_host', expected $h1"
  fi

  local correct_resp
  correct_resp="$(curl -s --max-time 3 -H "Host: ${h1}" "http://127.0.0.1:${http01_tardi_port}${real_path}" 2>/dev/null)"
  if [ -n "$real_token" ] && [ "$correct_resp" != "${correct_resp#"$real_token".}" ]; then
    ok "a3: the real HTTP-01 listener serves the correct key authorization for the issued token under its correct Host"
  else
    bad "a3: the real HTTP-01 listener serves the correct key authorization for the issued token under its correct Host" \
      "got '${correct_resp}' for token ${real_token} under Host ${h1}"
  fi

  local cross_host_code
  cross_host_code="$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' -H "Host: ${h2}" "http://127.0.0.1:${http01_tardi_port}${real_path}" 2>/dev/null)"
  if [ "$cross_host_code" = "404" ]; then
    ok "a3: the real HTTP-01 listener does not serve the issued token's key authorization under a different managed Host"
  else
    bad "a3: the real HTTP-01 listener does not serve the issued token's key authorization under a different managed Host" \
      "GET for $h2 unexpectedly returned HTTP $cross_host_code instead of 404"
  fi

  : >"$tap_release"

  if ! wait_served "$h1" 90; then
    docker logs "$pebble_name" >"$work/pebble.log" 2>&1
    bad "a3: real independent-CA HTTP-01 issuance served through the shipping gateway" \
      "gateway never served a CA-verified certificate for $h1 in time; tardi: $(tail -5 "$work/tardi.log" 2>/dev/null); pebble: $(tail -5 "$work/pebble.log" 2>/dev/null)"
    return
  fi
  if ! wait_served "$h2" 20; then
    bad "a3: multi-identifier order (second SAN) served through the shipping gateway" \
      "gateway never served a CA-verified certificate for $h2; $(tail -10 "$work/tardi.log" 2>/dev/null)"
    return
  fi
  ok "a3: real independent-CA HTTP-01 issuance of a multi-SAN order served end to end through the shipping gateway"

  # --- independent wire-level verification (plain TLS, not the ACME client) --
  if chain_for "$h1" "chain-h1" >/dev/null 2>&1 && [ -f "$work/chain-h1-0.pem" ]; then
    local san_text
    san_text="$(openssl x509 -in "$work/chain-h1-0.pem" -noout -text 2>/dev/null)"
    if echo "$san_text" | grep -q "DNS:${h1}" && echo "$san_text" | grep -q "DNS:${h2}"; then
      ok "a3: served certificate's SAN independently verified to cover both managed names"
    else
      bad "a3: served certificate's SAN independently verified to cover both managed names" "SAN did not list both $h1 and $h2"
    fi
    if [ -f "$work/chain-h1-1.pem" ]; then
      if openssl verify -CAfile "$work/pebble-issuing-root.pem" -untrusted "$work/chain-h1-1.pem" "$work/chain-h1-0.pem" 2>"$work/verify.err" | grep -q ': OK$'; then
        ok "a3: served certificate chain independently verifies against the real CA's fetched issuing root"
      else
        bad "a3: served certificate chain independently verifies against the real CA's fetched issuing root" "$(cat "$work/verify.err")"
      fi
    else
      bad "a3: served certificate chain independently verifies against the real CA's fetched issuing root" "no intermediate certificate in the served chain"
    fi
  else
    bad "a3: served certificate's SAN independently verified to cover both managed names" "could not fetch the served chain over TLS"
  fi

  # Fail-closed: an SNI nobody issued for gets no credential at all (no
  # default identity is configured in this harness).
  with_timeout 8 openssl s_client -connect "127.0.0.1:${main_port}" -servername "$unmanaged" \
    -alpn http/1.1 </dev/null >"$work/unmanaged.out" 2>"$work/unmanaged.err"
  if ! grep -q 'BEGIN CERTIFICATE' "$work/unmanaged.out" "$work/unmanaged.err"; then
    ok "a3: an unmanaged SNI identity is refused rather than falling back to a managed certificate"
  else
    bad "a3: an unmanaged SNI identity is refused rather than falling back to a managed certificate" "handshake for $unmanaged unexpectedly presented a certificate"
  fi

  # The real HTTP-01 listener must not keep serving challenge material once
  # the order that published it is done -- checked against the *actual*
  # issued token captured above, not an invented one (which would 404
  # regardless of whether real cleanup ever ran).
  local residue_code
  residue_code="$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' -H "Host: ${h1}" "http://127.0.0.1:${http01_tardi_port}${real_path}" 2>/dev/null)"
  if [ "$residue_code" = "404" ]; then
    ok "a3: the real HTTP-01 listener leaves no challenge residue for the actual issued token after issuance"
  else
    bad "a3: the real HTTP-01 listener leaves no challenge residue for the actual issued token after issuance" \
      "listener still answered the real issued token with HTTP $residue_code after issuance completed"
  fi

  # --- restart recovery with the CA process stopped: no network needed ---
  local fingerprint_before fingerprint_after
  fingerprint_before="$(openssl x509 -in "$work/chain-h1-0.pem" -noout -fingerprint -sha256 2>/dev/null)"
  local old_tardi_pid="$a3_tardi_pid"
  kill "$old_tardi_pid" 2>/dev/null; wait "$old_tardi_pid" 2>/dev/null; a3_tardi_pid=""
  docker stop "$pebble_name" >/dev/null 2>&1

  start_tardi
  if kill -0 "$old_tardi_pid" 2>/dev/null; then
    bad "a3: a restart recovers and serves the same committed certificate with the CA process stopped" "the pre-restart gateway process ($old_tardi_pid) is still alive; restart test would be meaningless"
  elif wait_served "$h1" 15; then
    chain_for "$h1" "chain-h1-restart" >/dev/null 2>&1
    fingerprint_after="$(openssl x509 -in "$work/chain-h1-restart-0.pem" -noout -fingerprint -sha256 2>/dev/null)"
    if [ -n "$fingerprint_before" ] && [ "$fingerprint_before" = "$fingerprint_after" ]; then
      ok "a3: a restart recovers and serves the same committed certificate with the CA process stopped"
    else
      bad "a3: a restart recovers and serves the same committed certificate with the CA process stopped" "fingerprint changed or was empty across restart"
    fi
  else
    bad "a3: a restart recovers and serves the same committed certificate with the CA process stopped" "gateway did not serve $h1 again after a restart with no CA reachable; $(tail -10 "$work/tardi.log" 2>/dev/null)"
  fi
  # Leave teardown (killing the gateway and tap, removing the Pebble
  # container, and the work dir) to the top-level `cleanup` EXIT trap,
  # which runs exactly once whether this mode succeeded, failed, or
  # returned early above.
}

run_a4() { skip_mode "a4: certificate publication/rotation/recovery" "not yet implemented by this harness (#941 first increment is a3-only; see the PR body for the deferred scope)"; }
run_a5() { skip_mode "a5: successive live renewal, restart and fault evidence" "not yet implemented by this harness (#941 first increment is a3-only; see the PR body for the deferred scope)"; }
run_a6() { skip_mode "a6: TLS-ALPN-01 interoperability" "not available: #938/#939/#940 (RFC 8737 challenge certs and ClientHello selector) have not landed yet"; }

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
case "$mode" in
  a3) run_a3 ;;
  a4) run_a4 ;;
  a5) run_a5 ;;
  a6) run_a6 ;;
  all)
    run_a3
    run_a4
    run_a5
    run_a6
    ;;
esac

echo "acme local-CA interop ($mode): $pass passed, $fail failed"
write_results "$started_at"
[ "$fail" -eq 0 ]
