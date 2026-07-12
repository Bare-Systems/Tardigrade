#!/usr/bin/env bash
# TLS/crypto binary linkage audit and dependency inventory (#379, epic #327).
#
# Inspects a produced tardigrade binary's dynamic dependencies and emits a
# machine-readable inventory. For the Bare Systems appliance profile it fails
# if the binary links OpenSSL, libcrypto, or any other foreign TLS/crypto/
# QUIC/H3/certificate library, and confirms the binary self-reports the
# native TLS path. For the general profile it records whether the OpenSSL
# adapter was selected and lists the full dependency set.
#
# Usage:
#   audit-release-binary.sh --binary PATH --profile {general|appliance} \
#       [--output inventory.json]
#
# Exit code 0 means the audit passed. A forbidden linkage, or a profile that
# disagrees with the binary's self-report, exits 1.

set -euo pipefail

BINARY=""
PROFILE=""
OUTPUT=""

usage() {
    cat <<'EOF'
Usage: audit-release-binary.sh --binary PATH --profile {general|appliance} [--output FILE]
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
    --binary)
        BINARY="$2"
        shift 2
        ;;
    --profile)
        PROFILE="$2"
        shift 2
        ;;
    --output)
        OUTPUT="$2"
        shift 2
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        usage
        exit 2
        ;;
    esac
done

if [ -z "$BINARY" ] || [ -z "$PROFILE" ]; then
    usage
    exit 2
fi
if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    exit 2
fi
case "$PROFILE" in
general | appliance) ;;
*)
    echo "invalid profile: $PROFILE (expected general or appliance)" >&2
    exit 2
    ;;
esac

# Foreign TLS/crypto/QUIC/H3/certificate libraries that must never appear in a
# Tardigrade link graph. openssl/crypto are handled separately: forbidden in
# the appliance profile, the approved adapter in the general profile.
FORBIDDEN_LIB_PATTERNS='ngtcp2|nghttp3|quiche|boringssl|mbedtls|wolfssl|gnutls|libtls|libressl|botan|s2n'

# ── Collect dynamic dependencies across platforms ────────────────────────────
os="$(uname -s)"
deps=""
inspection_tool=""
case "$os" in
Linux)
    inspection_tool="ldd"
    # ldd returns nonzero for a static binary ("not a dynamic executable");
    # that is a valid, dependency-free result, so tolerate the failure.
    deps="$(ldd "$BINARY" 2>/dev/null || true)"
    ;;
Darwin)
    inspection_tool="otool -L"
    deps="$(otool -L "$BINARY" 2>/dev/null || true)"
    ;;
*)
    echo "unsupported host OS for binary inspection: $os" >&2
    exit 2
    ;;
esac

# Normalize to one shared-object name per line for scanning and inventory.
dep_names="$(printf '%s\n' "$deps" |
    grep -oE '(lib[a-zA-Z0-9._+-]+\.(so|dylib)[0-9.]*)' |
    sort -u || true)"

links_openssl=false
if printf '%s\n' "$dep_names" | grep -qiE 'libssl|libcrypto'; then
    links_openssl=true
fi

forbidden_hits="$(printf '%s\n' "$dep_names" | grep -iE "$FORBIDDEN_LIB_PATTERNS" || true)"

# ── Binary self-report (the version line records the built-in profile) ───────
self_report="$("$BINARY" version 2>/dev/null || true)"
reported_backend="unknown"
case "$self_report" in
*"tls-backend=native"*) reported_backend="native" ;;
*"tls-backend=openssl-adapter"*) reported_backend="openssl-adapter" ;;
esac

# ── Policy evaluation ────────────────────────────────────────────────────────
status="pass"
declare -a violations=()

if [ -n "$forbidden_hits" ]; then
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        violations+=("forbidden foreign TLS/crypto/QUIC library linked: $hit")
    done <<<"$forbidden_hits"
fi

if [ "$PROFILE" = "appliance" ]; then
    if [ "$links_openssl" = true ]; then
        violations+=("appliance artifact links OpenSSL (libssl/libcrypto)")
    fi
    if [ "$reported_backend" != "native" ]; then
        violations+=("appliance artifact does not self-report the native TLS path (got '$reported_backend')")
    fi
else
    # General profile: OpenSSL is permitted, but the binary's self-report must
    # match its actual linkage so the inventory is trustworthy.
    if [ "$links_openssl" = true ] && [ "$reported_backend" != "openssl-adapter" ]; then
        violations+=("general artifact links OpenSSL but self-reports backend '$reported_backend'")
    fi
    if [ "$links_openssl" = false ] && [ "$reported_backend" = "openssl-adapter" ]; then
        violations+=("general artifact self-reports the OpenSSL adapter but does not link OpenSSL")
    fi
fi

if [ "${#violations[@]}" -gt 0 ]; then
    status="fail"
fi

# ── Emit machine-readable inventory ──────────────────────────────────────────
emit_inventory() {
    printf '{\n'
    printf '  "binary": %s,\n' "$(json_string "$BINARY")"
    printf '  "profile": %s,\n' "$(json_string "$PROFILE")"
    printf '  "host_os": %s,\n' "$(json_string "$os")"
    printf '  "inspection_tool": %s,\n' "$(json_string "$inspection_tool")"
    printf '  "reported_backend": %s,\n' "$(json_string "$reported_backend")"
    printf '  "self_report": %s,\n' "$(json_string "$self_report")"
    printf '  "links_openssl": %s,\n' "$links_openssl"
    printf '  "status": %s,\n' "$(json_string "$status")"
    printf '  "dependencies": ['
    first=true
    while IFS= read -r dep; do
        [ -z "$dep" ] && continue
        if [ "$first" = true ]; then
            first=false
            printf '\n'
        else
            printf ',\n'
        fi
        printf '    %s' "$(json_string "$dep")"
    done <<<"$dep_names"
    [ "$first" = false ] && printf '\n  '
    printf '],\n'
    printf '  "violations": ['
    first=true
    for violation in "${violations[@]:-}"; do
        [ -z "$violation" ] && continue
        if [ "$first" = true ]; then
            first=false
            printf '\n'
        else
            printf ',\n'
        fi
        printf '    %s' "$(json_string "$violation")"
    done
    [ "$first" = false ] && printf '\n  '
    printf ']\n'
    printf '}\n'
}

json_string() {
    # Minimal JSON string escaping for the fields we emit (paths, lib names,
    # a version line): backslash, double-quote, and control-free ASCII.
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

inventory="$(emit_inventory)"
if [ -n "$OUTPUT" ]; then
    printf '%s\n' "$inventory" >"$OUTPUT"
fi
printf '%s\n' "$inventory"

if [ "$status" = "fail" ]; then
    echo "binary audit failed for profile '$PROFILE':" >&2
    for violation in "${violations[@]}"; do
        echo "  - $violation" >&2
    done
    exit 1
fi

echo "binary audit passed for profile '$PROFILE' (backend: $reported_backend)" >&2
