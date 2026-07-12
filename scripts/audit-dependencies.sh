#!/usr/bin/env bash
# TLS dependency source/configuration audit (#379, epic #327).
#
# Enforces Tardigrade's external-library policy before anything is compiled:
#
#   1. Forbidden TLS/crypto/QUIC/H3 dependency names must not appear in build
#      configuration, workflows, scripts, or packaging metadata. External
#      implementations are allowed only as out-of-process interoperability
#      peers (scripts/interop/), never in the link graph.
#   2. OpenSSL headers may be included only inside the approved
#      general-profile adapter boundary.
#   3. Native implementation paths (TLS, PKI, QUIC, crypto, HTTP/3) must not
#      contain any @cImport at all.
#
# Exit code 0 means the audit passed; any violation prints the offending
# file/line and exits 1. Run from anywhere; paths resolve from the repo root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

failures=0

fail() {
    echo "AUDIT FAIL: $1" >&2
    failures=$((failures + 1))
}

# ── 1. Forbidden dependency identifiers in build/config surfaces ─────────────
# openssl itself is not in this list: the general profile's adapter is the
# single approved exception, enforced separately by checks 2 and 3 and by the
# binary audit (scripts/audit-release-binary.sh).
#
# The check targets configuration that would actually pull a dependency into
# the build or link graph, so comments are stripped before matching: policy
# permits naming these libraries in prose (e.g. documenting that external
# peers run out-of-process). A real dependency declaration is never inside a
# comment.
FORBIDDEN_NAMES='ngtcp2|nghttp3|quiche|boringssl|mbedtls|wolfssl|gnutls|libressl|rustls|s2n-tls|libtls|botan'

# Strip comments from a file according to its type, then print the result.
# .zig/.zon use `//`; shell/yaml/toml/Dockerfiles use `#`. Stripping is
# type-scoped so a URL scheme's `//` in a shell script is preserved.
strip_comments() {
    local file="$1"
    case "$file" in
    *.zig | *.zon) sed 's://.*$::' "$file" ;;
    *.sh | *.yml | *.yaml | *.toml | *Dockerfile* | *.spec | *.control) sed 's:#.*$::' "$file" ;;
    *) cat "$file" ;;
    esac
}

# Build configuration, automation, and packaging surfaces. Interop tooling
# (scripts/interop/) is excluded by policy: it drives external peers as
# separate processes and must name them. The audit scripts are excluded
# because they define the deny list.
scan_files=(build.zig build.zig.zon)
while IFS= read -r f; do
    scan_files+=("$f")
done < <(find .github/workflows packaging -type f 2>/dev/null | sort)
if [ -d scripts ]; then
    while IFS= read -r script; do
        case "$script" in
        scripts/interop/*) ;;
        scripts/audit-dependencies.sh | scripts/audit-release-binary.sh) ;;
        *) scan_files+=("$script") ;;
        esac
    done < <(find scripts -type f | sort)
fi
while IFS= read -r dockerfile; do
    scan_files+=("$dockerfile")
done < <(find . -path ./.zig-cache -prune -o -path ./zig-out -prune -o -name 'Dockerfile*' -type f -print | sed 's|^\./||' | sort)

for file in "${scan_files[@]}"; do
    [ -f "$file" ] || continue
    if matches="$(strip_comments "$file" | grep -niE "$FORBIDDEN_NAMES" 2>/dev/null)"; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            fail "forbidden dependency configuration in $file: $line"
        done <<<"$matches"
    fi
done

# ── 2. OpenSSL includes restricted to the approved adapter boundary ──────────
OPENSSL_INCLUDE_ALLOWLIST=(
    src/http/tls_termination.zig
    src/http/acme_client.zig
)

if matches="$(grep -rn '@cInclude("openssl/' src/ 2>/dev/null)"; then
    while IFS= read -r line; do
        file="${line%%:*}"
        allowed=false
        for allowed_file in "${OPENSSL_INCLUDE_ALLOWLIST[@]}"; do
            if [ "$file" = "$allowed_file" ]; then
                allowed=true
                break
            fi
        done
        if [ "$allowed" = false ]; then
            fail "OpenSSL include outside the approved adapter boundary: $line"
        fi
    done <<<"$matches"
fi

# ── 3. Native implementation paths must be free of @cImport entirely ─────────
NATIVE_PATHS=(src/tls src/pki src/quic src/crypto src/http3)

for path in "${NATIVE_PATHS[@]}"; do
    [ -d "$path" ] || continue
    if matches="$(grep -rn '@cImport' "$path" 2>/dev/null)"; then
        while IFS= read -r line; do
            fail "@cImport in native implementation path: $line"
        done <<<"$matches"
    fi
done

# ── Result ────────────────────────────────────────────────────────────────────
if [ "$failures" -gt 0 ]; then
    echo "dependency audit failed with $failures violation(s)" >&2
    exit 1
fi
echo "dependency audit passed: no forbidden dependencies, OpenSSL confined to the adapter boundary, native paths free of @cImport"
