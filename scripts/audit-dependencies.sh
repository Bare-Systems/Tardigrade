#!/usr/bin/env bash
# TLS dependency source/configuration audit (#379, epic #327).
#
# Enforces Tardigrade's external-library policy before anything is compiled:
#
#   1. Forbidden TLS/crypto/QUIC/H3 dependency names must not appear in build
#      configuration, workflows, scripts, or packaging metadata. External
#      implementations are allowed only as out-of-process interoperability
#      peers (scripts/interop/), never in the link graph.
#   2. OpenSSL may be referenced only inside the approved general-profile
#      adapter boundary.
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

# Strip comments from a line stream while respecting string literals, so a
# forbidden name inside a real declaration (e.g. a `.url = "https://.../ngtcp2"`
# dependency, whose `//` would otherwise be mistaken for a comment) is never
# hidden, while a mention in prose is ignored. `style` is `zig` (// comments,
# " and ' string/char literals, \\ multiline-string lines kept verbatim) or
# `hash` (# comments that start a token, ' and " strings).
strip_comments() {
    awk -v style="$2" '
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39) }
    {
        line = $0
        if (style == "zig") {
            tmp = line
            sub(/^[ \t]+/, "", tmp)
            if (substr(tmp, 1, 2) == "\\\\") { print line; next }
        }
        out = ""; inq = ""; n = length(line); i = 1
        while (i <= n) {
            ch = substr(line, i, 1)
            if (inq != "") {
                out = out ch
                if (ch == "\\") { i++; if (i <= n) out = out substr(line, i, 1); i++; continue }
                if (ch == inq) inq = ""
                i++; continue
            }
            if (ch == dq || ch == sq) { inq = ch; out = out ch; i++; continue }
            if (style == "zig" && ch == "/" && substr(line, i + 1, 1) == "/") break
            if (style == "hash" && ch == "#") {
                prev = (i == 1) ? " " : substr(line, i - 1, 1)
                if (prev == " " || prev == "\t") break
            }
            out = out ch; i++
        }
        print out
    }' "$1"
}

comment_style_for() {
    case "$1" in
    *.zig | *.zon) echo zig ;;
    *.sh | *.yml | *.yaml | *.toml | *Dockerfile* | *.spec | *.control) echo hash ;;
    *) echo none ;;
    esac
}

stripped() {
    local style
    style="$(comment_style_for "$1")"
    if [ "$style" = none ]; then
        cat "$1"
    else
        strip_comments "$1" "$style"
    fi
}

# Resolve build.zig's transitive `@import("*.zig")` closure so linkage moved
# into an imported build helper (e.g. `build/dependencies.zig`) is still
# audited, rather than trusting the root file to hold every declaration.
resolve_build_sources() {
    local -a queue=("build.zig")
    local -A seen=()
    local f dir imp target
    while [ "${#queue[@]}" -gt 0 ]; do
        f="${queue[0]}"
        queue=("${queue[@]:1}")
        [ -n "${seen[$f]:-}" ] && continue
        seen[$f]=1
        [ -f "$f" ] || continue
        printf '%s\n' "$f"
        dir="$(dirname "$f")"
        while IFS= read -r imp; do
            [ -z "$imp" ] && continue
            target="$(realpath -m --relative-to="$REPO_ROOT" "$REPO_ROOT/$dir/$imp" 2>/dev/null || true)"
            case "$target" in
            "" | ../*) continue ;; # outside the repo
            esac
            queue+=("$target")
        done < <(grep -oE '@import\("[^"]+\.zig"\)' "$f" 2>/dev/null | sed -E 's/.*@import\("([^"]+)"\).*/\1/')
    done
}

# ── 1. Forbidden dependency identifiers in build/config surfaces ─────────────
# openssl itself is not in this list: the general profile's adapter is the
# single approved exception, enforced separately by checks 2 and 3 and by the
# binary audit (scripts/audit-release-binary.sh).
FORBIDDEN_NAMES='ngtcp2|nghttp3|quiche|boringssl|mbedtls|wolfssl|gnutls|libressl|rustls|s2n-tls|libtls|botan'

# Build configuration (the resolved build-graph sources plus the manifest),
# automation, and packaging surfaces. Interop tooling (scripts/interop/) is
# excluded by policy: it drives external peers as separate processes and must
# name them. The audit scripts are excluded because they define the deny list.
scan_files=("build.zig.zon")
while IFS= read -r f; do
    scan_files+=("$f")
done < <(resolve_build_sources)
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

# De-duplicate (build.zig may already appear via the graph and via a glob).
declare -A scanned=()
for file in "${scan_files[@]}"; do
    [ -f "$file" ] || continue
    [ -n "${scanned[$file]:-}" ] && continue
    scanned[$file]=1
    if matches="$(stripped "$file" | grep -niE "$FORBIDDEN_NAMES" 2>/dev/null)"; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            fail "forbidden dependency configuration in $file: $line"
        done <<<"$matches"
    fi
done

# ── 2. OpenSSL references restricted to the approved adapter boundary ─────────
# Match the literal `openssl/` header path anywhere in comment-stripped source
# rather than one exact @cInclude spelling, so whitespace variants and
# reformatted includes cannot escape the allowlist.
OPENSSL_ALLOWLIST=(
    src/http/tls_termination.zig
    src/http/acme_client.zig
)

while IFS= read -r zigfile; do
    allowed=false
    for allowed_file in "${OPENSSL_ALLOWLIST[@]}"; do
        if [ "$zigfile" = "$allowed_file" ]; then
            allowed=true
            break
        fi
    done
    [ "$allowed" = true ] && continue
    if matches="$(stripped "$zigfile" | grep -niE 'openssl/' 2>/dev/null)"; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            fail "OpenSSL reference outside the approved adapter boundary in $zigfile: $line"
        done <<<"$matches"
    fi
done < <(find src -name '*.zig' -type f | sort)

# ── 3. Native implementation paths must be free of @cImport entirely ─────────
NATIVE_PATHS=(src/tls src/pki src/quic src/crypto src/http3)

for path in "${NATIVE_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r zigfile; do
        if matches="$(stripped "$zigfile" | grep -niE '@cImport' 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                fail "@cImport in native implementation path $zigfile: $line"
            done <<<"$matches"
        fi
    done < <(find "$path" -name '*.zig' -type f | sort)
done

# ── Result ────────────────────────────────────────────────────────────────────
if [ "$failures" -gt 0 ]; then
    echo "dependency audit failed with $failures violation(s)" >&2
    exit 1
fi
echo "dependency audit passed: no forbidden dependencies, OpenSSL confined to the adapter boundary, native paths free of @cImport"
