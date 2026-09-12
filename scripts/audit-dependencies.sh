#!/usr/bin/env bash
# Production dependency boundary audit (#379, #634, #649, #651).
#
# Enforces the project-wide rule before anything is compiled:
#
#   Production `tardi` implementation inputs may use Tardigrade Zig code,
#   Zig stdlib, reviewed pure-Zig packages, and narrow OS/kernel/platform ABI
#   substrate. Foreign-language product implementations are allowed only in
#   explicit test/interop/differential/fuzz/benchmark scopes.
#
# Production scope audited here:
#   - production-scoped Zig source across the repository (comments/prose ignored);
#   - build.zig and its imported build helpers plus build.zig.zon;
#   - .github workflows, packaging metadata, package builders, Dockerfiles,
#     and non-interop scripts that can affect shipped artifacts.
#
# Explicit non-production exemptions:
#   - tests/ and src/**/testdata fixture generators;
#   - scripts/interop/ external peer tooling;
#   - benchmark competitors and fuzz/differential/oracle tools when they are
#     clearly wired outside the `tardi` executable graph.
#
# Usage:
#   scripts/audit-dependencies.sh [--root PATH]
#   scripts/audit-dependencies.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SELF_TEST=false

while [ "$#" -gt 0 ]; do
    case "$1" in
    --root)
        REPO_ROOT="$(cd "$2" && pwd -P)"
        shift 2
        ;;
    --self-test)
        SELF_TEST=true
        shift
        ;;
    -h | --help)
        sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
    esac
done

failures=0
SELF_TEST_TMP=""

fail() {
    echo "AUDIT FAIL: $1" >&2
    failures=$((failures + 1))
}

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
    *.sh | *.yml | *.yaml | *.toml | *Dockerfile* | *.spec | *.control | *.service | *.plist | *.rb) echo hash ;;
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

relpath() {
    local path="$1"
    case "$path" in
    "$REPO_ROOT"/*) printf '%s\n' "${path#"$REPO_ROOT"/}" ;;
    *) printf '%s\n' "$path" ;;
    esac
}

zig_import_paths() {
    stripped "$1" |
        tr '\n' ' ' |
        grep -oE '@import[[:space:]]*\([[:space:]]*"[^"]+\.zig"[[:space:]]*\)' |
        sed -E 's/.*@import[[:space:]]*\([[:space:]]*"([^"]+)"[[:space:]]*\).*/\1/' || true
}

resolve_build_sources() {
    local -a queue=("build.zig")
    local -A seen=()
    local f dir imp target
    while [ "${#queue[@]}" -gt 0 ]; do
        f="${queue[0]}"
        queue=("${queue[@]:1}")
        [ -n "${seen[$f]:-}" ] && continue
        seen[$f]=1
        [ -f "$REPO_ROOT/$f" ] || continue
        printf '%s\n' "$f"
        dir="$(dirname "$f")"
        while IFS= read -r imp; do
            [ -z "$imp" ] && continue
            if target="$(
                cd "$REPO_ROOT/$dir" &&
                    cd "$(dirname "$imp")" 2>/dev/null &&
                    pwd -P
            )"; then
                :
            else
                target=""
            fi
            [ -n "$target" ] || continue
            target="$(relpath "$target/$(basename "$imp")")"
            case "$target" in
            ../* | /*) continue ;;
            esac
            queue+=("$target")
        done < <(zig_import_paths "$REPO_ROOT/$f")
    done
}

is_nonproduction_file() {
    case "$1" in
    .git/* | .zig/* | .zig-cache/* | zig-out/* | .claude/worktrees/* | .codex/worktrees/* | tests/* | scripts/interop/* | benchmarks/* | src/*/testdata/* | scripts/remote-bench.sh | scripts/run-proxmox-performance-campaign.sh | scripts/profile.sh | scripts/upload-benchmarks-gdrive.rb) return 0 ;;
    scripts/test-deb-package.sh | scripts/test-rpm-package.sh | scripts/test-homebrew-formula.sh | scripts/test-homebrew-release-formula.sh | scripts/test-homebrew-tap-sync.sh | scripts/test-public-homebrew-tap.sh | scripts/test-install.sh | scripts/test-docker-image.sh | scripts/test-launchd-service.sh) return 0 ;;
    *) return 1 ;;
    esac
}

is_nonproduction_zig_file() {
    case "$1" in
    .git/* | .zig/* | .zig-cache/* | zig-out/* | .claude/worktrees/* | .codex/worktrees/* | tests/* | scripts/interop/* | benchmarks/* | src/*/testdata/* | scripts/run-proxmox-performance-campaign.sh) return 0 ;;
    scripts/test-deb-package.sh | scripts/test-rpm-package.sh | scripts/test-homebrew-formula.sh | scripts/test-homebrew-release-formula.sh | scripts/test-homebrew-tap-sync.sh | scripts/test-public-homebrew-tap.sh | scripts/test-install.sh | scripts/test-docker-image.sh | scripts/test-launchd-service.sh) return 0 ;;
    *) return 1 ;;
    esac
}

is_explicit_nonproduction_helper() {
    case "$1" in
    scripts/test-deb-package.sh | scripts/test-rpm-package.sh | scripts/test-homebrew-formula.sh | scripts/test-homebrew-release-formula.sh | scripts/test-homebrew-tap-sync.sh | scripts/test-public-homebrew-tap.sh | scripts/test-install.sh | scripts/test-docker-image.sh | scripts/test-launchd-service.sh) return 0 ;;
    *) return 1 ;;
    esac
}

explicit_nonproduction_helper_pattern() {
    printf '%s\n' 'scripts/test-deb-package\.sh|scripts/test-rpm-package\.sh|scripts/test-homebrew-formula\.sh|scripts/test-homebrew-release-formula\.sh|scripts/test-homebrew-tap-sync\.sh|scripts/test-public-homebrew-tap\.sh|scripts/test-install\.sh|scripts/test-docker-image\.sh|scripts/test-launchd-service\.sh|scripts/run-proxmox-performance-campaign\.sh|scripts/interop/[A-Za-z0-9_./@-]+|scripts/remote-bench\.sh|scripts/profile\.sh|scripts/upload-benchmarks-gdrive\.rb|benchmarks/[A-Za-z0-9_./@-]+|\./\.github/workflows/[A-Za-z0-9_.@/-]+\.ya?ml'
}

forbidden_dependency_pattern() {
    printf '%s\n' 'openssl|libssl|libcrypto|ngtcp2|nghttp3|quiche|boringssl|mbedtls|wolfssl|gnutls|libressl|rustls|s2n|botan|brotli|libbrotli|libbrotlienc'
}

logical_zig_statements() {
    awk '
    {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line == "") next
        stmt = stmt " " line
        if (line ~ /;[ \t]*$/ || line ~ /\{[ \t]*$/ || line ~ /\}[ \t]*$/) {
            print stmt
            stmt = ""
        }
    }
    END { if (stmt != "") print stmt }
    ' "$1"
}

logical_zig_calls() {
    awk '
    {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line == "") next
        stmt = stmt " " line
        if (line ~ /;[ \t]*$/) {
            print stmt
            stmt = ""
        }
    }
    END { if (stmt != "") print stmt }
    ' "$1"
}

logical_shell_statements() {
    awk '
    {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line == "") next
        if (line ~ /\\[ \t]*$/) {
            sub(/\\[ \t]*$/, "", line)
            stmt = stmt " " line
            next
        }
        stmt = stmt " " line
        print stmt
        stmt = ""
    }
    END { if (stmt != "") print stmt }
    ' "$1"
}

resolve_build_string() {
    local file="$1" token="$2"
    stripped "$file" | sed -nE "s/^[[:space:]]*(const|var)[[:space:]]+${token}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\\2/p" | tail -n 1
}

is_allowed_nonproduction_build_statement() {
    local stmt="$1"
    case "$stmt" in
    *'evp_oracle_mod.addCSourceFile'*'tests/evp_oracle.c'*) return 0 ;;
    *'linkSystemLibrary(evp_oracle, "crypto"'*) return 0 ;;
    *) return 1 ;;
    esac
}

allowed_c_header() {
    case "$1" in
    arpa/inet.h | dirent.h | errno.h | fcntl.h | grp.h | limits.h | netdb.h | netinet/in.h | poll.h | pthread.h | pwd.h | regex.h | signal.h | stdint.h | stdlib.h | string.h | sys/epoll.h | sys/event.h | sys/ioctl.h | sys/mman.h | sys/resource.h | sys/socket.h | sys/stat.h | sys/time.h | sys/types.h | sys/uio.h | sys/un.h | time.h | unistd.h) return 0 ;;
    *) return 1 ;;
    esac
}

allowed_system_library() {
    case "$1" in
    c | System | pthread | m | dl | rt | resolv | regex | util | socket | nsl) return 0 ;;
    *) return 1 ;;
    esac
}

is_reviewed_generated_build_module() {
    case "$1" in
    build_options) return 0 ;;
    *) return 1 ;;
    esac
}

scan_source_ffi() {
    [ -d "$REPO_ROOT" ] || return 0
    local zigfile rel content normalized include_exprs include_expr include_header
    while IFS= read -r zigfile; do
        rel="$(relpath "$zigfile")"
        is_nonproduction_zig_file "$rel" && continue
        content="$(stripped "$zigfile")"
        if ! printf '%s\n' "$content" | grep -qE '@cImport'; then
            continue
        fi
        normalized="$(printf '%s\n' "$content" | tr '\n' ' ')"
        include_exprs="$(printf '%s\n' "$normalized" | grep -oE '@cInclude[[:space:]]*\([[:space:]]*[^)]*\)' || true)"
        if [ -z "$include_exprs" ]; then
            fail "production @cImport without reviewable @cInclude header list in $rel"
            continue
        fi
        while IFS= read -r include_expr; do
            [ -z "$include_expr" ] && continue
            include_header="$(printf '%s\n' "$include_expr" | sed -nE 's/.*@cInclude[[:space:]]*\([[:space:]]*"([^"]+)"[[:space:]]*\).*/\1/p')"
            if [ -z "$include_header" ]; then
                fail "production @cInclude uses unresolved non-literal header expression in $rel: $include_expr"
                continue
            fi
            if ! allowed_c_header "$include_header"; then
                fail "foreign/product C header imported from production source $rel: $include_expr"
            fi
        done <<<"$include_exprs"
    done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -path "$REPO_ROOT/.zig" -prune -o -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o -name '*.zig' -type f -print | sort)
}

scan_runtime_loading() {
    [ -d "$REPO_ROOT" ] || return 0
    local zigfile rel matches line
    while IFS= read -r zigfile; do
        rel="$(relpath "$zigfile")"
        is_nonproduction_zig_file "$rel" && continue
        if matches="$(stripped "$zigfile" | grep -niE 'DynLib|DynamicLibrary|dlopen|LoadLibrary[A-Za-z]*' 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                fail "production runtime dynamic loading boundary in $rel: $line"
            done <<<"$matches"
        fi
    done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -path "$REPO_ROOT/.zig" -prune -o -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o -name '*.zig' -type f -print | sort)
}

resolve_relative_import() {
    local from_rel="$1" import_path="$2" from_dir target_dir
    from_dir="$(dirname "$from_rel")"
    if target_dir="$(
        cd "$REPO_ROOT/$from_dir" &&
            cd "$(dirname "$import_path")" 2>/dev/null &&
            pwd -P
    )"; then
        :
    else
        return 1
    fi
    relpath "$target_dir/$(basename "$import_path")"
}

scan_nonproduction_zig_imports() {
    [ -d "$REPO_ROOT" ] || return 0
    local zigfile rel import_call import_path target
    while IFS= read -r zigfile; do
        rel="$(relpath "$zigfile")"
        is_nonproduction_zig_file "$rel" && continue
        while IFS= read -r import_call; do
            [ -n "$import_call" ] || continue
            import_path="$(printf '%s\n' "$import_call" | sed -nE 's/.*@import[[:space:]]*\([[:space:]]*"([^"]+)"[[:space:]]*\).*/\1/p')"
            if [ -z "$import_path" ]; then
                fail "production Zig source uses unresolved @import expression in $rel: $import_call"
                continue
            fi
            case "$import_path" in
            *.zig) ;;
            *) continue ;;
            esac
            target="$(resolve_relative_import "$rel" "$import_path" || true)"
            [ -n "$target" ] || continue
            case "$target" in
            ../* | /*) continue ;;
            esac
            if is_nonproduction_zig_file "$target"; then
                fail "production Zig source imports non-production source root $target from $rel"
            fi
        done < <(stripped "$zigfile" | tr '\n' ' ' | grep -oE '@import[[:space:]]*\([[:space:]]*[^)]*\)' || true)
    done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -path "$REPO_ROOT/.zig" -prune -o -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o -name '*.zig' -type f -print | sort)
}

scan_build_production_graph() {
    local file stmt module root exe name root_mod root_path parent child installed target lib anon alias_name alias_value token
    local anon_index=0
    local -A aliases=() module_roots=() executable_roots=() executable_root_paths=() executable_names=() installed_executables=() edges=() foreign_calls=() system_link_calls=() reachable=()
    graph_resolve_alias() {
        local value="$1" guard=0
        while [ -n "${aliases[$value]:-}" ] && [ "$guard" -lt 20 ]; do
            value="${aliases[$value]}"
            guard=$((guard + 1))
        done
        printf '%s\n' "$value"
    }
    while IFS= read -r file; do
        [ -f "$REPO_ROOT/$file" ] || continue
        while IFS= read -r stmt; do
            [ -z "$stmt" ] && continue
            alias_name="$(printf '%s\n' "$stmt" | sed -nE 's/.*(const|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\2/p')"
            alias_value="$(printf '%s\n' "$stmt" | sed -nE 's/.*(const|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\3/p')"
            if [ -n "$alias_name" ] && [ -n "$alias_value" ]; then
                aliases[$alias_name]="$(graph_resolve_alias "$alias_value")"
            fi
            module="$(printf '%s\n' "$stmt" | sed -nE 's/.*(const|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*createModule[[:space:]]*\(.*/\2/p')"
            if [ -n "$module" ]; then
                module_roots[$module]="${module_roots[$module]:-}"
                root="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*"([^"]+)".*/\1/p')"
                if [ -z "$root" ]; then
                    token="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                    [ -z "$token" ] || root="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
                fi
                [ -z "$root" ] || module_roots[$module]="$root"
            fi
            module="$(printf '%s\n' "$stmt" | sed -nE 's/.*(const|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*b\.(addObject|addLibrary|addStaticLibrary|addSharedLibrary)[[:space:]]*\(.*/\2/p')"
            if [ -n "$module" ]; then
                module_roots[$module]="${module_roots[$module]:-}"
                root_mod="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_module[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                root_path="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*"([^"]+)".*/\1/p')"
                if [ -z "$root_path" ]; then
                    token="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                    [ -z "$token" ] || root_path="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
                fi
                [ -z "$root_mod" ] || root_mod="$(graph_resolve_alias "$root_mod")"
                [ -z "$root_path" ] || module_roots[$module]="$root_path"
                [ -z "$root_mod" ] || edges[$module]="${edges[$module]:-} $root_mod"
            fi
            exe="$(printf '%s\n' "$stmt" | sed -nE 's/.*(const|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*addExecutable[[:space:]]*\(.*/\2/p')"
            if [ -n "$exe" ]; then
                name="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.name[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p')"
                root_mod="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_module[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                root_path="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*"([^"]+)".*/\1/p')"
                if [ -z "$root_path" ]; then
                    token="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                    [ -z "$token" ] || root_path="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
                fi
                [ -z "$root_mod" ] || root_mod="$(graph_resolve_alias "$root_mod")"
                executable_names[$exe]="$name"
                executable_roots[$exe]="$root_mod"
                executable_root_paths[$exe]="$root_path"
            fi
            installed="$(printf '%s\n' "$stmt" | sed -nE 's/.*installArtifact[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
            if [ -z "$installed" ]; then
                installed="$(printf '%s\n' "$stmt" | sed -nE 's/.*addInstallArtifact[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
            fi
            if [[ "$stmt" == *"installArtifact"* && -z "$installed" ]]; then
                fail "build installArtifact uses unresolved artifact expression in $file: $stmt"
            fi
            if [[ "$stmt" == *"addInstallArtifact"* && -z "$installed" ]]; then
                fail "build addInstallArtifact uses unresolved artifact expression in $file: $stmt"
            fi
            [ -z "$installed" ] || installed_executables[$installed]=1
            parent="$(printf '%s\n' "$stmt" | sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)(\.root_module)?\.addImport[[:space:]]*\(.*/\1/p')"
            child="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.addImport[[:space:]]*\([^,]+,[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
            if [ -n "$parent" ]; then
                parent="$(graph_resolve_alias "$parent")"
                root="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.addImport[[:space:]]*\(.*b\.createModule[[:space:]]*\(.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*"([^"]+)".*/\1/p')"
                if [ -z "$child" ] && [ -n "$root" ]; then
                    anon="__anonymous_module_$anon_index"
                    anon_index=$((anon_index + 1))
                    module_roots[$anon]="$root"
                    edges[$parent]="${edges[$parent]:-} $anon"
                elif [ -n "$child" ]; then
                    child="$(graph_resolve_alias "$child")"
                    edges[$parent]="${edges[$parent]:-} $child"
                else
                    fail "build addImport uses unresolved module expression in $file: $stmt"
                fi
            fi
            parent="$(printf '%s\n' "$stmt" | sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)(\.root_module)?\.addAnonymousImport[[:space:]]*\(.*/\1/p')"
            root="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.addAnonymousImport[[:space:]]*\(.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*"([^"]+)".*/\1/p')"
            if [ -z "$root" ]; then
                token="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.addAnonymousImport[[:space:]]*\(.*\.root_source_file[[:space:]]*=[[:space:]]*b\.path[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                [ -z "$token" ] || root="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
            fi
            if [ -n "$parent" ]; then
                parent="$(graph_resolve_alias "$parent")"
                if [ -z "$root" ]; then
                    fail "build addAnonymousImport uses unresolved root source in $file: $stmt"
                else
                    anon="__anonymous_module_$anon_index"
                    anon_index=$((anon_index + 1))
                    module_roots[$anon]="$root"
                    edges[$parent]="${edges[$parent]:-} $anon"
                fi
            fi
            parent="$(printf '%s\n' "$stmt" | sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)(\.root_module)?\.(addObject|linkLibrary)[[:space:]]*\(.*/\1/p')"
            child="$(printf '%s\n' "$stmt" | sed -nE 's/.*\.(addObject|linkLibrary)[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\2/p')"
            if [ -n "$parent" ] && [ -n "$child" ]; then
                parent="$(graph_resolve_alias "$parent")"
                child="$(graph_resolve_alias "$child")"
                edges[$parent]="${edges[$parent]:-} $child"
            fi
            parent="$(printf '%s\n' "$stmt" | sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)(\.root_module)?\.(addCSourceFiles|addCSourceFile|addObjectFile|addAssemblyFile)[[:space:]]*\(.*/\1/p')"
            if [ -n "$parent" ]; then
                parent="$(graph_resolve_alias "$parent")"
                foreign_calls[$parent]="${foreign_calls[$parent]:-}${foreign_calls[$parent]:+$'\n'}$file: $stmt"
            fi
            target="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*),[[:space:]]*"([^"]+)".*/\1/p')"
            lib="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[[:space:]]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*),[[:space:]]*"([^"]+)".*/\2/p')"
            if [ -n "$target" ] && [ -n "$lib" ]; then
                target="$(graph_resolve_alias "$target")"
                system_link_calls[$target]="${system_link_calls[$target]:-}${system_link_calls[$target]:+$'\n'}$lib $file: $stmt"
            fi
        done < <(logical_zig_calls <(stripped "$REPO_ROOT/$file"))
    done < <(resolve_build_sources)

    for installed in "${!installed_executables[@]}"; do
        exe="$(graph_resolve_alias "$installed")"
        if [ -z "${executable_names[$exe]:-}" ]; then
            fail "installed artifact $installed does not resolve to a known compile step"
            continue
        fi
        if [ -z "${executable_names[$exe]}" ]; then
            fail "installed executable uses unresolved name expression in build graph for $exe"
            continue
        fi
        [ "${executable_names[$exe]}" = "tardi" ] || continue
        reachable[$exe]=1
        root_mod="${executable_roots[$exe]:-}"
        root_path="${executable_root_paths[$exe]:-}"
        if [ -n "$root_mod" ]; then
            edges[$exe]="${edges[$exe]:-} $root_mod"
        elif [ -n "$root_path" ] && is_nonproduction_zig_file "$root_path"; then
            fail "installed tardi executable is rooted in non-production source $root_path"
        elif [ -z "$root_path" ]; then
            fail "installed tardi executable uses unresolved root module/source expression in build graph for $exe"
        fi
    done

    local changed rel line
    changed=true
    while [ "$changed" = true ]; do
        changed=false
        for parent in "${!reachable[@]}"; do
            for child in ${edges[$parent]:-}; do
                [ -n "$child" ] || continue
                if [ -z "${reachable[$child]:-}" ]; then
                    reachable[$child]=1
                    changed=true
                fi
            done
        done
    done

    for module in "${!reachable[@]}"; do
        rel="${module_roots[$module]:-}"
        if [ -n "$rel" ] && is_nonproduction_zig_file "$rel"; then
            fail "installed tardi module graph reaches non-production source root $rel via $module"
        fi
        if [ -z "$rel" ] && [ -z "${executable_names[$module]:-}" ] && ! is_reviewed_generated_build_module "$module"; then
            fail "installed tardi module graph reaches unresolved module/root $module"
        fi
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            fail "installed tardi module graph reaches foreign source/object/assembly build input through $module in $line"
        done <<<"${foreign_calls[$module]:-}"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            lib="${line%% *}"
            if ! allowed_system_library "$lib"; then
                fail "installed tardi graph reaches foreign system library link through $module in ${line#* }"
            fi
        done <<<"${system_link_calls[$module]:-}"
    done
}

validate_build_imports() {
    local file="$1" imports line
    if imports="$(stripped "$REPO_ROOT/$file" | tr '\n' ' ' | grep -oE '@import[[:space:]]*\([[:space:]]*[^)]*\)' | grep -vE '@import[[:space:]]*\([[:space:]]*"[^"]+"' || true)"; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            fail "production build helper import uses unresolved non-literal expression in $file: $line"
        done <<<"$imports"
    fi
}

scan_build_graph() {
    local file rel stmt lib token srcfile
    while IFS= read -r file; do
        [ -f "$REPO_ROOT/$file" ] || continue
        validate_build_imports "$file"
        while IFS= read -r stmt; do
            case "$stmt" in
            *linkSystemLibrary*'('*)
                case "$stmt" in
                " fn linkSystemLibrary("* | *"compile.root_module.linkSystemLibrary(name"*) continue ;;
                esac
                if is_allowed_nonproduction_build_statement "$stmt"; then
                    continue
                fi
                lib="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[^(]*\([^"]*"([^"]+)".*/\1/p')"
                if [ -z "$lib" ]; then
                    token="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[^(]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                    if [ -n "$token" ] && [ "$token" != "name" ]; then
                        lib="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
                    fi
                fi
                if [ -z "$lib" ]; then
                    fail "production system library link uses unresolved library expression in $file: $stmt"
                elif ! allowed_system_library "$lib"; then
                    fail "production foreign system library link in $file: $stmt"
                fi
                ;;
            *addCSourceFiles* | *addCSourceFile* | *addObjectFile* | *addAssemblyFile* | *addTranslateC*)
                if ! is_allowed_nonproduction_build_statement "$stmt"; then
                    fail "production vendored foreign source/object compilation in $file: $stmt"
                fi
                ;;
            esac
        done < <(logical_zig_statements <(stripped "$REPO_ROOT/$file"))
    done < <(resolve_build_sources)

    scan_build_production_graph
    scan_manifest_dependencies

    while IFS= read -r srcfile; do
        rel="$(relpath "$srcfile")"
        is_nonproduction_file "$rel" && continue
        case "$rel" in
        *.c | *.cc | *.cpp | *.cxx | *.m | *.mm) fail "vendored foreign implementation source in production scope: $rel" ;;
        esac
    done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -path "$REPO_ROOT/.zig" -prune -o -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o -type f -print | sort 2>/dev/null || true)
}

approved_manifest_dependency() {
    local name="$1" path="$2" url="$3" hash="$4"
    case "$name:$path:$url:$hash" in
    pure_zig:vendor/pure_zig::) return 0 ;;
    *) return 1 ;;
    esac
}

scan_manifest_dependencies() {
    [ -f "$REPO_ROOT/build.zig.zon" ] || return 0
    local manifest deps dep name path url hash pattern
    pattern="$(forbidden_dependency_pattern)"
    manifest="$(stripped "$REPO_ROOT/build.zig.zon")"
    if printf '%s\n' "$manifest" | grep -niE '\.(url|path)[[:space:]]*=' | grep -qEi "$pattern|\.c(pp)?($|[?#\"])"; then
        fail "production manifest dependency appears to introduce a foreign runtime implementation in build.zig.zon"
    fi
    deps="$(printf '%s\n' "$manifest" | awk '
        /\.dependencies[[:space:]]*=[[:space:]]*\.\{/ {
            capture=1
            depth=1
            line=$0
            sub(/.*\.dependencies[[:space:]]*=[[:space:]]*\.\{/, "", line)
            opens=gsub(/\{/, "{", line)
            closes=gsub(/\}/, "}", line)
            if (line != "") print line
            depth += opens - closes
            if (depth <= 0) capture=0
            next
        }
        capture {
            line=$0
            opens=gsub(/\{/, "{", line)
            closes=gsub(/\}/, "}", line)
            print
            depth += opens - closes
            if (depth <= 0) capture=0
        }
    ')"
    while IFS= read -r dep; do
        name="$(printf '%s\n' "$dep" | sed -nE 's/^[[:space:]]*\.([A-Za-z0-9_]+)[[:space:]]*=.*/\1/p; s/^[[:space:]]*\.@"([^"]+)"[[:space:]]*=.*/\1/p')"
        [ -n "$name" ] || continue
        path="$(printf '%s\n' "$deps" | awk -v dep="$name" '
            $0 ~ "^[[:space:]]*\\." dep "[[:space:]]*=" || index($0, ".@\"" dep "\"") > 0 { capture=1 }
            capture && /\.path[[:space:]]*=/ { line=$0; sub(/.*\.path[[:space:]]*=[[:space:]]*"/, "", line); sub(/".*/, "", line); print line; exit }
            capture && /^[[:space:]]*\},?/ { capture=0 }
        ')"
        url="$(printf '%s\n' "$deps" | awk -v dep="$name" '
            $0 ~ "^[[:space:]]*\\." dep "[[:space:]]*=" || index($0, ".@\"" dep "\"") > 0 { capture=1 }
            capture && /\.url[[:space:]]*=/ { line=$0; sub(/.*\.url[[:space:]]*=[[:space:]]*"/, "", line); sub(/".*/, "", line); print line; exit }
            capture && /^[[:space:]]*\},?/ { capture=0 }
        ')"
        hash="$(printf '%s\n' "$deps" | awk -v dep="$name" '
            $0 ~ "^[[:space:]]*\\." dep "[[:space:]]*=" || index($0, ".@\"" dep "\"") > 0 { capture=1 }
            capture && /\.hash[[:space:]]*=/ { line=$0; sub(/.*\.hash[[:space:]]*=[[:space:]]*"/, "", line); sub(/".*/, "", line); print line; exit }
            capture && /^[[:space:]]*\},?/ { capture=0 }
        ')"
        if ! approved_manifest_dependency "$name" "$path" "$url" "$hash"; then
            fail "production manifest dependency .$name is not in the reviewed pure-Zig dependency allowlist"
        fi
    done < <(printf '%s\n' "$deps" | grep -E '^[[:space:]]*\.([A-Za-z0-9_]+|@"[^"]+")[[:space:]]*=' || true)
}

is_allowed_metadata_dependency_statement() {
    local stmt="$1"
    local deps token seen_package=false
    stmt="$(printf '%s\n' "$stmt" | tr -s '[:space:]' ' ')"
    stmt="$(printf '%s\n' "$stmt" | sed -E 's/^[0-9]+:[[:space:]]*//')"
    stmt="${stmt#"${stmt%%[![:space:]]*}"}"
    stmt="${stmt%"${stmt##*[![:space:]]}"}"
    if printf '%s\n' "$stmt" | grep -qiE "$(forbidden_dependency_pattern)"; then
        return 1
    fi
    if [[ "$stmt" == *"apt-get install"* || "$stmt" == *"apt install"* ]]; then
        deps="$(printf '%s\n' "$stmt" | sed -E 's/.*apt(-get)? install //')"
        for token in $deps; do
            case "$token" in
            '&&' | ';' | '|' | '||') break ;;
            -*) continue ;;
            ca-certificates | curl | xz-utils | rpm | file | binutils)
                seen_package=true
                ;;
            *)
                return 1
                ;;
            esac
        done
        [ "$seen_package" = true ]
        return $?
    fi
    if [[ "$stmt" == "printf '  depends_on :linux\\n\\n'" || "$stmt" == "printf ' depends_on :linux\\n\\n'" ]]; then
        return 0
    fi
    if [[ "$stmt" == "depends_on :linux" ]]; then
        return 0
    fi
    return 1
}

metadata_dependency_statement_pattern() {
    printf '%s\n' 'apt(-get)? install|apk add|brew install|depends_on|Depends:|Requires:|cargo|go get|pip install'
}

scan_metadata() {
    local -a scan_files=()
    local f rel matches line helper_pattern
    helper_pattern="$(explicit_nonproduction_helper_pattern)"
    [ -f "$REPO_ROOT/.github/workflows/release.yml" ] && scan_files+=("$REPO_ROOT/.github/workflows/release.yml")
    while IFS= read -r f; do scan_files+=("$f"); done < <(find "$REPO_ROOT/packaging" -type f 2>/dev/null | sort)
    while IFS= read -r f; do
        rel="$(relpath "$f")"
        case "$rel" in
        scripts/interop/* | scripts/audit-dependencies.sh | scripts/audit-release-binary.sh) ;;
        *) scan_files+=("$f") ;;
        esac
    done < <(find "$REPO_ROOT/scripts" -type f 2>/dev/null | sort)
    while IFS= read -r f; do scan_files+=("$f"); done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.zig" -prune -o -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o \( -name 'Dockerfile*' -o -name 'compose.yaml' -o -name 'compose.yml' \) -type f -print | sort)

    for f in "${scan_files[@]}"; do
        [ -f "$f" ] || continue
        rel="$(relpath "$f")"
        is_nonproduction_file "$rel" && continue
        case "$rel" in
        *.md) continue ;;
        esac
        if ! is_explicit_nonproduction_helper "$rel"; then
            if matches="$(logical_shell_statements <(stripped "$f") | grep -niE "$helper_pattern" 2>/dev/null)"; then
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    fail "production metadata references explicit non-production helper in $rel: $line"
                done <<<"$matches"
            fi
        fi
        if matches="$(logical_shell_statements <(stripped "$f") | grep -niE "$(metadata_dependency_statement_pattern)" 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                if ! is_allowed_metadata_dependency_statement "$line"; then
                    fail "production package/container metadata contains unreviewed dependency declaration in $rel: $line"
                fi
            done <<<"$matches"
        fi
        if matches="$(logical_shell_statements <(stripped "$f") | grep -niE 'LD_PRELOAD|DYLD_INSERT_LIBRARIES|[A-Za-z0-9_./@-]+\.(so|dylib|dll)([^A-Za-z0-9_]|$)|\.framework(/|:|$)' 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                fail "production metadata can inject or mount a foreign runtime library in $rel: $line"
            done <<<"$matches"
        fi
    done
}

run_audit() {
    cd "$REPO_ROOT"
    failures=0
    scan_nonproduction_zig_imports
    scan_source_ffi
    scan_runtime_loading
    scan_build_graph
    scan_metadata
    if [ "$failures" -gt 0 ]; then
        echo "dependency audit failed with $failures violation(s)" >&2
        return 1
    fi
    echo "dependency audit passed: production graph is Zig/native-only with only reviewed OS/platform ABI boundaries"
}

make_fixture_repo() {
    local root="$1" kind="$2"
    mkdir -p "$root/src" "$root/tests" "$root/scripts/interop" "$root/packaging" "$root/.github/workflows"
    cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    _ = b;
}
EOF
    printf '.{}\n' >"$root/build.zig.zon"
    printf 'pub fn main() void {}\n' >"$root/src/main.zig"
    case "$kind" in
    fail-cimport)
        cat >"$root/src/main.zig" <<'EOF'
const c = @cImport({
    @cInclude("wolfssl/options.h");
});
pub fn main() void { _ = c; }
EOF
        ;;
    fail-link)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.linkSystemLibrary("foreignssl");
}
EOF
        ;;
    fail-link-multiline)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.root_module.linkSystemLibrary(
        "foreignssl",
        .{},
    );
}
EOF
        ;;
    fail-link-indirect)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const product_lib = "foreignssl";
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.root_module.linkSystemLibrary(product_lib, .{});
}
EOF
        ;;
    fail-csource)
        printf 'int foreign_impl(void) { return 1; }\n' >"$root/src/foreign_impl.c"
        ;;
    fail-build-csource-multiline)
        printf 'int foreign_impl(void) { return 1; }\n' >"$root/foreign_impl.c"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.addCSourceFile(.{
        .file = b.path("foreign_impl.c"),
    });
}
EOF
        ;;
    fail-build-helper-computed-import)
        mkdir -p "$root/build"
        printf 'foreign object placeholder\n' >"$root/foreign.o"
        cat >"$root/build/product.zig" <<'EOF'
const std = @import("std");
pub fn configure(b: *std.Build, exe: *std.Build.Step.Compile) void {
    exe.addObjectFile(b.path("foreign.o"));
}
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
const helper_path = "build/product.zig";
const product = @import(helper_path);
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    product.configure(b, exe);
    b.installArtifact(exe);
}
EOF
        ;;
    fail-build-helper-split-import)
        mkdir -p "$root/build"
        printf 'foreign object placeholder\n' >"$root/foreign.o"
        cat >"$root/build/product.zig" <<'EOF'
const std = @import("std");
pub fn configure(b: *std.Build, exe: *std.Build.Step.Compile) void {
    exe.addObjectFile(b.path("foreign.o"));
}
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
const product = @import
("build/product.zig");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    product.configure(b, exe);
    b.installArtifact(exe);
}
EOF
        ;;
    fail-test-looking-production-target)
        printf 'foreign object placeholder\n' >"$root/foreign.o"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const benchmark_tardi = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    benchmark_tardi.addObjectFile(b.path("foreign.o"));
    b.installArtifact(benchmark_tardi);
}
EOF
        ;;
    fail-tests-support-object-reached)
        mkdir -p "$root/tests/support"
        printf 'foreign object placeholder\n' >"$root/tests/support/foreign.o"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.addObjectFile(b.path("tests/support/foreign.o"));
    b.installArtifact(exe);
}
EOF
        ;;
    fail-evp-oracle-name-production-object)
        printf 'foreign object placeholder\n' >"$root/foreign.o"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const evp_oracle_tardi = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    evp_oracle_tardi.addObjectFile(b.path("foreign.o"));
    b.installArtifact(evp_oracle_tardi);
}
EOF
        ;;
    fail-tests-interop-object-reached)
        mkdir -p "$root/tests/interop"
        printf 'foreign object placeholder\n' >"$root/tests/interop/foreign.o"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.addObjectFile(b.path("tests/interop/foreign.o"));
    b.installArtifact(exe);
}
EOF
        ;;
    fail-nonproduction-source-imported)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("../benchmarks/product.zig");
pub fn main() void { product.load(); }
EOF
        ;;
    fail-split-nonproduction-source-imported)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import
("../benchmarks/product.zig");
pub fn main() void { product.load(); }
EOF
        ;;
    fail-nonliteral-production-source-import)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product_path = "../benchmarks/product.zig";
const product = @import(product_path);
pub fn main() void { product.load(); }
EOF
        ;;
    fail-named-nonproduction-module-import)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("product");
pub fn main() void { product.load(); }
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const product_mod = b.createModule(.{ .root_source_file = b.path("benchmarks/product.zig"), .target = target, .optimize = optimize });
    exe_mod.addImport("product", product_mod);
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-anonymous-nonproduction-module-import)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("product");
pub fn main() void { product.load(); }
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    exe_mod.addAnonymousImport("product", .{
        .root_source_file = b.path("benchmarks/product.zig"),
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-computed-tardi-name)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const product_name = "tardi";
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{ .name = product_name, .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-install-artifact-alias)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const evp_oracle_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11" } });
    const tardi = b.addExecutable(.{ .name = "tardi", .root_module = evp_oracle_mod });
    const shipping = tardi;
    b.installArtifact(shipping);
}
EOF
        printf 'int main(void) { return 0; }\n' >"$root/tests/evp_oracle.c"
        ;;
    fail-add-install-artifact)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const evp_oracle_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11" } });
    const tardi = b.addExecutable(.{ .name = "tardi", .root_module = evp_oracle_mod });
    const install = b.addInstallArtifact(tardi, .{});
    b.getInstallStep().dependOn(&install.step);
}
EOF
        printf 'int main(void) { return 0; }\n' >"$root/tests/evp_oracle.c"
        ;;
    fail-reachable-computed-module-root)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        printf 'pub fn ok() void {}\n' >"$root/src/safe.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("product");
pub fn main() void { product.load(); }
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const product_path_value = "benchmarks/product.zig";
    const product_path = product_path_value;
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const safe_mod = b.createModule(.{ .root_source_file = b.path("src/safe.zig"), .target = target, .optimize = optimize });
    const product_mod = b.createModule(.{ .root_source_file = b.path(product_path), .target = target, .optimize = optimize });
    product_mod.addImport("safe", safe_mod);
    exe_mod.addImport("product", product_mod);
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-reachable-module-alias)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("product");
pub fn main() void { product.load(); }
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const product_mod = b.createModule(.{ .root_source_file = b.path("benchmarks/product.zig"), .target = target, .optimize = optimize });
    const product_alias = product_mod;
    exe_mod.addImport("product", product_alias);
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-inline-add-import-module)
        mkdir -p "$root/benchmarks"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/benchmarks/product.zig"
        cat >"$root/src/main.zig" <<'EOF'
const product = @import("product");
pub fn main() void { product.load(); }
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    exe_mod.addImport("product", b.createModule(.{
        .root_source_file = b.path("benchmarks/product.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        ;;
    fail-oracle-module-installed)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const evp_oracle_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11" } });
    const tardi = b.addExecutable(.{ .name = "tardi", .root_module = evp_oracle_mod });
    b.installArtifact(tardi);
}
EOF
        printf 'int main(void) { return 0; }\n' >"$root/tests/evp_oracle.c"
        ;;
    fail-oracle-object-bridged)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const evp_oracle_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11" } });
    const oracle_obj = b.addObject(.{ .name = "oracle_obj", .root_module = evp_oracle_mod });
    exe_mod.addObject(oracle_obj);
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        printf 'int main(void) { return 0; }\n' >"$root/tests/evp_oracle.c"
        ;;
    fail-static-library-bridged)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const evp_oracle_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11" } });
    const oracle_lib = b.addLibrary(.{ .name = "oracle_lib", .root_module = evp_oracle_mod, .linkage = .static });
    exe_mod.linkLibrary(oracle_lib);
    const exe = b.addExecutable(.{ .name = "tardi", .root_module = exe_mod });
    b.installArtifact(exe);
}
EOF
        printf 'int main(void) { return 0; }\n' >"$root/tests/evp_oracle.c"
        ;;
    fail-evp-oracle-name-production-link)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
fn linkSystemLibrary(compile: *std.Build.Step.Compile, name: []const u8) void {
    compile.root_module.linkSystemLibrary(name, .{});
}
pub fn build(b: *std.Build) void {
    const evp_oracle = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    linkSystemLibrary(evp_oracle, "crypto");
    b.installArtifact(evp_oracle);
}
EOF
        ;;
    fail-assembly-file)
        printf '.globl foreign_impl\nforeign_impl:\n  ret\n' >"$root/foreign.s"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.addAssemblyFile(b.path("foreign.s"));
    b.installArtifact(exe);
}
EOF
        ;;
    fail-cinclude-computed)
        cat >"$root/src/main.zig" <<'EOF'
const foreign_header = "foreigncodec/api.h";
const os = @cImport({
    @cInclude("unistd.h");
});
const foreign = @cImport({
    @cInclude(foreign_header);
});
pub fn main() void { _ = os; _ = foreign; }
EOF
        ;;
    fail-cimport-split-foreign-header)
        cat >"$root/src/main.zig" <<'EOF'
const foreign = @cImport
({
    @cInclude
    ("foreigncodec/api.h");
});
pub fn main() void { _ = foreign; }
EOF
        ;;
    fail-translate-c)
        cat >"$root/foreign.h" <<'EOF'
int foreign_impl(void);
EOF
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    _ = b.addTranslateC(.{ .root_source_file = b.path("foreign.h") });
}
EOF
        ;;
    fail-package)
        printf 'Package: tardigrade\nDepends: libssl3\n' >"$root/packaging/control"
        ;;
    fail-docker-multiline)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libssl3
EOF
        ;;
    fail-test-helper-reached)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN ./scripts/test-install-runtime.sh
EOF
        cat >"$root/scripts/test-install-runtime.sh" <<'EOF'
#!/usr/bin/env bash
apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3
EOF
        chmod +x "$root/scripts/test-install-runtime.sh"
        ;;
    fail-allowlisted-helper-reached)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN ./scripts/test-install.sh
EOF
        cat >"$root/scripts/test-install.sh" <<'EOF'
#!/usr/bin/env bash
apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3
EOF
        chmod +x "$root/scripts/test-install.sh"
        ;;
    fail-outside-src-runtime-loading)
        mkdir -p "$root/vendor"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so"); }\n' >"$root/vendor/product.zig"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const product_mod = b.createModule(.{ .root_source_file = b.path("vendor/product.zig") });
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.root_module.addImport("product", product_mod);
    b.installArtifact(exe);
}
EOF
        ;;
    fail-neutral-dependency-c)
        mkdir -p "$root/vendor/fastcodec"
        cat >"$root/build.zig.zon" <<'EOF'
.{
    .dependencies = .{
        .fastcodec = .{ .path = "vendor/fastcodec" },
    },
}
EOF
        cat >"$root/vendor/fastcodec/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const lib = b.addStaticLibrary(.{ .name = "fastcodec", .root_source_file = b.path("root.zig") });
    lib.addCSourceFile(.{ .file = b.path("codec.c") });
}
EOF
        printf 'pub fn ok() void {}\n' >"$root/vendor/fastcodec/root.zig"
        printf 'int codec(void) { return 1; }\n' >"$root/vendor/fastcodec/codec.c"
        ;;
    fail-quoted-dependency-key-c)
        mkdir -p "$root/vendor/fastcodec"
        cat >"$root/build.zig.zon" <<'EOF'
.{
    .dependencies = .{
        .@"fast-codec" = .{ .path = "vendor/fastcodec" },
    },
}
EOF
        cat >"$root/vendor/fastcodec/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const lib = b.addStaticLibrary(.{ .name = "fastcodec", .root_source_file = b.path("root.zig") });
    lib.addCSourceFile(.{ .file = b.path("codec.c") });
}
EOF
        printf 'pub fn ok() void {}\n' >"$root/vendor/fastcodec/root.zig"
        printf 'int codec(void) { return 1; }\n' >"$root/vendor/fastcodec/codec.c"
        ;;
    fail-inline-zon-dependency)
        mkdir -p "$root/vendor/fastcodec"
        cat >"$root/build.zig.zon" <<'EOF'
.{
    .name = .tardigrade,
    .version = "0.0.0",
    .fingerprint = 0x763f21d3055af9f4,
    .minimum_zig_version = "0.16.0",
    .paths = .{ "build.zig", "build.zig.zon", "src" },
    .dependencies = .{ .fastcodec = .{ .path = "vendor/fastcodec" }, },
}
EOF
        ;;
    fail-compose-preload)
        cat >"$root/compose.yaml" <<'EOF'
services:
  tardigrade:
    image: tardigrade:local
    environment:
      LD_PRELOAD: /plugins/ForeignCodec.so
    volumes:
      - ./ForeignCodec.so:/plugins/ForeignCodec.so:ro
EOF
        ;;
    fail-unknown-package)
        printf 'Package: tardigrade\nDepends: libforeigncodec1\n' >"$root/packaging/control"
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends foreigncodec-runtime
EOF
        ;;
    fail-unknown-package-after-ca)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates foreigncodec-runtime
EOF
        ;;
    fail-unknown-package-after-rpm)
        cat >"$root/.github/workflows/release.yml" <<'EOF'
jobs:
  release:
    steps:
      - run: sudo apt-get install -y rpm foreigncodec-runtime
EOF
        ;;
    fail-homebrew-linux-plus-dependency)
        cat >"$root/packaging/tardigrade.rb" <<'EOF'
class Tardigrade < Formula
  depends_on :linux; depends_on "foreigncodec"
end
EOF
        ;;
    fail-nonproduction-helper-reached-broad)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN ./scripts/interop/install-foreign-peer.sh
EOF
        cat >"$root/scripts/interop/install-foreign-peer.sh" <<'EOF'
#!/usr/bin/env bash
apt-get install -y foreigncodec-runtime
EOF
        chmod +x "$root/scripts/interop/install-foreign-peer.sh"
        ;;
    fail-release-reusable-workflow)
        cat >"$root/.github/workflows/release.yml" <<'EOF'
jobs:
  package:
    uses: ./.github/workflows/package.yml
EOF
        cat >"$root/.github/workflows/package.yml" <<'EOF'
jobs:
  package:
    steps:
      - run: sudo apt-get install -y foreigncodec-runtime
EOF
        ;;
    fail-dlopen)
        printf 'const std = @import("std");\npub fn main() void { _ = std.DynLib.open("libssl.so"); }\n' >"$root/src/main.zig"
        ;;
    pass-platform)
        cat >"$root/src/main.zig" <<'EOF'
const c = @cImport({
    @cInclude("unistd.h");
});
pub fn main() void { _ = c; }
EOF
        ;;
    pass-platform-split-cimport)
        cat >"$root/src/main.zig" <<'EOF'
const c = @cImport
({
    @cInclude
    ("unistd.h");
});
pub fn main() void { _ = c; }
EOF
        ;;
    pass-test-peer)
        printf 'openssl version\n' >"$root/scripts/interop/run.sh"
        chmod +x "$root/scripts/interop/run.sh"
        printf 'Package docs mention libssl in prose only.\n' >"$root/packaging/README.md"
        ;;
    pass-benchmark-gdrive-upload)
        cat >"$root/scripts/upload-benchmarks-gdrive.rb" <<'EOF'
DIRECTORIES = ['benchmarks/results', 'benchmarks/baselines', 'docs/evidence']
EOF
        chmod +x "$root/scripts/upload-benchmarks-gdrive.rb"
        ;;
    pass-isolated-nonproduction-zig)
        mkdir -p "$root/scripts/interop"
        printf 'const std = @import("std");\npub fn load() void { _ = std.DynLib.open("libforeigncodec.so") catch return; }\n' >"$root/scripts/interop/product.zig"
        ;;
    pass-pure-zig)
        mkdir -p "$root/vendor/pure_zig"
        cat >"$root/build.zig.zon" <<'EOF'
.{
    .dependencies = .{
        .pure_zig = .{ .path = "vendor/pure_zig" },
    },
}
EOF
        ;;
    pass-toolchain-install-dir)
        # scripts/install-zig.sh installs the toolchain into ./.zig by
        # default, and release.yml's "Install Zig" step runs before the
        # audit. The toolchain's own vendored compiler-rt/libtsan/libunwind
        # C/C++ runtime sources must not be mistaken for a production
        # vendored implementation.
        mkdir -p "$root/.zig/0.16.0/zig-x86_64-linux-0.16.0/lib/libtsan/sanitizer_common"
        printf 'int not_our_code(void) { return 1; }\n' \
            >"$root/.zig/0.16.0/zig-x86_64-linux-0.16.0/lib/libtsan/sanitizer_common/sanitizer_common.cpp"
        ;;
    esac
}

run_self_test() {
    local tmp kind rc
    tmp="$(mktemp -d)"
    SELF_TEST_TMP="$tmp"
    trap 'rm -rf "$SELF_TEST_TMP"' EXIT
    for kind in fail-cimport fail-link fail-link-multiline fail-link-indirect fail-csource fail-build-csource-multiline fail-build-helper-computed-import fail-build-helper-split-import fail-test-looking-production-target fail-tests-support-object-reached fail-evp-oracle-name-production-object fail-tests-interop-object-reached fail-nonproduction-source-imported fail-split-nonproduction-source-imported fail-nonliteral-production-source-import fail-named-nonproduction-module-import fail-anonymous-nonproduction-module-import fail-computed-tardi-name fail-install-artifact-alias fail-add-install-artifact fail-reachable-computed-module-root fail-reachable-module-alias fail-inline-add-import-module fail-oracle-module-installed fail-oracle-object-bridged fail-static-library-bridged fail-evp-oracle-name-production-link fail-assembly-file fail-cinclude-computed fail-cimport-split-foreign-header fail-translate-c fail-package fail-docker-multiline fail-test-helper-reached fail-allowlisted-helper-reached fail-outside-src-runtime-loading fail-neutral-dependency-c fail-quoted-dependency-key-c fail-inline-zon-dependency fail-compose-preload fail-unknown-package fail-unknown-package-after-ca fail-unknown-package-after-rpm fail-homebrew-linux-plus-dependency fail-nonproduction-helper-reached-broad fail-release-reusable-workflow fail-dlopen; do
        make_fixture_repo "$tmp/$kind" "$kind"
        if "$0" --root "$tmp/$kind" >/dev/null 2>&1; then
            echo "self-test failed: $kind unexpectedly passed" >&2
            return 1
        fi
    done
    for kind in pass-platform pass-platform-split-cimport pass-test-peer pass-benchmark-gdrive-upload pass-isolated-nonproduction-zig pass-pure-zig pass-toolchain-install-dir; do
        make_fixture_repo "$tmp/$kind" "$kind"
        if ! "$0" --root "$tmp/$kind" >/dev/null; then
            rc=$?
            echo "self-test failed: $kind unexpectedly failed with $rc" >&2
            "$0" --root "$tmp/$kind" || true
            return 1
        fi
    done
    echo "dependency audit self-test passed"
}

if [ "$SELF_TEST" = true ]; then
    run_self_test
else
    run_audit
fi
