#!/usr/bin/env sh
set -eu

[ "$#" -eq 3 ] || {
    echo "Usage: $0 <docker-image> <archive-path> <expected-version>" >&2
    exit 2
}

image="$1"
archive_dir=$(cd "$(dirname "$2")" && pwd -P)
archive="$archive_dir/$(basename "$2")"
expected_version="$3"

test -f "$archive" || { echo "archive not found: $archive" >&2; exit 2; }

archive_sha=$(sha256sum "$archive" | awk '{print $1}')
printf 'archive=%s\narchive_sha256=%s\n' "$(basename "$archive")" "$archive_sha"

docker pull --platform linux/amd64 "$image"
docker image inspect --format 'image={{index .RepoDigests 0}}' "$image"

echo "Verifying $archive in $image"

docker run --rm --platform linux/amd64 \
    -e EXPECTED_VERSION="$expected_version" \
    -v "$archive:/artifact.tar.gz:ro" \
    "$image" \
    /bin/sh -euxc '
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y curl ca-certificates file binutils
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates file binutils
        if ! command -v curl >/dev/null 2>&1; then
            dnf install -y curl-minimal
        fi
    else
        echo "No supported package manager found" >&2
        exit 1
    fi

    mkdir -p /tmp/ext
    cd /tmp/ext
    tar -xzf /artifact.tar.gz

    if [ ! -x ./tardi ]; then
        echo "archive does not contain executable root-level tardi" >&2
        exit 1
    fi
    if [ ! -L ./tardigrade ]; then
        echo "archive does not contain tardigrade symlink" >&2
        exit 1
    fi
    link_target=$(readlink ./tardigrade)
    if [ "$link_target" != "tardi" ]; then
        echo "unexpected tardigrade symlink target: $link_target (expected tardi)" >&2
        exit 1
    fi

    tardi=./tardi

    cat /etc/os-release
    uname -m
    getconf GNU_LIBC_VERSION || true
    ldd --version
    file "$tardi"
    ldd "$tardi"
    readelf --version-info "$tardi"
    
    printf "referenced_glibc_versions:\n"
    readelf --version-info "$tardi" \
      | grep -oE "GLIBC_[0-9]+(\.[0-9]+)*" \
      | sort -Vu \
      | sed "s/^/  /"
    
    version_output=$("$tardi" version)
    printf "tardi_version=%s\n" "$version_output"
    
    expected="$EXPECTED_VERSION (tls-profile=general, tls-backend=native)"
    # Current binaries include source/build provenance; older published releases
    # retain the original identity. Keep the version/profile/backend checks exact
    # and require experimental ACME to be disabled when provenance is present.
    identity=$(printf "%s\n" "$version_output" | sed -E "s/, commit=[^,()]+, acme-experimental=false\\)$/)/")
    if [ "$identity" != "$expected" ]; then
        echo "unexpected tardi version identity" >&2
        echo "expected: $expected" >&2
        echo "actual:   $version_output" >&2
        exit 1
    fi
    
    cat > tardigrade.conf <<EOF
listen 18089;
server_name localhost;
location = /health {
    return 200 compat-ok;
}
EOF
    "$tardi" check -c tardigrade.conf

    "$tardi" run -c tardigrade.conf > tardi.log 2>&1 &
    pid=$!

    ready=false
    i=0
    while [ $i -lt 50 ]; do
        if curl -fsS http://localhost:18089/health >/dev/null 2>&1; then
            ready=true
            break
        fi
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
        i=$((i+1))
    done

    if [ "$ready" != "true" ]; then
        cat tardi.log >&2
        echo "Failed to start or serve traffic" >&2
        exit 1
    fi

    res=$(curl -fsS http://localhost:18089/health)
    if [ "$res" != "compat-ok" ]; then
        echo "Unexpected response: $res" >&2
        exit 1
    fi

    kill -INT "$pid"
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do
        sleep 0.2
        i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        cat tardi.log >&2
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        echo "tardi did not exit after SIGINT" >&2
        exit 1
    fi
    if wait "$pid"; then
        :
    else
        status=$?
        cat tardi.log >&2
        echo "tardi exited non-zero after SIGINT: $status" >&2
        exit 1
    fi
'
