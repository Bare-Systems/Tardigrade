# Local build support only: this image is not published to a registry.
# See docs/DEPLOYMENT.md for the full Docker deployment workflow and
# packaging/README.md for current packaging/distribution status.

# debian:bookworm-slim, pinned by digest for reproducible builds.
FROM debian@sha256:34cd9e9fd437c0a095ec39cb2e73422c9f30821b0d0848ed74fd0d43bae4d958 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Pin to the same Zig version CI builds/tests against (.github/workflows/ci.yml).
RUN sh ./scripts/install-zig.sh 0.16.0 /opt/zig \
    && ln -s "$(find /opt/zig -maxdepth 3 -type f -name zig)" /usr/local/bin/zig

# Default "general" TLS profile: links the approved OpenSSL adapter (see
# docs/TLS_DEPENDENCY_POLICY.md). Requires libssl-dev above.
RUN zig build -Doptimize=ReleaseFast

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian@sha256:34cd9e9fd437c0a095ec39cb2e73422c9f30821b0d0848ed74fd0d43bae4d958 AS runtime

# Fixed, documented numeric identity: compose.yaml and scripts/test-docker-image.sh
# pin their tmpfs/ownership checks to these exact values. `useradd --system`
# without an explicit --uid lets the distro allocate whatever's next free,
# which happens to be 999 on the currently pinned base but isn't a contract —
# a future base image refresh could silently break tmpfs ownership.
ARG TARDIGRADE_UID=10001
ARG TARDIGRADE_GID=10001

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "$TARDIGRADE_GID" tardigrade \
    && useradd --system --uid "$TARDIGRADE_UID" --gid "$TARDIGRADE_GID" \
        --no-create-home --shell /usr/sbin/nologin tardigrade

COPY --from=build /src/zig-out/bin/tardi /usr/local/bin/tardi

RUN mkdir -p /etc/tardigrade /var/lib/tardigrade /run/tardigrade /var/log/tardigrade \
    && chown -R tardigrade:tardigrade /var/lib/tardigrade /run/tardigrade /var/log/tardigrade

USER tardigrade
WORKDIR /var/lib/tardigrade

ENV TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid

EXPOSE 8069/tcp

# Exec form so `tardi` runs as PID 1 and receives SIGTERM/SIGHUP directly from
# `docker stop` / `docker kill -s HUP`, rather than a shell intermediary.
ENTRYPOINT ["/usr/local/bin/tardi"]
CMD ["run", "-c", "/etc/tardigrade/tardigrade.conf"]
