FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 wget && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /var/lib/tardigrade --create-home --shell /usr/sbin/nologin tardigrade

COPY zig-out/bin/tardigrade /usr/local/bin/tardigrade
RUN ln -s /usr/local/bin/tardigrade /usr/local/bin/tardi

USER tardigrade
WORKDIR /var/lib/tardigrade

EXPOSE 8069
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8069/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/tardigrade"]
