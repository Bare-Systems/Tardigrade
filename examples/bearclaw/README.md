# BearClaw Example Deployment

This directory contains a deployment example for running Tardigrade in front of a BearClaw stack.

What is included:

- `tardigrade.conf`: nginx-style Tardigrade config with TLS, server blocks, static assets, and the application-facing gateway routes
- `tardigrade.env.example`: environment variables for upstreams, bearer auth, approvals, devices, session persistence, transcript persistence, mux, and logging

This example is intentionally isolated from the root project documentation so the main repo remains generic.

## Files

### `tardigrade.conf`

Use this as the runtime config file:

```bash
TARDIGRADE_CONFIG_PATH=examples/bearclaw/tardigrade.conf ./zig-out/bin/tardigrade
```

### `tardigrade.env.example`

Copy this into your deployment environment and replace placeholder values before starting Tardigrade.

## Deployment Notes

- The example assumes BearClaw application upstreams are reachable over HTTP on local loopback ports.
- TLS file paths are placeholders and must be replaced with real certificate and key paths.
- The config keeps Tardigrade generic by using plain reverse-proxy locations for `/v1/chat` and `/v1/commands`.
- The intended mobile and pairing auth path is bearer-token based. Set `TARDIGRADE_AUTH_TOKEN_HASHES` to SHA-256 hashes of the raw bearer tokens your upstream issues.
- Session state, approval state, and request transcripts can be persisted independently with `TARDIGRADE_SESSION_STORE_PATH`, `TARDIGRADE_APPROVAL_STORE_PATH`, and `TARDIGRADE_TRANSCRIPT_STORE_PATH`.
- If you run HTTP/3, build with `-Denable-http3-ngtcp2=true` and provide a QUIC-capable client.

## HTTPS Edge Contract

Use this example when Tardigrade is the public TLS terminator and the BearClaw application only listens on loopback HTTP.

- Public edge: Tardigrade listens on `443` with `tls_cert_path` and `tls_key_path`.
- App upstream: `TARDIGRADE_UPSTREAM_BASE_URL` points at `http://127.0.0.1:<port>`.
- Chat proxy: `location = /v1/chat { proxy_pass /v1/chat; }`.
- Command proxy: `location = /v1/commands { proxy_pass /v1/commands; }`.
- Static shell: `/` and `/assets/` continue serving the application shell from disk.
- Persistence: session, approval, and transcript files live under `/var/lib/tardigrade/`.

The integration fixture in [tests/integration.zig](/Users/joecaruso/Projects/BareLabs/Tardigrade/tests/integration.zig) exercises this path over HTTPS with Tardigrade-owned TLS.

## Suggested Startup

```bash
set -a
source examples/bearclaw/tardigrade.env.example
set +a

zig build
./zig-out/bin/tardigrade
```
