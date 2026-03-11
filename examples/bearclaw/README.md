# BearClaw Example Deployment

This directory contains a deployment example for running Tardigrade in front of a BearClaw stack.

What is included:

- `tardigrade.conf`: nginx-style Tardigrade config with TLS, server blocks, static assets, and the application-facing gateway routes
- `tardigrade.env.example`: environment variables for upstreams, auth, approvals, devices, sessions, mux, and logging

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
- The config uses Tardigrade's built-in API, websocket, mux, and SSE routes exactly as this repo currently exposes them.
- If you run HTTP/3, build with `-Denable-http3-ngtcp2=true` and provide a QUIC-capable client.

## Suggested Startup

```bash
set -a
source examples/bearclaw/tardigrade.env.example
set +a

zig build
./zig-out/bin/tardigrade
```
