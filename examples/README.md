# Tardigrade Examples

Curated, copy/paste-runnable configs for common Tardigrade deployments.
Each example includes a short explanation, the minimal setup required to run it locally, and a reference to the environment variables it uses.

Prefer fewer high-quality examples over many incomplete snippets. If something
is not represented here, check the
[configuration reference](../docs/CONFIGURATION.md),
[configuration overview](../README.md#overview), and
[Core v1 support matrix](../docs/SUPPORT_MATRIX.md), or open an issue.

## Index

| Example | What it demonstrates |
|---------|----------------------|
| [static-file-server](static-file-server/README.md) | Serve static files over plain HTTP. |
| [reverse-proxy](reverse-proxy/README.md) | Proxy all requests to a local application. |
| [tls-termination](tls-termination/README.md) | Terminate HTTPS and forward plain HTTP to an upstream. |
| [virtual-hosts](virtual-hosts/README.md) | Route multiple hostnames to different upstreams using server blocks. |
| [health-checks](health-checks/README.md) | Active upstream health probing with automatic failover. |
| [rate-limiting](rate-limiting/README.md) | Per-client request-rate caps with burst allowance. |
| [forward-auth](forward-auth/README.md) | Delegate access decisions to an external auth service (`auth_request`/`forward_auth` style). |
| [access-logs](access-logs/README.md) | Structured JSON access logging with optional syslog forwarding. |
| [prometheus-metrics](prometheus-metrics/README.md) | Built-in Prometheus metrics endpoint. |
| [graceful-reload](graceful-reload/README.md) | Hot-reload config and drain connections on shutdown. |
| [production-baseline](production-baseline/README.md) | Full hardened deployment combining TLS, security headers, rate limiting, metrics, health checks, and drain. |
| [bearclaw](bearclaw/README.md) | BearClaw-specific edge shape (product-specific; see support matrix). |

## Generating a starter config

`tardi init <profile>` (or the verbose `tardi config init --profile <profile>`)
generates a minimal starter config for one of five common shapes, without
hand-copying an example:

| `tardi init` profile | Descriptive alias | Corresponding example |
|---|---|---|
| `static` | `static-site` | [static-file-server](static-file-server/README.md) |
| `proxy` | `reverse-proxy` | [reverse-proxy](reverse-proxy/README.md) |
| `tls` | `tls-termination` | [tls-termination](tls-termination/README.md) |
| `metrics` | `metrics-enabled` | [prometheus-metrics](prometheus-metrics/README.md) |
| `prod` | `production-baseline` | [production-baseline](production-baseline/README.md) |

```bash
./zig-out/bin/tardi init static > tardigrade.conf
./zig-out/bin/tardi check ./tardigrade.conf
```

The generated starters are intentionally minimal; once a profile fits your
deployment, use the corresponding example above (and its `README.md`) for the
complete, copy/paste-runnable version with every relevant knob explained.

## How to run an example

All examples follow the same pattern:

```bash
# 1. Build Tardigrade
zig build

# 2. Point Tardigrade at the example config
TARDIGRADE_CONFIG_PATH=examples/<name>/tardigrade.conf ./zig-out/bin/tardi

# 3. (Optional) dry-run the config without starting listeners
./zig-out/bin/tardi check examples/<name>/tardigrade.conf
```

Examples that require TLS certificates or upstream URLs use environment
variables. Copy `tardigrade.env.example` (where present) and fill in the
values for your environment:

```bash
cp examples/tls-termination/tardigrade.env.example /tmp/my.env
# Edit /tmp/my.env ...
set -a && source /tmp/my.env && set +a
TARDIGRADE_CONFIG_PATH=examples/tls-termination/tardigrade.conf ./zig-out/bin/tardi
```

## CI validation

All example configs are parsed by `tardi check` in CI to ensure they remain
syntactically valid as the parser evolves. See `.github/workflows/ci.yml` for
the `examples` job.
