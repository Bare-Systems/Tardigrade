<h1 align="center">Tardigrade</h1>

<p align="center">
  A small Zig HTTP server and edge gateway for static delivery, reverse proxying,
  config-driven routing, TLS termination, and operator-friendly reloads.
</p>

---

Tardigrade is an early-stage Zig service runtime for lightweight edge deployments,
internal platforms, and controlled homelab environments.

The project currently focuses on:

- static file serving
- reverse proxying
- config-driven routing with `server` and `location` blocks
- TLS termination
- config validation and hot reloads
- access logging and basic operational controls

Some protocol and gateway features are still experimental. Prefer the example
configs and integration tests as the source of truth when evaluating a specific
capability.

## Quick Start

### Prerequisites

- [Zig](https://ziglang.org/) 0.14.1 or later

### Build and run from source

```bash
git clone https://github.com/Bare-Systems/Tardigrade.git
cd Tardigrade
zig build run
```

The default development listener starts on `http://localhost:8069`.

### Install latest release

```bash
curl -fsSL https://raw.githubusercontent.com/Bare-Systems/Tardigrade/main/scripts/install.sh | sh
```

## Basic Usage

```bash
./zig-out/bin/tardigrade run
./zig-out/bin/tardigrade validate -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade reload -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade stop -c /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardigrade config init
```

## Minimal Config Example

```nginx
listen_port 8069;
root ./public;
try_files $uri /index.html;

location /api/ {
    proxy_pass http://127.0.0.1:8080;
}

location = /health {
    return 200 ok;
}
```

When proxying, Tardigrade strips hop-by-hop request headers, including headers
named by the incoming `Connection` header, before forwarding requests upstream.

Static file requests are percent-decoded and normalized before filesystem
access. Traversal attempts and symlink escapes outside the configured root are
rejected with `403`.

## Documentation

| Topic | Location |
| --- | --- |
| Packaging | `packaging/README.md` |
| Kubernetes | `packaging/kubernetes/README.md` |
| Benchmarks | `benchmarks/README.md` |
| BearClaw example | `examples/bearclaw/README.md` |
| Security policy | `SECURITY.md` |
| Contributing | `CONTRIBUTING.md` |
| Release history | `CHANGELOG.md` |

## Testing

```bash
zig build test
zig build test-integration
```
