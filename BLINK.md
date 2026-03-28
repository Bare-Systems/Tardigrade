# Tardigrade Blink Contract

This file documents the real behavior of [`blink.toml`](/Users/joecaruso/Projects/BareSystems/Tardigrade/blink.toml).

## Target

- `homelab`
- type: SSH
- host: `blink`
- user: `admin`
- runtime dir: `/home/admin/barelabs/runtime/tardigrade-build`

## Build Behavior

- Source is bundled locally as `dist/tardigrade-src.tgz`
- The tarball is uploaded to the host
- A remote script installs Zig if needed and builds the binary on the host side

## Deploy Behavior

Pipeline:

- `fetch_artifact`
- `provision`
- `install`
- `remote_script`
- `stop`
- `start`
- `health_check`
- `verify`

Rollback pipeline:

- `stop`
- `shell`
- `health_check`

The deploy flow stages source, builds remotely, backs up the current binary, replaces the runtime binary, and restarts the user service.

## Verification

- HTTPS health on `https://127.0.0.1:8443/health`
- service-running check
- port-listening check
- BearClaw upstream configuration check
- Host-header preservation check

## Operator Notes

- Tardigrade is the public homelab edge.
- The manifest assumes the shared `blink-homelab` runtime layout and user service management.
- Update this file whenever the build transport, runtime paths, rollback behavior, or verification checks change.
