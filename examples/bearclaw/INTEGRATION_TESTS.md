# BearClaw integration contract validation

Issue #202 tracks the process boundary between Tardigrade and BearClaw. Tardigrade is the public HTTPS edge; the BearClaw application remains a loopback HTTP upstream. The integration suite exercises this boundary with a stub upstream, so no BearClaw agent or provider API key is required.

## Run the focused suite

From the repository root:

```sh
zig build test-integration \
  -Dintegration-test-filter=bearclaw \
  --summary all --error-style verbose
```

`integration-test-filter` is the build-level filter used by `test-integration`; do not pass `--test-filter` after `--` for this suite.

Run the complete integration gate with:

```sh
zig build test-integration --summary all --error-style verbose
```

The integration step requires the same local prerequisites documented in `CONTRIBUTING.md` (including system OpenSSL for the live-process integration fixtures).

## Contract covered by the fixture

The BearClaw cases in `tests/integration.zig` collectively pin the edge-side behavior expected by the deployment example:

- Tardigrade owns the HTTPS listener and TLS handshake; the upstream remains plain loopback HTTP.
- `/v1/chat` reaches the stub upstream when the configured bearer token is valid.
- Missing or invalid bearer credentials are rejected at the edge before the protected upstream route is served.
- The `/bearclaw` prefix routing contract is exercised: public health remains reachable while protected `/bearclaw/v1/*` routes require authentication.
- Correlation/request metadata is generated and propagated through the proxy path, together with the trusted forwarding headers described in `README.md`.
- Transcript persistence and transcript-write failure behavior are exercised without requiring a real BearClaw service.
- Upstream and fixture failures are reported as Tardigrade edge/integration failures rather than depending on an external BearClaw provider.

The authoritative route and header contract remains `examples/bearclaw/README.md` plus `tardigrade.conf`; this file documents how to verify that contract locally.

## Failure triage

When a focused case fails, separate the boundary being tested before changing either project:

1. **Tardigrade startup/TLS failure** — inspect the spawned Tardigrade diagnostics and fixture certificate/config setup.
2. **Edge auth/routing failure** — inspect the HTTP status and Tardigrade route/auth configuration; the request should not be attributed to BearClaw application behavior if it never reached the stub upstream.
3. **Proxy/upstream failure** — inspect the stub upstream observation and the gateway response mapping.
4. **Persistence failure** — inspect the fixture's temporary transcript/session paths; no production BearClaw state is involved.

This keeps #202 scoped to the Tardigrade side of the process contract and makes the integration suite reproducible without external credentials or services.
