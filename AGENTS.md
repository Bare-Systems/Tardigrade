# Agent Guide

Scope: the `Tardigrade` repository.

## Rules

- Keep the core runtime generic.
- Do not add product-specific logic to core.
- Put integrations under `examples/`.
- Keep docs concise and operator-focused.

## Workflow

- Keep active unfinished work in `ROADMAP.md`.
- Update `README.md` for operator-facing behavior.
- Update `BLINK.md` for deployment reality.
- Record notable repo changes in `CHANGELOG.md`.

## Validation

```bash
zig build test
zig build test-integration
```

## HTTP/3 Session Resumption and 0-RTT

HTTP/3 support is gated on the `enable_http3_ngtcp2` build option and requires
ngtcp2 + nghttp3 + an OpenSSL build with QUIC support at link time.

### Session resumption

TLS session tickets are always enabled for HTTP/3 connections
(`TARDIGRADE_TLS_SESSION_TICKETS`, default `true`).  On reconnect, ngtcp2 offers
the stored ticket via ClientHello and the server validates the embedded QUIC
version before accepting it.  Resumption reduces the connection handshake from 1
RTT to 0 RTT for the TLS layer.

### 0-RTT early data

`TARDIGRADE_HTTP3_ENABLE_0RTT` (default `false`) controls whether the server
accepts early data from resuming clients.

- **Default (disabled):** `SSL_CTX_set_max_early_data(ctx, 0)` instructs
  OpenSSL to reject all 0-RTT data.  Clients must complete a full handshake
  before sending requests.
- **Enabled:** the server accepts early-data frames.  Any stream that carries
  `NGTCP2_STREAM_DATA_FLAG_0RTT` data is marked as an early-data stream.  When
  a complete request is assembled from such a stream, Tardigrade checks the HTTP
  method:
  - **Safe methods** (GET, HEAD, OPTIONS, TRACE) are forwarded to the request
    handler normally.
  - **Unsafe methods** (POST, PUT, PATCH, DELETE, CONNECT) are rejected with
    `425 Too Early` without invoking the handler.  This prevents replay attacks
    where a network adversary retransmits 0-RTT packets to trigger side-effecting
    requests.

### Production caveats

- Enable 0-RTT only on services whose GET/HEAD responses are safe to replay
  (e.g. read-only APIs, static files).
- Even safe-method 0-RTT requests are subject to replay by a network attacker.
  Do not process 0-RTT GET requests that carry authentication tokens granting
  write access.
- `warnRiskyConfig` logs a warning when `http3_0rtt_enabled` is true at startup
  and on every config reload.
