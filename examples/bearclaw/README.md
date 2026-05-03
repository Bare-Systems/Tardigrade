# BearClaw Example Deployment

This directory contains a deployment example for running Tardigrade in front of a BearClaw stack.

What is included:

- `tardigrade.conf`: nginx-style Tardigrade config with TLS, server blocks, static assets, and the application-facing gateway routes
- `tardigrade.env.example`: environment variables for upstreams, bearer auth, approvals, devices, session persistence, transcript persistence, mux, and logging

This example is intentionally isolated from the root project documentation so the main repo remains generic.

Use `tardigrade.conf` plus `tardigrade.env.example` as the canonical BearClaw-facing edge shape.

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

## Edge Contract

Use this example when Tardigrade is the public TLS terminator and the BearClaw application only listens on loopback HTTP.

### Ports

| Port | Protocol | Role |
|------|----------|------|
| 443 | HTTPS (TLS + HTTP/2) | Public edge; all external traffic enters here |
| 8080 | HTTP (loopback only) | BearClaw upstream; never exposed externally |

### Base Paths

| Path | Auth | Behavior |
|------|------|----------|
| `GET /health` | none | Returns `200 ok` directly from the edge with no upstream hop |
| `POST /v1/chat` | required | Proxies to upstream `/v1/chat` |
| `POST /v1/commands` | required | Proxies to upstream `/v1/commands` |
| `GET /bearclaw/health` | none | Strips `/bearclaw` and proxies to upstream `/health` |
| `/bearclaw/v1/*` | required | Strips `/bearclaw` and proxies to upstream `/v1/*` |
| `/bearclaw/transcripts` | required | Exposes the redacted NDJSON transcript browser |
| `/bearclaw/transcripts/:id` | required | Returns a single transcript entry |
| `GET /tardigrade/reload/status` | none (internal) | Hot-reload status endpoint; firewall-restrict it |

### Auth Behavior

Auth is declared on individual `location` blocks rather than inferred from path patterns.

In `tardigrade.conf`:

```nginx
location /api/ {
    proxy_pass /api/;
    auth required;
}

location = /health {
    return 200 ok;
    # no auth directive means auth off
}
```

In `TARDIGRADE_LOCATION_BLOCKS` (env var format, `;`-separated):

```text
prefix|/api/|proxy_pass|http://backend|auth:required;exact|/health|return|200|ok
```

Valid `auth` values:

- `required`
- `off` (default)

Required request headers by auth mode:

| Header | Value | Used for |
|--------|-------|---------|
| `Authorization` | `Bearer <raw-token>` | Static bearer token auth |
| `Authorization` | `Bearer <hs256-jwt>` | JWT auth for BearClawWeb |
| `X-Session-Token` | `<64-lowercase-hex>` | Session auth |
| `X-Device-ID` | device identifier | Device auth with signed request metadata |
| `X-Device-Timestamp` | Unix ms timestamp | Device auth replay prevention |
| `X-Device-Signature` | HMAC-SHA256 signature | Device auth integrity |

### Identity Header Stripping

Inbound `X-Tardigrade-*` headers are stripped before the auth pipeline runs. Clients cannot forge asserted-identity headers by sending them directly.

### Header Forwarding Contract

Tardigrade forwards the following headers to upstreams on proxied requests:

| Header | When set |
|--------|----------|
| `X-Correlation-ID` | Always |
| `X-Forwarded-For` | Always |
| `X-Real-IP` | Always |
| `X-Forwarded-Proto` | Always |
| `X-Forwarded-Host` | Always |
| `X-Tardigrade-Auth-Identity` | When any auth method resolves an identity |
| `X-Tardigrade-User-ID` | JWT auth; `sub` claim |
| `X-Tardigrade-Device-ID` | JWT auth; `device_id` claim |
| `X-Tardigrade-Scopes` | JWT auth; `scope` claim |
| `X-Tardigrade-Api-Version` | When versioned routing is active |

Upstreams must trust these headers only when the request originates from Tardigrade, validated by `TARDIGRADE_TRUST_SHARED_SECRET` or network policy.

### Token Hashing

`TARDIGRADE_AUTH_TOKEN_HASHES` stores lowercase SHA-256 hashes of raw bearer tokens, never the raw tokens themselves.

```bash
# macOS / BSD
printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}'

# Linux
printf '%s' "$TOKEN" | sha256sum | awk '{print $1}'
```

Multiple tokens are provided as a comma-separated list of hashes.

### Session, Device, and Transcript Storage

Session store:

- `TARDIGRADE_SESSION_STORE_PATH`: Tardigrade-managed JSON file
- Shape: `{ "version": 1, "entries": [...] }`
- Each entry stores the session token, identity, client IP, optional device ID, creation timestamp, last activity timestamp, and revoked flag
- `TARDIGRADE_SESSION_TTL_SECONDS`: idle timeout, default `3600`
- `TARDIGRADE_SESSION_MAX`: max concurrent live sessions, default `10000`
- File permissions: service account owned, `chmod 600`

Device registry:

- `TARDIGRADE_DEVICE_REGISTRY_PATH`: line-oriented flat file
- Format: one `device_id|public_key` entry per line
- File permissions: service account owned, `chmod 600`
- Treat it like a credential file because it authorizes device signatures

Transcript store:

- `TARDIGRADE_TRANSCRIPT_STORE_PATH`: append-only NDJSON file
- Each line records `ts_ms`, `scope`, `route`, `correlation_id`, `identity`, `client_ip`, `upstream_url`, request body, response status, response content type, and response body
- Raw bearer tokens and raw JWT values are redacted before write
- File permissions: service account owned, `chmod 600`
- Keep it outside the web root

### Rate Limiting

- Keyed on asserted identity for JWT and bearer auth, with IP fallback for unauthenticated traffic
- `TARDIGRADE_RATE_LIMIT_RPS`: sustained request rate ceiling, default `0` (disabled)
- `TARDIGRADE_RATE_LIMIT_BURST`: burst headroom above the configured ceiling
- Idle limiter buckets are evicted automatically to keep memory bounded
- Recommended production starting point: `TARDIGRADE_RATE_LIMIT_RPS=60`, `TARDIGRADE_RATE_LIMIT_BURST=10`

### Sticky Upstream Affinity

- When multiple upstreams are configured for a relative proxy target, Tardigrade issues a per-host, per-location HMAC-signed sticky cookie
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax`
- Tampered cookies are ignored
- Cookies that point at unhealthy upstreams are remapped to a healthy backend and rotated
- Requires `TARDIGRADE_TRUST_SHARED_SECRET`

The integration fixture in [tests/integration.zig](/Users/joecaruso/Projects/BareSystems/Tardigrade/tests/integration.zig) exercises this path over HTTPS with Tardigrade-owned TLS.

## Suggested Startup

```bash
set -a
source examples/bearclaw/tardigrade.env.example
set +a

zig build
./zig-out/bin/tardigrade
```
