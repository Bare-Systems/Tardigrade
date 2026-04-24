# Tardigrade Agent Guide

Scope: the `Tardigrade` repository.

## Purpose

Tardigrade is the BareSystems edge gateway and reverse proxy.

## Workflow

- Keep active unfinished work in the workspace root `ROADMAP.md`.
- Keep operator-facing behavior documented in `README.md`.
- Keep deployment reality documented in `BLINK.md`.
- Record notable repo changes in `CHANGELOG.md`.

## BearClaw Edge Contract

Use `examples/bearclaw/tardigrade.conf` plus `examples/bearclaw/tardigrade.env.example`
as the canonical BearClaw-facing edge shape.

### Ports

| Port | Protocol | Role |
|------|----------|------|
| 443  | HTTPS (TLS + HTTP/2) | Public edge — all external traffic enters here |
| 8080 | HTTP (loopback only) | BearClaw upstream — never exposed externally |

### Base paths

| Path | Auth | Behavior |
|------|------|----------|
| `GET /health` | none | Returns `200 ok` directly from the edge (no upstream hop). |
| `POST /v1/chat` | required | Proxies to upstream `/v1/chat`. |
| `POST /v1/commands` | required | Proxies to upstream `/v1/commands`. |
| `GET /bearclaw/health` | none | Strips `/bearclaw` and proxies to upstream `/health`. |
| `/bearclaw/v1/*` | required | Strips `/bearclaw` prefix and proxies to upstream `/v1/*`. |
| `/bearclaw/transcripts` | required | Exposes the redacted NDJSON transcript browser. |
| `/bearclaw/transcripts/:id` | required | Single-entry transcript detail. |
| `GET /tardigrade/reload/status` | none (internal) | Hot-reload status endpoint — should be firewall-restricted. |

### Per-location auth directives

Auth is declared on individual location blocks, not inferred from path patterns.

In `tardigrade.conf`:
```nginx
location /api/ {
    proxy_pass /api/;
    auth required;   # bearer/JWT/session enforced for this location
}

location = /health {
    return 200 ok;
    # no auth directive → defaults to auth off (public)
}
```

In `TARDIGRADE_LOCATION_BLOCKS` (env var format, `;`-separated):
```
prefix|/api/|proxy_pass|http://backend|auth:required;exact|/health|return|200|ok
```

Valid `auth` values: `required`, `off` (default).

### Required auth headers

| Header | Value | Used for |
|--------|-------|---------|
| `Authorization` | `Bearer <raw-token>` | Static bearer token auth |
| `Authorization` | `Bearer <hs256-jwt>` | JWT auth (BearClawWeb) |
| `X-Session-Token` | `<64-lowercase-hex>` | Session auth |
| `X-Device-ID` | device identifier | Device auth (combined with below) |
| `X-Device-Timestamp` | Unix ms timestamp | Device auth replay prevention |
| `X-Device-Signature` | HMAC-SHA256 signature | Device auth integrity |

### Identity header stripping

**Inbound `X-Tardigrade-*` headers are stripped unconditionally** before the auth pipeline runs. Clients cannot forge asserted-identity headers regardless of what they send.

### Header forwarding contract to upstreams

Tardigrade forwards the following headers to every upstream on proxied requests:

| Header | When set |
|--------|----------|
| `X-Correlation-ID` | Always |
| `X-Forwarded-For` | Always |
| `X-Real-IP` | Always |
| `X-Forwarded-Proto` | Always |
| `X-Forwarded-Host` | Always |
| `X-Tardigrade-Auth-Identity` | When any auth method resolves an identity |
| `X-Tardigrade-User-ID` | JWT auth — `sub` claim |
| `X-Tardigrade-Device-ID` | JWT auth — `device_id` claim |
| `X-Tardigrade-Scopes` | JWT auth — `scope` claim |
| `X-Tardigrade-Api-Version` | When versioned routing is active |

Upstreams must trust these headers only when the request originates from Tardigrade
(validated via `TARDIGRADE_TRUST_SHARED_SECRET` or network policy).

### Token hashing procedure

`TARDIGRADE_AUTH_TOKEN_HASHES` stores lowercase SHA-256 hashes of raw bearer tokens,
never the raw tokens themselves.

```bash
# macOS / BSD
printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}'

# Linux
printf '%s' "$TOKEN" | sha256sum | awk '{print $1}'
```

Multiple tokens: comma-separated list of hashes.

### Session TTL and store

- `TARDIGRADE_SESSION_STORE_PATH`: Tardigrade-managed JSON file.
- Shape: `{ "version": 1, "entries": [...] }` — each entry holds the session
  token, identity, client IP, optional device ID, creation timestamp, last
  activity timestamp, and revoked flag.
- `TARDIGRADE_SESSION_TTL_SECONDS`: idle timeout (default: `3600`).
- `TARDIGRADE_SESSION_MAX`: max concurrent live sessions; oldest are evicted
  when the limit is reached (default: `10000`).
- File permissions: owned by the Tardigrade service account, `chmod 600`.

### Device registry format and permissions

- `TARDIGRADE_DEVICE_REGISTRY_PATH`: line-oriented flat file (not JSON).
- Format: one `device_id|public_key` entry per line.
- File permissions: owned by the Tardigrade service account, `chmod 600`.
- Treat it like a credential file — it authorises device signatures.

### Transcript file

- `TARDIGRADE_TRANSCRIPT_STORE_PATH`: append-only NDJSON file.
- Each line records: `ts_ms`, `scope`, `route`, `correlation_id`, `identity`,
  `client_ip`, `upstream_url`, request body, response status, response content
  type, and response body.
- Raw bearer tokens and raw JWT values are redacted before write.
- File permissions: owned by the Tardigrade service account, `chmod 600`.
- Keep outside the web root.

### Rate limiting

- Keyed on asserted identity (JWT/bearer) with IP fallback for unauthenticated traffic.
- `TARDIGRADE_RATE_LIMIT_RPS`: sustained request rate ceiling (default: `0` = disabled).
- `TARDIGRADE_RATE_LIMIT_BURST`: burst headroom above the RPS ceiling.
- Idle limiter buckets are evicted automatically to keep memory bounded.
- Recommended production starting point: `TARDIGRADE_RATE_LIMIT_RPS=60`, `TARDIGRADE_RATE_LIMIT_BURST=10`.

### Sticky upstream affinity

- When multiple upstreams are configured for a relative proxy target, Tardigrade
  issues a per-host, per-location HMAC-signed sticky cookie.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax`.
- Tampered cookies are ignored. Cookies pointing at unhealthy upstreams are
  remapped to a healthy backend and rotated.
- Requires `TARDIGRADE_TRUST_SHARED_SECRET` to be set.

## Validation

```bash
zig build test
zig build test-integration
```
