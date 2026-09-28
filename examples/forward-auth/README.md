# External Authentication (`forward_auth`)

Delegates the access decision for selected locations to an external auth
service before Tardigrade proxies or serves the request. This fills the same
role as NGINX `auth_request` and Caddy `forward_auth`, and works with services
such as oauth2-proxy and Authelia.

## What it demonstrates

- `forward_auth` protecting a reverse-proxied location and a static location.
- Propagating the authenticated user to the upstream with
  `forward_auth_upstream_headers`, safe against client spoofing.
- Relaying login redirects, challenges and cookies from the auth service.
- Bounded, fail-closed behavior when the auth service is slow or down.

## Quick start

```bash
zig build
python3 examples/forward-auth/auth.py &            # auth service on :4180
python3 -m http.server 3000 &                      # upstream app on :3000
mkdir -p /tmp/tardigrade-reports && echo "q3 numbers" > /tmp/tardigrade-reports/q3.txt
TARDIGRADE_CONFIG_PATH=examples/forward-auth/tardigrade.conf ./zig-out/bin/tardi &

curl -i http://localhost:8080/admin/                                   # → 401 + WWW-Authenticate
curl -i -H 'Accept: text/html' http://localhost:8080/admin/            # → 302 to the login page
curl -i -H 'Authorization: Bearer letmein' http://localhost:8080/admin/          # → 200 from upstream
curl -i -H 'Authorization: Bearer letmein' http://localhost:8080/reports/q3.txt  # → 200 static file
kill %1; curl -i http://localhost:8080/admin/                          # → 503 auth_unavailable
```

## How a request is decided

1. Rate limiting, access control and `auth required` run first.
2. Tardigrade sends a bounded HTTP/1.1 subrequest to the `forward_auth` URL:
   `GET` with no body by default (`POST` with the body only when
   `forward_auth_body` allows it).
3. **2xx** allows the request. Headers listed in
   `forward_auth_upstream_headers` are copied onto the upstream request after
   every client-supplied copy of those names is removed.
4. **3xx / 4xx** denies it. The auth service's status, body, `Content-Type`,
   `Location` (3xx), `WWW-Authenticate` (401) and any
   `forward_auth_client_headers` are returned to the client with
   `Cache-Control: no-store`.
5. **Anything else** — connect failure, timeout, 1xx/5xx, malformed or
   oversized (>64 KiB) response — fails closed with
   `forward_auth_failure_status` (default 503) and a JSON error
   (`auth_unavailable` or `auth_timeout`).

Denied requests never reach the upstream, a mirror target, or a retry.

## What the auth service receives

Client end-to-end headers (for example `Authorization`, `Cookie`, `Accept`,
`User-Agent`) are forwarded under the same hop-by-hop and trust rules as a
proxied request. Tardigrade then sets:

| Header | Value |
|--------|-------|
| `X-Forwarded-Method`, `X-Original-Method` | Original method. |
| `X-Forwarded-Uri`, `X-Original-URI` | Original path and query. |
| `X-Forwarded-Host` | Original `Host` / `:authority`. |
| `X-Forwarded-Proto` | `http` or `https`. |
| `X-Forwarded-For`, `X-Real-IP` | Client IP after trusted-proxy resolution. |
| `X-Request-ID`, `X-Correlation-ID` | Tardigrade request ID. |
| `traceparent` (+ `tracestate`) | Child span of a valid inbound trace, or a new trace. |

Client-supplied copies of these headers are never passed through.

## Key directives

| Directive | Default | Purpose |
|-----------|---------|---------|
| `forward_auth <url>;` | — | Absolute `http://` or `https://` auth endpoint. HTTPS always verifies the certificate against the URL host. |
| `forward_auth_upstream_headers <name>...;` | none | Auth-response headers copied to the upstream on success. |
| `forward_auth_client_headers <name>...;` | none | Extra auth-response headers relayed to the client on denial. |
| `forward_auth_body <bytes>\|off;` | `off` | Forward request bodies up to this size; larger bodies get 413. |
| `forward_auth_timeout_ms <ms>;` | upstream timeouts, else 5000 | Connect and response deadline for the subrequest. |
| `forward_auth_failure_status <status>;` | `503` | One of 401, 403, 500, 502, 503, 504. |

Header lists cannot name hop-by-hop headers, `Host`, `Content-*`,
`X-Forwarded-*`, `Forwarded`, `X-Real-IP`, request/correlation IDs, trace
context, or `X-Tardigrade-*`; those are owned by Tardigrade.

## Notes

- Only the protected location strips client copies of
  `forward_auth_upstream_headers`. If other, unprotected locations reach the
  same upstream, make sure it does not trust those headers from them.
- Protected locations reject 0-RTT early data (425), because the auth
  subrequest is itself a side effect.
- Outcomes are exported as
  `tardigrade_forward_auth_total{protocol,outcome}` on the metrics endpoint.
