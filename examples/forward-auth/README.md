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
   a bodyless `GET` by default, or a `POST` carrying the body (possibly empty)
   whenever `forward_auth_body` is set.
3. **2xx** allows the request. Headers listed in
   `forward_auth_upstream_headers` are copied onto the upstream request after
   every client-supplied copy of those names is removed. Headers listed in
   `forward_auth_client_headers` (for example a refreshed `Set-Cookie`) are
   added to the response the client receives, whether it is proxied,
   streamed, static or local, including after a rewrite or `try_files`
   fallback. If a rewrite leads to another protected location that denies the
   request, no earlier grant's headers are sent.
4. **A redirect (301, 302, 303, 307, 308 with a `Location`) or any 4xx**
   denies it. The auth service's status, body, `Content-Type`, `Location`,
   `WWW-Authenticate` (401) and any `forward_auth_client_headers` are
   returned to the client.
5. **Anything else** — connect failure, timeout, 1xx/5xx, a `304` or other
   non-redirect 3xx, a redirect without a `Location`, a malformed or
   oversized (>64 KiB) response — fails closed with
   `forward_auth_failure_status` (default 503) and a JSON error
   (`auth_unavailable` or `auth_timeout`).

Every denial and failure carries exactly one `Cache-Control: no-store`, and no
CDN or surrogate cache field, even when `TARDIGRADE_ADD_HEADERS` configures
one globally. Allowed responses
are never shared-cacheable either, whatever the origin says: a shared cache
would otherwise answer the next request without asking the auth service.
When the auth service added headers (such as a refreshed session cookie) the
response is `Cache-Control: no-store`; otherwise every origin `Cache-Control`
field is folded into one `private` policy (`public`, `s-maxage` and
`proxy-revalidate` are dropped), and a `no-store` in any field wins. The
cache-controlling fields that CDNs and reverse proxies honor ahead of
`Cache-Control` (`CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`,
`Surrogate-Control`, `Edge-Control`, `X-Accel-Expires`) are removed, and a
`Cache-Control` from `TARDIGRADE_ADD_HEADERS` cannot override the policy. If
the policy cannot be attached, the response is replaced by an empty 503
rather than sent unprotected. Cache rules configured *in* a CDN that ignore
origin headers remain the operator's responsibility. A `HEAD` request
gets the same status and headers, including `Content-Length`, without a body.
Denied requests never reach the upstream, a mirror target, or a retry.
Auth-response headers the auth service nominates as hop-by-hop through
`Connection` are never copied, even when allowlisted.

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

Client headers in the `X-Forwarded-*` and `X-Original-*` namespaces (for
example `X-Forwarded-User` or `X-Original-URL`), `Forwarded`, and the
location's `forward_auth_upstream_headers` names are never passed through, so
a client cannot hand the auth service a forged proxy assertion. The exception
is `Authorization` and `Cookie`: they are the client's credentials, so the
auth service always receives them, even when `forward_auth_upstream_headers`
names them. In that case only the upstream request gets the auth service's
value, which enables token exchange (verify the client's bearer token, send
the origin a different one). Across a rewrite chain every verifier, including
built-in `auth required`, judges the client's own credentials, never a token
an earlier location's auth service minted for the origin, and never a client
copy of a header an earlier location asserted. Conditional and range headers
(`If-None-Match`, `If-Modified-Since`, `Range`, ...) are not forwarded, so the
auth service is asked for a decision rather than a representation.

## Key directives

| Directive | Default | Purpose |
|-----------|---------|---------|
| `forward_auth <url>;` | — | Absolute `http://` or `https://` auth endpoint. HTTPS always verifies the certificate against the URL host. |
| `forward_auth_upstream_headers <name>...;` | none | Auth-response headers copied to the upstream on success. |
| `forward_auth_client_headers <name>...;` | none | Auth-response headers added to the client response, on allow and on denial. |
| `forward_auth_body <bytes>\|off;` | `off` | Send the request as a `POST` with bodies up to this size; larger bodies get 413. |
| `forward_auth_timeout_ms <ms>;` | upstream timeouts, else 5000 | Connect and response deadline for the subrequest. |
| `forward_auth_failure_status <status>;` | `503` | One of 401, 403, 500, 502, 503, 504. |

Header lists cannot name hop-by-hop headers, `Host`, `Content-*`,
`Cache-Control`, `X-Forwarded-*`, `Forwarded`, `X-Real-IP`,
request/correlation IDs, trace context, or `X-Tardigrade-*`; those are owned
by Tardigrade. `Cache-Control` is excluded so an auth response can never make
an access decision cacheable.

## Notes

- HTTP/2 does not run `rewrite` actions for forward_auth locations yet: such a
  request gets 404 (it fails closed, it is never served unauthorized). Use
  `proxy_pass`, `return` or `root`/`alias` locations if HTTP/2 clients must
  behave the same as HTTP/1.1 and HTTP/3. Tracked in
  [#814](https://github.com/Bare-Systems/Tardigrade/issues/814).
- A `rewrite` that leads into a protected location is authorized against the
  rewritten target before anything is served, and asserted headers from an
  earlier hop stay in place for the origin; a rewrite never reaches
  protected content around `forward_auth`. This includes a rewrite back into
  the same protected location: its `forward_auth` is asked again about the
  rewritten target before the static root answers.
- Only the protected location strips client copies of
  `forward_auth_upstream_headers`. If other, unprotected locations reach the
  same upstream, make sure it does not trust those headers from them.
- Protected locations reject replay-exposed 0-RTT early data with 425 on
  HTTP/1.1, HTTP/2 and HTTP/3, because the auth subrequest is itself a side
  effect. On HTTP/2 this holds even after the handshake completes.
- Server-sent events proxied with `proxy_streaming response` are gated like
  any other response, and allowed streams carry `forward_auth_client_headers`
  on their streamed head. Tardigrade does not relay WebSocket upgrades, so
  there is no WebSocket path to protect.
- Outcomes are exported as
  `tardigrade_forward_auth_total{protocol,outcome}` on the metrics endpoint.
