# Configuration Reference

This reference documents the public Tardigrade configuration surface loaded by
`EdgeConfig` and the nginx-style config-file adapter.

Runtime config-file selection, highest priority first:

1. `-c/--config` on commands that accept it.
2. `TARDIGRADE_CONFIG_PATH`.
3. `./tardigrade.conf`.
4. `./config/tardigrade.conf`.
5. `/etc/tardigrade/tardigrade.conf`.
6. `$HOME/.config/tardigrade/tardigrade.conf`.

`check [<config>]` and `config validate [<config>]` are validation commands.
When no path is supplied, `check` validates `./tardigrade.conf` directly
rather than using the full runtime search path above. `run` discovers that
same local file when no higher-precedence `TARDIGRADE_CONFIG_PATH` override
is set.

Effective value precedence, highest priority first:

1. Process environment.
2. Selected config-file overrides.
3. Decrypted secret-file overrides.
4. Built-in defaults.

Validate before startup:

```bash
./zig-out/bin/tardi check ./tardigrade.conf
./zig-out/bin/tardi config validate ./tardigrade.conf
```

For copy/paste-runnable configs, see [examples/](../examples/README.md):
[static files](../examples/static-file-server/README.md),
[reverse proxy](../examples/reverse-proxy/README.md),
[TLS termination](../examples/tls-termination/README.md),
[virtual hosts](../examples/virtual-hosts/README.md),
[health checks](../examples/health-checks/README.md),
[rate limiting](../examples/rate-limiting/README.md),
[access logs](../examples/access-logs/README.md),
[Prometheus metrics](../examples/prometheus-metrics/README.md),
[graceful reload](../examples/graceful-reload/README.md), and
[production baseline](../examples/production-baseline/README.md).

## Generating a Starter Config

`tardi init <profile>` writes a ready-to-check config for a common
deployment shape to stdout only, so `tardi init proxy > tardigrade.conf`
produces a clean file with no extra output mixed in:

```bash
tardi init static > tardigrade.conf     # static files + SPA fallback + health
tardi init proxy > tardigrade.conf      # reverse proxy to an upstream app
tardi init tls > tardigrade.conf        # TLS termination + proxy
tardi init metrics > tardigrade.conf    # proxy starter documenting /status/metrics
tardi init prod > tardigrade.conf       # production-oriented TLS/proxy scaffold
```

Each profile also has a longer descriptive alias that resolves to the same
template, e.g. `tardi init reverse-proxy` is identical to `tardi init proxy`.
Run `tardi init --help` for the full profile/alias list. The `tls` and `prod`
profiles reference certificate/key paths you must provision yourself — see
[examples/tls-termination](../examples/tls-termination/README.md) and
[examples/production-baseline](../examples/production-baseline/README.md)
for how to generate a local test certificate. The `metrics` profile
documents the existing `/status/metrics` endpoint; protect it in production
with `TARDIGRADE_METRICS_REQUIRE_AUTH=true` or a network-boundary
restriction.

`tardi config init [<path>] [--force | --stdout] [--profile <profile>]` is
the verbose, file-writing form of the same generator: it supports the same
profiles via `--profile`, writes to a file (creating parent directories and
refusing to overwrite an existing file unless `--force` is given), and keeps
a generic starter output when no `--profile` is given.

## CLI Command Reference

```bash
tardi check ./tardigrade.conf
tardi config validate ./tardigrade.conf
tardi validate -c ./tardigrade.conf
tardi print-config -c ./tardigrade.conf
tardi status -c ./tardigrade.conf
tardi reload -c ./tardigrade.conf
tardi stop -c ./tardigrade.conf
tardi init <profile>
tardi config init
tardi explain <field>
tardi config explain <field>
```

Not sure what a directive does or which values it accepts? `tardi explain
<field>` looks it up from a built-in reference -- no config file required:

```bash
tardi explain listen
tardi explain location.proxy_pass
tardi explain upstream_protocol
```

`tardi config explain <field>` is a verbose alias for the same command.
`explain` is a static documentation lookup: it describes the *supported*
configuration contract (type, default, valid values, environment variable,
example) and never loads a config file, inspects a running process, or
prints current environment/secret values -- that's what `print-config`
(effective configuration) is for.

## Config File Syntax

Config files are nginx-inspired. Directives end in `;`; `server {}` and
`location {}` blocks are supported; `#` starts a comment. `include` accepts a
path or a single `*` glob suffix, and relative includes resolve from the current
file. `set $name value;` defines variables referenced as `${name}`. Environment
variables can also be interpolated with `${NAME}`.

Unknown top-level directives are normalized to environment keys by uppercasing,
replacing `-` with `_`, and prefixing `TARDIGRADE_`. For example,
`upstream_timeout_ms 5000;` maps to `TARDIGRADE_UPSTREAM_TIMEOUT_MS=5000`.

## Core Directives

| Directive | Env key | Type | Default | Notes | Example |
| --- | --- | --- | --- | --- | --- |
| `include` | n/a | path/glob | n/a | Parses another config file. A single `*` suffix is supported. | `include conf.d/*.conf;` |
| `set` | n/a | variable | n/a | Defines a config variable without the leading `$`. | `set $root /srv/www;` |
| `listen` | `TARDIGRADE_LISTEN_HOST`, `TARDIGRADE_LISTEN_PORT`, `TARDIGRADE_HTTP2_ENABLED` | host/port | `0.0.0.0:8069` | Accepts `host:port`, `port`, or `host`; `http2` flag enables HTTP/2. Ports must be 1-65535. | `listen 0.0.0.0:8443 http2;` |
| `worker_processes` | `TARDIGRADE_WORKER_PROCESSES` | u32 | `1` | `auto` maps to `0`; used with master-process mode. | `worker_processes auto;` |
| `worker_connections` | `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | u32 | `0` | `0` means unlimited active client connections. | `worker_connections 4096;` |
| `master_process` | `TARDIGRADE_MASTER_PROCESS` | bool | `false` | Enables master-process supervision mode; required for `worker_processes` to take effect. Current limitation: master/worker mode does not provide coherent PID-file/SIGHUP reload control across all workers; use single-process mode when relying on `tardi reload` and the configured PID file. `TARDIGRADE_BINARY_UPGRADE` is effective through the master loop. | `master_process true;` |
| `pid` | `TARDIGRADE_PID_FILE` | path | `""` | Empty disables pid-file writing. | `pid /run/tardigrade.pid;` |
| `user` | `TARDIGRADE_RUN_USER`, `TARDIGRADE_RUN_GROUP` | names | `""` | First token is user; optional second token is group. | `user tardigrade tardigrade;` |
| `error_log` | `TARDIGRADE_ERROR_LOG_PATH`, `TARDIGRADE_LOG_LEVEL` | path + enum | `""`, `info` | Levels: `debug`, `info`, `warn`, `error`. | `error_log /var/log/tardigrade/error.log warn;` |

## Secrets Bootstrap

Secrets are bootstrapped from the process environment before config-file
overrides are parsed. Do not use `secrets_file` or `secret_key` directives in
config files for secret bootstrap; although the parser recognizes them, they are
parsed too late to activate the secret store. Use environment variables instead.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_SECRETS_PATH` | path | unset | File containing `KEY=value` lines. Plain values are used directly; `ENC2:` values are AES-256-GCM encrypted; legacy `ENC:` values are also supported. | `TARDIGRADE_SECRETS_PATH=/etc/tardigrade/secrets.env` |
| `TARDIGRADE_SECRET_KEYS` | CSV hex keys | `""` | Comma-separated hex decryption key material. `ENC2:` uses 32-byte AES-256-GCM keys, represented as 64 hex characters. Empty disables secret-file override loading. | `TARDIGRADE_SECRET_KEYS=0000000000000000000000000000000000000000000000000000000000000000` |

## Server Blocks

When no `server {}` blocks exist, top-level `server_name`, `root`, `try_files`,
and locations define the only virtual host. Once any `server {}` block exists,
host selection is based on server blocks only: the first matching named block
wins, then an unnamed/default block, then the first block as fallback. A selected
named fallback that does not match the request Host is rejected. Server blocks
start from the top-level config and overlay non-empty per-block values. See the
[virtual-hosts example](../examples/virtual-hosts/README.md).

| Directive | Type | Default | Notes | Example |
| --- | --- | --- | --- | --- |
| `server_name` | list | `[]` | Hostnames for this block. A block with no names is the default block. | `server_name api.example.com;` |
| `root` | path | `""` | Per-server static root. | `root /srv/site;` |
| `try_files` | string/list | `""` | Per-server static fallback. | `try_files $uri /index.html;` |
| `tls_cert_path` | path | `""` | Per-server TLS cert. With `tls_key_path`, also adds SNI certs for block names. Appliance profile rejects server-block TLS material. | `tls_cert_path /etc/tls/api.crt;` |
| `tls_key_path` | path | `""` | Per-server TLS key. Must be paired with cert path. Appliance profile rejects server-block TLS material. | `tls_key_path /etc/tls/api.key;` |
| `upstream_base_url` | URL | `""` | Per-server default reverse-proxy upstream. | `upstream_base_url http://127.0.0.1:8081;` |
| `proxy_pass_chat` | URL | `""` | BearClaw/chat route upstream. | `proxy_pass_chat http://127.0.0.1:9001;` |
| `proxy_pass_commands_prefix` | URL/path | `""` | BearClaw commands prefix upstream. | `proxy_pass_commands_prefix http://127.0.0.1:9002;` |
| `proxy_set_header` | name value | `[]` | Default upstream request-header rules for this block's `proxy_pass` locations. See [Upstream request headers](#upstream-request-headers-proxy_set_header). | `proxy_set_header X-Forwarded-Proto https;` |
| nested `location` | block | `[]` | Locations scoped to this server block. The parser requires the block opener on a line ending with `{` and a closing line containing only `}`. | See matcher examples below. |

## Location Blocks

Location matching follows nginx-style precedence: exact matches, then `^~`
priority prefixes, then regexes in declaration order, then the longest plain
prefix. Each location must choose one action family: proxy, FastCGI/SCGI/uWSGI,
return, rewrite, or static.

| Directive | Type | Default | Notes | Example |
| --- | --- | --- | --- | --- |
| `location = /path` | matcher | n/a | Exact match. | See exact example below. |
| `location ^~ /path/` | matcher | n/a | Prefix priority. | See priority-prefix example below. |
| `location ~ pattern` | matcher | n/a | Case-sensitive regex. | See regex example below. |
| `location ~* pattern` | matcher | n/a | Case-insensitive regex. | See case-insensitive regex example below. |
| `location /path/` | matcher | n/a | Plain prefix. | See plain-prefix example below. |
| `proxy_pass` | URL/path | n/a | Proxies matching requests. | `proxy_pass http://127.0.0.1:8080;` |
| `fastcgi_pass` | endpoint | n/a | FastCGI upstream. | `fastcgi_pass unix:/run/php.sock;` |
| `scgi_pass` | endpoint | n/a | SCGI upstream. | `scgi_pass 127.0.0.1:4100;` |
| `uwsgi_pass` | endpoint | n/a | uWSGI upstream. | `uwsgi_pass 127.0.0.1:4200;` |
| `root` | path | n/a | Serves files under root. | `root /srv/site;` |
| `alias` | path | n/a | Serves files from alias path. | `alias /srv/assets;` |
| `index` | filename | `index.html` | Directory index fallback. Set `""` to opt out. | `index index.html;` |
| `autoindex` | bool | `off` | `on`, `off`, `true`, `false`. | `autoindex off;` |
| `try_files` | string/list | `""` | Location-level candidate list. | `try_files $uri /index.html;` |
| `return` | status/body | n/a | Status u16 and optional response body. | `return 200 ok;` |
| `rewrite` | pattern/replacement/flag | n/a | Default flag is `last`; accepted flags are `last`, `break`, `redirect`, `permanent`. The rewritten target is matched against the locations again (HTTP/1.1 and HTTP/3), and that location's `auth`, `forward_auth` and path policy are enforced before it runs. A rewrite back into the same location is served from the server `root`. A `?query` in the replacement replaces the request's query. More than 4 locations in one rewrite chain fails with 508. | `rewrite ^/old/(.*)$ /new/$1 last;` |
| `error_page` | statuses/target | `[]` | Status codes followed by path or HTTP(S) URL target. | `error_page 502 503 /50x.html;` |
| `auth` | enum | `off` | `off`, `required`. | `auth required;` |
| `proxy_streaming` / `proxy_streaming_mode` | enum | `inherit` | `inherit`, `off`/`buffered`, `response`/`responses`, `full`/`request_response`/`request-response`. | `proxy_streaming response;` |
| `early_data` | enum | `off` | `off`, `replay_safe`/`replay-safe`. | `early_data replay_safe;` |
| `proxy_early_data` | enum | `off` | `off`, `rfc8470`/`rfc-8470`; valid only with `proxy_pass`. | `proxy_early_data rfc8470;` |
| `proxy_set_header` | name value | `[]` | Set, overwrite or clear an upstream request header; valid only with `proxy_pass`. Repeatable, one per header name. See [Upstream request headers](#upstream-request-headers-proxy_set_header). | `proxy_set_header Host auth.example.com;` |
| `forward_auth` | URL | n/a | External auth subrequest before the action runs (NGINX `auth_request` / Caddy `forward_auth` role). 2xx allows; a 4xx, or a 301/302/303/307/308 with a `Location`, is relayed to the client; anything else (including 304) fails closed. Responses to allowed requests are never shared-cacheable: `no-store` when the auth service added client headers, otherwise all origin `Cache-Control` fields folded into one `private` policy (`no-store` in any field wins); `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`, `Surrogate-Control`, `Edge-Control` and `X-Accel-Expires` are removed, and `TARDIGRADE_ADD_HEADERS` cannot override it, on allowed responses or on refusals. Over HTTP/2, a `rewrite` action in a forward_auth location is not supported yet and answers 404 ([#814](https://github.com/Bare-Systems/Tardigrade/issues/814)); HTTP/1.1 and HTTP/3 re-authorize every rewrite hop. Absolute `http://`/`https://` without userinfo or fragment; HTTPS always verifies against the URL host. Protected locations reject replay-exposed early data. See [examples/forward-auth](../examples/forward-auth/README.md). | `forward_auth http://127.0.0.1:4180/oauth2/auth;` |
| `forward_auth_upstream_headers` | header names | none | Auth-response headers copied to the upstream on 2xx. Client copies are always removed from the upstream request first, and from the auth subrequest too, except `Authorization` and `Cookie`, which the auth service always receives so it can verify them (token exchange). Cannot name hop-by-hop, `Host`, `Content-*`, `Cache-Control`, `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, request/correlation ID, trace-context, or `X-Tardigrade-*` headers. | `forward_auth_upstream_headers X-Auth-Request-User X-Auth-Request-Email;` |
| `forward_auth_client_headers` | header names | none | Auth-response headers added to the client response: on allow, to whatever the location returns (proxied, streamed, static or local); on denial, in addition to `Location` (3xx) and `WWW-Authenticate` (401). Repeated fields such as `Set-Cookie` are kept. Same name restrictions. | `forward_auth_client_headers Set-Cookie;` |
| `forward_auth_body` | bytes / `off` | `off` | Send the subrequest as a `POST` carrying bodies up to this size (an empty body is sent with `Content-Length: 0`); larger bodies get 413. `off` sends a bodyless `GET`. A non-zero limit disables upload streaming for the location. | `forward_auth_body 8192;` |
| `forward_auth_timeout_ms` | ms | upstream response timeout, else `5000` | Connect and response deadline for the subrequest. Responses are capped at 64 KiB. | `forward_auth_timeout_ms 500;` |
| `forward_auth_failure_status` | status | `503` | Status for timeouts, connect failures, 1xx/5xx and malformed responses: 401, 403, 500, 502, 503 or 504. | `forward_auth_failure_status 502;` |
| `proxy_websocket` | enum | `off` | `on` relays HTTP/1.1 WebSocket upgrades through this location's `proxy_pass`; valid only with `proxy_pass`. Off keeps stripping `Upgrade` and refusing an upstream `101`. See [WebSocket proxying](#websocket-proxying-proxy_websocket). | `proxy_websocket on;` |
| `proxy_websocket_idle_timeout_ms` | ms | `60000` | Close a tunnel after this long with no bytes moving in either direction. Requires `proxy_websocket on`. | `proxy_websocket_idle_timeout_ms 300000;` |
| `proxy_websocket_max_lifetime_ms` | ms | `0` (unlimited) | Close a tunnel this long after it opened. Requires `proxy_websocket on`. | `proxy_websocket_max_lifetime_ms 3600000;` |
| `proxy_websocket_reload` | enum | top-level value, else `preserve` | What a successful hot reload does to open tunnels: `preserve` keeps them under their admission configuration, `drain` closes them `proxy_websocket_reload_timeout_ms` after the reload. Also valid at top level. Requires `proxy_websocket on`. See [WebSocket proxying](#websocket-proxying-proxy_websocket). | `proxy_websocket_reload drain;` |
| `proxy_websocket_reload_timeout_ms` | ms | top-level value, else `30000` | Drain window for `drain` tunnels, from the reload that superseded their configuration. Also valid at top level. Requires `proxy_websocket on`. | `proxy_websocket_reload_timeout_ms 10000;` |
| `proxy_websocket_origins` | origins | any | Browser origins (`scheme://host[:port]`) allowed to open a WebSocket; others get 403 before the upstream is contacted. Handshakes without `Origin` are allowed. Requires `proxy_websocket on`. | `proxy_websocket_origins https://app.example.com;` |
| `proxy_response_stream_reload` | enum | top-level value, else `preserve` | Per-location reload policy for admitted long-lived streamed HTTP responses: `preserve` or `drain`. Valid only with `proxy_pass`; the process-wide active-stream cap is not overridable per location. | `proxy_response_stream_reload drain;` |
| `proxy_response_stream_reload_timeout_ms` | u32 ms | top-level value, else `30000` | Per-location drain window for `drain` response streams, measured from the first successful reload that supersedes their admission generation. Valid only with `proxy_pass`; `0` means drain immediately on reload. | `proxy_response_stream_reload_timeout_ms 10000;` |

Parser-valid matcher examples:

```nginx
location = /health {
    return 200 ok;
}

location ^~ /assets/ {
    root /srv/www;
}

location ~ \.php$ {
    fastcgi_pass unix:/run/php.sock;
}

location ~* \.(png|jpg)$ {
    root /srv/www;
}

location /api/ {
    proxy_pass http://127.0.0.1:8080;
}
```

## Upstream Request Headers (`proxy_set_header`)

`proxy_set_header NAME VALUE;` rewrites a request header on its way to a
`proxy_pass` upstream, with nginx syntax so existing configs port directly. It
applies to HTTP/1.1 and HTTP/2 upstreams, on the buffered and streaming proxy
paths, for HTTP/1.1, HTTP/2 and HTTP/3 clients.

```nginx
location /realms/ekho/ {
    proxy_pass http://keycloak:8080/realms/ekho/;
    proxy_set_header Host auth.example.com;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host auth.example.com;
    proxy_set_header X-Forwarded-Port 443;
    proxy_set_header X-Forwarded-For "";
}
```

- **Overwrite, not append.** Every instance of the header is removed first,
  whatever its case and however many times the client sent it, and so is the
  value Tardigrade itself would have added (`X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`, `X-Request-ID`, ...).
  Then the configured value is added once.
- **An empty value removes the header** (`proxy_set_header X-Forwarded-For "";`).
  So does a value whose variables all expand to nothing.
- **`Host`** sets the HTTP/1.1 `Host` line and the HTTP/2 `:authority`. The
  connection still goes to the `proxy_pass` address. `Host` is the one header
  that cannot be removed, because HTTP/1.1 requires `Host` and HTTP/2 requires
  `:authority`: `proxy_set_header Host "";` is rejected at config load, and a
  `Host` value whose variables expand to nothing (for example `$host` on a
  request without one) falls back to the `proxy_pass` host and port.
- **Variables:**

  | Variable | Value |
  | --- | --- |
  | `$host` | Client `Host` (or `:authority`), port removed, lowercased; empty if absent. |
  | `$http_host` | Client `Host` exactly as sent. |
  | `$remote_addr` | The client IP Tardigrade resolved (the `X-Real-IP` value), after `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` / `TARDIGRADE_REAL_IP_HEADER` are applied. Never a raw client `X-Forwarded-For` entry. See the note below for HTTP/2 and HTTP/3 clients. |
  | `$scheme` | `https` when Tardigrade terminates TLS, else `http`. |
  | `$proxy_add_x_forwarded_for` | The `X-Forwarded-For` value Tardigrade would send: `$remote_addr` appended to the inbound chain. |
  | `$request_id` | The request's correlation ID. |

  For HTTP/2 and HTTP/3 clients, the client IP is read from
  `TARDIGRADE_REAL_IP_HEADER` / `X-Forwarded-For` / `X-Real-IP` only when the
  connecting peer matches an explicitly configured
  `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` entry. Otherwise it is the
  transport peer, so a direct client cannot choose its own address. HTTP/1.1
  also trusts every peer when no identities are configured (the open-trust
  default described in [PROXY_SECURITY.md](PROXY_SECURITY.md#trusted-upstream-identity)).

  `${NAME}` is still config-load interpolation (from `set` or the environment),
  as for every other directive. An unknown `$name` fails config load.
- **Inheritance:** `proxy_set_header` in a `server {}` block applies to that
  block's `proxy_pass` locations. A location with *any* `proxy_set_header` of
  its own uses only its own list and does not merge with the server's (nginx's
  rule). A top-level `proxy_set_header` is rejected; put it in a `server` or
  `location` block.
- **Rejected at config load (`tardi check`):** header names that are not
  valid tokens; values containing CR, LF, NUL or other control characters; the
  same name twice in one block; an empty `Host`; `Content-Length` and `Transfer-Encoding`
  (request framing); `Early-Data`; `X-Tardigrade-*` (asserted identity); and
  any non-empty value for a hop-by-hop header (`Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`,
  `Trailer`, `Upgrade`). Tardigrade always strips hop-by-hop headers itself,
  so clearing one (`proxy_set_header Connection "";`) is accepted and does
  nothing.

### Upstream response header size

HTTP/1.1 upstream response heads (status line plus headers) of at least
32 KiB relay without tuning (verified end to end for HTTP/1.1 clients), so a large `Location` plus several session
`Set-Cookie` headers from an identity provider passes through. There is no
equivalent of nginx's `proxy_buffer_size` to raise.

- Buffered proxying (the default): the head counts toward
  `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` and has no separate limit.
- Streaming proxying (`TARDIGRADE_PROXY_STREAMING_MODE`): a head larger than
  `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` spills into a fixed 64 KiB side buffer.
  That buffer is charged in full to the stream's proxy-buffer limits
  (`TARDIGRADE_PROXY_BUFFER_*`) before it is allocated, and released once the
  head is parsed. Heads over 64 KiB fail with 502; a spill the proxy-buffer
  limits cannot admit fails with 503.

Large response heads from HTTP/2 upstreams have not been verified end to end.

## WebSocket Proxying (`proxy_websocket`)

`proxy_websocket on;` lets a `proxy_pass` location relay WebSocket
connections (RFC 6455) to its origin, the way NGINX does with
`proxy_http_version 1.1` plus `Upgrade`/`Connection` headers. It is off by
default, and without it Tardigrade keeps stripping `Upgrade` and refuses an
upstream `101`, so a client cannot switch protocols on a location that did not
opt in.

```nginx
location /ws/ {
    proxy_pass http://127.0.0.1:9000;
    proxy_websocket on;
    proxy_websocket_idle_timeout_ms 120000;
    proxy_websocket_origins https://app.example.com;
}
```

How a handshake is handled:

1. **Every ordinary gate runs first.** Rate limits, ACL/geo, `auth required`,
   `forward_auth`, path policy and the 0-RTT checks apply exactly as for any
   request. A denied handshake gets the normal denial response and no
   upstream connection is opened. A replay-exposed (0-RTT) handshake gets
   425.
2. **The handshake is validated strictly.** It must be a `GET` over HTTP/1.1
   with `Connection: upgrade`, `Upgrade: websocket`, exactly one
   `Sec-WebSocket-Key` that decodes to 16 bytes, and no body or body framing
   (`Content-Length` other than 0, or any `Transfer-Encoding`). Anything else
   gets 400; a `Sec-WebSocket-Version` other than 13 gets 426 with
   `Sec-WebSocket-Version: 13`. When `proxy_websocket_origins` is set, a
   browser `Origin` that is not listed gets 403 (cross-site WebSocket
   hijacking protection).
3. **A tunnel slot is reserved** before the origin is contacted (see the cap
   below). Over the cap, the client gets 503.
4. **A fresh HTTP/1.1 connection** is opened to the origin (`ws://` as
   `http://`, `wss://` as `https://` under the usual upstream TLS
   verification rules; TLS origins are offered only `http/1.1`). Upgrade
   connections never come from or return to the keep-alive pool, are never
   retried or replayed, and are never mirrored. The origin gets the same
   forwarding, request-ID, trace, identity and `proxy_set_header` headers as
   any proxied request, with `Upgrade: websocket` and `Connection: Upgrade`
   set by Tardigrade. `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions`
   pass through unchanged, in both directions.
5. **The origin's answer decides.** A `101` must carry `Upgrade: websocket`,
   `Connection: upgrade` and a `Sec-WebSocket-Accept` matching the client's
   key, or the client gets 502 and never sees it. A valid `101` is relayed
   (with the origin's other end-to-end headers, the request ID, and any
   `forward_auth_client_headers`), and both hops then carry raw bytes until
   either side closes. Any other status is relayed as an ordinary response,
   and the client connection is closed afterwards.

**Tunnels.** Tardigrade does not parse frames: ping/pong, fragmentation,
close handshakes, subprotocols and extensions are between the client and the
origin. Each direction has one fixed buffer
(`TARDIGRADE_PROXY_STREAM_BUFFER_SIZE`, at least 16 KiB), charged to the
proxy-buffer limits before the origin is contacted. A slow reader on one side
stops Tardigrade reading the other side, so TCP flow control pushes back on
the sender instead of memory growing. A tunnel ends when either side closes
(the other side's bytes already read are flushed first), after
`proxy_websocket_idle_timeout_ms` with no traffic, after
`proxy_websocket_max_lifetime_ms`, on an I/O error, or at shutdown. Idle and
lifetime limits close the TCP connections without a WebSocket close frame
(clients see close code 1006), so applications that stay quiet longer than
the idle timeout should send pings.

**Capacity.** A worker runs the handshake and every admission check, then
hands the established tunnel to a WebSocket reactor thread and goes back to
serving requests (#818). A small fixed pool of reactor threads
(`proxy_websocket_reactor_threads` /
`TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS`, default one per four CPUs,
between 1 and 4; read at startup only, and reload rejects changes) relays every open tunnel, each thread
sleeping in one `poll()` over the sockets it owns, so thousands of mostly idle
WebSockets cost sockets and buffers, not threads, and do not slow ordinary
requests. An open tunnel still counts as an active connection
(`max_active_connections`) but no longer as an in-flight request.
`proxy_websocket_max_tunnels` / `TARDIGRADE_PROXY_WEBSOCKET_MAX_TUNNELS`
caps concurrent tunnels per process; the default (`0`) is a quarter of the
file-descriptor soft limit, at most 4096, since each tunnel holds two sockets.
Raise the descriptor limit (`TARDIGRADE_FD_SOFT_LIMIT`) together with the cap for very
large tunnel counts.

**Hot reload.** A tunnel is admitted under the configuration generation its
handshake leased, and everything about it comes from that snapshot: its
location's settings and its reload behavior. `proxy_websocket_reload` decides
what a successful reload does to tunnels that are already open:

- `preserve` (default): the tunnel keeps relaying under its admission
  configuration until a peer closes it, a timeout ends it, or the process
  shuts down. **This holds even if the reload changed or removed its
  location**, restricted its `auth`/`forward_auth`/ACL/Origin rules, or
  pointed it at another origin: an established connection is not
  re-authorized. Use `drain` where a reload must also revoke open sessions.
- `drain`: the tunnel keeps relaying for `proxy_websocket_reload_timeout_ms`
  (default 30000) after the first successful reload that supersedes its
  admission configuration, then both hops are closed
  (`tunnel_close_reason` `reload`). The deadline starts at that reload and is
  never extended: later reloads, including ones that change the timeout,
  do not move it. `0` closes the tunnel at the reload.

Set `proxy_websocket_reload` and `proxy_websocket_reload_timeout_ms` at top
level for a default and in a location to override either one. Both are read
from the admission configuration, so a reload that changes them affects only
tunnels opened after it. A reload that fails or is rejected publishes
nothing and never affects open tunnels; malformed or explicitly empty values
for either setting, or for `proxy_websocket_max_tunnels` (for example
`proxy_websocket_reload_timeout_ms 250ms;`, `""`, a variable that expands to
nothing, or an empty environment variable) fail `tardi check` and reject the
reload instead of falling back to a default. Only an unset value takes the
default. New handshakes use the new
configuration as soon as the reload is applied.

```nginx
proxy_websocket_reload drain;
proxy_websocket_reload_timeout_ms 30000;

location /ws/ {
    proxy_pass http://127.0.0.1:9000;
    proxy_websocket on;
}

location /live-feed/ {
    proxy_pass http://127.0.0.1:9001;
    proxy_websocket on;
    proxy_websocket_reload preserve;
}
```

**Shutdown.** Graceful shutdown overrides `preserve`: every open tunnel keeps
relaying for `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` and is then closed, so
tunnels never hold the process open. A `drain` tunnel that is already inside
a reload drain closes at whichever deadline comes first.

**Protocols.** WebSocket relaying is HTTP/1.1 only, over plaintext or
Tardigrade's native TLS (`wss://`). HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220)
extended CONNECT are not supported: Tardigrade never advertises
`SETTINGS_ENABLE_CONNECT_PROTOCOL`, so browsers open WebSockets over a
separate HTTP/1.1 connection even when the page itself uses HTTP/2 or HTTP/3.
An HTTP/2 or HTTP/3 request carrying `Upgrade` is not upgraded.

**Observability.** `tardigrade_websocket_upgrades_total{outcome}`,
`tardigrade_websocket_tunnels_active`,
`tardigrade_websocket_tunnel_bytes_total{direction}`,
`tardigrade_websocket_tunnel_duration_seconds`,
`tardigrade_websocket_tunnel_closes_total{reason}`, and reactor load
(`tardigrade_websocket_reactor_threads`, `_reactor_tunnels`,
`_reactor_thread_tunnels_max`, `_reactor_handoffs_total`,
`_reactor_wakeups_total`); the handshake's access-log
line is written when the tunnel closes, with status 101 and
`tunnel_close_reason`, `tunnel_duration_ms` and byte counts. See
[OBSERVABILITY.md](OBSERVABILITY.md#metrics) and the runnable
[examples/websocket-proxy](../examples/websocket-proxy/README.md).

## Top-Level Routing Directives

These directives are accepted at top level and apply to all methods through the
encoded routing fields listed below.

| Directive | Env key | Syntax / behavior | Example |
| --- | --- | --- | --- |
| `rewrite` | `TARDIGRADE_REWRITE_RULES` | `rewrite <pattern> <replacement> [flag];`; default flag is `last`; accepted flags are `last`, `break`, `redirect`, `permanent`. | `rewrite ^/old/(.*)$ /new/$1 permanent;` |
| `return` | `TARDIGRADE_RETURN_RULES` | `return <status> [body];`; maps to a catch-all return rule. | `return 200 ok;` |
| `if` | `TARDIGRADE_CONDITIONAL_RULES` | <code>if ($&lt;variable&gt; ~ or ~* &lt;pattern&gt;) return-or-rewrite ...;</code>; variables are `request_uri`, `http_host`, `args`; `~` is case-sensitive and `~*` is case-insensitive. | `if ($request_uri ~* ^/admin) return 403 blocked;` |

## Field Reference

All fields are optional unless noted. Empty string defaults generally disable
the feature or let runtime code choose a fallback. Boolean parsing accepts
`true`/`1` as true for permissive bool fields.

### Listener And Protocol

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_LISTEN_HOST` | string | `0.0.0.0` | Bind address. | `TARDIGRADE_LISTEN_HOST=127.0.0.1` |
| `TARDIGRADE_LISTEN_PORT` | u16 | `8069` | 1-65535. | `TARDIGRADE_LISTEN_PORT=8443` |
| `TARDIGRADE_HTTP1_ENABLED` | bool | `true` | Enables HTTP/1.1. At least one of HTTP/1.1 or HTTP/2 must stay enabled; plaintext listeners require HTTP/1.1 because downstream h2c is not supported. | `TARDIGRADE_HTTP1_ENABLED=true` |
| `TARDIGRADE_HTTP2_ENABLED` | bool | `true` | Enables HTTP/2 where supported. HTTP/2-only downstream listeners require TLS. | `TARDIGRADE_HTTP2_ENABLED=true` |
| `TARDIGRADE_TLS_HTTP1_NO_ALPN_FALLBACK` | bool | `false` | Allows HTTP/1.1 on TLS clients that omit ALPN. | `TARDIGRADE_TLS_HTTP1_NO_ALPN_FALLBACK=true` |
| `TARDIGRADE_PROXY_PROTOCOL` | enum | `off` | `off`, `auto`, `v1`, `v2`. Appliance/native TLS profiles require `off` when TLS is configured. | `TARDIGRADE_PROXY_PROTOCOL=auto` |
| `TARDIGRADE_PROXY_STREAMING_MODE` | enum | `off` | `off`/`buffered`, `response`/`responses`, `full`/`request_response`/`request-response`. | `TARDIGRADE_PROXY_STREAMING_MODE=response` |
| `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` | bytes | `16384` | 1-1048576; must fit proxy buffer hard limit. | `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE=65536` |
| `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` | bool | `false` | Stream all upstream statuses instead of mapping non-200 responses. | `TARDIGRADE_PROXY_STREAM_ALL_STATUSES=true` |

#### Stable protocol limits

HTTP/1.1, HTTP/2, and HTTP/3/QUIC are stable only within their documented
listener contracts:

- HTTP/2 downstream support is TLS/ALPN `h2`. Plaintext downstream h2c is not
  supported, so a downstream listener that disables HTTP/1.1 and leaves only
  HTTP/2 enabled must also configure TLS.
- `TARDIGRADE_HTTP2_ENABLED=false` removes `h2` from the downstream ALPN offer.
  It does not disable explicit h2c upstream origins configured separately.
- HTTP/3 runs on a separate UDP listener controlled by
  `TARDIGRADE_HTTP3_ENABLED` and `TARDIGRADE_QUIC_PORT`; opening the TCP
  listener port does not make H3 reachable.
- HTTP/3 advertisement is owned by Tardigrade. `TARDIGRADE_HTTP3_ALT_SVC=auto`
  advertises only while the runtime is ready, and disabled/withdrawn H3 emits
  no live H3 alternative.

### Routing And Static Serving

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_SERVER_NAMES` | list | `[]` | Comma or whitespace separated host patterns. Empty matches any host. | `TARDIGRADE_SERVER_NAMES=example.com,www.example.com` |
| `TARDIGRADE_DOC_ROOT` | path | `""` | Enables static fallback when set. | `TARDIGRADE_DOC_ROOT=/srv/www` |
| `TARDIGRADE_TRY_FILES` | string/list | `""` | Candidate list; supports `$uri`. | `TARDIGRADE_TRY_FILES=$uri /index.html` |
| `TARDIGRADE_SERVER_BLOCKS` | encoded list | `""` | Internal representation generated by `server {}` blocks. Records use byte `0x1e`; fields use byte `0x1f`. Prefer config-file blocks. | <code>export TARDIGRADE_SERVER_BLOCKS=$'example.com\x1f/srv/www\x1f$uri /index.html\x1f\x1f\x1fhttp://127.0.0.1:8080\x1f\x1f\x1f'</code> |
| `TARDIGRADE_LOCATION_BLOCKS` | encoded list | `""` | Internal representation generated by `location {}` blocks. Prefer config-file blocks. | <code>TARDIGRADE_LOCATION_BLOCKS=prefix&#124;/api/&#124;proxy_pass&#124;http://127.0.0.1:8080</code> |
| `TARDIGRADE_LOCATION_ERROR_PAGES` | encoded list | `""` | Internal error-page representation. Prefer `error_page` in locations. | <code>TARDIGRADE_LOCATION_ERROR_PAGES=prefix&#124;/api/&#124;502,503&#124;/50x.html</code> |
| `TARDIGRADE_INTERNAL_REDIRECT_RULES` | encoded list | `""` | <code>method&#124;pattern&#124;target;...</code>; target can be a path or named location. | <code>TARDIGRADE_INTERNAL_REDIRECT_RULES=GET&#124;^/old$&#124;/new</code> |
| `TARDIGRADE_NAMED_LOCATIONS` | encoded list | `""` | <code>name&#124;path;...</code>. | <code>TARDIGRADE_NAMED_LOCATIONS=fallback&#124;/index.html</code> |
| `TARDIGRADE_MIRROR_RULES` | encoded list | `""` | <code>method&#124;pattern&#124;target_url;...</code>; best-effort bounded copies after the primary route completes. Only `http://` and `https://` targets are accepted; any other scheme fails configuration validation. Mirror connect/response waits use the upstream timeout settings and never become unbounded when those settings are zero. Requests denied by a location `auth required` rule are never mirrored. | <code>TARDIGRADE_MIRROR_RULES=POST&#124;^/api/&#124;http://127.0.0.1:9000</code> |
| `TARDIGRADE_REWRITE_RULES` | encoded list | `""` | <code>method&#124;pattern&#124;replacement&#124;flag;...</code>; config-file `rewrite` is preferred. | <code>TARDIGRADE_REWRITE_RULES=*&#124;^/old/(.*)$&#124;/new/$1&#124;last</code> |
| `TARDIGRADE_RETURN_RULES` | encoded list | `""` | <code>method&#124;pattern&#124;status&#124;body;...</code>; config-file `return` is preferred. | <code>TARDIGRADE_RETURN_RULES=*&#124;^/health$&#124;200&#124;ok</code> |
| `TARDIGRADE_CONDITIONAL_RULES` | encoded list | `""` | Encoded inline <code>if (...) return&#124;rewrite</code> rules. Variables are `request_uri`, `http_host`, `args`; sensitivity is `cs` or `ci`. | <code>TARDIGRADE_CONDITIONAL_RULES=request_uri&#124;ci&#124;^/admin&#124;return&#124;403&#124;blocked</code> |

### Proxy And Upstreams

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_BASE_URL` | URL | `http://127.0.0.1:8080` | Default upstream. | `TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:3000` |
| `TARDIGRADE_UPSTREAM_BASE_URLS` | CSV URLs | `[]` | Primary upstream pool. | `TARDIGRADE_UPSTREAM_BASE_URLS=http://10.0.0.1,http://10.0.0.2` |
| `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match `UPSTREAM_BASE_URLS`. | `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS=3,1` |
| `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` | CSV URLs | `[]` | Backup upstreams. | `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS=http://10.0.1.1` |
| `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS` | CSV URLs | `[]` | Chat-specific upstream pool. | `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS=http://10.0.2.1` |
| `TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match chat URLs. | `TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS=1,1` |
| `TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS` | CSV URLs | `[]` | Chat backup upstreams. | `TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS=http://10.0.3.1` |
| `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS` | CSV URLs | `[]` | Commands-specific upstream pool. | `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS=http://10.0.4.1` |
| `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match command URLs. | `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS=2,1` |
| `TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS` | CSV URLs | `[]` | Commands backup upstreams. | `TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS=http://10.0.5.1` |
| `TARDIGRADE_UPSTREAM_LB_ALGORITHM` | enum | `round_robin` | `round_robin`, `least_connections`, `ip_hash`, `generic_hash`, `random_two_choices`; hyphen variants accepted. | `TARDIGRADE_UPSTREAM_LB_ALGORITHM=least_connections` |
| `TARDIGRADE_UPSTREAM_PROTOCOL` | enum | `http1` | `http1`/`http/1.1`/`h1`, `h2`/`http2`, `auto`, `h2c`. | `TARDIGRADE_UPSTREAM_PROTOCOL=auto` |
| `TARDIGRADE_UPSTREAM_TIMEOUT_MS` | u32 ms | `10000` | Per-attempt upstream timeout. | `TARDIGRADE_UPSTREAM_TIMEOUT_MS=5000` |
| `TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS` | u32 ms | `5000` | Upstream TCP connect timeout; `0` disables. | `TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS=1000` |
| `TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS` | u32 ms | `0` | Wait for upstream response start; `0` falls back to upstream timeout. | `TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS=2000` |
| `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` | u64 ms | `0` | Total budget across attempts; `0` disables. | `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS=12000` |
| `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` | u32 | `1` | Minimum effective value is `1`. | `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=3` |
| `TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY` | bool | `true` | Restricts retries to idempotent methods. | `TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY=true` |
| `TARDIGRADE_UPSTREAM_POOL_ENABLED` | bool | `true` | Reuse plain-HTTP upstream connections. Upstream-pool policy changes require restart. | `TARDIGRADE_UPSTREAM_POOL_ENABLED=true` |
| `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST` | usize | `32` | Idle pooled connections per origin. Upstream-pool policy changes require restart. | `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST=64` |
| `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | u64 ms | `90000` | Idle pool eviction age. Upstream-pool policy changes require restart. | `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS=30000` |
| `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS` | u64 ms | `0` | Hard pooled-connection lifetime; `0` disables. Upstream-pool policy changes require restart. | `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS=600000` |
| `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` | usize | `0` | Concurrent checked-out upstream connections per origin; `0` unlimited. Upstream-pool policy changes require restart. | `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST=128` |
| `TARDIGRADE_UPSTREAM_POOL_LOCK_METRICS` | bool | `false` | Benchmark-only lock wait counters. | `TARDIGRADE_UPSTREAM_POOL_LOCK_METRICS=false` |
| `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED` | bool | `true` | Request gzip from upstream and gunzip in gateway. | `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED=true` |
| `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` | bytes | `262144` | Must be at least 1. | `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES=1048576` |
| `TARDIGRADE_PROXY_PASS_CHAT` | URL | `""` | BearClaw/chat route upstream. | `TARDIGRADE_PROXY_PASS_CHAT=http://127.0.0.1:9001` |
| `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` | URL/path | `""` | BearClaw commands route prefix/upstream. | `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX=http://127.0.0.1:9002` |

### Upstream TLS

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_TLS_VERIFY` | bool | `true` | Verify HTTPS upstream certificates. False logs a warning. | `TARDIGRADE_UPSTREAM_TLS_VERIFY=true` |
| `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE` | path | `""` | PEM CA bundle. Empty uses system defaults. | `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE=/etc/ssl/certs/ca.pem` |
| `TARDIGRADE_UPSTREAM_TLS_SERVER_NAME` | hostname | `""` | Overrides upstream SNI. Empty uses URL hostname. | `TARDIGRADE_UPSTREAM_TLS_SERVER_NAME=origin.example.com` |
| `TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT` | path | `""` | PEM client certificate for upstream mTLS. | `TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT=/etc/tardigrade/upstream.crt` |
| `TARDIGRADE_UPSTREAM_TLS_CLIENT_KEY` | path | `""` | PEM client private key for upstream mTLS. | `TARDIGRADE_UPSTREAM_TLS_CLIENT_KEY=/etc/tardigrade/upstream.key` |

Behavior is identical across both `-Dtls-profile` builds (#634, #649): the
native upstream TLS client (`src/http/tls_termination.zig`'s
`UpstreamTlsConn`) serves every profile — same knobs, same semantics, no
OpenSSL. "System defaults" for an empty `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE`
means the first readable well-known system CA bundle file
(`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/ssl/cert.pem`, and similar OS-standard locations); if neither an
explicit bundle nor a well-known location is usable, verification fails
deterministically rather than silently trusting nothing.

Verification currently authenticates certificate chain signatures made with
Ed25519, ECDSA P-256/SHA-256, RSA-PSS/SHA-256, or (as of #645) RSA PKCS#1
v1.5/SHA-256 or SHA-384 (`sha256WithRSAEncryption`/`sha384WithRSAEncryption`,
still common among public CAs); an origin signed with another unsupported
algorithm (e.g. ECDSA/SHA-384) fails verification even with a correct CA
bundle and hostname (see `docs/TROUBLESHOOTING.md`). RSA PKCS#1 v1.5 support
is certificate-chain-signature verification only — the TLS 1.3 handshake's
own `CertificateVerify` proof-of-possession still only uses Ed25519, ECDSA
P-256/SHA-256, or RSA-PSS/SHA-256, since RFC 8446 §4.2.3 forbids `rsa_pkcs1`
schemes there. Each peer certificate entry is also capped at 8 KiB DER bytes
and the whole handshake message at 16 KiB (#646) — generous enough for
ordinary public WebPKI certificates/chains, including a leaf with a large
SAN set; a certificate or chain genuinely outside those norms fails even
when its signature algorithm is otherwise supported.

### Health Checks And Circuit Breaking

For active-probe aliases, `TARDIGRADE_UPSTREAM_PROBE_*` names are preferred only
when set in the process environment. With the current loader, config-file and
secret overrides must use the `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_*` names because
the primary `PROBE_*` names bypass file/secret lookup.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_CB_THRESHOLD` | u32 | `0` | Circuit breaker failure threshold; `0` disables. | `TARDIGRADE_CB_THRESHOLD=5` |
| `TARDIGRADE_CB_TIMEOUT_MS` | u64 ms | `30000` | Open timeout before half-open probe. | `TARDIGRADE_CB_TIMEOUT_MS=10000` |
| `TARDIGRADE_UPSTREAM_MAX_FAILS` | u32 | `0` | Passive health failure threshold; `0` disables. | `TARDIGRADE_UPSTREAM_MAX_FAILS=3` |
| `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS` | u64 ms | `10000` | Passive failure retry timeout. | `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS=30000` |
| `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS` | u64 ms | `0` | Preferred process-env name for active-probe interval; `0` disables. | `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=5000` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS` | u64 ms | `0` | Config-file/secret-compatible active-probe interval name. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS=5000` |
| `TARDIGRADE_UPSTREAM_PROBE_PATH` | path | `/` | Preferred process-env name for active-probe path. | `TARDIGRADE_UPSTREAM_PROBE_PATH=/health` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH` | path | `/` | Config-file/secret-compatible active-probe path name. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH=/healthz` |
| `TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS` | u32 ms | `2000` | Preferred process-env name for active-probe timeout. | `TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS=1000` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS` | u32 ms | `2000` | Config-file/secret-compatible active-probe timeout name. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS=1000` |
| `TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD` | u32 | `1` | Preferred process-env name for active-probe failure threshold; minimum effective value is 1. | `TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD=2` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD` | u32 | `1` | Config-file/secret-compatible fail threshold name. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD=2` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD` | u32 | `1` | Consecutive successes before clearing unhealthy; minimum effective value is 1. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD=2` |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS` | status/range | `200-299` | Preferred process-env name; accepts a single u16 status or inclusive `min-max`. | `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS=200-399` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS` | status/range | `200-299` | Config-file/secret-compatible success range name. | `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS=204` |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS_OVERRIDES` | encoded list | `""` | Preferred process-env name; format is <code>upstream_url&#124;status-or-range;...</code>. | <code>TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS_OVERRIDES=http://127.0.0.1:8080&#124;200-399</code> |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS_OVERRIDES` | encoded list | `""` | Config-file/secret-compatible success override name. | <code>TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS_OVERRIDES=http://a&#124;204</code> |
| `TARDIGRADE_UPSTREAM_SLOW_START_MS` | u64 ms | `0` | Slow-start window for recovered upstreams; `0` disables. | `TARDIGRADE_UPSTREAM_SLOW_START_MS=30000` |

### TLS Termination

Both TLS profiles (`general`, the default, and `appliance`) are pure-Zig
native (#649) and TLS 1.3-only. The settings below that only ever applied to
the retired OpenSSL adapter (TLS 1.2, cipher overrides,
OpenSSL session cache/tickets, OCSP, CRL, the filesystem credential
watcher) now deterministically fail config validation in every profile if
set to anything other than their listed default — see
[docs/TLS_DEPENDENCY_POLICY.md](TLS_DEPENDENCY_POLICY.md#retired-openssl-capability-disposition)
for the complete disposition of each.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_TLS_CERT_PATH` | path | `""` | Required for TLS; must be paired with key path. | `TARDIGRADE_TLS_CERT_PATH=/etc/tls/fullchain.pem` |
| `TARDIGRADE_TLS_KEY_PATH` | path | `""` | Required for TLS; must be paired with cert path. | `TARDIGRADE_TLS_KEY_PATH=/etc/tls/privkey.pem` |
| `TARDIGRADE_TLS_MIN_VERSION` | string | `1.3` | Must be exactly `1.3`; anything else is rejected. | `TARDIGRADE_TLS_MIN_VERSION=1.3` |
| `TARDIGRADE_TLS_MAX_VERSION` | string | `1.3` | Must be exactly `1.3`; anything else is rejected. | `TARDIGRADE_TLS_MAX_VERSION=1.3` |
| `TARDIGRADE_TLS_CIPHER_LIST` | string | `""` | Retired OpenSSL-format TLS <=1.2 cipher list; must be empty. | (unset) |
| `TARDIGRADE_TLS_CIPHER_SUITES` | string | `""` | Retired OpenSSL-format TLS 1.3 cipher-suite override; must be empty. | (unset) |
| `TARDIGRADE_TLS_SERVER_NAME` | DNS name | `""` | Unused by the general profile. Appliance requires one non-wildcard DNS name when TLS is enabled; appliance credential/name changes require restart. | `TARDIGRADE_TLS_SERVER_NAME=edge.example.com` |
| `TARDIGRADE_TLS_SNI_CERTS` | encoded list | `""` | Additional SNI certs as <code>name:cert:key&#124;name2:cert2:key2</code>. Appliance profile requires empty. On `general`, an explicit entry always wins for its hostname; for any hostname with no entry, the default (`tls_cert_path`/`tls_key_path`) identity is served instead if its own certificate's SAN already covers that hostname (#634), otherwise the handshake fails closed. | `TARDIGRADE_TLS_SNI_CERTS=api.example.com:/a.crt:/a.key` |
| `TARDIGRADE_TLS_SESSION_CACHE` | bool | `false` | Retired OpenSSL session cache; must be false (see `TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`). | (unset) |
| `TARDIGRADE_TLS_SESSION_CACHE_SIZE` | u32 | `20480` | Unused; retained for config-file compatibility. | (unset) |
| `TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS` | u32 | `300` | Unused; retained for config-file compatibility. | (unset) |
| `TARDIGRADE_TLS_SESSION_TICKETS` | bool | `false` | Retired OpenSSL session tickets; must be false (see `TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`). | (unset) |
| `TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS` | u32 ms | `5000` | TLS handshake read timeout. `0` falls back to keep-alive timeout. | `TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS=3000` |
| `TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS` | u64 ms | `0` | Retired OpenSSL cert/key watcher interval; must be `0` (credential rotation is the explicit SIGHUP reload path instead). | (unset) |
| `TARDIGRADE_TLS_CLIENT_CA_PATH` | path | `""` | PEM bundle of CAs trusted to issue client certificates. Required when `TARDIGRADE_TLS_CLIENT_VERIFY=true`; never falls back to the system trust store. Re-read on config reload. | `TARDIGRADE_TLS_CLIENT_CA_PATH=/etc/tls/clients.pem` |
| `TARDIGRADE_TLS_CLIENT_VERIFY` | bool | `false` | Request and verify downstream client certificates (mTLS) on the native TLS listener. Required by default: a handshake without a valid certificate fails. HTTP/1.1 and HTTP/2 only; rejected together with `TARDIGRADE_HTTP3_ENABLED`. See [Downstream mTLS](#downstream-mtls). | `TARDIGRADE_TLS_CLIENT_VERIFY=true` |
| `TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL` | bool | `false` | With `TARDIGRADE_TLS_CLIENT_VERIFY`, also accept clients that present no certificate. A certificate that *is* presented must still verify. | `TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL=true` |
| `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH` | u32 | `3` | Longest accepted client certification path (leaf plus intermediates, excluding the trust anchor), 1 to 8: depth 1 accepts leaf → anchor, depth 2 leaf → intermediate → anchor. | `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH=3` |
| `TARDIGRADE_TLS_CRL_PATH` | path | `""` | Unused; retained for config-file compatibility. | (unset) |
| `TARDIGRADE_TLS_CRL_CHECK` | bool | `false` | Retired CRL checking; must be false. | (unset) |
| `TARDIGRADE_TLS_OCSP_STAPLING` | bool | `false` | Retired OCSP stapling; must be false. | (unset) |
| `TARDIGRADE_TLS_OCSP_RESPONSE_PATH` | path | `""` | Unused; retained for config-file compatibility. | (unset) |
| `TARDIGRADE_TLS_OCSP_AUTO_REFRESH` | bool | `false` | Retired OCSP auto-refresh; must be false. | (unset) |
| `TARDIGRADE_TLS_OCSP_REFRESH_INTERVAL_MS` | u64 ms | `3600000` | Unused; retained for config-file compatibility. | (unset) |
| `TARDIGRADE_TLS_OCSP_REFRESH_TIMEOUT_MS` | u32 ms | `10000` | Unused; retained for config-file compatibility. | (unset) |

### Native TLS Resumption And Replay

These settings affect native pure-Zig TLS-over-TCP and QUIC/H3 engines, not
OpenSSL `TARDIGRADE_TLS_SESSION_*` behavior.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE` | enum | `disabled` | `disabled`, `stateful`, `stateless`, `hybrid`. | `TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE=stateless` |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS` | u32 seconds | `86400` | When resumption mode is enabled, must be `1`-`604800` seconds. | `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS=3600` |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_USAGE` | enum | `reusable` | `reusable`, `single_use`. | `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_USAGE=single_use` |
| `TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH` | path | `""` | Requires `stateless` or `hybrid`. Ticket-key source mode changes require restart. | `TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH=/var/lib/tardigrade/tickets.json` |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE` | enum | `disabled` | `disabled`, `process_local`/`process-local`. Replay-store topology changes require restart. | `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE=process_local` |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES` | usize | `65536` | Strictly parsed. Must be 1-1048576. Replay capacity changes require restart. | `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES=131072` |

### TLS Buffer Limits

Each TLS buffer scope has three byte fields:
`<PREFIX>_LOW_WATERMARK_BYTES`, `<PREFIX>_HIGH_WATERMARK_BYTES`, and
`<PREFIX>_HARD_LIMIT_BYTES`. Prefixes are
`TARDIGRADE_TLS_INBOUND_CIPHERTEXT`, `TARDIGRADE_TLS_INBOUND_PLAINTEXT`,
`TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT`, and `TARDIGRADE_TLS_HANDSHAKE`.

Values must be positive with `low < high <= hard`; hard limits must fit native
TLS stream capacity. Defaults are deterministic from native stream queue capacities: ciphertext queues use capacity `4 * 16645`, inbound plaintext uses `32768`, and handshake uses `16384`.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES` | bytes | `16645` | Positive; less than corresponding high watermark. | `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES=16645` |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES` | bytes | `49935` | Positive; greater than low and `<=` hard. | `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES=49935` |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | bytes | `66580` | Positive; native inbound ciphertext queue hard limit. | `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HARD_LIMIT_BYTES=66580` |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_LOW_WATERMARK_BYTES` | bytes | `8192` | Positive; less than corresponding high watermark. | `TARDIGRADE_TLS_INBOUND_PLAINTEXT_LOW_WATERMARK_BYTES=8192` |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HIGH_WATERMARK_BYTES` | bytes | `24576` | Positive; greater than low and `<=` hard. | `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HIGH_WATERMARK_BYTES=24576` |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HARD_LIMIT_BYTES` | bytes | `32768` | Positive; native inbound plaintext queue hard limit. | `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HARD_LIMIT_BYTES=32768` |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES` | bytes | `16645` | Positive; less than corresponding high watermark. | `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES=16645` |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES` | bytes | `49935` | Positive; greater than low and `<=` hard. | `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES=49935` |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | bytes | `66580` | Positive; native outbound ciphertext queue hard limit. | `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HARD_LIMIT_BYTES=66580` |
| `TARDIGRADE_TLS_HANDSHAKE_LOW_WATERMARK_BYTES` | bytes | `4096` | Positive; less than corresponding high watermark. | `TARDIGRADE_TLS_HANDSHAKE_LOW_WATERMARK_BYTES=4096` |
| `TARDIGRADE_TLS_HANDSHAKE_HIGH_WATERMARK_BYTES` | bytes | `12288` | Positive; greater than low and `<=` hard. | `TARDIGRADE_TLS_HANDSHAKE_HIGH_WATERMARK_BYTES=12288` |
| `TARDIGRADE_TLS_HANDSHAKE_HARD_LIMIT_BYTES` | bytes | `16384` | Positive; native handshake queue hard limit. | `TARDIGRADE_TLS_HANDSHAKE_HARD_LIMIT_BYTES=16384` |

### ACME

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_TLS_ACME_ENABLED` | bool | `false` | Retired OpenSSL-adapter ACME automation; must be false in every profile. A native ACME client is tracked separately (#391, #634). | (unset) |
| `TARDIGRADE_TLS_ACME_CERT_DIR` | path | `""` | Certificate storage directory. | `TARDIGRADE_TLS_ACME_CERT_DIR=/var/lib/tardigrade/acme` |
| `TARDIGRADE_TLS_ACME_DIRECTORY_URL` | URL | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL. | `TARDIGRADE_TLS_ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory` |
| `TARDIGRADE_TLS_ACME_DOMAINS` | CSV DNS names | `[]` | Domains to obtain/renew. Empty logs a warning when ACME is enabled. | `TARDIGRADE_TLS_ACME_DOMAINS=example.com,www.example.com` |
| `TARDIGRADE_TLS_ACME_EMAIL` | email | `""` | ACME account email. | `TARDIGRADE_TLS_ACME_EMAIL=ops@example.com` |
| `TARDIGRADE_TLS_ACME_ACCOUNT_KEY_PATH` | path | `""` | PEM ECDSA P-256 account key path; created on first run. | `TARDIGRADE_TLS_ACME_ACCOUNT_KEY_PATH=/var/lib/tardigrade/acme/account.key` |
| `TARDIGRADE_TLS_ACME_RENEW_DAYS_BEFORE_EXPIRY` | u32 days | `30` | Renewal trigger window. | `TARDIGRADE_TLS_ACME_RENEW_DAYS_BEFORE_EXPIRY=21` |

### HTTP/3 And QUIC

HTTP/3/QUIC is stable for the native Zig backend and the deployment model
documented in [HTTP3_ROLLOUT.md](HTTP3_ROLLOUT.md). Operators must provide a
compatible TLS identity, permit UDP traffic to `TARDIGRADE_QUIC_PORT`, and use
restart rather than reload for listener-owned transport settings. The supported
topology is one process owning one UDP runtime and one in-process Destination
Connection ID routing table; multi-process `SO_REUSEPORT`, eBPF, or external
DCID steering is outside the current support promise.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_HTTP3_ENABLED` | bool | `false` | Enables native QUIC/H3. Requires TLS identity in native paths. HTTP/3 listener topology changes require restart. | `TARDIGRADE_HTTP3_ENABLED=true` |
| `TARDIGRADE_QUIC_PORT` | u16 | `443` | UDP QUIC listener port, 1-65535. HTTP/3 listener topology changes require restart. | `TARDIGRADE_QUIC_PORT=8443` |
| `TARDIGRADE_HTTP3_ALT_SVC` | enum | `off` | `off`, `auto`. | `TARDIGRADE_HTTP3_ALT_SVC=auto` |
| `TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS` | u32 | `300` | `Alt-Svc` `ma` value; must be `0`-`86400`. | `TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS=86400` |
| `TARDIGRADE_HTTP3_ENABLE_0RTT` | bool | `false` | Enables 0-RTT. Logs replay warning; appliance profile rejects true. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_ENABLE_0RTT=false` |
| `TARDIGRADE_HTTP3_CONNECTION_MIGRATION` | bool | `false` | QUIC connection migration; appliance profile rejects true. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_CONNECTION_MIGRATION=true` |
| `TARDIGRADE_HTTP3_RETRY_POLICY` | enum | `off` | `off`, `address_validation`/`address-validation`; appliance profile rejects non-off. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_RETRY_POLICY=address_validation` |
| `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` | bytes | `2048` | Bounds discovered send size; transport clamps to `[1200, 2048]` and may lower it for the peer/path. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE=2048` |
| `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES` | bytes | `0` | Advisory socket receive buffer target. `0` leaves kernel sizing. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES=1048576` |
| `TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES` | bytes | `0` | Advisory socket send buffer target. `0` leaves kernel sizing. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES=1048576` |
| `TARDIGRADE_HTTP3_ECN` | bool | `true` | Enables QUIC ECN where supported. HTTP/3 listener-owned changes require restart. | `TARDIGRADE_HTTP3_ECN=true` |
| `TARDIGRADE_HTTP3_QLOG_DIR` | path | `""` | Debug-only qlog output directory. Empty disables qlog. Non-empty writes one `*.sqlog` per accepted QUIC connection; restart required to change. | `TARDIGRADE_HTTP3_QLOG_DIR=/tmp/tardigrade-qlog` |
| `TARDIGRADE_HTTP3_KEYLOG_PATH` | path | `""` | Debug-only NSS keylog output path. Empty disables key logging. Non-empty permits packet decryption and must be handled as sensitive; restart required to change. | `TARDIGRADE_HTTP3_KEYLOG_PATH=/tmp/tardigrade-qlog/http3.keys` |

### Security, Auth, And Policy

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_AUTH_REQUEST_URL` | URL | `""` | External auth request endpoint. Empty disables. | `TARDIGRADE_AUTH_REQUEST_URL=http://127.0.0.1:9000/auth` |
| `TARDIGRADE_JWT_SECRET` | secret | `""` | JWT secret. Redacted in config-conflict logs. | `TARDIGRADE_JWT_SECRET=change-me` |
| `TARDIGRADE_JWT_ISSUER` | string | `""` | Expected JWT issuer. | `TARDIGRADE_JWT_ISSUER=https://issuer.example.com` |
| `TARDIGRADE_JWT_AUDIENCE` | string | `""` | Expected JWT audience. | `TARDIGRADE_JWT_AUDIENCE=tardigrade` |
| `TARDIGRADE_BASIC_AUTH_HASHES` | CSV SHA-256 hex | `[]` | 64-char SHA-256 hashes of `user:password`. | `TARDIGRADE_BASIC_AUTH_HASHES=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| `TARDIGRADE_AUTH_TOKEN_HASHES` | CSV SHA-256 hex | `[]` | 64-char SHA-256 hashes of bearer tokens. | `TARDIGRADE_AUTH_TOKEN_HASHES=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| `TARDIGRADE_SESSION_TTL_SECONDS` | u32 seconds | `3600` | Session TTL. | `TARDIGRADE_SESSION_TTL_SECONDS=7200` |
| `TARDIGRADE_SESSION_MAX` | u32 | `128` | Max sessions retained. | `TARDIGRADE_SESSION_MAX=1024` |
| `TARDIGRADE_SESSION_STORE_PATH` | path | `""` | File-backed session store. Path changes on reload require restart. | `TARDIGRADE_SESSION_STORE_PATH=/var/lib/tardigrade/sessions.json` |
| `TARDIGRADE_DEVICE_REGISTRY_PATH` | path | `""` | Device registry used by device-signature auth. Entries are HMAC **shared secrets**, so the file is created owner-only (0600) and Tardigrade refuses to append to a group/world-accessible registry. | `TARDIGRADE_DEVICE_REGISTRY_PATH=/var/lib/tardigrade/devices.registry` |
| `TARDIGRADE_POLICY_RULES` | semicolon-separated `method\|path_regex\|required_scope\|approval_required\|UTC_hours\|device_regex` | `""` | Request authorization rules. All six fields are required; optional constraints are empty fields. | `TARDIGRADE_POLICY_RULES=POST\|^/deploy$\|admin\|true\|8-18\|^managed-` |
| `TARDIGRADE_POLICY_USER_SCOPES` | semicolon-separated `identity:scope,scope` | `""` | Scope grants used by policy rules. | `TARDIGRADE_POLICY_USER_SCOPES=alice:admin,deploy` |
| `TARDIGRADE_POLICY_APPROVAL_ROUTES` | semicolon-separated `method\|path_regex` | `""` | Routes that require an approval token. | `TARDIGRADE_POLICY_APPROVAL_ROUTES=POST\|^/deploy$` |
| `TARDIGRADE_APPROVAL_STORE_PATH` | path | `""` | Approval store. Path changes on reload require restart. | `TARDIGRADE_APPROVAL_STORE_PATH=/var/lib/tardigrade/approvals.json` |
| `TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK` | URL | `""` | Approval escalation webhook. Changes on reload require restart. | `TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK=https://hooks.example.com/tardi` |
| `TARDIGRADE_APPROVAL_TTL_MS` | i64 ms | `300000` | Positive values set the approval token TTL; `<= 0` uses the `300000` ms fallback. | `TARDIGRADE_APPROVAL_TTL_MS=600000` |
| `TARDIGRADE_APPROVAL_MAX_PENDING_PER_IDENTITY` | u32 | `0` | Pending approvals per identity; `0` disables this cap. | `TARDIGRADE_APPROVAL_MAX_PENDING_PER_IDENTITY=10` |
| `TARDIGRADE_TRANSCRIPT_STORE_PATH` | path | `""` | Transcript store. Path changes on reload require restart. | `TARDIGRADE_TRANSCRIPT_STORE_PATH=/var/lib/tardigrade/transcripts` |
| `TARDIGRADE_TRUST_GATEWAY_ID` | string | `tardigrade-edge` | Gateway identity for signed upstream trust headers. | `TARDIGRADE_TRUST_GATEWAY_ID=edge-us-east-1` |
| `TARDIGRADE_TRUST_SHARED_SECRET` | secret | `""` | Signs outbound `X-Tardigrade-Gateway-Id`, timestamp, and signature headers sent to upstreams. Empty disables outbound trust-header signing. | `TARDIGRADE_TRUST_SHARED_SECRET=change-me` |
| `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` | CSV strings | `[]` | Trusted peer hosts, addresses, or CIDR blocks allowed to supply inbound forwarded-client and geo metadata; also the proxy hops skipped when `X-Forwarded-For` is walked right to left to find the client IP, and used by control-plane proxy trust enforcement. | `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES=192.0.2.10,172.16.0.0/12` |
| `TARDIGRADE_REAL_IP_HEADER` | header name | `""` | Header a trusted peer sets to the real client IP (for example `CF-Connecting-IP` behind Cloudflare). When set and valid, it takes precedence over `X-Forwarded-For` for rate limiting and access logs. Honored only from a trusted peer. | `TARDIGRADE_REAL_IP_HEADER=CF-Connecting-IP` |
| `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY` | bool | `false` | When true, inbound forwarded-client and geo metadata is accepted only from a listed trusted peer. Trusted control-plane proxying also requires its shared secret and an allowed upstream target; signed response headers are not currently verified. | `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY=true` |
| `TARDIGRADE_SECURITY_HEADERS` | bool | `true` | Adds default security headers. | `TARDIGRADE_SECURITY_HEADERS=true` |
| `TARDIGRADE_HSTS_ENABLED` | bool | `false` | Emits HSTS on HTTPS responses. | `TARDIGRADE_HSTS_ENABLED=true` |
| `TARDIGRADE_HSTS_MAX_AGE` | u32 seconds | `31536000` | HSTS max-age. | `TARDIGRADE_HSTS_MAX_AGE=63072000` |
| `TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS` | bool | `true` | Adds `includeSubDomains`. | `TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS=true` |
| `TARDIGRADE_HSTS_PRELOAD` | bool | `false` | Adds `preload`. | `TARDIGRADE_HSTS_PRELOAD=false` |
| `TARDIGRADE_GEO_BLOCKED_COUNTRIES` | CSV country codes | `[]` | Alphabetic ISO-style country codes from an external proxy/CDN header. Enabling this requires the trusted-source enforcement settings so direct clients cannot forge their country. | `TARDIGRADE_GEO_BLOCKED_COUNTRIES=RU,KP` |
| `TARDIGRADE_GEO_COUNTRY_HEADER` | header name | `CF-IPCountry` | Header supplying country code. | `TARDIGRADE_GEO_COUNTRY_HEADER=X-Country-Code` |
| `TARDIGRADE_ACCESS_CONTROL` | string | `""` | IP access control rules, e.g. `allow 10.0.0.0/8, deny 0.0.0.0/0`. | `TARDIGRADE_ACCESS_CONTROL=deny 203.0.113.0/24` |
| `TARDIGRADE_ADD_HEADERS` | encoded list | `""` | <code>Name: value&#124;Name2: value2</code>; appended response headers. | `TARDIGRADE_ADD_HEADERS=X-Frame-Options: DENY` |

### Rate Limits And Request Limits

| Env key | Type | Config default | Effective behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_RATE_LIMIT_RPS` | f64 | `10` | Requests per second per client IP. `> 0` enables; `<= 0` disables; exactly `0` logs a warning. | `TARDIGRADE_RATE_LIMIT_RPS=50` |
| `TARDIGRADE_RATE_LIMIT_BURST` | u32 | `20` | Burst capacity. | `TARDIGRADE_RATE_LIMIT_BURST=100` |
| `TARDIGRADE_MAX_BODY_SIZE` | bytes | `0` | `0` uses parser default `1048576`. | `TARDIGRADE_MAX_BODY_SIZE=10485760` |
| `TARDIGRADE_MAX_URI_LENGTH` | bytes | `0` | `0` uses parser default `8192`. | `TARDIGRADE_MAX_URI_LENGTH=16384` |
| `TARDIGRADE_MAX_HEADER_COUNT` | usize | `0` | `0` uses parser default `100`. | `TARDIGRADE_MAX_HEADER_COUNT=200` |
| `TARDIGRADE_MAX_HEADER_SIZE` | bytes | `0` | `0` uses parser default `8192`. | `TARDIGRADE_MAX_HEADER_SIZE=16384` |
| `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE` | bytes | `0` | `0` uses parser default `32768`; over-limit requests return 431. | `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE=65536` |
| `TARDIGRADE_BODY_TIMEOUT_MS` | u32 ms | `0` | `0` uses parser default `30000`. | `TARDIGRADE_BODY_TIMEOUT_MS=15000` |
| `TARDIGRADE_HEADER_TIMEOUT_MS` | u32 ms | `10000` | `0` uses parser default `10000`. | `TARDIGRADE_HEADER_TIMEOUT_MS=5000` |
| `TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS` | u32 ms | `0` | Overall request deadline; `0` disables. | `TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS=30000` |
| `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` | u32 ms | `5000` | Idle keep-alive timeout; `0` disables. | `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS=10000` |
| `TARDIGRADE_DOWNSTREAM_WRITE_TIMEOUT_MS` | u32 ms | `30000` | Downstream write timeout; `0` disables explicit deadline. | `TARDIGRADE_DOWNSTREAM_WRITE_TIMEOUT_MS=15000` |
| `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` | u32 | `100` | `0` means unlimited. | `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=1000` |
| `TARDIGRADE_MAX_CONNECTIONS_PER_IP` | u32 | `0` | `0` unlimited. Overridden by `TARDIGRADE_LIMIT_CONN_PER_IP` when that alias is non-empty. | `TARDIGRADE_MAX_CONNECTIONS_PER_IP=100` |
| `TARDIGRADE_LIMIT_CONN_PER_IP` | u32 alias | `""` | Compatibility alias for max connections per IP. | `TARDIGRADE_LIMIT_CONN_PER_IP=25` |
| `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | u32 | `0` | Total active client connections; `0` unlimited. | `TARDIGRADE_MAX_ACTIVE_CONNECTIONS=4096` |
| `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | u32 | `0` | Concurrent in-flight HTTP requests; `0` unlimited; returns 503 when exceeded. | `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS=1024` |

### Logging, Metrics, And Tracing

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_LOG_LEVEL` | enum | `info` | `debug`, `info`, `warn`, `error`. | `TARDIGRADE_LOG_LEVEL=warn` |
| `TARDIGRADE_ERROR_LOG_PATH` | path | `""` | Optional error-log destination; empty keeps stderr behavior. | `TARDIGRADE_ERROR_LOG_PATH=/var/log/tardigrade/error.log` |
| `TARDIGRADE_ACCESS_LOG_FORMAT` | enum | `json` | `json`, `plain`, `custom`. | `TARDIGRADE_ACCESS_LOG_FORMAT=json` |
| `TARDIGRADE_ACCESS_LOG_TEMPLATE` | string | `""` | Used when format is `custom`. | `TARDIGRADE_ACCESS_LOG_TEMPLATE={method} {path} {status}` |
| `TARDIGRADE_ACCESS_LOG_MIN_STATUS` | u16 | `0` | Minimum status logged; `0` logs all. | `TARDIGRADE_ACCESS_LOG_MIN_STATUS=400` |
| `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` | bytes | `0` | In-memory buffer before flush; `0` disables buffering. | `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE=65536` |
| `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP` | host:port | `""` | Optional syslog UDP endpoint. | `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP=127.0.0.1:514` |
| `TARDIGRADE_REDACT_HEADERS` | CSV header names | built-in list | Empty uses built-in redaction list. | `TARDIGRADE_REDACT_HEADERS=authorization,cookie` |
| `TARDIGRADE_METRICS_PATH` | path | `/status/metrics` | Empty disables Prometheus endpoint. | `TARDIGRADE_METRICS_PATH=/metrics` |
| `TARDIGRADE_METRICS_REQUIRE_AUTH` | bool | `false` | Requires request auth before serving metrics. | `TARDIGRADE_METRICS_REQUIRE_AUTH=true` |
| `TARDIGRADE_OTEL_ENABLED` | bool | `false` | Parsed operator setting reserved for telemetry; no OTLP exporter is currently wired to this flag. | `TARDIGRADE_OTEL_ENABLED=true` |
| `TARDIGRADE_OTEL_ENDPOINT` | URL | `""` | Parsed endpoint reserved for OTLP export; currently not consumed by a runtime exporter. | `TARDIGRADE_OTEL_ENDPOINT=http://jaeger:4318/v1/traces` |
| `TARDIGRADE_OTEL_SAMPLE_RATE` | u32 percent | `100` | Parsed and validated 0-100; currently not applied to runtime span export. | `TARDIGRADE_OTEL_SAMPLE_RATE=10` |

W3C `traceparent` propagation/origination is active on proxy requests even when
`TARDIGRADE_OTEL_ENABLED=false`.

### CLI-Owned Environment Fields

These public environment fields are consumed by CLI paths rather than
`EdgeConfig`.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_LOG_ROTATE_MAX_BYTES` | usize bytes | `0` | `0` disables startup size-triggered rotation; `> 0` rotates when the existing error log size reaches the threshold. | `TARDIGRADE_LOG_ROTATE_MAX_BYTES=10485760` |
| `TARDIGRADE_LOG_ROTATE_MAX_FILES` | usize | `5` | Number of retained rotated generations; `0` discards the current log when rotation triggers. | `TARDIGRADE_LOG_ROTATE_MAX_FILES=5` |
| `TARDIGRADE_VALIDATE_CONFIG_ONLY` | bool-like | `false` | `1` or case-insensitive `true` makes `run` execute legacy config validation and exit; other values do not enable it. | `TARDIGRADE_VALIDATE_CONFIG_ONLY=true` |

### Compression And Cache

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_COMPRESSION_ENABLED` | bool | `true` | Enables response compression. | `TARDIGRADE_COMPRESSION_ENABLED=true` |
| `TARDIGRADE_COMPRESSION_MIN_SIZE` | bytes | `256` | Minimum body size to compress. | `TARDIGRADE_COMPRESSION_MIN_SIZE=1024` |
| `TARDIGRADE_COMPRESSION_BROTLI_ENABLED` | bool | `false` | Reserved for a future native Brotli implementation; accepted today but does not load `libbrotlienc` or enable Brotli output. | `TARDIGRADE_COMPRESSION_BROTLI_ENABLED=false` |
| `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` | u32 | `5` | Reserved Brotli quality value; must be 0-11. | `TARDIGRADE_COMPRESSION_BROTLI_QUALITY=6` |
| `TARDIGRADE_IDEMPOTENCY_TTL` | u32 seconds | `300` | Idempotency cache TTL; `0` disables. | `TARDIGRADE_IDEMPOTENCY_TTL=600` |
| `TARDIGRADE_PROXY_CACHE_TTL_SECONDS` | u32 seconds | `0` | Proxy response cache TTL; `0` disables. | `TARDIGRADE_PROXY_CACHE_TTL_SECONDS=60` |
| `TARDIGRADE_PROXY_CACHE_PATH` | path | `""` | Disk-backed/tiered cache path. | `TARDIGRADE_PROXY_CACHE_PATH=/var/cache/tardigrade/proxy` |
| `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE` | string | `method:path:payload_sha256` | Colon-separated tokens: `method`, `path`, `payload_sha256`, `identity`, `api_version`. | `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE=method:path:identity` |
| `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS` | u32 seconds | `0` | Serve stale while revalidating after TTL expiry. | `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS=30` |
| `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS` | u32 ms | `250` | Wait for another request populating same cache key. | `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS=500` |
| `TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS` | u64 ms | `30000` | Cache manager maintenance interval. | `TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS=60000` |

### Runtime, Reload, And Workers

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_CONFIG_PATH` | path | unset | Config file to load when commands do not pass `-c/--config`. | `TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf` |
| `TARDIGRADE_PID_FILE` | path | `""` | Empty disables pid-file writing. | `TARDIGRADE_PID_FILE=/run/tardigrade.pid` |
| `TARDIGRADE_RUN_USER` | string | `""` | User for post-bind privilege drop. | `TARDIGRADE_RUN_USER=tardigrade` |
| `TARDIGRADE_RUN_GROUP` | string | `""` | Group for post-bind privilege drop. | `TARDIGRADE_RUN_GROUP=tardigrade` |
| `TARDIGRADE_CHROOT_DIR` | path | `""` | Chroot after bind. | `TARDIGRADE_CHROOT_DIR=/var/empty` |
| `TARDIGRADE_REQUIRE_UNPRIVILEGED_USER` | bool | `false` | Require runtime to be unprivileged after startup. | `TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true` |
| `TARDIGRADE_WORKER_THREADS` | u32 | `0` | Connection-handling worker threads; `0` means auto CPU count. Changes require restart. | `TARDIGRADE_WORKER_THREADS=8` |
| `TARDIGRADE_LISTENER_SHARDS` | u16 | `0` | `0`/`1` single listener; `>1` starts parallel accept loops where supported. Topology changes require restart. | `TARDIGRADE_LISTENER_SHARDS=4` |
| `TARDIGRADE_ACCEPT_BATCH_LIMIT` | u32 | `64` | Minimum effective value is 1. | `TARDIGRADE_ACCEPT_BATCH_LIMIT=128` |
| `TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY` | u32 | `0` | Yield after this many accepts; `0` disables. | `TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY=32` |
| `TARDIGRADE_EVENT_LOOP_BACKEND` | enum | `default` | `default`, `epoll`, `kqueue`, `io_uring`/`io-uring`; explicit unavailable backends fail startup. | `TARDIGRADE_EVENT_LOOP_BACKEND=io_uring` |
| `TARDIGRADE_EVENT_LOOP_IO_URING_ENTRIES` | u16 | `256` | 64-4096. Ignored by epoll/kqueue. | `TARDIGRADE_EVENT_LOOP_IO_URING_ENTRIES=512` |
| `TARDIGRADE_MASTER_PROCESS` | bool | `false` | Enables master process supervision mode. Current limitation: master/worker mode does not provide coherent PID-file/SIGHUP reload control across all workers; use single-process mode when relying on `tardi reload` and the configured PID file. | `TARDIGRADE_MASTER_PROCESS=true` |
| `TARDIGRADE_WORKER_PROCESSES` | u32 | `1` | Worker processes in master mode. | `TARDIGRADE_WORKER_PROCESSES=4` |
| `TARDIGRADE_BINARY_UPGRADE` | bool | `true` | Enables SIGUSR2 binary upgrade path; effective through the master loop. | `TARDIGRADE_BINARY_UPGRADE=true` |
| `TARDIGRADE_WORKER_RECYCLE_SECONDS` | u32 seconds | `0` | Worker recycle interval; `0` disables. | `TARDIGRADE_WORKER_RECYCLE_SECONDS=3600` |
| `TARDIGRADE_WORKER_CPU_AFFINITY` | string | `""` | CPU list for worker role pinning. | `TARDIGRADE_WORKER_CPU_AFFINITY=0,1,2,3` |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | usize | `1024` | Max queued accepted connections waiting for workers. Changes require restart. | `TARDIGRADE_WORKER_QUEUE_SIZE=4096` |
| `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` | usize | `0` | Per-worker queue depth; `0` no per-worker limit. Changes require restart. | `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH=256` |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | u64 ms | `30000` | Graceful drain timeout. `0` force-closes immediately. Coherent drain-policy changes require restart. | `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS=60000` |
| `TARDIGRADE_FD_SOFT_LIMIT` | u64 | `0` | Desired `RLIMIT_NOFILE` soft limit; `0` leaves OS default. | `TARDIGRADE_FD_SOFT_LIMIT=65535` |
| `TARDIGRADE_CONNECTION_POOL_SIZE` | usize | `256` | Maximum idle connection sessions cached for reuse. | `TARDIGRADE_CONNECTION_POOL_SIZE=512` |
| `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` | bytes | `2097152` | Max retained bytes per active connection; `0` unlimited. | `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES=4194304` |
| `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` | bytes | `0` | Estimated total connection memory cap; `0` unlimited. | `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES=1073741824` |

### Reload Behavior

See [Reload, Drain, and Shutdown](RELOAD_SHUTDOWN.md) for the full lifecycle
contract. `tardi reload` and `SIGHUP` load and validate a new config, prepare
reload-owned resources, then publish it for new requests without draining active
connections. If loading or validation fails before publication, the previous
config remains active.

Reloaded settings fall into three operational categories:

| Reload behavior | Fields / surfaces | Example |
| --- | --- | --- |
| Reloadable or rebuilt in place | Request routing and per-request config fields carried by the published `EdgeConfig`; rate limiter; proxy cache store/path/TTL; response and security headers; H3 `Alt-Svc` advertisement; connection caps; proxy and TLS buffer limits; compression config; logger level; access logging after publication. New requests acquire the newly published config after reload publication. | `TARDIGRADE_RATE_LIMIT_RPS=50` |
| Reload rejected; restart required | Listener-shard topology, native early-data replay mode/capacity, HTTP/3 listener-owned fields (`HTTP3_ENABLED`, `QUIC_PORT`, `HTTP3_ENABLE_0RTT`, `HTTP3_CONNECTION_MIGRATION`, `HTTP3_RETRY_POLICY`, `HTTP3_MAX_DATAGRAM_SIZE`, UDP buffer sizes, ECN, qlog/keylog artifact destinations), native ticket-key source-mode changes, appliance TLS credential configuration (`TLS_CERT_PATH`, `TLS_KEY_PATH`, `TLS_SERVER_NAME`, `TLS_SNI_CERTS` — `hotReloadConfig` rejects any change to these outright, regardless of what the underlying credential type technically supports), and — in every profile — enabling or disabling TLS itself (`hasTlsFiles` toggling): the native credential owner is startup-fixed, so a reload that would turn TLS on for a process that started plaintext (or off for one that started with TLS) is rejected outright rather than publishing a config the runtime cannot honor (#634). | `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE=1200` |
| Config may publish, but live startup-owned state changes only after restart | Bound TCP socket host/port; event-loop backend and io_uring entries; runtime identity/chroot; PID file; master/worker-process topology; worker thread/queue/recycle/affinity settings; FD soft limit; connection-pool capacity; upstream TLS client state; circuit-breaker construction; idempotency TTL; session TTL/max/store path; access-control object; approval TTL/max-pending/store/escalation state; transcript store path; native resumption mode/ticket lifetime/ticket usage; the retired OpenSSL-adapter TLS context inputs (min/max version, ciphers, session cache/tickets, client verification/CA/CRL, OCSP/ACME/watcher settings — these are also rejected outright by config validation if set to anything but their default, see the TLS Termination table above); SSE event-hub capacity; DNS-discovery construction; coherent shutdown-drain policy; upstream-pool policy. On the general profile, a configured SNI identity's certificate/key file *content* at an unchanged path is re-read and applied on every reload — the same store serves both TCP and HTTP/3, so this is a single atomic credential swap, not per-protocol drift (#629's mixed-owner special case, and the OpenSSL terminator it protected against, no longer exist as of #649). Reload may log a restart-required warning for some of these. | `TARDIGRADE_WORKER_THREADS=8` |

`error_log`/`TARDIGRADE_ERROR_LOG_PATH` doesn't fit either row cleanly, and
the live-relocation behavior is directional. Editing the config file is
not sufficient by itself: `envOrDefault()` gives an already-present
process-environment `TARDIGRADE_ERROR_LOG_PATH` precedence over the file
value (with a logged conflict warning), so a reload candidate only
resolves to a *different* effective path if no higher-precedence env value
is already pinning it. When it does resolve to a new path, `SIGHUP`
publishes that effective path but never reopens the fd
(`configureErrorLog()`'s `dup2` runs once at process startup). A following
`SIGUSR1` reopens against whatever `error_log_path` is on the *currently
published* config (`reopenErrorLog()`) — but only when that path is
non-empty:
`reopenErrorLog()` returns immediately when the published path is empty or
`stderr`, without touching the existing file-backed fd. So in the default
single-process deployment, a **config-file** change to a new non-empty
file path (stderr→file, or file A→file B) can be made live with `SIGHUP`
then `SIGUSR1`; a change *back* to empty/`stderr` cannot — that requires
restart, as does any change delivered via `EnvironmentFile=`/container env
(a process-environment change `SIGHUP` never sees) or any destination
change under `master_process true;` (SIGHUP reload isn't coherent across
workers there).

### Proxy Buffer Limits

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES` | bytes | `262144` | Must be positive and less than high watermark. | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES=131072` |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` | bytes | `786432` | Must be `<=` hard limit and no larger than HTTP/2 max receive window. | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES=524288` |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES` | bytes | `1048576` | Must be at least high watermark and at least effective streaming relay allocation. | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES=1048576` |
| `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | bytes | `0` | `0` disables. Nonzero must be at least per-stream hard limit. | `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES=10485760` |
| `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | bytes | `0` | `0` disables. Nonzero must be at least per-stream hard limit. | `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES=1073741824` |

### Protocol Adapters

These adapter surfaces are in-tree and configurable, but they are outside the
stable HTTP/1.1, HTTP/2, and HTTP/3/QUIC Core v1 edge contract unless the
[support matrix](SUPPORT_MATRIX.md) marks them `stable`.

| Env key / directive | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `fastcgi_pass` / `TARDIGRADE_FASTCGI_UPSTREAM` | endpoint | `""` | Location `fastcgi_pass` is wired to request dispatch. Top-level / env `TARDIGRADE_FASTCGI_UPSTREAM` is parsed and logged, but does not install a route by itself. | `fastcgi_pass unix:/run/php.sock;` |
| `fastcgi_index` / `TARDIGRADE_FASTCGI_INDEX` | filename | `index.php` | Default FastCGI directory index used by dispatched FastCGI location routes. | `TARDIGRADE_FASTCGI_INDEX=index.php` |
| `fastcgi_param` / `TARDIGRADE_FASTCGI_PARAMS` | key/value list | `[]` | Directive appends `NAME value`; env format is <code>NAME=value&#124;NAME2=value2</code>; used by dispatched FastCGI location routes. | `TARDIGRADE_FASTCGI_PARAMS=APP_ENV=prod` |
| `scgi_pass` / `TARDIGRADE_SCGI_UPSTREAM` | endpoint | `""` | Parsed. Current config-file lowering maps location `scgi_pass` to a `scgi:` proxy target, but the gateway does not install a live SCGI route from this setting. | `TARDIGRADE_SCGI_UPSTREAM=127.0.0.1:4100` |
| `uwsgi_pass` / `TARDIGRADE_UWSGI_UPSTREAM` | endpoint | `""` | Parsed. Current config-file lowering maps location `uwsgi_pass` to a `uwsgi:` proxy target, but the gateway does not install a live uWSGI route from this setting. | `TARDIGRADE_UWSGI_UPSTREAM=127.0.0.1:4200` |
| `smtp_pass` / `TARDIGRADE_SMTP_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live mail route in the current gateway. | `TARDIGRADE_SMTP_UPSTREAM=127.0.0.1:2525` |
| `imap_pass` / `TARDIGRADE_IMAP_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live mail route in the current gateway. | `TARDIGRADE_IMAP_UPSTREAM=127.0.0.1:1143` |
| `pop3_pass` / `TARDIGRADE_POP3_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live mail route in the current gateway. | `TARDIGRADE_POP3_UPSTREAM=127.0.0.1:1110` |
| `TARDIGRADE_GRPC_UPSTREAM` | URL | `""` | Parsed and included in startup diagnostics; does not install a live gRPC route in the current gateway. | `TARDIGRADE_GRPC_UPSTREAM=http://127.0.0.1:50051` |
| `TARDIGRADE_MEMCACHED_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live Memcached route in the current gateway. | `TARDIGRADE_MEMCACHED_UPSTREAM=127.0.0.1:11211` |
| `TARDIGRADE_TCP_PROXY_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live TCP proxy route in the current gateway. | `TARDIGRADE_TCP_PROXY_UPSTREAM=127.0.0.1:9000` |
| `TARDIGRADE_UDP_PROXY_UPSTREAM` | endpoint | `""` | Parsed and included in startup diagnostics; does not install a live UDP proxy route in the current gateway. | `TARDIGRADE_UDP_PROXY_UPSTREAM=127.0.0.1:9001` |
| `TARDIGRADE_STREAM_SSL_TERMINATION` | bool | `false` | Parsed and included in stream-proxy startup diagnostics; no live stream route is installed by this flag alone. | `TARDIGRADE_STREAM_SSL_TERMINATION=true` |

### WebSocket And Long-Lived Response Streams

WebSockets are relayed per location with `proxy_websocket on;` (see
[WebSocket proxying](#websocket-proxying-proxy_websocket)); its global settings are:

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_PROXY_WEBSOCKET_RELOAD` | enum | `preserve` | Default hot-reload behavior for open tunnels, `preserve` or `drain`; a location's `proxy_websocket_reload` overrides it. Config directive: `proxy_websocket_reload`. | `TARDIGRADE_PROXY_WEBSOCKET_RELOAD=drain` |
| `TARDIGRADE_PROXY_WEBSOCKET_RELOAD_TIMEOUT_MS` | u32 ms | `30000` | Default drain window for `drain` tunnels. Config directive: `proxy_websocket_reload_timeout_ms`. | `TARDIGRADE_PROXY_WEBSOCKET_RELOAD_TIMEOUT_MS=10000` |
| `TARDIGRADE_PROXY_WEBSOCKET_MAX_TUNNELS` | u32 | `0` (a quarter of the descriptor soft limit, at most 4096) | Maximum concurrent WebSocket tunnels per process. A handshake over the cap gets 503 before the origin is contacted. Config directive: `proxy_websocket_max_tunnels`. | `TARDIGRADE_PROXY_WEBSOCKET_MAX_TUNNELS=256` |
| `TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS` | u32 | `0` (one per four CPUs, between 1 and 4) | Threads that relay established WebSocket tunnels; each owns many tunnels. Read at startup only (0-64); a hot reload that changes it is rejected and requires restart. Config directive: `proxy_websocket_reactor_threads`. | `TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS=2` |

Long-lived streamed HTTP responses, including SSE, have a separate generic
lifecycle contract. The HTTP/1 streaming relay identifies them from HTTP
response metadata before committing the downstream head; Tardigrade does not
inspect event or application payloads.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE` | positive u32 | `256` | Process-wide maximum number of admitted long-lived response streams. Config directive: `proxy_response_stream_max_active`. This cap cannot be overridden per location. | `TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE=512` |
| `TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD` | enum | `preserve` | Default policy for streams admitted by a configuration generation: `preserve` or `drain`. A location's `proxy_response_stream_reload` overrides it. Config directive: `proxy_response_stream_reload`. | `TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD=drain` |
| `TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD_TIMEOUT_MS` | u32 ms | `30000` | Default window after the first successful superseding reload before a `drain` stream is due to close. `0` means immediately. A location's `proxy_response_stream_reload_timeout_ms` overrides it. Config directive: `proxy_response_stream_reload_timeout_ms`. | `TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD_TIMEOUT_MS=10000` |

Only an absent setting takes its default. Empty strings, values containing
units (for example `30s`), signed values, overflow, an active cap of `0`, and
reload policies other than `preserve` or `drain` reject startup, `tardi check`,
or a reload. A rejected reload publishes no generation and therefore cannot
schedule an existing `drain` stream. The reload policy and timeout are captured
from the admission generation; a later reload cannot change or extend them.

Server-sent events need no special setting: proxy them as a streamed response
(`proxy_streaming response;` on the location, or
`TARDIGRADE_PROXY_STREAMING_MODE=response`). See
[PROXY_STREAMING.md](PROXY_STREAMING.md#server-sent-events).

The older `TARDIGRADE_WEBSOCKET_ENABLED`, `TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS`,
`TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE`, `TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS`
and `TARDIGRADE_SSE_*` keys belonged to built-in realtime endpoints that were
removed. They are still parsed but have no effect, and are being retired.

### DNS Discovery

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST` | hostname | `""` | When non-empty, periodically resolves A/AAAA addresses and merges them into upstream pool. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST=app.service.local` |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT` | u16 | `80` | Port assigned to DNS-discovered addresses. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT=8080` |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS` | bool | `false` | Use HTTPS for DNS-discovered upstreams. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS=true` |
| `TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS` | u64 ms | `30000` | Re-resolution interval (A/AAAA); in SRV mode, the maximum refresh interval. | `TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS=10000` |
| `TARDIGRADE_UPSTREAM_SRV_NAME` | SRV name | `""` | DNS SRV discovery (#766): resolves `_service._proto.name`, then each target's A/AAAA. Wins over `..._DNS_DISCOVERY_HOST`. | `TARDIGRADE_UPSTREAM_SRV_NAME=_api._tcp.service.internal` |
| `TARDIGRADE_UPSTREAM_SRV_TLS` | bool | `false` | Use HTTPS for SRV-discovered upstreams. | `TARDIGRADE_UPSTREAM_SRV_TLS=true` |
| `TARDIGRADE_UPSTREAM_SRV_MIN_REFRESH_MS` | u64 ms | `5000` | Lower bound of the TTL-derived refresh interval. | `TARDIGRADE_UPSTREAM_SRV_MIN_REFRESH_MS=2000` |
| `TARDIGRADE_UPSTREAM_SRV_STALE_MAX_MS` | u64 ms | `300000` | How long the last good set survives SERVFAIL/timeouts. | `TARDIGRADE_UPSTREAM_SRV_STALE_MAX_MS=120000` |
| `TARDIGRADE_UPSTREAM_SRV_TIMEOUT_MS` | u32 ms | `2000` | Per-nameserver SRV query timeout. | `TARDIGRADE_UPSTREAM_SRV_TIMEOUT_MS=1000` |
| `TARDIGRADE_UPSTREAM_SRV_NAMESERVERS` | csv | `""` | Nameservers for SRV queries (`ip`, `ip:port`, `[ip6]:port`); empty uses `/etc/resolv.conf`. | `TARDIGRADE_UPSTREAM_SRV_NAMESERVERS=10.0.0.2:53` |

#### DNS SRV upstream discovery

```sh
TARDIGRADE_UPSTREAM_SRV_NAME=_api._tcp.service.internal
TARDIGRADE_UPSTREAM_SRV_TLS=true
```

- **Priority/weight:** each SRV priority is a group; only the first group that
  has a healthy endpoint is ever used, and lower-priority groups are unreachable
  while it has any healthy member (including for sticky affinity). Inside the
  active group, `round_robin` runs smooth weighted round-robin over the SRV
  *targets* with their exact weights (weight 0 counts as 1), then rotates over
  the chosen target's A/AAAA addresses, so a target's share does not depend on
  how many addresses it has. The other algorithms (`least_connections`,
  `ip_hash`, `generic_hash`, `random_two_choices`) choose among the active
  group's addresses and treat them equally. Sticky affinity works for
  discovery-only pools. Health checks apply to each `ip:port`; slow start is not
  applied to discovered endpoints.
- **Refresh:** TTL-driven, clamped to `[SRV_MIN_REFRESH_MS, DNS_REFRESH_INTERVAL_MS]`
  with ±10% jitter. Resolution runs on a joinable background thread (shutdown
  waits for it); the live set is
  swapped atomically, and removed endpoint strings stay valid for 10 minutes so
  in-flight requests are never corrupted.
- **Stale policy:** NXDOMAIN, an empty answer or the RFC 2782 `.` target clears
  the set immediately. SERVFAIL, timeouts and "no target resolved" keep the last
  good set for up to `SRV_STALE_MAX_MS` after the last success (retrying with
  backoff), then clear it. Truncated UDP answers are used as received; there is
  no TCP fallback. Replies must come from the queried nameserver (connected UDP
  socket) and carry a matching random query id. At most 32 SRV records and 64 endpoints are kept.
- **TLS identity:** endpoints are dialed by IP, so verification uses
  `TARDIGRADE_UPSTREAM_TLS_SERVER_NAME` if set, otherwise the logical service
  name (the SRV name without `_service._proto.`, e.g. `service.internal`) —
  never the SRV target and never the IP. This name is process-wide, like the
  existing setting. mTLS uses the existing `TARDIGRADE_UPSTREAM_TLS_CLIENT_*`.
- **Metrics:** `tardigrade_upstream_discovery_endpoints{role}`,
  `..._stale`, `..._refresh_total`, `..._refresh_failures_total`,
  `..._changes_total`.

## Full Annotated Example

```nginx
# This complete example targets the general TLS profile (the default).
# Appliance TLS accepts one top-level identity only, so the server-block TLS
# material below would be rejected there.

# `worker_connections` caps total active client connections through
# TARDIGRADE_MAX_ACTIVE_CONNECTIONS.
worker_connections 4096;

# Write the active process id for service managers and send info-or-higher
# startup/runtime diagnostics to an explicit file instead of stderr.
pid /run/tardigrade.pid;
error_log /var/log/tardigrade/error.log info;

# Serve TLS on 8443 and advertise HTTP/2. Cert/key must be configured together.
# `tls_server_name` is intentionally omitted because this is a general-profile
# example; that field is required by the appliance profile.
listen 0.0.0.0:8443 http2;
tls_cert_path /etc/tardigrade/tls/fullchain.pem;
tls_key_path /etc/tardigrade/tls/privkey.pem;

# Because this config uses server blocks, host selection is based on those
# blocks rather than a top-level `server_name`. Represent every served host with
# a block. Top-level TLS settings are inherited by each selected block.
server {
    server_name example.com www.example.com;
    root /srv/www/example;
    try_files $uri /index.html;

    # Exact match routes are evaluated before prefixes and regexes, making this
    # a cheap health endpoint that never touches disk or upstreams.
    location = /health {
        return 200 ok;
    }

    # `^~` gives the assets prefix priority over regex locations. `index ""`
    # opts out of the default `index.html` directory fallback for this static
    # subtree.
    location ^~ /assets/ {
        root /srv/www/example;
        index "";
        autoindex off;
    }

    # Prefix route: proxy application traffic and stream upstream responses
    # instead of fully buffering large downloads. Request bodies remain buffered
    # because the mode is `response`, not `full`.
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_streaming response;
    }
}

# API virtual host: host-specific TLS material is merged into SNI config, and
# locations inside the block only apply when Host matches api.example.com.
server {
    server_name api.example.com;
    tls_cert_path /etc/tardigrade/tls/api.crt;
    tls_key_path /etc/tardigrade/tls/api.key;
    upstream_base_url http://127.0.0.1:9000;

    location = /health {
        return 200 api-ok;
    }

    # Plain prefix fallback for every API hostname path not handled above.
    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
```

Common production environment overrides:

```bash
export TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf
export TARDIGRADE_RATE_LIMIT_RPS=100
export TARDIGRADE_RATE_LIMIT_BURST=200
export TARDIGRADE_METRICS_PATH=/status/metrics
export TARDIGRADE_METRICS_REQUIRE_AUTH=true
export TARDIGRADE_ACCESS_LOG_FORMAT=json
export TARDIGRADE_REDACT_HEADERS=authorization,cookie,set-cookie
export TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=3
export TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY=true
export TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=5000
export TARDIGRADE_UPSTREAM_PROBE_PATH=/health
export TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS=30000
```

### Downstream mTLS

`TARDIGRADE_TLS_CLIENT_VERIFY=true` makes the native TLS 1.3 listener send a
`CertificateRequest` and verify the client's certificate chain with the same
pure-Zig PKI path validation used for upstream trust, against only the CAs in
`TARDIGRADE_TLS_CLIENT_CA_PATH`:

- the chain must build to a configured anchor within
  `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH`, with valid signatures and validity
  periods, CA/key-usage constraints and name constraints enforced;
- every certificate that carries an Extended Key Usage must allow
  `clientAuth` (a `serverAuth`-only certificate is rejected); no hostname
  policy applies to a client certificate;
- the client must prove possession of the leaf key (CertificateVerify);
- the chain is bounded (entry count and 8 KiB per certificate) and a
  malformed or oversized chain fails the handshake closed.

`required` (default) fails the handshake with a `certificate_required` alert
when no certificate is offered; `TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL=true`
lets certificate-less clients through (they simply carry no identity), while a
certificate that is presented must still verify.

**Identity propagation.** For requests on a connection with a verified client
certificate, proxied upstream requests (HTTP/1.1 and HTTP/2 downstream) carry:

| Header | Value |
|---|---|
| `X-Tardigrade-Client-Cert-Verified` | `1` |
| `X-Tardigrade-Client-Cert-Fingerprint-Sha256` | lowercase hex SHA-256 of the leaf DER (the stable identity key) |
| `X-Tardigrade-Client-Cert-Subject` / `-Issuer` | RFC 2253-style DN, printable ASCII, escaped |
| `X-Tardigrade-Client-Cert-Serial` | hex serial |
| `X-Tardigrade-Client-Cert-San-Dns` / `-San-Email` / `-San-Uri` | first SAN of each type |

Values are derived only from the verified certificate, are bounded
(512 bytes per DN, 255 per SAN) and escaped to printable ASCII; a field that
does not fit is omitted rather than truncated. Every client-supplied
`X-Tardigrade-*` request header is stripped before proxying, so a client
cannot forge these. Upstreams should trust them only from Tardigrade (use the
signed trust headers or network isolation). The raw certificate is never
logged or exported. Verified identity is currently asserted on the HTTP proxy
paths; FastCGI/SCGI/uwsgi, `forward_auth` subrequests and location-level
"require certificate" routing are not yet certificate-aware.

**Rotation.** The CA bundle is re-read on every config reload and published as
one atomic generation: a bundle that fails to load rejects the whole reload
and the serving trust set keeps verifying, and a handshake already in flight
finishes against the generation it started with. Enabling
`TARDIGRADE_TLS_CLIENT_VERIFY` on a process that started without it requires a
restart. Revocation (CRL/OCSP) is not consulted: remove a revoked CA or issue
short-lived client certificates; the validator's revocation seam stays
disabled until runtime OCSP/CRL support exists.

**Protocol coverage.** HTTP/1.1 and HTTP/2 over TCP TLS are supported. The
QUIC/HTTP-3 handshake does not request client certificates, so the
combination with `TARDIGRADE_HTTP3_ENABLED` is rejected at config validation
rather than advertised. Client verification is per listener, not per SNI
server block.

## Validation Notes

- `TARDIGRADE_TLS_CERT_PATH` and `TARDIGRADE_TLS_KEY_PATH` must be both set or
  both empty.
- `TARDIGRADE_TLS_CLIENT_VERIFY=true` requires `TARDIGRADE_TLS_CLIENT_CA_PATH`,
  `TARDIGRADE_TLS_CERT_PATH`/`TARDIGRADE_TLS_KEY_PATH` (otherwise the listener
  would serve plaintext), a depth of 1 to 8, and `TARDIGRADE_HTTP3_ENABLED=false`.
- `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` must be 0-11.
- `TARDIGRADE_OTEL_SAMPLE_RATE` must be 0-100.
- `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` has a minimum effective value of 1; `0`
  is clamped and malformed values fall back to 1.
- `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` must be at least 1.
- `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` must be 1-1048576 bytes.
- Many integer fields use permissive parsing and fall back to defaults on
  malformed values. Replay and TLS buffer fields fail validation instead.
