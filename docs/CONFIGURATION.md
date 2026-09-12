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
| `rewrite` | pattern/replacement/flag | n/a | Default flag is `last`; accepted flags are `last`, `break`, `redirect`, `permanent`. | `rewrite ^/old/(.*)$ /new/$1 last;` |
| `error_page` | statuses/target | `[]` | Status codes followed by path or HTTP(S) URL target. | `error_page 502 503 /50x.html;` |
| `auth` | enum | `off` | `off`, `required`. | `auth required;` |
| `proxy_streaming` / `proxy_streaming_mode` | enum | `inherit` | `inherit`, `off`/`buffered`, `response`/`responses`, `full`/`request_response`/`request-response`. | `proxy_streaming response;` |
| `early_data` | enum | `off` | `off`, `replay_safe`/`replay-safe`. | `early_data replay_safe;` |
| `proxy_early_data` | enum | `off` | `off`, `rfc8470`/`rfc-8470`; valid only with `proxy_pass`. | `proxy_early_data rfc8470;` |

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
the retired OpenSSL adapter (TLS 1.2, cipher overrides, downstream mTLS,
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
| `TARDIGRADE_TLS_CLIENT_CA_PATH` | path | `""` | Required when `TARDIGRADE_TLS_CLIENT_VERIFY=true`. | `TARDIGRADE_TLS_CLIENT_CA_PATH=/etc/tls/clients.pem` |
| `TARDIGRADE_TLS_CLIENT_VERIFY` | bool | `false` | Retired downstream client-cert (mTLS) verification; must be false. | (unset) |
| `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH` | u32 | `3` | Unused; retained for config-file compatibility. | (unset) |
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
| `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` | CSV strings | `[]` | Trusted peer hosts/addresses allowed to supply inbound forwarded-client and geo metadata; also used by control-plane proxy trust enforcement. | `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES=192.0.2.10,192.0.2.11` |
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

### WebSocket And SSE

These are configurable in-tree surfaces outside the stable Core v1 baseline.

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_WEBSOCKET_ENABLED` | bool | `false` | Enables WebSocket handling. | `TARDIGRADE_WEBSOCKET_ENABLED=true` |
| `TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS` | u32 ms | `30000` | WebSocket idle timeout. | `TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS=60000` |
| `TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE` | bytes | `65536` | Maximum WebSocket frame size. | `TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE=131072` |
| `TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS` | u32 ms | `15000` | Ping interval. | `TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS=30000` |
| `TARDIGRADE_SSE_ENABLED` | bool | `false` | Enables SSE handling. | `TARDIGRADE_SSE_ENABLED=true` |
| `TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC` | usize | `128` | Retained events per topic. | `TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC=1024` |
| `TARDIGRADE_SSE_POLL_INTERVAL_MS` | u32 ms | `250` | SSE poll interval. | `TARDIGRADE_SSE_POLL_INTERVAL_MS=500` |
| `TARDIGRADE_SSE_MAX_BACKLOG` | u32 | `128` | Maximum SSE backlog. | `TARDIGRADE_SSE_MAX_BACKLOG=512` |
| `TARDIGRADE_SSE_IDLE_TIMEOUT_MS` | u32 ms | `30000` | SSE idle timeout. | `TARDIGRADE_SSE_IDLE_TIMEOUT_MS=60000` |

### DNS Discovery

| Env key | Type | Default | Valid values / behavior | Example |
| --- | --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST` | hostname | `""` | When non-empty, periodically resolves A/AAAA addresses and merges them into upstream pool. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST=app.service.local` |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT` | u16 | `80` | Port assigned to DNS-discovered addresses. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT=8080` |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS` | bool | `false` | Use HTTPS for DNS-discovered upstreams. | `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS=true` |
| `TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS` | u64 ms | `30000` | Re-resolution interval. | `TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS=10000` |

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

## Validation Notes

- `TARDIGRADE_TLS_CERT_PATH` and `TARDIGRADE_TLS_KEY_PATH` must be both set or
  both empty.
- `TARDIGRADE_TLS_CLIENT_VERIFY=true` requires `TARDIGRADE_TLS_CLIENT_CA_PATH`.
- `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` must be 0-11.
- `TARDIGRADE_OTEL_SAMPLE_RATE` must be 0-100.
- `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` has a minimum effective value of 1; `0`
  is clamped and malformed values fall back to 1.
- `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` must be at least 1.
- `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` must be 1-1048576 bytes.
- Many integer fields use permissive parsing and fall back to defaults on
  malformed values. Replay and TLS buffer fields fail validation instead.
