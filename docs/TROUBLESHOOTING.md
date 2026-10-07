# Troubleshooting

This is the canonical operator runbook for diagnosing Tardigrade failures. It
assumes you have a symptom (a bad response, a process that won't start, a
metric that looks wrong) and walks you from that symptom to a concrete check,
a likely cause, a fix, and a way to verify the fix worked.

It is deliberately not a second copy of the reference docs. Where a fix
requires a full directive/environment-variable listing, this guide links to
[Configuration](CONFIGURATION.md), [Deployment](DEPLOYMENT.md),
[Reload, drain, and shutdown](RELOAD_SHUTDOWN.md), or
[Observability](OBSERVABILITY.md) instead of restating them.

All examples use the canonical packaged config path,
`/etc/tardigrade/tardigrade.conf`, and the canonical binary name, `tardi`
(`tardigrade` also works as a compatibility alias installed by the release
script — see [README.md#install](../README.md#install)). Substitute your own
config path throughout; **always pass it explicitly** (`-c <path>` or a
positional argument) for packaged deployments rather than relying on
defaults. For local first-run use, `tardi check` with no path validates
`./tardigrade.conf` directly; `tardi run` discovers that same local file
only when no higher-precedence `TARDIGRADE_CONFIG_PATH` override is set --
see [Configuration](CONFIGURATION.md) for the full runtime search order.

## Contents

1. [Five-minute triage](#1-five-minute-triage)
2. [Config does not parse or validate](#2-config-does-not-parse-or-validate)
3. [Listener fails to bind / service is unreachable](#3-listener-fails-to-bind--service-is-unreachable)
4. [Route does not match](#4-route-does-not-match)
5. [Static files return 404 or 403](#5-static-files-return-404-or-403)
6. [Upstream returns 502 / 504 / 503](#6-upstream-returns-502--504--503)
7. [TLS certificate/key errors](#7-tls-certificatekey-errors)
8. [Health checks mark an upstream down](#8-health-checks-mark-an-upstream-down)
9. [Metrics endpoint unavailable](#9-metrics-endpoint-unavailable)
10. [Logs are missing / going somewhere unexpected](#10-logs-are-missing--going-somewhere-unexpected)
11. [Reload did not apply expected changes](#11-reload-did-not-apply-expected-changes)
12. [Performance appears worse than expected](#12-performance-appears-worse-than-expected)
13. [Still stuck?](#13-still-stuck)

---

## 1. Five-minute triage

### Symptoms

Something about Tardigrade is wrong and you haven't yet isolated whether
it's a config problem, a process problem, or a network/routing problem.

### First checks

```bash
tardi version

tardi check /etc/tardigrade/tardigrade.conf

tardi print-config -c /etc/tardigrade/tardigrade.conf

tardi routes -c /etc/tardigrade/tardigrade.conf

tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

For a packaged/systemd deployment, add the process-level checks:

```bash
tardi status --pid-file /run/tardigrade/tardigrade.pid
sudo systemctl status tardigrade
sudo journalctl -u tardigrade -n 100 --no-pager
```

Then probe the listener you're actually diagnosing. Only do this if the
config you're checking actually defines a `/health` route — it isn't a
built-in path, it's a convention used throughout `examples/` (a
`location = /health { return 200 ok; }` block); `tardi routes` above tells
you whether yours has one. Send a `Host` header that matches your config's
`server_name`:

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/health
```

For TLS, make the **TLS identity (SNI) and the HTTP `Host` agree** — `-H
'Host: ...'` only rewrites the HTTP request line/header *after* the
handshake, it does not set the `ClientHello` SNI. Sending a request to a
raw IP with `-H 'Host: localhost'` can select the wrong certificate (or the
wrong SNI-routed path) while the HTTP layer routes as `localhost`. Use
`--resolve` so both the transport name and the HTTP host are `localhost`:

```bash
curl -v --resolve localhost:8443:127.0.0.1 https://localhost:8443/health
```

`-k`/`--insecure` here would skip certificate trust validation entirely,
which is fine for a first-pass reachability check but not for confirming
the certificate itself is correct — see [§7](#7-tls-certificatekey-errors)
for a validating check once you know the listener responds at all.

> The starter config and every example match on a specific `server_name`
> (`localhost` by default). A request whose `Host` (and, for TLS, SNI)
> doesn't match any configured `server_name` returns `404`, not `200` —
> that's expected virtual-host behavior, not a bug. Match your config's
> `server_name`, or configure an unnamed/default `server {}` block (a block
> with no `server_name` names) if you need one to catch non-matching hosts —
> see [CONFIGURATION.md's Server Blocks section](CONFIGURATION.md#server-blocks).

**Critical inspection-command warning: `print-config`, `routes`, and
`upstreams` inspect the effective configuration resolved by *that CLI
invocation* — the selected config path plus that process's own current
environment (env values take precedence over file values, same as
everywhere else). They do not talk to a running Tardigrade process, they
can differ from the actual service's environment (an interactive shell
usually doesn't inherit systemd's `EnvironmentFile=`), and they do not
prove that a previous `tardi reload`/`SIGHUP` was applied successfully.**
Running any of the three after editing a config file only tells you what
*this invocation* resolves — not that the live service process resolves
the same thing, and not that it's actually serving it. For live reload
state, use the runtime status/log/metric surfaces in
[§11](#11-reload-did-not-apply-expected-changes), primarily
`GET /tardigrade/reload/status`.

### Likely causes

This pass doesn't diagnose a specific cause by itself — it tells you which
section below to jump to:

- `tardi check`/`print-config` fails → [§2](#2-config-does-not-parse-or-validate)
- the process won't start, or `status`/`systemctl status` shows it isn't
  running → [§3](#3-listener-fails-to-bind--service-is-unreachable)
- the process is up and `tardi routes`/`upstreams` look right, but a live
  request behaves unexpectedly → whichever of
  [§4](#4-route-does-not-match)–[§9](#9-metrics-endpoint-unavailable)
  matches the symptom (routing, static files, upstream status code, TLS,
  health, or metrics)
- a config edit doesn't seem to be taking effect → [§11](#11-reload-did-not-apply-expected-changes)

### Concrete fixes

None at this stage — apply the fix in whichever section your triage pointed
you to.

### Verify the fix

None at this stage — each section below has its own verification step.

### Related documentation

- [CONFIGURATION.md](CONFIGURATION.md#configuration-reference) — full
  effective-value precedence (process environment, then config file, then
  decrypted secrets, then built-in defaults); check there before assuming
  a config-file edit is what's actually in effect, since a `TARDIGRADE_*`
  environment variable set on the process always wins.
- [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md) — the live reload contract
  referenced above.

## 2. Config does not parse or validate

### Symptoms

`tardi check` (or `tardi run`, `sudo systemctl start tardigrade`) exits
non-zero with an `error: configuration parse failed …` or
`error: configuration validation failed …` message instead of
`configuration valid`.

### First checks

```bash
tardi check /etc/tardigrade/tardigrade.conf
echo "exit code: $?"
```

Exit code `2` is the deterministic configuration/preflight failure class —
this covers more than syntax/semantic validation: a missing selected or
`include`d config file, a permission error reading one, and (on the
appliance TLS profile) credential-preflight failures all also exit `2`.
Exit code `1` is reserved for whatever isn't classified as a
configuration/preflight error — an unexpected internal/runtime failure —
so don't spend time re-reading the config file for a `1`; the printed
diagnostic text tells you which specific class occurred either way.

For package deployments, also check as the service user, since file
permissions differ between your shell and the service account:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

**This check does not see `/etc/tardigrade/tardigrade.env`.** A value that
only exists there (a secret bootstrap reference, a port override, a TLS path
override) can make the standalone check pass while the actual service still
fails to start — see [DEPLOYMENT.md's
`ExecStartPre` note](DEPLOYMENT.md#commands) for why the unit's own
`ExecStartPre` (not this ad hoc invocation) is the real pre-flight gate.

### Likely causes

Syntax-level (the parser rejects the file before semantic validation runs):

- missing `;` at the end of a directive
- mismatched `{`/`}` — the parser requires the block opener on a line ending
  in `{` and a closing line containing only `}`
- malformed `server {}` / `location {}` block
- an `include` path or glob that doesn't resolve
- a `${VAR}` interpolation that references an unset environment variable

Semantic/resource-level (the file parses, but a value is invalid):

- an out-of-range port, invalid enum value, or malformed URL
- a `tls_cert_path` set without a matching `tls_key_path` (or vice versa) —
  Tardigrade requires both or neither, at both the top level and per
  `server {}` block
- a malformed `proxy_pass`/`upstream_base_url`
- contradictory settings (e.g. both HTTP/1.1 and HTTP/2 disabled)
- pointing at the wrong config file entirely — double-check
  `-c`/`--config`, `TARDIGRADE_CONFIG_PATH`, and the runtime discovery order
  in [CONFIGURATION.md](CONFIGURATION.md#configuration-reference)
- a process-environment `TARDIGRADE_*` variable silently overriding a
  file value you just edited (env wins — see the precedence note above)

`tardi check`/`tardi run` also print non-fatal `config warning: …` lines for
risky-but-valid settings (upstream TLS verification disabled, rate limiting
disabled, HSTS off with TLS configured, 0-RTT enabled, etc.) — read these
even when the check otherwise passes.

### Concrete fixes

Fix the specific line the diagnostic names, then re-run `tardi check`. For
syntax errors, work from the top of the file down — one missing `;` can
cascade into misleading downstream parse errors. For "config file not
found", pass the exact path you intend with `-c`/`--config` rather than
relying on discovery order.

### Verify the fix

```bash
tardi check /etc/tardigrade/tardigrade.conf
```

should print `configuration valid` followed by the config summary, with exit
code `0`. Then confirm the specific fields you changed:

```bash
tardi print-config -c /etc/tardigrade/tardigrade.conf
```

### Related documentation

- [Configuration reference](CONFIGURATION.md) — full directive/env-var
  listing, syntax rules, and precedence.
- [examples/](../examples/README.md) — copy/paste-runnable configs, CI-checked
  with `tardi check` on every change.

## 3. Listener fails to bind / service is unreachable

### A. Tardigrade never binds

#### Symptoms

The process exits immediately (`tardi run` prints `error: tardigrade exited:
…` and exits non-zero) or `systemctl start tardigrade` / `docker compose up`
never reaches a healthy state. No `Tardigrade edge listening on …` line
appears in the logs.

#### First checks

```bash
tardi check /etc/tardigrade/tardigrade.conf
tardi print-config -c /etc/tardigrade/tardigrade.conf
sudo ss -ltnp
```

**`tardi check` never binds a socket** — it's a dry parse/validate only, so
a passing check does not rule out a bind failure. `ss -ltnp` (or
`sudo journalctl -u tardigrade -n 50 --no-pager` for the actual startup
error) is what tells you whether the port is already taken.

#### Likely causes

- the port is already in use — by a previous Tardigrade instance that
  didn't fully stop, or by an unrelated process; `ss -ltnp` names the owning
  PID
- an invalid or non-local `TARDIGRADE_LISTEN_HOST`/`listen` address (a host
  that doesn't resolve to a local interface)
- attempting to bind `80`/`443` directly without the capability to do so
  (see below)
- systemd sandboxing (`ProtectSystem=full`, `ProtectHome=true`, etc.)
  blocking a path your config references outside the allowed directories

#### Concrete fixes

Kill or reassign the conflicting process, or change `listen`/
`TARDIGRADE_LISTEN_PORT`. **For privileged ports (`80`/`443`), do not run
Tardigrade as root.** Follow [DEPLOYMENT.md's ports and privilege
model](DEPLOYMENT.md#ports-and-privilege-model): put a frontend load
balancer or NAT in front and expose `80`/`443` there, or grant the systemd
unit `AmbientCapabilities=CAP_NET_BIND_SERVICE` (plus
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`) so the unprivileged
`tardigrade` service account can bind the port directly. Tardigrade can also
be configured to refuse to start under UID 0 at all
(`TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true`) — if you see a startup
rejection referencing this, that guard is working as intended; fix the
deployment, don't disable the guard.

If a systemd hardening directive is blocking a path your deployment
legitimately needs, extend that directive's allowlist for the specific path
rather than loosening `ProtectSystem`/`ProtectHome` globally — see
[DEPLOYMENT.md's filesystem layout section](DEPLOYMENT.md#host-filesystem-layout).

#### Verify the fix

```bash
sudo systemctl restart tardigrade
sudo journalctl -u tardigrade -n 20 --no-pager
```

Look for `Tardigrade edge listening on <host>:<port>`, then confirm with
`ss -ltnp` and a local `curl`.

### B. Listener exists but remote clients cannot connect

#### Symptoms

`ss -ltnp` shows Tardigrade bound and listening, `curl` succeeds from
`127.0.0.1` on the host itself, but remote clients time out or get
connection-refused.

#### First checks

Prove local connectivity first (it isolates "Tardigrade problem" from
"network path problem"):

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/health
```

(Substitute your own `server_name` and port; the values above match the
starter config used throughout this guide.)

Then check what address it's actually bound to:

```bash
sudo ss -ltnp | grep tardi
```

#### Likely causes

- bound to `127.0.0.1` (loopback-only) instead of `0.0.0.0` or a specific
  reachable interface
- a host or cloud-provider firewall/security-group blocking the port
- a load balancer or NAT pointing at the wrong backend target/port
- under Docker, the container port was never published (missing/incorrect
  `ports:` mapping in `compose.yaml`)
- the client is using the wrong scheme (`http://` against a TLS-only
  listener, or `https://` against a plaintext one)

#### Concrete fixes

Set `TARDIGRADE_LISTEN_HOST`/`listen` to a reachable address, open the
firewall/security-group rule for the port, fix the load balancer's backend
target, or add/correct the Docker `ports:` mapping (see
[DEPLOYMENT.md's Docker section](DEPLOYMENT.md#docker)).

#### Verify the fix

Repeat the remote client's request (or `curl` from an external host) and
confirm you get the expected response rather than a timeout/connection
refused.

### Related documentation

- [DEPLOYMENT.md](DEPLOYMENT.md) — filesystem layout, permissions, systemd
  unit contract, Docker port publication.
- [CONFIGURATION.md](CONFIGURATION.md#listener-and-protocol) — listener and
  protocol fields.

## 4. Route does not match

### Symptoms

A request that should hit a specific `location`/`proxy_pass`/`return`
instead gets routed somewhere else, returns `404`, or hits the wrong
upstream.

### First checks

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
```

Then reproduce the exact request, including the `Host` header if your config
uses `server_name`/multiple `server {}` blocks:

```bash
curl -v -H 'Host: api.example.com' \
  http://127.0.0.1:8069/api/users
```

### Likely causes

- **wrong `Host` / virtual host**: when any `server {}` block exists, host
  selection is based on server blocks only — the first matching named block
  wins, then an unnamed/default block, then the first block as a last-resort
  fallback. A selected named fallback that doesn't actually match the
  request `Host` is rejected outright (`404`), not silently served. See
  [CONFIGURATION.md's Server Blocks section](CONFIGURATION.md#server-blocks).
- **a different server block was selected than you expect** because of the
  fallback order above
- **exact vs. prefix mismatch**: `location = /path` only matches that exact
  path, not `/path/` or `/path/sub`
- **priority-prefix shadowing**: `location ^~ /path/` wins over any regex or
  plain-prefix location for requests under that prefix, even a regex that
  would otherwise match more specifically
- **an earlier regex matched first**: `location ~`/`~*` blocks are evaluated
  in declaration order, and the first match wins — not the most specific one
- **the request is hitting a different listener, process, or config
  entirely** — a second Tardigrade instance, a stale process still bound
  from before a restart, or the wrong `-c`/`TARDIGRADE_CONFIG_PATH`
- **an edited config was never successfully reloaded** — see
  [§11](#11-reload-did-not-apply-expected-changes); `tardi routes` only
  shows what this CLI invocation resolves, which proves nothing about
  what the running process is actually serving

Query strings and fragments are stripped before location matching — a
`?query=string` never affects which `location` block wins. Only `if
($request_uri …)`/`if ($args …)` conditional rules can see the query string;
ordinary `location` matching never does.

### Concrete fixes

Reorder or tighten `location` blocks to get the precedence you want (exact
`=` for a single path, `^~` to force priority over regex, and remember
regex order matters). Fix the `server_name`/`Host` mismatch, or add a
default/catch-all `server {}` block if you need one. If the CLI-resolved
config is what you intend but live behavior differs, use
[§11](#11-reload-did-not-apply-expected-changes) to distinguish a
service-environment difference (a higher-precedence env value the service
sees but your shell doesn't) from an unapplied or rejected reload, rather
than assuming another edit will fix it.

### Verify the fix

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
curl -v -H 'Host: api.example.com' http://127.0.0.1:8069/api/users
```

Confirm both the static route table and the live response match what you
expect.

### Related documentation

- [CONFIGURATION.md — Location Blocks](CONFIGURATION.md#location-blocks) and
  [Server Blocks](CONFIGURATION.md#server-blocks) — full precedence rules.
- [examples/virtual-hosts](../examples/virtual-hosts/README.md).

## 5. Static files return 404 or 403

Treat these as two different failure classes — a `403` here is a deliberate
security rejection, not a permissions bug to work around by loosening
anything.

### 404 — file not found

#### Symptoms

A static request returns `404` where you expected a file to be served.

#### First checks

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
sudo -u tardigrade test -r /var/lib/tardigrade/public/index.html
```

Run the readability check as the service account because a file can exist
and resolve correctly while the worker still cannot open it — an
`AccessDenied` from the actual `openFile` call is propagated as its own
error rather than converted to `404`, so don't assume this case is an
ordinary 404. Check the runtime log and the actual client response, and fix
ownership/permissions for the service account.

#### Likely causes

- the file genuinely doesn't exist at the resolved path
- wrong `root`/`alias` for the matched location
- a relative `root` resolved from an unexpected working directory (prefer
  absolute paths in production configs)
- the request matched a different `location`/`server` block than you
  expected — see [§4](#4-route-does-not-match)
- `try_files` candidates don't include a fallback that resolves
- directory-index behavior: for a directory-style request, Tardigrade tries
  `try_files` first, then `index` (which defaults to `index.html` and is
  resolved *relative to the requested directory*, not the root — `GET
  /docs/` checks `docs/index.html`), then `autoindex` if enabled. A
  nonexistent directory still 404s even with `try_files`/`index`
  configured. See [PROXY_SECURITY.md §12a](PROXY_SECURITY.md#12a-root--index--try_files-interaction-437)
  for the exact resolution order.

#### Concrete fixes

Correct `root`/`alias`/`try_files` for the matching location, fix file
ownership/permissions for the service account (readable, not necessarily
writable), or set an explicit `index "";` if you deliberately don't want the
default `index.html` fallback.

#### Verify the fix

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/index.html
```

Substitute your own `server_name` and file path. Confirm `200` with the
expected body.

### 403 — security-driven rejection

#### Symptoms

A static request returns `403` instead of `404`, often for a request that
"looks like" it should resolve, or contains `..`/encoded traversal
sequences.

#### Likely causes

This is intentional: Tardigrade resolves the canonical (`realpath`) absolute
path of both the configured document root and the requested file, and
rejects any resolved path that doesn't have the root as a prefix — with
`403`, not `404`. Raw `..` segments, single-percent-encoded traversal,
backslash traversal, and symlinks that resolve outside the document root
are rejected this way, as `403`, when they resolve to an escaping path. See
[PROXY_SECURITY.md §12](PROXY_SECURITY.md#12-directory-traversal--static-file-serving)
for the full list.

Double (or additional) percent-encoding is also prevented from ever
escaping the root, but it is **not guaranteed to be a `403`** — decoding
happens once, so a double-encoded sequence like `%252e%252e` can remain a
literal, non-decoded path segment that simply fails to resolve to any
file, surfacing as an ordinary `404` instead. Either outcome means the
traversal didn't succeed; don't read a `404` on a double-encoded path as
"the protection didn't trigger."

#### Concrete fixes

**Do not "fix" a `403` here by loosening filesystem permissions or moving
files to make traversal succeed** — that defeats the boundary the `403` is
protecting. If the rejection is a false positive (a legitimate file that
happens to be reached through a symlink), either move the real file inside
the document root or point `root`/`alias` at the actual containing
directory so the request never needs to leave it.

#### Verify the fix

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/index.html
```

Substitute your own `server_name` and a real file path. Confirm you get
`200` for the legitimate path. To confirm traversal is
still correctly rejected, send the raw `..` sequence with `--path-as-is` —
without it, curl normalizes dot-segments client-side before the request
ever leaves the machine, so the server may never see the traversal attempt
at all and the test would silently pass or fail for the wrong reason:

```bash
curl --path-as-is -v -H 'Host: <server_name>' \
  'http://127.0.0.1:8069/../../etc/passwd'
```

This should return `403`.

### Related documentation

- [PROXY_SECURITY.md](PROXY_SECURITY.md) — full traversal/symlink threat
  model and static-serving security guarantees.
- [CONFIGURATION.md — Location Blocks](CONFIGURATION.md#location-blocks).
- [examples/static-file-server](../examples/static-file-server/README.md).

## 6. Upstream returns 502 / 504 / 503

These three statuses map to three distinct failure classes in Tardigrade's
proxy path — don't treat them interchangeably.

### First checks

Inspect the configured upstream policy first — remember this is
configuration, not a live probe:

```bash
tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

Then contact the origin from the **same host/container/network namespace**
Tardigrade uses — a check from your laptop proves nothing if Tardigrade
reaches the origin over a different network path:

```bash
curl -v http://127.0.0.1:3000/health
```

(This is a direct-to-origin check, a different target than Tardigrade
itself — it doesn't need Tardigrade's `Host`/vhost header.)

For an HTTPS origin:

```bash
curl -v https://backend.example.com/health
```

### 502 — Bad Gateway

#### Symptoms

`502 Bad Gateway`. The access-log classifier (`classifyErrorCategory()`)
currently records `502` under the generic `error_category: internal_error`
bucket, the same as any other `5xx` it doesn't special-case — it is **not**
labeled `upstream_error` in the access log (that string is used as an API
error *code* in some proxy error response bodies, a different field). To
tell a `502` apart from an unrelated internal `5xx`, use the status itself
together with the access log's `upstream_addr`/`upstream_status` fields and
the runtime error log, not `error_category` alone.

#### Likely causes

Non-timeout gateway/protocol failures:

- connection refused (nothing listening at the configured target)
- wrong target host/port/scheme in `proxy_pass`/`upstream_base_url`
- the upstream closed the connection before sending a complete response
  head, or sent a malformed/truncated status line
- upstream TLS verification or handshake failure when proxying to `https://`
- a protocol mismatch (e.g. `TARDIGRADE_UPSTREAM_PROTOCOL` set to something
  the origin doesn't actually speak)

#### Concrete fixes

Fix the target URL/scheme, start or repair the origin process, or correct
the upstream TLS configuration. **Do not "fix" an upstream TLS handshake
failure by disabling `TARDIGRADE_UPSTREAM_TLS_VERIFY`** — that removes
certificate validation for every request to that origin. Instead fix the
origin's certificate, supply the correct CA bundle via
`TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE`, or correct
`TARDIGRADE_UPSTREAM_TLS_SERVER_NAME` if SNI doesn't match what the origin
presents. This applies identically on every `-Dtls-profile` build (#634,
#649): upstream HTTPS always goes through the native TLS/PKI stack
(`src/http/tls_termination.zig`'s `UpstreamTlsConn`), never OpenSSL — the
same knobs, the same 502-on-failure mapping, and the same "fix the
certificate, don't disable verification" guidance apply everywhere.

**Native signature-algorithm coverage:** certificate chain verification
authenticates signatures made with Ed25519, ECDSA P-256/SHA-256,
RSA-PSS/SHA-256, or (as of #645) classic RSA PKCS#1 v1.5
(`sha256WithRSAEncryption`/`sha384WithRSAEncryption`, still common among
public CAs) — `src/pki/verify.zig`, #343 and #645. RSA PKCS#1 v1.5 support is
certificate-chain-signature verification only; it does not change what the
TLS 1.3 handshake itself can use for `CertificateVerify` (RFC 8446 §4.2.3
forbids `rsa_pkcs1` there, so that step still only offers Ed25519, ECDSA
P-256/SHA-256, or RSA-PSS/SHA-256). An origin whose chain is signed with
another unsupported combination (e.g. ECDSA/SHA-384, or RSA PKCS#1 v1.5/
SHA-512) still fails closed here even with a correct CA bundle and hostname —
this is a native signature-algorithm coverage gap, not a misconfiguration,
and disabling verification is still not the fix. There is no OpenSSL-backed
profile to fall back to any more (#649 retired it); until the native matrix
is extended further, such an origin cannot be proxied with verification
enabled.

Independently of signature support, the native handshake engine also caps
each peer certificate entry at 8 KiB DER bytes and the whole handshake
message at 16 KiB (`src/tls/tls13_backend.zig`'s `max_certificate_len`/
`max_message_len`, #646) — generous enough for ordinary public WebPKI
certificates/chains, including a leaf with a large SAN set, but still a
deliberate ceiling. An origin whose certificate/chain genuinely exceeds
either bound fails closed here even with an otherwise-supported signature
algorithm; that is expected for a chain this far outside ordinary norms, not
a bug, and disabling verification does not help (the bound applies before
verification runs).

#### Verify the fix

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/api/users
```

Substitute your own `server_name` and a real proxied route. Confirm the
proxied response now matches what the origin returns directly.

### 504 — Gateway Timeout

#### Symptoms

`502` and `504` look similar to the client but classify differently in
Tardigrade's own logs/metrics (`error_category: upstream_timeout`) —
`504` specifically means Tardigrade gave up waiting, not that it couldn't
reach the origin at all.

#### Likely causes

- connect timeout: the origin never accepted the TCP connection in time
  (`TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS`)
- response timeout: the origin accepted the connection but never finished
  responding in time (`TARDIGRADE_UPSTREAM_TIMEOUT_MS`,
  `TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS`)
- an overloaded or hung upstream process
- genuine network latency or packet loss between Tardigrade and the origin
- retry policy (`TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS`) extending the total
  observed latency before the final timeout is returned

#### Concrete fixes

Fix the slow/hung origin, or tune the timeout values in
[CONFIGURATION.md's Proxy And Upstreams section](CONFIGURATION.md#proxy-and-upstreams)
to match realistic origin latency — raising a timeout papers over a slow
origin rather than fixing it, so treat that as a stopgap, not a resolution.

#### Verify the fix

Time the direct-to-origin request and the proxied request and confirm both
complete well inside the configured timeout:

```bash
time curl -v http://127.0.0.1:3000/health
time curl -v -H 'Host: localhost' http://127.0.0.1:8069/api/users
```

(Substitute your own `server_name` and proxied route.)

### 503 — Service Unavailable

#### Symptoms

`503`, sometimes with `Retry-After: 1` and `Connection: close`, sometimes
just `Connection: close` with no `Retry-After` — but **absence of
`Retry-After` alone doesn't identify which family you're looking at**;
three of the four families below omit it. Neither shape means Tardigrade
itself is unhealthy.

#### Likely causes

`503` here is a local capacity/availability signal, not a gateway or
timeout failure — don't fold it into the 502/504 explanations above. There
are five independent local-capacity/availability families that all return `503`, and
they need different metrics/response bodies to tell apart:

1. **Accept-time connection/worker-queue saturation** — the global or
   per-IP connection cap, the connection memory budget, or the worker
   queue was hit before request parsing. This is the one deterministic
   path that adds `Retry-After: 1` (the fixed empty
   `gateway_accept.overload_response_503`). See the [overload-response
   table in OBSERVABILITY.md](OBSERVABILITY.md#configured-limits) for the
   exact caps.
2. **In-flight request cap** (`TARDIGRADE_MAX_IN_FLIGHT_REQUESTS`) —
   enforced later, after request parsing, by `tryAcquireRequestSlot()`. It
   goes through the generic error path (JSON body,
   `"code":"overloaded"`), closes the connection, but does **not** add
   `Retry-After`, and does **not** move `connection_rejections_total`/
   `queue_rejections_total` — only `tardigrade_error_overload_total` moves.
   Flat connection/queue rejection counters alone don't identify this
   family, though — families 3, 4, and 5 below also leave those two flat;
   `code:"overloaded"` plus `tardigrade_error_overload_total` rising is
   what actually identifies family 2 specifically.
3. **Per-origin upstream connection-pool cap** —
   `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` is exhausted for that
   specific origin, and the checkout fails fast (`error.UpstreamAtCapacity`)
   instead of queuing. JSON `"code":"upstream_saturated"`, no
   `Retry-After`, connection closed.
4. **Proxy aggregate buffer capacity** — a per-origin or global proxy
   buffer hard limit (`TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES`/
   `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES`) refuses a reservation
   before any response byte is committed (`error.ProxyBufferCapacityUnavailable`).
   JSON `"code":"proxy_buffer_saturated"`, no `Retry-After`, connection
   closed.
5. **Process-wide upstream circuit breaker open** —
   `TARDIGRADE_CB_THRESHOLD` is enabled and recent confirmed upstream
   failures opened the breaker. Requests fail before contacting the upstream
   with JSON `"code":"upstream_circuit_open"`, no `Retry-After`, and recover
   through a single half-open probe after `TARDIGRADE_CB_TIMEOUT_MS`.

The response body's `code` field (`overloaded`/`upstream_saturated`/
`proxy_buffer_saturated`/`upstream_circuit_open`) plus the family-specific
counters below are what actually distinguish families 2–5 from each other —
not the presence or absence of `Retry-After`.

Marking backends unhealthy (passive failure tracking or active probing —
see [§8](#8-health-checks-mark-an-upstream-down)) changes backend
*selection*, not the status code by itself: a healthy backup is preferred
over an unhealthy primary, but with no healthy backup available Tardigrade
still probes a primary in round-robin order rather than short-circuiting to
`503`. So "every backend looks unhealthy" alone can still produce a `502`
or `504` (from whatever that probed primary actually does), not
necessarily a `503` — check the access log's `upstream_status`/
`error_category` for the specific request rather than assuming `503` from
health state alone.

For `"code":"upstream_circuit_open"`, check whether the upstream has just
returned repeated 5xx responses, timed out, reset streams, or failed
protocol/connection handling. Local proxy capacity refusals, client upload
errors, and downstream write failures do not trip the breaker. If the origin
has recovered, wait at least `TARDIGRADE_CB_TIMEOUT_MS` for the half-open
probe window; one probe is allowed through, and additional concurrent requests
continue to fail fast until that probe succeeds.

#### Concrete fixes

Point 503s at the metric family matching the `503` shape you observed,
rather than a single generic grep:

```bash
curl -s -H 'Host: localhost' http://127.0.0.1:8069/status/metrics | grep -E \
  'tardigrade_(connection_rejections|queue_rejections)_total|tardigrade_error_overload_total|tardigrade_upstream_pool_(at_capacity_total|connections_active)|tardigrade_.*buffer.*limit_exceeded'
```

- `tardigrade_connection_rejections_total`/`tardigrade_queue_rejections_total`
  climbing → family 1 (accept/connection/worker-queue); raise the relevant
  cap only after confirming headroom (CPU/memory/fds) to honor it.
- `tardigrade_error_overload_total` climbing while the two counters above
  stay flat → family 2 (in-flight request cap); raise
  `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` only after confirming the gateway
  has spare worker/upstream capacity to actually serve more concurrent
  requests, or investigate what's holding requests in flight so long.
- `tardigrade_upstream_pool_at_capacity_total{upstream="..."}` climbing
  against `tardigrade_upstream_pool_connections_active{upstream="..."}` →
  family 3 (per-origin pool cap); raise
  `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` for that origin, or
  reduce concurrent demand on it.
- `tardigrade_upstream_pool_buffer_limit_exceeded_total`/the HTTP/2
  equivalent, or `tardigrade_buffer_limit_exceeded_total` with
  `scope="origin"`/`scope="global"`, climbing → family 4 (proxy buffer
  capacity); raise the relevant `TARDIGRADE_PROXY_BUFFER_*_HARD_LIMIT_BYTES`
  only if you've confirmed the memory headroom to back it.

If backend health looks like the underlying issue instead, fix the
origin(s) and use [§8](#8-health-checks-mark-an-upstream-down) to confirm
they're marked healthy again — that resolves the `502`/`504`s the
unhealthy state was actually producing, a separate class from all four
`503` families above.

#### Verify the fix

```bash
curl -s -H 'Host: localhost' http://127.0.0.1:8069/status/metrics | grep -E \
  'tardigrade_(connection_rejections|queue_rejections)_total|tardigrade_error_overload_total|tardigrade_upstream_pool_(at_capacity_total|connections_active)|tardigrade_.*buffer.*limit_exceeded'
curl -v -H 'Host: localhost' http://127.0.0.1:8069/api/users
```

Confirm the specific counter you were chasing isn't climbing anymore and
the proxied request succeeds with the status you expect.

### Related documentation

- [OBSERVABILITY.md — Resource Limits and Overload Behavior](OBSERVABILITY.md#resource-limits-and-overload-behavior)
  — the full overload-cause-to-signal mapping, including the local-capacity
  `503` path that isn't an upstream problem at all.
- [CONFIGURATION.md — Proxy And Upstreams](CONFIGURATION.md#proxy-and-upstreams)
  and [Health Checks And Circuit Breaking](CONFIGURATION.md#health-checks-and-circuit-breaking).
- [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) — connection pool contract.

## 7. TLS certificate/key errors

Separate startup credential validation (Tardigrade won't start at all) from
client-facing handshake failures (Tardigrade is running, but a given client
can't complete a TLS handshake).

### Startup validation failures

`tardi check` and actual server startup validate different things, and
conflating them leads to false confidence:

1. **`tardi check`, general profile (the default,
   `-Dtls-profile=general`):** config-shape validation, including
   deterministic rejection of the retired OpenSSL-adapter-only settings
   (TLS 1.2, cipher overrides, downstream mTLS, session cache/tickets,
   OCSP, CRL, ACME, the credential watcher, PROXY protocol with TLS — see
   `docs/TLS_DEPENDENCY_POLICY.md#retired-openssl-capability-disposition`).
   It does not parse or cross-check the certificate/key files themselves.
2. **`tardi run`/service startup, general profile:** before the gateway
   begins serving, the certificate/key files are loaded into the native
   credential store (`src/http/native_tls_connection.zig`). **Malformed
   PEM, an unreadable/invalid key, or a cert/key mismatch fail `tardi
   run`/service startup outright — even though a prior `tardi check` may
   have printed `configuration valid`.** This is not a "wait for a real
   handshake" problem; it's a "run the process, not just `check`" problem.
3. **Validity/trust/hostname, general profile:** an expired, not-yet-valid,
   untrusted, or hostname-mismatched certificate is a separate class,
   normally observed by the *client* during handshake validation, not
   something that blocks Tardigrade's own startup — see [Runtime handshake
   failures](#runtime-handshake-failures) below.
4. **Appliance TLS profile (`-Dtls-profile=appliance`):** `tardi check`
   additionally runs the appliance credential preflight (PEM parse,
   chain shape, leaf/key match, validity-window checks), so it catches
   the supported material/validity failures earlier, at `check` time.

Confirm which profile you're running with `tardi version` (it prints
`tls-profile=...`) before assuming which of the above applies.

#### Symptoms

`tardi check` fails with a certificate/key-related validation error instead
of `configuration valid` (appliance profile, or a config-shape problem on
either profile); or `tardi check` passes but `tardi run`/
`systemctl start tardigrade` still fails at startup with a certificate-load
or key-mismatch error (general profile).

#### First checks

Config-shape validation (both profiles):

```bash
tardi version   # confirm tls-profile
tardi check /etc/tardigrade/tardigrade.conf
tardi print-config -c /etc/tardigrade/tardigrade.conf
sudo -u tardigrade test -r /etc/tardigrade/tls/fullchain.pem
sudo -u tardigrade test -r /etc/tardigrade/tls/privkey.pem
```

Certificate metadata (either profile — this is plain `openssl`, not a
Tardigrade check):

```bash
openssl x509 \
  -in /etc/tardigrade/tls/fullchain.pem \
  -noout -subject -issuer -dates
```

A profile-independent cert/key match check (compares extracted public
keys rather than relying on a Tardigrade-side match check that only runs
on appliance builds). Avoid a bare `| sha256sum` pipeline here without
`set -o pipefail` — if an earlier `openssl` stage fails and produces no
output, `sha256sum` still succeeds hashing an empty stream, and two
independently-broken inputs can produce the same "matching" empty-input
digest, which is exactly the false negative you don't want in a
credential-mismatch check:

```bash
(
  cert_pub=$(mktemp) || exit 1
  key_pub=$(mktemp) || { rm -f "$cert_pub"; exit 1; }
  trap 'rm -f "$cert_pub" "$key_pub"' EXIT

  if ! openssl x509 -in /etc/tardigrade/tls/fullchain.pem -pubkey -noout >"$cert_pub"; then
    echo "certificate PEM is invalid or unreadable" >&2
    exit 1
  fi

  if ! openssl pkey -in /etc/tardigrade/tls/privkey.pem -pubout >"$key_pub"; then
    echo "private key is invalid or unreadable" >&2
    exit 1
  fi

  if ! cmp -s "$cert_pub" "$key_pub"; then
    echo "cert/key MISMATCH" >&2
    exit 1
  fi
  echo "cert/key match"
)
```

Wrapped in a subshell `(...)` so `exit`/`trap` stay local to the check —
without it, the `exit 1` branches would terminate the operator's actual
shell/session on failure, and a successful run's `trap ... EXIT` would
stay installed in that shell until it eventually exits, silently
replacing any `EXIT` trap already set there.

The exit status and the printed message agree: `0`/`cert/key match` means
the public keys match; a nonzero exit from either `openssl` stage means
the PEM material itself is invalid/unreadable and must be fixed before a
match can even be checked; a nonzero exit at the final `cmp` means a
genuine cert/key mismatch.

#### Likely causes

Config-shape (rejected by `tardi check` on **either** profile):

- only `tls_cert_path` or only `tls_key_path` configured — Tardigrade
  requires both or neither, and rejects a cert-only/key-only configuration
  at validation time rather than silently falling back to plaintext
- for the appliance TLS profile specifically: more than one certificate
  identity configured (server-block TLS material or `TARDIGRADE_TLS_SNI_CERTS`)
  — the appliance profile supports exactly one identity; see
  [BARE_APPLIANCE_TLS.md](BARE_APPLIANCE_TLS.md)

Credential material — on the appliance profile these are rejected by
`tardi check` itself; on the general/default profile `tardi check` will
not catch them, but **`tardi run`/service startup still will**, before the
listener starts serving:

- the service account can't read the private key
- malformed PEM, or an ambiguous/ill-formed certificate chain
- the certificate and key don't match (`cmp` check above)

Genuinely separate from the above — an expired or not-yet-valid certificate
(`openssl x509 … -dates` above) does not fail loading on the general
profile; it's ordinarily a *client-side* handshake-validation failure (see
[Runtime handshake failures](#runtime-handshake-failures)), not a startup
failure.

#### Concrete fixes

Provision the missing half of the cert/key pair, fix the PEM encoding, or
replace an expired certificate. For a permissions fix:

**Never make the private key world-readable.** Keep it `root:tardigrade
0640` (or narrower), owned by a group the service account belongs to. If
you're running under Docker with a bind-mounted key, the failure is usually
a **numeric GID mismatch**, not a mode problem: a host file owned
`root:tardigrade 0640` is only readable inside the container if the
container's `tardigrade` group numerically matches the host group that owns
the file (group *names* don't cross the container boundary, only numeric
IDs do) — `chmod`-ing the bind-mounted file to fix this changes the mode on
the host file too, making the key world-readable there. Instead add the
container to the correct numeric group with Compose's `group_add:`. Full
walkthrough: [DEPLOYMENT.md's permissions
section](DEPLOYMENT.md#permissions-and-ownership).

#### Verify the fix

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

Should print `configuration valid` with `tls: enabled` in the summary. On
the general/default profile this only confirms config *shape* — it is not
proof the credential material loads. Confirm that separately by actually
starting the process and checking it comes up:

```bash
sudo systemctl restart tardigrade
sudo systemctl status tardigrade
sudo journalctl -u tardigrade -n 20 --no-pager
```

A `CertificateLoadFailed`/`PrivateKeyLoadFailed`/`CertificateKeyMismatch`-
class failure here means `tardi check` passing did not guarantee a working
credential; go back to the causes above. Once the service is actually
running, follow up with the [runtime handshake
check](#runtime-handshake-failures) below to confirm a client can complete
a handshake against it too.

### Runtime handshake failures

#### Symptoms

Tardigrade is running and `tardi check` passes, but a specific client (or
all clients) can't complete a TLS handshake against it.

#### First checks

```bash
openssl s_client \
  -connect 127.0.0.1:8443 \
  -servername api.example.com
```

Read the handshake output for the actual failure: certificate rejected,
protocol version mismatch, no shared cipher, or the connection closing
during `ClientHello`.

#### Likely causes

- SNI/hostname mismatch — the client's `-servername` (or its equivalent)
  doesn't match any configured cert's names, and the wrong cert (or none)
  is presented
- a TLS-version or cipher-suite mismatch between client and
  `TARDIGRADE_TLS_MIN_VERSION`/`TARDIGRADE_TLS_MAX_VERSION`/
  `TARDIGRADE_TLS_CIPHER_LIST`/`TARDIGRADE_TLS_CIPHER_SUITES`
- a plaintext HTTP request sent to a TLS listener (or vice versa) — the
  symptom looks like a "hang" or protocol error, not a clean TLS alert
- client certificate verification enabled
  (`TARDIGRADE_TLS_CLIENT_VERIFY=true`) but the client didn't present one
  (`certificate_required` alert; use `TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL`
  to allow it), or its chain doesn't validate against
  `TARDIGRADE_TLS_CLIENT_CA_PATH` — wrong issuing CA, expired or not-yet-valid
  certificate, a `serverAuth`-only Extended Key Usage, a path longer than
  `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH`, or a missing intermediate the client
  did not send. Check the gateway log for `native tls handshake failed`; the
  client certificate itself is never logged. With per-`server {}` client
  auth the policy follows the TLS **SNI**: a certificate from CA A is refused
  by a host that trusts CA B, and a client that connects without SNI matches only a
  `server {}` block with no `server_name` (else the listener-wide policy). A `421 Misdirected Request`
  means the request's `Host` maps to a different client-auth policy than the
  SNI the connection was admitted under — reconnect with SNI equal to the
  host (curl: use the real hostname or `--connect-to`, not `--resolve` to a
  different name). If a reload logs
  `client trust reload failed`, the previous CA bundle is still serving.
  Over HTTP/3 the same failures surface to the client as a QUIC
  `CONNECTION_CLOSE` carrying a TLS alert (`0x12a` bad_certificate, `0x174`
  certificate_required) and increment
  `tardigrade_quic_handshake_failures_total`; the application never sees a
  request from the refused peer.

#### Concrete fixes

Correct the SNI name or add the missing name to `TARDIGRADE_TLS_SNI_CERTS`,
widen `TARDIGRADE_TLS_MIN_VERSION`/`_MAX_VERSION` only if you understand the
compatibility tradeoff, or fix the client's scheme. **Do not weaken
TLS verification (client or upstream) as a generic fix** — diagnose the
actual mismatch instead.

#### Verify the fix

```bash
openssl s_client -connect 127.0.0.1:8443 -servername api.example.com </dev/null
curl -v --resolve api.example.com:8443:127.0.0.1 https://api.example.com:8443/health
```

The `curl` here sends `api.example.com` as both SNI and HTTP `Host` — as in
the triage section, `-H 'Host: ...'` alone against a raw IP would not do
that. Add `--cacert <path>` if the certificate chains to a private/
self-signed CA you want validated, or `-k` only if you're deliberately
separating reachability/routing from trust validation (see the note in
[§1](#1-five-minute-triage)). Confirm the handshake completes and the
response comes back as expected.

### Related documentation

- [CONFIGURATION.md — TLS Termination](CONFIGURATION.md#tls-termination) —
  full TLS field reference.
- [BARE_APPLIANCE_TLS.md](BARE_APPLIANCE_TLS.md) — appliance TLS profile
  constraints.
- [PKI_REVOCATION.md](PKI_REVOCATION.md) — OCSP/CRL policy, if you're
  chasing a revocation-related failure.
- [examples/tls-termination](../examples/tls-termination/README.md).

## 8. Health checks mark an upstream down

### Symptoms

Requests to a route fail or fail over unexpectedly, and you suspect
Tardigrade's active/passive health checking has marked a backend unhealthy.

### First checks

```bash
tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

This shows the **configured** active-probe path/interval/timeout/thresholds
and passive failure policy from the effective config resolved by this CLI
invocation — **it is not a live backend-health dashboard.** It cannot tell
you whether a backend is currently marked unhealthy by the running
process.

For live aggregate health, use metrics:

```bash
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics | \
  grep tardigrade_upstream_unhealthy_backends
```

Then probe the actual health-check endpoint from Tardigrade's own network
context (same host/container/namespace), using the configured probe path:

```bash
curl -v http://127.0.0.1:3000/health
```

(Substitute your own upstream host, port, and probe path —
`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH`/the origin's `-c` config — for the
one shown above.)

### Likely causes

- the configured probe path or expected success-status range doesn't match
  what the origin actually returns
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH`/`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS`)
- the probe timeout is too small for the origin's real response time
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS`)
- fail/recovery thresholds are too aggressive for a flaky-but-usable origin
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD`/`_SUCCESS_THRESHOLD`)
- passive failures from real request traffic tripping
  `TARDIGRADE_UPSTREAM_MAX_FAILS` before the active probe would have caught it
- a namespace/address mismatch — the probe reaches a different network path
  than real proxied traffic does (common in containerized deployments)
- an HTTPS probe target failing TLS/SNI verification, distinct from a
  plain reachability failure
- the origin is genuinely unhealthy

Note the active-probe env-var naming split documented in
[CONFIGURATION.md](CONFIGURATION.md#health-checks-and-circuit-breaking):
config-file/secret overrides must use the `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_*`
names, not the process-environment-only `TARDIGRADE_UPSTREAM_PROBE_*`
aliases — setting the wrong family in a config file silently does nothing.

### Concrete fixes

Align the probe path/status range with what the origin actually serves,
raise the probe timeout to match real origin latency, or loosen fail/success
thresholds if a healthy-but-occasionally-slow origin is being marked down
too aggressively. Fix the underlying origin if it's genuinely failing.

### Verify the fix

```bash
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics | \
  grep tardigrade_upstream_unhealthy_backends
```

Confirm the count returns to `0` (or the expected number) after the
configured number of consecutive successful probes
(`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD`) have completed, then
confirm proxied requests succeed. With a threshold greater than `1`, the
first successful probe only moves a down backend to `half_open` — it isn't
routable yet — so wait for the required additional successful probe
cycles rather than expecting recovery after a single interval; otherwise a
perfectly healthy recovery can look stuck when the threshold was
deliberately raised above `1`.

### Related documentation

- [CONFIGURATION.md — Health Checks And Circuit Breaking](CONFIGURATION.md#health-checks-and-circuit-breaking).
- [examples/health-checks](../examples/health-checks/README.md).

## 9. Metrics endpoint unavailable

### Symptoms

`curl` (or your Prometheus scraper) against the metrics path fails or
returns something other than metrics text.

### First checks

```bash
curl -v -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics
```

Send the `Host` your config's `server_name` expects — like every other
route, the metrics path is resolved after virtual-host selection, so a
`Host` that matches no server block 404s before the metrics handler is ever
reached.

### Likely causes and how to tell them apart

| Symptom | Meaning |
| --- | --- |
| `404 Not Found` | Wrong path, metrics disabled (`TARDIGRADE_METRICS_PATH=""`), a `Host` header that doesn't match any configured `server_name` (see above), or you're hitting the wrong listener. Check `tardi print-config -c <path>` for the `metrics:` line and `tardi routes` for the active `server_name`s. |
| `401 Unauthorized` | `TARDIGRADE_METRICS_REQUIRE_AUTH=true` and the request didn't authenticate. This uses the same request-auth mechanism as any other protected route — Basic auth (`TARDIGRADE_BASIC_AUTH_HASHES`), a static bearer-token hash (`TARDIGRADE_AUTH_TOKEN_HASHES`), or JWT bearer auth (`TARDIGRADE_JWT_SECRET`), whichever your config enables — not specifically a bearer token. This is expected hardening, not a bug — see [DEPLOYMENT.md's hardening checklist](DEPLOYMENT.md#production-hardening-checklist). |
| Connection refused | The listener itself is down or unreachable — this is [§3](#3-listener-fails-to-bind--service-is-unreachable), not a metrics-specific problem. |
| TLS handshake failure | Wrong scheme (`http://` vs `https://`) or a certificate problem — see [§7](#7-tls-certificatekey-errors). |
| Curl from the host succeeds, Prometheus scrape fails | The failure is on the scraper's side of the network path — a firewall rule, wrong scrape target, wrong scheme/TLS config in the scrape job, or `TARDIGRADE_METRICS_REQUIRE_AUTH` without credentials matching whichever auth mechanism your config requires. Not a Tardigrade-side problem once local `curl` works. |

### Concrete fixes

Correct `TARDIGRADE_METRICS_PATH`/re-enable metrics, configure the scraper
for whichever request-auth mechanism your config actually requires (Basic
auth, static bearer token, or JWT) if `TARDIGRADE_METRICS_REQUIRE_AUTH=true`,
or fix the scraper's target/scheme/network path. Don't disable
`TARDIGRADE_METRICS_REQUIRE_AUTH` in production just to unblock a scrape —
fix the scrape job's auth instead.

### Verify the fix

```bash
curl -v -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics | head -5
```

Confirm you get Prometheus text output (lines starting `# HELP`/`# TYPE`),
then confirm the scraper's own target status shows the endpoint as up.

### Related documentation

- [OBSERVABILITY.md — Metrics](OBSERVABILITY.md#metrics) — full metric
  catalog.
- [examples/prometheus-metrics](../examples/prometheus-metrics/README.md).

## 10. Logs are missing / going somewhere unexpected

### Symptoms

You expect log output (runtime or access logs) and don't see it where you're
looking, or a specific request/status isn't showing up.

### First checks

For systemd deployments, journald is the default surface:

```bash
sudo journalctl -u tardigrade -n 100 --no-pager
sudo journalctl -u tardigrade -f
```

For Docker:

```bash
docker compose logs -f tardigrade
```

If you configured `error_log`/`TARDIGRADE_ERROR_LOG_PATH`, check that file
instead:

```bash
tardi print-config -c /etc/tardigrade/tardigrade.conf   # inspect the effective path resolved by this CLI invocation
sudo tail -f /var/log/tardigrade/error.log   # substitute the effective path you just resolved above
```

As with the inspection-command warning in [§1](#1-five-minute-triage),
`print-config` here proves what *this CLI invocation* resolves from the
selected file plus its own current process environment — not
live-process introspection, and not necessarily the file's literal value
either: an already-set `TARDIGRADE_ERROR_LOG_PATH` in your shell overrides
the file (same env-over-file precedence as everywhere else — see
[CONFIGURATION.md](CONFIGURATION.md#configuration-reference)), and your
interactive shell's environment usually differs from the systemd
service's `EnvironmentFile=`. Moving the live `error_log` destination live
is possible, but only in one direction and one deployment shape — don't
assume it always works:

- **Config-file change to a new non-empty file path, single-process
  mode, no higher-precedence env override:** if no process-environment
  `TARDIGRADE_ERROR_LOG_PATH` is already pinning the value (same
  precedence rule as above — a service with that variable set in
  `EnvironmentFile=` won't see a file-only edit at all), a successful
  `SIGHUP` publishes the new *effective* path, and a following `SIGUSR1`
  (reopens against whatever `error_log_path` is on the *currently
  published* config — `reopenErrorLog()`) moves the live destination,
  whether that's stderr→file or file A→file B:

  ```bash
  sudo systemctl reload tardigrade   # publish the new effective error_log path
  sudo systemctl kill --kill-who=main --signal=USR1 tardigrade   # reopen against it
  ```

  `SIGHUP` by itself leaves the process writing to the *old* destination
  regardless of what `print-config` now shows.
- **Moving a file-backed destination back to `stderr`/empty does *not*
  work this way.** `reopenErrorLog()` returns immediately when the
  published `error_log_path` is empty or `stderr` — it never touches the
  file-backed fd. That direction requires a restart.
- **`TARDIGRADE_ERROR_LOG_PATH` set via `EnvironmentFile=`/Compose
  `env_file:`** is a process-environment change, not a config-file
  change — `SIGHUP` can't see the edited value at all (same rule as any
  other `tardigrade.env` edit, [§11](#11-reload-did-not-apply-expected-changes)).
  Restart.
- **`master_process true;`**: `SIGHUP` reload isn't coherent across
  workers, and `--kill-who=main --signal=USR1` only reaches the main
  process — this two-signal recipe assumes the default single-process
  mode. Restart for a coherent destination change under master/worker.

A full restart always works for any of the above; the two-signal sequence
is only a shortcut for the one case it actually covers. See
[CONFIGURATION.md's reload matrix](CONFIGURATION.md#reload-behavior) for
the same scoped note.

### Likely causes

- **expecting a file while output is actually going to journald/stderr**:
  both runtime logs and access logs write to **stderr** by default (not
  stdout) — that's what `journalctl`/`docker compose logs` capture.
- **expecting a separate access-log file**: there is no independent
  access-log file in either case. Without `error_log`/
  `TARDIGRADE_ERROR_LOG_PATH` configured, both log types stay on stderr.
  With it configured, Tardigrade `dup2`s that same shared stderr stream
  onto one configured file at startup, so runtime *and* access logs still
  end up interleaved together — just redirected, not split into
  `access.log`/`error.log`; the file takes whatever name you gave
  `error_log`.
- **`error_log` is configured but the target directory/file isn't writable
  by the service account** — check ownership of `/var/log/tardigrade/`
- **log level filtering**: `error_log … warn;` (or
  `TARDIGRADE_LOG_LEVEL=warn`) suppresses `info`/`debug` runtime lines you
  might be expecting
- **access-log minimum status**: `TARDIGRADE_ACCESS_LOG_MIN_STATUS` set
  above `0` hides successful requests from the access log by design
- **buffering**: `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` set above `0` batches
  access-log writes until the buffered bytes cross that threshold — a
  request you just made may not appear yet. There is no time-based flush;
  entries flush only when the buffer fills, on an explicit flush, or at
  process teardown, so waiting alone will not surface a line that hasn't
  reached the threshold.
- **a misconfigured syslog target** (`TARDIGRADE_ACCESS_LOG_SYSLOG_UDP`)
  silently drops entries the sink refuses (access logging is best-effort and
  never blocks the request path — see
  [OBSERVABILITY.md's log/metrics sink note](OBSERVABILITY.md#configured-limits))
- **looking at access logs for a startup failure** — a config or bind
  failure happens before any request is ever handled, so it will never
  appear in the access log; check runtime logs (journald/`error_log`)
  instead
- **under Docker with a freshly bind-mounted log directory**: `error_log`
  fails with `EACCES` because the bind mount replaced the image's
  pre-owned `10001:10001` directory with a root-owned host path — see
  [DEPLOYMENT.md's Logs section](DEPLOYMENT.md#logs) for the
  `install -d -o 10001 -g 10001` fix

Two rotation mechanisms are supported — don't invent a third:
`TARDIGRADE_LOG_ROTATE_MAX_BYTES`/`TARDIGRADE_LOG_ROTATE_MAX_FILES`
trigger a one-time size check and rotation at process **startup** only
(not while the process stays up); the packaged DEB/RPM logrotate policy
handles **ongoing** rotation while running, and sends `SIGUSR1` after each
rotation so Tardigrade's `SIGUSR1` handler reopens the log file cleanly
against the rotated-in path. Don't assume the startup size check runs
periodically on its own — it doesn't.

### Concrete fixes

Point your monitoring at the actual active surface (journald vs. the one
`error_log` file), raise the log level or lower
`TARDIGRADE_ACCESS_LOG_MIN_STATUS` if you're missing entries, fix
`/var/log/tardigrade/` ownership, or — if you need near-real-time
visibility — generate enough log volume to cross the configured buffer
threshold, or set `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE=0` to disable
buffering entirely rather than waiting for it to flush on its own.

### Verify the fix

```bash
curl -v -H 'Host: <server_name>' http://127.0.0.1:8069/health
sudo journalctl -u tardigrade -n 5 --no-pager
# or, when error_log is configured (runtime and access logs are interleaved):
sudo tail -5 /var/log/tardigrade/error.log
```

Confirm the request you just made shows up where you expect it.

### Related documentation

- [OBSERVABILITY.md — Structured Logs](OBSERVABILITY.md#structured-logs) —
  full field reference for both log types.
- [DEPLOYMENT.md — Logs](DEPLOYMENT.md#logs) — journald vs. file logs,
  logrotate/`SIGUSR1` contract, Docker persistence caveats.
- [examples/access-logs](../examples/access-logs/README.md).

## 11. Reload did not apply expected changes

### Symptoms

You edited `tardigrade.conf`, reloaded, and the running process still
behaves like the old config — or reload appears to have "worked" (no error
printed) but nothing changed.

### First checks

Pre-validate what this ad-hoc CLI invocation resolves first — a failed
reload silently keeps the old config active, so if the new file is invalid
you'd otherwise have no idea:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

This catches parse/semantic problems before you signal the service, but
it does not load systemd's `EnvironmentFile=` — like every other
inspection command in this guide, it validates what *this* invocation
resolves under its own environment, which may differ from the running
service's actual reload candidate. The live reload status below is
authoritative, not this precheck.

Reload:

```bash
sudo systemctl reload tardigrade
# or, without systemd:
tardi reload --pid-file /run/tardigrade/tardigrade.pid
```

**Then check the live result, not the CLI's own resolution.**
`tardi print-config`/`routes`/`upstreams` show only what *this invocation*
resolves from the selected file plus its own process environment — not
live-process introspection, and not proof the running service process
resolves the same thing or actually published it. Use the runtime
reload-status endpoint instead:

```bash
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/tardigrade/reload/status
```

This returns `{"ok":<bool|null>,"at_ms":<timestamp>,"error":<string|null>}` —
`ok: false` with a non-null `error` means the proposed config was **not
published**: the previous published request-routing/config lease remains
active. That's a narrower guarantee than "everything rolled back" —
reload-owned runtime resources are not fully transactional, and some
runtime work (e.g. native ticket-key/credential/TLS-policy preparation)
can happen before the later rejection, so it may not itself un-happen. If
complete rollback of a specific runtime surface matters, don't assume it
from `ok: false` alone — check that surface's own logs/metrics, and
restart if you need a clean state. Cross-check with logs and metrics:

```bash
sudo journalctl -u tardigrade -n 50 --no-pager | grep -i reload
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics | \
  grep tardigrade_reload
```

Expect one of `configuration hot-reload starting` /
`configuration hot-reload applied` (success) or `config reload failed during
load: …` / `config reload rejected by validation: …` / `config reload
rejected: … restart the process …` (failure) in the runtime log around the
time you reloaded.

### Likely causes

- **the reload was rejected** — the `reload/status` endpoint and logs above
  will say so explicitly; the previously published request-routing/config
  lease stays active (see the transactionality caveat above)
- **the field you changed is not reload-eligible.** Tardigrade classifies
  every setting into one of three buckets — see the [full matrix in
  CONFIGURATION.md](CONFIGURATION.md#reload-behavior):
  1. reloadable in place (routing, rate limits, proxy/TLS buffer limits,
     response/security headers, log level, access logging, etc.) — takes
     effect immediately on the next request after publication;
  2. **reload rejected outright**, restart required (listener-shard
     topology, HTTP/3 listener-owned settings, native early-data
     replay/ticket-key mode, and **appliance-profile** TLS credential
     configuration — `TLS_CERT_PATH`, `TLS_KEY_PATH`, `TLS_SERVER_NAME`,
     `TLS_SNI_CERTS`) — `SIGHUP` refuses these and keeps the old config
     running rather than applying a partial change;
  3. **the reload "succeeds" and publishes the new config, but the specific
     live runtime state doesn't change until restart** (bound socket
     host/port, worker thread/queue counts, PID file, upstream-pool policy,
     session/approval/transcript store paths, and the retired
     OpenSSL-adapter TLS context inputs — protocol/cipher/session/
     client-verify/CA/CRL/OCSP/ACME/watcher settings, which are also
     rejected outright by config validation if set to anything but their
     default) — this is the easiest case to mistake for "reload is
     broken", because there's no rejection to see.

  TLS credential/config identity is not a generic `SIGHUP`-hot-reloadable
  surface in either profile: appliance credential-configuration changes are
  rejected outright (bucket 2), and enabling or disabling TLS itself is
  rejected outright in every profile (also bucket 2) — the native
  credential owner is startup-fixed. On the general profile, a reload does
  re-read the configured certificate/key files' *content* and publish a new
  identity if every other check passes; since one `NativeCredentialStore`
  serves both stable TCP and HTTP/3 (#649 retired the #629 mixed-owner
  composition, where a separate OpenSSL terminator served TCP), that single
  atomic swap keeps both surfaces coherent — there is no longer a case
  where they could drift from each other. See "TLS Credential Identity" in
  [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md#tls-credential-identity) for the
  full contract, including why the appliance profile's `ApplianceCredentials`
  owner — despite technically supporting reload methods — is fully
  startup-owned in practice, since `hotReloadConfig` never calls them.
- **you edited `tardigrade.env`, not `tardigrade.conf`** — `SIGHUP` reloads
  the *config*; it cannot change the *process environment* of an
  already-running process. `tardigrade.env` (and any
  `EnvironmentFile=`/Compose `env_file:` source) only takes effect on the
  next full restart. This includes systemd `EnvironmentFile=` changes —
  editing the file never touches a process that's already running.
- **`master_process true;`**: PID-file/`SIGHUP` reload does not yet provide
  coherent control across all workers in master/worker mode — use
  `systemctl restart tardigrade` instead of reload when running with a
  master process. See [DEPLOYMENT.md's master/worker
  section](DEPLOYMENT.md#commands).
- **an in-flight request observed the old config** — in-flight requests
  keep their request-scoped config lease across a reload by design; only
  new requests after publication acquire the new version. This is expected
  behavior, not a bug, and resolves itself as soon as the in-flight request
  completes.

### Concrete fixes

For a rejected reload: fix whatever `reload/status`/the logs say is wrong,
then reload again. For a restart-required field: `sudo systemctl restart
tardigrade` (or recreate the Docker container) instead of reload — reload
will never apply it. For a `tardigrade.env` edit: restart, not reload.

### Verify the fix

```bash
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/tardigrade/reload/status
curl -s -H 'Host: <server_name>' http://127.0.0.1:8069/status/metrics | \
  grep -E 'tardigrade_reload_(success|failure)_total'
```

`ok: true` and a fresh `at_ms`, with `reload_success_total` incremented and
`reload_failure_total` unchanged since your attempt, confirms the reload
actually installed. Then re-check the specific behavior you changed against
a live request — not just the CLI-resolved static config from
`tardi print-config`.

### Related documentation

- [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md) — full hot-reload/drain/shutdown
  contract.
- [CONFIGURATION.md — Reload Behavior](CONFIGURATION.md#reload-behavior) —
  the complete reloadable/restart-required/publish-but-inactive matrix.
- [examples/graceful-reload](../examples/graceful-reload/README.md).

## 12. Performance appears worse than expected

### Symptoms

Latency or throughput looks worse than published benchmark numbers, or
worse than you expect for the workload.

### First checks

Confirm you're actually running a release build — a debug build is
substantially slower and is not what published benchmarks measure:

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/tardi version
```

Then rule out the most common false alarms before assuming a Tardigrade
regression:

- Are you hitting the intended route/server/protocol? A request that falls
  through to an unexpected `location` or upstream will not perform like the
  one you meant to measure — check with [§4](#4-route-does-not-match).
- Is the client reusing connections? Per-request TCP/TLS handshake
  overhead dominates small-request latency; compare with keep-alive.
- Is the slowness on Tardigrade's side or the upstream's? Time the origin
  directly (as in [§6](#6-upstream-returns-502--504--503)) before assuming
  Tardigrade is the bottleneck.

### Likely causes

- debug build instead of `ReleaseFast`
- rate limiting (`TARDIGRADE_RATE_LIMIT_RPS`) becoming the effective
  bottleneck and returning `429`s — a common benchmark-methodology mistake,
  not a real capacity problem; check
  [benchmarks/README.md's path-and-host-overrides
  note](../benchmarks/README.md#path-and-host-overrides)
- worker-pool queue saturation — check `tardigrade_worker_queued_jobs` vs.
  `tardigrade_worker_queue_capacity` and `tardigrade_worker_active_jobs` in
  `/status/metrics`; see the [overload troubleshooting table in
  OBSERVABILITY.md](OBSERVABILITY.md#operator-troubleshooting)
- upstream latency/saturation rather than local queueing — check
  `tardigrade_proxy_ttfb_ms` and the upstream directly
- excessive debug/synchronous logging (`error_log … debug;` in production)
- streaming vs. buffered proxy mode mismatch for large transfers — compare
  `tardigrade_proxy_streaming_requests_total` against
  `tardigrade_proxy_buffered_requests_total` for the route in question; see
  [PROXY_STREAMING.md](PROXY_STREAMING.md)
- **comparing an ad hoc laptop/debug run against published benchmark
  numbers.** Published Tardigrade benchmark numbers are captured on a
  dedicated, idle, deployment-class target, not a shared laptop — a laptop
  can measure materially faster or slower than the canonical deployment
  target because CPU, frequency scaling, scheduler noise, background work,
  and topology all differ. Treat any local run as a smoke test, not a
  regression signal, unless it's run with matched hardware, concurrency,
  and protocol against the baseline you're comparing to.

### Concrete fixes

Rebuild in `ReleaseFast`, fix the false-alarm cause you found above, or tune
the specific limit/timeout the metrics point at (see
[OBSERVABILITY.md's tuning principle](OBSERVABILITY.md#configured-limits):
raise a limit only after confirming headroom exists to honor it).

### Verify the fix

Reproduce your benchmark with the same tool, path, concurrency, and
protocol you used for the original comparison:

```bash
./benchmarks/run.sh \
  --host 127.0.0.1 \
  --host-header localhost \
  --pid-file /run/tardigrade/tardigrade.pid \
  --scenarios static-http1,proxy-http1,keepalive
```

`--host-header` matters here for the same reason every other Tardigrade-
facing example in this guide sends an explicit `Host`: on a named-vhost
config, a benchmark run without it measures the 404 vhost-mismatch path
instead of the static/proxy routes you intended to benchmark, which is a
silent way to get numbers for the wrong thing entirely. Compare `p50`/
`p95`/`p99` and `req/s` against your actual baseline, not against the
README's headline numbers unless your hardware and workload genuinely
match theirs.

### Related documentation

- [benchmarks/README.md](../benchmarks/README.md) — full benchmark
  methodology, measurement-reliability pitfalls, and scenario list.
- [OBSERVABILITY.md — Resource Limits and Overload Behavior](OBSERVABILITY.md#resource-limits-and-overload-behavior).
- [PROXY_STREAMING.md](PROXY_STREAMING.md) — streaming vs. buffered proxy
  behavior.

## 13. Still stuck?

Before filing an issue, check whether the surface you're troubleshooting is
listed as `stable` in the [Core v1 support matrix](SUPPORT_MATRIX.md). HTTP/2
and HTTP/3/QUIC are stable within their documented TLS/ALPN, UDP, Alt-Svc, and
restart/drain limits. Experimental surfaces (WebSocket/SSE, ACME, auth/session
extensions, DNS-driven upstream discovery, and more) carry weaker operational
guarantees, and a rough edge there may be expected rather than a bug.

If you're still stuck, open a [GitHub
issue](https://github.com/Bare-Systems/Tardigrade/issues) with this filled
in:

```text
Tardigrade version:
Installation method:
OS/distribution:
Deployment: shell / systemd / Docker
Affected protocol: HTTP/1.1 / HTTP/2 / HTTP/3
Support-matrix maturity:
Exact command:
Config path:
Relevant config section (secrets removed):
Expected result:
Actual result:
HTTP status/error:
Relevant log lines:
Output of tardi print-config:
Output of tardi routes, if routing-related:
Output of tardi upstreams, if proxy-related:
Relevant metrics:
```

Get the version with `tardi version`.

**Redact before pasting**: TLS private key contents, bearer/API tokens,
secret-store keys and values, credentials embedded in URLs
(`https://user:pass@host/`), session tokens, and any TLS keylog/qlog
material (`TARDIGRADE_HTTP3_KEYLOG_PATH` output decrypts traffic). Don't
over-redact past that — listener addresses, route patterns, upstream
hostnames, and HTTP status codes are exactly what a maintainer needs and
are not secrets by default.

For suspected security vulnerabilities specifically, use
[SECURITY.md](../SECURITY.md) instead of a public issue.

### Related documentation

- [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) — stable vs. experimental surface.
- [SECURITY.md](../SECURITY.md) — vulnerability reporting.
