# Reload, Drain, and Shutdown

Tardigrade has three distinct lifecycle paths:

- **Hot reload** (`tardi reload`, `SIGHUP`) validates and publishes a new runtime
  configuration without stopping the process.
- **Graceful shutdown** (`tardi stop`, `SIGTERM`, `SIGINT`, or `SIGUSR2` upgrade)
  stops accepting new work and drains worker jobs before exit.
- **Hard termination** (`SIGKILL`, process crash, or an external supervisor kill
  after its own timeout) is outside Tardigrade's graceful path; the OS closes
  sockets and in-flight requests can be interrupted.

## Commands

Use a PID file in production so control commands can find the running process:

```bash
TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf \
TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid \
./zig-out/bin/tardi run
```

Validate config edits before publishing them:

```bash
./zig-out/bin/tardi check /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid
./zig-out/bin/tardi status --pid-file /run/tardigrade/tardigrade.pid
./zig-out/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid
```

`tardi reload` sends `SIGHUP`. `tardi stop` sends `SIGTERM`. Both commands also
accept `--pid <pid>` when a PID file is not available.

For systemd installs, validate first and then let the unit's `ExecReload` run:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
sudo systemctl reload tardigrade
sudo systemctl stop tardigrade
```

This standalone `tardi check` validates `tardigrade.conf` only — it doesn't
load `/etc/tardigrade/tardigrade.env`, so it isn't a complete pre-flight
check of everything the running service uses. See
[DEPLOYMENT.md#commands](DEPLOYMENT.md#commands) for the full
validation/reload/restart contract, including why `tardigrade.env` edits
need a restart rather than a reload, and the current single-process-only
scope of this control path (`master_process true;` doesn't yet get coherent
SIGHUP/PID-file reload across workers).

Set systemd `TimeoutStopSec` slightly above
`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` so systemd does not escalate to a hard
kill before Tardigrade's drain has finished.

## Hot Reload

On `SIGHUP`, the gateway handles reload on the maintenance tick:

1. Load the new config from the configured source.
2. Validate it.
3. Prepare reload-owned runtime resources, such as reloadable TLS credentials.
4. Reject the reload if it changes process-owned settings that require a
   restart, such as listener shard topology, HTTP/3 listener-owned settings,
   native early-data replay mode/capacity, native ticket-key source mode, or
   (see "TLS Credential Identity" below) a certificate/key/SNI change on a
   build where that would leave two TLS surfaces on different identities.
5. Publish the new config through the lease-counted config store.

New requests acquire the newly published config after step 5. In-flight requests
retain their original config lease for request-scoped config reads. Reload also
updates some process-shared runtime policy, so an in-flight request is not a
fully isolated snapshot of the previous runtime configuration. Reload does not
drain worker jobs, stop the listener, or close active client connections.

If reload fails before config publication, the previously published config
remains active for request routing and config leases. Reload-owned runtime
resources are not fully transactional: a runtime update performed before a later
failure may remain in effect even though the new config is not published.
Operators can inspect the last result through:

```bash
curl http://127.0.0.1:8080/tardigrade/reload/status
```

The endpoint returns JSON in this shape:

```json
{"ok":false,"at_ms":1780000000000,"error":"validation rejected: InvalidConfigValue"}
```

Expected reload logs include:

```text
configuration hot-reload starting
configuration hot-reload applied
config reload failed during load: ...
config reload rejected by validation: ...
config reload rejected: ... restart the process ...
```

### TLS Credential Identity

Tardigrade has one TLS credential owner type per build profile, shared by
every protocol that profile serves (#649 retired the OpenSSL adapter and
the split-owner composition it used to require):

- The **native credential store**
  (`http.native_tls_connection.NativeCredentialStore`), used for *both*
  native TCP and native HTTP/3 on the general-purpose profile
  (`tls-profile=general`, the default, #634). It supports a real
  prepare/commit hot-swap of certificate, key, and SNI identity from the
  proposed reload paths, and `hotReloadConfig` uses that capability on
  every accepted `SIGHUP`: the configured certificate/key files' *content*
  is re-read and republished even when the configured *path* is unchanged,
  so an in-place certificate rotation at the same path is picked up. Since
  one store serves both protocols, that swap is a single atomic operation —
  TCP and HTTP/3 can never end up presenting different certificates for the
  same hostname (the hazard [#629](https://github.com/Bare-Systems/Tardigrade/issues/629)
  used to guard against under the old OpenSSL-TCP/native-HTTP3 split no
  longer exists, because that split no longer exists).
- **`ApplianceCredentials`**, the strict single-identity owner used on the
  appliance profile (`tls-profile=appliance`) for *both* native TCP and
  native HTTP/3. Although the type itself exposes reload methods, no
  runtime call path ever invokes them: `hotReloadConfig` rejects the whole
  reload outright via `applianceCredentialConfigChanged` for any change to
  `TLS_CERT_PATH`/`TLS_KEY_PATH`/`TLS_SERVER_NAME`/`TLS_SNI_CERTS`, so in
  practice appliance credentials are fully startup-owned — a `SIGHUP` never
  changes what either protocol serves.

TLS *topology* is still startup-owned in every profile: the credential
store/provider is created only when cert/key paths exist at startup, so
`hotReloadConfig` rejects any reload that would turn TLS on for a process
that started plaintext, or off for one that started with TLS — "enabling or
disabling native TLS requires restart".

## Active Connections

Tardigrade tracks accepted client connections separately from requests:

- A keep-alive connection holds one connection slot while it is parked between
  requests.
- Parked keep-alive connections do not occupy a worker thread.
- When a parked connection sends another request, it is resumed and submitted to
  the worker pool.
- On hot reload, parked and active client connections stay open. Their next
  request uses whichever config version they acquire at handler entry.
- On graceful shutdown, new accepts stop and keep-alive is disabled for requests
  already being handled, so connections close instead of being re-parked.
- Already-parked idle keep-alive connections are not worker jobs. They remain in
  the parked registry during worker drain and are closed when the downstream
  runtime is torn down; they do not extend the worker-pool drain deadline.

The main related knobs are:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` | `5000` | Idle parked downstream keep-alive timeout. |
| `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` | `100` | Maximum requests served before closing a downstream connection. |
| `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | `0` | Optional global accepted-connection cap (`0` means unlimited). |
| `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | `0` | Optional in-flight request cap (`0` means unlimited). |

See [TIMEOUTS.md](TIMEOUTS.md) for request phase timeout semantics.

## Worker Jobs and Drain

Graceful shutdown is the path that uses the drain timeout. Once shutdown is
requested, the accept loop exits and the TCP worker pool drains with
`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` (default `30000` ms).

Drain behavior:

- Active, already-dispatched handlers are allowed to finish naturally.
- Requests whose handler/lifecycle starts after shutdown has been requested cap
  their request deadline to the drain window when no stricter deadline exists.
  Requests already executing when shutdown is requested keep their existing
  lifecycle and phase deadlines.
- Queued, not-yet-started connection jobs wait until the drain deadline.
- If the drain deadline expires, remaining queued file descriptors owned by the
  worker queue are closed and counted as forced closes.
- A drain timeout of `0` skips the wait and abandons queued jobs immediately.
  Queue-owned unstarted accepted sockets are closed, while non-owning
  resume/poll work is discarded and cleaned up by its owning runtime state.

For TCP worker jobs, the drain timeout is a soft worker-drain cap: active
handlers are not killed inside the process. Their own phase deadlines,
downstream disconnects, or the supervisor's external stop timeout bound the
final exit.

Native HTTP/3 uses the same shutdown timeout as a QUIC/H3 drain deadline.
Shutdown refuses new QUIC connections, sends H3 GOAWAY, and rejects new request
streams past the drain boundary. Existing H3 work may complete before the
deadline; remaining H3 connections are closed when the deadline expires.

Expected TCP worker-pool shutdown logs include:

```text
Shutdown requested; draining active connection work (timeout=30000ms active_connections=...)
drain timeout elapsed; force-closed N queued connection(s)
Graceful shutdown complete (forced_closes=N drain_timed_out=true)
```

WebSocket tunnels (`proxy_websocket`, #812) are the exception to the soft
cap: an open tunnel keeps relaying for the drain window after shutdown is
requested and is then closed by Tardigrade itself (logged with
`tunnel_close_reason` `shutdown`), so a long-lived WebSocket never holds the
process open. Hot reload leaves tunnels open under the location settings they
were opened with. Streamed responses such as server-sent events are ordinary
handlers and follow the soft cap above.

Related knobs:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | `30000` | TCP worker-pool drain window and native HTTP/3 drain deadline for graceful shutdown. The final shutdown path uses the startup value; hot reload can publish a different request-scoped value, but the process drain/H3 deadline still requires restart to change coherently today. |
| `TARDIGRADE_WORKER_THREADS` | `0` | Startup-owned worker thread count; `0` uses the runtime default. Restart required to change. |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | `1024` | Startup-owned worker queue capacity. Restart required to change. |
| `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` | `0` | Startup-owned optional per-worker queue depth cap (`0` means unlimited beyond queue capacity behavior). Restart required to change. |

Related references:

- [TIMEOUTS.md lifecycle table](TIMEOUTS.md#lifecycle--operations) for timeout
  semantics of `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`.
- [examples/graceful-reload/tardigrade.env.example](../examples/graceful-reload/tardigrade.env.example)
  for commented PID-file and drain-timeout configuration.

## Upstream Keepalive Pools

Upstream pools are origin-side keepalive caches. They are independent from the
downstream client connection lifecycle:

- Hot reload keeps existing upstream idle and active pooled connections alive.
- Requests already using an upstream connection finish under their current
  request/config lease.
- New requests use the current request config, but they may still reuse an
  existing pooled connection governed by the pool policy installed at startup.
- Idle upstream connections are evicted by the maintenance tick when they exceed
  idle or lifetime limits.
- Shutdown closes idle upstream pool connections during runtime teardown after
  worker drain.

Hot reload does not reconfigure the process-owned upstream pool policy. Changes
to pool enablement, capacity, idle timeout, lifetime, or active checkout limits
require a restart today; existing pool instances and their startup policy remain
in effect. Reloaded proxy-buffer limits are the exception and are applied through
the pool's runtime setters.

Related knobs:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_UPSTREAM_POOL_ENABLED` | `true` | Enables HTTP/1 upstream keepalive reuse. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST` | `32` | Maximum idle upstream HTTP/1 connections per origin. |
| `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | `90000` | Idle upstream pool eviction age. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS` | `0` | Maximum pooled connection lifetime (`0` means unlimited). |
| `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` | `0` | Optional fail-fast active checkout cap per origin. |

See [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) for the complete pool contract.

## Observability

Lifecycle logs are emitted through the runtime logger. Metrics are exposed at
the configured metrics path, `/status/metrics` by default:

| Metric | Meaning |
| --- | --- |
| `tardigrade_reload_attempts_total` | Reloads started. |
| `tardigrade_reload_success_total` | Reloads successfully installed. |
| `tardigrade_reload_failure_total` | Reloads rejected; previous config kept. |
| `tardigrade_drain_total` | Graceful-shutdown drains started. |
| `tardigrade_drain_timeouts_total` | TCP worker-pool drains that reached a positive drain deadline before worker jobs finished; does not report native H3 deadline expiry. |
| `tardigrade_drain_forced_closes_total` | Queue-owned unstarted TCP accepted sockets closed on worker drain expiry or an immediate zero-timeout shutdown. |
| `tardigrade_active_connections` | Currently accepted downstream connections. |
| `tardigrade_worker_active_jobs` | Worker jobs currently running. |
| `tardigrade_worker_queued_jobs` | Worker jobs waiting in queues. |

See [OBSERVABILITY.md](OBSERVABILITY.md) for full metric and logging details,
and [examples/graceful-reload](../examples/graceful-reload/README.md) for a
copy/paste runnable local workflow.
