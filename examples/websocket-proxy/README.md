# WebSocket Proxying (`proxy_websocket`)

Relays WebSocket connections through `proxy_pass`, so an application behind
Tardigrade can use WebSockets the way it would behind NGINX
(`proxy_http_version 1.1` + `Upgrade`/`Connection`), Caddy or Traefik.

Maturity: `experimental` (see [SUPPORT_MATRIX.md](../../docs/SUPPORT_MATRIX.md)).

## What it demonstrates

- Opting a location in with `proxy_websocket on;`. Other locations keep
  stripping `Upgrade` and never switch protocols.
- The idle timeout, a maximum tunnel lifetime and the per-process tunnel cap.
- An `Origin` allowlist that stops cross-site WebSocket hijacking.
- `proxy_set_header` applied to the upstream handshake.

## Quick start

```bash
zig build
python3 examples/websocket-proxy/echo_server.py &      # echo origin on :9000
TARDIGRADE_CONFIG_PATH=examples/websocket-proxy/tardigrade.conf ./zig-out/bin/tardi &

python3 examples/websocket-proxy/client.py ws://127.0.0.1:8080/ws/echo
# HTTP/1.1 101 Switching Protocols
# echo: hello through tardigrade
# pong: (10, b'ping')
# close: (8, b'\x03\xe8')

python3 examples/websocket-proxy/client.py ws://127.0.0.1:8080/app-socket/ http://evil.example
# HTTP/1.1 403 Forbidden

python3 examples/websocket-proxy/client.py ws://127.0.0.1:8080/app-socket/ http://localhost:8080
# HTTP/1.1 101 Switching Protocols ...

curl -s http://127.0.0.1:8080/status/metrics | grep tardigrade_websocket_
```

Browsers work the same way: `new WebSocket("ws://127.0.0.1:8080/ws/echo")`.
With TLS configured, `wss://` clients are terminated by Tardigrade, and a
`proxy_pass https://...` origin is reached as `wss://` under the usual
upstream TLS verification rules.

## How a handshake is decided

1. Rate limits, access control, `auth required`, `forward_auth` and path
   policy run first. A denied handshake never reaches the origin.
2. The handshake must be a valid RFC 6455 opening handshake (400 otherwise;
   426 for another `Sec-WebSocket-Version`), and a browser `Origin` must be
   in `proxy_websocket_origins` when that is set (403 otherwise).
3. A tunnel slot is reserved (503 when `proxy_websocket_max_tunnels` is
   reached), and a fresh HTTP/1.1 connection goes to the origin with
   Tardigrade's forwarding headers plus `Upgrade: websocket`.
4. A `101` with the right `Sec-WebSocket-Accept` is relayed and the tunnel
   opens. Anything else is relayed as a normal response (a 101 with a wrong
   accept value becomes 502).

## Operating notes

- Each open tunnel holds a worker thread. The default cap is half of
  `worker_threads`, rounded down, so a single-worker process refuses
  upgrades with 503; raise both together for many long-lived sockets.
- Quiet connections are closed after `proxy_websocket_idle_timeout_ms`
  (default 60 s). Send pings more often than that.
- On `tardi stop`, open tunnels keep working for the drain window
  (`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`) and are then closed.
- HTTP/2 and HTTP/3 extended CONNECT are not supported; browsers open
  WebSockets over HTTP/1.1.

See [docs/CONFIGURATION.md](../../docs/CONFIGURATION.md#websocket-proxying-proxy_websocket)
for the full contract.
