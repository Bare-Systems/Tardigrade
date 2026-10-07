# WebSocket reactor validation

This is the focused WebSocket-only evidence for #830. It deliberately does not replace #819's mixed WebSocket, SSE, and REST long-duration validation. The reactor claims here are bounded ownership and resource-settle claims, not throughput claims.

## PR smoke

`zig build test-integration-websocket-reactor-smoke` starts a real Tardigrade process with one request worker, two WebSocket reactor threads, and a per-process tunnel cap equal to the requested population (24 by default). It opens the population concurrently, verifies that all established tunnels have been handed to the two reactor threads, proves a cap rejection without an extra origin handshake, relays traffic through several tunnels, measures ordinary `/healthz` requests before and during socket load, churns half the population, and waits for tunnel/reactor/connection accounting to settle.

The command is a normal Linux PR-CI gate. CI writes and uploads a JSON evidence artifact named `websocket-reactor-smoke` with the source SHA, platform, fixed worker/reactor counts, requested tunnel count, handoffs, cap rejections, REST worst-case latency before/during load, and whether resource settle completed. The test fails rather than emitting a successful artifact if any invariant is not met.

The smoke has companion coverage in the same integration suite for upstream connect/101 failure, client abort, native-TLS `wss://` downstream and upstream, idle/lifetime expiry, reload preserve/drain (including repeated reload and failed reload), and graceful shutdown. `src/http/tunnel_reactor.zig` adds deterministic socket-pair coverage for registration rollback, handoff failure, stalled-reader fixed buffers, timer wakeups, drain, shutdown, and 1,500 tunnels on two threads. The focused smoke stays small so it remains a useful PR signal rather than duplicating #819's mixed-traffic soak.

## Dedicated runner scale profile

Use a Linux runner with an `nofile` limit sufficient for at least four descriptors per requested tunnel plus normal process headroom. This asks for a 1,000-tunnel live plaintext population while retaining one request worker and two reactor threads:

```sh
ulimit -n 8192
TARDIGRADE_WS_REACTOR_SMOKE_TUNNELS=1000 \
TARDIGRADE_WS_REACTOR_EVIDENCE="$PWD/websocket-reactor-scale.json" \
TARDIGRADE_WS_REACTOR_SOURCE_SHA="$(git rev-parse HEAD)" \
zig build test-integration-websocket-reactor-smoke --summary all
```

The profile accepts 4 through 2,000 tunnels. It skips before opening sockets when the inherited descriptor limit cannot support the requested population; a skip is not scale evidence. Retain the JSON output with the runner machine description, OS/kernel, available CPU, and descriptor limit when passing the result to #819. The result demonstrates ownership, admission, and settle on that machine; it must not be used as an unsupported throughput or capacity claim for other machines.

Run the native-TLS subset alongside it:

```sh
zig build test-integration \
  -Dintegration-test-filter="proxy_websocket carries wss:// clients over native TLS to a wss:// origin (#812)" \
  --summary all
```

This test exercises reactor handoff on both native-TLS downstream and `wss://` upstream hops, then verifies that both edge processes settle their active and reactor-owned tunnel gauges.

## Evidence fields and thresholds

The Prometheus scrape remains the detailed source of truth during every phase:

- `tardigrade_websocket_tunnels_active` and `tardigrade_websocket_reactor_tunnels` must match the expected open population, then both return to zero.
- `tardigrade_websocket_reactor_threads` stays fixed at two; `tardigrade_websocket_reactor_handoffs_total` reaches one per successful handshake; and `tardigrade_websocket_reactor_thread_tunnels_max` remains below the whole population for two or more tunnels.
- `tardigrade_websocket_upgrades_total{outcome="capacity"}` increments for the deliberate cap rejection, before a new origin handshake occurs.
- `tardigrade_active_connections` returns to the pre-load baseline after every churn/close phase. The smoke treats ten seconds as a failed settle.
- Ordinary `/healthz` requests remain successful; the maximum loaded latency must remain below one second and below 20 times the measured baseline (whichever allowance is larger).

RSS and FD/socket counts are machine-specific operating-system measurements, not portable in-process gauges. Collect them with the dedicated runner's standard process monitor before load, after population, after churn, and after settle; record the values next to the JSON artifact. A monotonically rising post-settle RSS or FD/socket count is a failure to investigate, not a new published limit. #819 consumes these artifacts with its separate SSE and mixed-traffic evidence.
