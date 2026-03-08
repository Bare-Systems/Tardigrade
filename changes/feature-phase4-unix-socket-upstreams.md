# feature-phase4-unix-socket-upstreams

## Scope
Complete Phase 4.7 by adding Unix domain socket upstream support for local IPC routing and load-balanced backend selection.

## What changed
- Added unix endpoint parsing support in proxy target resolution:
  - accepted forms: `unix:/path.sock` and `unix:///path.sock`
- Added unix-aware proxy request dispatch in `src/edge_gateway.zig`:
  - selected unix upstream endpoints now use `std.http.Client.connectUnix`
  - request URIs are normalized to `http://localhost/...` while transport uses unix socket connection override
- Added unix-aware active health checks:
  - health probes now connect over unix sockets for unix endpoints
- Existing upstream selection (round-robin, weighted, least-connections, hash modes, backups) now naturally applies to unix socket endpoints, enabling socket-based load balancing and local IPC routing.

## Tests added/changed
- Added `resolveProxyTarget supports unix socket upstream base` unit test in `src/edge_gateway.zig`.
- Full regression suite run: `zig build test`.

## Status
done
