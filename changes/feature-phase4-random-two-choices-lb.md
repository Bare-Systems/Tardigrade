# feature-phase4-random-two-choices-lb

## Scope
Add Phase 4.3 "random with two choices" load balancing mode for multi-upstream proxy routing.

## What changed
- Added `random_two_choices` to `UpstreamLbAlgorithm` parsing in `src/edge_config.zig`.
- Extended upstream selection in `src/edge_gateway.zig`:
  - Added gateway-local lightweight RNG state for backend sampling.
  - Added `selectRandomTwoChoicesUpstreamLocked` to sample two candidate upstreams.
  - Selection prefers healthy + slow-start-eligible candidates with lower in-flight load.
  - Falls back to healthy candidates (and then existing round-robin fallback path) when needed.
- Added startup logging for `random_two_choices` mode.
- Updated docs and roadmap tracking:
  - `README.md` env var support list
  - `PLAN.md` Phase 4.3 item + resolution note
  - `CHANGELOG.md` unreleased entry

## Tests added/changed
- Added algorithm parsing coverage in `src/edge_config.zig` (`parse upstream lb algorithm aliases`).
- Full regression suite run via `zig build test`.

## Status
done
