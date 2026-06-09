# Code Review Checklist

Use this checklist on every non-trivial PR. Keep it short — if a check takes
more than a minute, it belongs in a separate automated test.

---

## Build and Tests

- [ ] `zig fmt --check build.zig src/ tests/` passes with no diff
- [ ] `zig build test --summary all` green
- [ ] `zig build test-integration` green (required for protocol, proxy, and TLS changes)
- [ ] New behavior is covered by at least one new test
- [ ] Every expected error path has a test

## Memory and Allocators

- [ ] Every allocation has a visible `defer deinit` or `defer free` at the point
      of allocation
- [ ] `errdefer` guards partial construction so errors do not leak
- [ ] No new uses of `std.Thread.Pool`, `std.fs.cwd()`, or `std.mem.indexOf`
- [ ] `std.testing.allocator` used in all new unit tests

## Error Handling

- [ ] No new `catch {}` without a comment explaining why the error is safe to ignore
- [ ] New panics and `unreachable` sites are justified by an invariant that
      cannot be violated by external input
- [ ] Errors are returned to the caller rather than converted to panics where
      recovery is possible

## Security Impact

Answer these for every change that touches request parsing, routing, auth,
headers, TLS, or file serving:

- [ ] Does this change affect header parsing? If yes: hop-by-hop stripping, TE/CL
      conflict detection, and size limits are still enforced.
- [ ] Does this change affect path handling? If yes: normalization runs before
      matching and symlink escapes are still rejected.
- [ ] Does this change affect auth? If yes: checks run before handler logic and
      no auth decision is cached without revalidation.
- [ ] Does this change affect logging? If yes: `Authorization` values and tokens
      are still redacted.
- [ ] Does this change expose a new regression? If yes: a regression test is
      included.

## Performance Impact

Answer these for changes that touch the event loop, worker pool, or hot paths:

- [ ] Does this change affect the event loop main thread? If yes: no new blocking
      I/O is introduced on the main thread.
- [ ] Does this change affect request throughput? If yes: a before/after
      benchmark comparison is included or throughput is not expected to change.
- [ ] Does this change affect allocator pressure? If yes: per-request arenas or
      buffer reuse are considered.

## Documentation

- [ ] `CHANGELOG.md` updated with a short description of the change
- [ ] `README.md` updated if operator-visible behavior changed
- [ ] `BLINK.md` updated if deployment topology or blink.toml behavior changed
- [ ] `AGENTS.md` updated if architecture decisions or shared-state inventory changed
