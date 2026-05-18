# Tardigrade — Zig 0.16 Engineering Guide

This guide is Tardigrade-specific. It documents the Zig 0.16 patterns, APIs, and
constraints that apply to this codebase. It is not a generic Zig tutorial.

LLMs are often wrong about Zig 0.16 stdlib changes. Agents and reviewers must
consult this document rather than assuming general Zig knowledge is current.

---

## Project Principles

- **Boring, explicit, testable.** Runtime code should read like a sequence of
  obvious operations. Cleverness is a liability.
- **Small modules with clear ownership.** Each file owns one concept. When a
  file exceeds ~1 000 lines, treat it as a split candidate.
- **Avoid broad rewrites.** Refactor only when the change reduces risk or
  unlocks a concrete feature. Cosmetic restructuring is not worth its merge
  cost.
- **Isolate OS-specific code.** Platform calls (`std.posix`, `std.c`, kqueue,
  epoll, OpenSSL) belong in the modules that require them. Do not scatter them
  into business logic.

---

## Zig 0.16 APIs and Patterns

### `std.Io`

Zig 0.16 introduces `std.Io` as the canonical I/O interface. Tardigrade uses a
global `compat.io()` singleton as a migration bridge (see `src/zig_compat.zig`).

**Long-term pattern** — inject `std.Io` explicitly rather than reaching through
the global:

```zig
// Before: global singleton
pub fn doWork(allocator: std.mem.Allocator) !void {
    var dir = std.Io.Dir.cwd().openDir(compat.io(), path, .{});
}

// After: explicit injection
pub fn doWork(io: std.Io, allocator: std.mem.Allocator) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{});
}
```

At unmigrated call sites pass `compat.io()` as the `io` argument. Migrate one
module at a time; do not rewrite unrelated modules in the same PR.

Modules still using the global singleton are tracked in `AGENTS.md`.

### `std.Io.Dir` and `std.Io.File`

`std.Io.Dir` and `std.Io.File` replace the Zig 0.13-era `std.fs.Dir` /
`std.fs.File` for new code.

- Open directories via `std.Io.Dir.cwd().openDir(io, path, .{})`.
- Pass an `io` handle so the operation participates in the runtime I/O model.
- Do not use `std.fs.cwd()` in new code (see [APIs to Avoid](#apis-to-avoid)).

### `std.process.spawn`

Use `std.process.spawn` for child process creation. The API requires explicit
stdin/stdout/stderr configuration; do not leave them as inherited unless that is
intentional and documented.

```zig
var child = try std.process.spawn(allocator, &.{ "program", "arg" }, .{
    .stdin_behavior = .Ignore,
    .stdout_behavior = .Pipe,
    .stderr_behavior = .Inherit,
});
defer child.wait() catch {};
```

### Unmanaged `std.ArrayList`

Prefer `std.ArrayListUnmanaged` when the list is stored in a struct that already
carries an allocator, to avoid duplicating the allocator pointer:

```zig
// Prefer this for struct fields:
items: std.ArrayListUnmanaged(Item) = .{},

// Then pass the allocator at each mutating call:
try state.items.append(allocator, item);
state.items.deinit(allocator);
```

Use the managed `std.ArrayList` only in short-lived local scopes where passing
the allocator repeatedly would obscure intent.

### `std.mem.find` / `findScalar` / `findPos`

Zig 0.16 replaces the old `std.mem.indexOf` family:

| Old (avoid)             | New (use)                      |
|-------------------------|--------------------------------|
| `std.mem.indexOf`       | `std.mem.find`                 |
| `std.mem.indexOfScalar` | `std.mem.findScalar`           |
| `std.mem.indexOfPos`    | `std.mem.findPos`              |

All three return an optional index (`?usize`). Use them consistently; do not
mix old and new forms in the same file.

### `std.crypto`

- Use `std.crypto` for HMAC, hashing, and CSPRNG needs inside Zig code.
- Do **not** call OpenSSL crypto functions directly from Zig unless you are
  inside a TLS or ACME path that already depends on OpenSSL (see the audit in
  `AGENTS.md`).
- Use `std.crypto.random` for cryptographically secure random bytes. Never use
  `std.rand` for security-sensitive values.
- Zero sensitive buffers with `std.crypto.secureZero` before freeing.

### `std.testing.allocator`

- Use `std.testing.allocator` in all unit tests. It detects leaks automatically
  and fails the test if any allocation is not freed.
- Do not use a `GeneralPurposeAllocator` or fixed buffer in tests unless you
  are testing allocator-specific behavior (e.g., OOM handling).
- Always pair `deinit` calls with `defer` so they run even on test failure:

```zig
test "example" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(u8){};
    defer list.deinit(alloc);
    // ...
}
```

---

## APIs to Avoid

| Avoid | Reason |
|---|---|
| `std.fs.cwd()` in new code | Deprecated path; use `std.Io.Dir.cwd()` with an `io` handle |
| `std.mem.indexOf` / `indexOfScalar` / `indexOfPos` | Replaced by `find` / `findScalar` / `findPos` in 0.16 |
| `std.Thread.Pool` | Removed in Zig 0.13. Tardigrade uses manual `std.Thread.spawn` (see `AGENTS.md`) |
| `std.Io.Group` for blocking tasks | `Io.Group` expects non-blocking async tasks; blocking calls stall the whole group |
| Hidden global allocation ownership | Every allocation must have a visible free/deinit path |
| `catch {}` without a comment | Silent swallowing is only acceptable for documented best-effort operations |

When you encounter one of these in existing code, prefer fixing it in an
isolated cleanup PR rather than mixing it into a feature change.

---

## Runtime Architecture

### Main Event Loop

The main thread runs a level-triggered epoll/kqueue loop on the listener socket.

- `accept()` is called in a tight drain loop before returning to `epoll_wait` /
  `kevent`. Level-triggered mode ensures no connection is silently dropped.
- The main thread never performs blocking I/O on connection sockets.
- Timer ticks fire background housekeeping: hot-reload, log rotation,
  proxy-cache maintenance, and active health probes.
- DNS resolution (`runDnsDiscoveryRefresh`) runs in the timer-tick path; the
  blocking resolve completes in < 1 ms on LAN and does not materially affect
  accept latency.

### Worker Threads

Each accepted connection is switched to blocking mode before dispatch.

- Workers perform blocking `read` / `write` / `SSL_read` / `SSL_write` on
  their assigned connection.
- TLS handshake, request parsing, upstream proxying, and response writing are
  all blocking operations inside the worker.
- The worker pool is implemented with manual `std.Thread.spawn` (not
  `std.Thread.Pool` or `std.Io.Group`) because the blocking I/O model is
  incompatible with group-managed async execution.

### Background Threads

Long-running blocking operations that must not block the event loop run in
dedicated background threads:

- Active health probes use a dedicated thread guarded by
  `GatewayState.health_probe_running` (atomic bool).
- Each background thread that reads config must hold a `ConfigLease` for its
  lifetime so hot-reload cannot free the config while work is in flight.

### Blocking vs Non-Blocking Boundaries

| Context | Mode | Rationale |
|---|---|---|
| Listener socket (main thread) | Non-blocking | Required for drain-accept loop |
| Connection socket (worker thread) | Blocking | TLS + HTTP parsing require contiguous reads |
| Background threads | Blocking | Isolated from event loop; short-lived |

### Future `std.Io` Injection

The `compat.io()` singleton is a migration bridge. As modules are migrated,
they should receive `std.Io` as an explicit parameter. Do not migrate more than
one module per PR. The migration list is tracked in `AGENTS.md`.

---

## Allocator and Ownership Rules

### When to Use Each Allocator

| Allocator | Use when |
|---|---|
| `std.heap.smp_allocator` | Shared process-lifetime runtime state in the `run` path — `GatewayState`, long-lived config, HTTP/2 connection state |
| `std.heap.DebugAllocator` | One-shot CLI/control-plane work where leak/use-after-free diagnostics matter more than throughput |
| `std.heap.ArenaAllocator` | Request-scoped allocations that all free at the same time; config validation |
| `BufferPool` (slab) | Request and relay read buffers; reused across requests to reduce GPA pressure |
| `std.testing.allocator` | All unit tests |

Tardigrade's Zig 0.16 toolchain does not expose the old
`std.heap.GeneralPurposeAllocator` API in the runtime path here. For shared
multi-threaded gateway state, use `std.heap.smp_allocator` instead of
re-introducing `DebugAllocator` into the long-lived `run` path.

### Ownership Rules

- Every allocation must have a visible `defer x.deinit(allocator)` or `defer
  allocator.free(x)` at the point of allocation.
- Use `errdefer` for partial construction so allocations are freed on any error
  path:

```zig
const buf = try allocator.alloc(u8, size);
errdefer allocator.free(buf);
const thing = try Thing.init(allocator, buf);
errdefer thing.deinit(allocator);
```

- Do not store an allocator pointer inside a struct unless the struct has a
  `deinit(self: *Self)` that uses it. Prefer `deinit(self: *Self, allocator:
  std.mem.Allocator)` for structs that do not need to retain the allocator.
- Do not share arenas across request boundaries. A per-request arena must be
  deinited before the response is written.

---

## Error Handling Rules

- **No silent swallowing.** `catch {}` is only acceptable for explicitly
  best-effort operations (sleep, log flushing, non-critical socket options).
  Add a comment explaining why the error is safe to ignore.
- **Return errors; avoid panics.** Use `return error.SomeName` at boundaries
  where the caller can recover. Panics are for invariants that cannot be
  violated if the code is correct.
- **Use `unreachable` / `std.debug.assert` only for impossible states.** If the
  condition can be caused by user input, external data, or a race, use an error
  instead.
- **Every expected failure path needs a test.** If a function can return an
  error, there must be a test that exercises that path.

```zig
// Good: best-effort with explanation
setNonBlocking(fd) catch {}; // blocking mode still works; best-effort

// Bad: hiding a real error
parseRequest(buf) catch {};
```

---

## Security-Sensitive Coding Rules

### Header Parsing

- Strip hop-by-hop headers (and headers named by the incoming `Connection`
  header) before forwarding requests upstream.
- Reject requests with both `Transfer-Encoding` and `Content-Length` (TE/CL
  conflict; request-smuggling vector).
- Enforce maximum header count and maximum individual header size limits.
- Never pass raw header values to format strings or shell commands.

### Request Smuggling

- Reject ambiguous framing (both `TE` and `CL`, or multiple `CL` values).
- Normalize chunked encoding before proxying.
- Do not forward `Transfer-Encoding: chunked` to HTTP/1.0 upstreams.

### Path Normalization

- Percent-decode and normalize all request paths before filesystem access.
- Reject paths that resolve outside the configured root after normalization.
- Apply normalization before pattern matching (location blocks), not after.

### Symlink Escapes

- Use `openat`-based traversal, not string concatenation, for filesystem paths.
- Reject symlinks that point outside the configured root. Do not follow them.

### Auth Boundaries

- Authentication checks must run before any handler logic.
- Do not cache auth decisions across requests without validating the session is
  still valid.
- Validate JWT signatures and expiry before inspecting claims.

### Logging Redaction

- Do not log `Authorization` header values.
- Do not log request bodies unless explicitly enabled and the body contains no
  sensitive fields.
- Redact tokens and credentials in error messages before writing to the access
  log.

### TLS / OpenSSL Interop

- Use `std.c.malloc` / `std.c.free` only for buffers passed to OpenSSL C
  callbacks. OpenSSL owns those allocations.
- Do not mix Zig allocator-owned and OpenSSL-owned buffers in the same struct
  field without clear ownership documentation.
- Use OpenSSL's ALPN/SNI callbacks only for negotiation; do not perform request
  processing inside a callback.

---

## Testing Requirements

- **Every parser gets table-driven tests.** Cover valid inputs, boundary values,
  and malformed inputs in the same table.
- **Every security fix gets a regression test.** The test must fail on the
  unfixed code and pass after the fix.
- **Every config option gets a validation test.** Test both valid and invalid
  values, and test the resulting error message.
- **Every concurrency primitive gets shutdown and drain tests.** Verify that
  in-flight work completes (or is discarded) and threads join cleanly.
- **Every new protocol behavior gets integration coverage.** Add an integration
  test in `tests/` that exercises the behavior end-to-end.

### Table-Driven Test Pattern

```zig
test "parseContentLength" {
    const cases = [_]struct {
        input: []const u8,
        want: ?u64,
    }{
        .{ .input = "0",   .want = 0 },
        .{ .input = "42",  .want = 42 },
        .{ .input = "-1",  .want = null },
        .{ .input = "abc", .want = null },
        .{ .input = "",    .want = null },
    };
    for (cases) |c| {
        const got = parseContentLength(c.input);
        try std.testing.expectEqual(c.want, got);
    }
}
```

---

## Cross-Reference

For deeper context on topics covered briefly above, see:

| Topic | Location |
|---|---|
| WorkerPool design rationale | `AGENTS.md` — WorkerPool Design Rationale |
| `std.c` / `std.posix` audit | `AGENTS.md` — std.c / std.posix Usage Audit |
| `compat.io()` migration pattern | `AGENTS.md` — compat.io() Migration Pattern |
| Shared state and mutex inventory | `AGENTS.md` — Shared State Inventory |
| Event loop I/O model detail | `AGENTS.md` — Event Loop I/O Model |
| Architecture and ownership audit | `AGENTS.md` — Architecture and Ownership Audit |
| Performance targets and benchmarks | `AGENTS.md` — Zig 0.16 Performance Characteristics |
| Security-sensitive coding rules (pentest) | `docs/PENTEST_PLAYBOOK.md` |
| Security test plan | `docs/SECURITY_TEST_PLAN.md` |
