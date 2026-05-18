# Agent Guide

Scope: the `Tardigrade` repository.

## Key References

Before making any code changes, read these documents:

- **[docs/ZIG_ENGINEERING_GUIDE.md](docs/ZIG_ENGINEERING_GUIDE.md)** — Zig 0.16 patterns, APIs to avoid, runtime architecture, allocator rules, error handling, security rules, and testing requirements.
- **[docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)** — Official Core v1 scope and feature maturity levels (`stable`, `experimental`, `adapter`, `internal`).
- **[docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md)** — Short checklist to run on every non-trivial change before committing.

## Rules

- Keep the core runtime generic. Do not add product-specific logic to core.
- Put integrations under `examples/`.
- Keep docs concise and operator-focused.
- Runtime allocator policy: keep `DebugAllocator` for one-shot control-plane
  work, and keep the long-lived `run` path on `std.heap.smp_allocator` plus
  request-scoped arenas/buffer pools.
- New user-facing work must declare its target maturity level and update `docs/SUPPORT_MATRIX.md` when the public support contract changes.

## Workflow

- Keep active unfinished work in `ROADMAP.md`.
- Update `README.md` for operator-facing behavior.
- Update `BLINK.md` for deployment reality.
- Record notable repo changes in `CHANGELOG.md`.

## Validation

```bash
zig build test
zig build test-integration
```

## Benchmarks

Run benchmarks on a dedicated benchmark target against `127.0.0.1` for canonical numbers. Label any local fallback runs as non-canonical.
