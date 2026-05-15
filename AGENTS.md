# Agent Guide

Scope: the `Tardigrade` repository.

## Key References

Before making any code changes, read these documents:

- **[docs/ZIG_ENGINEERING_GUIDE.md](docs/ZIG_ENGINEERING_GUIDE.md)** — Zig 0.16 patterns, APIs to avoid, runtime architecture, allocator rules, error handling, security rules, and testing requirements.
- **[docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md)** — Short checklist to run on every non-trivial change before committing.

## Rules

- Keep the core runtime generic. Do not add product-specific logic to core.
- Put integrations under `examples/`.
- Keep docs concise and operator-focused.

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
