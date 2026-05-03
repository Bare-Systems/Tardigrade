# Agent Guide

Scope: the `Tardigrade` repository.

## Rules

- Keep the core runtime generic.
- Do not add product-specific logic to core.
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
