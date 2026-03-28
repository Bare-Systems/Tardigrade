# Contributing to Tardigrade

## Setup

```bash
zig build test
zig build test-integration
```

If you work on the optional HTTP/3 path, run the relevant HTTP/3-enabled variants as well.

## Expectations

- Preserve generic gateway behavior and avoid product-specific shortcuts in the core runtime.
- Update `README.md` for operator-facing changes.
- Update `BLINK.md` when build, deploy, rollback, or verification behavior changes.
- Update `CHANGELOG.md` for notable repo changes.

Active unfinished work belongs in the workspace root `ROADMAP.md`.
