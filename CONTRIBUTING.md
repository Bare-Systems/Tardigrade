# Contributing

## Workflow

Tardigrade uses `UPGRADES.md` as the implementation backlog and execution order.

When contributing:

1. Pick the next unchecked item in [UPGRADES.md](./UPGRADES.md)
2. Make one focused change at a time
3. Add or update a short reference note under `changes/`
4. Keep [CHANGELOG.md](./CHANGELOG.md) current while you work
5. Run the local test suite before considering the change done

## Development Setup

Prerequisites:

- Zig `0.14.1+`
- OpenSSL 3 headers and libraries available to Zig
- Homebrew `curl` with HTTP/3 support if you need the HTTP/3 integration path

Basic loop:

```bash
zig build test
zig build test-integration
```

If you are touching the HTTP/3/ngtcp2 path, also run:

```bash
zig build test -Denable-http3-ngtcp2=true
zig build test-integration -Denable-http3-ngtcp2=true
```

## Change Notes

Each feature-sized change should get a short note under `changes/` that records:

- scope
- files changed
- tests added or updated
- current status

This repo has accumulated a lot of behavior behind feature increments; the `changes/` notes are
how later contributors understand why a path exists and what it was meant to guarantee.

## Quality Bar

- Prefer incremental, verifiable changes over broad rewrites
- Preserve existing behavior unless the upgrade explicitly changes it
- Add integration coverage for gateway, protocol, or process-lifecycle changes
- Do not leave speculative or half-wired code paths in the tree

## Docs

If you change behavior visible to operators or integrators, update:

- [README.md](./README.md)
- [CHANGELOG.md](./CHANGELOG.md)
- the relevant note in `changes/`
