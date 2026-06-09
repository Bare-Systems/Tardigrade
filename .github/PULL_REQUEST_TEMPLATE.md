**What changed and why**
Brief description of the change and the motivation behind it.

**Related issues**
Closes #

**Tests**
Describe the tests added or updated. If no tests were added, explain why.

**Security impact**
Does this change affect header parsing, routing, auth, TLS, path handling, or
logging? If yes, describe what was reviewed. If no, write "None."

**Performance impact**
Does this change affect the event loop, worker pool, or a hot path? If yes,
describe the expected impact. If no, write "None."

**Checklist**
- [ ] `zig fmt --check build.zig src/ tests/` passes
- [ ] `zig build test --summary all` green
- [ ] `zig build test-integration` green (required for protocol, proxy, and TLS changes)
- [ ] New behavior covered by tests
- [ ] [docs/CODE_REVIEW_CHECKLIST.md](docs/CODE_REVIEW_CHECKLIST.md) completed
- [ ] README / CHANGELOG updated if operator-visible behavior changed
