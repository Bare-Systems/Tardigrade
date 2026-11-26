# Local builds

Use `./scripts/zig-build` instead of direct `zig build` for local builds and
tests. It forwards the same arguments and automatically bounds retained local
and global compiler caches to 8 GiB per checkout. See CONTRIBUTING.md for the
retention policy. Use `./scripts/zig-build test-fast` or a narrower target for
ordinary iteration; follow CONTRIBUTING.md for required validation.
