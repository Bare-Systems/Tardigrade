# Feature: Phase 11.1 URL Rewriting Foundation

## Scope
Implement Phase 11.1 rewrite/return directive foundation with regex matching, flag handling, and conditional rule execution in the gateway request pipeline.

## What Was Added
- New module `src/http/rewrite.zig`:
  - POSIX regex matching helper (`regexMatches`) for path evaluation.
  - Rewrite flag enum + parser (`last`, `break`, `redirect`, `permanent`).
  - Rule types for rewrite and return directives.
  - Rule evaluator with bounded rewrite loops and method-conditional matching.
- `src/edge_config.zig`:
  - Added rewrite/return rule config fields to `EdgeConfig`.
  - Added env parsing:
    - `TARDIGRADE_REWRITE_RULES` format: `METHOD|REGEX|REPLACEMENT|FLAG` entries separated by `;`
    - `TARDIGRADE_RETURN_RULES` format: `METHOD|REGEX|STATUS|BODY` entries separated by `;`
  - Added allocation/deallocation lifecycle for parsed rule sets.
- `src/edge_gateway.zig`:
  - Added pre-routing rewrite evaluation in `handleConnection`.
  - Added pre-routing return/redirect short-circuit responses.
  - Rewritten path is applied before existing route matching/auth logic.
- `src/http.zig`:
  - Exported `http.rewrite` module.

## Tests Added/Changed
- New tests in `src/http/rewrite.zig` for:
  - flag parsing
  - regex matching
  - rewrite+return evaluation behavior
- New parser tests in `src/edge_config.zig` for rewrite/return env directives.
- Full suite run: `zig build test` (passing).

## Status
- done

## Notes / Decisions
- Rewrite matching is regex-based, but replacement is static path substitution (capture-group substitution is deferred).
- `last` rewrites can re-run rule evaluation in a bounded loop to avoid infinite rewrite cycles.
