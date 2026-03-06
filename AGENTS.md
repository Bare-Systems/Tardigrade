
Your purpose is to create, maintain, and implement the instructions of a `PLAN.md` file in a **target repository**.

You should always refer to the `PLAN.md` file for guidance on how to proceed with tasks, the order to progress, and any other specific instructions provided.

Work incrementally. Implement features one at a time and create a short reference document for each feature under the `changes/` folder (for example `changes/feature-autoindex.md`). Each `changes/*` file should summarize the scope, what was added, tests added/changed, and the status (in-progress / done).

Changelog policy
- Keep `CHANGELOG.md` updated as you make changes. For every branch you create to implement a feature or fix, add a new entry to `CHANGELOG.md` using the project's semantic-versioned release sections. At minimum include the version header and a short bullet under the appropriate section (e.g., `### Added`) noting the feature or fix. This ensures the changelog tracks work in progress and prevents forgetting release notes when merging.

Branch and versioning guideline
- When you create a feature branch, add a new unreleased semantic-version entry in `CHANGELOG.md` (for example `## [0.6.0] - 2026-02-xx`) and add the short bullets for the work you plan to do. Keep that heading at the top of the changelog while the branch is active. When the branch is merged into `main`, update the date to the merge date and ensure the bullets accurately reflect the final implementation.

Practical checklist for each feature branch
- Create branch: open `CHANGELOG.md` and add a topmost, new semantic-version heading with placeholder date and initial bullets.
- Create `changes/feature-xyz.md` describing scope, files changed, tests, and acceptance criteria.
- Implement code and unit tests; keep commits small and focused.
- Update the `changes/feature-xyz.md` with progress notes and mark done when finished.
- Update `PLAN.md` if the work changes project priorities or next steps.
- Run the full test suite locally (`zig build test`) and fix failures before merging.
- When merging: update the `CHANGELOG.md` date, squash or clean commits if desired, and push to `main`.

If `PLAN.md` is missing or incomplete, create or update it based on the repository state and the small-feature workflow above. Always record decisions (why a heuristic ETag was chosen, why a streaming vs in-memory path was used, etc.) so future contributors can follow the rationale.

This file documents the collaboration expectations: keep changelog and change-reference files updated continuously, and add a semantic-versioned changelog entry for every branch so release notes are never lost.