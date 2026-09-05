# Fuzz Campaign Orchestration

Issue #739 owns setup only: resumable execution wrappers, evidence capture, and
disposable VM plumbing for the existing Zig fuzz targets. It does not satisfy
the sustained #675 campaign by itself.

## Local Runner

List the campaign-visible registry derived from the current source tree:

```bash
scripts/run-fuzz-campaign.sh --list
```

Run a cheap non-canonical smoke row:

```bash
scripts/run-fuzz-campaign.sh \
  --tier 1 \
  --family quic \
  --budget 1K \
  --output artifacts/hardening/fuzz/smoke \
  --noncanonical-smoke \
  --skip-preflight
```

Run a canonical exact-target row on a frozen SHA:

```bash
sha="$(git rev-parse HEAD)"
scripts/run-fuzz-campaign.sh \
  --tier 2 \
  --family quic \
  --target 'fuzz: packet parser preserves bounded slice and progress invariants' \
  --budget 50M \
  --source-sha "$sha" \
  --output "artifacts/hardening/fuzz/${sha}-tier2-quic-packet"
```

Tier defaults come from #675:

- Tier 1: six-family discovery baseline, 10M mutations per family.
- Tier 2: high-risk exact target runs, 50M mutations per target.
- Tier 3: finding-driven saturation, 100M+ mutations after fixes or where
  evidence justifies it.

The runner invokes only the existing build steps:

```text
test-tls-protocol-fuzz
test-tls-record-fuzz
test-tls-resumption-fuzz
test-pki-fuzz
test-crypto-provider-fuzz
test-quic
```

and their existing filter options. It does not add mutation, minimization,
corpus, or fuzz semantics.

## Evidence

Each output directory keeps:

```text
campaign.json
environment.txt
targets.tsv
preflight/attempts/<attempt-id>/
manifest.jsonl
runs/<family>__<target-or-family>__<budget>/attempts/<attempt-id>/
findings/<family>__<target-or-family>/<attempt-id>/
```

`campaign.json`, `environment.txt`, and `targets.tsv` are created once and then
validated or reused. `manifest.jsonl` is append-only, and every fuzz/preflight
attempt writes unique log/result paths before appending its manifest row.
`--resume` skips a row only when the manifest contains a pass for the same
source SHA, build step, exact filter, and a same-or-greater mutation budget.
Failed, interrupted, and watchdog-expired rows never count as complete.

Canonical runs refuse to start when the checked-out SHA does not match
`--source-sha`, the worktree is dirty, Zig is not `0.16.0`, or deterministic
preflight fails. `--noncanonical-smoke --skip-preflight` is reserved for cheap
orchestration validation and must not be cited as #675 campaign evidence.

On a non-zero or interrupted fuzz result, the runner stops by default, retains
stdout/stderr, preserves `.zig-cache` state under `findings/`, and writes the
owning family/filter/replay command. Exact crash input recovery, minimization,
and regression promotion remain deliberate follow-up work under the existing
fuzz contracts.

`zig build --fuzz` exits 0 even when the fuzzer finds a failing input: it
saves the input (usually to `.zig-cache/f/crash`), stops the session early,
and the build summary still reports success. The runner therefore also scans
the run output for a saved-crash report, records such a run as `fail` with a
nonzero runner exit, and copies the saved input bytes plus their SHA-256 into
the finding directory and manifest row when Zig persisted a non-empty file
(replays of an already-saved corpus entry can leave the crash file empty; the
preserved `.zig-cache` archive still holds the corpus in that case).

## Disposable Proxmox KVM

The Proxmox wrapper packages the exact local Git commit with `git archive`,
records the source tarball SHA-256, creates a fresh KVM VM, installs Zig
`0.16.0`, invokes `scripts/run-fuzz-campaign.sh` inside the guest, copies
evidence back, and tears the VM down after successful collection unless
retention was requested.

Example smoke:

```bash
scripts/run-proxmox-fuzz-campaign.sh \
  --target root@10.250.250.2 \
  --bind 10.250.250.1 \
  --storage local-lvm \
  --snippets-storage local \
  --tier 1 \
  --family quic \
  --budget 1K \
  --noncanonical-smoke \
  --skip-preflight \
  --out-dir artifacts/hardening/fuzz/proxmox-smoke
```

Pass `--campaign-target 'fuzz: packet parser preserves bounded slice and progress invariants'`
for exact target runs. Use `--keep-guest` to retain the VM unconditionally, or
the default keep-on-failure behavior to inspect a failed campaign after artifact
collection.
