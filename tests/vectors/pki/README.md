# Hostile PKI differential fixtures

This directory contains fixed, project-owned X.509 inputs for issue `#348`.
They exercise certificate parsing, path construction, RFC 5280 validation, and
DNS identity matching against Tardigrade, OpenSSL, and Go's `crypto/x509`.

## Provenance and license

- Origin: generated for Tardigrade by `generate.go`; no third-party corpus is
  copied or transformed.
- License: Apache-2.0, the same license as the Tardigrade repository.
- Generator dependencies: Go `1.26.5` (the canonical regeneration version)
  and the OpenSSL command-line tool. Corpus use is offline and has no runtime
  dependency on either tool.
- Private keys: none are checked in or written by the generator. Fixture-only
  Ed25519 keys are deterministically derived from labels, held in process
  memory, and discarded on exit. They are not production credentials.

All certificates use fixed serial numbers, subjects, Ed25519 keys, and validity
from `2026-01-01T00:00:00Z` through `2036-01-01T00:00:00Z`. The validation time
for every decision is Unix `1784332800` (`2026-07-18T00:00:00Z`). Deterministic
Ed25519 signatures make generated output byte-for-byte reproducible.

## Fixture inventory and expected decisions

| Case | Inputs | Server name | OpenSSL | Go `crypto/x509` |
|---|---|---|---|---|
| Valid chain | `root.crt`, `intermediate.crt`, `valid-leaf.crt` | `api.example.test` | accept | accept |
| Wildcard, one label | `root.crt`, `intermediate.crt`, `wildcard-leaf.crt` | `api.example.test` | accept | accept |
| Wildcard, apex | same wildcard chain | `example.test` | reject identity | reject identity |
| Wildcard, multiple labels | same wildcard chain | `deep.api.example.test` | reject identity | reject identity |
| Unknown critical extension | `root.crt`, `intermediate.crt`, `unknown-critical-leaf.crt` | `critical.example.test` | reject validation | reject validation |
| Corrupt Ed25519 signature | `root.crt`, `intermediate.crt`, `signature-corrupt-leaf.crt` | `api.example.test` | reject validation | reject validation |
| `pathLenConstraint` violation | `root.crt`, `pathlen-chain.crt`, `pathlen-leaf.crt` | `pathlen.example.test` | reject validation | reject validation |
| Ambiguous cross-sign path | `cross-roots.crt`, `cross-untrusted-b-first.crt`, `cross-leaf.crt` | `cross.example.test` | accept | accept |
| Duplicate critical extension | `duplicate-extension-leaf.crt` | `duplicate.example.test` | reject parsing or validation | reject parsing |
| Truncated certificate seed | `malformed-truncated.crt` (`malformed-truncated.der` is the raw fuzz input) | n/a | reject parsing | reject parsing |

`pathlen-chain.crt` orders `pathlen-subordinate-ca.crt` before
`pathlen-zero-ca.crt`. The latter permits no non-self-issued CA below it, so the
otherwise cryptographically valid chain must fail.

`cross-untrusted-b-first.crt` deliberately orders `cross-intermediate-b.crt`
before `cross-intermediate-a.crt`. Both intermediates have the same subject and
public key, and `cross-roots.crt` trusts both issuers. The stable case therefore
has two valid paths. The individual root and intermediate files remain
available for focused path-ordering regressions without changing the corpus.

`signature-corrupt-leaf.crt` is a parseable copy of `valid-leaf.crt` with one
signature bit changed. `duplicate-extension-leaf.crt` repeats documentation
OID `1.3.6.1.4.1.32473.348.2` from the RFC 5612 example PEN; validators may
reject it during parsing or during critical-extension processing, but must
never accept it.

`malformed-truncated.crt` wraps `malformed-truncated.der` in a PEM
`CERTIFICATE` block so every differential validator can consume one file
format. The byte-identical raw DER remains available for parser fuzzing.

## Mismatch minimization and the reduced regression corpus

Every unexplained differential mismatch triggers bounded automated
minimization (`tests/pki_reduce.zig`): the disagreeing leaf input is shrunk
by deterministic greedy delta debugging while Tardigrade's exact
classification — status plus diagnostic, never just accept/reject — is
preserved, under a hard oracle-call budget. The harness writes the reduced
input as `<case-id>.reduced.der` and `<case-id>.reduced.crt` next to the JSON
artifact, re-verifies the reduced input against OpenSSL and Go, and records
in the artifact whether every validator's observed status survived the
reduction (`preserves_observed_statuses`).

Reduced inputs are promoted into `reduced/manifest.zig`, the registry that
the build embeds into the PKI unit-test module. Every registry seed
automatically joins the DER and X.509 fuzz corpora and gets a decision
regression test asserting its recorded parse outcome
(`src/pki/x509_tests.zig`, `src/pki/der_tests.zig`). Promotion is auditable:
each seed records its source case, provenance, license, and expected outcome,
and `zig build test-pki-reduce` regenerates each seed from its documented
source and requires byte-for-byte equality — which also proves the seed is
1-minimal, since the reducer's final pass shows no single deletion preserves
the classification.

Byte-level deletion respects DER framing implicitly: structurally valid
hostile certificates typically cannot shrink (their checked-in seed doubles
as a minimality proof), while malformed inputs converge to the smallest
input reproducing the same rejection class.

## Regeneration

Run from any directory:

```sh
tests/vectors/pki/generate.sh
```

The wrapper generates the full corpus twice and diffs it to prove deterministic
output. It then runs the Go verification matrix embedded in `generate.go`, runs
the equivalent OpenSSL checks, rejects unexpected files and PEM block types,
scans the directory for private-key blocks, and replaces the checked-in
fixtures only after every check passes.

For direct Go-only generation into a temporary directory:

```sh
go run tests/vectors/pki/generate.go -out /tmp/tardigrade-pki-fixtures
```
