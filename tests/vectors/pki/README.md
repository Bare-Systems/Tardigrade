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
| DNS-only Name Constraints permitted | `root.crt`, `dns-constraints-intermediate.crt`, `dns-permitted-leaf.crt` | `api.example.test` | accept | accept |
| DNS-only Name Constraints excluded | `root.crt`, `dns-constraints-intermediate.crt`, `dns-excluded-leaf.crt` | `blocked.example.test` | reject Name Constraints | reject Name Constraints |
| IP-only Name Constraints permitted | `root.crt`, `ip-constraints-intermediate.crt`, `ip-permitted-leaf.crt` | n/a | accept | accept |
| IP-only Name Constraints excluded | `root.crt`, `ip-constraints-intermediate.crt`, `ip-excluded-leaf.crt` | n/a | reject Name Constraints | reject Name Constraints |
| Isolated identity mismatch | `root.crt`, `intermediate.crt`, `identity-mismatch-leaf.crt` | `wrong.example.test` | reject identity | reject identity |
| Duplicate critical extension | `duplicate-extension-leaf.crt` | `duplicate.example.test` | reject parsing or validation | reject parsing |
| Truncated certificate seed | `malformed-truncated.crt` (`malformed-truncated.der` is the raw fuzz input) | n/a | reject parsing | reject parsing |
| Algorithm-confusion fixtures | `algorithm-*.crt` plus matching raw `.der` files | n/a | reject validation/parsing by pinned semantic reason | reject validation/parsing by pinned semantic reason |
| Hostile DER encoding fixtures | `der-*.crt` plus matching raw `.der` files | n/a | reject or accept by pinned parser policy | reject malformed DER or algorithm encoding by pinned semantic reason |

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

The DNS-only and IP-only Name Constraints chains avoid unrelated critical name
forms, so their negative cases prove each validator reached the rule named by
the case. The legacy directoryName fixtures remain in the extended corpus with
an explicit normalization for Go's unsupported critical directoryName
constraint.

The `algorithm-*` family mutates Ed25519 certificate AlgorithmIdentifier and
SubjectPublicKeyInfo OID encodings without adding production support for new
algorithms. The generated TBS bytes are re-signed whenever the mutation leaves
a certificate-shaped object, so these cases do not depend on stale-signature
rejection.

The `der-*` family records strict DER policy boundaries such as non-minimal
lengths, indefinite lengths, malformed INTEGER/BIT STRING encodings,
constructed primitive encodings, trailing bytes, and malformed nested
extension lengths. The `.crt` files let external validators consume the same
bytes through PEM while the raw `.der` files remain available for parser and
reducer coverage.

## Mismatch minimization and the reduced regression corpus

Every unexplained differential mismatch triggers bounded automated
minimization (`tests/pki_reduce.zig`): deterministic greedy delta debugging
under a hard per-component oracle-call budget. The mismatch can live anywhere
in the chain, so every component — the leaf, each intermediate, and each
trust anchor — gets its own reduction pass that substitutes only that
certificate's DER while Tardigrade's semantic classification (status, bounded
reason, and certificate index when known) must be preserved; the component with
the largest shrink wins deterministically.

An emitted reduced fixture is always a reproduction of the observed
disagreement. The harness writes the reduced component
(`<case-id>.reduced.der`/`.crt`, plus a substituted bundle file when the
component is an intermediate or root) and re-verifies the reduced case
against all three validators. If any validator's semantic tuple diverges from
the original tuple, the reduction is reverted to the original component bytes
and the disqualifying observations are recorded (`candidate_observed`,
`reverted_external_divergence`). The schema-v4 artifact records the
component, sizes, oracle budget spent, `budget_exhausted` and `one_minimal`
flags (1-minimality is only claimed after a completed single-byte sweep),
SHA-256, per-validator reduced semantic observations, validator identities,
runtime OS/architecture, subprocess bounds, and a `promotable` verdict that
requires the observed status/reason/index tuples to survive.

Promotable inputs land in `reduced/manifest.zig`, the registry the build
embeds into the PKI unit-test module. Every seed automatically joins the DER
and X.509 fuzz corpora and gets a regression test for its recorded outcome:
`parse_error` seeds assert the exact parse failure
(`src/pki/x509_tests.zig`), while `tardigrade_class` seeds parse successfully
and replay the recorded full-pipeline class — path building, RFC 5280
validation, identity matching — in their source case's chain context
(`tests/pki_differential.zig`). Promotion is auditable: each entry records
its source case (which must resolve in the differential manifest), placement
in the chain, provenance, and license; the registry derives each embedded
seed path from the entry name; and `zig build test-pki-reduce` regenerates
each seed from its documented source, requiring byte-for-byte equality and a
completed 1-minimality proof.

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
