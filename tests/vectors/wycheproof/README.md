# Reduced Wycheproof-style crypto corpus

This directory contains a checked-in, offline corpus for `zig build test-crypto-corpus`.
CI must not download upstream vectors.

## Origin and License

- Source: C2SP Project Wycheproof, `https://github.com/C2SP/wycheproof`
- Upstream commit: `fc24cd5b787d8e496bff31b0468af693a652b0f2`
- Upstream license: Apache-2.0
- Local schema: `tardigrade-wycheproof-reduced-v1`

The checked-in `corpus.json` is a reduced project-owned representation. It keeps
the upstream source file, group index, `tcId`, result classification, comment,
flags, and reproducible input values needed by the current `CryptoProvider`
contract.

## Included Suites

- `wycheproof-aes-128-gcm-reduced`
- `wycheproof-aes-256-gcm-reduced`
- `wycheproof-chacha20-poly1305-reduced`
- `wycheproof-x25519-reduced`
- `wycheproof-ed25519-verify-reduced`

These suites are the first pure-Zig-provider slice for issue `#374`. They cover
only operations currently supported through the shared provider boundary.

## Skipped Suites

- RSA-PSS: provider capability remains deferred for issue `#374` follow-up.
- ECDSA-P256-SHA256: supported provider operation, but outside this first
  merge-sized `#374` corpus slice.
- X448 and broader asymmetric formats: unsupported by the current provider
  capability matrix.

Every skipped suite must name a reason and tracking issue in both
`corpus.json` and `tests/crypto_corpus_manifest.zig`.

## Acceptable Case Policy

Wycheproof `acceptable` means the upstream project allows more than one
implementation policy. Tardigrade does not treat `acceptable` as success by
default. Each acceptable case included in this reduced corpus must carry an
explicit `expected` provider outcome. The current X25519 low-order public-key
case is classified as upstream `acceptable` and expected to return
`invalid-input` because the provider contract rejects all-zero shared secrets.

## Parser Limits

The runner enforces bounded parsing before execution:

- file size: 64 KiB
- JSON nesting depth: 12
- groups per suite: 8
- total cases: 64
- identifier length: 96 bytes
- comments: 256 bytes
- flags per case: 8
- encoded hex field: 512 bytes
- decoded bytes across executable fields: 8192 bytes

Malformed hex, duplicate case IDs, unsupported schema versions, unknown
algorithms, unknown execution-affecting fields, missing required fields,
unknown classifications, and oversized values are rejected.

## Update Procedure

1. Fetch the upstream commit recorded above, or deliberately choose and record a
   new commit.
2. Select only cases that execute through the shared `CryptoProvider`.
3. Preserve upstream source file, group index, `tcId`, classification, comment,
   and flags.
4. Keep the reduced schema small enough for review.
5. Update `tests/crypto_corpus_manifest.zig` case counts and skipped suites.
6. Run `zig build test-crypto-corpus --summary all --error-style verbose`.
7. Run `git diff --check`.

When a corpus case exposes a bug, reduce it into a permanent focused regression
fixture near the provider or protocol code that owns the behavior, then keep or
add the corpus case as the broader provenance-backed guard.

