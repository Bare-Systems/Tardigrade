# TLS/crypto dependency policy and pure-Zig cutover (#379, epic #327)

This note records Tardigrade's external-library policy for TLS, crypto, QUIC,
HTTP/3, and certificate handling, how that policy is enforced in source, build
configuration, CI, and release artifacts, and the checklist that governs the
cutover to the pure-Zig implementation. It is the deliverable of research story
**327-J** and a required v0.5 release gate for the Bare Systems appliance
(#391).

## Why

Tardigrade is moving its TLS/crypto stack from OpenSSL to a pure-Zig
implementation (epic #327). During that transition two products ship from one
tree, and their dependency rules differ:

- The **Bare Systems appliance** must contain no OpenSSL or other foreign
  TLS/crypto implementation at all — no linkage, no configuration, no hidden
  runtime fallback.
- **General-purpose Tardigrade** may keep a single, narrowly isolated OpenSSL
  adapter as a compatibility backend until the native path reaches the v1.0
  support contract.

A policy that is only written down drifts. This one is enforced by the build
graph and by CI, and every release artifact makes its selected profile and
linked dependencies inspectable.

## Approved build profiles

The profile is selected at build time with `-Dtls-profile` and is baked into
the binary. There is no runtime switch and no fallback between profiles.

### Bare Systems appliance profile (`-Dtls-profile=appliance`)

- Uses the native Zig TLS/crypto path only.
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library.
- The OpenSSL adapter module (`src/http/tls_termination.zig`) is **replaced in
  the module graph** by a no-OpenSSL stub (`src/http/tls_termination_stub.zig`)
  via `src/http/tls_backend.zig`. Because the adapter source is never imported,
  its `@cImport("openssl/...")` is never analyzed and OpenSSL is never linked.
- Until the native TLS termination path lands, the stub fails closed at startup
  (`error.ContextInitFailed`) rather than silently degrading. The supported
  TLS/certificate/client matrix for the appliance is defined by #391.

### General-purpose profile (`-Dtls-profile=general`, default)

- Links the single approved OpenSSL adapter as a compatibility/reference
  backend.
- OpenSSL types and state stay behind the adapter boundary
  (`src/http/tls_termination.zig`, `src/http/acme_client.zig`) and must not
  shape TLS, HTTP, QUIC, PKI, or application interfaces.
- No external TLS/crypto implementation other than the approved OpenSSL adapter
  may be linked.

### Shared policy

- ngtcp2/nghttp3 remain fully removed (#328); HTTP/3 and QUIC run on the
  pure-Zig transport.
- External TLS/QUIC/H3 implementations may run only as out-of-process or
  containerized interoperability peers (`scripts/interop/`), never in the
  Tardigrade link graph.
- Build and release artifacts must make their selected profile and linked
  dependencies inspectable.

## How the binary reports its profile

`tardi version` prints the profile and backend, so operators and release
audits can verify an artifact without inspecting its link graph:

```
$ tardi version
0.5.0 (tls-profile=appliance, tls-backend=native)
$ tardi version
0.5.0 (tls-profile=general, tls-backend=openssl-adapter)
```

## Enforcement

### Source and configuration audit — `scripts/audit-dependencies.sh`

Runs before anything is compiled and fails if:

1. A forbidden TLS/crypto/QUIC/H3 dependency name (ngtcp2, nghttp3, quiche,
   BoringSSL, mbedTLS, wolfSSL, GnuTLS, LibreSSL, rustls, s2n-tls, botan, …) is
   **configured** in `build.zig`, `build.zig.zon`, workflows, scripts,
   Dockerfiles, or packaging metadata. Comments are stripped before matching so
   the policy can be documented in prose; only real configuration fails.
2. An OpenSSL `@cInclude` appears outside the approved adapter boundary.
3. Any `@cImport` appears in a native implementation path (`src/tls`,
   `src/pki`, `src/quic`, `src/crypto`, `src/http3`).

### Binary linkage audit — `scripts/audit-release-binary.sh`

Inspects a produced binary's dynamic dependencies (`ldd` on Linux, `otool -L`
on macOS) and emits a machine-readable JSON inventory. It fails if:

- an appliance artifact links OpenSSL or any forbidden foreign library, or does
  not self-report the native TLS path; or
- a general artifact's actual linkage disagrees with its self-reported backend
  (so the inventory cannot lie).

The inventory records the binary, profile, host OS, inspection tool,
self-reported backend, full dependency list, and any violations.

### CI

The `TLS dependency audit` job in `.github/workflows/ci.yml` runs the source
audit, builds **both** profiles, and runs the binary audit against each,
uploading the inventories as artifacts. It is a required check: CI fails if any
forbidden implementation is configured, imported, or linked in any profile.

### Release

`.github/workflows/release.yml` re-runs the source audit, audits each released
(general-profile) binary's linkage, and publishes the dependency inventory
alongside the release assets and SBOM.

## Cutover checklist

### Bare Systems appliance (blocks #391)

- [x] `appliance` build profile selects the native TLS/crypto path.
- [x] Appliance builds link no OpenSSL/libcrypto/foreign TLS library (enforced
      by binary audit).
- [x] No hidden runtime fallback to OpenSSL (stub fails closed; profile is a
      build-graph decision).
- [x] Appliance artifact self-reports the native TLS path.
- [x] CI builds and audits the appliance artifact on every change.
- [ ] Native TLS termination and client paths implement the #391 appliance
      support matrix (handshake, certificate verification, session resumption).
      **Until this lands the appliance profile compiles and audits clean but
      refuses TLS connections at runtime.**
- [ ] Appliance integration/interop coverage proves live operation through the
      native path.

### General-purpose native-TLS parity (governs OpenSSL adapter removal)

- [x] OpenSSL confined to the adapter boundary; no OpenSSL types in TLS/HTTP/
      QUIC/PKI/application interfaces (enforced by source audit).
- [x] General artifacts expose a complete dependency inventory and identify the
      selected backend.
- [ ] Native TLS reaches the v1.0 general-purpose support contract
      (`docs/SUPPORT_MATRIX.md`).
- [ ] Native path passes the TLS/interop conformance suite at parity with the
      OpenSSL adapter.
- [ ] Default profile flips from `general` to native once parity holds.
- [ ] OpenSSL adapter removed from all builds; `configureSsl`, the adapter
      modules, and the general profile retired.

When the final boxes are checked, the OpenSSL adapter and the `-Dtls-profile`
switch can be removed and Tardigrade ships a single pure-Zig TLS stack.
