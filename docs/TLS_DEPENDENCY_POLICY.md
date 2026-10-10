# Production dependency policy (#379, epic #327, #634, retirement #649, #651)

This note records Tardigrade's production implementation dependency policy and
how that policy is enforced in source, build configuration, CI, package/
container metadata, and release artifacts. It began as the TLS/crypto/QUIC/
HTTP/3 dependency policy from research story **327-J** and the Bare Systems
appliance release gate (#391), then #651 broadened it into the project-wide
#634 rule:

> Every implementation dependency reachable from shipping/supported production
> `tardi` must be Zig code, Zig stdlib, a reviewed pure-Zig package, or normal
> OS/kernel/platform substrate. Foreign-language implementations may exist only
> in explicit test, interop, differential, fuzz, or benchmark scopes.

**#649 completed the central TLS build/source cutover #634 called for**: every
supported production TLS build is native-only, and the OpenSSL production
backend no longer exists in any shipping configuration. #651 extends that same
mechanical boundary to the rest of the production build, packaging, and
container surfaces.

## The architecture

**The native Zig production implementation is the only implementation that
ships to users:**

- Every distributed `tardi` artifact — release archives, packages,
  containers, Homebrew, installer paths — is built from Zig production code,
  Zig stdlib, reviewed pure-Zig dependencies, and narrow OS/platform ABI
  substrate, with no OpenSSL or other foreign product implementation linked,
  compiled, configured, packaged, or reachable through hidden runtime loading.
- External implementations (OpenSSL, GnuTLS, independent QUIC stacks, Brotli C
  libraries, and similar peers) remain valuable as **test, interoperability,
  differential-validation, fuzz, and benchmark infrastructure** — always
  outside the shipping link/runtime graph, never reachable from it.
- Appliance vs. general-purpose differences are **product policy** expressed
  on the same native implementation (cipher/identity/lifecycle policy), not
  a choice of implementation backend.
- Normal OS/kernel/platform ABI facilities remain allowed: libc/libSystem as
  platform substrate, sockets, filesystem/process/thread primitives,
  poll/epoll/kqueue/io_uring, POSIX regex, and similar OS interfaces. These
  allowlists are intentionally narrow and reviewed in
  `scripts/audit-dependencies.sh`.
- Pure-Zig dependencies are allowed when reviewed; `build.zig.zon` is not a
  no-dependencies zone. The audit focuses on implementation language and FFI
  boundaries rather than rejecting third-party Zig packages by default.

A policy that is only written down drifts. This one is enforced by the build
graph and by CI, and every release artifact makes its selected profile and
linked dependencies inspectable.

## Approved build profiles

The profile is selected at build time with `-Dtls-profile` and is baked into
the binary. There is no runtime switch and no fallback between profiles.
Both profiles are native: no foreign TLS/crypto/QUIC/H3/certificate library
is ever configured, imported, or linked for either one.

### General-purpose profile (`-Dtls-profile=general`, the default)

- The general-purpose expression of the native implementation: generic
  multi-identity credential loading (default cert/key plus
  `TARDIGRADE_TLS_SNI_CERTS`), native TCP TLS termination, native QUIC/H3,
  SIGHUP-driven credential reload, opt-in native resumption
  (`TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`), and a **native upstream
  HTTPS/TLS client** (`src/http/tls_termination.zig`'s `UpstreamTlsConn`,
  #634) — `proxy_pass https://…` upstreams are served entirely by the
  native TLS engine, record layer, and PKI stack.
- `zig build` with no flags selects this profile — it is the default and
  requires no `-Dtls-profile` flag.
- Downstream SNI selection: an explicit `TARDIGRADE_TLS_SNI_CERTS` mapping
  always wins first; failing that, the default identity is served if its own
  certificate's SAN actually covers the requested hostname (RFC 9525 matching
  via `src/pki/identity.zig`, not string heuristics — see
  `sni_provider.UnknownSniPolicy.use_default_when_identity_matches`); failing
  that, the handshake fails closed. Absent SNI still serves the default
  identity unconditionally.
- Upstream TLS: certificate verification (`TARDIGRADE_UPSTREAM_TLS_VERIFY`,
  `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE`) uses the same native PKI path-building/
  validation as downstream mTLS would (`src/tls/webpki_verifier.zig`), falling
  back to a small set of well-known system CA bundle file locations when no
  bundle is configured; SNI/hostname derivation
  (`TARDIGRADE_UPSTREAM_TLS_SERVER_NAME`), upstream ALPN/protocol selection
  (`TARDIGRADE_UPSTREAM_PROTOCOL`), upstream client certificates (mTLS to the
  origin), and existing connect/response timeouts all continue to work
  unchanged; disabling verification still encrypts the connection, it just
  skips identity checking. See `docs/CONFIGURATION.md` for the full knob
  list and `docs/TROUBLESHOOTING.md` for upstream TLS failure modes.
  **Signature algorithm caveat:** chain validation authenticates each
  certificate's signature through the native matrix (`src/pki/verify.zig`),
  originally #343 (Ed25519, ECDSA P-256/SHA-256, RSA-PSS/SHA-256) and
  extended by #645 to also cover classic `sha256WithRSAEncryption`/
  `sha384WithRSAEncryption` (RSA PKCS#1 v1.5/SHA-256 and SHA-384) —
  still-common signature algorithms among public CAs and intermediates. RSA
  PKCS#1 v1.5 support is certificate-chain-signature verification only: RFC
  8446 §4.2.3 forbids `rsa_pkcs1` schemes in TLS 1.3 `CertificateVerify`, so
  the native handshake engine's own proof-of-possession step continues to use
  only Ed25519, ECDSA P-256/SHA-256, or RSA-PSS/SHA-256 regardless of what
  algorithm signed the certificate chain (`src/tls/crypto_profile.zig`'s
  `supportsSignatureScheme` unconditionally refuses to advertise or select
  it). Other public-WebPKI variants — ECDSA/SHA-384 and RSA PKCS#1 v1.5/
  SHA-512 among them — remain unsupported; a chain signed with one of them
  still fails closed with a verification error, mapped through the same
  bounded upstream-TLS failure path as any other handshake/certificate
  failure (see `docs/TROUBLESHOOTING.md`). Extending the native signature
  matrix further (e.g. ECDSA/SHA-384) remains tracked separately; until then,
  upstream HTTPS is production-ready only against origins whose certificate
  chain uses one of the five now-supported signature algorithms.
  **Certificate/handshake size caveat (#646, resolved):** the shared
  handshake engine (`src/tls/tls13_backend.zig`) used to hard-cap every peer
  `CertificateEntry` at `max_certificate_len` (2048 bytes) and the whole
  handshake message at `max_message_len` (8 KiB), rejected before the
  signature/verifier code ever ran — a certificate did not need an
  unsupported algorithm to cross this: an Ed25519 leaf, already supported,
  could exceed 2 KiB DER with a moderately large SAN set, and a
  multi-certificate public chain could exceed the aggregate 8 KiB bound even
  with small individual certificates. Both bounds are now `max_certificate_len`
  (8 KiB) and `max_message_len` (16 KiB) — comfortably above ordinary public
  WebPKI norms while still fail-closed against a genuinely oversized/DoS-shaped
  handshake — so this is no longer an independent blocker alongside #645.
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library — audited identically to the appliance
  profile.
- Every capability the retired OpenSSL adapter used to own (TLS 1.2,
  cipher-string overrides, the OpenSSL
  session cache/tickets, OCSP stapling, CRL checks, ACME, the filesystem
  credential watcher, PROXY protocol with TLS) fails config validation
  deterministically (`UnsupportedNativeTlsConfiguration`) instead of being
  silently ignored or silently changing semantics — see "Retired OpenSSL
  capability disposition" below for the complete, final list. Upstream TLS
  is not on this list: every upstream TLS knob is supported natively (see
  above), not rejected.

### Bare Systems appliance profile (`-Dtls-profile=appliance`)

- Uses the same native Zig TLS/crypto path as the general profile, with the
  strict Bare Systems product policy on top: a single Ed25519 identity, a
  required `TARDIGRADE_TLS_SERVER_NAME`, TLS 1.3 only, restart-owned
  credential rotation. The supported TLS/certificate/client matrix is
  defined by #391.
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library.
- Live termination runs on `src/http/native_tls_connection.zig`.
  `src/http/tls_termination.zig`'s `TlsTerminator`/`TlsConnection` types
  exist only to keep the API surface every caller compiles against stable;
  any attempt to actually construct one fails closed
  (`error.ContextInitFailed`) in every profile, since real downstream TLS
  is always served by the native listener.

### Retired: the general-purpose OpenSSL profile

Before #649, `-Dtls-profile=general` linked a single approved OpenSSL
adapter as a transitional compatibility backend, and a separate
`-Dtls-profile=native` name distinguished the OpenSSL-free general-purpose
profile from it. #649 retired the OpenSSL adapter entirely (deleted the
`configureSsl` build-graph linkage, the OpenSSL-backed
`src/http/tls_termination.zig`/`src/http/acme_client.zig` implementations,
and the `tls_backend.zig`/`acme_backend.zig` selector layer that switched
between them and their native counterparts) and reused the `general` name
for what was previously called `native` — there is no longer an
implementation-backend distinction to name. `-Dtls-profile=native` is no
longer a valid flag value.

### Shared policy

- ngtcp2/nghttp3 remain fully removed (#328); HTTP/3 and QUIC run on the
  pure-Zig transport.
- External TLS/QUIC/H3 implementations may run only as out-of-process or
  containerized interoperability peers (`scripts/interop/`) or test-only
  differential tooling (`evp_oracle`/`tests/crypto_openssl_diff.zig`,
  `tests/pki_openssl_diff.zig`), never in the Tardigrade production link
  graph. This tooling is not gated by `-Dtls-profile` at all — it builds
  and runs unconditionally, entirely outside the `tls_profile`-selected
  module graph.
- Build and release artifacts must make their selected profile and linked
  dependencies inspectable.

## Retired OpenSSL capability disposition

Every operator-visible feature/config knob the OpenSSL production backend
used to provide now has exactly one final disposition, so removing the
adapter cannot silently remove behavior operators were promised:

| Capability | Disposition |
|---|---|
| TLS 1.3 termination, SNI, ALPN, HTTP/1.1+HTTP/2, upstream HTTPS (incl. upstream mTLS) | **native + supported**, in every profile |
| QUIC/HTTP/3, 0-RTT, connection migration, session resumption (`TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`) | **native + supported** (general profile; appliance restricts 0-RTT/migration/retry-policy as product policy, not a capability gap) |
| TLS 1.2 / non-1.3 version negotiation | **unsupported**, deterministic config failure (`UnsupportedNativeTlsConfiguration`) |
| OpenSSL-format cipher-suite/cipher-list overrides | **unsupported**, deterministic config failure |
| Downstream client-certificate verification (mTLS) | **native + supported** on HTTP/1.1, HTTP/2 and HTTP/3/QUIC (#763): pure-Zig PKI path validation against `TARDIGRADE_TLS_CLIENT_CA_PATH`, one shared trust store across protocols |
| OpenSSL session cache / session tickets | **unsupported**, deterministic config failure — superseded by native resumption |
| OCSP stapling, OCSP auto-refresh, CRL checking | **unsupported**, deterministic config failure |
| ACME automated issuance/renewal | **unsupported**, deterministic config failure — `src/http/acme_client.zig`'s `runOnce` always returns `error.AcmeProtocolError`; tracked for a native implementation alongside #391; design contract in `docs/ACME_AUTOMATIC_HTTPS.md` (#831) |
| Filesystem credential watcher (`TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS`) | **unsupported**, deterministic config failure — superseded by the explicit SIGHUP reload path |
| PROXY protocol combined with TLS | **unsupported**, deterministic config failure |
| OpenSSL itself, as a differential/interop test peer (`evp_oracle`, `tests/crypto_openssl_diff.zig`, `tests/pki_openssl_diff.zig`, `scripts/interop/`) | **non-production test/interop only** — never reachable from any shipping `tardi` target |

Every "unsupported" row fails at config-validation time
(`edge_config.zig`'s `validateNativeTlsBuildConfig`, unconditional across
both profiles since #649) rather than being silently accepted and either
ignored or changing behavior. See "native-TLS builds reject
OpenSSL-adapter-only TLS settings one at a time" in `tests/integration.zig`
for the enumerated regression coverage.

## How the binary reports its profile

`tardi version` prints the profile and backend, so operators and release
audits can verify an artifact without inspecting its link graph. Every
supported build now reports `tls-backend=native`:

```
$ tardi version
0.6.0 (tls-profile=general, tls-backend=native)
$ tardi version
0.6.0 (tls-profile=appliance, tls-backend=native)
```

## Enforcement

### Source/build/package audit — `scripts/audit-dependencies.sh`

Runs before anything is compiled and fails if:

1. Production-scoped Zig source across the repository uses `@cImport` for
   anything outside the narrow OS/platform header allowlist.
2. Production source uses runtime dynamic loading (`std.DynLib`, `dlopen`,
   `LoadLibrary`, etc.) that could hide a foreign implementation fallback.
3. Production build-graph sources link a non-allowlisted system library or
   compile vendored C/C++/Objective-C/object code into a production target.
4. Production package/container/release metadata contains an unreviewed
   dependency declaration. Ordinary OS/build substrate such as CA bundles is
   explicitly allowlisted; newly named product implementation dependencies
   fail closed until reviewed.

The script also defines the production/non-production split mechanically.
Explicitly non-production paths include `tests/`, `scripts/interop/`,
benchmarks, checked-in testdata fixture generators, and a narrow set of named
package/install smoke-test scripts. The audit deliberately does not exempt
every `scripts/test-*` helper by prefix: adding a new nominally test-named
helper that installs a foreign implementation is a production-scope failure
unless it is reviewed into the explicit non-production allowlist. The
`--self-test` fixture mode proves representative failures and passes: foreign
production `@cImport`, computed C includes, multiline/indirect system-library
linkage, computed build-helper imports, vendored C/object inputs, runtime
loading, multiline package/container installs, production paths reaching
nominal test helpers, quoted ZON dependency keys, and unknown package
dependencies fail; OS-substrate `@cImport`, reviewed pure-Zig packages,
interop peers, and prose mentions pass.

### Binary linkage audit — `scripts/audit-release-binary.sh`

Inspects a produced binary's dynamic dependencies (`readelf`/`objdump` on
Linux, `otool -L` on macOS) and emits a machine-readable JSON inventory. It
fails if:

- an artifact of either profile has a dynamic dependency outside the narrow
  per-platform OS/runtime substrate allowlist (`libSystem.B.dylib` on Darwin;
  libc/loader/thread/math/dl/rt/resolver/compiler-unwind substrate on Linux);
  or
- an artifact does not self-report the native TLS path; or
- an artifact's self-reported `tls-profile` disagrees with the profile it
  was built and audited as.

The inventory records the binary, its SHA-256 checksum, profile, host OS,
inspection tool, self-reported backend, full dependency list, and any
violations. The checksum lets a consumer that cannot execute the binary
itself — e.g. the standalone DEB/RPM builders packaging a cross-architecture
artifact (`packaging/deb/build.sh`, `packaging/rpm/build.sh`) — bind an
already-produced inventory to the exact artifact instead of trusting a
caller-supplied backend flag.

### CI

The `Production dependency audit (Linux)` job in `.github/workflows/ci.yml`
runs the source audit, source-audit fixtures, binary-audit fixtures, builds
both profiles, and runs the binary audit against each, uploading the inventories
as artifacts. `Production binary audit (macOS)` builds and audits the Darwin
general-profile artifact so platform-specific dynamic dependencies are checked
in PR CI too. These are required checks: CI fails if any forbidden
implementation is configured, imported, packaged, dynamically loaded, or linked
in a production path.

### Release

`.github/workflows/release.yml` re-runs the source audit, audits each released
binary's linkage, and publishes the dependency inventory alongside the
release assets and SBOM.

## History

- **#634** (umbrella epic) set the target architecture: native-only
  production, OpenSSL confined to an adapter boundary during the
  transition, default profile eventually flipping to native.
- **#641** landed the general-purpose native profile foundation as a
  separately selectable `-Dtls-profile=native` build, alongside the
  OpenSSL-backed default.
- **#643** added the native upstream HTTPS/TLS client and default-identity
  SNI fallback, closing the last data-plane gap between the native and
  OpenSSL profiles for ordinary proxying.
- **#645**/**#646** extended the native certificate-signature matrix and
  raised handshake size bounds so the native upstream client is usable
  against ordinary public-WebPKI origins.
- **#649** made native the default and *only* selectable production
  implementation: retired the OpenSSL adapter, `configureSsl`, the
  `general`/`native` profile distinction (merged into a single native
  `general` tag), and every OpenSSL production source surface. #634 stays
  open for the distribution/packaging and final-release-proof work it also
  covers, which #649 does not.
- **#650** finished the local/package/container distribution cutover left
  open by #649: the root `Dockerfile` no longer installs `libssl-dev` or
  `libssl3` for Tardigrade, its runtime binary is audited directly with
  `scripts/audit-release-binary.sh` rather than inferred from Dockerfile
  text, and the standalone `packaging/deb/build.sh`/`packaging/rpm/build.sh`
  builders no longer accept `--tls-backend openssl-adapter` or emit an
  OpenSSL runtime dependency — the packaged artifact's native identity is
  always proven by the same audit script (self-audited for a host-executable
  binary, or via a SHA-256-bound `--audit-inventory` file for
  cross-architecture packaging) instead of a caller-supplied backend flag.
