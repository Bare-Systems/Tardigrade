# Bare Systems Appliance TLS Provisioning (v0.5)

This document is the complete supported contract for the fixed-profile Bare
Systems appliance TLS identity (#392). It applies to binaries built with
`-Dtls-profile=appliance` (no OpenSSL/libcrypto linkage; pure-Zig TLS only).

## Supported profile

The appliance profile is deliberately narrow:

- exactly **one** provisioned server identity per appliance;
- **Ed25519 only** (RFC 8410);
- one **leaf-first** ordered certificate chain, cryptographically coherent
  end to end;
- **TLS 1.3 only**, key exchange **X25519**, cipher `TLS_AES_128_GCM_SHA256`;
- ALPN `h2` and `http/1.1` over native TCP;
- the **same credential provider instance** authenticates native HTTP/3
  (QUIC);
- no OpenSSL, libcrypto, or any foreign TLS/crypto library.

Explicit non-goals (rejected, not silently degraded): RSA, ECDSA/P-256
signing, encrypted private keys, OpenSSH keys, multiple SNI identities,
wildcard host names, client certificates/mTLS, full public-PKI *trust*
policy (root/CA-bundle pinning, revocation, path-length/name-constraint
enforcement), hardware/remote signers, filesystem watchers, and heuristic
PEM/DER format detection. See [Certificate-chain coherence](#certificate-chain-coherence)
for exactly what *is* validated about a multi-certificate chain — it is more
than parse-validity, but it is not a trust decision.

## Configuration

| Setting | Environment | Directive |
| --- | --- | --- |
| Certificate chain file | `TARDIGRADE_TLS_CERT_PATH` | `tls_cert_path` |
| Private key file | `TARDIGRADE_TLS_KEY_PATH` | `tls_key_path` |
| Served host name | `TARDIGRADE_TLS_SERVER_NAME` | `tls_server_name` |

`tls_cert_path`/`tls_key_path` are also accepted as top-level config-file
directives (previously only available per `server{}` block).

When TLS is enabled in an appliance build, `tls_server_name` is **required**
and must be exactly one valid, non-wildcard DNS host name.
`TARDIGRADE_TLS_SNI_CERTS` (and per-`server`-block certificates, including a
single unnamed default block) are rejected: the appliance serves one
identity, configured directly.

The appliance profile also rejects, deterministically, active configuration
its engine cannot honor: `tls_min_version`/`tls_max_version` must both be
`"1.3"` (defaults to `"1.3"` automatically in appliance builds — only an
explicit override to something else is rejected); `tls_cipher_list`/
`tls_cipher_suites` must be empty (the cipher is fixed); `tls_client_verify`,
`tls_ocsp_stapling`, `tls_crl_check`, and `tls_acme_enabled` must be off;
`tls_session_cache`/`tls_session_tickets` must be off (default off in
appliance builds; these are OpenSSL-terminator-only features this owner
never constructs); and if `http3_enabled` is set, a complete identity must
also be configured and `http3_enable_0rtt`/`http3_connection_migration` must
be off. Each violation is a distinct `UnsupportedApplianceConfiguration`
failure, not a silent no-op.

### SNI behavior

- Exact configured name (case-insensitive) selects the identity.
- Absent SNI selects the same identity (it is the default).
- Any other non-empty SNI **fails the handshake** before any HTTP parsing.
- A peer that does not offer the `ed25519` signature scheme fails the
  handshake deterministically.

## Certificate-chain file format

Strict RFC 7468 PEM:

- one or more `CERTIFICATE` blocks — **leaf first**, intermediates following
  in transmission order;
- at most 8 certificates;
- only certificate blocks and ASCII whitespace: no prose, comments,
  OpenSSL `subject=` annotations, unrelated PEM labels, or trailing
  non-whitespace material;
- strict base64 (standard alphabet, canonical padding);
- every decoded certificate must be exactly one fully consumed DER
  certificate object (parsed with the shared pure-Zig X.509 parser, not
  merely a well-formed DER SEQUENCE);
- the leaf must carry a canonical RFC 8410 Ed25519 SubjectPublicKeyInfo:
  the Ed25519 AlgorithmIdentifier with no parameters (not even an explicit
  ASN.1 NULL), zero BIT STRING unused bits, exactly 32 key bytes.

Raw DER files are **not** accepted.

### Certificate-chain coherence

Every entry — not only the leaf — is parsed and validated. This module adds
no second X.509/SPKI parser and makes no trust decision (no root pinning,
no CA-bundle lookup, no revocation checking, no path-length or
name-constraint enforcement); it proves the transmitted bytes are an
internally coherent, ordered signing chain that an independent client which
already trusts the issuer of the last transmitted certificate can actually
validate:

- the leaf must not assert `basicConstraints CA:TRUE`; if it carries
  `keyUsage`, `digitalSignature` must be set; if it carries
  `extendedKeyUsage`, it must allow `serverAuth`;
- the configured `tls_server_name` must appear in the leaf's
  `subjectAltName` (SAN-only per RFC 9525 — there is no Common Name
  fallback; a matching presented wildcard SAN, e.g. `*.example.test`, is
  honored per the same one-label rule QUIC/HTTP clients apply);
- every certificate after the leaf must assert `basicConstraints CA:TRUE`;
  if it carries `keyUsage`, `keyCertSign` must be set;
- for each adjacent pair, the earlier certificate's issuer must name-chain
  (RFC 5280 §7.1) to the later certificate's subject, and the earlier
  certificate's signature must verify under the later certificate's public
  key;
- no two entries may be byte-identical;
- any certificate carrying a critical extension this profile does not
  recognize is rejected (RFC 5280 §4.2).

A malformed or incoherent entry fails as one of the deterministic classes in
[Error classes](#error-classes) — never as an undifferentiated internal
error, and never only once a live handshake is attempted.

## Private-key file format

Exactly one RFC 7468 `PRIVATE KEY` block, surrounded only by ASCII
whitespace, containing an **unencrypted PKCS#8 / RFC 5958** structure with:

- the RFC 8410 Ed25519 AlgorithmIdentifier (`1.3.101.112`) with **absent**
  parameters;
- exactly one 32-byte Ed25519 seed in the canonical
  `OCTET STRING { OCTET STRING (32) }` encoding;
- no attributes, appended public key, or trailing DER.

Rejected: `EC PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`,
OpenSSH keys, raw DER, multiple key blocks, unrelated PEM blocks, prose,
wrong seed sizes, unknown algorithm OIDs, and any malformed, truncated,
noncanonical, oversized, or ambiguous material. The file and in-memory APIs
run the exact same parser and produce the same errors.

## Limits

| Bound | Default |
| --- | --- |
| Certificate file size | 256 KiB |
| Private-key file size | 64 KiB |
| Chain entries | 8 |
| Single certificate DER | 2048 bytes (the TLS writer bound) |
| Encoded TLS Certificate flight | `max_message_len` minus the writer's own worst-case non-certificate flight cost |

The flight bound is preflighted **before publication** using the TLS
handshake writer's own exported framing constants
(`tls13_backend.certificate_message_overhead`, `.certificate_entry_overhead`,
`.max_non_certificate_server_flight_bytes`) rather than a duplicated
estimate, so a chain this preflight accepts is proven — by a direct test
driving the real writer at that exact boundary, for both the native TCP and
HTTP/3 transport-extension profiles — to actually serialize, never
overflowing during a live handshake. A caller-supplied `Limits` can only
tighten these bounds, never loosen them past what the writer can serialize.

## Startup, `tardi check`, and reload

At startup — and before any daemon fork, PID file, or master/worker startup
in `tardi run` — the appliance profile loads and fully validates the
credential **before any TCP or UDP listener is bound**. On any failure the
process refuses to start and reports the failure synchronously to the
invoking shell with the deterministic error class and exit code 2; HTTP
dispatch is never reachable with invalid credentials, `run --daemon` never
prints a false "started" message for a child that cannot start, and a
master process never writes a PID file or enters its worker-respawn loop
for credentials that can never load. The long-lived credential owner that
actually serves connections is still constructed separately by the worker
process.

`tardi check` performs the identical preflight without opening any socket:
file reads, strict PEM/PKCS#8 parsing, Ed25519 key parse, chain-coherence
and SAN validation, exact leaf/private public-key comparison plus a fixed
sign-and-verify probe, server-name policy, chain and flight bounds, and
provider snapshot construction/teardown.

Hot reload (`SIGHUP`) **rejects** a configuration that changes the
certificate path, key path, `tls_server_name`, or SNI credential
configuration — including a reload that would turn TLS on for a server that
started in plaintext, or off for one that started with TLS, regardless of
whether the running process happened to construct a credential owner at
startup. The previous configuration and credentials remain active.
Rotating credentials requires a restart in v0.5. In-flight handshakes always
complete on the snapshot they selected.

## Error classes

Loader failures are deterministic and operator-actionable — never collapsed
into a generic bootstrap error:

`MissingCertificateChain`, `MissingPrivateKey`, `CertificateFileTooLarge`,
`PrivateKeyFileTooLarge`, `EmptyCertificateChain`, `TooManyCertificates`,
`MalformedCertificatePem`, `AmbiguousCertificateInput`,
`CertificateTooLarge`, `MalformedCertificateDer`, `MalformedPrivateKeyPem`,
`AmbiguousPrivateKeyInput`, `MalformedPrivateKeyDer`,
`UnsupportedPrivateKeyAlgorithm`, `UnsupportedPrivateKeyParameters`,
`InvalidPrivateKeySize`, `InvalidPrivateKey`, `UnsupportedLeafKeyAlgorithm`,
`UnsupportedLeafKeyParameters`, `KeyCertificateMismatch`,
`CertificateFlightTooLarge`, `InvalidServerName`, `CertificateNameMismatch`,
`IntermediateNotCa`, `InvalidLeafCertificate`,
`CertificateKeyUsageViolation`, `CertificateExtendedKeyUsageViolation`,
`UnhandledCriticalCertificateExtension`, `DuplicateCertificateEntry`,
`InvalidCertificateChainOrder`, `CertificateSignatureInvalid`,
`UnsupportedApplianceConfiguration`, `ProviderPublicationFailed`,
`FileNotFound`, `AccessDenied`, `OutOfMemory`.

Error output never includes key bytes, seeds, DER, signatures, or
key-derived identifiers.

## Ownership and zeroization

- Private-key file bytes, decoded PKCS#8 DER, and the extracted seed live
  only in typed secret containers (`crypto.secrets.BoundedSecret` /
  `FixedSecret`) and are wiped on **every** success and error path,
  including the file API's own bounded-read probe buffer.
- The seed crosses into the long-lived signing key through
  `SoftwareSigningKey.fromSeedSecret`, a narrow typed-secret bridge: it
  copies the seed exactly once into a scope it wipes itself and clears the
  caller's `FixedSecret` before key derivation runs, rather than passing an
  un-wiped by-value array copy across the call boundary.
- The long-lived signing key is an opaque `SoftwareSigningKey` owned by the
  published provider snapshot; snapshot retirement (reload or shutdown)
  securely erases it exactly once through the signer release path.
- The TLS engine sees only the provider-neutral
  `credentials.CredentialProvider`; private-key bytes never cross that seam,
  and the HTTP/3 runtime retains no certificate or key material of its own.

## Provider sharing (HTTP/1.1, HTTP/2, HTTP/3)

One `tls.appliance_credentials.ApplianceCredentials` owner is constructed at
the composition root and outlives every connection:

```
ApplianceCredentials (owns ReloadableProvider snapshot + signer)
        │ borrow: credentials.CredentialProvider
        ├── NativeTlsConnection (TCP) ── ALPN h2 / http/1.1 dispatch
        └── http3_runtime ── Tls13Backend.initServerWithProvider (QUIC/H3)
```

## Development fixtures

Generate development material (test identities only — **never** production
credentials; the checked-in `tests/fixtures/tls/native_ed25519*` files are
public test fixtures):

```sh
openssl req -x509 -newkey ed25519 -nodes \
  -keyout appliance.key -out appliance.crt \
  -days 365 -subj "/CN=appliance.example" \
  -addext "subjectAltName=DNS:appliance.example" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```

For a leaf+intermediate chain, issue the leaf from a separate self-signed
Ed25519 CA (`basicConstraints=critical,CA:TRUE`,
`keyUsage=critical,keyCertSign`) instead of self-signing it, and transmit
`leaf.crt` followed by `ca.crt`.

Do not generate RSA or `EC PRIVATE KEY` material for the appliance profile;
it is rejected at load time.
