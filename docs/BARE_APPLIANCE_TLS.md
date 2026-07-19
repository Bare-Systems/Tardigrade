# Bare Systems Appliance TLS Provisioning (v0.5)

This document is the complete supported contract for the fixed-profile Bare
Systems appliance TLS identity (#392). It applies to binaries built with
`-Dtls-profile=appliance` (no OpenSSL/libcrypto linkage; pure-Zig TLS only).

## Supported profile

The appliance profile is deliberately narrow:

- exactly **one** provisioned server identity per appliance;
- **Ed25519 only** (RFC 8410);
- one **leaf-first** ordered certificate chain;
- **TLS 1.3 only**, key exchange **X25519**, cipher `TLS_AES_128_GCM_SHA256`;
- ALPN `h2` and `http/1.1` over native TCP;
- the **same credential provider instance** authenticates native HTTP/3
  (QUIC);
- no OpenSSL, libcrypto, or any foreign TLS/crypto library.

Explicit non-goals (rejected, not silently degraded): RSA, ECDSA/P-256
signing, encrypted private keys, OpenSSH keys, multiple SNI identities,
wildcard host names, client certificates/mTLS, public-PKI path validation,
trust-store policy, hardware/remote signers, filesystem watchers, and
heuristic PEM/DER format detection.

## Configuration

| Setting | Environment | Directive |
| --- | --- | --- |
| Certificate chain file | `TARDIGRADE_TLS_CERT_PATH` | `tls_cert_path` |
| Private key file | `TARDIGRADE_TLS_KEY_PATH` | `tls_key_path` |
| Served host name | `TARDIGRADE_TLS_SERVER_NAME` | `tls_server_name` |

When TLS is enabled in an appliance build, `tls_server_name` is **required**
and must be exactly one valid, non-wildcard DNS host name.
`TARDIGRADE_TLS_SNI_CERTS` (and per-`server`-block certificates) are rejected:
the appliance serves one identity.

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
  certificate; the leaf must carry a canonical RFC 8410 Ed25519
  SubjectPublicKeyInfo (zero BIT STRING unused bits, exactly 32 key bytes).

Raw DER files are **not** accepted.

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
| Encoded TLS Certificate flight | `max_message_len` − 512 bytes headroom |

The flight bound is preflighted **before publication** using the same
framing arithmetic as the TLS handshake writer, so an oversized chain fails
at startup/`check`, never during a live handshake.

## Startup, `tardi check`, and reload

At startup the appliance profile loads and fully validates the credential
**before any TCP or UDP listener is bound**. On any failure the process
refuses to start; HTTP dispatch is never reachable with invalid credentials.

`tardi check` performs the identical preflight without opening any socket:
file reads, strict PEM/PKCS#8 parsing, Ed25519 key parse, exact leaf/private
public-key comparison plus a fixed sign-and-verify probe, server-name policy,
chain and flight bounds, and provider snapshot construction/teardown. Every
failure is reported as a configuration error with a deterministic class.

Hot reload (`SIGHUP`) **rejects** a configuration that changes the
certificate path, key path, `tls_server_name`, or SNI credential
configuration; the previous configuration and credentials remain active.
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
`KeyCertificateMismatch`, `CertificateFlightTooLarge`, `InvalidServerName`,
`UnsupportedApplianceConfiguration`, `FileNotFound`, `AccessDenied`,
`OutOfMemory`.

Error output never includes key bytes, seeds, DER, signatures, or
key-derived identifiers.

## Ownership and zeroization

- Private-key file bytes, decoded PKCS#8 DER, and the extracted seed live
  only in typed secret containers (`crypto.secrets.BoundedSecret` /
  `FixedSecret`) and are wiped on **every** success and error path.
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
credentials; the checked-in `tests/fixtures/tls/native_ed25519.*` keys are
public test fixtures):

```sh
openssl req -x509 -newkey ed25519 -nodes \
  -keyout appliance.key -out appliance.crt \
  -days 365 -subj "/CN=appliance.example" \
  -addext "subjectAltName=DNS:appliance.example"
```

Do not generate RSA or `EC PRIVATE KEY` material for the appliance profile;
it is rejected at load time.
