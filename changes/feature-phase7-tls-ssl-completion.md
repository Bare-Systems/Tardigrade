# Feature: Phase 7 TLS/SSL Completion

Status: done

## Scope
Complete Phase 7 TLS/SSL roadmap items, including protocol/cipher controls, SNI multi-cert behavior, session resumption, OCSP stapling, client certificate verification, CRL checks, and dynamic certificate management hooks.

## What Was Added
- TLS runtime options expanded in config:
  - Protocol selection (`TARDIGRADE_TLS_MIN_VERSION`, `TARDIGRADE_TLS_MAX_VERSION`)
  - Cipher controls (`TARDIGRADE_TLS_CIPHER_LIST`, `TARDIGRADE_TLS_CIPHER_SUITES`)
  - SNI cert mapping (`TARDIGRADE_TLS_SNI_CERTS`)
  - Session resumption/ticket controls (`TARDIGRADE_TLS_SESSION_*`)
  - OCSP stapling controls (`TARDIGRADE_TLS_OCSP_STAPLING`, `TARDIGRADE_TLS_OCSP_RESPONSE_PATH`)
  - mTLS controls (`TARDIGRADE_TLS_CLIENT_CA_PATH`, `TARDIGRADE_TLS_CLIENT_VERIFY`, `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH`)
  - CRL controls (`TARDIGRADE_TLS_CRL_PATH`, `TARDIGRADE_TLS_CRL_CHECK`)
  - Dynamic reload cadence (`TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS`)
  - Optional ACME-style cert directory discovery (`TARDIGRADE_TLS_ACME_ENABLED`, `TARDIGRADE_TLS_ACME_CERT_DIR`)
- Replaced TLS termination module implementation (`src/http/tls_termination.zig`) with:
  - OpenSSL protocol min/max enforcement
  - Cipher/ciphersuite configuration
  - SNI callback with per-host certificate selection
  - Session cache/tickets configuration
  - Optional static OCSP response loading and per-handshake stapling attachment
  - Optional client cert verification and chain-depth handling
  - Optional CRL loading/check flags on cert store
  - Timer-driven maintenance reload for cert/key/OCSP/CRL and SNI sources
- Gateway integration updates:
  - TLS terminator init now receives full TLS options from config
  - Event loop maintenance now calls TLS maintenance reload hook

## Files Changed
- `src/http/tls_termination.zig`
- `src/edge_config.zig`
- `src/edge_gateway.zig`
- `README.md`
- `PLAN.md`
- `CHANGELOG.md`

## Tests Added/Changed
- Existing TLS OpenSSL init test retained.
- Full suite run:
  - `zig build test` (pass)

## Notes
- ACME integration is implemented as optional filesystem-driven cert discovery (`<host>.crt` + `<host>.key`) rather than a built-in ACME client.
- Dynamic reload is polling-based via event-loop maintenance ticks.
