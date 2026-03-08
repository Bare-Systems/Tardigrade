# feature-phase4-service-trust-model

## Scope
Implement Phase 4.6 service trust model foundations for upstream proxying.

## What changed
- Added trust model config in `src/edge_config.zig`:
  - `trust_gateway_id`
  - `trust_shared_secret`
  - `trusted_upstream_identities`
  - `trust_require_upstream_identity`
- Added environment variables:
  - `TARDIGRADE_TRUST_GATEWAY_ID`
  - `TARDIGRADE_TRUST_SHARED_SECRET`
  - `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES`
  - `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY`
- Added signed upstream header propagation in `src/edge_gateway.zig` when trust secret is configured:
  - `X-Tardigrade-Gateway-Id`
  - `X-Tardigrade-Trust-Timestamp`
  - `X-Tardigrade-Trust-Signature`
- Added auth context forwarding headers on upstream calls:
  - `X-Tardigrade-Auth-Identity`
  - `X-Tardigrade-Api-Version`
- Added trusted upstream identity enforcement against configured upstream identities before dispatch.
- Added explicit proxy execution error mapping for untrusted upstream paths (`upstream_untrusted`).

## Tests added/changed
- Existing full suite run: `zig build test`.
- Updated test config literals for expanded `EdgeConfig` fields.

## Status
done
