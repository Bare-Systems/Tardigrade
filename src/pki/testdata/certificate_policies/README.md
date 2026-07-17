# Certificate-policy differential fixtures (#345)

Fixed, OpenSSL-generated chains for the RFC 5280 / RFC 9618 certificate-policy
matrix.  `zig build test-pki-policy-openssl` compares Tardigrade's decisions
against `openssl verify` on these exact certificates; the normal offline unit
tests never read them.

Regenerate with `./generate.sh` (requires an OpenSSL with Ed25519 support).
Only public certificates are committed; private keys are created in a temp
directory and destroyed.

Test policy OIDs: `1.3.6.1.4.1.99999.1` (OID1) and `1.3.6.1.4.1.99999.2`
(OID2).

| Chain (root → … → leaf) | Exercises |
| --- | --- |
| policy-intermediate → leaf-policy1 | direct explicit-policy success |
| policy-intermediate → leaf-policy2 | missing required policy |
| any-intermediate → any-leaf | anyPolicy propagation, plus initial anyPolicy inhibition |
| inhibit-ca1 → inhibit-ca2 → inhibit-leaf | inhibitAnyPolicy=0 extension |
| mapping-intermediate → mapping-leaf | OID1→OID2 policy mapping, plus initial mapping inhibition |
| mapinhibit-ca1 → mapinhibit-ca2 → mapinhibit-leaf | inhibitPolicyMapping:0 policyConstraints |
| rep-intermediate → rep-leaf | requireExplicitPolicy:0 with a policy-free leaf |

## Intentional differences from OpenSSL

- Tardigrade always processes certificate-policy extensions.  OpenSSL skips
  policy processing — including a CA's `requireExplicitPolicy` — unless
  `-policy_check` or a `-policy` argument enables it, so the differential
  harness always passes `-policy_check`.
- Tardigrade rejects noncritical `policyConstraints` and `inhibitAnyPolicy`
  extensions (RFC 5280 §§4.2.1.11 and 4.2.1.14 make criticality a MUST for
  conforming CAs); OpenSSL accepts them.  Every fixture marks these
  extensions critical, so the fixture matrix is unaffected.
- Tardigrade rejects `policyMappings` on a target certificate; OpenSSL
  ignores it.  No fixture exercises this.
