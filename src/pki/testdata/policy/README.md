# Certificate policy fixtures

These public Ed25519 certificates exercise RFC 5280/RFC 9618 policy
processing: direct intersection, a missing target extension, `anyPolicy`, a
one-to-one policy mapping, `requireExplicitPolicy`, and user-side inhibit
flags. Private keys are generated only in a temporary directory and are never
checked in.

Regenerate with `./generate.sh`. The script verifies every expected decision
with OpenSSL before replacing the fixed fixture set. Run
`zig build test-pki-openssl` for the differential Tardigrade/OpenSSL matrix.
