# OpenSSL Name Constraints fixtures

These fixed certificates are generated independently with OpenSSL by
`generate.sh`. The script keeps private keys in a temporary directory and
checks the expected OpenSSL decisions before exiting.

The fixture matrix covers permitted DNS, excluded-over-permitted DNS, IPv4
subnets (including the last address), directoryName rejection, and a
constrained intermediate. A separate leading-dot intermediate records the
OpenSSL compatibility behavior adopted by Tardigrade: `.example.com` permits
one or more labels below the domain but does not permit `example.com` itself.

The normal `test-pki` target embeds these public certificates and remains
offline. Run `zig build test-pki-openssl` to compare every fixture decision
with the local OpenSSL CLI.

Intentional policy differences outside this fixture matrix:

- Tardigrade rejects noncritical Name Constraints because RFC 5280 requires
  conforming CA certificates to mark the extension critical.
- Tardigrade supports the historical exact-mailbox rfc822Name constraint for
  compatibility, while RFC 9549 removes mailbox constraints for newly issued
  certificates. Host and domain constraints follow RFC 9549.
- Unsupported GeneralName constraint forms and non-contiguous IP masks fail
  closed instead of inheriting provider-specific behavior.
- Internationalized DNS and email hosts must already use ASCII A-label form;
  this slice does not perform U-label conversion or full IDNA validation.
- A self-issued rollover is covered by deterministic signed unit fixtures;
  the independent set omits it because OpenSSL CA database/key-rollover setup
  would add mutable generation state without increasing matcher coverage.
