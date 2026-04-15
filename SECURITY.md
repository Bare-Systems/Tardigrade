# Security Policy

Tardigrade is a public-edge service and should be treated as security-sensitive infrastructure.

## Reporting

Report vulnerabilities privately with:

- affected listener, protocol, or route type
- configuration involved
- reproduction steps
- expected versus actual auth, routing, or TLS behavior

## Baseline Expectations

- Keep the core runtime generic and policy-driven.
- Public-edge behavior must be documented in `README.md` and `BLINK.md`.
- Operator-facing auth, routing, and approval behavior changes require documentation updates.
