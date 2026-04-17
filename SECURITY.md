# Security Policy

Tardigrade is a public-edge service that terminates TLS, enforces auth, and proxies traffic to internal upstreams. Security process maturity is a first-class concern.

---

## Supported Versions

| Series | Status |
|--------|--------|
| Latest `main` | Actively maintained — security fixes applied immediately |
| Tagged releases | Latest tag receives backported security fixes; older tags do not |

Only the most recent tagged release is supported. If you are running an older release, upgrade to the latest tag before reporting.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately using one of the following channels:

- **GitHub private advisory**: [Security → Report a Vulnerability](https://github.com/Bare-Labs/Tardigrade/security/advisories/new) (preferred)
- **Email**: `security@baresystems.dev`

Include as much of the following as possible:

- Tardigrade version or commit hash
- Affected listener, protocol, or route type (TLS termination, reverse proxy, auth, WebSocket, SSE, rate limiter, etc.)
- Configuration involved (sanitized — omit real secrets)
- Reproduction steps
- Expected versus actual behavior (auth bypass, information disclosure, crash, etc.)
- Any CVEs or references for related upstream issues

---

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledgement | ≤ 72 hours |
| Initial assessment (severity triage) | ≤ 7 days |
| Fix development | Depends on severity; critical issues targeted ≤ 14 days |
| Coordinated disclosure | After fix is available; reporter notified before public release |

---

## Disclosure Process

1. Reporter submits via private channel.
2. Maintainers acknowledge, triage, and assign a severity (Critical / High / Medium / Low).
3. Fix is developed on a private branch and reviewed.
4. A patch release is cut and tagged.
5. A GitHub Security Advisory is published simultaneously with the release.
6. Reporter is credited in the advisory (unless they prefer anonymity).

Tardigrade follows a **coordinated disclosure** model. We ask reporters to give us a reasonable fix window (up to 90 days for non-critical issues) before publishing independently. We will always try to move faster than that.

---

## Security Fixes in Releases

Security releases are tagged with an incremented version and noted in `CHANGELOG.md` under a `### Security` heading. GitHub Releases include the severity and a link to the advisory.

Operators subscribed to GitHub release notifications will receive the announcement automatically.

---

## Scope

In scope for this policy:

- TLS termination and certificate handling
- Auth enforcement (`isProtectedAuthRequestRoute`, bearer token / JWT / session / device auth)
- Proxy path traversal, header injection, or response splitting
- Rate limiter bypass or information leakage through timing
- Approval workflow bypass
- Transcript store: unauthorized access, token/credential leakage

Out of scope:

- Vulnerabilities in upstream services proxied through Tardigrade
- Issues in the Zig standard library (report those to the Zig project)
- Denial-of-service via resource exhaustion without a practical exploit path

---

## Baseline Security Expectations

- Keep the core runtime generic and policy-driven; avoid product-specific coupling in security-sensitive code paths.
- Public-edge behavior must be documented in `README.md` and `BLINK.md`.
- Auth, routing, and approval behavior changes require documentation updates before merge.
- Secrets (tokens, JWTs, raw credentials) must be redacted before logging or transcript write.
