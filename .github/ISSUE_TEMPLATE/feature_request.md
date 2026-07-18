---
name: Feature Request
about: Propose a new capability or improvement
title: "[Feature]: "
labels: type:feature
---

<!--
Thanks for proposing an improvement! Please fill in as much of this template
as you can so maintainers can evaluate scope and impact.

Do not include in this issue any private keys, certificates containing
sensitive identity information, tokens, credentials, or production secrets.

If this proposal is actually a security concern, please do not open a public
issue — report it privately per SECURITY.md instead:
https://github.com/Bare-Systems/Tardigrade/security/advisories/new
-->

**Problem statement**
What gap or pain point does this address?

**Operator or developer value**
Who benefits and how? (operators running Tardigrade, contributors, downstream
integrators, etc.)

**Proposed behavior**
What should Tardigrade do differently?

**Alternatives considered**
Other approaches you evaluated, including doing nothing.

**Affected area or protocol**
Which component, protocol, or subsystem does this touch (e.g. HTTP/1.1,
HTTP/2, HTTP/3/QUIC, TLS, proxy/routing, config, auth, metrics, PKI)?

**Impact on the stable core**
Does this touch a feature listed as `stable` in the
[Support Matrix](https://github.com/Bare-Systems/Tardigrade/blob/main/docs/SUPPORT_MATRIX.md)?
If so, describe the impact on the Core v1 compatibility promise.

**Compatibility or migration concerns**
Any breaking changes, migration steps, or deprecations this would require.

**Configuration or CLI implications**
New config fields, CLI flags, defaults, or env vars this would introduce or
change.

**Documentation impact**
What docs (README, Support Matrix, CONTRIBUTING, config reference) would need
updates?

**Testing and interoperability impact**
What tests would prove this feature is correct, and does it affect
interop with external clients/servers (e.g. QUIC/H3 interop peers)?

**Security and resource-bound implications**
Does this touch auth, header handling, TLS, path serving, logging, or
introduce new unbounded resource usage (memory, connections, file handles)?

**Related issue, epic, PR, standard, or RFC**
Links to related work, prior discussion, or external specs.

**Proposal type**
- [ ] Release blocker
- [ ] Epic child (part of a larger tracked epic)
- [ ] Follow-up to existing work
- [ ] Independent enhancement

**Willingness to help**
- [ ] I'm willing to implement this
- [ ] I'm willing to test this
- [ ] I'm just proposing the idea

**Additional context**
Links, prior art, config examples, etc.
