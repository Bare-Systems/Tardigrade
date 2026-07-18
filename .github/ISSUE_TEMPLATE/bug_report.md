---
name: Bug Report
about: Report something broken or behaving unexpectedly
title: "[Bug]: "
labels: type:bug
---

<!--
Thanks for taking the time to report a bug! Please fill in as much of this
template as you can — it helps us reproduce and fix the issue faster.

Do not include in this issue:
- Private keys
- Certificates containing sensitive identity information
- Tokens, credentials, or production secrets
- Unredacted private configuration

If this is a security vulnerability (auth bypass, header injection, path
traversal, information disclosure, etc.), please do not open a public issue.
Report it privately per SECURITY.md instead:
https://github.com/Bare-Systems/Tardigrade/security/advisories/new
-->

**Summary**
A clear, concise description of the bug.

**Affected surface**
Is the affected feature `stable`, `experimental`, or unknown? See the
[Support Matrix](https://github.com/Bare-Systems/Tardigrade/blob/main/docs/SUPPORT_MATRIX.md).

- [ ] Stable
- [ ] Experimental
- [ ] Unknown / not sure

**Environment**
- Tardigrade version, commit, or branch:
- Zig version:
- OS / architecture:
- Installation or build method (release binary, `zig build`, container image, etc.):

**Configuration**
Relevant configuration excerpt, with secrets and identifying details removed.

```
# paste sanitized config here
```

**Steps to reproduce**
1.
2.
3.

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Logs, metrics, or traces**
Relevant log lines, metrics output, stack traces, or packet traces. Redact
tokens, credentials, and any identifying data first.

```
# paste sanitized output here
```

**Regression?**
- [ ] Yes, this used to work
- [ ] No / not sure

If yes, last known working version, commit, or branch:

**Troubleshooting already attempted**
Tests, config changes, or workarounds you've already tried.

**Minimal reproduction**
- [ ] I can provide a minimal reproduction (repo, config, or script)
- [ ] I cannot provide a minimal reproduction

**Additional context**
Anything else that might help — related issues, links, environment quirks.
