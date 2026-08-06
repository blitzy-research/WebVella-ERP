# blitzy-WebVella-ERP

WebVella ERP — .NET 10 / ASP.NET Core modular monolith on PostgreSQL, which has been through an
OWASP Top 10 (2021) security audit and remediation. The solution comprises nineteen projects: a shared
core library, a web framework, seven independently hosted site applications and six plugins.

## Security

Of 53 findings — 5 Critical, 20 High, 18 Medium and 10 Low — every Critical and High has an
implemented fix, and every Medium and Low is documented with a recommended fix.

**Remediation is not the same as full validation, so the two are reported separately.** Two of the
engagement's five validation gates do not pass at this revision: static analysis is **PARTIAL**, because
only four of the eleven relevant analyzer families execute at the frozen analysis level, and manual
verification is **DEFERRED**, because one mandatory scenario has not been executed. A third gate is
**vacuous by construction** — the repository contains no test suite. One process requirement, *atomic
commits per vulnerability class*, **FAILED**. The authoritative gate-by-gate table is
[Status at this revision](security/security-audit-report.md#status-at-this-revision-gate-by-gate).

- [Audit Report](security/security-audit-report.md) — all 53 findings, each with severity, CWE, location, description, impact, evidence and remediation
- [Remediation Log](security/remediation-log.md) — what was fixed, per vulnerability class, with the verification performed for each
- [Risk Register](security/risk-register.md) — accepted risks, open owner decisions, and every documented-only finding
- [Secure Configuration](security/secure-configuration.md) — operator guide: required settings, secret supply, response headers, transport security, cookies, rate limiting
- [Credential Migration](security/credential-migration.md) — how existing password hashes are upgraded on next login, and what operators must do
- [`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) — the vulnerability disclosure policy: how to report an issue, and which versions are supported

**Read Secure Configuration before deploying.** The platform refuses to start until its connection string
and encryption key are supplied externally — the bearer-token signing key behaves differently, disabling
the token routes rather than stopping the host — and several controls activate only outside the
Development environment. The
third-party dependency inventory is in [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md).
