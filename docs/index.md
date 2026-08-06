# blitzy-WebVella-ERP

WebVella ERP — .NET 10 / ASP.NET Core modular monolith on PostgreSQL, with a completed
OWASP Top 10 (2021) security audit and remediation. The solution comprises nineteen projects: a shared
core library, a web framework, seven independently hosted site applications and six plugins.

## Security

An OWASP Top 10 (2021) audit and remediation is complete: of 53 findings — 5 Critical, 20 High, 18
Medium and 10 Low — every Critical and High is remediated, and every Medium and Low is documented
with a recommended fix.

* [Audit Report](security/security-audit-report.md) — all 53 findings, each with severity, CWE, location, description, impact, evidence and remediation
* [Remediation Log](security/remediation-log.md) — what was fixed, per vulnerability class, with the verification performed for each
* [Risk Register](security/risk-register.md) — accepted risks, open owner decisions, and every documented-only finding
* [Secure Configuration](security/secure-configuration.md) — operator guide: required settings, secret supply, response headers, transport security, cookies, rate limiting
* [Credential Migration](security/credential-migration.md) — how existing password hashes are upgraded on next login, and what operators must do
* [`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) — the vulnerability disclosure policy: how to report an issue, and which versions are supported

**Read Secure Configuration before deploying.** The platform refuses to start until its secrets are
supplied externally, and several controls activate only outside the Development environment. The
third-party dependency inventory is in [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md).
