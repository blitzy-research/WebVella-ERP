# blitzy-WebVella-ERP

WebVella ERP monolith decomposition — cloud-native microservices, serverless architecture, and OWASP security audit

## Security documentation

The platform has been audited against the OWASP Top 10 (2021). The findings, the changes made, and
the operator guidance that follows from them are recorded in the documents below.

| Document | What it covers |
|---|---|
| [Security audit report](security/security-audit-report.md) | Every finding in the mandated eight-field format: finding, severity, CWE, location, description, impact, evidence, remediation |
| [Remediation log](security/remediation-log.md) | What changed, grouped by vulnerability class, with the verification performed for each |
| [Risk register](security/risk-register.md) | Recorded decisions, accepted risks, standing warnings and ongoing recommendations |
| [Secure configuration guide](security/secure-configuration.md) | Operator guidance: required secrets, response headers, transport security, cookies, rate limiting |
| [Credential migration guide](security/credential-migration.md) | The password-hash migration, operator actions, and rollback guidance |

**Start with the [secure configuration guide](security/secure-configuration.md) if you are deploying
the platform.** Three secrets must be supplied before it will start, and several controls activate
only outside the Development environment.

The vulnerability disclosure policy is in
[`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md), and the
third-party dependency inventory — including licences, advisory state and the recorded licensing
decision — is in
[`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md).
