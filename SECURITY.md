# Security Policy

This is the security policy for **WebVella ERP**, a free and open-source .NET 10 / ASP.NET Core modular monolith on PostgreSQL, distributed under the terms in [LICENSE.txt](LICENSE.txt).

It covers how to report a vulnerability, what happens after you do, and what the platform's security posture actually is. It is deliberately short: the detail lives in the documents listed under [Security Documentation](#security-documentation), and this file's job is to make sure nobody has to guess where to look.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security report.** A public issue tells everyone about the weakness at the same moment it tells the maintainers, which leaves every deployed installation exposed for as long as the fix takes.

Use one of these channels instead:

* **GitHub private vulnerability reporting** on this repository — open the **Security** tab and choose **Report a vulnerability**. This is preferred: it opens a private draft advisory visible only to you and the maintainers.
* **The security contact listed at <https://webvella.com>**, if private reporting is unavailable at the time you need it. Ask for a private channel first, and keep vulnerability details out of that opening message.

A report is actionable when a maintainer can reproduce it without guessing. Please include:

* The **affected version, commit hash or branch** you tested.
* The **affected component** — a file path, a route, or a host application name.
* **Reproduction steps**, ideally the smallest sequence that demonstrates the problem.
* The **observed impact**: what an attacker gains, and what privileges they need to start.
* Where you know them, a **CWE identifier** and an **OWASP Top 10 (2021) category** — these are fields the platform's own findings already carry, so supplying them lets your report be filed straight against the same scheme.
* Any proof-of-concept request, payload, log or screenshot you captured.

Please also **do not test against deployments you do not own**. Scanners, fuzzers and load tests belong on your own installation, never on somebody else's production system or a third party's hosted instance. Do not access, modify or exfiltrate anyone else's data, and use a vulnerability no further than the minimum needed to demonstrate it.

## Response Expectations

WebVella ERP is a free and open-source project maintained on a best-effort basis. The timelines below are **targets, not guarantees** — stated plainly rather than dressed up as a service-level agreement the project cannot honour.

| Stage | Target |
| --- | --- |
| Acknowledgement that the report was received and read | 3 business days |
| Triage: confirmed or not, with a severity assigned and the reasoning for it | 10 business days |
| Remediation | Driven by the assigned severity — see [Severity Classification](#severity-classification) |

Disclosure is **coordinated**. Please allow a reasonable window for a fix to be published before going public, and say so if you have a deadline of your own, so it can be worked to rather than discovered. Reporters are credited when the fix ships, if they want to be. Not every confirmed weakness is closed by changing code — some are accepted with compensating controls, and where a risk is accepted rather than fixed it is recorded in the [risk register](docs/security/risk-register.md) with its reasoning, so the decision is auditable rather than invisible.

## Severity Classification

Reports are triaged, and the findings in the [security audit report](docs/security/security-audit-report.md) are classified, on one scheme — so that a report and an audit finding can be compared directly:

```text
Critical: RCE, authentication bypass, data breach exposure, privilege escalation to admin
          -> Immediate remediation required
High:     SQL injection, XSS (stored), IDOR with sensitive data, session hijacking
          -> Remediation required
Medium:   XSS (reflected), CSRF, information disclosure, weak cryptography
          -> Document with fix guidance
Low:      Missing security headers, verbose errors, minor misconfigurations
          -> Document for future sprint
```

This matrix is **prescriptive, not advisory**: it names the vulnerability classes that belong in each tier, and a finding is placed by matching it against the matrix rather than by scoring it independently. Two consequences are worth stating, because they surprise readers who expect a generic scoring system:

* **Unsalted password hashing is Critical**, as *data breach exposure* — not Medium "weak cryptography". The stored hashes were directly recoverable, so what is exposed is the credentials themselves.
* **Missing security headers are Low**, not Medium. They are defence-in-depth, and their absence is not by itself an information disclosure.

## Supported Versions

There is no long-term-support branch and no backport programme. Security fixes are made against the **`master` branch**, and an installation is supportable to the extent that it can take changes from it.

| Scope | Status |
| --- | --- |
| `master` branch | Supported — security fixes land here |
| `WebVella.Erp` 1.7.7, `WebVella.Erp.Web` 1.7.9, `WebVella.Erp.Plugins.Mail` 1.7.5 | Supported — the versions currently declared in the manifests |
| Earlier versions already published to nuget.org | Not supported — no backports are issued |
| Runtime | .NET 10 on PostgreSQL; all 19 projects target `net10.0` |

Running an unsupported runtime is a security condition in its own right, not merely a maintenance one: an advisory raised against an end-of-life framework line can never be patched. `net7.0` left support on **2024-05-14**, and the two Blazor WebAssembly projects that still targeted it were retargeted to `net10.0` as part of this remediation — finding **H-18**, **CWE-1104**.

## Security Posture

The platform has been audited against the **OWASP Top 10 (2021)**, categories **A01 through A10**. The audit produced **5 Critical, 20 High, 18 Medium and 10 Low findings — 53 in total**. Every one carries a CWE identifier, an OWASP category and a file-and-line evidence locator, and every one is written up in the [security audit report](docs/security/security-audit-report.md) in a fixed eight-field format.

The disposition rule is that **every Critical and High finding is remediated**, while **Medium and Low findings are documented with recommended fixes**. A Medium is *additionally* remediated only where it is a compensating control for a confirmed Critical or High, is mandated by one of the audit's Fix Implementation Standards, or is an unavoidable by-product of a Critical or High fix in the same method.

The controls now in force:

* **Credential storage** — salted, work-factored, fixed-time password hashing replaces unsalted MD5 (C-03), with stored hashes upgraded transparently on each user's next successful login, so no password reset is forced and no user is locked out.
* **Secret management** — no secrets in the repository: all eight `Config.json` files ship with empty values, the compiled-in encryption key and its silent fallback are gone, and startup **fails fast** when a required secret is absent (C-04, H-04, H-05).
* **Authorization** — deny-by-default provisioning, with the Guest-role grants on the user and role entities revoked and administrator-only permissions assigned to the password field (C-02, C-05).
* **Session and token handling** — a bounded authentication ticket, token lifetime validation with an explicit clock-skew allowance, UTC timestamps, logged validation failures, and secure cookie attributes across all seven hosts (H-02, H-03, H-15).
* **Transport and response headers** — the seven mandated response headers, HSTS and HTTPS redirection guarded to non-development environments, and SMTP certificate validation restored (H-11, H-15, M-01).
* **Injection and deserialisation** — a validate-and-quote helper for SQL identifiers, and a serialisation binder with an explicit type allow-list (H-09, H-10).
* **File handling** — extension allow-listing, size limits, content-type verification, filename sanitisation, attachment disposition on download, and ownership checks on move and delete (H-08).
* **Brute-force protection** — a five-attempt account lockout plus framework rate limiting (H-16).
* **Dependencies** — four version changes clearing three advisories, and a retarget off an end-of-life runtime (H-01, H-18, H-20).
* **Build-level enforcement** — dependency auditing and .NET security analyzers configured in [`Directory.Build.props`](Directory.Build.props) and exercised in CI by [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml).

One thing the fixes cannot undo: **every secret value that ever appeared in this repository's history must still be treated as public.** See the [Secure Deployment Checklist](#secure-deployment-checklist).

## Automated Security Validation

The gate is the build itself, so it runs wherever the project is built rather than only in CI. [`Directory.Build.props`](Directory.Build.props) is inherited by all 19 projects and sets:

| Control | Properties | Effect |
| --- | --- | --- |
| Dependency auditing | `NuGetAudit`, `NuGetAuditMode=all`, `NuGetAuditLevel=low` | Every direct **and transitive** package is checked against the advisory database, at every severity |
| Advisories fail the build | `NU1900`–`NU1905` promoted through `WarningsAsErrors` | The four advisory-severity codes `NU1901`–`NU1904`, plus the two availability codes `NU1900` and `NU1905` so that an audit which *could not run* also fails rather than reporting green |
| Static analysis | `EnableNETAnalyzers`, `AnalysisLevel=latest-recommended` | The .NET analyzers run on every compilation at the recommended level |

**A dependency advisory fails the build by design.** That is the whole point of the gate: a package carrying a published advisory cannot be introduced without somebody dealing with it. Analyzer diagnostics deliberately stay *warnings* — enabling them across roughly 700 pre-existing source files surfaces a large legacy backlog, and failing the build on that would force exactly the repository-wide refactor the remediation scope forbids. [`global.json`](global.json) pins the SDK exactly, so the audit defaults and the analyzer rule set are reproducible rather than dependent on whichever toolchain a machine happens to have. [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs restore with auditing, then the analyzer build, then `dotnet list package --vulnerable --include-transitive`.

Three substitutions are disclosed rather than concealed, because a validation claim is worth only as much as its provenance:

* **The external SAST, container/dependency and secrets scanners named in the audit brief could not be installed in the audit environment.** They were not run, and nothing here implies otherwise. The disclosed substitutes are the .NET analyzers, `NuGetAudit`, and a signature sweep of the tracked tree for credential patterns, which the CI workflow performs on every run.
* **The "existing test suite passes completely" gate is vacuous by construction** — there is no test project, no test file and no test-framework reference in any of the 19 projects. The substitute is a solution-wide restore, an analyzer-enabled build with zero errors, and a written manual verification checklist recorded in the [remediation log](docs/security/remediation-log.md). Creating a test suite was out of scope as feature work.
* **Advisory, version and licence data was obtained by direct retrieval** from the GitHub Advisory REST API and the NuGet flat-container API, because web search returned no results in the audit environment.

## Known Accepted Risks

Each item below is recorded in full — with its reasoning, its compensating control and the conditions for revisiting it — in the [risk register](docs/security/risk-register.md). An accepted risk is still a risk; the register exists so that these stay owned rather than forgotten.

* **The AutoMapper licence question is unresolved, and it is a repository-owner decision.** The advisory half is closed: the pin is on a patched version, with nothing suppressed. The licensing half is open — every patched version ships under the Reciprocal Public License 1.5, which conflicts with this project's Apache-2.0 posture and with publishing packages for third-party consumption, and there is no patched permissive version to retreat to. The documented fallback is to revert the pin behind a narrowly scoped, per-advisory audit suppression together with a formal recorded risk acceptance. Nothing in this remediation settles it.
* **The Content-Security-Policy ships in report-only mode first.** Four components emit inline script, so enforcing the mandated policy immediately would break the interface. The mandated header value is emitted exactly as specified; only the delivery mode is staged, with a documented report-then-enforce rollout.
* **Four by-design raw-output channels are not encoded** — the HTML-block page component and the generated inline-script emitters. Encoding them would disable the features they implement, so the compensating control is that authoring markup or script requires a privileged role.
* **The password-hashing algorithm deviates from the literal wording of the cryptographic standard**, which names bcrypt, scrypt or Argon2 at cost factor 12 or above. A high-iteration PBKDF2-HMAC-SHA256 primitive is used instead: sanctioned by the authoritative password-storage guidance at the iteration count applied, satisfying the rule's unambiguous intent of slow, salted, work-factored, fixed-time verification, and adding no dependency. Substituting a dedicated bcrypt or Argon2 package for literal compliance is recorded as an owner option.
* **The login throttle is per-instance.** It is backed by the existing in-process cache, to avoid both a schema change and a new dependency, so a multi-instance deployment is not protected by it. A distributed backing store is a recorded recommendation.
* **Login latency increases by design.** A high-iteration key-derivation function is deliberately slow. This is a pre-declared, accepted trade-off confined to the authentication path — not a regression.

## Security Documentation

| Document | What it covers |
| --- | --- |
| [Security audit report](docs/security/security-audit-report.md) | All 53 findings, each in the eight-field format: finding, severity, CWE, location, description, impact, evidence, remediation |
| [Remediation log](docs/security/remediation-log.md) | What changed, grouped by vulnerability class, with the verification performed for each |
| [Risk register](docs/security/risk-register.md) | Accepted risks, sanctioned deviations, documented-only Medium and Low findings, and ongoing recommendations |
| [Secure configuration guide](docs/security/secure-configuration.md) | Operator guidance: required secrets, response headers, transport security, cookies, rate limiting |
| [Credential migration guide](docs/security/credential-migration.md) | The password-hash migration, what operators must do, and rollback guidance |
| [`LIBRARIES.md`](LIBRARIES.md) | Third-party dependency inventory with versions, licences and advisory state |
| [`README.md`](README.md#configuration-required-secrets) | The required-settings table, without which the application will not start |

## Secure Deployment Checklist

Before exposing an installation to an untrusted network:

* **Rotate every secret this repository ever published — do not merely replace it.** The example encryption key and the example bearer-token signing key were committed here, so they are permanently public to anyone able to read the history, and scrubbing the working tree does not undo that. Generate fresh material. Both published defaults are additionally refused by digest comparison, so they cannot be reused even deliberately.
* **Supply every required secret from your own secret store**, by environment variable or user secrets — the connection string, the encryption key, and the bearer-token signing key on hosts that serve tokens. The application refuses to start without them, by design.
* **Never set `ASPNETCORE_ENVIRONMENT=Development` in production.** Development mode enables a developer exception page that returns stack traces.
* **Terminate TLS, and make sure the application can actually see an HTTPS request.** HTTPS redirection and HSTS are active outside Development, and the authentication and antiforgery cookies are `Secure`-only, so a plaintext-only host cannot complete a sign-in.
* **Configure the cross-origin allow-list** rather than relying on a default. No permissive any-origin policy remains on any host; supply the allowed origins for any host a browser client calls cross-origin.
* **Change the seeded administrator credential immediately**, and confirm the previous one no longer authenticates.
* **Leave e-mail transport certificate validation enabled.** It is the secure default; do not opt out of it.
* **Review the Content-Security-Policy rollout before enforcing it**, working through the inline-script inventory in the secure configuration guide.

The [secure configuration guide](docs/security/secure-configuration.md) expands every item above, including the exact variable names and the reasoning behind each default.

## Licence

WebVella ERP is distributed under the terms in [LICENSE.txt](LICENSE.txt) — the Apache License 2.0.
