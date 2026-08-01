# Security Policy

This file is the entry point for anything security-related about WebVella ERP: how to report a vulnerability, what is supported, and what the platform's current security posture actually is.

It is deliberately short. The detail lives in the documents linked under [Security documentation](#security-documentation), and this file's job is to make sure nobody has to guess where to look.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** A public issue tells everyone about the weakness at the same moment it tells the maintainers, which leaves every deployed installation exposed for as long as the fix takes.

Use **GitHub's private vulnerability reporting** on this repository instead:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the issue.

If private reporting is not enabled for the repository at the time you need it, contact the maintainers privately through the channels listed in [`README.md`](README.md) and ask them to enable it, without including vulnerability details in that first message.

### What to include

A report is actionable when it lets a maintainer reproduce the problem without guessing:

* The affected component - a file path, a route, or a host application name.
* The version, commit hash or branch you tested.
* Reproduction steps, ideally the smallest sequence that shows the problem.
* The impact you believe it has: what an attacker gains, and what privileges they need to start.
* Any proof-of-concept request, payload or script, and whatever logs or screenshots you captured.

### What to expect

* **Acknowledgement** that the report was received and read.
* **An assessment** - whether the behaviour is confirmed, what severity it is assigned, and the reasoning behind that assignment. The severity matrix used is the one recorded in [the security audit report](docs/security/security-audit-report.md).
* **A remediation decision.** Not every confirmed weakness is fixed by changing code: some are accepted with compensating controls, and some are bounded by constraints such as backward compatibility. Where a risk is accepted rather than fixed, it is recorded in [the risk register](docs/security/risk-register.md) with its reasoning, so the decision is auditable rather than invisible.
* **Credit**, if you want it, when the fix is published.

Timelines are set by the maintainers of this repository, not by this document; promising a response window that nobody has committed to would be worse than saying nothing.

### Please do not

* Run automated scanners, fuzzers or load tests against installations you do not own.
* Access, modify or exfiltrate data belonging to anyone else.
* Use a vulnerability any further than the minimum needed to demonstrate it.

## Supported versions

Security fixes are made against the **default branch**. There is no long-term-support branch and no backport programme, so an installation is supportable to the extent that it can take changes from the default branch.

The platform targets **.NET 10** and requires **PostgreSQL**. Two projects previously targeted .NET 7, which stopped receiving security patches on **2024-05-14**; both were retargeted to .NET 10 during the security audit, so the whole solution is now on a supported runtime line. See [`LIBRARIES.md`](LIBRARIES.md) for the full dependency inventory and the reasoning behind every version decision.

Running an unsupported runtime is itself a security condition, not just a maintenance one: an advisory raised against an end-of-life framework line is permanently unfixable.

## Severity classification

Findings are classified on the scheme used by the platform's own security audit, so that a report and
an audit finding can be compared directly:

| Severity | Examples | Handling |
| --- | --- | --- |
| **Critical** | Remote code execution, authentication bypass, data-breach exposure, privilege escalation to administrator | Immediate remediation |
| **High** | SQL injection, stored cross-site scripting, insecure direct object reference over sensitive data, session hijacking | Remediation required |
| **Medium** | Reflected cross-site scripting, cross-site request forgery, information disclosure, weak cryptography | Documented with fix guidance; remediated when it is a compensating control for a confirmed Critical or High |
| **Low** | Missing security headers, verbose errors, minor misconfigurations | Documented for a future sprint |

## Security posture

The platform has been through a security audit against the **OWASP Top 10 (2021)**. The findings, their severities, and what was done about each are recorded in the documents linked below. Three things about the posture are worth stating plainly here, because they change what an operator has to do:

* **Secrets are supplied by the operator, and known published secrets are rejected rather than trusted.** The connection string, the encryption key and the JWT signing key must be supplied by environment variable or another configuration provider. Values that are absent, or that match a known published default, are refused rather than silently used, and there is no compiled-in fall-back. The tracked `Config.json` files now ship with **empty** secret values and `"DevelopmentMode": "false"`, and `WebVella.Erp.Site/web.config` sets `Production`. The files are retained rather than deleted, because the JSON configuration source is not optional and deleting them breaks start-up. **Every value ever published in this repository's history must still be treated as compromised** — rejection by digest comparison means a historically published key cannot be reused even deliberately. See [the secure configuration guide](docs/security/secure-configuration.md).
* **The bearer-token routes disable themselves when the signing key is unacceptable.** This is deliberate. A signing key that is published in a public repository is a key an attacker also holds, and a token endpoint signing with it would let anyone mint an administrator token. Supplying a real key re-enables the routes.
* **Stored password hashes are upgraded transparently, on each user's next successful login.** No password reset is forced and no user is locked out. See [the credential migration guide](docs/security/credential-migration.md).
* **Any secret that was ever committed must be rotated, not merely replaced.** A value removed from the working tree remains in repository history, so anyone deploying from this source has to generate fresh material for the encryption key, the token signing key and the database credentials. The published values in this repository are to be treated as public for all time.

Some risks are **accepted rather than fixed**, each with its reasoning recorded. The most consequential is a dependency advisory that cannot be closed without changing the product's effective licence; the full decision is in [the risk register](docs/security/risk-register.md) and in [`LIBRARIES.md`](LIBRARIES.md). An accepted risk is still a risk - the register exists so that these are owned and revisitable rather than forgotten.

### Enforced automatically on every build

The repository carries a build-level security gate in [`Directory.Build.props`](Directory.Build.props),
inherited by every project:

| Control | Property | Effect |
| --- | --- | --- |
| Dependency auditing | `NuGetAudit=true`, `NuGetAuditMode=all`, `NuGetAuditLevel=low` | Every direct **and transitive** package is checked against the advisory database, reporting advisories of every severity. |
| Advisories fail the build | `NU1901`–`NU1904` promoted through `WarningsAsErrors` | A package with a published advisory of any severity cannot be introduced without the build failing. |
| An audit that cannot run also fails the build | `NU1900` and `NU1905` promoted through `WarningsAsErrors` | These are *availability* diagnostics, not severities: the advisory source was unreachable, or supplied no data. Left as warnings they produce a green build that audited nothing. Six codes are promoted in total. |
| Static analysis | `EnableNETAnalyzers=true`, `AnalysisLevel=latest-recommended` | The .NET security analyzer rules run on every compilation — hard-coded keys, disabled certificate validation, SQL injection, insecure deserialisation, weak hashing, non-random initialisation vectors, cookie security. |

Analyzer diagnostics are reported as **warnings**, not errors, deliberately: enabling them across
roughly 700 pre-existing source files surfaces a large backlog, and failing the build on it would
force a mass refactor. Only the dependency advisory codes are errors, because those are actionable
by a version change.

The toolchain is pinned in [`global.json`](global.json) so that the audit defaults and the analyzer
rule set are reproducible rather than dependent on whichever SDK happens to be installed.

### What is hardened, and what is still open

Remediation is committed as **one atomic commit per vulnerability class**, and each class contributes
its findings to the audit report as it lands. The audit report and the
[remediation log](docs/security/remediation-log.md) are therefore the authoritative statement of what
is closed at any given commit — this file does not duplicate them, because a duplicated status list
goes stale.

Open decisions and accepted residual risk are in the [risk register](docs/security/risk-register.md).

### Before you run this in production

The shipped `Config.json` files no longer carry secrets: the connection string, encryption key, token
signing key, cloud storage connection string and mail password are **blank**, and every file sets
`DevelopmentMode` to `false`. **The application will therefore not start until you supply the required
secrets** — that is deliberate, and it fails fast with a message naming each missing setting (never
its value).

Any value that ever appeared in this repository's history must be treated as compromised. The two
published defaults — the example encryption key and the example token signing key — are additionally
rejected by digest comparison, so they cannot be reused even on purpose.

At minimum, supply these as environment variables:

```bash
export Settings__ConnectionString='Host=...;Database=...;Username=...;Password=...'
export Settings__EncryptionKey="$(openssl rand -hex 32)"
export Settings__Jwt__Key="$(openssl rand -base64 48)"   # only for hosts exposing token routes
export ASPNETCORE_ENVIRONMENT=Production
```

The [secure configuration guide](docs/security/secure-configuration.md) is the full checklist, and
[`README.md`](README.md) carries the complete required-settings table. Read the
[credential migration guide](docs/security/credential-migration.md) before upgrading an existing
installation.

One demo credential remains in the Blazor WebAssembly **client** page `Client/Pages/Index.razor.cs`.
It is browser-side sample code outside the scope of this remediation, and it is recorded in the risk
register rather than silently left.

## Security documentation

| Document | What it covers |
|---|---|
| [Security audit report](docs/security/security-audit-report.md) | Every finding, in a fixed eight-field format: finding, severity, CWE, location, description, impact, evidence, remediation |
| [Remediation log](docs/security/remediation-log.md) | What changed, grouped by vulnerability class, with the verification performed for each |
| [Risk register](docs/security/risk-register.md) | Accepted risks, sanctioned deviations, documented-only findings, and ongoing recommendations |
| [Secure configuration guide](docs/security/secure-configuration.md) | Operator guidance: required secrets, response headers, transport security, cookies, rate limiting |
| [Credential migration guide](docs/security/credential-migration.md) | The password-hash migration, what operators must do, and rollback guidance |
| [`LIBRARIES.md`](LIBRARIES.md) | Third-party dependency inventory, licences, advisory state and the recorded licensing decision |

## Scope

In scope for a security report: the application code in this repository, its shipped configuration,
its dependency manifests, and the documented behaviour of the seven host applications.

Out of scope, though still worth telling us about: findings in third-party dependencies that are
already public and already fixed upstream — we would rather receive the version bump; issues that
require an attacker to already hold administrator credentials, unless they cross a documented
privilege boundary; and the operational configuration of any particular deployment, which belongs to
whoever runs it. The [risk register](docs/security/risk-register.md) records what is already known,
accepted or deliberately deferred; a report that matches an entry there is still welcome, but it will
be triaged against that record.

### Already recorded - no need to re-report

These are known and documented. A report showing that one of them is *worse* than recorded is very welcome; a
report merely restating one is triaged against the existing record.

*worse*
than recorded is very welcome:

* Anything already recorded in the [audit report](docs/security/security-audit-report.md) or the
  [risk register](docs/security/risk-register.md), including the open licensing decision `RISK-001`.
* Secrets that appear in this repository's **history**. The tracked `Config.json` files now ship
  blank, and the two published default keys are rejected by digest comparison, so they cannot be used
  even deliberately. History cannot be rewritten retrospectively; treat those values as public and
  never reuse them. This is documented above and in the secure configuration guide rather than being a
  defect to report.
* The demo credential in the Blazor WebAssembly client page `Client/Pages/Index.razor.cs`. Known,
  recorded, and outside the scope of the remediation that scrubbed the server-side configuration.
* Components that emit author-supplied markup or script by design — the HTML-block page component and
  the generated inline-script emitters. These are raw output channels on purpose; the control is that
  authoring them requires a privileged role. Report a way to reach them *without* that role.
* Missing defence-in-depth features that the platform does not claim to have, such as multi-factor
  authentication. These are treated as recommendations for a future sprint rather than defects, and
  are carried in the risk register as the security documentation set is completed.
* Vulnerabilities in third-party dependencies, unless the platform's own usage is what makes them
  reachable. Report those upstream; the dependency gate above will surface the advisory here.

## Hardening checklist for operators

Before exposing an installation to untrusted networks:

* Supply `Settings__ConnectionString`, `Settings__EncryptionKey` and `Settings__Jwt__Key` from your own secret store. Do not reuse any value found in a repository, including this one.
* Set the environment to `Production`. Development mode enables a developer exception page that returns stack traces.
* Terminate TLS in front of the application. Outside Development it issues HSTS on every response; plaintext redirection additionally requires an HTTPS port to be discoverable (set `ASPNETCORE_HTTPS_PORTS`, and forward the protocol if TLS terminates at a proxy) - otherwise the redirect is silently inert.
* Change the seeded administrator credential immediately, and confirm the old one no longer authenticates.
* Restrict cross-origin access to origins you control. A permissive `Access-Control-Allow-Origin: *` policy is still present on two hosts and is recorded as an open finding.
* Review the Content-Security-Policy rollout. It ships in report-only mode by design, so it reports violations without blocking them until the inline-script inventory in the secure configuration guide has been worked through.

The secure configuration guide expands each of these, including the exact variable names and the reasoning behind the defaults.

## Licence

WebVella ERP is distributed under the terms in [LICENSE.txt](LICENSE.txt).
