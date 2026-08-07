# Security Policy

This is the security policy for **WebVella ERP**, a free and open-source .NET 10 / ASP.NET Core modular monolith on PostgreSQL, distributed under the terms in [LICENSE.txt](LICENSE.txt).

It covers how to report a vulnerability, what happens after you do, and what the platform's security posture actually is. It is deliberately short: the detail lives in the documents listed under [Security Documentation](#security-documentation), and this file's job is to make sure nobody has to guess where to look.

> **Status authority.** This document is **not** the authority for the security posture's status.
> Exactly one surface is: the audit report's
> [Status at this revision, gate by gate](docs/security/security-audit-report.md#status-at-this-revision-gate-by-gate) section. Where any statement here disagrees
> with it, that section governs and this one is superseded. Configuration requirements are owned by the [secure configuration guide](docs/security/secure-configuration.md).
> Recorded under code-review findings `MAJ-06` and `MAJ-12`.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security report.** A public issue tells everyone about the weakness at the same moment it tells the maintainers, which leaves every deployed installation exposed for as long as the fix takes.

Use one of these channels instead:

- **GitHub private vulnerability reporting** on this repository — open the **Security** tab and choose **Report a vulnerability**. This is preferred: it opens a private draft advisory visible only to you and the maintainers.
- **The security contact listed at <https://webvella.com>**, if private reporting is unavailable at the time you need it. Ask for a private channel first, and keep vulnerability details out of that opening message.

A report is actionable when a maintainer can reproduce it without guessing. Please include:

- The **affected version, commit hash or branch** you tested.
- The **affected component** — a file path, a route, or a host application name.
- **Reproduction steps**, ideally the smallest sequence that demonstrates the problem.
- The **observed impact**: what an attacker gains, and what privileges they need to start.
- Where you know them, a **CWE identifier** and an **OWASP Top 10 (2021) category** — these are fields the platform's own findings already carry, so supplying them lets your report be filed straight against the same scheme.
- Any proof-of-concept request, payload, log or screenshot you captured.

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

- **Unsalted password hashing is Critical**, as *data breach exposure* — not Medium "weak cryptography". The stored hashes were directly recoverable, so what is exposed is the credentials themselves.
- **Missing security headers are Low**, not Medium. They are defence-in-depth, and their absence is not by itself an information disclosure.

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

The platform has been audited against the **OWASP Top 10 (2021)**, categories **A01 through A10**. The audit produced **5 Critical, 20 High, 17 Medium and 11 Low findings — 53 in total**. *(An earlier revision counted 18 Medium and 10 Low. `M-01`, missing security response headers, was reclassified from Medium to **Low** under code-review finding `MAJ-07`, because the matrix above names that class in the Low tier and eligibility for remediation is not a severity input. The total is unchanged. It is still remediated in full — see the audit report.)*

> **Implemented is not the same as verified, and this section describes what is implemented.** Every Critical and High finding has a fix in the tree with its own recorded verification. **The platform is NOT release-ready at this revision, and three separate things keep it that way** — an unmet acceptance criterion, an open owner decision on a dependency licence, and a scope deviation that only the repository owner can resolve. Gate by gate: the **static-analysis gate's coverage is now closed at 19 of 19 compilations** — the whole Security category is armed, the `CA3001`–`CA3012` taint family runs for eighteen projects in the ordinary build and for the nineteenth, `WebVella.Erp.Web`, through a dedicated terminating scan under a cost bound whose reporting capability is proved in the same step (code-review finding `MAJ-01`), and every Security-category diagnostic that fires is an accepted residual carrying a risk reference and a written disposition. The **manual-verification gate's manual half passes**: the matrix carries 50 rows, and all 32 manual rows — 31 mandatory plus the single advisory row — have been executed against disposable hosts and live databases and are attested, so `deferred=0` and **no manual row blocks release**. But the matrix also carries a row that **fails by design**: `A17` records that the mandated seven-header set is **not** satisfied while the Content-Security-Policy ships under the report-only name (code-review finding `MAJ-03`), so `RELEASE-READY` prints `no` and the release gate exits non-zero. A third gate is **vacuous by construction** because no test suite exists. *(Earlier revisions of this paragraph said 24 or 25 manual rows were unattested and that the gate was red for that reason. Both halves are superseded: the rows are attested, and the gate is red for the header reason instead.)* One engagement process requirement, *atomic commits per vulnerability class*, **FAILED** historically: seven of thirteen commits in the original remediation carry more than one class, and acknowledging that is not the same as complying with it — every commit made since has carried exactly one class. The authoritative, gate-by-gate status table is [Status at this revision](docs/security/security-audit-report.md#status-at-this-revision-gate-by-gate) in the audit report. Where any sentence below reads as a completion claim, that table governs. Every one carries a CWE identifier, an OWASP category and a file-and-line evidence locator, and every one is written up in the [security audit report](docs/security/security-audit-report.md) in a fixed eight-field format. Five records reached an earlier revision with the CWE field asserting no identifier — for a missing header set, an unobserved asynchronous call, commented-out package references, a committed binary and an unpinned toolchain — on the reasoning that each was a hygiene observation rather than a weakness. CWE has classes for all five (CWE-693, CWE-252, CWE-1164, CWE-1357 and CWE-494), so the abstentions were withdrawn and the claim above now holds without exception.

The original fifty-three-finding audit used this disposition rule: **Critical and High findings require remediation**, while **Medium and Low findings require documentation with recommended fixes**. Within that original inventory, all five Critical and all twenty High findings are remediated. That statement is deliberately scoped to the audit inventory rather than presented as a blanket claim about every defect later found in the product: independent post-remediation reviews added further `P-`, `F-`, `CR2-F-`, `B3-` and `SR-` records to the [audit report](docs/security/security-audit-report.md). The eight-finding review `F-01` through `F-08` is closed — seven findings by code changes and `F-08` by synchronising this documentation set. **The most recent review is a checkpoint review of the remediation itself**, recorded as `CK-01` through `CK-23` in Part 5 of the audit report: one Critical, three High, eight Medium, four Low and seven release or compliance blockers. Sixteen are closed by code changes, two are documented-only under explicit AAP exclusions, one is an owner decision whose mechanism is closed, and one is a process failure complied with from that point rather than rewritten. Its Critical, `CK-01`, was an authenticated remote-code-execution path that this document set's own automated gate could not detect — which is why four of its findings are about the gates rather than about the product. The review before it was of the frontend and API seam, recorded as `SR-01` through `SR-16` in Part 4 and closed in full. It matters to a reader of this section because three of its four Critical findings, and its highest-impact Major, were **invisible to every control described here**: a Blazor WebAssembly client composing its own request URLs, a third-party package whose JavaScript this repository cannot edit, and a stored cross-site-scripting chain whose sink is a client-side `innerHTML` assignment rather than a Razor expression — so no server-side sink census could reach it. Two further defects were found while closing those sixteen and are recorded with them: one a regression introduced after the checkpoint baseline by this engagement, the other a regression introduced by one of the sixteen remediations itself and caught by runtime verification of that remediation. Accepted residuals, documented-only issues and owner decisions remain visible in the [risk register](docs/security/risk-register.md), so this posture must not be read as a claim that no further risk or undiscovered instance exists.

A Medium is *additionally* remediated only where it is a compensating control for a confirmed Critical or High, is mandated by one of the audit's Fix Implementation Standards, or is an unavoidable by-product of a Critical or High fix in the same method.

**What "remediated" means here, stated precisely.** It means a code change is in place and is covered by the automated gate: the analyzer build, the dependency audit and the secret sweep all pass on every push. It used **not** to mean that every fix had been observed working against a running deployment — 32 of the verification scenarios need a live PostgreSQL instance, a browser or an SMTP server, and a workflow runner has none of the three, so CI recorded those rows as deferred and a separate **blocking release gate** refused to pass while any of them was unattested. **All 32 have since been executed by hand** against disposable hosts and live PostgreSQL databases and are attested in the tracked `manual-verification-results.txt`, commit-bound, dated and each bound to the hash of the scenario text it was executed against — so a scenario that is later rewritten invalidates its own attestation and must be re-executed rather than inheriting a pass. *(An earlier revision of this paragraph said four were executed and twenty-five were not. That is superseded.)* **The release gate is nevertheless still red, and for a different reason**: the mandated Content-Security-Policy header ships under its report-only name, which does not satisfy a requirement for an enforced header set, and the matrix now records that as a failing row rather than accepting the substitute. Two further items are open and are **not** engineering follow-ups: the `AutoMapper` Reciprocal Public License question, which mechanically blocks `dotnet pack`, and the scope deviation the audit report discloses. Anyone deploying this platform should read the [risk register](docs/security/risk-register.md) for what is accepted rather than fixed and should not read this section as a clearance to skip verification.

The controls now in force:

- **Credential storage** — salted, work-factored, fixed-time password hashing replaces unsalted MD5 (C-03), with stored hashes upgraded transparently on each user's next successful login, so no password reset is forced and no user is locked out.
- **Secret management** — no secrets in the repository: all eight `Config.json` files ship with empty values, the compiled-in encryption key and its silent fallback are gone, and startup **fails fast** when a required secret is absent (C-04, H-04, H-05).
- **Authorization** — deny-by-default provisioning, with the Guest-role grants on the user and role entities revoked and administrator-only permissions assigned to the password field (C-02, C-05).
- **Session and token handling** — a bounded authentication ticket, token lifetime validation with an explicit clock-skew allowance, UTC timestamps, logged validation failures, and secure cookie attributes across all seven hosts (H-02, H-03, H-15).
- **Transport and response headers** — the seven mandated response headers, HSTS and HTTPS redirection guarded to non-development environments, invariant parsing and range validation for a configured public HTTPS port, and SMTP certificate validation restored (H-11, H-15, M-01, F-07).
- **Injection and deserialisation** — a validate-and-quote helper for SQL identifiers, and a serialisation binder with an explicit type allow-list (H-09, H-10).
- **File handling** — extension allow-listing, size limits, content-type verification, filename sanitisation, attachment disposition on download, private caching for authenticated files, `no-store` for staged files, ownership checks on move and delete, and transactionally pinned destination state for overwrite moves (H-08, F-04, F-05).
- **Brute-force protection** — a five-attempt account lockout plus framework rate limiting (H-16).
- **Error handling and security auditing** — the two unconditional stack-trace responses are gone, and every fault path on the web API surface now answers with a generic message while recording the full detail server-side (H-13). Diagnostics are written through a single failure-isolated boundary, so a logging fault can never replace the response a caller was owed, and every record is written non-notifying so an error path cannot be driven into a mail flood. The authentication surface emits one bounded record per evaluated attempt *and per refusal* — sampling refusals would let an account under attack be refused hundreds of times behind a single row — plus records for sign-out, session revocation and replay of a revoked token (M-12). Records that an attacker can repeat at will are rate-bounded and report the volume they withheld, so the evidence exists without becoming a log-growth primitive.
- **Dependencies** — four version changes clearing three advisories, and a retarget off an end-of-life runtime (H-01, H-18, H-20).
- **Build-level enforcement** — dependency auditing and .NET security analyzers configured in [`Directory.Build.props`](Directory.Build.props) and exercised in CI by [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml).

One thing the fixes cannot undo: **every secret value that ever appeared in this repository's history must still be treated as public.** See the [Secure Deployment Checklist](#secure-deployment-checklist).

## Automated Security Validation

The gate is the build itself, so it runs wherever the project is built rather than only in CI. [`Directory.Build.props`](Directory.Build.props) is inherited by all 19 projects and sets:

| Control | Properties | Effect |
| --- | --- | --- |
| Dependency auditing | `NuGetAudit`, `NuGetAuditMode=all`, `NuGetAuditLevel=low` | Every direct **and transitive** package is checked against the advisory database, at every severity |
| Advisories fail the build | `NU1900`–`NU1905` promoted through `WarningsAsErrors` | The four advisory-severity codes `NU1901`–`NU1904`, plus the two availability codes `NU1900` and `NU1905` so that an audit which *could not run* also fails rather than reporting green |
| Static analysis | `EnableNETAnalyzers`, `AnalysisLevel=latest-recommended`, `AnalysisLevelSecurity=latest-all` | The .NET analyzers run on every compilation: the general rule set at the recommended level, and the **whole Security category** at every rule the pinned SDK defines in it. The category level is what makes the audit's own static-analysis gate checkable — nine of the eleven security families the gate names do not execute at `latest-recommended`. It is delivered through a configuration the **SDK ships**, so no `.globalconfig` exists in this repository and the workflow asserts that none does |
| The one analyzer exclusion | `NoWarn` carries `CA3001`–`CA3012` **for `WebVella.Erp.Web` only** | The interprocedural taint-dataflow family is excluded for a **measured termination** reason, not a scope preference — and the exclusion is now scoped to the single project the measurement implicates. Armed and untuned the solution build produced no further output for over thirty-five minutes with 3 of 17 projects finished; per project, eighteen of the nineteen complete in 0 to 6 seconds each with zero `CA3001`–`CA3012` diagnostics while `WebVella.Erp.Web` alone does not finish — killed at a 600-second bound, and re-measured past **2,700 seconds** for code-review finding `MAJ-01`. **The exclusion is a build-time measure, not a coverage gap.** Under `MAJ-01` that nineteenth compilation is scanned by its own workflow step with the family armed and the interprocedural chain bounded to one hop — about **220 seconds**, exit 0, **zero** `CA3001`–`CA3012` diagnostics — and the step proves the bounded configuration still reports by requiring `CA3001` and `CA3003` against deliberate taint flows before it trusts that zero, treats a timeout as a hard failure, and publishes `taint-scan-web.txt` as evidence. **Taint coverage is therefore 19 of 19 compilations**; what remains a residual is analysis depth for that one project (`RISK-051`). The workflow asserts the exclusion in both directions, so it can neither be lost nor widened unobserved. Carried as `RISK-138` |

**A dependency advisory fails the build by design.** That is the whole point of the gate: a package carrying a published advisory cannot be introduced without somebody dealing with it. Analyzer diagnostics deliberately stay *warnings* — enabling them across roughly 700 pre-existing source files surfaces a large legacy backlog, and failing the build on that would force exactly the repository-wide refactor the remediation scope forbids. [`global.json`](global.json) pins the SDK exactly, so the audit defaults and the analyzer rule set are reproducible rather than dependent on whichever toolchain a machine happens to have. [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs restore with auditing, then the analyzer build, then `dotnet list package --vulnerable --include-transitive`.

Three substitutions are disclosed rather than concealed, because a validation claim is worth only as much as its provenance:

- **The external SAST, container/dependency and secrets scanners named in the audit brief could not be installed in the audit environment.** They were not run, and nothing here implies otherwise. The disclosed substitutes are the .NET analyzers, `NuGetAudit`, and a signature sweep of the tracked tree for credential patterns, which the CI workflow performs on every run.
- **There is no test suite, and the "existing test suite passes completely" gate is vacuous by construction** — there is no test project, no test file and no test-framework reference in any of the 19 projects. The substitute is a solution-wide restore, an analyzer-enabled build with zero errors, and a written manual verification checklist recorded in the [remediation log](docs/security/remediation-log.md). Creating a test suite was out of scope as feature work.
- **Advisory, version and licence data was obtained by direct retrieval** from the GitHub Advisory REST API and the NuGet flat-container API, because web search returned no results in the audit environment.

## Known Accepted Risks

Each item below is recorded in full — with its reasoning, its compensating control and the conditions for revisiting it — in the [risk register](docs/security/risk-register.md). An accepted risk is still a risk; the register exists so that these stay owned rather than forgotten.

- **The AutoMapper licence question is unresolved, and it is a repository-owner decision.** The advisory half is closed: the pin is on a patched version, with nothing suppressed. The licensing half is open — every patched version ships under the Reciprocal Public License 1.5, which conflicts with this project's Apache-2.0 posture and with publishing packages for third-party consumption, and there is no patched permissive version to retreat to. The documented fallback is to revert the pin behind a narrowly scoped, per-advisory audit suppression together with a formal recorded risk acceptance. Nothing in this remediation settles it.
- **The Content-Security-Policy ships in report-only mode, so it is emitted but not enforced — and the mandated seven-header requirement is therefore `UNRESOLVED / PARTIAL`, not compliant.** Five first-party components emit inline script, and a measured browsing session produced at least 379 report-only violations dominated by inline *style*, so enforcement is a project rather than a configuration flag and is a repository-owner decision. The mandated header value is emitted exactly as specified and cannot be weakened by configuration; only the delivery mode is staged. The authoritative status row is in the audit report's [status section](docs/security/security-audit-report.md#status-at-this-revision-gate-by-gate); the promotion governance is `RISK-022` and the measured backlog is `RISK-170`.
- **By-design raw-output channels are not encoded** — the HTML-block page component and the generated inline-script emitters, five in total. Encoding them would disable the features they implement. The compensating control is that only an administrator can **place** such a channel on a page or set its option, because the five page-node mutation actions are gated by `IsCodeAuthoringAuthorized`. It is **not** that only privileged users can influence the bytes: the option is resolved through `PageDataModel.GetPropertyValueByDataSource`, so an administrator may point the channel at a record field, after which anyone able to write that field influences what is emitted unencoded. For the HTML-block component specifically, that data-bound path is now **sanitised** — code-review finding `HIGH-01` — while administrator-authored literal markup still renders raw. The Content-Security-Policy is the load-bearing half of this compensation for the remaining channels — see `RISK-023` for the acceptance and `RISK-170` for the complete inventory of all 111 raw-output sinks with their writers and authorization contracts. An earlier revision of this bullet counted four channels and cited `RISK-004`, which is the broken-hash analyzer entry; both are corrected here.
- **The password-hashing algorithm deviates from the literal wording of the cryptographic standard**, which names bcrypt, scrypt or Argon2 at cost factor 12 or above. A high-iteration PBKDF2-HMAC-SHA256 primitive is used instead: sanctioned by the authoritative password-storage guidance at the iteration count applied, satisfying the rule's unambiguous intent of slow, salted, work-factored, fixed-time verification, and adding no dependency. Substituting a dedicated bcrypt or Argon2 package for literal compliance is recorded as an owner option.
- **The login throttle used to be per-instance; it no longer is, and this bullet is retained rather than deleted because the change matters operationally.** Review finding `H-OPEN-02` moved the counters into the platform's existing `plugin_data` table under a reserved key prefix, mutated by atomic row-locked read-modify-write — still no schema change and still no new dependency. Five failures now means five in total rather than five per process, a lockout survives a restart and spans instances, and the throttle fails closed when the store cannot be reached. **The residual is the reverse of the old one:** an operator can no longer release a lockout by bouncing the process, so plan on waiting out the fifteen-minute window. See `RISK-008`.
- **All thirty-two runtime verifications have now been executed by hand and attested; what the automated gate alone cannot prove, it still does not claim.** Each of the manual rows verifies a Critical or High fix and each needs a live PostgreSQL instance, a browser or an SMTP server, which a hosted runner does not have. They are therefore **not** proven by the gate itself: the matrix classifies 31 of the 32 as REQUIRED, and a manual row leaves `DEFERRED` only on an attestation bound to a commit that is an ancestor of the commit under test, to a hash of the scenario with its procedure and prerequisites, and to a named environment — in a committed file. Every one of the 32 now holds such a line, executed against disposable hosts and disposable databases, so the matrix reports `deferred=0`. Release readiness is nonetheless still **not** established: the workflow's own gates all pass, but the open AutoMapper licence decision is reserved to the repository owner and blocks `dotnet pack` through the `ERPLIC001` gate. And a plain-text attestation is auditable rather than cryptographically trustworthy — a green run means the automated evidence is clean and a human has signed for the rest, not that the signature is unforgeable.
- **Three armed analyzer rules have never been observed to fire.** `CA5382`, `CA5383` and `CA5402` are enabled by the category level above, but no probe in this environment has provoked any of them, so they are deliberately left out of the per-rule ratchet rather than baselined at zero — a zero from a rule nothing has proven can speak is not evidence. Carried as `RISK-137`.
- **Login latency increases by design.** A high-iteration key-derivation function is deliberately slow. This is a pre-declared, accepted trade-off confined to the authentication path — not a regression.

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

- **Rotate every secret this repository ever published — do not merely replace it.** The example encryption key and the example bearer-token signing key were committed here, so they are permanently public to anyone able to read the history, and scrubbing the working tree does not undo that. Generate fresh material. Both published defaults are additionally refused by digest comparison, so they cannot be reused even deliberately.
- **Supply every required secret from your own secret store**, by environment variable or user secrets — the connection string, the encryption key, and the bearer-token signing key on hosts that serve tokens. The application refuses to start without them, by design.
- **Never set `ASPNETCORE_ENVIRONMENT=Development` in production.** Development mode enables a developer exception page that returns stack traces.
- **Terminate TLS, and make sure the application can actually see an HTTPS request.** HTTPS redirection and HSTS are active outside Development, and the authentication and antiforgery cookies are `Secure`-only, so a plaintext-only host cannot complete a sign-in.
- **Configure the cross-origin allow-list** rather than relying on a default. No permissive any-origin policy remains on any host; supply the allowed origins for any host a browser client calls cross-origin.
- **Change the seeded administrator credential immediately**, and confirm the previous one no longer authenticates.
- **Leave e-mail transport certificate validation enabled.** It is the secure default; do not opt out of it.
- **Review the Content-Security-Policy rollout before enforcing it**, working through the inline-script inventory in the secure configuration guide.

The [secure configuration guide](docs/security/secure-configuration.md) expands every item above, including the exact variable names and the reasoning behind each default.

## Licence

WebVella ERP is distributed under the terms in [LICENSE.txt](LICENSE.txt) — the Apache License 2.0.
