# blitzy-WebVella-ERP

WebVella ERP — .NET 10 / ASP.NET Core modular monolith on PostgreSQL, which has been through an
OWASP Top 10 (2021) security audit and remediation. The solution comprises nineteen projects: a shared
core library, a web framework, seven independently hosted site applications and six plugins.

> **Status authority.** This document is **not** the authority for the security posture's status.
> Exactly one surface is: the audit report's
> [Status at this revision, gate by gate](security/security-audit-report.md#status-at-this-revision-gate-by-gate) section. Where any statement here disagrees
> with it, that section governs and this one is superseded. Configuration requirements are owned by the [secure configuration guide](security/secure-configuration.md).
> Recorded under code-review findings `MAJ-06` and `MAJ-12`.

## Security

Of 53 findings — 5 Critical, 20 High, 17 Medium and 11 Low — every Critical and High has an
implemented fix, and every Medium and Low is documented with a recommended fix.

**That count is the original audit inventory, not the total number of defects found.** Later independent
reviews added their own inventories to the audit report, and the most recent — a review of the frontend and
API seam of the product — contributed sixteen further records, `SR-01` through `SR-16`, all closed, and the
**most recent of all is a checkpoint review of the remediation itself**, recorded as `CK-01` through `CK-23`
in Part 5: one Critical, three High, eight Medium, four Low and seven release or compliance blockers. Three
of the earlier seam review's four
Critical findings were invisible to every server-side control the audit established, because they lived in a
browser-delivered WebAssembly client, in a third-party package's JavaScript, and in a client-side `innerHTML`
sink that no Razor census can see. The report now carries **138 finding records across five parts**.

**The most recent review found a Critical in the remediation, and four findings about the gates themselves.**
`CK-01` is an authenticated remote-code-execution path at the page-component render route that the
remediation's own analyzer gate could not see; `CK-18` through `CK-20` are findings about the dependency
verdict, the verification matrix and the analyzer scope. A gate that cannot detect the defect it exists to
detect is a finding in its own right, and all four are closed.

**Remediation is not the same as full validation, so the two are reported separately.** Two of the
engagement's five validation gates do not pass at this revision. Static analysis is **PARTIAL**: the whole
Security category is armed by `AnalysisLevelSecurity=latest-all`, and the `CA3001`–`CA3012` taint family
runs for **all nineteen** projects: eighteen in the ordinary build, and `WebVella.Erp.Web` — which cannot
finish an unbounded scan — through a dedicated terminating scan under a cost bound whose reporting
capability is proved against deliberate taint flows in the same step, so **taint coverage is 19 of 19
compilations** and what remains is analysis depth for one project rather than its absence (code-review
finding `MAJ-01`). Manual verification is **executed in full**: the matrix carries 50 rows, and all **32**
manual rows — 31 mandatory plus the single advisory row — have been executed against disposable hosts and
live databases and hold committed, commit-bound attestations, so `deferred=0`. Executing the workflow's
**22** `run:` steps in order reports `deferred=0` and `RELEASE-READY=no`, and the release gate exits
non-zero. **That `no` is deliberate and its reason is exact:** row `A17` records that the engagement's
seven-header standard is **not** satisfied, because the mandated Content-Security-Policy is delivered under
its report-only name — which enforces nothing — and code-review finding `MAJ-03` refused the alternative of
rewriting the check to accept the substitute name. *(An earlier revision of this paragraph read
`rows=48 proven=48 failed=0` with `RELEASE-READY=yes`; that measurement rested on the rewritten check and
is superseded.)* The project is not shippable, and three separate things keep it that way: that unmet header
criterion, the open AutoMapper licence decision reserved to the repository owner which blocks `dotnet pack`,
and the disclosed scope deviation only the owner can resolve. A third gate is **vacuous by construction** —
the repository contains no test suite. One process requirement, *atomic commits per
vulnerability class*, **FAILED** historically and has been complied with for every commit since. The authoritative gate-by-gate table is
[Status at this revision](security/security-audit-report.md#status-at-this-revision-gate-by-gate).

- [Audit Report](security/security-audit-report.md) — the 53-finding audit inventory and every later review finding, **138 records** in five parts, each with severity, CWE, location, description, impact, evidence and remediation
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
