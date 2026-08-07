# Audit Report

Audit of the WebVella ERP platform against the OWASP Top 10 (2021). The platform is a .NET 10 /
ASP.NET Core modular monolith on PostgreSQL: nineteen projects, roughly seven hundred C# source files
and three hundred and ninety-five Razor views, with seven independently hosted site applications
sharing a common core library and web framework. The audit covered all ten OWASP categories, A01
through A10, and in addition dependency vulnerability scanning, secrets detection, security response
headers, TLS and transport configuration, input validation and output encoding, error handling and
information disclosure, rate limiting and denial-of-service protection, cross-origin resource sharing
policy, file upload security, and API security. It produced **fifty-three findings**. Within that
original inventory, every Critical and every High finding is remediated; every Medium and Low finding
is documented with a recommended fix.

**How to read that claim, because it has been wrong once and the correction is part of the record.** The
disposition above describes the *audit's own* fifty-three findings. The delivered controls have since been
re-reviewed against the tree several times, and each pass found further instances of classes this report had
already marked closed — recorded as `P-`, `F-`, `CR2-F-` and `B3-` identifiers in
[Part 2](#part-2-post-remediation-review-inventory) and
[Part 3](#part-3-product-vulnerabilities-first-discovered-by-reviewing-the-remediation) rather than folded
silently into the counts above. The most recent such pass raised eight findings, of which five were High. All
eight are closed: seven by code changes and the eighth by the corrections this sentence belongs to. So the
claim is accurate **as of this revision** and is not a guarantee that no further instance exists; where a
record here says "closed", the closing change and its verification are traceable in
[the remediation log](remediation-log.md), and every residual deliberately left open is named in
[the risk register](risk-register.md) with its disposition and owner.

**"Remediated" here means the fix is implemented and its own verification is recorded. It does not mean
every validation gate passed.** Two of the five engagement gates are *not* satisfied at this revision,
and one engagement process requirement **failed** outright. Read
[Status at this revision](#status-at-this-revision-gate-by-gate) before quoting any completion statement
from this report; it is the single authoritative status surface, and where any other sentence in this
document set disagrees with it, it is superseded.

## Result summary

| Severity | Count | Disposition | State |
| --- | --- | --- | --- |
| Critical | 5 | Immediate remediation required | All five remediated |
| High | 20 | Remediation required | All twenty remediated |
| Medium | 18 | Document with fix guidance | All eighteen documented. **Eight** are additionally remediated under one of the three exception limbs — `M-01`, `M-03`, `M-04`, `M-05`, `M-06`, `M-12`, `M-13`, `M-18` — and **two more, `M-09` and `M-10`, are partially changed** by later review-finding work while their own declines stand. An earlier revision of this row said "nine also remediated" without naming them; the canonical limb-by-limb mapping, including the two partial cases, is [in the risk register](risk-register.md#the-governing-disposition-rule-and-which-mediums-qualified) |
| Low | 10 | Document for a future sprint | All ten documented; three closed incidentally by work a higher-severity class required |
| **Total** | **53** | | |

Each of the fifty-three carries its own eight-field record in [Part 1](#part-1-the-audit-inventory),
under an identifier in the ranges `C-01`–`C-05`, `H-01`–`H-20`, `M-01`–`M-18` and `L-01`–`L-10`. The
governing rule for the Medium and Low bands is the severity matrix reproduced below: those bands are
*documented*, and are remediated only where one of the three tests named in the table above is met.
Which test each remediated Medium meets is stated in its own record, and the reasoning behind every
decision not to fix is in the [risk register](risk-register.md) rather than repeated here.

## Status at this revision — gate by gate

This is the **single authoritative status surface** for the engagement. Where any other sentence in this
document set, in `SECURITY.md`, in `docs/index.md` or in `LIBRARIES.md` disagrees with a row below, the
row governs and the other sentence is superseded. It exists because an earlier revision of this report
led with a completion statement and then described the gates individually, so a reader who stopped at the
summary would have taken "all Criticals and Highs remediated" as "everything passed". Those are different
claims and this section keeps them apart.

**Implemented is not the same as verified.** Every Critical and High finding does have an implemented fix
with its own recorded verification. Two of the five engagement gates nevertheless do **not** pass at this
revision, and one engagement process requirement failed outright.

| # | Gate, as the engagement specifies it | Status | What was actually done, and what is missing |
| --- | --- | --- | --- |
| 1 | SAST scan: 0 Critical, 0 High | **PARTIAL, and materially less partial than it was** | The named external scanner could not be installed. The substitute is the .NET analyzers with `AnalysisLevel=latest-recommended` **and `AnalysisLevelSecurity=latest-all`**, which arms the whole Security category. Under code-review finding `GATE-03` the `CA3001`–`CA3012` taint exclusion was narrowed from all nineteen projects to `WebVella.Erp.Web` alone: measured per project, eighteen build in 0 to 6 seconds each with **zero** `CA3001`–`CA3012` diagnostics, while that one project is killed at a 600-second bound. A probe carrying deliberate taint flows reports `CA3001` and `CA3003`, and the workflow's positive control now **requires** both, so the eighteen zeros are an absence of defects rather than an absence of analysis. Still PARTIAL because one project remains outside the family and `CA5351` reports **five** accepted residuals rather than zero. See the Gate 1 detail below and `RISK-051`. |
| 2 | Dependency scan: 0 Critical/High CVEs | **PASS** | Solution-wide restore with `NuGetAudit`/`NuGetAuditMode=all`/`NuGetAuditLevel=low` and `NU1900`–`NU1905` promoted to errors, plus per-project coverage for the two non-solution-member projects, corroborated by `dotnet list package --vulnerable --include-transitive`. Nothing suppressed anywhere. Contingent on the `H-19` casing repair, which had to land first. |
| 3 | Secrets scan: 0 hardcoded credentials | **PASS** | The named external scanner could not be installed. The substitute is a multi-layer signature sweep over the tracked tree plus a known-published-value layer that fingerprints candidates against digests of the five published values, with **no evidence-field exemption** and a positive control that must fire. |
| 4 | Existing test suite: 100% pass rate | **VACUOUS — no suite exists** | There is no test project, no test file and no test-framework reference in any of the nineteen projects; `dotnet test` discovers nothing. **No test suite was run and no reader should infer that one was.** Creating one is out of scope under the engagement's modification boundaries. Reported as vacuous rather than passed. |
| 5 | Manual verification of all Critical/High fixes | **DEFERRED — not complete, and now honestly counted** | The matrix declares **45** rows: 16 proven by an evidence artifact the workflow produces and 29 manual. Under code-review finding `GATE-02` four scenarios were added for the findings the matrix could not previously reach — `M26` for the page-component render route, `M27`, `M28` and `M29` for the restart, multi-instance, capacity and transport-downgrade boundaries of session revocation, login lockout and mail transport — and **all four were executed against running hosts and a live PostgreSQL database and are attested** in the tracked `manual-verification-results.txt`, commit-bound and dated. The remaining **25** manual rows are unexecuted and recorded `DEFERRED`; a separate blocking release gate refuses to pass while any mandatory row is unattested. A gate with unexecuted mandatory rows is not satisfied, and an earlier revision of this report marked Gate 5 *Satisfied*; that marking stays withdrawn. |

| Engagement process requirement | Status | Where the evidence is |
| --- | --- | --- |
| Minimal Change guideline 9 — **atomic commits per vulnerability class** | **FAIL historically, COMPLIED WITH since** | Seven of thirteen commits in the original remediation carry more than one vulnerability class; history was not rewritten. Every commit made while closing the code-review findings carries exactly one class — eighteen consecutive single-class commits at the time of writing — so the requirement is met going forward without the earlier failure being erased. The remediation log records the requirement as *NOT MET* and explains why history was not rewritten. Acknowledgement is not compliance, and no completion statement in this document set may cite the acknowledgement as though it were. See the [corrected accounting](remediation-log.md#guideline-9-was-not-met-the-corrected-accounting). |
| Prescribed execution sequence, stage by stage | **FAIL** | Four ordering and atomicity failures, `F-07` through `F-10`, named in [Methodology](#methodology) above. Final tree state is correct in all four cases. |
| Minimal Change guideline 10 — validate after each fix category | **PARTIAL** | Every class carries an executed `### Verification` section; the qualification is recorded in the log on the same row as guideline 9. |

### Gate 1 in detail — what executes, and what does not

**This subsection said "four families execute" and named eleven more as disabled. That is no longer true,
and the reversal is recorded rather than overwritten.** `AnalysisLevelSecurity=latest-all` arms the whole
Security category, and `GATE-03` narrowed the one remaining exclusion to a single project, so twelve
ratcheted families now execute and their counts are asserted against a recorded baseline on every run. The
figures below are re-measured at this revision from the workflow's own `Build with analyzers enabled and
ratchet the security diagnostic counts` step, which reports `no growth in any of the 55-diagnostic security
baseline (55 observed)`:

| Rule | What it detects | Count at this revision | Disposition |
| --- | --- | --- | --- |
| `CA2100` | Query construction from a non-constant string | **20** | Accepted residuals across 8 files, all in the data layer where the *values* are parameterised and only identifiers are composed — the `H-09` analysis. On the reviewed allow-list |
| `CA2326` | Unrestricted `TypeNameHandling` on a deserialiser | **20** | Accepted residuals across 6 files. Every in-scope site carries the `ErpSerializationBinder` type allow-list; the rule fires on the *presence* of `TypeNameHandling`, not on the absence of a binder. On the reviewed allow-list |
| `CA2327` | Insecure `SerializationBinder` | 0 | Must stay zero |
| `CA2328` | `TypeNameHandling` without a binder, dataflow-confirmed | **9** | Accepted residuals across 4 files, same reasoning as `CA2326`. On the reviewed allow-list |
| `CA5350` | Weak hashing algorithm | 0 | Must stay zero |
| `CA5351` | Broken hashing algorithm | **5** | Accepted residuals: **one** in `WebVella.Erp/Utilities/PasswordUtil.cs` on the legacy MD5 verification retained so existing credentials are not invalidated (`RISK-004`), and **four** in `WebVella.Erp/Utilities/CryptoUtility.cs` on content hashing and key derivation, which belong to the secret-management class rather than to any credential path (`RISK-004`, `RISK-006`). Neither promoted nor suppressed. |
| `CA5359` | Disabled certificate validation | 0 | Must stay zero |
| `CA5362` | Deserialisation cycle with potential for code execution | **1** | One accepted residual in `WebVella.Erp/Api/Models/QueryObject.cs`. On the reviewed allow-list |
| `CA5364` | Deprecated transport protocol | 0 | Must stay zero |
| `CA5390` | Hard-coded encryption key | 0 | Must stay zero — and this zero is **measured while armed**, which is the whole point of `C-04` |
| `CA5401` | Non-random initialisation vector | 0 | Must stay zero |
| `CA5404` | Disabled token-validation checks | 0 | Must stay zero — measured while armed, which is what makes the `H-02` fix checkable |

Those twelve baselines total **55** diagnostics, and the workflow fails the job on growth in any one of
them. The distinct `(rule, file)` pairs behind them number **21**, every one on a reviewed allow-list, with
the unreviewed set **empty** — both re-measured at this revision from `security-diagnostics.txt`,
`security-allowlist.txt` and `security-unreviewed.txt`.

**What is still not covered, stated exactly.** Two things, and neither is a family-wide absence any more:

- **`CA3001`–`CA3012`, the interprocedural taint-dataflow family, for `WebVella.Erp.Web` alone.** It is
  armed for the other eighteen projects, which complete in 0 to 6 seconds each with zero diagnostics, while
  that one project is killed at a 600-second bound. The exclusion is a **measured termination** decision,
  not a scope preference, and the workflow asserts it in both directions so it can neither be lost nor
  widened. Carried as `RISK-051` and `RISK-138`.
- **`CA5382`, `CA5383` and `CA5402` are armed but have never been observed to fire.** No probe in this
  environment has provoked any of them, so they are deliberately left **out** of the ratchet rather than
  baselined at zero — a zero from a rule nothing has proven can speak is not evidence. Carried as
  `RISK-137`.

Everything else that this subsection previously listed as disabled now executes and is baselined above.
The reasoning that once justified leaving them off — that a global analyzer configuration file and
per-rule cost tuning were both outside the frozen scope — was superseded when it turned out the SDK
honours `AnalysisLevelSecurity` directly, so no `.globalconfig` was needed and none exists in this
repository. The remaining cost measurement, and the exclusion it justifies, are recorded in
`Directory.Build.props` beside the properties themselves. The **positive control** is what makes the zeros
above evidence rather than assumption: a throwaway probe carrying deliberate defects makes `CA5350`,
`CA5359`, `CA5364`, `CA2100`, `CA2326`, `CA2327`, `CA5390`, `CA5401` and `CA5404` all fire, and — since
`GATE-03` — `CA3001` and `CA3003` as well, each assertion anchored to the probe's own file so a real
occurrence elsewhere in the repository cannot satisfy it.

### Freshly measured evidence for this revision

Every figure below was measured against the tree this commit publishes, not carried forward from an
earlier run. Each names the command that produces it, so a reader can re-derive rather than trust it.

| Measurement | Value at this revision | Command |
| --- | --- | --- |
| Solution restore | exit 0, zero `NU19xx` | `dotnet restore WebVella.ERP3.sln` |
| Solution build | exit 0, **0 errors**, **3,055** warnings | `dotnet build WebVella.ERP3.sln --no-restore -c Debug -m:2 -t:Rebuild` |
| Distinct analyzer diagnostics | **3,028** unique `(file, line, column, rule)` `CA` pairs, spanning **50** distinct rules and **641** distinct `(file, rule)` pairs. The raw log carries 6,108 `CA` warning lines because a multi-project build restates each one; de-duplication is therefore mandatory, and MSBuild's own summary total of 3,055 counts every category, not just `CA` | de-duplicate the build log's `CA` warning lines on the repo-relative path |
| Executing security families | `CA5350`=0, `CA5351`=5, `CA5359`=0, `CA5364`=0 | filter the same build log per rule |
| Families that used to be silent, now executing | **This row is the reverse of what it said at an earlier revision, and the reversal is the point.** `AnalysisLevelSecurity=latest-all` arms the whole Security category, so the families that reported 0 *because they did not run* now run and speak: `CA2100`=20, `CA2326`=20, `CA2328`=9, `CA5362`=1. Three still report 0 while armed — `CA5390`, `CA5401`, `CA5404` — which is a genuine zero rather than an absent rule, and three more armed rules have never been *observed* to speak at all, `CA5382`, `CA5383` and `CA5402`, so they are deliberately excluded from the per-rule ratchet (`RISK-137`) | same filter; compare against the arming properties in `Directory.Build.props` |
| Taint family `CA3001`–`CA3012` | **0** diagnostics in the solution build, and that zero is only partly evidence: the family is armed for **18 of 19** projects and excluded for `WebVella.Erp.Web` alone, on a measured termination bound (`RISK-051`, `RISK-138`) | same filter; the exclusion is asserted in both directions by the workflow |
| MD5 API uses in the tree | **6** grep hits — **5** live API uses, matching `CA5351` exactly, plus one inside a commented-out helper that predates this engagement (`WebVella.Erp.Web/Services/CodeEvalService.cs:L17`) | `grep -rn 'MD5\.\|MD5CryptoServiceProvider' --include='*.cs' .` |
| Solution members vs tracked projects | **17** of **19** | `dotnet sln WebVella.ERP3.sln list`; `git ls-files '*.csproj'` |
| Workflow shape | **23** steps — **3** `uses:` and **20** `run:`, publishing **21** evidence paths | load the YAML and count `steps` entries carrying each key; count the `path:` lines on the upload step |
| Gate 5 declared rows | **45** — `A01`–`A16` plus `M01`–`M29`; **28** of the 29 manual rows are REQUIRED and one, `M18`, is ADVISORY | `grep -n 'expected_rows=' .github/workflows/security-scan.yml` |
| Gate 3, executed locally against this tree | exit 0, **0** `FAIL` lines; **1,578** tracked files inspected with **0** credential-shaped locations and **0** tolerated; the known-value layer swept **1,521** files, fingerprinted **536** length-matched candidates and matched **0** — documentation included, with no evidence-field exemption; the detector first proved itself against credentials planted in **10** file formats, and the closing line reports **1,522** tracked text files. **These file counts move whenever a file is added or removed**, and did so twice within this engagement — when `.markdownlint.jsonc` was added and again when `manual-verification-results.txt` was committed — so re-derive them from the command rather than citing them | extract the *Sweep for hardcoded credentials* `run:` block and execute it under `bash -e` |
| Remediation log sections | **44** `## ` sections. This figure has now drifted four times — 24, then 39, then 40, now 44 — so read it as a measurement of one revision and re-derive it rather than citing it | `grep -c '^## ' docs/security/remediation-log.md` |
| Eight-field records in this report | **138** in total — **53** in Part 1, one per AAP finding, and **85** across Parts 2 through 5: 20 in Part 2, 26 in Part 3, 16 in Part 4 and 23 in Part 5. The workflow asserts a floor of 138 and that every identifier is distinct | `grep -c '^\| \*\*FINDING\*\*' docs/security/security-audit-report.md` |

**Counts elsewhere in this document set that disagree with this table are historical.** They were correct
against the revision that measured them and are retained, marked as superseded, because a security
document that silently rewrites its own measurements reproduces the defect it is trying to record. The
specific figures that have moved since they were first published are the workflow shape (from 12/3/9,
then 16/3/13, then 17/3/14, now **23/3/20**), the Gate 5 row total (from 32, then 33, then 41, to **45**),
the remediation log's section count (from 18, 19, 23, 24, 39 and 40 to **44**), the eight-field record
total (from 96 to **138**) and the build warning total (from 3,046, then 3,044, to **3,055**). One figure
did not merely move but **inverted**: the row that recorded seven security families as silent *because
they did not run* now records four of them reporting real diagnostics, because the arming property was
added after that measurement was taken.

**One thing this section cannot claim.** No *hosted* CI run has executed this workflow. Every gate result
above was produced by executing the workflow's own shell blocks locally against this tree. That is enough
to prove the commands work and are committed; it is not the same as a run recorded by the CI provider,
and the first hosted execution will be the one that produces provider-attested evidence.

## How to read this report

The report carries **three finding inventories**. They are complementary rather than alternative, and
all three are reproduced because they answer different questions.

| Part | Inventory | Question it answers |
| --- | --- | --- |
| [Part 1](#part-1-the-audit-inventory) | The fifty-three findings of the audit itself | *What is wrong with the platform?* |
| [Part 2](#part-2-post-remediation-review-inventory) | The review of the controls as delivered | *Does the remediation actually work on a live request path?* |
| [Part 3](#part-3-product-vulnerabilities-first-discovered-by-reviewing-the-remediation) | Product vulnerabilities the audit had not reached | *What did reviewing the fixes reveal about the product?* |

**Only Part 1 is the audit inventory, and only its identifiers count towards the fifty-three.** Parts
2 and 3 number their findings in their own namespaces: Part 1 uses the zero-padded two-digit form
(`H-08`), Part 2 the single-digit form (`H-8`), and Part 3 the `P-` prefix. **Every finding identifier
in this report is nevertheless unique, and that is asserted mechanically rather than trusted** — the
security workflow fails the build if any identifier heads two records (see
[validation gates](#validation-gates)). Two identifiers previously were not: Part 2's tenth and
eleventh high-severity records collided exactly with Part 1's `H-10` and `H-11`, and they now carry the
review-namespace prefix `HR-`, matching the `CR-` Part 2's critical record already used. The
[identifier index](#identifier-index) below records where each cited identifier resolves.

**One collision has been eliminated rather than merely explained.** This passage previously ended
"and `H-10` and `H-11` occur in both parts with entirely different subjects", which was true and was
still a defect: two records in one document sharing an identifier cannot be cited unambiguously, and a
reader following a citation had no way to know which record was meant. Part 2's two records are now
`HR-10` and `HR-11` — the `HR-` prefix marks the post-remediation review namespace for a High
finding, matching the `CR-` form Part 2's critical record already used — so every
one of the finding identifiers in this report is unique — **138 records, 138 distinct identifiers**, across
what are now **four** parts. Part 1 keeps `H-10` and `H-11` unchanged, because renaming an audit finding
would break every citation of it in the remediation log, the risk register and the source comments.

**Part 4 was added under the same discipline, deliberately.** The frontend and API seam review's own
identifiers were `C-01`–`C-04`, `M-01`–`M-09` and `L-01`, every one of which collides *exactly* with a
Part 1 record rather than merely resembling one. Adopting them would have reintroduced the condition this
passage exists to record, fourteen times over. They are carried in the previously unused `SR-` namespace
instead, and each record states the review identifier it maps from so a reader holding the review can
follow it without guessing.

Part 2 exists because a control that compiles is not a control that runs. Five helpers had been added
to the codebase — the hashing utility, the SQL identifier validator, the deserialisation binder, the
response-headers middleware and the login throttle — and at the point of review **none of them was
reachable from any live path**. Part 2 is severity-rated on the vulnerability that remained open, not
on the quality of the unused helper. All five are now wired, and the wiring is recorded in the
[remediation log](remediation-log.md).

The companion documents are the [remediation log](remediation-log.md), which records what changed and
the verification performed per vulnerability class; the [risk register](risk-register.md), which
records accepted risks, declined changes and standing recommendations; the
[secure configuration guide](secure-configuration.md), which is the operator guidance; and the
[credential migration guide](credential-migration.md), which covers the password-hash migration.

### How compromised historic values are written in this document set

Every secret this audit found had already been published in this repository, so each of them is
permanently compromised and **must be rotated**. That fact does not license this report to publish
them a second time. Earlier revisions of these documents quoted the observed literals in their
`EVIDENCE` fields — including one description from which the shipped token signing key could be
reconstructed in full — which contradicted both Validation Gate 3 and the no-secrets claim in
[`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md). Those
quotations are withdrawn and replaced, throughout this document set, by an **irreversible redaction**
of one fixed shape:

```text
[REDACTED — <n> characters, SHA-256 prefix <16 hexadecimal characters>]
```

The redaction keeps everything a reader legitimately needs and discards the only thing they do not:

- the **locator** stays, so the finding remains falsifiable at a named file and line;
- the **length** stays, because several findings turn on it — `H-04`'s weakness is entropy rather than
  length, and saying so requires the length to be visible;
- the **fingerprint** stays, so an operator can decide whether their own deployment still carries the
  published value by fingerprinting it — `printf '%s' "$VALUE" | sha256sum | cut -c1-16` — and comparing
  the result with the prefix recorded here, without this document, or their own notes, ever holding the
  value;
- the **value** goes.

The fingerprints are the same digests the platform screens against at start-up:
`WebVella.Erp/ErpSettings.cs` holds the full SHA-256 of the published token signing key and of the
published encryption key as constants and refuses either one outright, so a reader can corroborate a
redaction here against executable code rather than against prose.

**One literal is deliberately retained in source, and it is named here rather than left to be
discovered.** `WebVella.Erp/ERPService.cs:L2291` passes the historic seeded administrator password to
`PasswordUtil.VerifyMd5Hash` because the version-4 migration must *recognise* that credential in order
to invalidate it; a migration that cannot identify the value it exists to withdraw would silently skip
every affected installation. That one site is therefore a named, justified exception in the Gate 3
sweep, carrying an inline justification at the call. Documentation has no such need, so documentation
carries no such literal.

The redaction changes nothing about the exposure it describes. Every value below **remains in this
repository's git history** and must be treated as known to anyone who has ever read the repository.
Rotation is mandatory, not advisable; the procedure is in the
[secure configuration guide](secure-configuration.md).

## Methodology

The engagement followed the prescribed sequence:

```text
Discovery -> Scan -> Classify -> Prioritize -> Remediate -> Validate -> Document -> Deliver
```

**But it did not complete each stage before the next began, and an earlier revision of this sentence
claimed that it did. That claim is withdrawn.** A subsequent code review recorded **four** specific
ordering and atomicity failures in the executed history, and they are named here rather than left to be
discovered in a companion document:

| Finding | The failure |
| --- | --- |
| `F-07` | **Ordering.** The secret scrub was committed *before* operators had an external provider path, inverting the mandated provider-chain-first sequence. |
| `F-08` | **Atomicity.** The seed corrections and the schema version 4 migration were committed separately, when they must ship together or a new installation and an existing one diverge. |
| `F-09` | **Atomicity.** Five equivalent SMTP certificate-validation callbacks were remediated four-plus-one across commits rather than as one class. |
| `F-10` | **Atomicity.** Commits mix vulnerability classes, and the `AutoMapper` version pin was split from the constructor adaptation it requires. |

Each is a **process** failure whose final tree state is nevertheless correct, and that distinction is
the whole content of the four findings — collapsing it in either direction would misrepresent them. The
evidence for each, and the reason none was repaired by rewriting history, is in the
[remediation log](remediation-log.md#formal-acknowledgement-of-the-four-ordering-and-atomicity-failures).
The related engagement requirement — *atomic commits per vulnerability class* — is recorded as **FAIL**
in [Status at this revision](#status-at-this-revision-gate-by-gate).

Discovery itself was an exhaustive sweep of the tracked tree: every `.cs`, `.cshtml`, `.razor`, `.csproj`,
`.json`, `.config`, `.props`, `.targets`, `.yml`, `.md` and script file, plus the solution file. No
directory was excluded and no ignore file exists in the checkout. Automated scanning ran before manual
review wherever tooling permitted, and the substitutions made where it did not are disclosed in full
below. Classification used the engagement's own severity matrix rather than an external scoring
system, because that matrix is prescriptive: it names the vulnerability classes that belong in each
tier.

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

Because that matrix is prescriptive rather than advisory, it decides two classifications that a
generic scoring system would have decided differently, and both are worth stating plainly:

- **Unsalted password hashing is Critical, not Medium.** The matrix places *data breach exposure* in
  the Critical tier, and a password column stored as unsalted single-pass digests is recoverable
  wholesale. It is deliberately **not** filed under the Medium tier's *weak cryptography*, because the
  consequence is disclosure of every credential rather than a theoretical algorithm weakness. That is
  finding `C-03`.
- **Missing security response headers belong to the Low tier, not the Medium tier.** The matrix names
  *missing security headers* in the Low tier explicitly, where a generic scoring system would have
  rated the absence of a content-security policy as Medium. This report nonetheless files the header
  absence as `M-01` at Medium, and that record states why: the headers are the compensating control
  that bounds several other findings inside a browser, which is the condition under which the matrix
  itself calls for a Medium to be remediated rather than only documented. The tier the matrix assigns
  is stated here so that the departure is visible rather than silent.

The [vulnerability disclosure policy](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md)
reproduces the same matrix and the same two consequences, so a reported vulnerability and an audit
finding can be compared directly.

Categorisation against OWASP is recorded on every finding using the A01–A10 taxonomy. Every finding is
written up in exactly these eight fields, in this order:

```text
FINDING
SEVERITY
CWE
LOCATION
DESCRIPTION
IMPACT
EVIDENCE
REMEDIATION
```

`LOCATION` carries a verified path and a line locator. `EVIDENCE` carries the construct actually
observed — the code shape or configuration value read from the tree — rather than a paraphrase of it.
Every locator in Part 1 was read from the audit baseline, the last commit before any remediation
landed; every locator describing a delivered control was read from the tree at this commit.

One convention governs the `CWE` field, and it exists so that no identifier is presented as more
authoritative than it is. Where a weakness maps cleanly onto a published entry, that entry is named and
linked, and where two entries apply both are named. Where no entry applies, the field carries an em
dash rather than an invented number — `M-01`, `M-03` and `L-07` are the cases. Where the closest
published entry describes the weakness by analogy rather than exactly, the identifier is written with
an explicit `-adjacent` hedge, as at `H-19`, `M-16`, `L-03`, `L-05`, `L-08` and `L-10`; the hedge is
part of the claim and is not to be hardened into a bare identifier by a later editor. A small number of
records supply a mapping that the engagement's own inventory left blank — `M-10` is the clearest case,
where `[AllowAnonymous]` on a resource endpoint maps to CWE-306 by textbook definition. Those are the
report's own classification, offered because leaving the field empty would have been less useful than
naming the obvious entry, and they are never presented as having been handed over with the requirement.

### How each remediation traces to a fix implementation standard

The engagement supplies six fix implementation standards and treats them as binding acceptance
criteria rather than as advice. Every `REMEDIATION` field in Part 1 names the standard it answers to,
and this table is the index so that the coverage can be checked rather than taken on trust.

| Standard | Findings whose remediation it governs |
| --- | --- |
| **Injection Prevention** — parameterised queries, context-appropriate output encoding, allowlist validation | `H-06`, `H-07`, `H-08` (the upload type allow-list), `H-09`, `H-10`, `H-17`, `M-18` |
| **Authentication Hardening** — 12-character minimum, five-attempt lockout, secure session attributes, constant-time comparison | `C-01`, `C-03`, `H-02`, `H-03`, `H-15`, `H-16`, `M-03`, `M-04`, `M-05`, `M-13` |
| **Authorization Enforcement** — deny by default, validate on every request, object-level checks, log authorization failures | `C-02`, `C-05`, `H-08` (the ownership checks), `H-13`, `H-14`, `M-12` |
| **Cryptographic Standards** — TLS 1.2 or better, no embedded key material, work-factored password hashing, CSPRNG | `C-03`, `C-04`, `H-04`, `H-05`, `H-11`, `M-06` |
| **Dependency Updates** — patch known Critical and High advisories, pin versions, replace end-of-life components | `H-01`, `H-18`, `H-19`, `H-20`, `L-07` |
| **Security Headers** — the seven headers with their exact values | `M-01`, and `H-12` as its precondition |

Two boundaries on that table are stated rather than glossed. First, a standard describes the shape of a
remediation for a vulnerability class **confirmed present**; it is not a mandate to add a control where
no finding was confirmed. That is why multi-factor authentication (`M-14`), password expiry and history,
authenticated-encryption adoption and a health endpoint (`L-05`) are recorded as recommendations rather
than built. Second, the documented-only findings are not governed by a fix standard at all — their
governing rule is the severity matrix's own disposition, *document with fix guidance* for a Medium and
*document for a future sprint* for a Low. Each such record therefore carries a concrete recommended fix
in its `REMEDIATION` field and a cross-reference to the [risk register](risk-register.md), which is
where the reasoning for not fixing it is held.

## Tooling, research channel and substitutions

Three constraints shaped how this audit was evidenced. All three are disclosed rather than concealed,
because the reliability of the claims in this report rests on them.

**The `web_search` facility returns empty results in this environment.** Proceeding on unverified
recollection would have been indefensible for advisory data and package versions, so external
verification was performed instead by direct retrieval from authoritative sources: the **GitHub
Advisory REST API** for every advisory identifier, severity, CWE and first-patched version cited
anywhere in this report; the **NuGet flat-container API** for every upgrade target and every licence
and dependency-metadata claim; and direct documentation fetches for the framework guidance and the
password-storage guidance. Every dependency claim in this report rests on those retrievals.

**Direct retrieval of the OWASP Top 10 category pages returned nothing parseable.** This is immaterial
to the result but must not be papered over: the engagement requirements enumerate the A01–A10 taxonomy
in full, and **that enumeration is the authority used** for every categorisation in this report. No
claim here should be read as implying the category pages themselves were read.

**Three of the named external scanners could not be installed** in this environment — a static
analysis engine, a container and dependency scanner, and a secrets scanner. Their substitutes are named
per gate below, with the pass criterion each substitute actually enforces. No statement in this report
should be read as claiming that a scanner which was not installed was run.

The toolchain is the **.NET SDK 10.0.302**. It is now pinned in
[`global.json`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/global.json) as
`"version": "10.0.302"` with `"rollForward": "disable"` — an exact pin. An earlier revision used
`"latestPatch"`, on the reasoning that holding the feature band was enough because the audit-mode
default and the analyzer rule set are chosen by the band; that reasoning does not hold, because a patch
release can change an analyzer rule's default severity or the audit defaults within a band, and the
gate's verdict would then depend on whichever patch a machine happened to have. That is exactly the
non-reproducibility condition finding `L-07` records.

## Validation gates

The engagement specifies five gates:

```text
- SAST scan: 0 Critical, 0 High
- Dependency scan: 0 Critical/High CVEs
- Secrets scan: 0 hardcoded credentials
- Existing test suite: 100% pass rate
- Manual verification of all Critical/High fixes
```

Three of the five cannot be executed with the tooling they imply. What was done instead, and what each
substitute actually proves, is set out gate by gate.

**Gate 1 — static analysis.** The named external scanner is not installable. *Substitute:* the .NET
analyzers, enabled repository-wide by
[`Directory.Build.props`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/Directory.Build.props),
so that the security rule families relevant to the confirmed findings execute on every compilation —
hard-coded encryption key, disabled certificate validation, SQL and query construction, insecure
deserialisation, cross-site scripting and file canonicalisation, regular-expression injection, cookie
security, disabled token-validation checks, non-random initialisation vector, and weak or broken
hashing algorithms. *Pass criterion:* **absent-or-justified in those families across the remediated
files** — not zero repository-wide, and not silence either. Stated precisely, because an earlier revision
of this section claimed the criterion without the mechanism that could satisfy it, and because a bare
"zero" is unachievable here for reasons that are features of the remediation rather than gaps in it:
`CA2326` fires on the mere presence of non-`None` type-name handling **even where the remediation has
attached the allow-listing serialisation binder that is the sanctioned mitigation**, and `CA5351` fires on
the legacy digest verification path that exists precisely so already-stored credentials keep working.
Deleting either would undo the remediation.

So the gate enumerates instead of counting to zero. Measured on the tree this commit publishes: **55
Security-category diagnostics across 5 rules, reducing to 21 `(rule, file)` pairs**, every one of which
appears in Gate 1's allow-list with a written justification, and the job **fails on any pair that is not
on that list** and on any increase in any of the twelve ratcheted per-rule counts. Silence is never
accepted as proof: a positive control compiles a probe carrying deliberate violations and fails the job
unless all nine of the zero-or-newly-armed rules report against the probe's **own file**.

*How the families are armed.* `AnalysisLevelSecurity=latest-all` raises the Security category to every
rule the pinned SDK defines in it, through a configuration the **SDK ships** — so no `.globalconfig`
exists in this repository, and the workflow asserts both that none does and that the SDK's own
configuration is genuinely loaded into the compilation. Nine of the eleven families named above do not
execute at `latest-recommended`, so this property is what makes the criterion checkable at all.

*The one exclusion, and the two honest gaps.* `CA3001`-`CA3012`, the interprocedural taint family, are
excluded through `NoWarn` for a measured termination reason: armed and untuned the solution build produced
no further output for over thirty-five minutes with 3 of 17 projects finished, because `WebVella.Erp.Web`
compiles 395 Razor views into a single compilation; excluded, the same build completes in about 106
seconds. `CA5382`, `CA5383` and `CA5402` **are** armed but no probe in this environment has made them
fire, so they are deliberately left out of the ratchet rather than baselined at zero, because a zero from a
rule nothing has proven can speak is not evidence. Both gaps are carried in the
[risk register](risk-register.md).

Analyzer diagnostics deliberately remain **warnings**; only the dependency codes are promoted to errors.
Enabling the analyzers across roughly seven hundred source files surfaces a large pre-existing backlog —
the solution build reports **3,062** warnings at this commit, none escalated — and promoting that to errors
would demand precisely the mass refactor the engagement's modification boundaries forbid. That figure read
**3,093** before the frontend and API seam remediation and has only ever moved **downwards**; the accounting
is in the state-of-the-remediation table below.

**Gate 2 — dependency scan.** *Satisfied.* Solution-wide restore with auditing at all-dependency mode
and the dependency diagnostics promoted to build errors, corroborated by
`dotnet list package --vulnerable --include-transitive`. The gate mechanism is worth naming exactly:
`Directory.Build.props` sets `NuGetAudit=true`, `NuGetAuditMode=all` and `NuGetAuditLevel=low`, appends
`NU1900;NU1901;NU1902;NU1903;NU1904;NU1905` to `WarningsAsErrors`, and sets `EnableNETAnalyzers=true`
with `AnalysisLevel=latest-recommended` and `AnalysisLevelSecurity=latest-all`. `NU1901` through `NU1904` are the low, moderate, high and
critical advisory diagnostics; `NU1900` and `NU1905` are promoted alongside them so that an audit which
cannot be performed — an unreachable source, or a configured audit source serving no advisory data —
fails the build rather than passing quietly, which is the failure mode a gate must not have.

Two properties of that configuration are deliberate rather than inherited. `NuGetAuditMode=all` is set
**explicitly** because **MimeKit 4.14.0 is transitive through MailKit**, and `direct` mode would never
have reported `GHSA-g7hc-96xr-gvvx` at all. And the gate is expressed in **MSBuild rather than in a
repository-root editor configuration file** because each of the four existing `.editorconfig` files
declares `root = true`, so a root editor-config would not reach the subtrees they own, whereas
`Directory.Build.props` is inherited by every project through directory location.

*The decisive precondition:* the `H-19` casing repair had to land **before** any dependency-audit
verification. Until it did, the core project — the one owning the platform's only High-severity
advisory — silently dropped out of the restore graph and the audit **falsely reported clean**. Every
dependency claim in this report is contingent on that repair, which is why it is the first
vulnerability class in the remediation order.

*Result:* no vulnerable package in any of the nineteen tracked projects. That result takes **three**
commands rather than one, because two projects are not solution members:
`dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` covers the seventeen solution
members, and one per-project invocation covers each of `WebVella.Erp.WebAssembly/Server` and
`WebVella.Erp.WebAssembly/Shared`. The [residual coverage gap](#residual-coverage-gap) records why. Had
the licensing escalation on the object-mapping library gone to its documented fallback, the pass
criterion would have been redefined as **no unsuppressed** High or Critical, with the single suppression
accompanied by a recorded risk acceptance; it did not, so the criterion stands unqualified.

**Gate 3 — secrets scan.** The named external scanner is not installable. *Substitute:* a signature
sweep over the tracked tree for connection strings, signing keys, mail passwords, encryption keys and
the literal seeded password, asserting that all eight `Config.json` files carry empty secret values,
that `WebVella.Erp/Utilities/CryptoUtility.cs` no longer contains a default key constant, and that the
provisioning code no longer assigns a literal password.

*One layer was added after review finding `CR-01`, and it closes the gate's own blind spot.* Every
signature layer matches a **shape**, and none of them could see a compromised value reproduced as
ordinary prose — which is exactly what these documents were doing, quoting the observed literals in
their `EVIDENCE` rows on the argument that the mandated eight-field format requires the observed
construct to be quoted. That exemption is removed. A **known-published-value layer** now fingerprints
every length-matched candidate token in **every tracked text file — code, configuration, workflow and
documentation alike, with no evidence-field exemption** — against the SHA-256 digests of the five
published values, so a reproduction anywhere fails the build. The layer holds only digests, never
values, so the gate that polices published secrets cannot publish one; it carries a positive control
that plants a freshly generated 51-character value in a Markdown evidence-style line and requires the
matcher to find it, so a clean verdict is a measurement rather than a silence; and when it does fire it
reports a label and a path and never the matched text (`CR2-F-10`, CWE-532). Two of the five published
credentials are outside it by a recorded scope decision rather than by oversight — the seeded
administrator password and one database credential are 3- and 4-character lower-case dictionary words,
so a value match on them would fire on ordinary English and on the `erp@webvella.com` address this
document set must be able to print; they are covered by the source-assignment layer and by the targeted
absence assertions instead. *Measured at this commit:* 5 known digests, 1 518 files swept, 526
length-matched candidates fingerprinted, **0 matches**, and the negative direction proven by planting
the real 51-character key in a tracked document, which failed the gate and named the file without
echoing the value. *Plus the negative test that makes it
meaningful:* the application must **fail fast with an actionable message** when a required secret is
absent, which is what proves the silent fallback was genuinely removed rather than merely relocated.
The compiled-in token-signing default at `WebVella.Erp/ErpSettings.cs:L118` is inside this gate's
scope, not outside it — see `H-04`, which is the evidence that blanking the configuration files would
not have been sufficient on its own.

**Gate 4 — existing test suite: vacuous by construction, and stated as such.** There is **no test
project, no test file and no test-framework package reference in any of the nineteen projects**; the
only artefact whose name suggests testing is a JavaScript minifier folder, and `dotnet test` discovers
nothing. **No test suite was run, and no reader should infer that one was.** *Substitute:* solution-wide
restore plus an analyzer-enabled build, both required to succeed with zero errors, together with the
manual verification checklist recorded in the [remediation log](remediation-log.md). Creating a test
suite is explicitly out of scope — it is the feature work the engagement's modification boundaries
forbid — so the gate is reported as vacuous rather than silently dropped or silently claimed as passed.

**Gate 5 — manual verification of all Critical and High fixes.** *Partially satisfied, and the
unproven remainder is now release-blocking rather than recorded as complete.* An earlier revision of this
section read "*Satisfied*", which the evidence does not support and which a later review correctly
rejected: the checklist in the [remediation log](remediation-log.md) is a **procedure** per vulnerability
class, and a procedure is not an execution. Nineteen — now **twenty-nine** — of the scenarios need a live
PostgreSQL instance, a browser or an SMTP server, none of which the automated gate has. Four of the
twenty-nine have since been executed by hand and attested; twenty-five have not.

What the gate now does instead of claiming satisfaction:

- The verification matrix carries **45 rows: 16 proven by an evidence artifact the workflow itself
  produced, and 29 manual.** On the tree this commit publishes all 16 evidence-derived rows pass and none
  fails; of the 29 manual rows, 4 hold a committed, commit-bound attestation and read `PASS-MANUAL`.
- Every manual row is classified **REQUIRED** (28 of them — each verifies a Critical or High finding) or
  **ADVISORY** (1 — a latency measurement). An unproven REQUIRED row is reported on an ordinary run and is
  **fatal** on a version-tag push or a release-candidate dispatch, so a release cannot proceed while a
  Critical or High fix is unverified.
- A **RELEASE-READY** verdict is computed and printed on every run, so a green ordinary run can never be
  read as release readiness. At this commit it reads **no**, with all 24 required scenarios named.
- A manual row leaves DEFERRED only on a **bound** attestation: tied to a commit that is an ancestor of
  the commit under test, to a scenario revision that is the hash of the row's own text plus its procedure
  plus the shared prerequisites block, and to a named environment — in a file that must be committed.
  Rewriting a procedure therefore invalidates every earlier attestation for it automatically.
- Six of the procedures were **defective** and have been rewritten, each recording why it could not have
  passed: one asserted the absence of a field the remediation deliberately still emits with a redaction
  sentinel; one asked for a successful login immediately after lockout, which a working lockout must
  refuse; one required waiting out a 1,440-minute token lifetime; one asked for files to be downloaded
  that the upload allow-list refuses; and two omitted the boundary cases that are the whole point of the
  control. Six further scenarios were **added** for controls that had none: cookie expiry and attributes,
  the editor callback, SQL identifier validation, the deserialisation binder, the credential-lookup
  metacharacter and timing properties, and the file-mutation race.
- Every mutating procedure binds a **prerequisites block** — disposable host and database, backup before
  and comparison after, throwaway subjects only, a controlled SMTP server, environment-supplied secrets,
  and unconditional cleanup — because an attestation from a run that skipped those is not evidence.

The two highest-risk verifications in the engagement remain what they were, and remain unproven by the
automated gate for the same reason as the rest: that a legacy credential still authenticates and is
transparently rehashed (`M01`), and that a full-record round-trip update does not overwrite a stored hash
with the redaction sentinel (`M17`).

### The mandated response headers

The engagement specifies seven headers with exact values. All seven are emitted by
`WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` with these values, byte for byte:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

The value of the content-security policy is preserved exactly as specified. Only its **delivery mode**
is staged: it ships under `Content-Security-Policy-Report-Only` first, with the enforced value
configurable, because four components in the platform deliberately emit inline script or
author-supplied markup and enforcing the policy on first deployment would break them. That is the one
place in this engagement where a mandated control could not be enforced immediately without violating
the requirement that existing functionality be preserved, and it is recorded as an accepted risk with a
report-then-enforce path in the [risk register](risk-register.md) rather than resolved by weakening the
mandated value.

### Additional acceptance criteria

- All nineteen projects build, and the claim is evidenced by **three** commands rather than the two an
  earlier revision cited — which is the point a later review pressed, because the solution enumerates only
  **17** of the 19 tracked projects. `dotnet restore WebVella.ERP3.sln` exits 0 with no `NU19xx`
  diagnostic and `dotnet build WebVella.ERP3.sln` exits 0 with **0 errors** for those 17; the remaining two
  are `WebVella.Erp.WebAssembly/Server` and `/Shared`, which are not solution members and are covered by
  their own named restore, build and vulnerable-package steps in the workflow. A membership assertion runs
  first and fails the job if any tracked project is neither a solution member nor a declared non-member, so
  the 17 + 2 = 19 arithmetic cannot drift unobserved. Executed end to end at this commit: the workflow now
  declares **20** `run:` steps, of which **19** are the evidence-gathering gates — every one of those
  nineteen was extracted from the parsed YAML, executed in order against this tree, and exited 0. The
  twentieth is the `Release gate`, which exits **1** by design while 24 mandatory manual scenarios are
  unattested; it is reported separately rather than folded into the "all exited 0" claim.
- **The API contract changed in exactly four intentional ways, and no others.** An earlier revision of this
  bullet read *no controller route, verb or response envelope changed, with one deliberate exception: the
  removal of stack-trace text from two error bodies* — and that absolute form was **false**, because this very
  document set records a route being added. Review finding `SR-14` raised the contradiction; it is corrected
  here rather than overwritten, and the wording is now the same wording row 15 of the
  [remediation log](remediation-log.md) already carried, so the two artefacts state one thing. The four are:
  (1) **stack-trace text removed from two error bodies** — the `H-13` remediation, and the only one the
  engagement's boundaries pre-authorised; (2) **one route ADDED**, `POST api/v3/en_US/auth/jwt/token/logout`
  (`RevokeJwtToken`), authenticated, carrying no `[AllowAnonymous]`, returning the controller's standard
  `ResponseModel` envelope; (3) **the download response gains a `Content-Disposition: attachment` header** for
  every extension outside the inline set — the back half of the `H-08` chain, a header addition rather than a
  body or status change; (4) **`POST /fs/move/` returns the endpoint's own `FSResponse` refusal envelope**
  where a withheld or raced staged target previously escaped as an unhandled fault with a zero-length body —
  a repair of a broken response rather than a new shape. **A fifth was added by the frontend and API seam
  remediation, and it is a removal**: (5) **two Razor Page routes were retired**, `/ckeditor` (and its
  `/ckeditor/Index` form) and `/ckeditor/ImageFinder`, by deleting the four files that declared them — the
  `SR-04` remediation. Retiring a route is a contract change and is listed as one rather than treated as
  exempt because it is subtractive. Two things bound it: neither page could ever render, because both
  referenced roughly seventy assets absent from the repository, and both were referenced from **zero** other
  files. The live CKEditor 5 integration is **not** affected — it uses the MVC controller endpoints
  `/ckeditor/drop-upload-url` and `/ckeditor/image-upload-url`, which are untouched and still routed.
- The narrower claim that **is** absolute, stated with the precision it needs: **no route template, verb or
  authorization attribute was CHANGED or ADDED after the checkpoint baseline `80042d8c`** — the only movement
  is the two `@page` declarations **removed** by `SR-04` above. Re-verified at this commit by filtering the
  full diff, staged deletions included, for `[Route]`, `[AcceptVerbs]`, `[HttpGet]`, `[HttpPost]`,
  `[Authorize]`, `[AllowAnonymous]`, `MapControllerRoute`, `MapRazorPages`, `MapControllers`,
  `.RequireAuthorization`, `AuthorizeFolder`, `AllowAnonymousToPage`, `AddPolicy` and `@page`: the only
  matches are those two removed `@page` lines plus two lines of **comment prose** that mention `[Authorize]`
  and `[AllowAnonymous]` without changing either. **An earlier revision of this bullet omitted the removal
  and so was itself false** — the deletions are staged, so a diff of unstaged changes alone does not show
  them, which is exactly how this class of claim goes wrong.
- No schema definition statement was emitted at any point. The single migration in this work changes
  rows, not columns.
- The login-latency increase caused by the deliberate high-iteration key derivation is measured and
  recorded as an **accepted, pre-declared** trade-off confined to the authentication path, rather than
  treated as a regression discovered late. The measurement is in `C-03`.

## State of the remediation at this commit

Measured against the tree at this commit rather than asserted.

| Area | State |
| --- | --- |
| Solution restore and build | `dotnet restore WebVella.ERP3.sln` exit 0 with zero `NU19xx`; `dotnet build WebVella.ERP3.sln -c Debug` exit 0, **0 errors**, **3,062** analyzer warnings, none escalated. **Re-measured with `--no-incremental` at this commit**, which matters: an *incremental* solution build reports a single warning because nothing recompiles, so it cannot be used for regression comparison. The history of this figure, since every movement is accounted for rather than replaced: it read 3,096 while a repository-root `.globalconfig` armed additional rules; 3,094 after that file was removed and the final regression pass replaced two `throw new Exception` statements in `WebVella.Erp/Database/DbFileRepository.cs` with `FileNotFoundException`; **3,093** after the page-header encoding reconciliation, which is the figure the [remediation log](remediation-log.md) records for the tree this commit publishes; and **3,062** after the frontend and API seam remediation. **This row itself read 3,094 until that remediation, so it stood one revision stale against the remediation log's 3,093 — corrected here rather than overwritten, because a current-state figure drifting by one is the same class of defect as `SR-13`.** Every step of the movement is a **reduction**, and the two contributors are named: retiring four files under `SR-04`, and replacing five `throw new Exception` statements with typed exceptions under `SR-08`. **The warning-code multiset was diffed before and after that remediation and is identical in composition — 53 codes — so zero new warning codes were introduced.** The composition at this commit, which reconciles the total exactly: **3,035** `CA`, **21** `ASPDEPR`, **5** `CS` and **one codeless** warning (`libman.json does not exist`, emitted by the client-library restore target and carrying no diagnostic identifier) — 3,061 coded plus 1 codeless, which is why a code-only census of this build reports 3,061 rather than 3,062 |
| Dependency gate | **No vulnerable package in any of the nineteen tracked projects**, with the object-mapping library resolving at `15.1.3`. Reached by three commands, not one, because seventeen of the nineteen projects are solution members — see the [residual coverage gap](#residual-coverage-gap) |
| Build gate reach | All six gate properties evaluate on **19 of 19** projects from `Directory.Build.props`, which is inherited by directory location and therefore does not depend on solution membership. A seventh property and a repository-root `.globalconfig` were added by a later revision and both have since been removed, because the plan of record freezes the analyzer gate at those six; the workflow now asserts the absence of both on every run |
| Target frameworks | **19 of 19** projects on `net10.0`. No project remains on an end-of-life framework |
| Credential storage | PBKDF2-HMAC-SHA256, 600,000 iterations, a per-credential 16-byte CSPRNG salt, fixed-time verification, and legacy values upgraded on next authentication — wired on all four call sites |
| Cross-origin policy | `AllowAnyOrigin()` is applied at **no** host. This row previously read "two hosts", then "one host"; both hosts have since been narrowed to explicit origin allow-lists sourced from `Settings:Cors:AllowedOrigins`. A supplied list wins, an explicitly empty list denies every origin, and an absent key denies every origin outside Development |
| Shipped configuration | The eight `Config.json` files no longer carry a live connection string, encryption key, token signing key, storage connection string or mail password, and all eight set `"DevelopmentMode": "false"`; `WebVella.Erp.Site/web.config` sets `Production`; and the seeded administrator credential is no longer a literal |
| Seed and migration | Password bounds are 12 and 128. The two Guest CREATE grants and the Guest READ grant on the user entity are removed from the seed **and** revoked on already-provisioned installations by the version-4 migration. The Guest READ grant on the *role* entity is removed from the seed only — the version-5 migration that would have carried it to existing installations was withdrawn as outside the frozen scope, so it remains an open documented Medium in the [risk register](risk-register.md) |
| Frontend and API seam | **Sixteen further defects were found by a review of this seam and all sixteen are closed**, recorded as `SR-01` through `SR-16` in [Part 4](#part-4-the-frontend-and-api-seam-review). Four were Critical: a WebAssembly token-refresh route that could never resolve, a case-sensitive bearer-scheme comparison that answered correctly-authenticated API callers as anonymous, a cleartext API origin, and a retired editor shell referencing ~70 assets absent from the repository. Nine were Major, including a live stored-XSS chain into `innerHTML` in the Project plugin and an image pipeline that was **wholly non-functional on Linux** |
| Highest-severity open item | **None in the code — restated, because the earlier absolute form was measured too early.** This row previously read *None in the code* while sixteen defects, four of them Critical, were live in the frontend and API seam; review finding `SR-13` raised exactly that, and the correction is recorded rather than overwritten. The claim now holds against the tree at this commit, and the qualifier that makes it checkable is this: it is bounded by what has been reviewed, not by what exists. One **open owner decision** remains: the licence posture of the patched object-mapping library. The advisory is closed; what those patched versions are licensed under is not a question an automated remediation may settle. See `H-01` and the [risk register](risk-register.md) |

## Findings proven not applicable

Two areas were investigated thoroughly and found to carry no exposure. They are recorded so that no
speculative finding enters this report, and so that a later reader does not mistake their absence for an
oversight.

**A10:2021 — Server-Side Request Forgery does not apply.** Every `HttpClient` in the repository is
browser-side Blazor WebAssembly code. The single server-side construction of a URI from data is
prefix-guarded and resolved through the database rather than the network:
`WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs:L539` guards on
`src.StartsWith("/fs")`, `:L543` constructs `new Uri(src)` only to take its `AbsolutePath` at `:L544`
and strip the prefix at `:L548-L549`, and `:L551-L552` then resolve the value through
`DbFileRepository.Find(src)` with the bytes read at `:L556`. **No network call is ever made.** Recorded
as `L-09` so the investigation is evidenced rather than merely claimed.

**Filesystem path traversal on the file endpoints is bounded.** File storage is database-backed, route
segments cannot contain a path separator, and the path is lower-cased at
`WebVella.Erp.Web/Controllers/WebApiController.cs:L3274` before the repository lookup at `:L3276`.
Finding `H-08` is therefore scoped correctly to file type, size and authorization rather than to
filesystem escape, and its record says so.

## Eliminated false-positive classes

Four classes of apparent finding were investigated and eliminated. Each is named explicitly, because
reporting any of them would have put a false finding into this report — and in one case a false *High*.

**One — the fifteen XML-commented package references are not in the build graph.** All nineteen
manifests were parsed with XML comments stripped, so that a commented entry could never be mistaken for
a live reference. Fifteen `PackageReference` elements exist only inside comments:

| Owning manifest | Commented-out package references |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` (8) | `Microsoft.AspNetCore.Http.Abstractions` 2.2.0; `Microsoft.Extensions.Caching.Abstractions` 10.0.0; `Microsoft.Extensions.Caching.Memory` 10.0.0; `Microsoft.Extensions.Configuration.Json` 10.0.0; `Microsoft.Extensions.Hosting.Abstractions` 10.0.0; `Microsoft.Extensions.Logging` 10.0.0; `Microsoft.Extensions.Logging.Console` 10.0.0; `Microsoft.Extensions.Logging.Debug` 10.0.0 |
| `WebVella.Erp.Web/WebVella.Erp.Web.csproj` (4) | `Microsoft.AspNetCore.Mvc.ViewFeatures` 2.2.0; `Microsoft.AspNetCore.StaticFiles` 2.2.0; **`SixLabors.ImageSharp` 3.1.6** — which carries a genuine High out-of-bounds-write advisory that **does not apply to this build**; `SixLabors.ImageSharp.Drawing` 2.1.5 |
| `WebVella.Erp.Site/WebVella.Erp.Site.csproj` (3) | `Microsoft.AspNetCore.ResponseCompression` 2.2.0; `System.Linq` 4.3.0; `System.Threading` 4.3.0 |

An earlier pass had provisionally treated four end-of-life ASP.NET Core 2.2.0 entries, two 4.3.0 system
entries and the image-processing package as live High findings. All of them are commented out, so none
applies to this build, and reporting them would have placed false High findings in this report. The
hygiene observation that fifteen dead entries remain in the manifests is recorded at its true weight as
`L-02`.

**Two — roughly fifty-five raw-output occurrences render server-generated markup and are not sinks.**
The **original audit census** was exact and reproducible: **128** `Html.Raw(` occurrences across
**69** `.cshtml` files. Remediation removed confirmed text sinks, so the **current delivered tree**
contains **114 invocation sites across 62 views**. Within the original census,
`Html.Raw(action)` appeared **49** times and `Html.Raw(record["action"])` **6** times — **55**
server-generated-markup sites together. All seven builder sites that produce those values were
inspected, and every one interpolates only identifiers; for example
`WebVella.Erp.Plugins.SDK/Pages/data_source/list.cshtml.cs:L70` builds an anchor whose only
interpolations are a record identifier and an already-URL-encoded return URL. A search across all
builder sites for interpolation of a database text field returned **zero** matches. Encoding these would
risk breaking working screens for no security benefit, so they are excluded from remediation rather than
reported. One apparent contradiction is resolved honestly rather than left to look like an inconsistency:
`Html.Raw(` in `.cs` files is **0**; the single `.cs` occurrence referred to elsewhere is
`helper.Raw(input)` inside `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs:L11`, which is finding `M-18`.
In the SDK data-source listing specifically, `:L25` is the excluded `record["action"]` site, while
`:L39`, `:L43` and `:L47` already use auto-encoded plain expressions.

**Three — the permissive cross-origin policy affected two hosts, not seven.** `WebVella.Erp.Site.Crm`,
`.Mail`, `.MicrosoftCDM`, `.Next` and `.Sdk` already used a restrictive named policy and were never
permissive. Framing `H-14` as a platform-wide condition would have overstated it by five hosts.

**Four — server-side request forgery is proven not applicable**, on the evidence set out above.

## The complete anonymous attack surface

Enumerated so that no unauthenticated entry point is overlooked. **Regenerated from the route inventory
at this commit**, because an earlier revision of this section carried pre-remediation line locators, omitted
one environment-conditional endpoint, and over-counted the commented-out exemptions.

Class-level authorization is confirmed present at
`WebVella.Erp.Web/Controllers/WebApiController.cs:L36` and
`WebVella.Erp.Web/Controllers/ApiControllerBase.cs:L9`, both `[Authorize]`, so only explicit exemptions
are reachable without credentials. **Fourteen live exemption declarations** produce **six** distinct
anonymous route shapes in Production, and **eight** on the SDK host when it runs in Development:

- the login-page conventions across all seven hosts — legitimate;
- the error page — legitimate;
- the developer page, finding `M-09`;
- the project plugin's resource read, finding `M-10`;
- the stylesheet endpoint at `WebApiController.cs:L1038`;
- the bearer-token **issue** endpoint at `:L4273` and the token **refresh** endpoint at `:L4292`. The
  refresh endpoint is what made `H-02` exploitable, and both are where `H-13`'s unconditional stack
  traces were returned to an unauthenticated caller.

The two token routes deserve their explicit qualification, because "only two hosts expose bearer-token
routes" is the wrong shape of statement: they are declared in `WebVella.Erp.Web`, so **all seven hosts map
them**, and what only two hosts do is *enable the bearer scheme* — the other five answer the route without
being able to authenticate a token against it.

**Ten** `[AllowAnonymous]` attributes exist only inside commented-out code and are therefore unreachable:
eight in `WebApiController.cs` (`:L894`, `:L951`, `:L1005`, `:L1081`, `:L1124`, `:L1180`, `:L1354`,
`:L1467`) and two in `WebVella.Erp.Plugins.SDK/Controllers/AdminController.cs` (`:L38`, `:L434`). They are
recorded under `L-01` rather than treated as live surface. **An earlier revision of this section said
twelve**, which was the plan's estimate rather than a count of the tree; the figure here is measured, and
the correction is stated rather than quietly applied.

## Escalations, corrections and drift

### Two escalations corrected upward rather than softened

- **The two error paths at `WebApiController.cs:L4287` and `:L4306` were ungated by any development-mode
  check.** Flipping the environment marker would not have fixed them; the code had to change. An audit
  that had filed these as configuration findings would have been wrong. See `H-13`.
- **The download path at `:L3323` served uploaded content inline from the application's own origin.**
  That turns an upload weakness into a stored-scripting one, which is a higher-severity condition than
  either half suggests on its own, and it is why the remediation for `H-08` had to close the download
  side and not only the upload side.

### A correction to the platform's own specification

The platform's developer documentation states that field permissions are resolved per field during read
and write projection. **The code disproves it.** Enforcement exists only in the presentation layer, at
`WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L605-L610`, where `canRead` starts `false` and is
set true only if the role appears in `entityField.Permissions.CanRead` — so an empty read-permission list
means denial at render time and nothing whatever at the data layer. There is no per-field resolution in
the data layer at all. The correction is recorded here, in the audit report, rather than by editing the
developer documentation, because rewriting unrelated pages is outside the change boundary this engagement
sets; the drift itself is finding `L-08`.

### Why the broader field-permission fix was declined

Enforcing field permissions across all twenty-three field types and every projection would ripple through
the entire read path, and because the presentation base treats an empty read permission as denial, a
blanket port would hide fields wholesale on existing installations. `C-02` was therefore fixed surgically:
administrator-only permissions assigned to the password field, plus redaction of encrypted-flagged values
from read projections, which closes the Critical without touching the general mechanism. The residual
general gap is documented in the [risk register](risk-register.md).

### Documentation drift deferred into this report

Four drift items were identified by other work in this engagement, declined there as outside the change
boundary, and routed here. All four are part of finding `L-08`.

1. **`README.md:L12`** carries an `MIT` licence badge — the shields.io image path itself reads
   `img.shields.io/badge/MIT-green` — while `LICENSE.txt` is the Apache License 2.0 and every packable
   project declares `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`. That expression
   was verified at `WebVella.Erp/WebVella.Erp.csproj:L14` at the audit baseline and stands at `:L32` at
   this commit, the manifest having grown above it during remediation; the other three are unmoved at
   `WebVella.Erp.Web/…:L13`, `WebVella.Erp.Plugins.Mail/…:L10` and `WebVella.Erp.Plugins.SDK/…:L10`.
   Real drift; documented, not fixed.
2. **`README.md:L18`** states that the platform "targets ASP.NET Core 9" with "PostgreSQL 16", while the
   manifests showed 17 × `net10.0` and 2 × `net7.0` at the audit baseline and 19 × `net10.0` now.
   Documented, not fixed.
3. **`catalog-info.yaml`** — **now fixed; this item is closed.** At the audit baseline its `description`
   read "WebVella ERP monolith decomposition — cloud-native microservices, serverless architecture, and
   OWASP security audit", describing work this repository does not contain. Three separate revisions of
   this report handled it three different ways, and the sequence is recorded because two of them were
   wrong: one recorded it and `docs/index.md` as corrected while both were still stale; the next stated,
   correctly at the time, that both were still present; and the next **retained** the
   `PR #2: Serverless Microservices Rewrite` link on the reasoning that "a link to a pull request records
   history rather than asserting anything about the current tree". That last reasoning is withdrawn — the
   link's *title* is a claim about the component, it sits in a `links` list a catalogue reader treats as
   current, and there is no PR #2 in this repository for it to record. Measured at this commit:
   `catalog-info.yaml` describes a .NET 10 / ASP.NET Core modular monolith on PostgreSQL with a completed
   OWASP Top 10 (2021) audit and remediation; the serverless pull-request link is gone; the
   `Blitzy Documentation` link that pointed at `…/tree/master/blitzy/documentation` — a directory that is
   not tracked, verified by enumerating the tree — is gone; and three links whose targets were each
   verified to exist are added: the audit report, `SECURITY.md` and the `docs` tree. `docs/index.md:L3`
   was corrected by earlier work and reads the modular-monolith sentence at this commit, so the claim
   that "the identical sentence is still present" there is also withdrawn.
4. **The developer documentation set** carries historical claims — ".NET Core 2.1", "Visual Studio
   Community 2017", "ASP.NET Core 9, PostgreSQL 16, Bootstrap CSS 4". Documented, not fixed: those pages
   are untouched by this engagement.

Also under `L-08`:
[`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) was a
zero-byte file despite being linked from `README.md:L35` as the third-party inventory, and is populated in
this change set; `WebVella.Erp/WebVella.Erp.csproj:L19` declares a `<RepositoryUrl>` pointing at the
upstream repository rather than this fork; `WebVella.Erp.Site/JWT_README.txt:L3` cites the bearer
authentication package at `6.0.3` where the actual reference is `10.0.1`; and that same inventory
document states a finding count for this report that was accurate when it was written and is now
understated, because this report has since completed the eight-field records for the nine identifiers
that had previously been cross-referenced to companion documents instead. The count that governs is the
one in the [result summary](#result-summary) above: fifty-three.

Whole-file line totals are deliberately **not** cited for `README.md` or `catalog-info.yaml`; two
independent counts differ by one because of a trailing-newline artefact, so only the specific line
locators above — each verified directly — are given.

## Identifier index

Where each finding identifier cited from source, project, build or workflow files resolves. The census
below was taken from the tree at this commit rather than from the plan, and it is stated as measured.

**Thirty-one distinct Part 1 identifiers are cited in tracked non-documentation files**, most of them in
`THREAT ADDRESSED` comments at the point of fix, which is what makes a record in Part 1 mandatory for
each of them rather than a cross-reference to a companion document. The most heavily cited are `C-02`
(46 citations), `C-01` (39), `H-04` (40), `H-06` (38), `C-04` (36), `H-19` (31), `H-05` (25), `H-10` (22),
`M-13` (22), `C-05` (20) and `H-08` (20). Selected resolutions:

| Identifier | Cited from | Subject |
| --- | --- | --- |
| `C-01` | `ERPService.cs`, `PasswordUtil.cs`, `AuthService.cs`, `login.cshtml.cs`, `ErpUserPreferences.cs`, `security-scan.yml` | Hardcoded default administrator password in provisioning |
| `C-02` | `RecordManager.cs`, `SecurityManager.cs`, `DbRecordRepository.cs`, `SdkPlugin.20201221.cs`, `ProjectPlugin.20211012.cs` | Credential hash readable by non-administrator roles |
| `C-03` | `PasswordUtil.cs`, `SecurityManager.cs`, `RecordManager.cs`, `DbRecordRepository.cs` | Unsalted single-pass MD5 credential storage |
| `C-04` | `CryptoUtility.cs`, `ErpSettings.cs` | Hardcoded encryption key with a silent fallback |
| `C-05` | `ERPService.cs`, `SdkPlugin.20201221.cs`, `ProjectPlugin.20211012.cs` | Guest role granted create permission on user and role entities |
| `H-04` | `ErpSettings.cs`, `WebVella.Erp.Site/Startup.cs`, `WebVella.Erp.Site.Project/Startup.cs` | Weak default token signing key |
| `H-05` | `ErpSettings.cs` | Plaintext database credentials in shipped configuration |
| `H-08` | `WebApiController.cs`, at eighteen sites across the upload, download, move and delete paths | Unrestricted file upload chaining into inline execution |
| `H-09` | `DbIdentifier.cs`, `DbEntityRepository.cs`, `DbRecordRepository.cs`, `DbRelationRepository.cs`, `DbRepository.cs`, `EqlBuilder.Sql.cs`, `CodeGenService.cs`, `security-scan.yml` | SQL identifier injection through string concatenation |
| `H-10` | `ErpSerializationBinder.cs`, `DbEntityRepository.cs`, `DbRelationRepository.cs`, `JobProfile.cs`, `JobDataService.cs`, `NotificationContext.cs`, `CodeGenService.cs` | Unsafe polymorphic deserialisation |
| `H-12` | `web.config` and the `Config.json` files | Development mode enabled in every shipped configuration |
| `H-15` | the seven host `Startup.cs` files | No HTTPS enforcement, no HSTS, insecure cookie attributes |
| `H-16` | `LoginThrottleService.cs`, `login.cshtml.cs`, `WebApiController.cs`, `ErpMvcExtensions.cs` | No account lockout on repeated failed logins |
| `H-18` | `security-scan.yml` | Two projects targeted an end-of-life framework |
| `H-19` | `WebVella.ERP3.sln`, all fifteen affected manifests, `security-scan.yml` | Case-mismatched project references broke the dependency scan |
| `M-01` | the seven host `Startup.cs` files, `ErpMvcExtensions.cs:L98`, `SecurityHeadersMiddleware.cs:L15` and `:L89` | No security response headers |
| `M-04` | `AuthService.cs` | Local time used for token timestamps |
| `M-13` | `PasswordUtil.cs`, `SecurityManager.cs`, `RecordManager.cs`, `DbRecordRepository.cs`, `ERPService.cs` | Password length bounds of 6 to 24 characters |
| `L-01` | `login.cshtml.cs:L279` | Dead security code, left in place deliberately |
| `L-07` | `global.json` | No lock file and an unpinned SDK version |

### Cited identifiers that resolve to Part 2

Only two Part 2 identifiers are cited from source at this commit:

| Identifier as cited | Part 2 record | Cited from | Subject |
| --- | --- | --- | --- |
| `H-1` | `H-1` | `page/manage-custom.cshtml.cs:L101`, `page/manage.cshtml.cs:L149`, `BaseErpPageModel.cs:L81` | Open redirect and script-scheme injection through the return-URL parameter |
| `M-5` | `M-5` | *(citing files retired — see note)* | Output helper performed replacement, not encoding |

**One citation in the table above no longer resolves, and is left visible rather than deleted.** `M-5` was
cited from `WebVella.Erp.Web/Pages/ckeditor/Index.cshtml`, `ImageFinder.cshtml` and
`ImageFinder.cshtml.cs:L191`. All four files of that legacy editor shell were **retired** under review
finding `SR-04`, so those citations point at paths that are no longer in the tree. The finding itself is
unaffected: `M-5` is about the output helper in `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs`, which is
still present and still remediated. The stale locators are recorded here so a reader who greps for them and
finds nothing knows why, instead of concluding the finding was fabricated.

### The collision hazard, closed rather than restated

An earlier revision of this index recorded three zero-padded aliases — source comments writing `H-08`,
`M-01` and `L-01` while meaning Part 2's `H-8`, `M-1` and `L-1`. **Re-verified at this commit, those
aliases no longer exist.** `H-08` is cited only in `WebApiController.cs`, where it means the Part 1 upload
finding; `M-01` is cited in the host pipelines and the headers middleware, where it means the Part 1
header finding, and the deserialisation binder cites `H-10` throughout rather than any `M-0` identifier;
and `L-01` is cited once, at `login.cshtml.cs:L279`, where it means the Part 1 dead-code finding. The
correction is recorded rather than the stale table left standing.

**The remaining hazard is now closed, not merely documented.** Two Part 2 records shared an identifier
exactly with a Part 1 record: Part 2's tenth high-severity finding (two projects outside the solution)
collided with Part 1's `H-10` (unsafe polymorphic deserialisation), and Part 2's eleventh (the
object-mapping licence conflict) collided with Part 1's `H-11` (the SMTP certificate bypass). An earlier
revision of this section argued the collision away as a reading instruction — *resolve an identifier
through this index, not through its shape* — which put the burden on every reader of every citation in
five documents. **The two Part 2 records are renamed instead**, to `HR-10` and `HR-11`, carrying the
review-namespace prefix that Part 2's critical record already used as `CR-1` and that Part 3 already
used as `P-`. Only those two records were renamed, because they were the only exact duplicates: Part 2's
`H-1` through `H-9`, `M-1` through `M-7` and `L-1` are the single-digit form and cannot collide with Part
1's zero-padded `H-01`…`H-20`, `M-01`…`M-18` and `L-01`…`L-10`.

**Measured after the rename: 96 finding records, 96 distinct identifiers.** That figure is the measurement
*at the rename*, and it has since moved for a stated reason rather than drifted: [Part 4](#part-4-the-frontend-and-api-seam-review)
added sixteen records in the previously unused `SR-` namespace, so the tree now measures **115 finding
records and 115 distinct identifiers**, and the workflow's `expected_minimum_records` was raised from 96 to
115 in the same change the records were added — which is what that step's own instruction requires. The
`SR-` prefix was chosen precisely to avoid the hazard this section exists to close: the seam review's own
identifiers were `C-01`–`C-04`, `M-01`–`M-09` and `L-01`, every one of which collides exactly with a Part 1
record. Neither identifier was
cited from any source, project, build or workflow file — only Part 2's `H-1` and `M-5` are, and both are
untouched — so the rename is confined to this documentation set. Every cross-reference in the
[remediation log](remediation-log.md) and the [risk register](risk-register.md) was updated in the same
change. The property is asserted on every workflow run rather than left to review: the *Assert every
audit-report finding identifier is unique* step re-derives the identifier list from this file's own
headings and fails the job on any duplicate, so a future record cannot silently reintroduce one.

## Part 1: The audit inventory

All fifty-three findings against the platform as found, grouped by severity band and recorded in
the mandated eight-field format. Within a band the records are in identifier order.

### Critical severity findings

#### C-01 — Hardcoded default administrator password in provisioning

| Field | Value |
| --- | --- |
| **FINDING** | System provisioning created the platform's first administrator account with a hardcoded three-character password compiled into the source. |
| **SEVERITY** | Critical. The severity matrix places *authentication bypass* and *privilege escalation to admin* in the Critical tier, and this is both at once: the credential of the highest-privileged account in every default installation is public knowledge, so no bypass technique is even required. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) and [CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html). |
| **LOCATION** | `WebVella.Erp/ERPService.cs:L467`, inside the first-user seed block spanning `:L462-L475`. |
| **DESCRIPTION** | The provisioning routine that runs once against an empty database created a user with `SystemIds.FirstUserId`, the administrator role, and a literal password of `[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]`. Nothing prompted for a value, nothing generated one, and nothing marked the account as requiring a credential change. The matching e-mail address is published in the platform's own setup instructions, so both halves of the credential were public. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | Any installation provisioned from this source could be signed into as administrator by anyone who had read the repository. Administrator access in this platform is not merely elevated data access: it carries entity and field definition, permission assignment, and — through the page-component code hooks and the runtime script evaluator — server-side code execution. The finding therefore reaches remote code execution by way of a published password. |
| **EVIDENCE** | At the audit baseline the seed block read `user["id"] = SystemIds.FirstUserId;` at `:L464`, first and last name at `:L465-L466`, then **a literal string assignment to `user["password"]` at `:L467`** — the value being `[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]`, a lower-case dictionary word — `user["email"] = "erp@webvella.com"` at `:L468`, `user["username"] = "administrator"` at `:L469`, a fixed `created_on` of 2010-10-10 at `:L470`, `user["enabled"] = true` at `:L471`, and `recMan.CreateRecord("user", user)` at `:L473`. The e-mail address is **not** redacted: it is the account's identifier rather than its credential, it is the value an operator must type to sign in, and it remains the shipped address today. The password literal is redacted per [the redaction convention](#how-compromised-historic-values-are-written-in-this-document-set); the one place it is still retained in source, and why, is named there. |
| **REMEDIATION** | Traces to the **Authentication Hardening** standard. The literal is gone. `ERPService.ResolveInitialAdministratorPassword` (`:L1263`) takes an operator-supplied value from `Settings:InitialAdministratorPassword` — the environment variable `Settings__InitialAdministratorPassword` — and validates it against the password policy; where no value is supplied it **throws**, so provisioning is refused inside its own transaction and nothing is persisted. It never generates a value: an interim revision of this remediation did generate a 20-character password and surface it once on standard error, and that emission was removed as a disclosure defect of the fix itself (CWE-532, OWASP A09:2021) because those streams are captured and retained wholesale by every hosting substrate, making a notice described as one-time durable plaintext. The one CSPRNG generator still compiled in serves the local `system@webvella.com` background identity, whose value is hashed on write and never printed, stored in plaintext or returned. The account is flagged `password_change_required` through `ErpUserPreferences.PasswordChangeRequired`, which the login page enforces at `WebVella.Erp.Web/Pages/login.cshtml.cs:L234` and the bearer path refuses at `WebVella.Erp.Web/Services/AuthService.cs:L543`. Seed correction alone would have protected only new installations, so `RevokeSeedAdministratorCredential4` (`:L2245`), inside the version-4 migration gated at `:L1061`, invalidates the shipped credential on already-provisioned deployments. Operator steps are in the [credential migration guide](credential-migration.md). |

#### C-02 — Credential hash readable by Guest and Regular roles; password-field permissions never assigned

| Field | Value |
| --- | --- |
| **FINDING** | The user entity granted record-read to the Guest and Regular roles while the password field carried no field permissions at all, so the stored credential hash was readable by unauthenticated and ordinary callers through any route that projected the user record. |
| **SEVERITY** | Critical. *Data breach exposure* is a Critical-tier condition in the severity matrix, and the data exposed is the credential column itself. Combined with `C-03` — the digest being an unsalted single MD5 pass — reading the column was equivalent to reading the passwords. |
| **CWE** | [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html). |
| **LOCATION** | `WebVella.Erp/ERPService.cs:L79-L81` for the record grants and `:L204-L218` for the password field definition. The only enforcement anywhere was presentational, at `WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L605-L610`. |
| **DESCRIPTION** | The user-entity permission block at `:L72-L83` granted `CanRead` to three roles including Guest, while restricting `CanUpdate` and `CanDelete` to Administrator — so the sensitive operations were protected and the read was not. The password field was defined with `Encrypted = true` but **no permissions assignment whatsoever**, and an unassigned permission list is empty rather than restrictive. Because the platform resolves field permissions only in the presentation layer, an empty list denied the field at render time and constrained nothing at the data layer, which is where the query-language and API routes read. Maps to **OWASP A01:2021 — Broken Access Control** and **A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Any caller able to read a user record obtained every stored password hash. With Guest holding the read grant, that included unauthenticated callers on any anonymous route reaching a user projection. The hashes were unsalted MD5, so exfiltration was equivalent to credential recovery: weak and moderate passwords fall to precomputed tables immediately, and identical passwords produce identical digests, turning the column into a password-reuse map across accounts. |
| **EVIDENCE** | At the audit baseline `:L77` added the Guest role to `CanCreate`, `:L79` added Guest to `CanRead`, `:L80` Regular and `:L81` Administrator, while `:L82` and `:L83` were Administrator-only. The `InputPasswordField` block at `:L202-L222` — `new InputPasswordField()` at `:L204`, the field identifier at `:L205`, `Name = "password"` at `:L206`, `Required = true` at `:L211`, `Unique = false` at `:L212`, `Searchable = false` at `:L213`, `Auditable = false` at `:L214`, `System = true` at `:L215`, `MinLength = 6` at `:L216`, `MaxLength = 24` at `:L217`, `Encrypted = true` at `:L218` and `CreateField` at `:L220` — contains no permissions assignment, confirmed by reading the block in full. The presentation base reads `var canRead = false;` at `PcFieldBase.cs:L605` and sets it true only `if (entityField.Permissions.CanRead.Any(x => x == role.Id))` at `:L610`. |
| **REMEDIATION** | Traces to the **Authorization Enforcement** standard, applied surgically rather than by porting field permissions into every projection. Two moves. The password field is now assigned administrator-only permissions in the seed — `password.Permissions.CanRead` and `.CanUpdate` each receiving only `SystemIds.AdministratorRoleId`, at `ERPService.cs:L329-L335` — and the Guest read grant on the user entity is removed. Second, and independently of role, the value of any field carrying the encrypted flag is **redacted from read projections**: `RecordManager.EncryptedFieldRedactedValue` (`:L42`) is substituted for the stored value at `:L2283`, so a hash does not leave the server through the record or query path at all. The write path recognises the sentinel and leaves the stored hash untouched (`:L904`, `:L1630`, `:L2432`, `:L2607`), which is what prevents a client that round-trips a full user record from overwriting a credential with the marker — the highest-risk ripple in this engagement, and one that carries its own line on the manual verification checklist. Credential resolution opts back in explicitly and only from inside the core assembly, because without that opt-in every login would fail. `MigrateSecurityDefaults4` carries the permission corrections to already-provisioned installations. Why the general mechanism was left alone is recorded under [escalations, corrections and drift](#why-the-broader-field-permission-fix-was-declined) and in the [risk register](risk-register.md). |

#### C-03 — Passwords stored as an unsalted, single-pass MD5 digest

| Field | Value |
| --- | --- |
| **FINDING** | Account passwords were stored as an unsalted, single-pass MD5 digest, produced by a shared mutable hash instance, and the stored digest was compared for equality inside a SQL predicate. |
| **SEVERITY** | Critical. The engagement severity matrix places *data breach exposure* in the Critical tier, which is where this belongs: a leaked password column is recoverable wholesale. It is deliberately **not** filed under the Medium tier's "weak cryptography", because the consequence is disclosure of every credential rather than a theoretical algorithm weakness. |
| **CWE** | [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) and [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html). The comparison weakness and the shared-instance race are recorded separately as `M-05` and `M-06` below, because they are distinct weaknesses that happen to live in the same file. |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs` — the primitive. Consumed at `WebVella.Erp/Api/SecurityManager.cs:L84` (credential resolution), `WebVella.Erp/Api/RecordManager.cs:L2017` and `WebVella.Erp/Database/DbRecordRepository.cs:L554` and `:L1856` (the password write paths). |
| **DESCRIPTION** | `GetMd5Hash` computed a single MD5 pass over the UTF-8 bytes of the password and rendered it as 32 lower-case hexadecimal characters, with no salt, no iteration count and no per-credential parameterisation. There was no verification member: `SecurityManager` recomputed the digest and compared it to the stored column **inside the SQL statement** (`… AND password = @password`), which is what constrained the platform to a comparable — that is, unsalted — hash format. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | MD5 is fast by design, so an offline attacker holding the password column recovers weak and moderate passwords at negligible cost, and precomputed tables recover common passwords immediately. Because there is no salt, two accounts with the same password store the same digest, so one cracked value exposes every account sharing it and the column doubles as a password-reuse map. The cost asymmetry was measured rather than assumed: a single MD5 pass over a password takes **0.0007 ms** on the audit host, against **150 ms** for the replacement primitive as shipped — roughly a **210,000×** difference in the work an attacker must spend per guess. The replacement figure is the re-measured median for the shipped PBKDF2-HMAC-SHA-256 setting; an earlier revision quoted **367 ms**, which was the median for the HMAC-SHA-512 configuration this file no longer uses, and is withdrawn. The full measurement, its spread and its method are in [the remediation log](remediation-log.md). |
| **EVIDENCE** | At the pre-audit revision the file contained `private static MD5 md5Hash = MD5.Create();` as a single shared instance, `GetMd5Hash` calling `md5Hash.ComputeHash(...)`, and `VerifyMd5Hash` returning `0 == StringComparer.OrdinalIgnoreCase.Compare(hashOfInput, hash)`. The credential lookup at `SecurityManager.cs:L84-L86` computed the digest and passed it as an EQL parameter compared with `password = @password`. The analyzer gate independently reports the MD5 use as `CA5351` — *Do not use broken cryptographic algorithms*. |
| **REMEDIATION** | The primitive was replaced with a salted, work-factored, fixed-time hash-and-verify pair implemented **in this file** over `Rfc2898DeriveBytes.Pbkdf2`: **PBKDF2-HMAC-SHA-256, 600,000 iterations**, a fresh 128-bit cryptographically random salt per credential and a 256-bit subkey, written as a self-describing versioned payload — a 13-byte header carrying the format marker `0x01`, the pseudo-random-function identifier `1` for HMAC-SHA-256, the iteration count and the salt length, followed by the salt and the subkey, Base64-encoded to 84 characters — so the work factor can be raised later without invalidating anything already stored. It writes the same layout the ASP.NET Core `PasswordHasher` V3 format uses and is deliberately **not** a delegation to it: that type's options expose no pseudo-random-function selector and its V3 format is HMAC-SHA-512, so the mandated HMAC-SHA-256 is unreachable through it, and deriving in-file additionally keeps the core library free of an ASP.NET Core dependency it does not otherwise need. No new package was needed — the primitive ships in the framework the core library already references — and no schema change was needed, because the password column is already a 500-character variable-length string and the produced value is 84 characters. Legacy verification is retained deliberately, so credentials written by earlier releases keep working and are upgraded on next authentication rather than reset. The documented deviation from the letter of the mandated cryptographic standard — PBKDF2 rather than bcrypt, scrypt or Argon2 — is recorded as `RISK-003` in the [risk register](risk-register.md), and the retained MD5 surface as `RISK-004`. |

##### Status of this finding — closed on every live credential path

The primitive is delivered, verified **and wired**. Every consumer named under LOCATION now routes
through it, so the finding is closed rather than partially remediated:

| Aspect | State |
| --- | --- |
| The salted, work-factored primitive exists, is correct and is verified | **Yes** — see the verification table below |
| New credentials are written through it | **Yes** — `WebVella.Erp/Database/DbRecordRepository.cs:L557` and `:L1893` and `WebVella.Erp/Api/RecordManager.cs:L2025` all call `PasswordUtil.HashPassword` |
| Stored credentials are verified through it, and upgraded on login | **Yes** — `WebVella.Erp/Api/SecurityManager.cs` resolves the credential by exact e-mail, calls `PasswordUtil.IsLegacyHash` (`:L158`) and `PasswordUtil.VerifyPassword` (`:L161`) in application code, and calls `UpgradeStoredPasswordHash` → `PasswordUtil.HashPassword` (`:L250`) when the stored value is legacy |
| The comparison no longer happens inside the SQL predicate | **Yes** — the predicate selects on the anchored e-mail pattern only; there is no `password = @password` term left |
| An address that does not exist still costs one key derivation | **Yes** — `PasswordUtil.PerformDummyVerification` (`:L176`) equalises the timing, closing the enumeration channel the restructure would otherwise have opened (CWE-203) |
| Therefore C-03 is | **Remediated.** The primitive and all four call sites are in place |

Two further weaknesses in the same file are closed by the same change and are recorded separately
below: `M-06`, because the shared mutable hash instance is gone; and `M-05`, because verification now
compares through `CryptographicOperations.FixedTimeEquals`.

**One narrative was corrected across this document set, and the record of it is kept here.** Earlier
revisions of this row, of the risk register and of the remediation log described the primitive as a
delegation to the ASP.NET Core `PasswordHasher` in its V3 format, and therefore as
PBKDF2-**HMAC-SHA-512**, quoting latency measured for that configuration. That was true of an
intermediate revision and is not true of the tree: the shipped code derives in this file with
`Rfc2898DeriveBytes.Pbkdf2` over `HashAlgorithmName.SHA256`. Every statement of the format, the
pseudo-random function, the verifier, the risk-register reference and the measured latency is now
consolidated on the shipped implementation, and the superseded HMAC-SHA-512 figures are retained only
where they are explicitly labelled as the comparison they are. A plaintext length bound of 128
characters is enforced at all four entry points before any scan, encode, digest or derivation work is
performed, so an oversized submission to the anonymous login endpoint is refused for the cost of one
integer comparison.

##### Verification of the C-03 primitive

| Check | Result |
| --- | --- |
| The stored format is salted and non-deterministic | Hashing the same password twice yields different values; each carries its own 128-bit random salt |
| The format is self-describing, so the work factor can be raised later | The value encodes the format marker, the pseudo-random function, the iteration count and the salt; 84 Base64 characters beginning with `A`, the encoding of the `0x01` marker |
| Fits the existing column with no schema change | 84 characters against a 500-character column |
| Legacy and modern values are distinguishable without a new column | A legacy digest is exactly 32 hexadecimal characters; a modern value is 84 Base64 characters — the two shapes cannot collide at any casing |
| Verification is fixed-time | Both comparisons go through `CryptographicOperations.FixedTimeEquals` — the modern subkey comparison in `VerifyPbkdf2Hash` and the retained legacy digest comparison in `VerifyMd5Hash` |
| The upgrade signal works | A value written at a lower iteration count verifies with `needsRehash` set, so a future work-factor increase is carried by the same mechanism with no further code change |
| A corrupt stored value cannot become a denial of service | Verification returns false for a malformed value; only `FormatException` and `ArgumentException` are caught, so a genuine platform fault still propagates |
| Cost measured, not asserted — and **re-measured at this commit against the shipped setting** | Medians over 20 runs, single-threaded, .NET 10.0.10, PBKDF2-**HMAC-SHA-256** at 600,000 iterations: hash **150 ms**, verify **151 ms** on a quiet run of the shared build host, with medians rising to **344 ms** under contention on the same host. The earlier figures on this row — hash 367.0 ms, verify 364.1 ms — measured the HMAC-SHA-512 configuration the file no longer uses and are withdrawn. The cross-check that establishes the ratio was taken in the same process: SHA-512 at the same 600,000 iterations measured **477 ms**, about 3.2× the shipped cost per attempt. Because the host is shared, **treat the ratio as the finding and the absolute value as an order of magnitude**; the full transcript is in [the remediation log](remediation-log.md). See `RISK-003` for the accepted trade-off and the comparison against the OWASP floor |
| Module and solution compile | `dotnet build WebVella.Erp/WebVella.Erp.csproj -t:Rebuild` and `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` — exit 0, **0 errors** |

#### C-04 — Hardcoded encryption key with a silent fallback

| Field | Value |
| --- | --- |
| **FINDING** | A 256-bit encryption key was compiled into the source as a constant, and the key accessor fell back to it silently whenever configuration supplied no key. |
| **SEVERITY** | Critical — the key is published in the source repository, so any data it protects is readable by anyone who can read the code, which is a data-breach exposure. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) and [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) |
| **LOCATION** | `WebVella.Erp/Utilities/CryptoUtility.cs:L16` — the `defaultCryptKey` constant — and the fallback branch in the key accessor at `:L29-L30`, reached from the `CryptKey` property at `:L23` through the null check at `:L27`. The same 64-hex value also appears, byte-identically, in all eight `Config.json` files. |
| **DESCRIPTION** | The constant `defaultCryptKey` — a value of `[REDACTED — 64 characters, SHA-256 prefix 7810b2fe1ad52ed5]`, 64 hexadecimal characters — was present in source at `:L16`, and the accessor read `if (string.IsNullOrWhiteSpace(ErpSettings.EncryptionKey)) { cryptKey = defaultCryptKey; }`. A deployment that never configured a key therefore encrypted with a value published in a public repository, and did so **without any signal that it had done so**. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Anyone holding the ciphertext and the source recovers the plaintext. The silent fallback is what makes this Critical rather than merely poor practice: an operator had no way to discover the condition, because the platform started normally and encrypted successfully with a known key. |
| **EVIDENCE** | At the audit baseline the file read `private const string defaultCryptKey = "…";` at `:L16`, the assigned value being `[REDACTED — 64 characters, SHA-256 prefix 7810b2fe1ad52ed5]`, and `private static string cryptKey;` at `:L17`; the `CryptKey` property at `:L23` tested `if (string.IsNullOrEmpty(cryptKey))` at `:L27`, and the fallback at `:L29-L30` read `if (string.IsNullOrWhiteSpace(ErpSettings.EncryptionKey)) { cryptKey = defaultCryptKey; }`. The same 64-hex value appears **byte-identically in all eight** `Config.json` files, so it was compromised in two independent ways — once as a compiled-in constant and once as shipped configuration. The literal is **redacted, not truncated**, per [the redaction convention](#how-compromised-historic-values-are-written-in-this-document-set); the fingerprint above is the same digest `WebVella.Erp/ErpSettings.cs:L120` holds as `PublishedDefaultEncryptionKeyDigest` and refuses at start-up, so an operator can test their own key against it without either document holding the value. **The full value remains in repository history and is therefore permanently compromised, so rotation is mandatory rather than optional.** |
| **REMEDIATION** | **Both halves were changed, because removing only the constant would have relocated the defect rather than closed it.** The constant is deleted, and the fallback is replaced by an `InvalidOperationException` naming the missing setting, the environment variable that supplies it, the legacy misspelled key name that is still honoured, and the finding identifier — so the failure is actionable rather than cryptic. Fail-fast validation was additionally added at settings initialisation so a missing key aborts startup rather than surfacing at the first encryption. The residual weakness in the same file — the deterministic initialisation vector — is a separate Medium finding recorded as `M-08` and accepted as `RISK-006`. Traces to the **Cryptographic Standards** clause forbidding embedded key material. |

#### C-05 — Guest role granted create permission on user and role entities

| Field | Value |
| --- | --- |
| **FINDING** | The provisioning seed granted the Guest role permission to create records in both the user entity and the role entity. |
| **SEVERITY** | Critical. *Privilege escalation to admin* is a Critical-tier condition in the severity matrix. Create permission on the two entities that define identity and privilege is the shortest possible path to it, and the grant was held by the role that unauthenticated callers occupy. |
| **CWE** | [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html) and [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html). |
| **LOCATION** | `WebVella.Erp/ERPService.cs:L77` for the user entity and `:L363` for the role entity. A related Guest read grant on the role entity sits at `:L366`. |
| **DESCRIPTION** | Provisioning built the record-permission sets for the user and role entities and added `SystemIds.GuestRoleId` to `CanCreate` on both. The Guest role is the role an unauthenticated caller carries, so the platform shipped with anonymous create permission over its own identity and privilege tables. The seed is otherwise deliberate about restriction — update and delete on both entities are Administrator-only — which makes the create grants look like a development convenience that was never withdrawn rather than a considered decision. Maps to **OWASP A01:2021 — Broken Access Control**. |
| **IMPACT** | A caller reaching a record-create route without credentials could insert user rows and role rows. Creating a role is creating a privilege set; creating a user and associating it with a privileged role is a complete escalation to administrator, and administrator in this platform reaches server-side code execution through the page-component code hooks. The grant also violates deny-by-default at the exact place where deny-by-default matters most. |
| **EVIDENCE** | At the audit baseline `:L77` read `userEntity.RecordPermissions.CanCreate.Add(SystemIds.GuestRoleId);` and `:L363` read `roleEntity.RecordPermissions.CanCreate.Add(SystemIds.GuestRoleId);`, each immediately followed by the equivalent Administrator grant. `:L366` additionally read `roleEntity.RecordPermissions.CanRead.Add(SystemIds.GuestRoleId);`. |
| **REMEDIATION** | Traces to the **Authorization Enforcement** standard's deny-by-default clause. Both Guest `CanCreate` grants are removed from the seed, as is the Guest `CanRead` grant on the user entity that `C-02` covers. Because a seed correction protects only new installations, `RevokeGuestRecordPermissions4` (`:L2379`, with the per-entity overload at `:L2428`) revokes the same grants on already-provisioned deployments inside the version-4 migration. Two consequences are recorded rather than left to be discovered. First, the Guest **read** grant on the *role* entity is removed from the seed only: the migration that would have carried that removal to existing installations was withdrawn as outside the frozen scope of this engagement, because it is a Medium rather than a compensating control for a Critical, so a fresh installation does not have that grant while an existing one keeps it — an open documented Medium in the [risk register](risk-register.md). Second, two plugin patches restate the affected entities' full permission sets from source, so replaying them re-grants what the seed no longer contains; both patches now carry the correction, and the interaction is recorded in the [remediation log](remediation-log.md). |

### High severity findings

#### H-01 — Object-mapping library carries a High-severity advisory

| Field | Value |
| --- | --- |
| **FINDING** | The `AutoMapper` package was pinned to a version affected by a published High-severity advisory: uncontrolled recursion leading to denial of service. |
| **SEVERITY** | High — *Vulnerable and outdated component with a published High-severity advisory.* |
| **CWE** | [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj` (the package pin: `:L47` before the remediation, `:L88` at this commit after the escalation comments were added above it) and `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` (the single mapping-configuration construction site the upgrade required to change: `:L15` before, `:L23` at this commit). A third location joins them after `CR2-F-04`: `Directory.Build.props`, which carries the licence-governance gate that keeps the unratified claim unpublishable |
| **DESCRIPTION** | The core library pinned `AutoMapper` with the exact-version notation `[14.0.0]`. Advisory [GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x) / CVE-2026-32933 affects every version below `15.1.1` (and, separately, the `16.0.0` line below `16.1.1`), classifying the defect as uncontrolled recursion (CWE-674). The advisory maps to **OWASP A06:2021 — Vulnerable and Outdated Components**. Because the pin used exact-version notation, no transitive resolution could lift the platform onto a patched version. |
| **IMPACT** | A mapping graph that recurses without bound exhausts the stack and terminates the hosting process, so the exposure is availability loss (denial of service) rather than disclosure or code execution. Every one of the seven site hosts and the console application resolves its object mapping through this single package, so the affected component sits on the request path of the whole platform. Real-world exploitability in this codebase is low and is assessed in full in the [risk register](risk-register.md): all mappings are statically declared in source, and no user-controlled mapping configuration or type graph reaches the configuration builder, so the recursion path is reachable only through a self-referential mapping the developers themselves would have to author. |
| **EVIDENCE** | Reproduced with the toolchain's own dependency audit against the affected version: `dotnet restore` reports `warning NU1903: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x`, and `dotnet list package --vulnerable` reports the row `AutoMapper  [14.0.0]  14.0.0  High  https://github.com/advisories/GHSA-rvv3-g6hj-g44x`. Package metadata confirms the licence change described under REMEDIATION: `automapper.nuspec` declares `<license type="expression">MIT</license>` at 14.0.0 and `<license type="file">LICENSE.md</license>` at 15.1.3, where that licence file names the Reciprocal Public License 1.5. |
| **REMEDIATION** | The pin was raised to `[15.1.3]` — the newest release on the **lowest patched major**, chosen to minimise behavioural drift while still clearing the advisory. The upgrade requires exactly one code change: from 15.x the `MapperConfiguration` constructor takes an `ILoggerFactory`, so `ErpAutoMapper.Initialize` now supplies `NullLoggerFactory.Instance` (from the `Microsoft.AspNetCore.App` framework reference already present at `WebVella.Erp/WebVella.Erp.csproj:L61`, so **no new package dependency was added**). A no-op factory is used deliberately: the platform performs no AutoMapper logging, and introducing real logging would exceed the remediation scope. The `Initialize` signature and the `ErpAutoMapper.Mapper` field are unchanged, so both call sites and all mapping declarations, profiles and projection sites keep compiling untouched. Verification and the residual licensing decision are recorded in the [remediation log](remediation-log.md) and the [risk register](risk-register.md). Traces to the **Dependency Updates** standard's clause on packages with known Critical or High advisories. |

##### Verification of the H-01 fix

| Check | Result |
| --- | --- |
| `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` audit diagnostics** |
| `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for every project, **including `WebVella.Erp`** |
| Resolved package version | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| `dotnet build WebVella.ERP3.sln -c Debug` | exit 0, **0 errors** across all projects |
| Scan trustworthiness precondition | The project-reference path casing defect (finding H-19) is already fixed, so `WebVella.Erp` is genuinely present in the restore graph and the clean result is not a silent omission. Verified with `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` returning nothing. |
| Runtime verification | A host and the console application both start, initialise mapping and serve traffic; interactive login succeeds (`POST /login` → `302`) and the authenticated pages render, exercising the `EntityRecord` → `ErpUser` projection that the login path depends on. No `AutoMapperConfigurationException`, no `NullReferenceException` and no mapping error in either process. |

#### H-02 — Token lifetime validation disabled

| Field | Value |
| --- | --- |
| **FINDING** | Bearer-token validation omitted both `ValidateLifetime` and `ClockSkew`, and swallowed every validation failure without a trace. **This record has been corrected — see the correction note below it.** The original wording said lifetime validation was "switched off" and that an expired token was accepted "indefinitely"; measurement disproves both. |
| **SEVERITY** | High — session hijacking, but on the corrected basis stated below rather than the original one. The severity is retained because the practical outcome was still a token that never stopped working: `H-03` set the ticket's own expiry a century ahead, and the anonymous refresh route at `WebApiController.cs` made whatever lifetime existed indefinitely renewable. The tier follows the engagement's severity matrix, which places session hijacking in High. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) and [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs:L127-L136` — the token validation parameters — and the surrounding `catch` at `:L139-L142`. The anonymous refresh route that makes it reachable is `WebVella.Erp.Web/Controllers/WebApiController.cs:L4292-L4295`. |
| **DESCRIPTION** | The validation parameters omitted `ValidateLifetime` and `ClockSkew`, and the `catch (Exception)` around validation returned without recording anything. The omission of `ValidateLifetime` did **not** disable expiry checking — see the correction below — but the omission of `ClockSkew` left the framework's five-minute default in force, so every expired token stayed usable for a further five minutes. Compounding it, the token refresh endpoint is anonymous, so an indefinitely valid token was also indefinitely renewable. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | A token obtained once — from a log, a proxy, a browser history or a shared device — authenticates forever, so revocation by expiry does not exist. Silent failure handling additionally means an attacker probing with forged tokens leaves no evidence. |
| **EVIDENCE** | The pre-audit parameters, read from the baseline commit, set `ValidateIssuerSigningKey`, `ValidateIssuer`, `ValidateAudience`, `ValidIssuer`, `ValidAudience` and `IssuerSigningKey`, and contained **no** `ValidateLifetime` and **no** `ClockSkew` — an omission, not an explicit `false`. The exception handler discarded the exception object entirely (`catch (Exception)`). |
| **REMEDIATION** | `ValidateLifetime = true` with an explicit `ClockSkew` of one minute — explicit rather than default, because the framework default of five minutes silently extends every token's usable life. Validation failures are now logged, with a one-minute rate limit on the log write so a token-flooding attempt cannot itself become a log-volume denial of service, and with the log write wrapped so that a logging failure can never turn into an authentication failure. **Corrected by review finding `F7`:** at the time this record was first written the explicit skew existed only in the platform's own validator — both hosts' `AddJwtBearer` registrations omitted `ClockSkew` and therefore kept IdentityModel's five-minute default, so an expired bearer principal could stay authorized around four minutes longer than this record implied. All three validators now read one member, `AuthService.JwtClockSkew`, so they cannot drift apart. **Also narrowed by review finding `F11`:** the outer catch was still `catch (Exception)`, which converted any defect inside validation into "invalid token" and wrote an audit record asserting a credential rejection that had never been judged. It now catches only `SecurityTokenException` and `ArgumentException`, and anything else propagates into the error pipeline. Traces to the **Authentication Hardening** standard's secure-session clause. |

##### Correction of record for H-02, with the measurement behind it

An earlier revision of this record asserted that omitting `ValidateLifetime` "defaults the handler into
accepting any expiry", and therefore that an expired token "continued to be accepted indefinitely". Both
statements are false, and the correction is recorded here rather than the record quietly reworded.

`TokenValidationParameters` was instantiated against the exact pinned library — `Microsoft.IdentityModel.Tokens`
**8.15.0**, the version this repository resolves — and its defaults read out directly:

| Property | Default, measured | Consequence of omitting it |
| --- | --- | --- |
| `ValidateLifetime` | `True` | Expiry **was** checked. Omitting it changed nothing. |
| `ClockSkew` | `00:05:00` | An expired token stayed usable for a further **five minutes**. |
| `RequireExpirationTime` | `True` | A token with no `exp` claim was already rejected. |
| `ValidateIssuerSigningKey` | `False` | The baseline set this explicitly to `true`, which was correct. |

So the genuine defect at this site was narrower than the record claimed and is **two** defects, not one:
a five-minute acceptance window past expiry that nothing in the configuration acknowledged, and validation
failures that left no audit trace at all. The unbounded-session outcome the original wording described was
real, but it came from `H-03` and the anonymous refresh route, not from this parameter set.

The remediation is unchanged and remains correct on the corrected basis: setting `ValidateLifetime` explicitly
is defence in depth against a future default change, and setting `ClockSkew` explicitly narrows the window
from five minutes to one. What changes is the justification, and stating the smaller true defect is worth more
than keeping the larger false one.

#### H-03 — Authentication ticket expiry set 100 years ahead

| Field | Value |
| --- | --- |
| **FINDING** | The authentication cookie ticket was issued with an expiry 100 years in the future. |
| **SEVERITY** | High — session hijacking. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs:L44`, inside the `AuthenticationProperties` initialiser built at sign-in spanning `:L41-L47`. |
| **DESCRIPTION** | `ExpiresUtc = DateTimeOffset.UtcNow.AddYears(100)`. A stolen cookie therefore remained valid for the lifetime of the deployment and beyond. Maps to **OWASP A07:2021**. |
| **IMPACT** | Effectively unbounded session lifetime: a cookie captured from a shared or compromised machine grants access permanently, and signing out on one device does not invalidate a copy taken from another. |
| **EVIDENCE** | The `AddYears(100)` call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | Replaced with a bounded lifetime expressed as a named constant of 1 440 minutes — one day — chosen to align with the cookie expiry window rather than invented, so the ticket and the cookie cannot disagree about when the session ends. Traces to the **Authentication Hardening** standard's secure-session clause. |

#### H-04 — Weak default token signing key compiled into the settings

| Field | Value |
| --- | --- |
| **FINDING** | When no token signing key was configured, the platform substituted a compiled-in literal signing key — `[REDACTED — 17 characters, SHA-256 prefix 82794e7c1030b896]`, a short English phrase. |
| **SEVERITY** | High — anyone knowing the default can mint valid tokens for any account, which is authentication bypass. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) and [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) |
| **LOCATION** | **As audited:** `WebVella.Erp/ErpSettings.cs:L118` — the signing-key assignment, with the issuer and audience defaults at `:L119-L120`. The shipped values were at `WebVella.Erp.Site/Config.json:L25` and `WebVella.Erp.Site.Project/Config.json:L19-L20`, and a fourth occurrence of the same literal was published as documentation at `WebVella.Erp.Site/JWT_README.txt:L12`. All four are now blank or absent: the two configuration keys carry the empty string, the compiled-in fallback is deleted, and `JWT_README.txt:L12` shows `"Key": ""`. |
| **DESCRIPTION** | `JwtKey = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Key"]) ? <compiled-in literal> : configuration["Settings:Jwt:Key"];`. The fallback is both guessable and published. **The weakness is entropy, not length, and the distinction matters because the naive reading of it is wrong.** The two shipped values are byte-identical to each other and 51 characters long — `[REDACTED — 51 characters, SHA-256 prefix 87184b56659256b8]` — which is comfortably longer than the 256-bit minimum that HS256 wants, and HS256 is the algorithm actually in use (`SecurityAlgorithms.HmacSha256Signature` at `WebVella.Erp.Web/Services/AuthService.cs:L156`). So no claim of insufficient key length is made here, and none should be inferred. What is defective is that the value is a short English phrase repeated to fill its length, which carries near-zero entropy however long the result is, and that both it and the shorter 17-character compiled-in default were published in a public repository — which reduces the work of forging a token to reading the tree. **An earlier revision of this row named the phrase and its repetition count, from which the whole 51-character key could be reconstructed; that is withdrawn.** The structural property is what the finding needs, and it is stated without the value: an operator holding a candidate key can settle the question by fingerprinting it with `sha256sum`, and `WebVella.Erp/ErpSettings.cs:L119` refuses the value outright by the same digest. Maps to **OWASP A02:2021**. |
| **IMPACT** | A token signed with a known key is indistinguishable from a legitimate one, so an attacker forges a token carrying any identity and any role, including administrator. This is privilege escalation to administrator with no credential required. |
| **EVIDENCE** | The conditional with the literal fallback is present verbatim at the pre-audit revision, and the shipped 51-character value was read from both `Config.json` files at that same revision and confirmed to be the same phrase repeated three times. Both are truncated here deliberately; the full values remain in repository history and are therefore permanently compromised, so rotation of the signing key is mandatory and is not optional on the strength of the code fix alone. |
| **REMEDIATION** | The fallback is deleted — the key is now read straight from configuration and nothing is substituted — and the absence of a usable key now has a defined, screened outcome instead of a silent forgeable-token default. **That outcome is capability degradation, not a startup abort, and an earlier revision of this cell said otherwise.** It claimed "fail-fast validation aborts startup ... when a signing key is required but absent"; the executable behaviour is that startup proceeds, the bearer-token issue and refresh routes disable themselves and refuse every request, every presented token fails validation, cookie login is unaffected, and a `warn:` line naming the setting, its environment-variable form and this finding is written to standard error — but only when a `Settings:Jwt` section exists, so hosts that issue no tokens are neither forced to configure a key they never use nor warned about routes they never intended to serve. `ValidateRequiredSecurityConfiguration` aborts startup for `Settings:ConnectionString` and `Settings:EncryptionKey` only; `Settings:Jwt:Key` is never added to its `missingSecrets` accumulator. The two categories are set out in the [secure configuration guide](secure-configuration.md#required-settings). Traces to the **Cryptographic Standards** clause forbidding embedded key material. |

#### H-05 — Plaintext database credentials in eight shipped configuration files

| Field | Value |
| --- | --- |
| **FINDING** | Every shipped `Config.json` carries a live PostgreSQL connection string, including the database user name and password, and one also carries the mail account password. |
| **SEVERITY** | High — a repository read is enough to obtain database credentials for any deployment that kept the shipped values. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **LOCATION** | All eight `Config.json` files, at per-file locators, which is why the scrub had to be performed file by file rather than by a uniform patch. Connection string and encryption key at `:L4` and `:L5` in `WebVella.Erp.Site`, and at `:L3` and `:L4` in each of `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Project`, `.Sdk` and `WebVella.Erp.ConsoleApp`. `WebVella.Erp.Site:L13` and `:L11` in four of the others additionally exposed an internal UNC path. |
| **DESCRIPTION** | The database connection string and the encryption key are present as literal values in files tracked in version control, and two of the eight additionally carry the token signing key (finding `H-04`). Each file carries them at different line positions, so no uniform patch applies. **One correction is stated rather than inherited:** the mail password is **not** among them. `EmailSMTPPassword` is the empty string in **all eight** files — verified at `WebVella.Erp.Site:L18`, `WebVella.Erp.Site.Sdk:L18`, `WebVella.Erp.ConsoleApp:L17` and `:L16` in the remaining five — so this finding is scoped to the connection strings and the encryption key, and any claim that a live SMTP credential was published would be false. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Direct database access with the application's own privileges, which bypasses every application-level authorisation control the platform implements. Where the values were reused across environments, one leak compromises all of them. |
| **EVIDENCE** | The literal values are present verbatim in all eight files at the audit baseline, and the distribution is exact rather than approximate. **Seven** of the eight carry a live connection string to a private-range internal host and port — `[REDACTED — host:port, SHA-256 prefix 72858cca8cb5df2d]` — which is internal network-topology disclosure in its own right; the eighth, `WebVella.Erp.Site`, points its live string at `localhost:5432` and carries the internal host only in the commented-out string above it at `:L3`. The `User Id` and `Password` are the same word as each other in every file, and there are two such words across the eight: one of 4 characters, `[REDACTED — 4 characters, SHA-256 prefix 9f86d081884c7d65]`, in **six** files, and one of 3 characters, `[REDACTED — 3 characters, SHA-256 prefix ef260e9aa3c673af]`, in **two** — `WebVella.Erp.Site:L4` and `WebVella.Erp.Site.Project:L3`. The encryption key, `[REDACTED — 64 characters, SHA-256 prefix 7810b2fe1ad52ed5]` and 64 hexadecimal characters, is **byte-identical in all eight**. The values are **redacted, not truncated**, per [the redaction convention](#how-compromised-historic-values-are-written-in-this-document-set), and the redaction changes nothing about their status: **the full values remain in repository history and are therefore permanently compromised, so rotation is mandatory rather than optional.** One value present in the same files is deliberately **not** reported as a secret — `CloudBlobStorageConnectionString` in the SDK host at `:L13` is a local disk path, not a credential. |
| **REMEDIATION** | **Fixed.** An earlier revision of this row said "partially remediated; the scrub itself is a later stage" and that the finding "remains open"; both are retracted - the scrub has landed. All eight shipped configuration files now carry **empty** values for the connection string, encryption key, token signing key and mail password, and the files are retained rather than deleted because the JSON configuration source is not optional and deleting them stops every host from starting. The precondition that made scrubbing safe rather than fatal landed first, in the required order: startup now fails fast, with an actionable message naming each missing setting and its environment variable, when a required secret is absent. Two further changes are required before the values can be removed, and both are deliberately out of this stage: the configuration provider chain must be extended beyond its single JSON source, because there is currently no other channel by which an operator could supply a secret; and the files must then be scrubbed rather than deleted, because the JSON source is not optional and deleting them stops every host from starting. Both have landed, so this finding is closed **in the working tree**. One thing must still not be read into it: scrubbing the working tree does **not** remove these values from committed history, so every secret that was ever committed must be treated as compromised and rotated. The rotation instruction is in [the secure configuration guide](secure-configuration.md). Traces to the **Cryptographic Standards** clause forbidding embedded key material, and to the **Dependency Updates** standard's pin-and-externalise discipline as applied to configuration. |

#### H-06 — Cross-site scripting through unencoded output

| Field | Value |
| --- | --- |
| **FINDING** | The raw-output helper is used at 128 sites across 69 Razor views — **the census as taken at the audit baseline, which is the count this record is written against throughout.** It is not the current count: the remediation deleted raw wrappers at the confirmed text sinks, so the tree as delivered carries **114 invocation sites across 62 views**. Both numbers are stated wherever current state is discussed, and neither substitutes for the other — **128/69 is the original audit census**, **114/62 is the current census**. The current figure is reproducible rather than asserted: `grep -roE 'Html\.Raw\(' --include=*.cshtml . \| wc -l` returns 114 and `grep -rlE 'Html\.Raw\(' --include=*.cshtml . \| wc -l` returns 62. Counting *invocation* sites rather than every textual mention matters: a looser pattern also matches the seven places the helper is merely named in prose or in a comment, which is how a census can drift without any code changing. Three of them emit an unencoded, caller-supplied return URL into an `href` attribute; a further set render database text without encoding, including navigation and menu content that appears on every page of every host. |
| **SEVERITY** | High — stored cross-site scripting in navigation content executes for every user who loads any page. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html), and [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html) for the return-URL sinks |
| **LOCATION** | Reflected: `WebVella.Erp.Plugins.SDK/Pages/page/create.cshtml:L16`, `.../manage.cshtml:L21` and `.../manage-custom.cshtml:L18`. Stored, highest blast radius first: `WebVella.Erp.Web/Pages/Shared/NavItem.cshtml:L13` and `:L30`, `WebVella.Erp.Web/Pages/Shared/NavMenu.cshtml:L13` and `:L35`, and `WebVella.Erp.Web/Components/SiteMenu/SiteMenu.cshtml:L22`, all of which render on every page of every host; then `WebVella.Erp.Plugins.SDK/Pages/data_source/list.cshtml:L28`, `:L31`, `:L34` and `:L50`; then the six Project widget views — `PcProjectWidgetTimesheet/Design.cshtml:L18` and `Display.cshtml:L18`, `PcProjectWidgetTasksQueue/Design.cshtml:L55-L56` and `Display.cshtml:L54-L55`, and `PcProjectWidgetTaskDistribution/Design.cshtml:L41` and `Display.cshtml:L41`. The stored sinks' **root cause is not in those views at all**: the markup they render raw is composed in `WebVella.Erp.Web/Models/BaseErpPageModel.cs` (five sink blocks) and in the three Project widget builders `WebVella.Erp.Plugins.Project/Components/PcProjectWidgetTasksQueue/PcProjectWidgetTasksQueue.cs`, `.../PcProjectWidgetTimesheet/PcProjectWidgetTimesheet.cs` and `.../PcProjectWidgetTaskDistribution/PcProjectWidgetTaskDistribution.cs` (four sink lines). That is where the fix landed. |
| **DESCRIPTION** | Most of the 128 sites are **not** vulnerable and were proven so rather than assumed: roughly 55 render markup the server itself constructs from identifiers only, and four are by-design raw channels whose whole purpose is to emit author-supplied markup or script. Classifying every site by its argument was essential, because treating all 128 as defects would have produced a large volume of false findings. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Script executing on the application's own origin can read the session, act as the victim, and — because the navigation renders everywhere — reach every authenticated user of the platform. |
| **EVIDENCE** | The three reflected sinks emit the unencoded model property while sibling pages in the same area already use its encoded counterpart, which is what localised the defect. **The three navigation and menu sinks are `IsHtml`-guarded, not unconditional, and the guarded construct is quoted rather than paraphrased because the naive wording would be a false claim.** `NavItem.cshtml:L11` reads `@if (navItem.IsHtml)` and `:L13` `@Html.Raw(navItem.Content)`, while the `else` at `:L15` reaches `:L17` `@navItem.Content`, which Razor auto-encodes; the same pattern repeats at `:L28`, `:L30` and `:L32`. `NavMenu.cshtml:L11` reads `@if (menu.IsHtml)` with `@Html.Raw(menu.Content)` at `:L13` and the encoded `@menu.Content` at `:L17`, repeating at `:L33`, `:L35` and `:L37`. `SiteMenu.cshtml:L20` reads `@if (menuItem.IsHtml)` with `@Html.Raw(menuItem.Content)` at `:L22` and the encoded `@menuItem.Content` at `:L26`. These three therefore resolve to a **by-design opt-in markup channel whose safe auto-encoded path is already present in the `else` branch**; the residual is a **privileged-author** stored-scripting channel — whoever can set `IsHtml` true — carrying the same compensating control as the four by-design raw channels recorded in the [risk register](risk-register.md). The blast-radius statement stands unchanged: these views render on every page of every host, which is what keeps them the top sink of this finding. The genuine text sinks are elsewhere, and their remediation is subtractive — the raw wrapper is deleted so the plain Razor expression auto-encodes — while the icon value at `data_source/list.cshtml:L28` is triaged as a markup channel rather than encoded. A headless-browser run confirmed the exploit: HTML encoding alone stops attribute breakout but a `javascript:` scheme URL still executes when the link is activated, because the browser decodes entities *before* parsing the scheme. |
| **REMEDIATION** | **Closed — the reflected and the stored sinks are remediated; only the four by-design channels remain accepted. This row was previously wrong about that, and the correction is recorded rather than overwritten:** when it first said "closed", three further live sinks of this same class were still present in the tree and were found by a later code review as findings `F-01`, `F-02` and `F-03`. All three are now closed and each is recorded below with its own locator, so "closed" here means closed **as of this revision** and traceable, not closed by assertion. Encoding was the wrong control for the reflected sinks and was replaced by validation: the return URL is now accepted only if it is a same-site local URL, and anything else falls back to a safe default. The same policy was applied to the two companion redirect sinks in the page models, which were a second, unencoded path to the same weakness. The stored sinks were then closed **where the markup is composed, not where it is rendered**, because composition is where the untrusted values enter it. In `WebVella.Erp.Web/Models/BaseErpPageModel.cs` the four `MenuItem.Content` composition sites — the multi-node area link, the two sitemap node links, the single-node area link and the site-page anchor — now HTML-encode every interpolated label and title, admit a node URL only when it is a local path, a fragment or an explicit `http`/`https` absolute URL (rejecting control characters and protocol-relative `//host` forms), constrain an icon class to letters, digits, spaces, hyphens and underscores, and percent-escape the site-page name before it becomes a path segment. The three `PcProjectWidget*` component builders no longer assemble markup at all: they publish structured text, image-path, icon-class and colour fields, and their six Design and Display views render literal `<img>`, `<i>` and `<a>` elements so Razor's automatic encoding applies to every value. The raw-output helper therefore remains in the navigation, menu and site-menu views — removing it would break the deliberate icon markup those views carry and the dropdown rewrite `NavItem` performs on the composed string — but it now has nothing executable left to emit, so the per-sink triage previously planned for those views is no longer required. The four by-design channels are still never encoded; they are covered by the compensating control of restricting markup authoring to privileged roles plus the content-security policy, and remain recorded as accepted risk under `RISK-023`, which is confined to those four channels alone. Additionally, the platform's only escaping utility — a case-sensitive string replacement, trivially defeated by altered casing — was replaced by the framework encoder; see M-18. **Four further sinks of this class were found after this record was first written, and none of them is one of the 128 raw-output sites.** The first is the platform's single `WvSelectOption` conversion boundary, from which the third-party select component concatenates a stored option's `icon_class` and `color` into a `class` and a `style` attribute — closed separately as `P-23`. The other three were raised by a subsequent code review as `F-01`, `F-02` and `F-03`, and all three are closed; because each needs its own locator and its own reasoning, they are set out in full immediately below this table rather than compressed into this cell. Traces to the **Injection Prevention** standard's context-appropriate-output-encoding clause. |

##### The three sinks of this class closed after this record was first written

Each is a live instance of `H-06` that the row above had already declared closed. They are recorded here, with
the locators as delivered, because a finding that reappears is more useful to a future reader than a count.

**`F-01` — the same `WvSelectOption` boundary, one member further along.** `SelectOption.Label` reached the
vendor's raw sinks unaltered. Decompiling `WebVella.TagHelpers` 1.8.0 established the shape rather than
inferring it: `WvFieldSelect` and `WvFieldMultiSelect` each emit `AppendHtml($"<i …></i> {Label}")` at four
sites, and `WvFieldCheckboxList` and `WvFieldRadioList` emit `AppendHtml(Label)` **unconditionally**, with no
icon gate at all. Encoding was not an available control here, for two measured reasons: the same `Label`
instance also reaches encoding sinks (`Append`) in the same render, so a pre-encoded value would visibly
double-encode somewhere; and all four select2 initialisations pass
`escapeMarkup: function(markup){return markup;}` and re-inject the option's DOM-**decoded** text as
`innerHTML`, so entities written server-side are decoded before they arrive. Closed instead by value
**restriction** at `WebVella.Erp.Web/Utils/ModelExtensions.cs`: `ToWvSelectOption` passes the label through
the new `SafeStyleValue.DisplayText`, which removes only `<` — the one character that can begin a tag — and
`"`, which breaks the `title="…"` attribute that `WvFieldMultiSelect.inline-edit.js` builds in JavaScript.
`&`, `'` and `>` are left untouched, so `R&D`, `Client's request` and `> 30 days` render byte-identically and
the same string instance is returned when nothing needs removing. All 150 `new SelectOption` sites were
checked first: no legitimate label in the repository contains markup. Residual scope is `RISK-127`, and the
narrower icon residual it leaves is `RISK-129`.

**`F-02` — the page header's `description` attribute.**
`WebVella.Erp.Web/TagHelpers/WvPageHeader/WvPageHeader.cs` emitted it through `AppendHtml`, and both this
report and the risk register claimed its only non-literal supplier was a server-side builder. That claim was
**false**: `WebVella.Erp.Web/Components/PcPageHeader/PcPageHeader.cs` resolves the value from
`context.DataModel.GetPropertyValueByDataSource(instanceOptions.Description)`, and both
`PcPageHeader/Display.cshtml` and `PcPageHeader/Design.cshtml` bind it to `description=` — so a page
component could point the raw sink at any page or record data source. Closed by **splitting the channel**
rather than converting it, because converting it would have broken the list screens the original reasoning
was protecting: `description` now renders through `InnerHtml.Append` and is HTML-encoded, while a new,
explicitly named `description-html` attribute renders through `AppendHtml`, takes precedence, and is never
concatenated with the encoded one. The five SDK list views that legitimately pass builder-composed markup —
`application/list.cshtml`, `data_source/list.cshtml`, `entity/list.cshtml`, `entity/pages.cshtml` and
`page/list.cshtml` — moved to `description-html` in the same change, so those screens render exactly as
before. Verified with a hostile description bound through a record field: the rendered element's
`childElementCount` was **0** and its `innerHTML` fully entity-encoded, while all five list views still
emitted one `<strong>` and two `<li>` elements each. Supersedes `RISK-120`.

**`F-03` — the legacy multi-file field row.**
`WebVella.Erp.Web/TagHelpers/WvFieldUserFileMultiple/WvFieldUserFileMultiple.cs` interpolated a persisted
`user_file` row's `path` twice into quoted anchor attributes — `href` and `title` — and its `name` into
element content, all inside a single `AppendHtml` of a format string. New uploads were already sanitised, but
rows written by earlier releases were never migrated, so the legacy path stayed live for existing
installations. Closed by rebuilding both the icon `<div>` and the anchor with `TagBuilder`: attributes through
`AddCssClass` and `Attributes.Add`, the display name through `InnerHtml.Append`, and the fixed `<em>` as its
own child element rather than a literal inside a format string. Verified by parsing both renderings with an
HTML parser: the pre-fix markup yields an anchor carrying an `onmouseover` attribute plus an injected
`<img onerror>` element, the post-fix markup yields exactly the four intended attributes with no handler and
no injected element, and legitimate values render identically apart from attribute-quote style.


#### H-07 — Script injection through the rich-text editor upload callback

| Field | Value |
| --- | --- |
| **FINDING** | Script injection through the rich-text editor upload callback |
| **SEVERITY** | High |
| **CWE** | CWE-79, CWE-94 (OWASP A03:2021) |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs` — as audited, `:L4014` (source) flowing to `:L4029` and `:L4036` (sinks). Post-remediation the same code is at `:L4516` (source), `:L4526` (the validation gate) and `:L3819-L3826` (`BuildCKEditorCallback`, which now owns both surviving interpolations) |
| **DESCRIPTION** | The `UploadFileManagerCKEditor` action reads the editor's callback index straight from the query string into a local string and then concatenates that string into a `<script>` body returned to the browser. Neither sink validates the value and neither encodes it for a script context. The second sink additionally concatenates `ex.Message` into the same script. |
| **IMPACT** | An attacker who can cause a victim's browser to issue the upload request with a crafted `CKEditorFuncNum` value controls a JavaScript expression that executes on the application's own origin, inside an authenticated session. The exception sink also discloses server-side error text to the browser. |
| **EVIDENCE** | `string CKEditorFuncNum = HttpContext.Request.Query["CKEditorFuncNum"].ToString();` at `:L4014`, reaching `... callFunction(" + CKEditorFuncNum + ", ...` at `:L4029` and `:L4036`; `:L4036` also interpolates `ex.Message`. That was the state when the inventory was taken; the trailing sentence of this field previously read "Measured at this commit — the finding is open; no remediation has been applied", which contradicted the remediation field directly below it and is superseded. **The finding is closed**: the callback index is now integer-parsed before use, both sinks are encoded with `JavaScriptEncoder.Default`, the exception sink no longer echoes `ex.Message`, and all three emissions are funnelled through a single `BuildCKEditorCallback(int, string, string)` helper so a future sink cannot bypass the encoding. |
| **REMEDIATION** | **Fixed.** Every value now sits in a context it cannot escape. The callback index is parsed with `int.TryParse(..., NumberStyles.Integer, CultureInfo.InvariantCulture, ...)` and the request is rejected outright when it does not parse; thereafter it is carried as an `int`, so the bare — and therefore unquotable — numeric position holds no attacker-controlled text at all, which is why integer validation is both sufficient and lossless for what is simply a numeric callback index. The URL and message are emitted inside JavaScript string literals through `JavaScriptEncoder.Default`, which escapes the double quote to `\u0022` and also the backslash, the apostrophe, CR, LF, U+2028, U+2029 and `<` to `\u003C`, so neither the string literal nor the enclosing `</script>` element can be terminated. The echoed `ex.Message` is replaced by a fixed internal-error string while the exception continues to be logged server-side. All three sinks are funnelled through one helper, `BuildCKEditorCallback(int, string, string)`, whose signature makes the fix structural: the index cannot be a string at that boundary. `grep -c 'JavaScriptEncoder'` on the controller returns **2**, both inside that helper, and the fixed string is `INTERNAL_ERROR_MESSAGE` at `:L46`. No new dependency was required — the same encoder already backs the replaced output helper in `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs`. The markup, the content type and the CKEditor callback contract are unchanged, so the editor behaves exactly as before. Verify with `grep -n 'BuildCKEditorCallback' WebVella.Erp.Web/Controllers/WebApiController.cs` — the declaration at `:L4310` and four call sites (`:L5224`, `:L5239`, `:L5255`, `:L5268`), with the `int.TryParse` guard at `:L5203`. Traces to the **Injection Prevention** standard's allowlist-validation and output-encoding clauses. |

#### H-08 — Unrestricted file upload chaining into inline execution

| Field | Value |
| --- | --- |
| **FINDING** | Four upload actions accepted any file type and any size, stored the caller-supplied file name without sanitisation, and the download action then served the stored bytes **inline from the application's own origin** with no content-disposition — so an uploaded markup or vector file became stored script. Two adjacent file actions performed no object-level authorization at all. |
| **SEVERITY** | High. Two High-tier conditions in the severity matrix are met: *stored cross-site scripting*, reached by the upload-to-inline-download chain, and *insecure direct object reference over sensitive data*, in the unauthorised move and delete actions. |
| **CWE** | [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html), with the direct-object-reference half recorded as [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html). |
| **LOCATION** | Uploads at `WebVella.Erp.Web/Controllers/WebApiController.cs:L3962`, `:L4009`, `:L4041` and `:L4134`; caller-supplied file names consumed at `:L3977`, `:L4022`, `:L4061` and `:L4151`; the inline download at `:L3323`; the move action at `:L3355-L3368`; the catch-all delete action at `:L3370-L3383`. |
| **DESCRIPTION** | None of the four upload actions constrained extension, media type or size, and all four read the whole stream into memory before any size was known. The file name arrived from the caller and was concatenated straight into a storage path. Separately, the download action returned the stored bytes with a resolved MIME type and **no content-disposition header**, which is what turns a permissive upload into a scripting vulnerability rather than merely a storage-hygiene one: markup or SVG served inline executes on this application's origin, with this application's cookies. The move and delete actions fetched the target file and acted on it without ever asking whether the caller owned it, and the delete action was reachable through a catch-all route matching any path. Maps to **OWASP A04:2021 — Insecure Design** and **A03:2021 — Injection**. |
| **IMPACT** | An authenticated caller of any role could upload an HTML or SVG document and obtain a URL on the application's own origin that executes script in the browser of any user who opened it — stored cross-site scripting with session-scoped consequences, including credential-bearing requests made as the victim. The absent size bound made a single request a memory-exhaustion primitive. The unauthorised move and delete actions let any authenticated caller relocate or destroy any other user's file given only its path, which is a direct object reference over data the platform treats as private. |
| **EVIDENCE** | At the audit baseline the two editor uploads built their storage path as `var tempPath = "tmp/" + Guid.NewGuid() + "/" + upload.FileName;` (`:L3977`, `:L4022`) and the two multi-file uploads took the name from `ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName` (`:L4061`, `:L4151`), with no extension, media-type or length check on any path. The download action read `return File(file.GetBytes(), mimeType);` at `:L3323` — no disposition argument, so the browser renders in place. The move action fetched `fsRepository.Find(source)` and called `Move` with no authorization between them; the delete action was declared `[AcceptVerbs(new[] { "DELETE" }, Route = "{*filepath}")]` at `:L3370` and likewise called `Find` then `Delete`. That the omission was an oversight rather than a constraint is visible two dozen lines away, where `:L4056` reads `var currentUser = AuthService.GetUser(User);` — a user handle was already available in the same region. |
| **REMEDIATION** | Traces to the **Injection Prevention** standard's allowlist-validation clause and the **Authorization Enforcement** standard's object-level clause, and both halves of the chain are closed together because constraining either alone leaves it intact. Uploads now enforce an extension **allow-list** (`ALLOWED_UPLOAD_EXTENSIONS`), a 25 MiB size cap (`MAX_UPLOAD_SIZE_BYTES`, chosen to sit below the framework's own default request-body limit so it can never be the surprising bound), a content-type check, and a 200-character file-name bound with sanitisation before the name reaches a storage path. The allow-list is derived from the file types the platform already classifies rather than invented, with two deliberate exclusions that are the whole point of the finding: `.html` and `.htm`, which the platform's own document list contains and which are the exact payload of the scripting chain; and `.svg`, kept absent because an SVG is an XML document that can carry a script element while the content-type provider maps it to an image media type — which is precisely why the extension, not the declared media family, has to be the authority. On the download side, anything outside a narrow inline set is forced to an **attachment** disposition, backed by the `nosniff` header from the response-header work. **All FIVE live raw upload actions carry that one shared validation**, not just the four this record was scoped to: the fifth, `POST /fs/upload/`, was constrained in a later pass and the coverage is recorded in the [remediation log](remediation-log.md) and under the additional observation in Part 2. The move and delete actions now resolve the caller and refuse when the target does not belong to them, and refuse outright when the target does not resolve. **The move action's authorization is also atomic with its mutation**, which authorizing alone did not achieve: the destination it authorized is carried into the repository as an explicit expectation - a specific row, or absence - and both operands are locked and revalidated inside the single transaction that performs the delete and the update, so a concurrent request cannot substitute a different user's file behind the authorized target path and have it overwritten. Any mismatch answers the same generic refusal, and a destination that becomes occupied after an absence was authorized is refused by the `files.filepath` UNIQUE constraint rather than overwritten. **The finding is deliberately bounded**: filesystem path traversal is *not* achievable here, because storage is database-backed, route segments cannot contain a path separator, and the path is lower-cased at `:L3274` before lookup — so `H-08` is scoped to type, size and authorization, not to filesystem escape. Widening the allow-list is recorded as an owner decision in the [risk register](risk-register.md). |

#### H-09 — SQL identifier injection through string concatenation

| Field | Value |
| --- | --- |
| **FINDING** | Table identifiers derived from entity and relation names were concatenated directly into SQL text at six sites. |
| **SEVERITY** | High — SQL injection. |
| **CWE** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **LOCATION** | Six sites, each with the construct observed at the pre-remediation revision:<br>1. `WebVella.Erp/Database/DbEntityRepository.cs:L275` — `NpgsqlCommand command = con.CreateCommand("DELETE FROM entities WHERE id=@id; DROP TABLE rec_" + entity.Name);` — the most striking artefact in the audit, a `DROP TABLE` whose target is concatenated from data.<br>2. `WebVella.Erp/Database/DbRecordRepository.cs:L664` — `sql.AppendLine("SELECT " + columnNames + " FROM " + tableName);`<br>3. `WebVella.Erp/Database/DbRecordRepository.cs:L666` — the `SELECT DISTINCT` variant of the same statement.<br>4. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1018` — `$"SELECT * FROM rec_{entityName};"`<br>5. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1291` — `$"SELECT EXISTS(SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'rel_{relation.Name}');"`<br>6. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1305` — `$"SELECT * FROM public.rel_{relation.Name}"`<br>The exposure is bounded to identifiers, not values: `WebVella.Erp/Database/DbRepository.cs:L517` and `L528-530` show every value in this layer bound as an `NpgsqlParameter`. The helper introduced to close these is `WebVella.Erp/Database/DbIdentifier.cs`. |
| **DESCRIPTION** | PostgreSQL cannot bind an identifier as a parameter, so identifiers are necessarily interpolated. Every *value* in this layer is already parameterised, which confines the exposure precisely to identifier interpolation — one of the six sites concatenates an entity name straight into a `DROP TABLE` statement. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | An identifier containing a statement separator would execute additional SQL with the platform's own database privileges. Reachability is constrained by the platform's own entity-name validation, but that validation is a different layer with a different purpose, so relying on it is relying on a control nobody declared. |
| **EVIDENCE** | The concatenations are present verbatim. **This cell previously recorded zero `CA2100` and zero `CA23xx` diagnostics and read that silence as corroboration that values are parameterised. Both halves of that were wrong and are corrected here.** The silence was an artefact of the analysis level: neither rule is enabled by `AnalysisLevel=latest-recommended`, so it could not have corroborated anything. **A third correction is now needed, and it returns this cell to its first position.** `AnalysisLevelSecurity=latest-all` — under which `CA2100` reported at 20 sites and `CA2326`/`CA2328` at 20 and 9 — has been **removed** under review finding `GATE-03`, together with the `.globalconfig` that tuned it. Those rules do not execute again, so their silence is once more the silence of a rule that is not running and carries no signal in either direction. The parameterisation claim rests where it always actually rested: on direct reading of the data layer, where every *value* is bound through `NpgsqlParameter` and only identifiers are interpolated. The nineteen individually justified allow-list entries that covered those sites are no longer adjudicated by any automated gate; they are inventoried by hand in `risk-register.md` under `RISK-052`, which is the honest cost of the frozen gate shape. The `CA2327`-reports-zero corroboration is withdrawn for the same reason — see the deserialisation finding below. |
| **REMEDIATION** | A single audited helper — `DbIdentifier` — validates against a strict allow-list (a leading lower-case letter, then only lower-case letters, digits and single underscores, anchored at both ends) and double-quotes the result, failing hard on rejection rather than sanitising, because a silent repair would reintroduce the exposure while making the finding read as closed. One reviewable implementation is used rather than six local patches. **The helper is now attached at every concatenation site** - an earlier revision of this row said it "has no callers yet", which is retracted. It is applied well beyond the six sites the finding enumerated: the record, entity and relation repositories, the EQL SQL builder, the SDK code-generation service and an SDK migration all route identifiers through it. `Validate` and `Quote` are used deliberately differently - `Validate` where the bare name is needed, such as inside a string literal compared against `pg_tables`, and `Quote` where the identifier is emitted into the statement itself. Traces to the **Injection Prevention** standard's allowlist-validation clause. |

#### H-10 — Unsafe polymorphic deserialisation

| Field | Value |
| --- | --- |
| **FINDING** | Deserialisation was configured with unconstrained polymorphic type handling, so the type to instantiate was taken from the serialised payload. The plan enumerated **fourteen** sites; a systematic sweep of the tree found **twenty**. |
| **SEVERITY** | High. |
| **CWE** | [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |
| **LOCATION** | **Twenty sites across six files, all measured against the tree rather than taken from the plan.** Current line numbers are given because each site gained a threat comment, shifting every pre-remediation locator upward.<br><br>*The fourteen the plan enumerated:* `JobProfile.cs:L43, L54, L60, L101` (`All`, all four deserialise); `DbRelationRepository.cs:L58, L147` (`Auto`, serialise-only) and `:L201` (`Auto`, deserialise); `DbEntityRepository.cs:L64, L190` (`Auto`, serialise-only) and `:L246` (`Auto`, deserialise); `CodeGenService.cs:L969, L1011` (`Auto`, deserialise) and `:L9253, L9287` (`All`, deserialise).<br><br>*The six the plan did not:* `WebVella.Erp/Jobs/JobDataService.cs:L32, L101, L302, L351` (`All`, serialise-only — the write counterpart producing exactly the JSON `JobProfile.cs` reads) and `WebVella.Erp/Notifications/NotificationContext.cs:L115` (`Auto`, deserialise) and `:L160` (`Auto`, serialise-only).<br><br>Overall split: **11 deserialise, 9 serialise-only.** The binder introduced to close them is `WebVella.Erp/Api/Models/ErpSerializationBinder.cs`. |
| **DESCRIPTION** | Type handling was enabled in its permissive modes, which instructs the deserialiser to honour a type name embedded in the data. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | An attacker able to influence a persisted payload chooses which type is constructed during deserialisation, which is the standard route from data tampering to code execution via a gadget type reachable in the loaded assemblies. |
| **EVIDENCE** | The permissive type-handling settings were present at all **fourteen** sites the audit enumerated — which is the audit's count, not the attachment count: the binder is attached at **20** sites, the fourteen plus six write-side counterparts found later, and the basis of both figures is stated in the `H-10` record in Part 1. Two things are now recorded that the original evidence could not state. **First, the site count is 20, not 14, and the discrepancy is a counting artefact rather than a missed exposure**: a repository-wide search for `TypeNameHandling` returns more hits than there are settings, because several are mentions inside comments. Restricted to lines that actually *assign* the property, `git grep -n 'TypeNameHandling *=' -- '*.cs'` returns **20**, of which **19 attach `ErpSerializationBinder.Instance` on the same line**; the twentieth, `WebVella.Erp/Database/DbEntityRepository.cs:246`, attaches it on the next line of the same object initialiser. **Second, a claim made here is withdrawn.** This cell previously argued that the closure was *machine-checked* by an analyzer that was armed and silent: `CA2327` fires precisely when `TypeNameHandling` is not `None` *and* no `SerializationBinder` is set, it raised **zero** diagnostics across all 19 projects, and a throwaway probe carrying an identical initialiser with the binder omitted *did* raise it alongside `CA2326`. The probe result stands and the reasoning was sound **while the rule was enabled**. It no longer is: `CA2327` was reached through `AnalysisLevelSecurity=latest-all`, which review finding `GATE-03` removed along with the `.globalconfig` that accompanied it, because the plan of record freezes the analyzer gate at `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`. A rule that does not execute cannot be silent in the evidentiary sense — it is simply absent — so the strongest available evidence is again the enumeration above: **20** assigning lines, 19 attaching `ErpSerializationBinder.Instance` on the same line and the twentieth on the next line of the same object initialiser, verified by reading each site. That is weaker than a machine check, and saying so is the point of recording the withdrawal rather than deleting the paragraph. Carried in `risk-register.md` as `RISK-051`. |
| **REMEDIATION** | A serialisation binder with an explicit type allow-list, exposed as a singleton and failing hard on any type outside the list. Resolution is an **exact lookup** in the allow-list map — never a namespace or assembly-name prefix test, which is the shape that admitted the behaviour-carrying types described below — and the resolved type is re-validated before it is returned, with delegate and `IDisposable` gadget shapes refused at **two** independent points: once while the map is built and once on the resolution path, so a type that somehow reached the map could still not be constructed. **Removing type handling outright was rejected**: already-persisted job arguments and entity and relation payloads carry type discriminators and would fail to deserialise, breaking existing installations — so constraining the binder preserves round-tripping while closing the weakness. `BindToName` is intentionally left unrestricted, because constraining serialisation *output* protects nothing and would break writing. **The binder is now attached at every site.** For `JobProfile.cs` this was measured rather than assumed, and the measurement is the evidence that the finding is closed there: with the binder absent, a `$type` nested in `JobResultWrapper.Result` — a member declared `dynamic` — **instantiated `System.Diagnostics.Process`**; with the binder attached, the same payload is refused with a `JsonSerializationException`. Eight further gadget discriminators are refused at an `object` target, each against a control confirming the default binder resolved them. Every legitimate payload at all five consumers reached through the four sites deserialises **byte-identically with and without the binder**, which is what demonstrates that constraining resolution preserved existing installations. **The allow-list has since been narrowed a second time, and that narrowing is part of this finding's closure rather than an enhancement.** Review finding `F-03` observed that the list, while no longer a name prefix, still admitted "service/repository/background types", and that was correct: built by scanning five namespaces *and their descendants*, it admitted a measured **268** types, of which **38 carry behaviour rather than data** — seven repositories, thirteen object-mapping profiles, eight converters, three attributes, two ambient contexts, two managers, a job pool, a job data service and an exception. That breadth was **verified reachable, not merely theoretical**: because `JobResultWrapper.Result` is declared `dynamic`, `DbRecordRepository`, `JobPool`, `JobManager` and `JobDataService` were all successfully instantiated through a discriminator in the `jobs.result` column, and two of them through a value nested in a dynamic record as well. The namespace scan is replaced by an explicit `typeof` inventory of **45** persisted types — the transitive closure, over data members only, of what the deserialisation sites actually read — so behaviour-carrying types admitted falls from 38 to **zero** while all nine round-trip shapes continue to pass and the 27 permitted framework types are unchanged. A latent break was closed in the same edit: `CurrencySymbolPlacement`, which a currency field genuinely reaches, sat outside all five scanned namespaces and was being refused. Two counts in this record are also corrected by measurement: the binder is attached at **20** sites rather than the fourteen originally enumerated — the six additional ones are four serialise-only settings in `JobDataService.cs` and two in `NotificationContext.cs`, the latter covering the PostgreSQL `NOTIFY` payload — and the permissive type handling those six sites carry was present before remediation, so the original site census undercounted the surface. See the remediation log for the full transcript, the before-and-after measurements and the recorded deviation from the planned rule-based mechanism. Traces to the **Injection Prevention** standard's allowlist-validation clause, applied to deserialisable types rather than to input strings. |

#### H-11 — SMTP certificate validation unconditionally bypassed

| Field | Value |
| --- | --- |
| **FINDING** | The mail plugin installs a certificate-validation callback that returns `true` unconditionally at five sites, so every SMTP connection accepts any certificate. |
| **SEVERITY** | High — transport authentication is removed entirely, which makes an active machine-in-the-middle attack on mail delivery trivial. |
| **CWE** | [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs:L145`, `:L288`, `:L417` and `:L559`, plus `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs:L791` — five sites, and exactly five. |
| **DESCRIPTION** | The callback is not conditional on environment, configuration or host — it always accepts. Maps to **OWASP A02:2021 Cryptographic Failures**. |
| **IMPACT** | An attacker who can intercept the connection reads every outbound message and the SMTP credentials used to send it. This compounds with M-17, because exception detail is e-mailed before it is persisted, and with the mail-library injection advisories recorded as H-20. |
| **EVIDENCE** | Corroborated by the analyzer gate independently of manual review: at the pre-remediation revision `CA5359` (do not disable certificate validation) reported diagnostics at **exactly these five sites** on every build. At this commit the rule reports **none**, because a callback is installed only when the configuration-gated policy member allows it and the callback yields that member rather than a literal `true`. The diagnostic disappearing is itself evidence that the unconditional accept is gone. |
| **REMEDIATION** | **Remediated, and closed at all five sites.** The always-true callback was replaced by an explicit configuration flag that defaults to secure, so a self-signed development server stays usable without an insecure default shipping to production; the flag was then narrowed so it is honoured **only** in Development posture. `SmtpService.AllowInvalidRemoteCertificates` yields `true` only when `Settings:EmailSMTPAllowInvalidCertificates` parses as `true` **and** `ErpSettings.DevelopmentMode` is set; otherwise it yields `false` and, when the setting was nevertheless enabled, reports the refusal once per process on standard error. Because that one member gates every callback site, the four `SmtpService.cs` sites and the one `SmtpInternalService.cs` site are covered by the same change, and `ErpSettings.DevelopmentMode` defaults to `false` so the policy fails closed before configuration is initialised. No analyzer diagnostic was suppressed to reach this state — `CA5359` stopped firing because the construct it reports is gone. **Revocation checking is left entirely to the library and is not configurable**, which is the scope this finding's remediation was given: no send path assigns `client.CheckCertificateRevocation`, so MailKit's own default of `true` applies and nothing can turn it off. That is a deliberate correction of an earlier over-reach recorded honestly rather than quietly reverted: this remediation had additionally introduced `Settings:EmailSMTPCheckCertificateRevocation`, whose explicit `false` disabled revocation checking **in every posture including Production**, and review finding `INT-08` established that it weakened the production transport posture beyond the agreed remediation, was never required in order to remove the accept-all callback, and accommodated an external-relay risk the plan of record requires to be **documented** rather than configured around. The setting, its policy member, its one-shot notice and all five assignments were removed. **The operational consequence of validating certificates is therefore documented, not settable:** a relay whose chain names no reachable CRL distribution point or OCSP responder fails the handshake with a chain status of only `unable to get certificate CRL` while its certificate is otherwise valid, and the supported remedy is to publish the revocation source — see the [secure configuration guide](secure-configuration.md) and `RISK-060`. **This finding does not reach the platform's other mail client:** the diagnostic notification path uses a separate `System.Net.Mail.SmtpClient` that negotiates no TLS at all, so no certificate policy applies to it; that is `M-17` and `RISK-131`, corrected under review finding `INT-01`. The residual of a Development installation still accepting any certificate, by design, is `RISK-033`. Traces to the **Cryptographic Standards** transport clause. |

#### H-12 — Development mode enabled in every shipped configuration

| Field | Value |
| --- | --- |
| **FINDING** | All eight shipped `Config.json` files enable development mode, and one host's deployment manifest additionally forces the environment to `Development`. |
| **SEVERITY** | High — development mode turns on the developer exception page, which returns stack traces, source excerpts and configuration to any client that triggers an error. |
| **CWE** | [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html) and [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |
| **LOCATION** | All eight `Config.json` files — `WebVella.Erp.Site:L10`, `WebVella.Erp.ConsoleApp:L9`, and `:L8` in each of `.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Project` and `.Sdk` — plus `WebVella.Erp.Site/web.config:L10`, where `ASPNETCORE_ENVIRONMENT` is set to `Development`. What the flag gates is `WebVella.Erp.Web/Controllers/ApiControllerBase.cs:L49`, and what the environment marker gates is `WebVella.Erp.Site/Startup.cs:L147-L149`. |
| **DESCRIPTION** | The environment marker is what selects the developer exception page in each host's pipeline, so the shipped defaults expose internal detail on any unhandled error in a production deployment that kept them. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Stack traces disclose file paths, type and method names, framework versions and query text, which materially shortens the reconnaissance phase of an attack against every other finding in this report. |
| **EVIDENCE** | The development-mode flag is present in all eight files and the environment variable is set in the deployment manifest at the pre-audit revision. |
| **REMEDIATION** | **Fixed.** An earlier revision of this row said "not yet remediated" and that the finding "remains open"; both are retracted. All eight shipped configuration files now set `"DevelopmentMode": "false"` explicitly, and the setting is evaluated as `IsNullOrWhiteSpace(value) ? false : bool.Parse(value)`, so removing the key would resolve to `false` as well — there is no state in which a missing value silently enables development behaviour; and `WebVella.Erp.Site/web.config` sets `ASPNETCORE_ENVIRONMENT` to `Production`. Note the residual operational hazard: an environment variable outranks the file, so a stray `Settings__DevelopmentMode=true` re-enables development behaviour - audit the environment, not only the files. Flipping the flags was a two-line change per file, but it must land with the provider-chain extension so that hosts remain startable. Two related error paths are worth separating out, because a configuration change alone will **not** fix them: two API error responses concatenate stack-trace text unconditionally, with no environment check at all, so those require a code change and are tracked with their own finding. The flags are flipped, so this finding is closed. Traces to the **Security Headers** and secure-configuration discipline, in that a production posture is the precondition for every response-level control this remediation adds. |

#### H-13 — Unconditional stack-trace disclosure on anonymous endpoints

| Field | Value |
| --- | --- |
| **FINDING** | The two bearer-token endpoints returned the exception message concatenated with the full stack trace in the response body, to unauthenticated callers, with no environment or development-mode condition guarding either site. |
| **SEVERITY** | High. Not merely verbose errors — which the matrix would place at Low — but unconditional internal disclosure on the two routes that are reachable **without credentials**, feeding directly into exploitation of the token weaknesses recorded as `H-02`. |
| **CWE** | [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html). |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs:L4287` and `:L4306`. |
| **DESCRIPTION** | Both token actions wrapped their work in a catch-all, logged the exception server-side, and then assigned the exception text **and its stack trace** to the response message. The controller elsewhere gets this right: `WebVella.Erp.Web/Controllers/ApiControllerBase.cs:L49-L58` guards the same disclosure behind `if (ErpSettings.DevelopmentMode)` and otherwise returns `"An internal error occurred!"`. These two sites simply had no guard. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | An unauthenticated caller could provoke a failure and read the internal call stack: namespaces, class and method names, file layout and framework versions, and whatever the exception message itself carried. That is reconnaissance handed to the attacker at the precise place they are already probing — the credential and token surface. It also weakens `H-02`: distinguishing a signature failure from an expiry failure by their exception text is exactly the oracle a token attack wants. |
| **EVIDENCE** | At the audit baseline both sites read `response.Message = e.Message + e.StackTrace;` — at `:L4287` inside the `catch (Exception e)` opened at `:L4283`, and at `:L4306` inside the catch opened at `:L4302`. Each already logged server-side immediately before, at `:L4285` and `:L4304`, through `new LogService().Create(Diagnostics.LogType.Error, …)`. The actions they belong to are `[AllowAnonymous]`, declared at `:L4273` and `:L4292`. |
| **REMEDIATION** | **This is one of two findings escalated upward rather than softened.** Because neither site was guarded by any development-mode check, flipping the environment marker to `Production` — which `H-12` does — would **not** have fixed them; the code had to change. Both now return a generic message and retain the server-side log record, so no diagnostic capability is lost, mirroring the already-correct guarded pattern at `ApiControllerBase.cs:L49-L57`. The remediation then went considerably further than the two sites the audit had found: a review pass established that the same disclosure persisted at thirty-six further response sinks in this controller, ten of them concatenating the stack trace as well, and every one now routes through a single `SafeErrorMessage` helper. A solution-wide sweep found thirteen more unguarded sinks outside this controller — two in the record manager, one in the query builder, seven in the SDK administration controller and three in the project plugin's controller — and closed all of them. **The closure claim is now stated at the width the evidence supports, because an earlier revision of this cell over-claimed.** It read *"leaving no unguarded exception-text response sink anywhere in the tree"*, which is literally true but invites the reading that no exception text can reach a response at all. Measured: `WebVella.Erp.Web/Controllers/WebApiController.cs` now contains **zero** occurrences of `StackTrace` and routes every sink through one `SafeErrorMessage` helper at **37** call sites; tree-wide, **26** statements still concatenate a message and a stack trace, of which **25** are in four core-library manager classes — `EntityManager.cs` 13, `EntityRelationManager.cs` 5, `RecordManager.cs` 5, `ImportExportManager.cs` 2 — and the 26th is the reference implementation in `ApiControllerBase.cs`. **All 26 sit behind `if (ErpSettings.DevelopmentMode)`, so none is unguarded and none emits in the shipped Production posture** — but a configuration flag is a materially weaker control than the code-level fix this finding required, which is the very distinction that escalated `H-13`. What this finding closes, therefore, is its own two unconditional anonymous routes plus the sinks the widening touched; the 25 configuration-guarded manager sites are a named residual, inventoried with their guard status as `RISK-129` in the [risk register](risk-register.md). The widening is tracked in the [risk register](risk-register.md) and the [remediation log](remediation-log.md). Traces to the **Authorization Enforcement** standard's log-failures-rather-than-disclose-them clause. |

#### H-14 — Permissive cross-origin policy at two hosts

| Field | Value |
| --- | --- |
| **FINDING** | Two of the seven hosts registered a default cross-origin policy allowing any origin, any method and any header, and applied it to the whole pipeline. |
| **SEVERITY** | High. An any-origin policy on an authenticated application removes the browser's own boundary against cross-site reads, which is the enabling condition for session-scoped attacks the matrix places in the High tier. |
| **CWE** | [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html). |
| **LOCATION** | `WebVella.Erp.Site/Startup.cs:L58-L64`, applied at `:L164`; `WebVella.Erp.Site.Project/Startup.cs:L50-L55`, applied at `:L149`. |
| **DESCRIPTION** | Both hosts called `services.AddCors` with a default policy composed of `AllowAnyOrigin()`, `AllowAnyMethod()` and `AllowAnyHeader()`, then enabled it with `app.UseCors()` early enough to cover static files. In both files a restrictive named policy already existed **in commented form immediately above** the permissive one, naming specific localhost origins with credentials allowed — so the restrictive shape the fix needed was already present in the source, unused. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Any web page on any origin could issue cross-origin requests to these hosts and read the responses. Because a wildcard origin cannot be combined with credentialed requests, the exposure is bounded to what an uncredentialed request returns — but on these hosts that still includes anonymous routes, and it removes the cross-origin boundary that would otherwise contain a scripting payload delivered from elsewhere. It also broadens the reach of every other finding that depends on a browser making a request the user did not intend. |
| **EVIDENCE** | At the audit baseline `WebVella.Erp.Site/Startup.cs:L58-L64` read `services.AddCors(options => { options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()); });`, with `app.UseCors();` at `:L164` carrying the comment that it should precede static files so it applies to them too. `WebVella.Erp.Site.Project/Startup.cs:L50-L55` was byte-identical in shape, applied at `:L149`. The commented restrictive policies sat at `Site` `:L54-L57` and `Site.Project` `:L46-L49`. |
| **REMEDIATION** | Both hosts now register an explicit origin allow-list read from configuration at `Settings:Cors:AllowedOrigins`. A supplied list wins in every environment; an explicitly empty list denies every origin, which is legal and matches nothing; and an absent key denies every origin outside Development, where each host falls back to its own documented localhost origins. A repository-wide search for a live, non-commented `AllowAnyOrigin()` across all seven host pipelines now returns **zero** occurrences — the only remaining occurrences are explanatory comments. **The scope of this finding is two hosts, not seven, and that matters**: `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next` and `.Sdk` already used a restrictive named policy and were never permissive, so overstating the finding platform-wide would have been one of the false-positive classes this report eliminates. One sequencing constraint was binding: HTTPS redirection breaks cross-origin preflight with an invalid-redirect error, so the allow-list and the redirection introduced by `H-15` had to land in the same change and be verified together. Operator configuration is in the [secure configuration guide](secure-configuration.md). Traces to the **Authorization Enforcement** standard's deny-by-default clause, applied at the origin boundary. |

#### H-15 — No HTTPS enforcement, no HSTS, and insecure cookie attributes

| Field | Value |
| --- | --- |
| **FINDING** | Eight of the nine applications enforced nothing about transport security: no HTTP Strict Transport Security, no redirection from plaintext, and authentication cookies without the `Secure` and `SameSite` attributes. |
| **SEVERITY** | High — an attacker positioned on the network downgrades the connection and reads the session cookie, which is session hijacking. |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) and [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html) |
| **LOCATION** | Cookie options at `WebVella.Erp.Site/Startup.cs:L93-L101` and the equivalent block in each of the other six hosts; only `WebVella.Erp.WebAssembly/Server/Program.cs:L18` and `:L21` used the framework's HSTS and HTTPS-redirection middleware. |
| **DESCRIPTION** | The cookie authentication options set no `SecurePolicy`, no `SameSite` value, no explicit expiry window and no sliding expiration, and no host redirected plaintext requests or advertised a strict-transport policy. Maps to **OWASP A02:2021** and **A05:2021**. |
| **IMPACT** | A cookie without `Secure` is transmitted over plaintext, so a single downgraded request discloses it; without `SameSite` it is also attached to cross-site requests. Combined with the unbounded ticket lifetime recorded as H-03, a cookie captured once remained valid indefinitely. |
| **EVIDENCE** | The cookie options block is present without any of those attributes at the pre-audit revision, and a search for HSTS or HTTPS redirection across the seven site hosts returns nothing. |
| **REMEDIATION** | **Fixed — fully remediated.** An earlier revision of this row said "partially remediated", "no response actually carries the header" and "this finding remains open". All three statements are retracted: every half has since landed. The response-header middleware is **registered in all seven host pipelines**, ordered ahead of response compression and both static-file middlewares, and emits `Strict-Transport-Security: max-age=31536000; includeSubDomains` alongside the other six mandated headers. All seven headers were verified **on the wire** against a published host over HTTPS — on a dynamic response and on two static assets. The framework's HSTS middleware and HTTPS redirection are registered in all seven hosts, guarded to non-Development and ordered HSTS-first. Cookie attributes are supplied from a single shared configurator: `SecurePolicy=Always` unconditionally, `SameSite=Lax`, `ExpireTimeSpan=1440`, `SlidingExpiration=true`, `AllowRefresh=true`, `HttpOnly=true`, bounded by a 7-day absolute session horizon and verified by decrypting a real server-issued cookie. Redirection landed **together with** the cross-origin allow-list, as required, and the pairing was verified rather than assumed: a cross-origin preflight over plaintext is answered by CORS with `204` and no `Location`, while a non-preflight plaintext request to the same host still receives `307`. Two measured caveats are recorded in the [secure configuration guide](secure-configuration.md): `UseHttpsRedirection()` is inert unless the application knows an HTTPS port, and HSTS is deliberately suppressed in Development so a developer is not pinned to HTTPS for the whole shared `localhost` origin. |

#### H-16 — No account lockout on repeated failed logins

| Field | Value |
| --- | --- |
| **FINDING** | Failed authentication attempts were neither counted nor limited, at any layer. |
| **SEVERITY** | High. |
| **CWE** | [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) |
| **LOCATION** | Both credential-verification entry points: `WebVella.Erp.Web/Pages/login.cshtml.cs:L92`, inside the synchronous `OnPost` declared at `:L62`, with the generic failure branch at `:L100-L105`; and the anonymous bearer-token route `GetJwtToken` at `WebVella.Erp.Web/Controllers/WebApiController.cs:L4273`. The plan named only the first; the second is a second credential oracle and is throttled too. The service introduced to close it is `WebVella.Erp.Web/Services/LoginThrottleService.cs`. |
| **DESCRIPTION** | Nothing in the platform recorded a failed attempt, so an attacker could submit unlimited guesses against a known e-mail address at whatever rate the server would serve. Maps to **OWASP A07:2021**. |
| **IMPACT** | Credential stuffing and password guessing are unbounded. The exposure was worse before `C-03`, because the fast unsalted digest made server-side verification nearly free; the new key-derivation cost is itself a partial mitigation, but a cost is not a limit. |
| **EVIDENCE** | A repository-wide search of the pre-audit revision finds no attempt counter, no lockout state and no rate limiter. The one artefact whose name suggested it — an authentication cache — was entirely commented out. |
| **REMEDIATION** | A throttle service implementing the mandated five-attempt lockout with a fifteen-minute window, keyed on both the account and the client address, and backed by a **dedicated, size-bounded `MemoryCache` the service owns privately** — `SizeLimit = 20000` tracked principals with `CompactionPercentage = 0.2` — rather than the platform's shared `Utils.Cache` helper, which exposes no way to set a size limit and would therefore have left the CWE-770 growth exposure open so that **no schema change and no new dependency** is introduced — the least invasive control available. Every member is non-throwing by construction, so the throttle can never itself break the login path, and key components are length-bounded and normalised defensively. Its single-instance scope is a real limitation and is documented rather than hidden: behind a load balancer, each instance counts separately. **The service is now wired into the login page** - an earlier revision of this row said it "has no callers yet", which is retracted. `login.cshtml.cs` calls `TryBeginAttempt` before authenticating, then `RegisterFailedAttempt`, `RegisterSuccess` or `AbandonAttempt` on the corresponding outcome. Wiring reaches **both** credential entry points, not only the one this finding named: the anonymous bearer-token route in `WebApiController` follows the identical reserve-then-finalise sequence, and the token-refresh route — which presents no username to count against — uses the address-only `IsAddressRefusing` / `RegisterAddressFailure` pair. The framework's transport-level rate limiter is additionally enabled in all seven host pipelines, so the two controls layer rather than substitute for one another. Traces to the **Authentication Hardening** standard's five-failed-attempt lockout clause. **SUPERSEDED IN PART, and the superseded part is the limitation:** the sentence above recording the service's single-instance scope described the original remediation and is retained as the record of it. A later checkpoint review raised that scope as finding `H-OPEN-02` on the ground that a five-per-instance bound is not the mandated five-attempt bound, and it is closed — see record `CK-03`. The counters now live in the platform's existing `plugin_data` table through `WebVella.Erp/Database/DbSecurityStateRepository.cs` under the reserved `wv_sec_` key prefix, each transition a single atomic row-locked read-modify-write, so five means five in total, a lockout survives a restart and spans instances, and the service fails closed when the store cannot be consulted. Still no schema change and still no new dependency: the table already existed. The `MemoryCache` described above survives, but only as a positive mirror of an in-force lockout — a counter is never cached, because a count read from a stale local copy is a count that permits attempts it should have refused. |

#### H-17 — Regular-expression denial of service in the credential query

| Field | Value |
| --- | --- |
| **FINDING** | The credential-resolution query matched the supplied e-mail address with PostgreSQL's case-insensitive **regular-expression** operator, passing the caller's input as the pattern, on the one route reachable without credentials. |
| **SEVERITY** | High. The matrix places injection in the High tier, and this is injection into a regular-expression evaluator rather than into SQL structure: the attacker controls the pattern the database engine compiles and runs, on an anonymous endpoint. |
| **CWE** | [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) and [CWE-625: Permissive Regular Expression](https://cwe.mitre.org/data/definitions/625.html). |
| **LOCATION** | `WebVella.Erp/Api/SecurityManager.cs:L85`, inside the system-scope block opened at `:L82`. |
| **DESCRIPTION** | Authentication opened a system scope that bypasses permission checks, computed the MD5 digest of the submitted password at `:L84`, and then issued a query whose predicate was `email ~* @email AND password = @password`. The `~*` operator is a case-insensitive regular-expression match, not an equality comparison, so the login form's e-mail field was a pattern input to the database's regular-expression engine. Two further observations belong here rather than in a separate finding. First, `password = @password` sat **inside the SQL predicate**, which is exactly why a salted hash format was impossible without restructuring the query — the enabling constraint behind `C-03`. Second, an exact case-insensitive address comparison **already existed** in application code immediately afterwards, at `:L90`, which is what made dropping the permissive pattern semantically safe rather than a behaviour change. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | An unauthenticated caller could submit a crafted pattern in the e-mail field and consume database CPU on the login path — catastrophic backtracking against the user table, with no authentication required and no rate limit in place, since `H-16` establishes that none existed. Because the login route is the entry point every user needs, exhausting it is a denial of service against the whole platform rather than one feature. Separately, the permissive matching meant an address containing regular-expression metacharacters could match rows the caller did not name, which the application-code check happened to catch but which the query itself did not prevent. |
| **EVIDENCE** | At the audit baseline `:L82` read `using (var ctx = SecurityContext.OpenSystemScope())`, `:L84` read `var encryptedPassword = PasswordUtil.GetMd5Hash(password);`, and `:L85` read `new EqlCommand("SELECT *, $user_role.* FROM user WHERE email ~* @email AND password = @password", …)` with the two `EqlParameter` values supplied at `:L86`. The redundant exact comparison followed at `:L90`: `if (((string)rec["email"]).ToLowerInvariant() == email.ToLowerInvariant())`. |
| **REMEDIATION** | Traces to the **Injection Prevention** standard's allowlist-validation clause. The predicate no longer evaluates a regular expression at all, which removes the weakness rather than bounding it: candidate resolution issues `SELECT id, email FROM rec_user WHERE lower(email) = lower(@email) ORDER BY id LIMIT 2` with the address bound as a text parameter, so the operand is compared as a literal string by an equality operator and can only ever match itself. There is no pattern for a caller to craft and no backtracking engine to exhaust, and `Regex.Escape` and the `~*` operator are both gone from the credential path. The `password = @password` term is **gone** — verification moved into application code, which is the change that made salted hashing possible at all — and a page bound limits the candidate rows the lookup can return. The exact case-insensitive comparison at the application layer is retained as the authoritative address match. One consequence was closed in the same change rather than left open: moving verification out of the query would have created a user-enumeration timing channel, so a non-existent address still costs one key derivation through `PasswordUtil.PerformDummyVerification`. The restructure is documented in the [credential migration guide](credential-migration.md) and the [remediation log](remediation-log.md). |

#### H-18 — Two projects targeted an end-of-life framework

| Field | Value |
| --- | --- |
| **FINDING** | Two projects targeted .NET 7, which reached end of support on 14 May 2024 and therefore receives no security patches. |
| **SEVERITY** | High — an unsupported runtime cannot be patched, so any future advisory against it is permanently unfixed. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) |
| **LOCATION** | `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj:L4` and `WebVella.Erp.WebAssembly/Shared/WebVella.Erp.WebAssembly.Shared.csproj:L4` — the `TargetFramework` element in each — with the hosting package pinned to the same end-of-life line at `Server.csproj:L10` |
| **DESCRIPTION** | Both projects declared `<TargetFramework>net7.0</TargetFramework>` while the other seventeen projects in the repository targeted `net10.0`, and the Server project additionally pinned `Microsoft.AspNetCore.Components.WebAssembly.Server` to `7.0.13` — a package line on the same unsupported branch. Maps to **OWASP A06:2021 — Vulnerable and Outdated Components**. |
| **IMPACT** | This is not a specific exploitable defect; it is the absence of a route to fix one. Because the branch is out of support, a future advisory against the .NET 7 runtime or its ASP.NET Core packages would have no patched version to move to, so the exposure would become permanent rather than temporary. |
| **EVIDENCE** | At the pre-audit revision, `<TargetFramework>net7.0</TargetFramework>` appears at line 4 of both project files and the hosting package is pinned at `7.0.13`. |
| **REMEDIATION** | Both projects retargeted to `net10.0` and the hosting package lifted to `10.0.1`, bringing them onto the same supported target the other seventeen projects already use. No source change was required in either project. Traces to the **Dependency Updates** standard's replace-end-of-life clause. |

#### H-19 — Case-mismatched project references broke the dependency scan

| Field | Value |
| --- | --- |
| **FINDING** | Fifteen project references named the core project's directory as `WebVella.ERP` while the directory on disk is `WebVella.Erp`, so solution-wide restore failed on any case-sensitive filesystem and the core project silently dropped out of the dependency-audit graph. |
| **SEVERITY** | High. This is a build defect whose *security* consequence is that the vulnerability scan reported falsely clean, which is worse than reporting a finding: it produced confident, wrong assurance. |
| **CWE** | CWE-1104-adjacent — the effect is unaudited components rather than a code weakness. |
| **LOCATION** | Fifteen sites: `WebVella.ERP3.sln:L23`, plus a `ProjectReference` element in each of `WebVella.Erp.ConsoleApp:L22`, `WebVella.Erp.Plugins.Crm:L15`, `WebVella.Erp.Plugins.Mail:L33`, `WebVella.Erp.Plugins.MicrosoftCDM:L17`, `WebVella.Erp.Plugins.Next:L15`, `WebVella.Erp.Plugins.Project:L57`, `WebVella.Erp.Plugins.SDK:L45`, `WebVella.Erp.Site.Crm:L21`, `WebVella.Erp.Site.Mail:L20`, `WebVella.Erp.Site.MicrosoftCDM:L17`, `WebVella.Erp.Site.Next:L19`, `WebVella.Erp.Site.Project:L23`, `WebVella.Erp.Site.Sdk:L19` and `WebVella.Erp.Web:L119`. The already-correct reference at `WebVella.Erp.Site/WebVella.Erp.Site.csproj:L44` is the in-repository template the fix follows. |
| **DESCRIPTION** | MSBuild resolves the path literally, so on Linux the reference could not be found and restore failed with `MSB3202`. Because the core project owns the platform's only High-severity package advisory, its absence from the graph meant the advisory was never reported. Maps to **OWASP A06:2021** and **A08:2021**. |
| **IMPACT** | Every dependency-scan result obtained before this fix was unfounded, including any "no vulnerable packages" statement. The single host whose reference was already correct restored successfully, which is exactly what made the defect easy to miss: a per-project scan passed while the solution-wide scan failed. |
| **EVIDENCE** | The upper-cased segment appeared at fifteen sites; solution restore failed with `MSB3202` on a case-sensitive filesystem; the correct spelling was already present at one host, proving the fifteen were the outliers. |
| **REMEDIATION** | All fifteen paths corrected to match the on-disk casing — a no-op on case-insensitive filesystems and a repair on case-sensitive ones. Every one of the fourteen corrected project files now carries an identically worded comment naming the threat, so the constraint cannot be undone by a well-meaning edit; the solution file is excluded because its format tolerates no comment syntax. Verified: `grep -rn 'WebVella\.ERP\\'` returns nothing, and `MSB3202` and `MSB9008` counts are zero across a full solution rebuild. **This class was sequenced first**, because every subsequent dependency claim in this report depends on it. Traces to the **Dependency Updates** standard, as the precondition without which none of its clauses can be verified. |

#### H-20 — Mail and MIME libraries carried published advisories

| Field | Value |
| --- | --- |
| **FINDING** | The mail plugin depended on a version of `MailKit` affected by a STARTTLS response-injection advisory, and transitively on a version of `MimeKit` affected by a CRLF-injection advisory. |
| **SEVERITY** | High. Both advisories are rated Moderate by their publisher, but they compound in this codebase: the plugin handles user-influenced recipient addresses *and* disables transport certificate validation at five sites (finding `H-11`, owned by a later class), so an injection defect meets an absent certificate check on the same path. |
| **CWE** | [CWE-74: Improper Neutralization of Special Elements in Output](https://cwe.mitre.org/data/definitions/74.html) for the transport advisory and [CWE-93: Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html) for the MIME advisory. |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L28` — the `MailKit` package reference. `MimeKit` is not referenced directly; it resolves transitively through `MailKit`. |
| **DESCRIPTION** | `MailKit` was referenced at `4.14.1`. Advisory [GHSA-9j88-vvj5-vhgr](https://github.com/advisories/GHSA-9j88-vvj5-vhgr) / CVE-2026-41319 describes STARTTLS response injection through an unflushed stream buffer, enabling an authentication-mechanism downgrade, and is first patched at `4.16.0`. The resolved `MimeKit` was `4.14.0`; advisory [GHSA-g7hc-96xr-gvvx](https://github.com/advisories/GHSA-g7hc-96xr-gvvx) / CVE-2026-30227 describes CRLF injection in a quoted local part, enabling SMTP command injection and message forgery, and is first patched at `4.15.1`. Maps to **OWASP A06:2021 — Vulnerable and Outdated Components**. |
| **IMPACT** | Response injection during the STARTTLS handshake lets a network-positioned attacker influence which authentication mechanism is negotiated, which is a downgrade toward weaker or plaintext authentication of the mail credential. CRLF injection in an address lets a caller who can influence a recipient string inject additional SMTP commands, forging messages from the platform's own mail identity. |
| **EVIDENCE** | Reproduced with the toolchain's own dependency audit before the change: `dotnet list package --vulnerable --include-transitive` for the mail project reported both the `MailKit` and the `MimeKit` rows. |
| **REMEDIATION** | **One line closed both.** `MailKit` was raised to `4.17.0`, whose package metadata depends on `MimeKit 4.17.0`, so the transitive dependency is lifted past its own first-patched version without a second manifest entry. Verified after the change: `dotnet list package --include-transitive` reports `MailKit 4.17.0` and `MimeKit 4.17.0`, and the vulnerability listing reports neither. Adding an explicit `MimeKit` reference was deliberately avoided — it would have pinned a transitive dependency for no benefit, which is more change than the fix requires. Traces to the **Dependency Updates** standard's clause on packages with known advisories. |

### Medium severity findings

#### M-01 — No security response headers

| Field | Value |
| --- | --- |
| **FINDING** | The platform emitted none of the security response headers the engagement mandates. |
| **SEVERITY** | Medium — *missing security headers* sits in the Low tier of the severity matrix, but the absence of a content-security policy and of frame and content-type protections is what makes several other findings exploitable in a browser, so it is recorded here as the compensating control it is. |
| **CWE** | [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — the product does not use, or incorrectly uses, a protection mechanism that would defend against the attack. The frame-embedding half additionally maps to [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html). An earlier revision of this row asserted no identifier, on the reasoning that the finding is "a missing hardening control rather than a code weakness"; CWE-693 is precisely the class for a missing protection mechanism, so the abstention was unnecessary and is withdrawn. |
| **LOCATION** | The seven host pipelines. Only `WebVella.Erp.WebAssembly/Server/Program.cs:L18` and `:L21` emitted anything, and that was transport security alone. The middleware introduced to close it is `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, registered at `WebVella.Erp.Web/ErpMvcExtensions.cs:L98`. |
| **DESCRIPTION** | Only one project — the WebAssembly server — used any header middleware at all, and that was transport security alone. None of the seven site hosts emitted a content-security policy, frame options, content-type options, referrer policy or permissions policy. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Without `X-Content-Type-Options: nosniff` an uploaded file served with a benign type can be re-interpreted as script; without `X-Frame-Options` the interface can be framed for clickjacking; without a content-security policy an injected script has no second line of defence. These headers are what bound the damage when another control fails. |
| **EVIDENCE** | A repository-wide search of the pre-audit revision finds header middleware in exactly one project, emitting transport security only. |
| **REMEDIATION** | A middleware emitting all seven mandated headers with the exact mandated values. **The content-security policy ships in report-only mode**, with the enforced value configurable: four components in the platform deliberately emit inline script or author-supplied markup, so enforcing the policy immediately would break working features and violate the requirement that existing functionality be preserved. The value is never weakened — only its delivery mode is staged, and the report-then-enforce path is documented. **The overwrite behaviour is stated precisely here because an earlier revision of this row described it wrongly, claiming the middleware "does not overwrite a header a host has already set, so a host with a stricter policy keeps it" — that is retracted.** The middleware runs `AttachSecurityHeaders` twice, and the two passes behave differently on purpose. The **eager** pass runs before the pipeline continues and assigns every header **unconditionally**, so a value already present when this middleware executes — which, given its position, means one written by a middleware ordered ahead of it — **is replaced**. A host that wants a stricter policy therefore cannot get one by setting a header upstream; the policy text is a compile-time constant and the only bindable setting is the delivery mode, which is deliberate, because a configurable policy string is a configurable way to weaken it. The **response-start** pass then re-attaches only headers that are *missing*, which is what makes the set survive a downstream handler that resets the response, and is why it is a no-op on an ordinary response where the eager pass already wrote everything. Exactly one of the two policy header names is ever emitted, and the re-attach pass tests for **both** names before writing either, so a response can never carry two policy headers. **The middleware is now registered and ordered in all seven pipelines** - an earlier revision of this row said it "has no callers yet", which is retracted. It sits ahead of response compression and ahead of both static-file middlewares in every host, and all seven headers were verified **on the wire** against a published host on a dynamic response and on two static assets. The delivery switch binds from configuration — one key, `SecurityHeaders:ContentSecurityPolicyReportOnly` (environment variable `SecurityHeaders__ContentSecurityPolicyReportOnly`), whose two failure directions differ deliberately and were also previously misdescribed: an **absent or blank** value keeps the compiled report-only default, which is the mandated shipping posture, but a value that is **present and unparseable aborts startup** rather than falling back. It does not "fail safe to report-only" and must not, because either guess would be wrong — assuming report-only would leave the policy unenforced while the operator believed otherwise, and assuming enforcing would block the four components that deliberately emit inline script. The abort names the key and the two accepted values and never echoes the supplied value, so a secret pasted into the wrong variable cannot reach a log; the abort itself surfaces as an unhandled exception, which is recorded as `RISK-124` — so advancing the rollout to enforcement requires no code change. It is the **only** member of the options type bound from configuration; the policy text itself is a `public const`, so no configuration source can weaken it. There is **no** violation-report endpoint: the collector and its `report-uri` directive were removed in full, which is why the emitted value stays byte-identical to the mandated policy and why `Invoke` has exactly one path through it — verified as zero `return` statements and exactly one `await next(context)`. |

#### M-02 — No antiforgery validation on the MVC API surface

| Field | Value |
| --- | --- |
| **FINDING** | No antiforgery validation on the MVC API surface |
| **SEVERITY** | Medium |
| **CWE** | CWE-352 (OWASP A01:2021) |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs` — the whole controller, whose class-level `[Authorize]` is at `:L36`; contrast `WebVella.Erp.Web/Pages/login.cshtml.cs:L64`, which does validate |
| **DESCRIPTION** | No antiforgery attribute or global filter exists anywhere in the solution: a repository-wide search for `ValidateAntiForgeryToken`, `AutoValidateAntiforgeryToken`, `IgnoreAntiforgeryToken` and `AddAntiforgery` in `*.cs` returns nothing. The state-changing MVC API endpoints therefore accept cookie-authenticated requests with no request-bound token. The finding is correctly narrowed to the MVC surface: Razor Pages validate antiforgery by convention, which is why the login page is not affected. |
| **IMPACT** | A cookie-authenticated user who visits a hostile page can be made to issue state-changing API calls. The residual risk is reduced but not removed by the `SameSite=Lax` cookie policy the remediation added, which blocks cross-site *form* posts of the session cookie for unsafe methods. |
| **EVIDENCE** | `grep -rn 'ValidateAntiForgeryToken\|AutoValidateAntiforgeryToken\|IgnoreAntiforgeryToken\|AddAntiforgery' --include=*.cs .` returns no match at this commit. |
| **REMEDIATION** | Documented, deliberately not enforced. Existing JavaScript clients post without a verification token, so switching on validation would break working functionality — which the preservation requirement forbids. The zero-breakage half of the control (the `SameSite` and `Secure` cookie attributes) has been applied. Enforcement should be staged: emit the token in the layout, attach it from the platform's own AJAX helper, then enable `AutoValidateAntiforgeryToken` once telemetry shows no untokened callers remain. |

#### M-03 — Sign-in call not awaited

| Field | Value |
| --- | --- |
| **FINDING** | The cookie sign-in call was invoked without being awaited, so the returned task was abandoned. |
| **SEVERITY** | Medium. |
| **CWE** | [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html) — the returned `Task` is discarded, so neither its completion nor its failure is observed. The consequence maps to [CWE-703: Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html), because an exception raised inside the abandoned task is never surfaced on the request path that caused it. An earlier revision of this row asserted no identifier; both are exact and it is withdrawn. |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs:L50` — the sign-in call — and its single caller at `WebVella.Erp.Web/Pages/login.cshtml.cs:L62`. The suppression that hid the compiler warning is at `AuthService.cs:L119` and `:L161`. |
| **DESCRIPTION** | `httpContextAccesor.HttpContext.SignInAsync(...)` was called and its task discarded, so the sign-in could still be in flight when the response began, and any exception it raised was never observed. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | A race between writing the authentication cookie and completing the response, which manifests as an intermittent failure to be logged in after a correct credential, and — the security-relevant half — swallows any error raised while establishing the session, so a failed sign-in can be indistinguishable from a successful one. |
| **EVIDENCE** | The un-awaited call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | The call is awaited, which necessarily makes the method asynchronous and propagates to its single caller — the login page handler, which becomes `async Task<IActionResult>`. Traces to the **Authentication Hardening** standard's secure-session clause. That propagation is why the login page appears in this class's change set: it is compile-mandated, not opportunistic, and reverting it would break the build. **The sign-*out* counterpart was left in place at the time and has since been closed by review finding `F8`:** `Logout()` discarded the task returned by `SignOutAsync` in exactly the same way, which was recorded as observed and out of that finding's cited range. It is now `async Task LogoutAsync()`, awaited at both of its handlers, which additionally orders the server-side session revocation before the response is written rather than racing it. |

#### M-04 — Local time used for token timestamps

| Field | Value |
| --- | --- |
| **FINDING** | Token expiry was computed from local server time rather than UTC. |
| **SEVERITY** | Medium. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs:L158` — the token construction — against the correct `DateTime.UtcNow` used six lines earlier at `:L152`. |
| **DESCRIPTION** | `expires: DateTime.Now.AddMinutes(...)`. Token expiry claims are defined in UTC, so on any host not set to UTC the effective lifetime was shifted by the offset. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | West of UTC the token expires *later* than intended — silently extending session lifetime, which is the security-relevant direction; east of UTC it expires early, which is a functional defect. Either way the configured lifetime is not the actual one, and a daylight-saving transition changes it again. |
| **EVIDENCE** | The `DateTime.Now` call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | Changed to `DateTime.UtcNow`, so the claim means what it says regardless of host timezone. Traces to the **Authentication Hardening** standard's secure-session clause, since a token lifetime that shifts with the host's offset is not a bounded session. |

#### M-05 — Password hash comparison was not constant time

| Field | Value |
| --- | --- |
| **FINDING** | The legacy hash comparison used an ordinal string comparer, which stops at the first differing character, so its duration revealed how many leading characters of the stored digest were already correct. |
| **SEVERITY** | Medium — *weak cryptography* under the engagement severity matrix. |
| **CWE** | [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs:L28-L29` — inside `VerifyMd5Hash`, declared at `:L25`. |
| **DESCRIPTION** | `return (0 == StringComparer.OrdinalIgnoreCase.Compare(hashOfInput, hash));` short-circuits on the first mismatching character. The same member also returned **true** for an empty password against an empty stored digest, because both operands collapsed to `string.Empty`. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | A timing oracle lets an attacker who can measure response latency reconstruct a stored digest one character at a time, reducing recovery from a search over the whole digest space to a linear walk. The empty-against-empty case is the more direct defect: an account with no stored credential would authenticate with no password. Scope is bounded, and the bound is stated plainly: at the pre-audit revision this member had **no callers**, so neither weakness was reachable — the live credential comparison happened inside the SQL predicate at `SecurityManager.cs:L85`. It becomes reachable, and therefore matters, exactly when credential resolution is switched onto `VerifyPassword`. |
| **EVIDENCE** | The pre-audit member body is the two lines quoted above; a search of that revision finds no caller of `VerifyMd5Hash` outside the file. |
| **REMEDIATION** | Traces to the **Authentication Hardening** standard's constant-time-comparison clause. The comparison is now `CryptographicOperations.FixedTimeEquals` over equal-length byte spans, which inspects every byte regardless of where the values diverge. Casing is normalised before the comparison to preserve the case-insensitive tolerance the previous code had — normalising is not secret-dependent branching, so it does not reintroduce the oracle — and length is checked first on purpose, because fixed-time comparison is only fixed-time across equal-length spans and a length difference is not a secret that can be probed for. Absent input now fails closed on both sides, so the empty-against-empty case can no longer authenticate. **A second, distinct timing discrepancy at the *caller* level was subsequently identified as review finding `F28` and closed in a later pass.** Closing `M-05` inside the comparison did not close it: `SecurityManager.GetUser(email, password)` returned before any key derivation whenever the submitted password exceeded the 128-character bound, while an absent or legacy row still performed a 600,000-iteration dummy derivation — so latency alone answered *does this account exist*. The bound is now enforced **before** the lookup, and the dummy derivation is driven by an `out bool keyDerivationPerformed` fact reported by the verifier rather than predicted from the stored value's shape, so exactly one derivation happens on every credential path regardless of row or hash shape. Measured against a live database, the four failing paths are now indistinguishable: modern 123.0 ms, legacy 121.4 ms, corrupt 122.0 ms, absent 120.9 ms, and every over-long submission returns in 0.0 ms without touching the database. |

#### M-06 — Shared mutable hash instance used from concurrent requests

| Field | Value |
| --- | --- |
| **FINDING** | A single static, mutable MD5 instance was shared by every caller, and MD5 instances are not thread-safe. |
| **SEVERITY** | Medium. |
| **CWE** | [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html) |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs:L9` of the pre-audit revision. |
| **DESCRIPTION** | `private static MD5 md5Hash = MD5.Create();` was held for the process lifetime and used from `GetMd5Hash` without any synchronisation. Two concurrent calls could interleave inside `ComputeHash` and corrupt each other's digest. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | An interleaved computation yields a digest belonging to neither input. On a credential path that produces a spurious authentication failure at best, and a non-deterministic stored value at worst — a correctness and availability defect on a security-critical path, not merely a race in incidental code. Unlike `M-05`, this one was genuinely reachable: `GetMd5Hash` had, and still has, four live call sites across credential resolution and the two record write paths. |
| **EVIDENCE** | The single shared instance is the declaration quoted above; `GetMd5Hash` referenced it directly. Live callers at `SecurityManager.cs:L84`, `RecordManager.cs:L2017`, `DbRecordRepository.cs:L554` and `:L1856`. |
| **REMEDIATION** | Traces to the **Cryptographic Standards** block, which presumes a primitive that produces a correct digest before any question of algorithm strength arises. The shared instance was removed and replaced with the static one-shot `MD5.HashData(...)`, which keeps no shared state, is correct under concurrency and needs no lock. **Closed on the live path**, because the replacement sits in the member those four callers already use. |

#### M-07 — Unbounded script-evaluation cache holding compiled delegates

| Field | Value |
| --- | --- |
| **FINDING** | Unbounded script-evaluation cache holding compiled delegates |
| **SEVERITY** | Medium |
| **CWE** | CWE-770, CWE-94 |
| **LOCATION** | `WebVella.Erp.Web/Services/CodeEvalService.cs:L13` (the cache) and `:L46` (the unbounded insert) |
| **DESCRIPTION** | Compiled page-component scripts are memoised in a `private static readonly Dictionary<string, object>` keyed by a digest of the script text. Nothing removes an entry: the file contains no `Remove`, `Clear` or eviction call of any kind, and the dictionary is not a size-bounded cache. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | Each distinct script text permanently retains a compiled object and its loaded assembly, so a workload that generates many script variants grows process memory without bound and cannot release it. Because the cache holds executable delegates keyed only by content digest, it also lengthens the lifetime of any code a privileged author has injected. |
| **EVIDENCE** | `private static readonly Dictionary<string, object> scriptObjects = new Dictionary<string, object>();` at `:L13`; `scriptObjects[md5Key] = scriptObject;` at `:L46`; `grep -c 'Remove\|Clear\|Evict\|MemoryCache'` over the 62-line file returns **0**. |
| **REMEDIATION** | Documented, deliberately not changed — it is a resource-exhaustion concern rather than a confirmed Critical or High, and the minimal-change rule keeps it out of the remediation. The recommended fix is to replace the dictionary with a size-bounded `MemoryCache` carrying a `SizeLimit` and a per-entry `Size`, exactly as `WebVella.Erp.Web/Services/LoginThrottleService.cs` now does, so eviction is automatic and the cardinality bound is explicit. |

#### M-08 — Deterministic initialisation vector in the symmetric encryption helpers

| Field | Value |
| --- | --- |
| **FINDING** | The initialisation vector used by the symmetric encryption helpers is derived from the encryption key, so it is identical for every operation and the same plaintext always produces the same ciphertext. |
| **SEVERITY** | Medium — *weak cryptography* under the engagement severity matrix, which directs Medium findings to documentation with fix guidance rather than to remediation. |
| **CWE** | [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html) |
| **LOCATION** | `WebVella.Erp/Utilities/CryptoUtility.cs:L99`, `:L115`, `:L131` and `:L146` — the four `algorithm.IV = GetValidIV(key, …)` assignments — and the derivation helper itself, which digests the key text at `:L182` |
| **DESCRIPTION** | The vector is computed from the key rather than generated per operation, and the cipher mode is unauthenticated. A deterministic vector removes semantic security: an observer of two ciphertexts can tell whether the underlying plaintexts were equal. The mandated cryptographic standards name AES-256-GCM, an authenticated mode, which this construction is not. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Equality between encrypted values leaks, which for low-entropy plaintexts is close to leaking the values themselves, and an unauthenticated mode gives no detection of ciphertext tampering. The impact is bounded, and the bound is stated plainly rather than used to dismiss the finding: **the symmetric encrypt and decrypt members have no callers anywhere in the repository**, so no data is protected by this construction today. It is latent, not live. |
| **EVIDENCE** | The derivation helpers compute the vector from the key material; a repository-wide search finds no caller of the symmetric encrypt or decrypt members. |
| **REMEDIATION** | **Documented, deliberately not changed** — the disposition is recorded as `RISK-006` in the [risk register](risk-register.md), which carries the reasoning and the recommended fix. In short: the finding is Medium and latent, and changing the derivation or moving to an authenticated mode would make every already-persisted ciphertext undecryptable, which the requirement that existing functionality remain operational forbids. Recommended fix when a caller is first introduced — generate a fresh cryptographically random vector per operation, store it alongside the ciphertext, and prefer AES-256-GCM. Doing this *before* the first caller exists costs nothing, because there is no persisted ciphertext to migrate; afterwards it requires a re-encryption migration. Any `CA5389`, `CA5390` or `CA5401` diagnostic on that region is expected and is left visible as a warning rather than suppressed. |

#### M-09 — Anonymous access to a developer page

| Field | Value |
| --- | --- |
| **FINDING** | Anonymous access to a developer page |
| **SEVERITY** | Medium |
| **CWE** | CWE-306 |
| **LOCATION** | `WebVella.Erp.Site.Sdk/Startup.cs` — cited as `:L48`; the exemption now sits inside an `if (IsDevelopment)` block, so the locator has moved and is re-measured below |
| **DESCRIPTION** | The SDK host's Razor Pages conventions exempt `/dev` from authorization alongside the legitimate `/login` exemption, so the developer page is reachable without credentials on that host. Maps to **OWASP A01:2021 — Broken Access Control**. |
| **IMPACT** | An unauthenticated visitor reaches a developer-oriented page on the SDK host. The exposure is limited to that one host and to whatever that page renders, but it is an authentication bypass for the page in question and it widens the anonymous attack surface enumerated in this report. |
| **EVIDENCE** | `options.Conventions.AllowAnonymousToPage("/dev");` at `:L48`, immediately after the legitimate `AllowAnonymousToPage("/login")` at `:L47`. **Superseded measurement:** an earlier revision of this row read "Measured at this commit — the exemption is still present", which was true when written. The exemption is now granted only when the environment is `Development`; measured against a published Production host, anonymous `GET /dev` answers **302** to `/login?returnUrl=%2Fdev` with `content-length: 0`, and against a Development host it answers **200**. |
| **REMEDIATION** | **Production half fixed; Development half remains a documented decline.** An earlier revision of this row read "Documented, deliberately not changed … a Medium that does not act as a compensating control for any confirmed Critical or High". That reasoning was sound when written and is now **superseded**, and the reason it broke is worth stating precisely rather than quietly overwriting: it assessed the exemption *in isolation*, and the exemption is not in isolation. `/dev` renders a Blazor Server component and this host set `CircuitOptions.DetailedErrors = true`, so the anonymous page was the **delivery vehicle** for full server exception text to an unauthenticated caller — a composition that does meet the compensating-control test. Under review finding `CR2-F-07` the exemption is now **environment-gated rather than deleted**, which is both the smaller change and the one that keeps two requirements true at once: Agent Action Plan section 0.3.2 declined removal because it "would break the SDK development workflow that depends on reaching `/dev` without a session", and gating preserves that workflow exactly where it is used while a deployed host falls back to the deny-by-default `AuthorizeFolder("/")`. The two disclosures the page could reach are closed with it — `DetailedErrors` now follows the environment, and the Blazor hub, which is a **separate endpoint** carrying no authorization metadata of its own, requires authentication outside Development. The residual is that the page is still anonymous **in Development**, which is deliberate and is recorded as `RISK-113` in [the risk register](risk-register.md). Full treatment in [the remediation log](remediation-log.md). |

#### M-10 — Anonymous resource-read endpoint on the project plugin

| Field | Value |
| --- | --- |
| **FINDING** | Anonymous resource-read endpoint on the project plugin |
| **SEVERITY** | Medium |
| **CWE** | CWE-306, CWE-200 |
| **LOCATION** | `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` — the `[AllowAnonymous]` attribute on `TimeTrackJs`, at **L512** in the tree as it now stands. The original audit recorded L462, which was correct against the pre-remediation file; the guard and comment work in the same class moved it. The attribute and its action name are the durable locator, the line number is not. |
| **DESCRIPTION** | A single action carries `[AllowAnonymous]`, overriding the class-level authorization that otherwise protects the API surface, and serves a project resource read without authentication. Maps to **OWASP A01:2021 — Broken Access Control**. |
| **IMPACT** | Project resource data is readable without credentials. The scope is one read action rather than the controller, and no write path is exposed, but it is an unauthenticated data read that no requirement asks for. |
| **EVIDENCE** | `[AllowAnonymous]` at `:L462` is the only such attribute in the file; class-level authorization is confirmed present on the API surface at `WebVella.Erp.Web/Controllers/ApiControllerBase.cs:L9`. |
| **REMEDIATION** | **Partly remediated, and the remaining half is still a documented decline.** The anonymous exemption itself is unchanged, on the same governing rule as M-09 — it is a Medium that compensates for no confirmed Critical or High. What *has* changed, under review finding `F27`, is everything the exemption could be used to reach. The action served whatever resource name a caller supplied; it now admits exactly the two resource names the shipped page markup requests, through a case-insensitive map whose **value** — never the caller's string — is what reaches the resource lookup. An unlisted name is answered with the same empty script the blank-name case already returned, and **nothing is logged**, because logging refusals from an anonymous, unauthenticated, unthrottled endpoint is itself the log-volume and mail-amplification vector. A genuine packaging fault on an admitted name is recorded once per canonical name per process, under a fixed source string, with `LogNotificationStatus.DoNotNotify`, and is no longer re-thrown into the error pipeline. Verified live: sixty consecutive refusals — including traversal, a script tag, a CRLF log-injection payload and a 4,000-character name — added **zero** `system_log` rows, and a reflection-injected packaging fault driven forty-three times produced exactly **one** record. The recommended remaining fix is unchanged: remove the attribute, or move the action behind an explicit read-only policy that logs access. |

#### M-11 — Synchronous IO enabled for every request

| Field | Value |
| --- | --- |
| **FINDING** | Synchronous IO enabled for every request |
| **SEVERITY** | Medium |
| **CWE** | CWE-400 |
| **LOCATION** | `WebVella.Erp.Web/Middleware/ErpMiddleware.cs:L27` |
| **DESCRIPTION** | The platform middleware sets `AllowSynchronousIO = true` on the request's synchronous-IO feature for every request, re-enabling blocking reads and writes that the server disables by default. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Blocking IO on request-processing threads makes thread-pool starvation reachable under load, which is a denial-of-service amplifier rather than a direct vulnerability. |
| **EVIDENCE** | `syncIOFeature.AllowSynchronousIO = true;` at `:L27` — the only occurrence in the solution. |
| **REMEDIATION** | Documented, deliberately not changed. Removing the switch would break the synchronous manager code paths the platform is built on, and rewriting them is exactly the refactor the change scope forbids. The recommended fix is to convert the synchronous read and write paths to their async counterparts and then delete the switch, tracked as engineering work rather than as remediation. |

#### M-12 — Login auditing is unreachable dead code

| Field | Value |
| --- | --- |
| **FINDING** | Login auditing is unreachable dead code |
| **SEVERITY** | Medium |
| **CWE** | CWE-778 (OWASP A09:2021) |
| **LOCATION** | `WebVella.Erp.Web/Security/WebSecurityUtil.cs:L31-L95` — the entire region is commented out |
| **DESCRIPTION** | The historical login, token-login, logout and authenticate helpers — including the last-login update that would have produced an authentication audit trail — exist only as a contiguous commented-out block spanning lines 31 to 95. No live code path records authentication outcomes through them. |
| **IMPACT** | Without an authentication audit trail, credential-stuffing and password-spraying campaigns leave no first-class record, which delays detection and makes post-incident reconstruction dependent on transport-level logs. |
| **EVIDENCE** | Every `public static` member in the file (`Login` at `:L27`, `LoginWithToken` at `:L55`, `Logout` at `:L86`, `Authenticate` at `:L92`) is inside the comment; the commented run measured at lines 31-95. |
| **REMEDIATION** | **Fixed.** An earlier revision of this row said "documented, not remediated", correctly distinguishing rate-limit bookkeeping from an audit record; **a real audit record has since been added** and that verdict is retracted. `login.cshtml.cs` now calls `WriteAuthenticationAuditRecord` on all three outcomes - lockout refusal, authentication failure and authentication success - each writing a row to `system_log`. Three properties of it are load-bearing. It writes through the **core** `WebVella.Erp.Diagnostics.Log` writer, which performs a parameterized insert and nothing else, and deliberately **not** through `WebVella.Erp.Web.Services.LogService`, whose wrapper mails the entry *before* persisting it - routing a per-attempt record on an anonymous endpoint through that path would have turned the login form into an attacker-triggered mail flood and amplified M-17. `LogNotificationStatus.DoNotNotify` is passed explicitly rather than left to the parameter default. The whole write is wrapped so that a datastore fault during the insert can never fail a login, and the submitted username is length-bounded so the audit trail cannot itself become a storage-amplification vector. Only the submitted identity and the source address are recorded - never the password, request body, headers, cookies or antiforgery token. The earlier observation that the throttle is not an audit record remains true and is why both exist. Verified at runtime: neither the page nor the throttle service contains any `LogService` call, and after a successful sign-in the `last_logged_in` column of `rec_user` was unchanged. The recommended fix is a `system_log` write on both outcomes at that same entry point, carrying the account, the remote address and the result but never the submitted password; the platform's existing `LogService` already provides the write path. The dead block is deliberately left in place because deleting it is hygiene rather than remediation; it is also recorded as part of L-01. |

#### M-13 — Password length bounds of 6 to 24 characters

| Field | Value |
| --- | --- |
| **FINDING** | The password field was provisioned with a minimum length of 6 and a maximum of 24 characters — and the bounds were metadata only, enforced by nothing. |
| **SEVERITY** | Medium — *weak cryptography* in the matrix's sense, as a credential-policy weakness rather than an exploitable defect on its own. **Remediated rather than only documented**, because the mandated Authentication Hardening standard sets a 12-character minimum explicitly, and because the bound is a direct compensating control for `C-03`: a work-factored hash protects a weak password far less than a strong one. |
| **CWE** | [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html). |
| **LOCATION** | `WebVella.Erp/ERPService.cs:L216` and `:L217`, inside the password field definition at `:L202-L222`. |
| **DESCRIPTION** | Provisioning set `MinLength = 6` and `MaxLength = 24`. The **ceiling** is the more consequential half: a 24-character limit forbids passphrases outright, so it actively prevents the strongest credentials users would otherwise choose. And the bounds turned out to be declarative only — every consumer of the field's `MinLength` and `MaxLength` in the entity manager is commented out, so nothing in the platform rejected a one-character password. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | Six-character passwords are recoverable by exhaustive search at negligible cost, and with `C-03`'s unsalted MD5 storage they were recoverable instantly from a leaked column. Because nothing enforced the minimum, the effective floor was one character. The ceiling meanwhile prevented users from compensating: an operator who wanted a 40-character passphrase for an administrator account could not have one. With no account lockout either — finding `H-16` — an online guessing attack faced no barrier at all. |
| **EVIDENCE** | At the audit baseline `:L216` read `password.MinLength = 6;` and `:L217` read `password.MaxLength = 24;`. A review pass then established the enforcement gap by inspection: the `MinLength`/`MaxLength` consumers in the entity manager are commented out, so the metadata bound nothing. |
| **REMEDIATION** | Traces to the **Authentication Hardening** standard's complexity clause. The bounds are now 12 and 128, sourced from `PasswordUtil.MinPasswordLength` and `MaxPasswordLength` through the `PasswordMinLength` and `PasswordMaxLength` constants at `ERPService.cs:L50` and `:L63` and applied at `:L302-L303`, so the field definition and the validator cannot drift apart. More importantly the bounds are now **enforced** rather than declared: a single validator, `PasswordUtil.ValidatePasswordPolicy`, is applied at every boundary where a human chooses a credential — both `SecurityManager.SaveUser` branches (`:L951`, `:L1035`), the initial-administrator resolution in `ERPService`, and the generic record-write path through `RecordManager` (`:L2435`, `:L2628`) and `DbRecordRepository` (`:L752`), which is what the record API reaches. It is deliberately **not** applied inside the hashing primitive or on the legacy rehash path, because doing so would lock out existing users whose credentials predate the policy — the reasoning is recorded in the [risk register](risk-register.md), and the migration behaviour in the [credential migration guide](credential-migration.md). |

#### M-14 — No multi-factor authentication

| Field | Value |
| --- | --- |
| **FINDING** | No multi-factor authentication |
| **SEVERITY** | Medium |
| **CWE** | CWE-308 (OWASP A07:2021) |
| **LOCATION** | Architectural. **No line locator exists, and none is invented**: the finding is the absence of a construct rather than the presence of a defective one. The locator is the search itself — a repository-wide search for two-factor, MFA, TOTP or authenticator terms across every `*.cs` file returns nothing |
| **DESCRIPTION** | The platform authenticates with a single factor: an e-mail address and a password, plus an optional persistent cookie. There is no second-factor enrolment, challenge or recovery mechanism anywhere in the codebase, and no external identity provider is integrated. |
| **IMPACT** | A single leaked or guessed credential is sufficient for full account takeover, including for the administrator account. The remediation reduces the likelihood of guessing (work-factored hashing, a five-attempt lockout, rate limiting) but cannot compensate for a credential compromised elsewhere. |
| **EVIDENCE** | `grep -rniE 'two.?factor\|mfa\|totp\|authenticator' --include=*.cs .` returns no match at this commit. |
| **REMEDIATION** | Documented, deliberately not built. Adding a second factor is feature work with schema, enrolment, recovery and user-interface consequences, which the no-feature-additions boundary excludes. The recommended path is to adopt the framework's own two-factor primitives behind an opt-in policy for administrator accounts first, and it is carried as a standing recommendation in the risk register rather than as remediation. |

#### M-15 — Client library loaded from a content delivery network without an integrity attribute

| Field | Value |
| --- | --- |
| **FINDING** | A client-side library is loaded from a third-party content delivery network with no subresource-integrity attribute, and the repository's browser-side assets are unversioned. |
| **SEVERITY** | Medium — a compromise of the delivery network, or of the account that publishes to it, executes attacker-chosen script on the application's origin. Documented with fix guidance; not remediated. |
| **CWE** | [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) |
| **LOCATION** | `WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml:L124-L125` — a stylesheet and a script loaded from a public content delivery network, neither carrying an `integrity` attribute. More broadly, the repository contains 188 `.js` and 5 `.css` files and no client-side package manifest. |
| **DESCRIPTION** | Without an integrity attribute the browser accepts whatever the network returns. Because there is no client-side package manifest, the assets also have no recorded versions, so a compromised file cannot be detected by comparison. Maps to **OWASP A08:2021 Software and Data Integrity Failures**. |
| **IMPACT** | Script from a compromised delivery network runs with the same authority as the application's own script, so it can read the session and act as the user. |
| **EVIDENCE** | The script reference carries no `integrity` or `crossorigin` attribute, and no client-side package manifest exists anywhere in the repository. |
| **REMEDIATION** | **Documented, not changed.** Recommended fix: add an `integrity` hash and a `crossorigin` attribute to every externally hosted reference, or vendor the library into the repository so its bytes are version-controlled; then introduce a client-side package manifest so the browser-side assets carry recorded versions. The content-security policy this remediation introduces is a partial compensating control once it is enforced rather than report-only, because `default-src 'self'` refuses third-party origins outright. |

#### M-16 — Legacy timestamp behaviour enabled on every host

| Field | Value |
| --- | --- |
| **FINDING** | Legacy timestamp behaviour enabled on every host |
| **SEVERITY** | Medium |
| **CWE** | CWE-1254-adjacent (correctness of a security-relevant value) |
| **LOCATION** | All seven hosts: `WebVella.Erp.Site/Startup.cs:L40`, `WebVella.Erp.Site.Crm/Startup.cs:L27`, `WebVella.Erp.Site.Mail/Startup.cs:L27`, `WebVella.Erp.Site.MicrosoftCDM/Startup.cs:L29`, `WebVella.Erp.Site.Next/Startup.cs:L30`, `WebVella.Erp.Site.Project/Startup.cs:L34`, `WebVella.Erp.Site.Sdk/Startup.cs:L27` |
| **DESCRIPTION** | Each host sets the data provider's legacy timestamp switch, which changes how timestamp values are mapped between the database and the application — in particular how offsets and kinds are interpreted. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Security-relevant timestamps such as token issue and expiry, lockout windows and audit times are only as trustworthy as their time-zone handling. Inconsistent interpretation can shift a comparison across a boundary, which is why the remediation moved token timestamps to UTC explicitly rather than relying on this switch. |
| **EVIDENCE** | `AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);` measured at all seven locations listed above. |
| **REMEDIATION** | Documented, deliberately not changed. Turning the switch off changes how *already stored* timestamps are read and risks data corruption across every existing deployment, which the preservation requirement forbids. The remediation instead removed the dependence on it where it mattered, by making token timestamps explicitly UTC in `WebVella.Erp.Web/Services/AuthService.cs`. The recommended fix is a migration that normalises stored values, after which the switch can be removed host by host. |

#### M-17 — Exception details e-mailed off-box before they are persisted

| Field | Value |
| --- | --- |
| **FINDING** | The logging service sends an exception notification by e-mail before writing the record to the database, so internal detail leaves the host on a channel the platform does not control. |
| **SEVERITY** | Medium — information disclosure to an external mail relay, over an **unauthenticated** channel. Documented with fix guidance; not remediated. An earlier revision of this record claimed both conditions that made the exposure sharp had since been removed; one of those claims was wrong and is withdrawn here — see the evidence and remediation fields. |
| **CWE** | [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) and [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/LogService.cs:L41-L52` and `:L64-L76` — the notification path in both create overloads. The transport is `WebVella.Erp.Web/Services/MailService.cs:L22-L52` and `:L72-L80`, which is **not** one of the five MailKit send paths `H-11` hardened. The payload shape is bounded at `WebVella.Erp/Diagnostics/Log.cs:L81-L114`. |
| **DESCRIPTION** | The serialised log payload carries the message, the source, the exception detail and the request URL. It does **not** carry request headers, cookies or the request body, which bounds the exposure materially, though `Log.cs:L111` does include the query string. The transport is a `System.Net.Mail.SmtpClient` constructed in `MailService`, which never sets `EnableSsl` — whose framework default is `false` — so the session is plaintext, and the same relay username and password are supplied to it as `NetworkCredential`. Maps to **OWASP A05:2021**. |
| **IMPACT** | Exception text and the requested URL, including its query string, reach whatever mail infrastructure is configured, including any intermediate relay — and because no TLS is negotiated on this path, they are also exposed to any active network attacker, together with the SMTP credential itself. **This is not mitigated by `H-11`.** That finding restored certificate validation on the mail plugin's five MailKit sites; this notification uses a different client entirely and presents no certificate for any policy to act on. What does bound the impact: `ErpSettings.EmailEnabled` gates the whole path and is `false` in all eight shipped configuration files, defaulting to `false` when absent, so a default deployment never sends at all. |
| **EVIDENCE** | The notification call precedes the persistence call in both overloads. `MailService` constructs `new SmtpClient(host, port)`, assigns `Credentials = new NetworkCredential(...)` and calls `Send` with **no assignment to `EnableSsl`** anywhere in the file, and the client and message are never disposed while every exception is swallowed by an empty `catch`. The payload shape is fixed by the log record type, which serialises the URL and query string but no header, cookie or body. `Settings:EmailEnabled` is `false` in all eight tracked `Config.json` files. |
| **REMEDIATION** | **Documented, not changed** — it is a Medium and does not meet the compensating-control test that brings a Medium into remediation scope, and the plan of record excludes modifying external service integrations, requiring their risks to be documented instead. Two things genuinely narrow it, and one previously claimed mitigation does not. It **is** narrowed by `Settings:EmailEnabled` shipping `false`, so the path is inert on a default deployment; and it **is** narrowed by the closure of review finding `F26`, which replaced the twenty-eight notifying `LogService` writes on the web API surface with the non-notifying audit sink `WebVella.Erp.Web/Utils/SecurityAuditLog.cs`, so the platform's largest anonymous-reachable fault surface has no notification-eligible path left. It is **not** narrowed by `H-11`: the claim that restoring certificate validation meant this notification no longer travels over an unauthenticated connection was factually wrong — `H-11` touched MailKit, this path uses `System.Net.Mail` with TLS disabled by omission — and it is withdrawn under review finding `INT-01`. Attributing protection to the wrong control is worse than recording none, because it retires a risk that is still live. A configuration switch to enable TLS here was considered and rejected: adding another mail configuration key is precisely the out-of-plan widening that review finding `INT-08` required to be removed from the SMTP transport in the same pass, and enabling TLS unconditionally would break every deployment whose relay does not offer it. Recommended fix, in order: persist the record first and notify second so a delivery failure cannot lose the diagnostic; require TLS with certificate validation on this client and dispose it; bound its timeout; report rather than swallow its failures; and reduce the notified payload to an identifier and a severity, leaving the detail retrievable only from the database. Carried as `RISK-131`. This finding is also why the token-validation audit record added by this remediation suppresses notification — a notifying log on a path an attacker can trigger becomes a mail flood rather than a control. |

#### M-18 — The codebase's only output encoder was trivially bypassable

| Field | Value |
| --- | --- |
| **FINDING** | The platform's single output-escaping helper defended against exactly one literal string, `</script>`, by rewriting it — so any other spelling passed through untouched. |
| **SEVERITY** | Medium. It is remediated rather than merely documented because the defective encoder stands directly at a cross-site-scripting sink, which makes it a compensating control for a confirmed High finding rather than an isolated quality issue. |
| **CWE** | [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) |
| **LOCATION** | `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs:L6-L12`, the whole of a fourteen-line file: the class at `:L6`, the helper at `:L8`, and the substitution itself at `:L11`. |
| **DESCRIPTION** | The helper performed `.Replace("</script>", "</s\\cript>")` on its input before emitting it raw. The replacement is case-sensitive and whitespace-sensitive, so `</SCRIPT>`, `</script >` and `</script\n>` — all of which a browser accepts as a closing script tag — were not rewritten. A repository-wide search found no other encoder of any kind: no `HtmlEncoder`, no `HtmlEncode`, no anti-XSS library. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | Any value emitted through this helper into a script block could terminate that block and open an attacker-controlled one, which is stored cross-site scripting with the encoder's own blessing. Because it was the only escaping utility in the codebase, its weakness set the platform's effective escaping standard. |
| **EVIDENCE** | The single-string replacement is present verbatim at the pre-audit revision; searches for `HtmlEncoder`, `WebUtility.HtmlEncode` and `HttpUtility.HtmlEncode` return nothing anywhere in the repository. |
| **REMEDIATION** | Traces to the **Injection Prevention** standard's context-appropriate-output-encoding clause. Replaced with the framework's `JavaScriptEncoder`, applied to **every** `<` rather than to one spelling of one tag, so no casing or spacing variant survives. Behaviour is preserved for legitimate content: a browser parsing a JavaScript string literal converts the escape back to `<`, so rendered output is unchanged while breakout becomes impossible. The escape is computed once into a static field rather than per call, keeping the helper on its original hot path. |

### Low severity findings

#### L-01 — Dead security code retained in the tree

| Field | Value |
| --- | --- |
| **FINDING** | Three complete security classes and one wholly commented-out method body remain in the web framework, unreachable from any live path, together with ten `[AllowAnonymous]` exemptions that exist only inside comments. |
| **SEVERITY** | Low — a *minor misconfiguration* in the matrix's sense. Unreachable code is not exploitable, so the exposure is to future misuse rather than to a present attacker. |
| **CWE** | [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html). |
| **LOCATION** | `WebVella.Erp.Web/Security/AuthorizeAttribute.cs` (146 lines), `WebVella.Erp.Web/Security/AuthCache.cs` (61 lines), `WebVella.Erp.Web/Security/AuthToken.cs` (146 lines), and the commented block at `WebVella.Erp.Web/Security/WebSecurityUtil.cs:L40-L85`. |
| **DESCRIPTION** | The three classes implement a superseded authorization and token scheme — a custom authorization attribute, an authentication cache and a token type — and nothing constructs or references any of them. In `WebSecurityUtil` the entire region from `:L37` to `:L90` is `//`-commented line by line, including the two calls that would have recorded a successful sign-in. Ten further `[AllowAnonymous]` attributes appear across the tree only inside commented code, so they grant nothing. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | No present exposure: none of it executes. The risk is that a future maintainer reads a commented `AllowAnonymous`, or an authorization attribute that looks like the platform's own, and reintroduces a scheme that was abandoned for a reason — or, worse, assumes that the commented login-audit calls mean auditing exists. That second confusion is real enough to be its own finding: `M-12` records that login auditing was unreachable precisely because it lives inside this dead region. |
| **EVIDENCE** | Verified at this commit: the three files are present at the paths above with those line counts and no callers. `WebSecurityUtil.cs` carries `//            new SecurityManager().UpdateUserLastLoginTime(userId);` at `:L50` and the same call again at `:L76`, both inside the commented span, so the cited region lies entirely within dead code. A tree-wide count of commented `[AllowAnonymous]` **attributes** - as distinct from prose mentions of the attribute inside explanatory comments - returns **ten**: eight in `WebVella.Erp.Web/Controllers/WebApiController.cs` and two in `WebVella.Erp.Plugins.SDK/Controllers/AdminController.cs`, each enumerated in [the complete anonymous attack surface](#the-complete-anonymous-attack-surface). Earlier revisions of this record said twelve, carrying the plan's estimate forward instead of counting the tree; ten is measured, and none of the ten grants anything. |
| **REMEDIATION** | **Documented, not fixed** — deliberately, and the reasoning is the engagement's own: removing unreachable code is hygiene rather than remediation, and the modification boundaries forbid refactoring beyond what a security fix requires. The dead files and the commented region are therefore left exactly as they are, and recorded here so their status is unambiguous. The recommended fix for a future sprint is deletion of the three classes and the commented region in a single change that touches nothing else, after confirming with a solution-wide reference search that the absence of callers still holds. One naming trap is recorded because it has already caused confusion: the dead cache is `Security/AuthCache.cs`, while `WebVella.Erp.Web/Utils/Cache.cs` is a **different, live** 54-line memory-cache wrapper that is now the backing store for the login throttle introduced by `H-16`. The two must not be conflated. Tracked in the [risk register](risk-register.md). |

#### L-02 — Fifteen package references exist only inside XML comments

| Field | Value |
| --- | --- |
| **FINDING** | Fifteen `PackageReference` entries are commented out in the project manifests. They are not restored, not compiled against and not shipped. |
| **SEVERITY** | Low — a repository-hygiene issue with no runtime exposure. Documented for a future sprint. |
| **CWE** | [CWE-1164: Irrelevant Code](https://cwe.mitre.org/data/definitions/1164.html) — the product contains code that is not essential for execution, which raises maintenance cost and can mislead a reader about what the product depends on. That is exactly what a commented-out `PackageReference` is. An earlier revision of this row asserted no identifier on the grounds that "no weakness is present"; CWE-1164 is a maintainability weakness class rather than an exploitable one, so it applies without over-claiming, and the abstention is withdrawn. The entry still records why these references were **excluded** from the dependency findings. |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj:L51` and `:L52-L58`; `WebVella.Erp.Web/WebVella.Erp.Web.csproj:L136`, `:L137` and `:L139-L140`; `WebVella.Erp.Site/WebVella.Erp.Site.csproj:L51-L52` and `:L56`. |
| **DESCRIPTION** | Recorded because the alternative is worse than the clutter: several of the commented entries name versions that carry genuine published advisories, including an image-processing package with an out-of-bounds-write advisory and four end-of-life framework packages. Because they are not in the build graph, **none of those advisories applies to this build**, and reporting them would have put false High-severity findings into this report. Maps to **OWASP A06:2021** only in the sense of preventing a misclassification. |
| **IMPACT** | None at runtime. The risk is analytical: a future reader, or a scanner that parses manifests textually rather than resolving them, may mistake these for live references and either raise false findings or, worse, uncomment one. |
| **EVIDENCE** | All fifteen entries are inside XML comments; the dependency audit reports no advisory for any of them, and the full inventory with versions is recorded in the third-party inventory document. |
| **REMEDIATION** | **Documented, not changed.** Removing them is code hygiene rather than remediation, and the minimal-change boundary forbids refactoring beyond security fixes. Recommended fix for a future sprint: delete the commented entries, since version-control history already preserves them. Until then, treat the inventory document as the authority on which references are live. |

#### L-03 — Packaging script references manifests that do not exist

| Field | Value |
| --- | --- |
| **FINDING** | Packaging script references manifests that do not exist |
| **SEVERITY** | Low |
| **CWE** | CWE-1104-adjacent (unmaintained build tooling) |
| **LOCATION** | `create-nuget-pkgs.bat:L2-L5` |
| **DESCRIPTION** | The packaging script invokes `nuget pack` against four `.nuspec` manifests. No `.nuspec` file exists anywhere in the repository, so the script cannot succeed as written; it also spells one path `WebVella.Erp.Plugins.Sdk` where the folder on disk is `WebVella.Erp.Plugins.SDK`. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**, as a defect in the release path rather than in the application. |
| **IMPACT** | None directly — the script is already non-functional, so it cannot ship a mispackaged artifact. The concern is that a broken release path invites an ad-hoc manual one, which is how unreviewed content reaches a published package. |
| **EVIDENCE** | Four `nuspec` references at `:L2`, `:L3`, `:L4` and `:L5`; `find . -name '*.nuspec'` returns **0** files. |
| **REMEDIATION** | Documented, deliberately not changed. Repairing it is neither a security fix nor permitted under the minimal-change rule. The recommended fix is to delete the script and rely on `dotnet pack`, which the projects already support through their `PackageLicenseExpression` and related metadata. |

#### L-04 — Large binary committed to the repository

| Field | Value |
| --- | --- |
| **FINDING** | A large binary artefact is tracked in the repository. |
| **SEVERITY** | Low — no runtime exposure. Documented for a future sprint. |
| **CWE** | [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html) — a binary is shipped with no manifest, no checksum, no upstream reference and no licence file, so nothing establishes what it is or that it has not been altered. An earlier revision of this row asserted no identifier, calling it "a supply-chain hygiene observation rather than a weakness"; CWE-1357 is the supply-chain weakness class for exactly that condition, and the abstention is withdrawn. |
| **LOCATION** | `ExternalLibraries/libwkhtmltox.dll` — 29,765,120 bytes, roughly 28.4 MiB. **No line locator exists, and none is invented**: the artefact is binary, so its path and its exact byte size are the locator. It is recorded in the third-party inventory document. |
| **DESCRIPTION** | A committed binary cannot be reviewed, its provenance is not recorded, and it is not covered by the dependency audit, because that audit resolves package references rather than files. Maps loosely to **OWASP A08:2021**. |
| **IMPACT** | If the binary were ever replaced with a modified copy, nothing in the build or the audit would notice. The exposure is bounded by the fact that it is not executed as part of the application's request path. |
| **EVIDENCE** | The artefact is present and tracked; no checksum or provenance record accompanies it. |
| **REMEDIATION** | **Documented, not changed.** Deleting it is repository hygiene, not security remediation, and doing so could break whatever consumes it. Recommended fix for a future sprint: establish the artefact's provenance, record a checksum, and either move it to a package reference or to large-file storage so its integrity is verifiable. |

#### L-05 — No health endpoint, metrics, tracing or correlation identifier

| Field | Value |
| --- | --- |
| **FINDING** | No health or readiness endpoint, no metrics, no distributed tracing and no correlation identifier — four capabilities, each measured at zero. *Retitled under review finding `OBS-10`:* this row was headed "No health endpoint and no rollback tooling", and the second half was wrong — rollback guidance does exist. The accurate finding is the four zeros. |
| **SEVERITY** | Low |
| **CWE** | CWE-1059-adjacent (operational observability) |
| **LOCATION** | Repository-wide. **No line locator exists, and none is invented**: the finding is an absence. No `AddHealthChecks`, `MapHealthChecks` or health route exists in any of the nineteen projects |
| **DESCRIPTION** | There is no liveness or readiness endpoint, no metrics instrumentation, no distributed tracing and no correlation identifier. Deployment verification therefore depends on a human loading a page, and no request can be followed across a process or service boundary. Maps to **OWASP A09:2021 — Security Logging and Monitoring Failures**. *Corrected under review finding `OBS-10`:* an earlier wording of this row also claimed there was no smoke-test script and no documented rollback procedure. Both exist — see the evidence row — and the accurate residual is the four zero counts below rather than a total absence of operational tooling. |
| **IMPACT** | A security change that fails closed — the deliberate fail-fast on a missing encryption key, for example — is indistinguishable from an unrelated outage without a health signal, which lengthens time to detect and time to roll back. Two further consequences that "no health endpoint" understates. **Liveness cannot be distinguished from readiness:** the platform provisions schema and registers casts during startup, so a host can be accepting connections while still unable to serve a request, and an orchestrator has nothing to poll to find that out. **No correlation identifier crosses the SMTP boundary:** a fault notification e-mailed by the logging service carries no key tying it back to the database record written for the same fault, so an operator holding a notification can locate the persisted record only by timestamp and message text — which compounds `M-17`, where the notification is sent *before* the record exists. |
| **EVIDENCE** | Four probes across every `.cs` file in the repository, excluding build output, on the tree this commit publishes — all four return **0**: health (`AddHealthChecks`, `MapHealthChecks`, `UseHealthChecks`) **0**; metrics (`AddMetrics`, `new Meter(`, `CreateCounter`, `Prometheus`, `OpenTelemetry`) **0**; tracing (`ActivitySource`, `StartActivity`, `AddOpenTelemetry`) **0**; correlation (`CorrelationId`, `X-Correlation`, `TraceIdentifier`) **0**. What *does* exist, and what the earlier wording denied: the workflow runs a published-artifact startup smoke test that publishes and starts all eight artifacts and asserts each stops at the fail-fast secret validation, retaining `startup-smoke.txt` as evidence; and rollback guidance is documented in the credential migration guide. |
| **REMEDIATION** | Documented, deliberately not built — it is feature work outside the remediation scope, and a Low, which the severity matrix places in the *document for a future sprint* tier. Recommended fix, smallest first: (1) a readiness endpoint via `AddHealthChecks()` plus a database probe, reporting reachability and the presence of required secrets without exposing detail, so a fail-fast start is immediately distinguishable from a crash; (2) emit the framework's existing `HttpContext.TraceIdentifier` into every audit and log record — a correlation key with no new dependency and no new component; (3) include that identifier in the notification payload and subject, which closes the SMTP-boundary gap above; (4) adopt `ActivitySource` and a metrics meter behind configuration. Items 2 and 3 are small and would materially improve incident response; only item 4 is genuinely feature work. Carried as `RISK-141`. |

#### L-06 — Inert TypeScript build configuration in seven projects

| Field | Value |
| --- | --- |
| **FINDING** | Inert TypeScript build configuration in seven projects |
| **SEVERITY** | Low |
| **CWE** | CWE-1164 (irrelevant code) |
| **LOCATION** | Seven manifests: `WebVella.Erp/WebVella.Erp.csproj:L8` and `:L67-L68`, `WebVella.Erp.Site/WebVella.Erp.Site.csproj:L10-L11` and `:L72`, and the equivalent property groups in `WebVella.Erp.Site.Crm`, `.Mail`, `.Next`, `.Project` and `.Sdk` |
| **DESCRIPTION** | Seven manifests carry TypeScript build properties although the repository contains no TypeScript sources and no TypeScript compiler is invoked. The properties are evaluated and then have no effect. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | None directly. Dead build configuration is a supply-chain hygiene concern: it misleads a reader about what the build does, and a future toolchain change could give an inert property a real effect nobody reviewed. |
| **EVIDENCE** | `grep -rln 'TypeScriptCompileBlocked\|TypeScriptToolsVersion' --include=*.csproj .` returns exactly the seven manifests listed above. |
| **REMEDIATION** | Documented, deliberately not changed, on the no-refactoring-beyond-security rule. The recommended fix is to delete the properties from all seven manifests in a single hygiene change, verifying afterwards that `dotnet build` output is byte-comparable. |

#### L-07 — No lock file and an unpinned SDK version

| Field | Value |
| --- | --- |
| **FINDING** | `global.json` pinned no SDK version — the version key was commented out — so the toolchain floated, and the repository has no package lock file. |
| **SEVERITY** | Low — *minor misconfiguration* under the severity matrix. Its consequence is not a vulnerability but a loss of reproducibility in the very gates that detect vulnerabilities. |
| **CWE** | [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) for the missing lock file — a restore accepts whatever content the configured feed serves for a version range, with no recorded hash to check it against — and [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)-adjacent for the floating toolchain, since an unpinned SDK means the analyzer rule set and the audit defaults that produce this gate's evidence can change with no repository edit. An earlier revision of this row asserted no identifier at all. |
| **LOCATION** | `global.json:L3`, where the version key was commented out in a five-line, 45-byte file. |
| **DESCRIPTION** | The dependency-audit default behaviour and the analyzer rule set both vary by SDK version, so an unpinned toolchain means two developers, or a developer and a pipeline, can legitimately obtain different scan results from the same source. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | A gate whose result depends on the machine is not a gate. Without the pin, a "clean scan" claim is unverifiable by anyone else. |
| **EVIDENCE** | The pre-audit file contained `//"version": "7.0.103"` — commented out — and no `rollForward` policy; no `packages.lock.json` exists anywhere in the repository. |
| **REMEDIATION** | Traces to the **Dependency Updates** standard's pin-versions clause, applied to the toolchain rather than to a package. The SDK is pinned to `10.0.302` with **`rollForward: disable`**. An earlier revision set `latestPatch` and defended it as follows, quoted so the reasoning is not lost: both halves of the gate are selected by the SDK *feature band*, `latestPatch` holds the pin on the `10.0.3xx` band, and `disable` was rejected on availability grounds because it renders the repository unbuildable the moment this exact patch is superseded, for every developer and for CI simultaneously, in exchange for a guarantee the feature band already provides. Review findings `GATE-02` and `CR2-F-13` reversed that weighing - and the `latestPatch` interlude was itself a regression of `M-6`, which `disable` had already closed. The premise was wrong in one decisive respect: a **patch** is enough to add an analyzer rule, move a default severity or change an audit default, and every Gate 1 baseline in this remediation was measured against one exact SDK. A silent change of gate verdict is worse than a loud build failure, because nobody investigates what they cannot see. The availability cost is real, is accepted as a deliberate fail-closed, and is bounded by naming the required version in the workflow's SDK setup step, in `SECURITY.md` and in the secure-configuration guide. **The lock-file half is deliberately not done**: adding one changes restore behaviour for every project and every contributor, which is materially more invasive than the finding warrants, and the exact-version pins already present on the two most security-relevant packages give the same guarantee where it matters most. Recorded as remaining guidance rather than silently dropped. |

#### L-08 — Service-catalogue and documentation drift

| Field | Value |
| --- | --- |
| **FINDING** | Service-catalogue and documentation drift |
| **SEVERITY** | Low |
| **CWE** | CWE-1059-adjacent (documentation inconsistency) |
| **LOCATION** | **As audited:** `catalog-info.yaml:L5-L6` for the component description, `:L28-L30` for the stale pull-request link and `:L31-L33` for the link to an absent directory; `README.md:L12`, `:L18` and `:L35`; `docs/index.md:L3`; `WebVella.Erp/WebVella.Erp.csproj:L19`; `WebVella.Erp.Site/JWT_README.txt:L3`. The catalogue and `docs/index.md` items are now corrected; the residual items are enumerated under [documentation drift deferred into this report](#documentation-drift-deferred-into-this-report). |
| **DESCRIPTION** | The service catalogue descriptor advertises capabilities the repository does not contain: its description names cloud-native microservices and a serverless architecture alongside the security audit, and it links a pull request titled *Serverless Microservices Rewrite*. No container definition, orchestration manifest or serverless artifact exists anywhere in the tree. The four further drift items deferred into this report by other work in this engagement — the licence badge, the framework claim, the catalogue description and pull-request links, and the developer documentation's historical claims — are enumerated under [documentation drift deferred into this report](#documentation-drift-deferred-into-this-report). Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Inaccurate catalogue metadata misdirects a reader about the platform's actual shape and attack surface, and an inventory that overstates what exists is a weak basis for risk decisions. |
| **EVIDENCE** | At the audit baseline the `metadata.description` field and the `links` entries in `catalog-info.yaml`, read against a repository that contains no Dockerfile, no compose file and no infrastructure manifest. The absent link target was verified by enumeration: no `blitzy/` directory is tracked anywhere. |
| **REMEDIATION** | **Fixed for the catalogue, and the earlier disposition is withdrawn.** An earlier revision of this row read "Documented, deliberately not rewritten … correcting the microservices and serverless claims is the owner's editorial call on their own catalogue entry, not a security fix." That reasoning does not survive: an inventory that overstates what a component contains is a weak basis for *risk* decisions, which is the impact this very record states, and the engagement lists the catalogue among its own deliverables. `catalog-info.yaml` now describes what the repository is — a .NET 10 / ASP.NET Core modular monolith on PostgreSQL with a completed OWASP Top 10 (2021) audit and remediation — the pull-request link titled *Serverless Microservices Rewrite* is removed, the link to the absent `blitzy/documentation` directory is removed, and three links that resolve are added in their place: the audit report, the security policy and the documentation tree. Every link target was verified to exist in the tracked tree. `docs/index.md` was corrected by earlier work in this engagement. The residual drift items — the licence badge, the framework claim and the developer documentation's historical statements — remain documented rather than fixed, and are enumerated below with the reason in each case. |

#### L-09 — No server-side request forgery surface

| Field | Value |
| --- | --- |
| **FINDING** | No server-side request forgery surface |
| **SEVERITY** | Low (informational — investigated and found not applicable) |
| **CWE** | CWE-918 (OWASP A10:2021) — not present |
| **LOCATION** | Every `HttpClient` in the repository is under `WebVella.Erp.WebAssembly/Client/`; the one server-side URI construction is `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs:L539-L556` |
| **DESCRIPTION** | A10:2021 was investigated deliberately rather than assumed absent. Every outbound HTTP client in the codebase is browser-side Blazor WebAssembly code, so its requests originate from the user's browser and not from the server. No server-side code constructs an outbound request from user-controlled input. |
| **IMPACT** | None. This record exists so that the absence is evidenced rather than silently omitted, and so a future change that introduces a server-side outbound call is recognised as entering new territory. |
| **EVIDENCE** | `grep -rln 'new HttpClient(' --include=*.cs .` returns nothing; every `HttpClient` reference resolves to `WebVella.Erp.WebAssembly/Client/ApiService/*` or `WebVella.Erp.WebAssembly/Client/Utilities/HttpExt.cs`. |
| **REMEDIATION** | No remediation required, and **no fix implementation standard applies**, because no finding was confirmed — this record exists to evidence an investigation rather than a defect. If a server-side outbound call is ever introduced, it must validate the destination against an allow-list of hosts and schemes, refuse redirects to private address ranges, and be recorded as a new finding against this category. |

#### L-10 — No CI/CD pipeline existed

| Field | Value |
| --- | --- |
| **FINDING** | No CI/CD pipeline existed |
| **SEVERITY** | Low |
| **CWE** | CWE-1053-adjacent (missing build-time verification) |
| **LOCATION** | `.github/FUNDING.yml` was the only file the directory contained. **No line locator exists, and none is invented**: the finding is an absence — there was no `.github/workflows` directory, no Dockerfile and no compose file anywhere in the tree. The file created to close it cites the identifier at `.github/workflows/security-scan.yml:L3` |
| **DESCRIPTION** | Before this change the repository had no continuous-integration pipeline of any kind, so nothing verified the build, the dependency audit or the analyzer set on a push. The validation objective had nowhere to live. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | Without an automated gate, every security property asserted in this report would depend on a developer choosing to run the commands locally, and a regression — a reintroduced advisory or a reintroduced path-casing defect — could merge unnoticed. |
| **EVIDENCE** | The finding identifier is cited from `.github/workflows/security-scan.yml:L3`, the file created to close it. |
| **REMEDIATION** | **Closed, and since extended.** It answers to the engagement's automated-validation objective rather than to a fix implementation standard, since the defect was the absence of a gate rather than a weakness in the application. `.github/workflows/security-scan.yml` runs, in order: check out the repository; set up the pinned .NET SDK; assert the project graph is complete and correctly cased; assert solution membership matches the declared coverage model — every tracked project in exactly one of the solution and the explicitly-gated list; restore with dependency auditing; build with analyzers enabled and enforce the `.globalconfig` severities; list vulnerable packages including transitive dependencies; restore, build and list vulnerable packages for the two explicitly gated WebAssembly projects, whose build step also asserts each one's `TargetFramework` (finding H-18); Gate 1, failing on unreviewed security analyzer diagnostics; a positive control in which a deliberate security defect must be reported; the tracked-tree secret sweep with a repository-history audit; a Linux startup smoke test of the published artifacts; a negative control that must observe `error NU1903`; the evidence publication; and finally a blocking release gate that refuses to pass while any mandatory manual verification row is unproved. Counted from the parsed file, that is **18 named steps: 3 `uses:` actions, each pinned to a reviewed commit SHA, and 15 `run:` blocks.** Every `run:` block was extracted from the parsed YAML and `bash -n` checked — **15 / 15** pass — and each behaved as specified in both directions where a negative case exists. **Fourteen of the fifteen `run:` blocks exit 0 on this tree; the fifteenth is red by design and must not be counted with them.** The `Release gate` step was added for review finding `OBS-07`, which found that Gate 5 tallied `DEFERRED` manual rows without ever setting a failure status — so all nineteen manual Critical and High scenarios could sit unproved while the job reported success. The two steps are now a deliberate split: Gate 5 remains the honest recorder, deriving each row's status from retained evidence and failing only on a *proven* problem (a row attested `FAILED`, a missing artifact, or a malformed attestation), while the release gate refuses to pass any row that is not `PASS`/`PASS-MANUAL` and treats an absent matrix as failure rather than success. It is ordered *after* the evidence publication so a blocking verdict can never suppress the artifacts a reader needs to act on it. Because no attestation has been committed, that step fails here — which is the control working. Carried as `RISK-140`. Four corrections to earlier revisions of this row, recorded rather than quietly overwritten because each was asserted as measured: it once claimed a *test-suite step*, which the workflow has never contained and could not usefully contain because no test project exists anywhere in the 19 projects (Gate 4 is vacuous, as recorded in the methodology section); it once reported "8 / 8" `run:` steps; and it then reported "10 steps — 7 `run:` and 3 `uses:`", later "12 named steps … 9 `run:` blocks", and most recently "16 named steps … 13 `run:` blocks" — the last of these being the figure review finding `OBS-08` caught. Every one of those counts was stale by the time it was written; the current figures were re-counted from the parsed YAML at this commit, and the count changed this time for a substantive reason rather than by accretion — a new blocking step was added. |

## Part 2: Post-remediation review inventory

Findings against the controls as delivered. Identifiers in this part form their own namespace, and it is
now **disjoint from Part 1's by construction** rather than by convention.

The rule, stated once: Part 1 uses the **zero-padded two-digit** form (`C-01`–`C-05`, `H-01`–`H-20`,
`M-01`–`M-18`, `L-01`–`L-10`); Part 2 uses the **single-digit** form (`CR-1`, `H-1`–`H-9`, `M-1`–`M-7`,
`L-1`), which cannot collide with a zero-padded identifier — *except* at ten and above, where the
single-digit form of 10 and 11 is byte-identical to the zero-padded form. Part 2's tenth and eleventh
High findings therefore carry an explicit **`HR-`** prefix: `HR-10` and `HR-11`. Only those two need it,
because Part 2 has no other identifier that reaches ten.

**This replaced a documented hazard rather than a naming preference.** An earlier revision of this report
kept `H-10` and `H-11` in both parts with entirely different subjects and told the reader to "resolve an
identifier through this index, not through its shape". That left 55 canonical-looking `H-` headings across
the report where the audit inventory is 53 findings, and an index is a weaker guarantee than a namespace
that cannot collide. Two identifiers were renamed; nothing else changed, and no Part 2 identifier is cited
from source at ten or above, so no source comment needed to move.

### A note on how these findings were confirmed

Every finding below was verified against the actual repository state rather than inherited from a
plan. That mattered: **five security helpers had been added to the codebase and none of them was
reachable.** The hashing utility, the SQL identifier validator, the deserialisation binder, the
response-headers middleware and the login throttle all existed, compiled, and had **zero callers**.
Code that is never invoked provides no protection, and a review that reads only the new files would
have recorded five fixes where there were none. Several findings below are therefore of the form
*"the control exists but nothing calls it"* — which is why they are severity-rated on the
vulnerability that remained open, not on the quality of the unused helper.

### Critical severity review findings

#### CR-1 — Password hashing helpers unreachable; unsalted MD5 live on every real path

| Field | Value |
| --- | --- |
| **FINDING** | Modern salted hash-and-verify helpers were present but had no consumers, while unsalted MD5 remained the live hashing primitive at every credential read and write path. |
| **SEVERITY** | **Critical** — data breach exposure. |
| **CWE** | CWE-916 (password hash with insufficient computational effort), CWE-759 (one-way hash without a salt), CWE-208 (observable timing discrepancy). |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs`; consumers at `WebVella.Erp/Api/SecurityManager.cs`, `WebVella.Erp/Api/RecordManager.cs`, and two write paths in `WebVella.Erp/Database/DbRecordRepository.cs`. |
| **DESCRIPTION** | `HashPassword` and `VerifyPassword` existed with no callers. Credential verification instead computed an MD5 digest and compared it **inside a SQL predicate**, which is structurally incompatible with salting — a per-row salt cannot be matched by SQL equality — so the presence of the new helpers could not have changed behaviour without restructuring the query. Comparison was also a plain string equality, not constant-time. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Unsalted MD5 is effectively a non-hash for password storage: it is fast enough to brute-force at very high rates, and without a salt every user sharing a password shares a hash, so one cracked value compromises every account reusing it. Commodity rainbow tables cover it. Any disclosure of the user table — by SQL injection, backup exposure or insider access — yields plaintext passwords at scale, which are then reused against other systems. |
| **EVIDENCE** | The digest helper had zero external callers, while MD5 remained live at four sites. The security analyzers flag the primitive directly: `CA5351` (do not use broken cryptographic algorithms) fired on the MD5 usage before remediation and does not fire after it. |
| **REMEDIATION** | **Fixed.** Replaced with PBKDF2-HMAC-SHA256 at **600,000** iterations, a 128-bit cryptographically random salt per password, a versioned self-describing payload, and constant-time verification. Legacy MD5 values are still accepted and are transparently re-hashed on each user's next successful login, so no user is locked out and no reset is forced. Verification moved out of the SQL predicate into application code — the enabling change, not a cleanup. All three write paths route through the new primitive. No schema change was needed: the payload Base64-encodes to 84 characters in a `varchar(500)` column. See [the credential migration guide](credential-migration.md). |

### High severity review findings

#### H-1 — Open redirect and script-scheme injection through the return-URL parameter

| Field | Value |
| --- | --- |
| **FINDING** | A caller-supplied return URL reached redirect sinks and rendered `href` attributes without validation, so `javascript:` and protocol-relative URLs were both accepted. |
| **SEVERITY** | High. |
| **CWE** | CWE-601 (open redirect), CWE-79 (cross-site scripting). |
| **LOCATION** | `WebVella.Erp.Web/Models/BaseErpPageModel.cs` (root cause), `WebVella.Erp.Web/Pages/login.cshtml.cs`, `WebVella.Erp.Web/Components/PcPageHeader/PcPageHeader.cs`, `WebVella.Erp.Web/TagHelpers/WvPageHeader/WvPageHeader.cs`, and two SDK page models. |
| **DESCRIPTION** | The property is inherited by every page model and consumed by 48 views, 17 redirect sinks and 44 tag-helper bindings. **The finding is four code paths, not the three views originally identified:** the base property itself; a derived model that re-declared it with `new`, shadowing any fix applied to the base; a component reading the raw query string directly; and the shared back-button href sink. Maps to **OWASP A01:2021** and **A03:2021**. |
| **IMPACT** | An attacker-crafted link on a trusted origin redirects a victim to a hostile site — effective for phishing precisely because the initial hostname is genuine. With a `javascript:` scheme in a rendered `href`, a click executes script in the application's origin, yielding session theft. The shadowed path was worse still: the unsanitized value reached a local-redirect sink that threw, returning **HTTP 500 with a full stack trace to an anonymous, pre-authentication caller** — an information disclosure on the unauthenticated surface. |
| **EVIDENCE** | Confirmed at HTTP level before the fix: hostile payloads produced `500` responses, while a legitimate path produced a correct `302`. After the fix all hostile payloads produce `302` to `/`. Interactive verification found `alert(document.domain)` occurring **zero times** in the rendered HTML, and zero network requests to the attacker origin across 119 preserved requests. |
| **REMEDIATION** | **Fixed.** A sanitizing setter on the base property rejects absolute URLs, protocol-relative forms, backslash variants, control characters that split a scheme, and every scheme; empty is preserved as empty because many views render the value raw into an attribute. Both POST sinks use a local-redirect result. The shadowing declaration was removed and the sanitizer applied at the component's raw query read and the shared href sink. Control characters are rejected rather than normalised, because browsers strip tab, carriage return and newline from *within* a scheme. |

#### H-2 — SQL identifier injection: validator present, never called

| Field | Value |
| --- | --- |
| **FINDING** | A SQL identifier validation-and-quoting helper existed with zero callers, while schema identifiers continued to be concatenated into statements. |
| **SEVERITY** | High. |
| **CWE** | CWE-89 (SQL injection). |
| **LOCATION** | `WebVella.Erp/Database/DbIdentifier.cs`; sinks across the entity, record and relation repositories, the query builder, code generation, notifications and a plugin. |
| **DESCRIPTION** | Values throughout the data layer are correctly parameterised, so exposure was confined to **identifiers**, which cannot be parameterised and were interpolated directly. A systematic sweep found **19 real call sites across 7 files**, guarding over 100 identifier emission points — substantially more than the 6 sites originally enumerated. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | An identifier reaching statement construction unvalidated permits statement structure to be altered, up to arbitrary SQL execution in the database account's context — reading or destroying any data the application can reach. |
| **EVIDENCE** | The helper had no callers. Hostile identifiers were shown to be rejected and legitimate ones accepted by a dedicated harness; all four generated SQL shapes were validated against live PostgreSQL, including a counterfactual that distinguishes quoting from validation. |
| **REMEDIATION** | **Fixed.** The helper is applied at every identifier interpolation in the data layer — **24 lines across 7 files, 27 call occurrences**, verified with `git grep -n 'DbIdentifier\.\(Quote\|Validate\)' -- '*.cs'`. An earlier revision of this field said "all 19 sites"; the figure was from the finding's original sink enumeration and did not survive attachment, which surfaced further interpolations in the same layer. Identifiers are validated against a strict pattern and double-quoted, failing hard on rejection rather than passing through. Fixing only the enumerated sites would have left most of the surface open. |

#### H-3 — Unsafe polymorphic deserialisation: binder present, never attached

| Field | Value |
| --- | --- |
| **FINDING** | A serialisation binder restricting deserialisable types existed but was attached at no deserialisation site. |
| **SEVERITY** | High. |
| **CWE** | CWE-502 (deserialisation of untrusted data). |
| **LOCATION** | `WebVella.Erp/Api/Models/ErpSerializationBinder.cs`; **20** sites across the relation and entity repositories, job profiles, code generation, the job data service and the notification context. |
| **DESCRIPTION** | Polymorphic type handling was configured to resolve type names embedded in serialized payloads, with no restriction on which types could be constructed. The binder that would have constrained this was never wired in — including at one site the original enumeration omitted entirely. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | Unrestricted type resolution during deserialisation is a well-established remote-code-execution primitive: an attacker who influences a persisted payload can name a type whose construction or property setters produce arbitrary effects. |
| **EVIDENCE** | No attachment site existed. After remediation a harness of 45 assertions confirms that allow-listed types round-trip and non-allow-listed ones are refused, and that already-persisted payloads still deserialise. |
| **REMEDIATION** | **Fixed.** The binder is attached at all **20** sites and its allow-list holds **45** core-library persisted types. Type handling was **constrained rather than removed**, because already-persisted entity, relation and job payloads carry type discriminators and would otherwise fail to deserialise, breaking existing installations. **The two counts this finding uses, and the basis of each — stated once so they cannot read as a contradiction.** **45** is the number of core-library types in the `PersistedModelTypes` allow-list: 44 are the transitive closure, over data members only, of what the deserialisation sites actually read, and the 45th, `DbSystemSettings`, is a deliberate addition annotated at its entry so the `DbDocumentBase` subclass set stays complete for a collection discriminator naming the abstract base. **20** is the number of sites where `SerializationBinder = ErpSerializationBinder.Instance` is assigned in code: the **14** the original audit enumerated — `JobProfile.cs` 4, `DbRelationRepository.cs` 3, `DbEntityRepository.cs` 3, `CodeGenService.cs` 4 — plus **6** write-side counterparts found later, `JobDataService.cs` 4 and `NotificationContext.cs` 2. Earlier revisions of this document set quoted **33** types and **14** sites; both were correct measurements of earlier revisions of the code and are withdrawn as current figures. Reproduce with `grep -c 'typeof(' WebVella.Erp/Api/Models/ErpSerializationBinder.cs` bounded to the `PersistedModelTypes` initialiser, and `grep -rn 'SerializationBinder = ErpSerializationBinder.Instance' --include='*.cs' . \| grep -v '//'`. |

#### H-4 — Bearer tokens renewable indefinitely; no absolute session horizon

| Field | Value |
| --- | --- |
| **FINDING** | An anonymous refresh endpoint would renew a token without any ceiling, so a stolen token never had to expire. |
| **SEVERITY** | High — session hijacking. |
| **CWE** | CWE-613 (insufficient session expiration). |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs`; the token issue and refresh routes in `WebVella.Erp.Web/Controllers/WebApiController.cs`. |
| **DESCRIPTION** | Token refresh was reachable anonymously and imposed no absolute limit on the session's total age, so each refresh produced a fresh expiry indefinitely. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | A single token theft became a **permanent** account compromise: the holder could refresh forever without the credential, and no password change or sign-out would stop them. |
| **EVIDENCE** | After remediation, live verification confirmed the horizon at +7.000 days, returned byte-identical across refresh. The forged-token attack was proven dead **with a control**: a live horizon was accepted, while horizons in the past, exactly-now, absent and four malformed values were all refused, with no stack trace and no `500`. |
| **REMEDIATION** | **Fixed, with a documented residual.** A 7-day absolute session horizon is stamped at issue, carried verbatim across every refresh, and enforced by refusing refresh past it and capping the refreshed expiry at it. Worst-case exposure falls from **unbounded to at most 7 days with no operator action**. Rotating revocable refresh tokens were **not** implemented, because they require persisting token identifiers — a schema change the constraints forbid. Consequently sign-out does not invalidate an already-issued token. Recorded as `RISK-007`. **Improved since, by review finding `F8`:** the residual had a second half that needed no schema change at all — signing out deleted one browser cookie and revoked nothing, so a cookie copied beforehand kept authenticating for the rest of the ticket lifetime. Every ticket now carries a per-sign-in session identifier that sign-out records as revoked and that a cookie-validation hook checks on every request, which closed the **cookie** half. **Closed outright by review finding `CR2-F-02`:** the bearer half needed no schema change either, because the identifier the cookie half already used costs nothing to stamp into a token. Every issued token now carries the same `erp_session_id`, refresh carries it verbatim instead of minting a fresh one, and all three bearer decision points — the platform validator, the refresh mint site and the framework `AddJwtBearer` handler that actually authorises `[Authorize]` endpoints — refuse a revoked or unidentifiable session. Sign-out therefore ends the session for **both** credential forms; `RISK-007` is closed and only the in-process scope of the store remains, as `RISK-036`. **Made reachable by review finding `B3-SEAM-01`:** every sentence above was true of the *mechanism* and not yet of the *product*, because the shipped Blazor WebAssembly client never invoked it — its logout deleted the token from browser local storage and told the server nothing, so a bearer session in the shipped interface was still never revoked and a token copied beforehand stayed valid for its full 24-hour lifetime and refreshable under the horizon. An authenticated `POST api/v3/en_US/auth/jwt/token/logout` now delegates to the same single `AuthService.LogoutAsync` rather than duplicating any of it, and the client calls that route with the very token it is retiring before clearing its local state. The claim therefore now holds for the shipped sign-out control and not only for the machinery behind it. |

#### H-5 — Authentication ticket refreshable; declared cookie lifetime was inert

| Field | Value |
| --- | --- |
| **FINDING** | Ticket refresh was enabled, and an explicit ticket expiry silently overrode the cookie lifetime every host declared. |
| **SEVERITY** | High. |
| **CWE** | CWE-613 (insufficient session expiration). |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs`; the cookie options block in all seven `Startup.cs` files. |
| **DESCRIPTION** | The ticket permitted refresh, and no host disabled sliding expiration. Separately — and not in the original finding — all seven hosts declared an 8-hour window while the ticket was constructed with an explicit 24-hour expiry. **An explicit expiry overrides the declared window**, so the real lifetime was three times what every host declared and seven files' configuration had no effect. |
| **IMPACT** | A session that renews itself while merely open is precisely what an attacker holding a stolen cookie wants. The overridden window meant the deployed lifetime silently disagreed with the configured one — a control believed to be in force that was not. |
| **EVIDENCE** | Ticket refresh set to enabled, with zero hosts disabling sliding expiration. The override was confirmed by reading the ticket construction against the host configuration. |
| **REMEDIATION** | **Fixed, and the fix was subsequently revised — the revised form is what ships.** An earlier revision of this row recorded "ticket refresh disabled; sliding expiration disabled; expiry aligned to 480 minutes". That is retracted. The frozen session contract in force is: `ExpireTimeSpan` **1440 minutes** as an *idle* window, `SlidingExpiration` **true**, `AllowRefresh` **true**, `SecurePolicy` **`Always` unconditionally**, all supplied from a single shared configurator so the seven hosts cannot drift apart — and bounded by a **7-day absolute session horizon** stamped into the encrypted ticket at authentication. The horizon is what makes sliding renewal safe rather than indefinite: the renewal path rewrites only `IssuedUtc`/`ExpiresUtc`, so it cannot push the stamp outward, and a ticket presented past it is rejected by an `OnValidatePrincipal` handler. Worst case for a stolen cookie is 7 days rather than unbounded. Tickets issued before the change carried `AllowRefresh = false` and therefore cannot slide at all; they are deliberately not rejected outright, which would have signed out every active user on deployment. The bound is **invisible at the HTTP layer** because the ticket is non-persistent and both values live inside the encrypted payload — so it was verified by **decrypting a real server-issued cookie** (25 checks) rather than by reading response headers. |

#### H-6 — Login throttle never registered and never called

| Field | Value |
| --- | --- |
| **FINDING** | A login throttling service existed but was not registered for dependency injection and was invoked from no code path, leaving credential verification entirely unthrottled. |
| **SEVERITY** | High. |
| **CWE** | CWE-307 (improper restriction of excessive authentication attempts). |
| **LOCATION** | `WebVella.Erp.Web/Services/LoginThrottleService.cs`; `WebVella.Erp.Web/ErpMvcExtensions.cs`; `WebVella.Erp.Web/Pages/login.cshtml.cs`; the anonymous token route in `WebVella.Erp.Web/Controllers/WebApiController.cs`. |
| **DESCRIPTION** | No account lockout or attempt limiting was in force anywhere. Maps to **OWASP A07:2021**. A scope correction was required: the premise that there is a single login entry point is **factually wrong** — the anonymous bearer-token route is a second credential-verification surface. |
| **IMPACT** | Unlimited credential guessing enables password spraying and credential stuffing at machine speed. Compounded by the new hashing work factor, an unthrottled endpoint is also a CPU-exhaustion vector. |
| **EVIDENCE** | No registration and no call site existed. After remediation, interactive verification confirmed five failures then a sixth refused, and reset on success. |
| **REMEDIATION** | **Fixed.** Registered as a singleton at the single canonical registration point so all seven hosts inherit it, and consulted at **both** credential-verification surfaces. The existing generic failure message is preserved so the fix does not become a username-enumeration oracle; attempts five and six were verified **pixel-for-pixel identical**. |

#### H-7 — Four design defects in the login throttle

| Field | Value |
| --- | --- |
| **FINDING** | Key design, atomicity, cardinality and eviction defects each independently defeated the intended lockout. |
| **SEVERITY** | High. |
| **CWE** | CWE-307, CWE-362 (race condition), CWE-770 (allocation without limits). |
| **LOCATION** | `WebVella.Erp.Web/Services/LoginThrottleService.cs`. |
| **DESCRIPTION** | (1) A composite user-plus-address key meant rotating the source address reset an account's failure count. (2) Check-then-register allowed concurrent requests each to pass the check before any recorded a failure. (3) Backing the counters with a shared cache could not bound key cardinality. (4) An evicted entry silently granted unlimited attempts — fail-open. |
| **IMPACT** | Each defect alone reduces the lockout to a formality: the first via address rotation, the second via concurrency, the third by growing memory without limit through varied usernames, the fourth by evicting the record that enforces the lock. |
| **EVIDENCE** | A 46-assertion harness proves the threshold, the independence of the two counters, atomicity under concurrency, the cardinality bound and reset-on-success. One harness case exposed a **fail-closed-forever** bug introduced by the rewrite — after a lockout lapsed, the refusal check fired on a stale count, making the reset branch unreachable — which was root-caused to a single authoritative expiry rule rather than patched at the symptom. |
| **REMEDIATION** | **Fixed.** Independent per-account (5) and per-address (25) counters over a 15-minute window; an atomic reserve-then-finalise protocol; a private size-limited store; in-force lockouts pinned against eviction. The address threshold is deliberately five times the account threshold because NAT and shared egress mean many users share an address. Per-process scope, the lockout-as-denial-of-service trade-off and the eviction residual are recorded as `RISK-008`. |

#### H-8 — Security headers middleware invoked by no host

| Field | Value |
| --- | --- |
| **FINDING** | The response-headers middleware existed but was in no host's pipeline, so none of the seven mandated headers was ever emitted. |
| **SEVERITY** | High. |
| **CWE** | CWE-693 (protection mechanism failure), CWE-1021 (improper restriction of rendered UI layers), CWE-319 (cleartext transmission). |
| **LOCATION** | `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`; `WebVella.Erp.Web/ErpMvcExtensions.cs`; all seven `Startup.cs` files. |
| **DESCRIPTION** | No registration, no pipeline insertion, and no transport-security or HTTPS-redirection middleware in any host. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Absent framing protection permits clickjacking; absent content-type protection permits MIME confusion, which is what turns an uploaded file into script; absent transport security leaves credentials and session cookies exposed to network interception. |
| **EVIDENCE** | Zero pipeline insertions before remediation. After remediation, interactive verification confirmed all seven headers on **both** a dynamic response and a static file response. Re-verified later in a real browser over HTTPS across nine response classes — including two static assets that arrived `content-encoding: gzip`, which is the strongest available proof that the middleware is ordered ahead of both response compression and static-file serving — with all seven headers present on every one. |
| **REMEDIATION** | **Fixed.** Registered once at the canonical registration point and inserted **early** in all seven pipelines — ahead of response compression and both static-file middlewares, since headers registered later are absent from exactly the responses most likely to carry attacker-controlled bytes. Transport security and HTTPS redirection added, guarded to non-Development and ordered **after** CORS, because redirecting a preflight makes browsers reject it. Cookie attributes hardened and rate limiting added in the same class. |

#### H-9 — No dependency-audit or analyzer gate existed

| Field | Value |
| --- | --- |
| **FINDING** | The repository had no build-level dependency-audit or static-analysis configuration, so no security gate existed for any change to pass. |
| **SEVERITY** | High. |
| **CWE** | CWE-1104 (use of unmaintained third-party components), CWE-778 (insufficient logging of security-relevant state). |
| **LOCATION** | `Directory.Build.props` (absent); `.github/workflows/` (contained only a funding manifest). |
| **DESCRIPTION** | No `Directory.Build.props`, `Directory.Packages.props`, package-source configuration or lock file existed at the repository root, and no CI workflow of any kind. Maps to **OWASP A06:2021**. |
| **IMPACT** | Without a gate, a dependency advisory or an insecure-code pattern can enter the codebase with nothing to detect it, and the validation objective has nowhere to live. Every claim of a clean scan is unverifiable. |
| **EVIDENCE** | All four candidate build files confirmed absent; the workflow directory contained only a funding manifest. |
| **REMEDIATION** | **Fixed.** `Directory.Build.props` created with dependency auditing across all dependencies at the lowest reporting level, the dependency diagnostics promoted to **errors**, and .NET analyzers enabled. Expressed in MSBuild rather than an editor-configuration file because the four existing `.editorconfig` files each declare themselves a configuration root, so a root editor file would not reach their subtrees. A CI workflow runs restore, analyzer build and vulnerable-package listing. **Negative-tested**: injecting a package with a known advisory failed the build. ~~**Subsequently strengthened** (review finding `F2`): `AnalysisLevelSecurity=latest-all` raises the Security category alone to every rule the pinned SDK defines in it, and the auto-discovered repository-root `.globalconfig` promotes **ten of those security rules to `Error`** and holds **five** more at warning against an enumerated baseline. Measured after the change: `3096 Warning(s), 0 Error(s)`. Negative-tested in both directions: a probe with a hard-coded AES key and `new Random()` fails with real `error CA5390` and `error CA5394` lines, and with the property removed that same probe builds clean. Reintroducing the accept-all certificate callback that `H-11` removed fails with `error CA5359`.~~ ~~**That strengthening has been withdrawn in full** under review finding `GATE-03`: the plan of record freezes the analyzer gate at `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`, and both the property and the `.globalconfig` are removed from the tree, with the workflow now asserting their absence on every run.~~ **The withdrawal has itself been reversed in part, and this is the current state.** The reading that the plan froze the gate at `latest-recommended` was wrong: AAP 0.9.1 Gate 1 names **eleven** security families and sets the pass criterion "zero diagnostics in these families across the remediated files", and nine of them do not execute at that level — so the frozen reading did not preserve scope, it left Gate 1 unable to substantiate its own criterion. What has been **restored** is `AnalysisLevelSecurity=latest-all`, which selects a configuration the **SDK ships**; what stays **withdrawn** is the repository-root `.globalconfig` and every per-rule `Error` promotion, so "only the dependency diagnostic codes become errors" continues to hold exactly. The workflow still asserts that no `.globalconfig` exists in this repository — and now additionally asserts, from the post-`CoreCompile` item list, that the SDK's own `analysislevelsecurity_*_all.globalconfig` **is** loaded and that no analyzer configuration from outside the SDK is, because the previous absence check queried the item list at evaluation time, where no globalconfig has been added yet, and therefore proved nothing in either direction. The termination problem that forced the earlier full withdrawal is solved rather than avoided: it is confined to the interprocedural taint family, and `CA3001`-`CA3012` are excluded through `NoWarn`, measured — armed and untuned the solution build produced no further output for over thirty-five minutes with 3 of 17 projects finished; excluded, it completes in about **106 seconds**. **Twelve** Security-category rules now execute and are ratcheted, measured: `CA2100` **20**, `CA2326` **20**, `CA2327` 0, `CA2328` **9**, `CA5350` 0, `CA5351` **5**, `CA5359` 0, `CA5362` **1**, `CA5364` 0, `CA5390` 0, `CA5401` 0, `CA5404` 0 — **55** diagnostics reducing to **21 `(rule, file)` pairs**, each carrying a written justification in Gate 1's allow-list, which fails the job on any pair outside it. The positive control asserts all nine zero-or-newly-armed rules **must fire** against a probe containing deliberate violations, with every assertion anchored to the probe's own file so the tree's diagnostics cannot satisfy it, and asserts `CA3001`-`CA3012` **must not** fire against deliberate taint flows that provably emit `CA3001` and `CA3003` when the exclusion is removed. So the `H-11` proof survives through `CA5359`, and `CA5390` and `CA2100` are now proven to run rather than proven to be absent. Current baseline: `3094 Warning(s), 0 Error(s)` — and the per-rule figures an earlier revision quoted were **doubled**, because MSBuild emits every diagnostic twice in a solution build. One shape of the `H-11` defect is not detected by the rule and is recorded as `RISK-054`. |

#### HR-10 — Two projects outside the solution, invisible to every gate

| Field | Value |
| --- | --- |
| **FINDING** | Two projects were not solution members, so solution-wide restore, build, audit and analyzers silently skipped them. |
| **SEVERITY** | High. |
| **CWE** | CWE-1104 (use of unmaintained third-party components). |
| **LOCATION** | `WebVella.ERP3.sln`; the WebAssembly `Server` and `Shared` projects. |
| **DESCRIPTION** | The solution contained 17 of 19 projects. The two omitted were precisely the two still targeting an end-of-life framework, so the projects most in need of scrutiny were the ones excluded from it. |
| **IMPACT** | A gate that does not see a project cannot report on it. Any "clean" solution-wide result was clean only over the subset that happened to be enrolled — a false negative by construction. |
| **EVIDENCE** | `dotnet sln list` returns **17** and `dotnet list package` enumerates the same 17; `git ls-files '*.csproj'` returns **19**. The two figures deliberately do not converge: the remaining two projects are reached by dedicated restore, build and advisory steps, giving zero advisory rows across all 19 by two routes. Both non-members were confirmed to inherit every gate property by location — `dotnet msbuild <project> -getProperty:…` returns `NuGetAudit=true`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`, `EnableNETAnalyzers=true`, `AnalysisLevel=latest-recommended` and the same promoted `WarningsAsErrors` list as a solution member, and `-getItem:EditorConfigFiles` lists no global analyzer configuration for either — correctly, because none is supplied and the workflow asserts that absence on every run. An intermediate revision recorded both figures at **19** because the projects had been enrolled; that is corrected here (see `CR2-F-06` and `P-18`). |
| **REMEDIATION** | **Fixed — all three halves, membership included.** *The framework half:* both projects are retargeted to `net10.0`, so no project remains on an end-of-life framework and finding H-18 is closed. *The inheritance half was never actually broken:* `Directory.Build.props` is **directory-scoped, not solution-scoped**, so both projects inherited all six gate properties regardless of membership — verified by evaluating `NuGetAudit`, `NuGetAuditMode`, `NuGetAuditLevel`, `WarningsAsErrors`, `EnableNETAnalyzers` and `AnalysisLevel` on each directly. *The membership half is closed, but **not** by enrolment — and this cell has now said each thing in turn.* An earlier revision recorded a brief enrolment reverted on scope grounds; the next claimed the cumulative review had superseded that judgement and re-enrolled both projects, reporting `dotnet sln list` returning **19**. Review finding `GATE-01` settled it: enrolment is not an authorised edit to `WebVella.ERP3.sln`, because AAP 0.6.1 Class 1 authorises the H-19 path-casing repair and nothing else, and the review further found that carrying *both* models at once left the workflow asserting mutually contradictory coverage. The enrolment is reverted for the final time — the solution's diff against `origin/master` is casing-only, and `dotnet sln list` returns **17**. **The coverage obligation is nonetheless discharged, by the alternative the review itself named:** both projects are explicitly restored, built and audited by three named workflow steps, declared once in `env.EXPLICITLY_GATED_PROJECTS`, and the graph assertion fails closed if any tracked project is reached by neither route. Verification takes three commands rather than one and all three report no vulnerable package. The governing arithmetic is **17 solution members + 2 explicitly gated non-members = 19 tracked manifests**, asserted explicitly so the three deliberately-different figures are checked rather than left to the reader. Inheritance was never the issue and still is not: `Directory.Build.props` reaches all 19 by directory location. |

#### HR-11 — Patched object-mapping library conflicts with the declared product licence

| Field | Value |
| --- | --- |
| **FINDING** | The `AutoMapper` package was pinned to a version affected by a published High-severity advisory, and **every** patched version is licensed incompatibly with this product's declared licence — so closing the advisory and preserving the licence posture were mutually exclusive. |
| **SEVERITY** | High. |
| **CWE** | [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj` (the package pin and the `<PackageLicenseExpression>`); `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` (the single construction site an upgrade would change). |
| **DESCRIPTION** | Advisory [GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x) / CVE-2026-32933 affects every version below `15.1.1` and, separately, the `16.0.0` line below `16.1.1`. Because the pin uses exact-version notation, no transitive resolution can lift the platform onto a patched version. **The blocking fact is licensing:** `14.0.0` declares MIT, while `15.1.1`, `15.1.2`, `15.1.3`, `16.1.1` and `16.2.0` are **all** under the Reciprocal Public License 1.5. The product declares Apache-2.0 and publishes packages to nuget.org for third-party consumption. Maps to **OWASP A06:2021**. |
| **IMPACT** | Unbounded recursion in a mapping graph exhausts the stack and terminates the hosting process, so the exposure is availability loss rather than disclosure or code execution. Every host and the console application resolve mapping through this package. **Real-world exploitability in this codebase is low:** all 379 mappings are statically declared in source, and no user-controlled configuration or type graph reaches the single configuration-construction site, so the recursion path requires a self-referential mapping the project's own developers would have to author and ship. Against that, upgrading would impose a reciprocal source-disclosure obligation on every downstream consumer of the published packages — an irreversible change to the product's licensing posture. |
| **EVIDENCE** | Reproduced with the toolchain's own audit against the pre-remediation pin: `dotnet list package --vulnerable --include-transitive` reported `AutoMapper [14.0.0] 14.0.0 High https://github.com/advisories/GHSA-rvv3-g6hj-g44x` in **16 of 19 projects**. Licensing verified against the package registry rather than assumed: the `.nuspec` of all five patched releases was read, and all five declare a licence **file** resolving to the Reciprocal Public License 1.5, while `14.0.0` declares `<license type="expression">MIT</license>`. Separately, `15.1.3` declares **five** dependencies against `14.0.0`'s one, including a four-package `Microsoft.IdentityModel.*` chain at `8.14.0` — **behind** the `8.15.0` this solution already references directly. Re-measured at this commit, `dotnet list WebVella.Erp/WebVella.Erp.csproj package --include-transitive` shows that chain resolving at `8.14.0` alongside `Microsoft.IO.RecyclableMemoryStream 1.3.2`, `Microsoft.Win32.SystemEvents 10.0.1`, `NetBox 2.3.5` and `NodaTime 3.2.2`, and `--vulnerable` reports **no vulnerable package in any of the 17 solution projects**, with the two tracked projects outside the solution listed by their own dedicated steps and equally clean — **zero advisory rows across all 19**. An intermediate revision recorded this as one solution-wide command covering all 19, which held only while both WebAssembly projects were enrolled; that enrollment was reverted under `CR2-F-06`. |
| **REMEDIATION** | **Split, and only one half is closed: the advisory is closed by upgrade; the licensing consequence is OPEN, pending owner ratification, and is now mechanically blocked from shipping while it stays open.** An earlier revision of this record opened with the word *Decided* and described the licensing consequence as "formally accepted as a recorded residual". That framing was withdrawn under `CR2-F-04`: an automated remediation may close an advisory, but it may not decide — and must not appear to have decided — what licence a product declares to third parties. Recording the question as settled was absorption wearing the vocabulary of disclosure. The two halves of this finding are separable and have been separated. *The advisory:* the pin is raised to `[15.1.3]`, the newest release on the lowest patched major, and the one code change the upgrade requires — supplying `NullLoggerFactory.Instance` to the 15.x `MapperConfiguration` constructor at the repository's single construction site — is in place. `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` now reports **no vulnerable package in any of the 17 solution projects**, and two dedicated per-project listings report the same for the two tracked projects outside the solution — **zero advisory rows across all 19, by two routes rather than one** (see `RISK-030` and `CR2-F-06`; an intermediate revision claimed a single command because both had been enrolled). **No audit suppression is declared anywhere**: `Directory.Build.props` contains no `NuGetAuditSuppress` element, and the gate is green because the graph is clean rather than because a diagnostic is silenced. *The licence:* every patched release is under the Reciprocal Public License 1.5 while the product declares Apache-2.0 and publishes to nuget.org, so the reciprocal source-disclosure obligation is a real and irreversible change to the product's licensing posture. **The disposition is recorded once, in `RISK-001`, as OPEN — pending owner ratification — and the tree is left in the only state an agent may leave it in: the advisory closed, the declared licence expression unchanged, and the contradiction between the two visible at both sites in `WebVella.Erp/WebVella.Erp.csproj` rather than resolved in either direction.** Because "visible" is not the same as "cannot ship", the openness is also enforced mechanically. A target named `ErpAssertAutoMapperLicenceDecisionRecorded` runs `BeforeTargets="GenerateNuspec"` and fails packaging with `error ERPLIC001` while an RPL-licensed `AutoMapper` version is pinned and no owner decision is recorded; recording `declined-rpl-1.5` while an RPL version is still pinned fails with `ERPLIC002`; any value other than the two recognised ones fails with `ERPLIC003`, so a typo cannot be read as consent; and a failure to read the pin at all fails with `ERPLIC004`, so the gate cannot be disabled by moving the manifest it reads. **It is declared in `Directory.Build.props`, not in the project file, and that placement is itself a measured correction:** four manifests in this repository declare the same `Apache-2.0` expression and publish to nuget.org — `WebVella.Erp`, `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Mail` and `WebVella.Erp.Plugins.SDK` — and the other three each carry a `ProjectReference` to the core, so each ships a dependency reaching `AutoMapper`. With the target in the core manifest alone, packing each of the other three exited **0** and produced a package with no diagnostic; the emitted `WebVella.Erp.Web.nuspec` was read and carries `<license type="expression">Apache-2.0</license>` beside a `WebVella.Erp` dependency. Measured in ten directions across all four manifests, 26 invocations in total: `restore`, `build`, `publish`, `dotnet list package` and every CI gate step are unaffected and emit no `ERPLIC` diagnostic; `dotnet pack` fails with `ERPLIC001` and produces no package for **4 of 4**; `declined-rpl-1.5` fails with `ERPLIC002` for 4 of 4; an unrecognised value fails with `ERPLIC003` for 4 of 4; an unreadable core manifest fails with `ERPLIC004`; and packaging succeeds only once an owner supplies the decision property or declares the pinned version permissive — both of which are reviewable edits rather than side effects. Publishing is the one irrevocable action, because a package version cannot be recalled from nuget.org once a consumer has resolved it, so it is the one action gated. Three verified facts frame the decision without settling it. *First, there is no permissive escape:* the advisory's affected ranges are `< 15.1.1` and `>= 16.0.0, < 16.1.1`, so the lowest patched version is `15.1.1`; `14.0.0` is the last `14.x` release, there is no `14.0.1`, and the `.nuspec` of `15.0.0`, `15.1.1` and `15.1.3` each declare a licence **file** resolving to the Reciprocal Public License 1.5. Every patched version is reciprocal-licensed. *Second, the reversal path is no longer compatible with the gate it would have to pass through.* Retaining `[14.0.0]` requires suppressing `NU1903`, and because `AutoMapper` is present transitively in 16 project graphs a project-scoped suppression is insufficient — measured at exactly 15 residual `NU1903` errors. A repository-wide suppression, the only placement that works, is inherited by the CI negative-control probe as well, because `Directory.Build.props` is directory-scoped: the probe deliberately pins `AutoMapper 14.0.0` and *requires* its restore to fail, so suppression would disable the one step that proves Gate 2 can fail at all. That was verified by evaluating the probe's inherited properties and confirming its restore still fails with `error NU1903`. *Third, the reciprocity obligation is already satisfied in substance for this repository,* whose source is public; what is not settled is narrowly the licence **declared** to third-party package consumers. **No audit suppression is declared anywhere**, so the gate remains green because the graph is clean. |

### Medium severity review findings

#### M-1 — Deserialisation allow-list too broad

| Field | Value |
| --- | --- |
| **FINDING** | The serialisation binder allowed any type under a first-party namespace wildcard. |
| **SEVERITY** | Medium — remediated because it is the compensating control for H-3. |
| **CWE** | CWE-502 (deserialisation of untrusted data). |
| **LOCATION** | `WebVella.Erp/Api/Models/ErpSerializationBinder.cs`. |
| **DESCRIPTION** | A namespace wildcard admits every present and future type in that namespace, including types added later with no deserialisation review. |
| **IMPACT** | A wildcard weakens an allow-list toward a deny-list: the set of constructible types grows silently as the codebase grows, so the control decays without anyone changing it. |
| **EVIDENCE** | Harness assertions confirm the exact map accepts intended types and refuses everything else, including oversized and deeply nested type names. |
| **REMEDIATION** | **Fixed.** The wildcard was replaced with an **exact type map** resolved against pinned first-party assemblies, and oversized or deeply nested type names are rejected **before** resolution is attempted. |

#### M-2 — Secret validation accepted known published defaults

| Field | Value |
| --- | --- |
| **FINDING** | Configuration validation checked only that values were non-blank, required the token key only when a section already existed, and promised configuration providers the active initialisation path never consumed. Known published defaults passed. |
| **SEVERITY** | Medium. |
| **CWE** | CWE-798 (hard-coded credentials), CWE-1188 (insecure default initialisation). |
| **LOCATION** | `WebVella.Erp/ErpSettings.cs`; the four configuration-builder sites; the token routes; the bearer registration in two hosts. |
| **DESCRIPTION** | A non-blank check accepts the very placeholder values published in the repository. Environment-variable and user-secret providers were documented but not wired in, so there was no supply channel other than editing a tracked file. Maps to **OWASP A05:2021** and **A02:2021**. The plan's count of nine configuration sites was wrong; there are **four**, with five hosts inheriting the shared chain. |
| **IMPACT** | A signing key published in a public repository is a key an attacker also holds; a token endpoint signing with it lets anyone mint an administrator token. Accepting it as valid is worse than having none, because it presents as correctly configured. |
| **EVIDENCE** | A 41-assertion harness confirms the published default is rejected, a strong key accepted, blank and short keys rejected, and the entropy floor effective. Both runtime states were proven live: the application starts with secrets supplied **only** by environment variable, and refuses cleanly with no `500` and no stack trace when the key is unacceptable. |
| **REMEDIATION** | **Fixed.** Strength floors (length and distinct-character variety) plus **rejection of known published defaults by SHA-256 digest**, so neither the source nor this documentation reintroduces the secret it eliminates. Staged as warn-in-Development and fail-closed otherwise, so an existing developer checkout still starts. The provider chain now adds environment variables **after** the JSON file so they win. The token routes and the bearer registration fail closed: **an unacceptable key disables the bearer routes by design** while the scheme still exists so tokens fail validation safely. |

#### M-3 — Hash algorithm did not match the specified primitive

| Field | Value |
| --- | --- |
| **FINDING** | The versioned hash payload recorded HMAC-SHA-512 where HMAC-SHA-256 at the specified iteration count was required. |
| **SEVERITY** | Medium — remediated as part of CR-1. |
| **CWE** | CWE-916 (password hash with insufficient computational effort). |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs`. |
| **DESCRIPTION** | The stored parameters must match the specified primitive, both for compliance and so that the recorded work factor is meaningful when later evaluated for rehashing. |
| **IMPACT** | A mismatch between the specified and implemented primitive makes the work factor unverifiable, and — as the rehash policy shows — a naive correction can silently *reduce* it. |
| **EVIDENCE** | A 75-assertion harness asserts the iteration count and payload format explicitly, alongside round-trip, salt-uniqueness and fail-closed behaviour on malformed stored values. |
| **REMEDIATION** | **Fixed.** PBKDF2-HMAC-SHA256 at 600,000 iterations in the versioned format. A stored SHA-512 value is **accepted but deliberately not rehashed**, because at equal iterations SHA-512 is the more expensive primitive here, so rehashing it to SHA-256 would be a **work-factor downgrade** and would re-persist on every login for ever. An earlier claim in the source that SHA-256 and the versioned format were mutually exclusive was **false and has been withdrawn**; the remaining deviation — PBKDF2 rather than bcrypt, scrypt or Argon2 — is sanctioned by OWASP guidance and recorded as `RISK-003`. |

#### M-4 — Identifier length limit used the wrong unit

| Field | Value |
| --- | --- |
| **FINDING** | The identifier validator enforced a character count where PostgreSQL's limit is measured in **bytes**, and echoed unbounded input in diagnostics. |
| **SEVERITY** | Medium — remediated because it is the compensating control for H-2. |
| **CWE** | CWE-20 (improper input validation), CWE-117 (improper output neutralisation for logs). |
| **LOCATION** | `WebVella.Erp/Database/DbIdentifier.cs`. |
| **DESCRIPTION** | PostgreSQL truncates identifiers at 63 **bytes**, not characters, so multi-byte input passing a character check can still be truncated. The validator and the quoting function also disagreed about which name they were bounding, and diagnostics echoed caller input without bound or escaping. |
| **IMPACT** | Silent truncation can cause two distinct identifiers to collide on one physical name. Unbounded echoing of attacker input into logs is a log-injection and log-flooding vector. |
| **EVIDENCE** | A 24-assertion harness covers byte-length boundaries and hostile inputs; the quoting-versus-validation counterfactual was confirmed against live PostgreSQL. |
| **REMEDIATION** | **Fixed.** A strict character allow-list plus double-quoting is the injection control; byte rather than character semantics adopted for the length bound; the cheap length bound moved **ahead** of the regular expression so hostile input is rejected before pattern matching; diagnostics bounded and escaped; quoting and validation reconciled on the same physical name. **The bound is 67 bytes.** An interim revision reduced it to 63 and that was a functional regression, reverted at the code-review checkpoint (finding `F-07`): every one of the 21 `DbIdentifier.Validate`/`Quote` invocations, across 7 files, passes an already-prefixed name, prefixes are exactly 4 bytes (`rec_`, `rel_`), and the platform independently caps an entity or field name at 63 characters — so 63 + 4 = 67 is the longest *legitimate* physical name, and a 63-byte cap rejected entity names the platform itself accepts. The truncation-collision consequence is recorded as `RISK-010`: it is a creation-time **uniqueness** question that a helper seeing one name at a time cannot answer, and PostgreSQL truncation is deterministic, so a single over-long name resolves correctly rather than colliding. |

#### M-5 — Output helper performed replacement, not encoding

| Field | Value |
| --- | --- |
| **FINDING** | The only output-encoding helper replaced a single character, which is not sufficient for a JavaScript string context. |
| **SEVERITY** | Medium — remediated because it stands directly at a cross-site-scripting sink. |
| **CWE** | CWE-116 (improper encoding or escaping of output), CWE-79. |
| **LOCATION** | `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` and its call sites. |
| **DESCRIPTION** | A replacement list neutralises only the characters its author anticipated. In a quoted JavaScript string, a value must also neutralise quotes, backslashes and line terminators. Maps to **OWASP A03:2021**. |
| **IMPACT** | A value containing a quote or backslash breaks out of its string literal and executes as script in the application origin. |
| **EVIDENCE** | Harness assertions confirm quote, backslash, angle-bracket, newline and unicode-escape breakout attempts are all neutralised, and that a genuine JSON document round-trips byte-identically. Call sites were re-classified with comments stripped, after an initial count was inflated by matching the helper's own documentation. |
| **REMEDIATION** | **Fixed.** Split into a serialized-JSON API and a **true JavaScript-string API** backed by the framework `JavaScriptEncoder`, with the single quoted-string caller moved to the new API and JSON-document callers left on the JSON one. An **allow-list** encoder was chosen precisely because it cannot be defeated by a character its author failed to anticipate. |

#### M-6 — Toolchain pin not strict, making the gate non-reproducible

| Field | Value |
| --- | --- |
| **FINDING** | The SDK pin permitted patch roll-forward, so the toolchain that enforces the security gate could vary between machines. |
| **SEVERITY** | Medium — remediated because it underpins the dependency and analyzer gates. |
| **CWE** | CWE-1104 (use of unmaintained third-party components). |
| **LOCATION** | `global.json`. |
| **DESCRIPTION** | Both the dependency-audit defaults and the analyzer rule set vary by toolchain version, so a rolling pin means the gate's strictness is environment-dependent. |
| **IMPACT** | A build that passes on one machine can fail on another, or — worse — pass with fewer rules enforced, making a green result unreliable evidence. |
| **EVIDENCE** | The roll-forward policy was set to patch-level rather than disabled. |
| **REMEDIATION** | **Fixed.** Roll-forward disabled, pinning the SDK strictly so audit defaults and analyzer rule sets are deterministic. |

#### M-7 — Dependency inventory made unsupported claims and linked absent documents

| Field | Value |
| --- | --- |
| **FINDING** | The third-party inventory asserted clean scans and an enforcing gate that did not exist, carried stale figures, omitted security-relevant transitive packages, and linked to documents that were not present. |
| **SEVERITY** | Medium. |
| **CWE** | CWE-1059 (insufficient documentation). |
| **LOCATION** | `LIBRARIES.md`; `SECURITY.md`, `docs/security/secure-configuration.md` and `docs/security/credential-migration.md` (all absent); `mkdocs.yml`. |
| **DESCRIPTION** | Four specific defects: a claim that the advisory check reported no vulnerable packages, which was unsupported when written and later false; a stale project count contradicted by the solution fix; a version-change section describing an upgrade that had been reverted; and a blanket "clean" claim with no committed evidence. Security-relevant transitives — the cryptography library reached through the mail stack and the token-handling family — were omitted, as was all version skew. Three linked documents did not exist, and no security page was reachable from the site navigation. |
| **IMPACT** | Documentation asserting a clean security posture that cannot be reproduced is worse than none: it creates false assurance and, once a reader finds one claim false, discredits the accurate parts too. Broken links defeat the documentation deliverable outright. |
| **EVIDENCE** | A link audit found exactly three absent targets, all others resolving; the site navigation contained a single home entry, so every security page was unreachable. |
| **REMEDIATION** | **Fixed.** Each false claim was **withdrawn explicitly rather than silently edited**, and replaced with quoted command output and reproduction commands. Security-relevant transitives and a version-skew section were added, including the four-package chain that the reverted upgrade would have introduced. The licensing escalation became a **recorded decision**. The three absent documents were created, all links repaired, and a security section wired into the navigation. `mkdocs build --strict` passes. |

### Low severity review findings

#### L-1 — Mandated policy publicly replaceable; report-only with nowhere to report

| Field | Value |
| --- | --- |
| **FINDING** | The mandated Content-Security-Policy value was exposed through a writable property, so it could be replaced at runtime by a blank or weaker value with nothing to detect it, and the policy was emitted in report-only mode with no endpoint to receive reports. |
| **SEVERITY** | Low. |
| **CWE** | CWE-16 (configuration), CWE-778 (insufficient logging). |
| **LOCATION** | `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`. |
| **DESCRIPTION** | A settable property allows the mandated policy to be weakened or replaced at runtime with nothing to detect it. Report-only mode without a collection endpoint discards every violation, so the staged rollout produces no evidence and can never progress. |
| **IMPACT** | A policy that can be silently replaced provides no guarantee. A report-only policy with no collector is indistinguishable from no policy at all: it blocks nothing and records nothing. |
| **EVIDENCE** | The value is now a compile-time constant, so weakening it is a compilation error rather than a runtime possibility. `Invoke` was verified to contain **zero** `return` statements and exactly one `await next(context)`, so there is a single path through the middleware and every response reaching it is written by the same call. **What that single path attaches needs one qualification, and an earlier revision of this cell omitted it:** the **six fixed headers** are attached to every covered response unconditionally, while `Strict-Transport-Security` — the seventh — is attached only outside the Development environment. That is not a gap in the single path but a decision taken once in the constructor (`SecurityHeadersMiddleware.cs:L43-L71`, `emitStrictTransportSecurity`), mirroring the guard every host already applies to `UseHsts()`/`UseHttpsRedirection()`, because HSTS is browser-persisted for a year and would pin the whole `localhost` origin for a developer who loaded the application once. It guards on the ENVIRONMENT rather than on `Request.IsHttps`, so a production deployment behind a TLS-terminating proxy still receives it, and it fails **safe**: an unresolvable environment emits the header. The emitted `Content-Security-Policy-Report-Only` value was captured from a running host and compared byte-for-byte against the mandated directives; `report-uri` is absent, and `POST /csp-violation-report` no longer resolves to an anonymous 204 but falls through to the ordinary pipeline, which carries the same set. |
| **REMEDIATION** | **Fixed, then corrected.** The value was made immutable (`public const`, compiler-enforced). An intermediate revision also added a real collection endpoint at `/csp-violation-report`, handled inside the middleware ahead of routing and authentication, together with a 120-reports-per-minute logging cap to close a **CWE-779 log-flooding** vector it introduced. **That endpoint and its `report-uri` directive were subsequently removed in full**, on review, for two independent reasons: the `report-uri` directive meant the emitted header no longer matched the value the audit mandates, and the collector's early return gave the middleware a path that completed a request **without attaching the other six headers** (`CFG-02`, `CFG-04`). Removal was chosen over re-ordering the branch because re-ordering leaves a second path a future edit can reintroduce the defect into, whereas removal makes it structurally impossible. The half of this finding about *reporting* is therefore answered differently than first implemented: violations are read from the **browser console** for the duration of the report-only rollout, which carries the same blocked-URI and violated-directive information without adding an anonymous write-accepting route; a deployment wanting aggregation should terminate `report-to` at a reverse proxy or dedicated collector, outside this middleware. `RISK-005`, which existed only to record the logging-versus-acceptance trade-off, is **retired** — the vector was deleted along with the component that carried it. The staged rollout remains progressable: the report-only/enforcing switch is now bound from configuration, so advancing it requires no code change (`RISK-022`). |

### Additional observations

Confirmed during verification, outside this checkpoint's finding scope. Recorded so they are neither
lost nor mistaken for regressions. Each is tracked in [the risk register](risk-register.md).

- **A ninth location containing secret material.** A setup instructions text file in one host carries
  token configuration guidance referencing the signing key, in addition to the eight configuration
  files enumerated by the audit. Found by the secrets sweep; recorded under the secret-management
  finding so the enumeration is complete.
- **~~Stack-trace disclosure on the bearer-token route is live and unconditional.~~ Closed, and it has
  its own record.** A failed token request was confirmed to return exception text, including a method
  trace, to an **anonymous** caller, and because the path was not guarded by any environment check,
  setting the environment to Production did **not** suppress it — a code change was required. That
  observation is what escalated the condition into finding `H-13` in Part 1, where the remediation and
  its subsequent widening to every response sink in the tree are recorded. It is retained here because
  the runtime confirmation is the evidence, and because the reasoning that a configuration change would
  not have been sufficient was established at this point rather than assumed later.
- **~~A permissive `Access-Control-Allow-Origin: *` is live on one host.~~ Closed — it is live on
  none.** Originally confirmed on the login response of two hosts across three independent verification
  runs, then narrowed to one. Both hosts now serve an explicit origin allow-list and retain
  `AllowAnyOrigin()` only inside explanatory comments. The two superseded counts are quoted rather than
  deleted because both were published as this finding's status.
- **Analyzer evidence for the cryptography work, stated precisely.** The broken-algorithm rule
  `CA5351` **still fires five times**, and this is expected rather than a failure — but it must not be
  reported as a clean result. One occurrence is in the credential utility, on the **legacy MD5
  verification retained deliberately** so existing users are not locked out; it will disappear once the
  last legacy hash has been upgraded, and removing it sooner would break backward compatibility. The
  other four are in the encryption utility, which belongs to the **secret-management** vulnerability
  class and is **not** part of this checkpoint's findings. The weak-transport rule `CA5359` fired five
  times on the mail transport's certificate-validation bypass, likewise a different class; that class
  has since been remediated and the rule reports nothing there now. The
  defensible before-and-after statement is narrower than "the rule stopped firing": **no `CA5351`
  occurrence remains on any live password-hashing path** — every credential read and write now routes
  through PBKDF2, and the single remaining occurrence is on the compatibility path only.

- **The shipped configuration files were not scrubbed by the checkpoint this section reports on — they
  have been since.** As reported here, all eight contained development connection strings with
  passwords, a development-mode flag set true, and the published token signing
  key. **That scrub has since landed**, in a later pass: all eight files now carry empty secret values
  and `"DevelopmentMode": "false"`, `web.config` sets `Production`, and the seeded administrator
  password is no longer a literal. The *enabling* half had landed first and made it possible — the
  provider chain that lets operators supply secrets externally, and validation that **rejects the
  published defaults** so a historically published signing key disables the bearer routes rather than
  being trusted. `RISK-021` is closed for the tracked files; the residual is `RISK-026`.
- **Enforcing the Content-Security-Policy needs two directives the mandated policy omits entirely** —
  an image directive permitting `data:` URIs, because framework markup emits a 1×1 GIF spacer, and a
  worker directive permitting `blob:`, because the source editor loads a syntax worker. Both currently
  fall through to the default directive and would break images and the editor on first enforcement.
- **The inline-emitting surface is wider than the four components originally identified**, additionally
  implicating a rich-text editor, a lazy-loading web-component bundle (inline style *and* `eval`), and
  the source editor.
- **Three navigation anchors use a `javascript:` placeholder href** — framework dropdown toggles,
  byte-identical on every page. **These are not injection sinks**, and are named so a future scan hit
  is not misread.
- One page returns HTTP 500 because its page model does not derive from the type its layout requires;
  **proven pre-existing by counterfactual**. Two vendored source-map files answer 405 rather than 404.
  One page's document title disagrees with its visible heading. Four accessibility advisories were
  observed. None is a security finding.
- **A fifth live upload route exists that the finding inventory does not enumerate.**
  `WebVella.Erp.Web/Controllers/WebApiController.cs:L3459-L3477` binds `UploadFile` to
  `POST /fs/upload/` and accepts any type at any size: no extension allow-list, no size cap, no
  content-type check and no name sanitisation reach it, and its `file` argument is not null-guarded. Four
  working field components call it — `PcFieldImage` and `PcFieldFile`, design and display — which is why
  it was documented and raised as an owner decision rather than constrained unilaterally. Its residual is
  **bounded and measured, not merely asserted**: the escalation half of the unrestricted-upload chain is
  already closed for it, because the repository's **only** `return File(` — the shared download action at
  `:L3455` — forces an attachment disposition for every extension outside its inline set, and `.html`,
  `.htm`, `.svg`, `.xhtml`, `.xml` and `.js` were each confirmed absent from that set. The route also
  sits behind the controller's class-level `[Authorize]`. What remains is an unbounded read and an
  unconstrained stored type — **not** stored cross-site scripting.

  **Two corrections to this bullet, both of them later than the checkpoint it reports.** The route itself
  was subsequently **hardened**: review finding `F-09` routed it through the same
  `GetUploadRejectionReason` pre-validation as the other four actions — null guard, 25 MB cap, extension
  allow-list, content-type consistency check and filename sanitisation, all before any stream read — so it
  is no longer an unvalidated route and the owner decision it was raised as no longer stands open. What
  remains of it is the *transport-level* half, which the pre-validation cannot reach because model binding
  has already buffered the body: that residual is tracked as
  [`RISK-146`](risk-register.md) in the risk register. **This citation has now been wrong twice, and both
  corrections are recorded rather than the latest one simply presented as if it had always been right.** It
  first cited `RISK-033`, whose entry describes the SMTP certificate-validation posture and never described
  this subject. It was then corrected to `RISK-133` — which is also wrong, because that identifier heads
  *External storage writes are not compensated when the database transaction fails*. The register's own
  renumbering table settles it: this subject is `RISK-146`, entered new because it had been cited from two
  documents while having no entry anywhere. It is cited without an anchor because `RISK-146` is a summary
  row, not a detailed entry.

## Part 3: Product vulnerabilities first discovered by reviewing the remediation

The findings in Parts 1 and 2 came from the audit of the product and from the review of the delivered
controls. The findings below came from a **code review of the remediation itself**, and each one is a
genuine product vulnerability that the original audit had not reached. They are recorded in the same eight-field format and are **not** a separate class
of finding — a vulnerability found by reviewing a fix is still a vulnerability in the product.

They are presented separately for one reason only: so that a reader can see how much of the platform's
current protection exists because the audit's own output was independently reviewed rather than trusted.

**Three of them, `P-21`, `P-22` and `P-23`, came from a different route again** — QA passes that drove the
remediated build in a real browser rather than reading it. That distinction is worth keeping rather than
smoothing away, because the two routes fail differently. Code review found the gaps that are visible in a
diff; the runtime passes found a stored payload that rendered as inert text on a screen an earlier class had
remediated and then **executed one click away** on a screen no class had reached, and later found a fifth
render path for a value pair four separate fixes had already guarded. Neither route would have found the
other's findings, and the runtime ones could only have been found with the application running.

`P-23` is worth reading for a second reason: its root cause was not insufficient care but an **assembly
boundary**. The guard that closed the first four paths lived in a plugin, and the framework cannot reference
a plugin that references it, so that guard was structurally incapable of covering the widest path of the
five. The reusable lesson is in the count it got wrong — it enumerated *the paths that had been fixed* rather
than *the sinks that consume the value*.

### Review-discovered product vulnerabilities

#### P-01 — Every stored password hash readable through the public query-language route

| Field | Value |
| --- | --- |
| **FINDING** | The credential redaction added for C-02 covered the record-manager and repository read projections but not the entity query language. Any caller holding read access on the user entity could retrieve every stored password hash through a supported, documented public route. |
| **SEVERITY** | Critical — data breach exposure of every credential in the installation. |
| **CWE** | [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html), [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| **LOCATION** | `WebVella.Erp/Eql/EqlCommand.cs`, the `ConvertJObjectToEntityRecord` projection seam, reachable through the public query action on `WebVella.Erp.Web/Controllers/WebApiController.cs` |
| **DESCRIPTION** | The redaction was applied at three projection seams and missed a fourth. The omission was not an oversight of enumeration but a **circular dependency**: the credential lookup in `SecurityManager.GetUser` read the stored hash out of an EQL projection, so that projection could not redact without breaking login. The route is not anonymous — class-level authorization applies — but it is reachable by any authenticated caller with read access on the user entity, which the regular role holds. Maps to **OWASP A01:2021 Broken Access Control** and **A02:2021 Cryptographic Failures**. |
| **IMPACT** | An ordinary authenticated user could export the full credential table and attack it offline at leisure. Because the platform retains legacy unsalted digests until each user next authenticates, a meaningful share of those hashes were crackable by lookup rather than by brute force. |
| **EVIDENCE** | Verified at runtime against a live database: a projection through the public query route returned the hash before the fix and the redaction marker after it, for `SELECT *`, for an explicit field list and through a related-record projection. |
| **REMEDIATION** | **Fixed** by breaking the circular dependency rather than by widening the projection rule. `SecurityManager.ReadStoredPasswordHash` was added — an `internal static`, parameterized, single-column, single-row read used only by the authentication path — so the login flow no longer needs the hash to be present in any projection. `EqlCommand.ConvertJObjectToEntityRecord` then redacts **unconditionally**, reusing `DbRecordRepository.RedactEncryptedFieldValue` rather than duplicating the rule, so the four seams cannot drift apart. The write-side sentinel guard was re-verified as source-agnostic, so a redaction marker round-tripped back through an update still cannot overwrite a real hash. This change also removed a latent regression in the version-4 seed-credential revocation, which had been reading the hash the same way and would have silently stopped revoking. |

#### P-02 — SQL identifier injection in dynamic `ORDER BY` construction

| Field | Value |
| --- | --- |
| **FINDING** | Sort field names were concatenated into `ORDER BY` clauses without validation or quoting. |
| **SEVERITY** | Critical — arbitrary statement execution against the application's database role. |
| **CWE** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **LOCATION** | `WebVella.Erp/Database/DbRecordRepository.cs` — three separate sort-construction regions: the distinct-select pre-pass, and two query branches each of which has both a JSON branch and an else-branch, giving **four** vulnerable call sites |
| **DESCRIPTION** | The audit's identifier-injection finding (H-09) enumerated six concatenation sites and closed them with the `DbIdentifier` helper. It did not reach the sort path. The review cited one site; reading the sort construction end-to-end found three regions and four call sites, so fixing only the cited one would have left three open. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | A caller able to influence a sort term could append arbitrary SQL to a read query, reaching the full authority of the application's database role — which provisioning requires to be a superuser. |
| **EVIDENCE** | Six injection payloads were driven through the sort path against a live database. After the fix all six were skipped and no `DROP TABLE` executed, with a positive control confirming the harness could observe a refused query rather than silently passing. |
| **REMEDIATION** | **Fixed** with a single audited helper, `BuildSortColumnReference(Entity, string)`, applied at all four call sites. It resolves each sort identifier against entity metadata and quotes both the table and the column through `DbIdentifier`. An unresolvable field is **skipped** rather than rejected, deliberately matching the semantics the JSON branch already had, so legitimate sorts — ascending, descending, multi-term, related-field and quick-search — remain byte-identical. Verified separately. |

#### P-03 — Stored cross-site scripting in six Project widget views

| Field | Value |
| --- | --- |
| **FINDING** | Six Project plugin widget views emitted database text — usernames, task keys, task subjects, icon classes, colours and avatar paths — as unencoded markup. |
| **SEVERITY** | High — stored cross-site scripting executing for every user who opens a project dashboard. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **LOCATION** | Root cause in the composition code: `PcProjectWidgetTaskDistribution.cs`, `PcProjectWidgetTasksQueue.cs` and `PcProjectWidgetTimesheet.cs`. Symptom visible in their six `Design.cshtml` and `Display.cshtml` views. |
| **DESCRIPTION** | H-06 identified the widget views as stored sinks but scoped them to a later stage. The important discovery on returning to them is that **the views were the wrong place to fix**: the code-behinds compose HTML strings from database values, and the views merely emit the finished fragment. Encoding in the view would have encoded the server's own tags and broken every widget. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Any user who can set a task subject or a display name — ordinary project members — could execute script in the browser of every colleague who opened the dashboard, on the application's own origin. |
| **EVIDENCE** | Verified with an HTML parser rather than a substring scan, because a substring assertion cannot distinguish an encoded payload from an absent one. Server-authored elements and attributes survive; injected markup does not. |
| **REMEDIATION** | **Fixed at the root cause.** Ten untrusted interpolations are passed through the framework HTML encoder at the point of composition, while server-authored markup around them remains literal. Avatar images and task links still render, and output is byte-identical for legitimate content. One residual is documented rather than fixed: a seeded content snippet in an older project plugin patch populates an intentional-HTML field, whose remediation would require a stored-options data migration that the change scope forbids. It is recorded in [the risk register](risk-register.md). |

#### P-04 — No object-level authorization on the file endpoints

| Field | Value |
| --- | --- |
| **FINDING** | Upload, download, move, delete and staged-file promotion could each be driven against another user's file. The uploading user was also never persisted. |
| **SEVERITY** | Critical — insecure direct object reference over arbitrary stored files, with a destructive verb. |
| **CWE** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html), [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs` file routes; `WebVella.Erp/Database/DbFileRepository.cs`; `WebVella.Erp.Web/Services/UserFileService.cs`; `WebVella.Erp/Api/RecordManager.cs` staged-promotion paths |
| **DESCRIPTION** | H-08 covered upload type and size constraints and the inline-download escalation. It did not establish **who** may act on a given file. Two further problems compounded it: the temp-namespace check for staged promotion omitted its trailing separator, so a sibling path such as `/tmpfoo/...` satisfied it; and because the uploader was never recorded, simply adding an ownership check would have denied the legitimate owner. Maps to **OWASP A01:2021 Broken Access Control** and **A04:2021 Insecure Design**. |
| **IMPACT** | Any authenticated user could read, relocate or delete any other user's stored file by referencing its path, and could promote an arbitrary stored file into a record they controlled. |
| **EVIDENCE** | Verified against a live database across both the repository primitives and the shipped upload-to-save workflow, including negative controls proving a non-owner is refused and positive controls proving the legitimate owner still succeeds. |
| **REMEDIATION** | **Fixed.** Validation is bounded and performed **before the request body is read**; extensions are allow-listed; a size cap and magic-byte signature verification are applied; caller-supplied filenames are sanitised; non-image downloads are forced to attachment disposition and a null MIME type falls back to `application/octet-stream`; and move and delete are owner-predicated **compare-and-swap** operations so a concurrent change cannot slip between check and act. The uploading user is now persisted at every upload site. Staged promotion is constrained to the temp namespace with the separator included and pinned to the authorized row, at both the create-path and update-path twins. Authorization-failure logging is best-effort so it can never convert a refusal into a server error. |

#### P-05 — Deserialisation allow-list admitted side-effecting infrastructure types

| Field | Value |
| --- | --- |
| **FINDING** | The type allow-list added for H-10 resolved its membership by namespace reflection, admitting 267 types — 41 of which were name-shaped as side-effecting infrastructure such as repositories, services and contexts. |
| **SEVERITY** | High — a materially wider deserialisation surface than the control implied. |
| **CWE** | [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |
| **LOCATION** | `WebVella.Erp/Api/Models/ErpSerializationBinder.cs` |
| **DESCRIPTION** | A namespace-scoped allow-list is only as narrow as the namespaces happen to be. Because persisted model types share namespaces with infrastructure types, the binder admitted far more than the payloads required. Maps to **OWASP A08:2021 Software and Data Integrity Failures**. |
| **IMPACT** | The control read as a strict allow-list while behaving as a broad one, which is worse than an obviously permissive control because it discourages further scrutiny. |
| **EVIDENCE** | A discovery harness enumerated every wired polymorphic site — more than the review listed, including two the audit had not recorded — and measured the required closure against what the binder admitted: **33 types required, 267 admitted, 234 surplus, 0 required types missing.** |
| **REMEDIATION** | **Fixed** by replacing namespace reflection with an **exact enumerated** `Type` allow-list. *The count in this cell was **33** when it was written and is **45** now: a later narrowing under review finding `F-03` re-derived the list as the transitive closure over data members only, which is a different and stricter basis than the 33-type DTO measurement recorded here. The canonical basis for both the type count and the site count is in the `H-10` record in Part 1.* `BindToName` output is byte-identical, so already-persisted payloads still round-trip; every wired site was re-verified against real persisted entity, relation and job payloads; and a gadget-shaped type outside the list is rejected, with a positive control proving the test can observe admission. Independently corroborated by the static-analysis gate: `CA2327` reports **zero** while `CA2326` reports twenty, which is machine-checked proof that a binder is attached at every polymorphic site. |

#### P-06 — Permissive cross-origin policy still live at the second host

| Field | Value |
| --- | --- |
| **FINDING** | H-14 was specified for two hosts and landed at only one. `WebVella.Erp.Site.Project` still registered an any-origin default CORS policy and applied it. |
| **SEVERITY** | High — any website a signed-in user visited could issue cross-origin requests to the host and read the responses. |
| **CWE** | [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html) |
| **LOCATION** | `WebVella.Erp.Site.Project/Startup.cs` — the policy registration, applied by the `app.UseCors()` call in the same file |
| **DESCRIPTION** | The commented-out restrictive policy immediately above the live registration made the file *look* remediated on a quick read, and the sibling host's completed fix made the class look closed. Every aggregate check stayed green: the solution built, the warning census was clean, and no review finding named the file. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Cross-origin read access to authenticated responses from any origin, for the duration of a victim's session. |
| **EVIDENCE** | Found by enumerating **live versus commented** occurrences per host rather than by searching for the presence of a fixed shape. Confirmed against a running host before and after the change. |
| **REMEDIATION** | **Fixed** with an explicit allow-list drawn from **this host's own** commented-out policy, which names four origins — it allows one more than the sibling host, so a copy of the sibling's list would have broken a working client. Those four origins are now supplied through `Settings:Cors:AllowedOrigins` rather than written into source, and serve as the fallback **only** when that key is absent *and* `ASPNETCORE_ENVIRONMENT` is `Development`; a non-development deployment with no key configured denies every origin. `AllowCredentials()` is deliberately not added, because the framework rejects it alongside any-origin and adding it now would widen behaviour rather than preserve it. Verified against a running host in that development configuration: all four listed origins are echoed back with `Vary: Origin`; unlisted origins — a wholly external one, the literal `null` origin, and trailing-slash, case-altered, host-altered and scheme-altered variants of a listed origin — receive no header at all; the same host in `Production` with no key configured echoes **none** of the four; and the load-bearing ordering holds — a plaintext preflight is answered by CORS with `204` and no `Location`, while a non-preflight plaintext request to the same host still receives `307`. A repository-wide sweep confirms **zero** live any-origin registrations remain. |

#### P-07 — Plugin patches re-granted the guest permissions the seed revokes

| Field | Value |
| --- | --- |
| **FINDING** | Two plugin patches re-granted anonymous guest permissions on the user and role entities after the core seed and the version-4 migration had removed them. |
| **SEVERITY** | Critical — privilege escalation restored on every deployment that loads either plugin. |
| **CWE** | [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html), [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) |
| **LOCATION** | `WebVella.Erp.Plugins.SDK/SdkPlugin.20201221.cs` and `WebVella.Erp.Plugins.Project/ProjectPlugin.20211012.cs` |
| **DESCRIPTION** | Both patches call `EntityManager.UpdateEntity`, which **replaces** the entity's whole record-permission set rather than merging into it. Each therefore silently reinstated the guest grants that C-02 and C-05 exist to remove. This is why an earlier investigation concluded the stray grants were environmental contamination from another working copy: that measurement was taken with a harness that loads no plugins. **That conclusion was wrong and is retracted here** — the grants were a real product defect. Maps to **OWASP A01:2021 Broken Access Control**. |
| **IMPACT** | Anonymous callers regained create permission on the role entity and read and create permission on the user entity — a direct path to creating a privileged account without authenticating. |
| **EVIDENCE** | Proven on a **fresh** database rather than the shared one: 24 of 24 checks pass after running the SDK patch chain, and 24 of 24 again after the Project patch chain. A three-way comparison ruled out laundering by the harness's own ordering. |
| **REMEDIATION** | **Fixed** by removing all **four** guest grants from both patch files: create on `role`, read and create on `user`, and read on `role`. The read grant on `role` was initially retained on the premise that the sign-in page resolves role metadata before a user is authenticated. That premise is false — role hydration runs inside `SecurityContext.OpenSystemScope()` in `SecurityManager.GetUser`, so login never consults the Guest grants — and the version-5 migration revokes the grant under review finding `F17`. Because plugin patches run *after* the migrations, a patch that re-added it was the last write and left `F17` open on every freshly provisioned installation; the per-startup reconciliation now re-asserts the version-5 shape rather than the version-4 shape, so it cannot be reopened. |

#### P-08 — The version-4 migration emitted schema DDL

| Field | Value |
| --- | --- |
| **FINDING** | The migration that secures the password field's metadata did so through a field-update path that issued schema DDL. |
| **SEVERITY** | Medium — a constraint violation rather than an exploitable weakness, but one that could damage a production database. |
| **CWE** | [CWE-710: Improper Adherence to Coding Standards](https://cwe.mitre.org/data/definitions/710.html) |
| **LOCATION** | `WebVella.Erp/ERPService.cs`, the version-4 password-field metadata step |
| **DESCRIPTION** | The step called the entity manager's field-update path, which rebuilds the column: it emitted `ALTER TABLE`, `ALTER TABLE` and `DROP INDEX`. The remediation's own constraints forbid schema changes, and this one operated on the column holding every credential. |
| **IMPACT** | An index drop and two column alterations against the credential column during an upgrade, on a platform with no rollback tooling. |
| **EVIDENCE** | Measured with a database **event trigger** writing to a table, not by reading a server log — a pooled-connection client cannot reliably observe its own DDL in stderr output. Before: three DDL commands. After: zero. |
| **REMEDIATION** | **Fixed** by replacing the rebuild with an in-place metadata mutation that updates the stored field definition and clears the cache, retaining the permission guard. The migration remains idempotent and emits **zero** record-schema DDL. One boundary is stated precisely rather than absolutely: a full provisioning run still emits six pre-existing bootstrap commands — two extension creations and two cast creations with their drops — which belong to platform bootstrap, not to this migration, and are recorded in [the risk register](risk-register.md). |

#### P-09 — Unbounded regular expression accepted by the record-filter endpoint

| Field | Value |
| --- | --- |
| **FINDING** | Two endpoints accepted an arbitrary caller-supplied regular expression and placed it in a PostgreSQL `WHERE` predicate, which the server evaluates once per row, under a ten-minute command timeout. |
| **SEVERITY** | High — remote denial of service reachable by any authenticated caller, with no privilege beyond read access to one entity. |
| **CWE** | [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html), [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs`, `GetRecordsByFieldAndRegex`; and `WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml.cs`, the `FilterType.REGEX` branch. Both reach `WebVella.Erp/Database/DbRecordRepository.cs`, `case QueryType.REGEX`. |
| **DESCRIPTION** | The pattern was bound as a parameter, so this was never an injection seam — it was a **cost** seam. Cost is linear in the product of the pattern's explicit repetition bounds, and that cost is paid per row of a table scan. `Find` set a 600-second command timeout; `Count`, which every paged list issues beside its page, set none and inherited the connection string's 120 seconds. A separate defect sat on the same line: the pattern was read with `Expando`'s indexer, which throws `KeyNotFoundException` for an absent key, so a request omitting `"pattern"` produced an unhandled fault rather than a `400`. |
| **IMPACT** | A single request could hold a pooled connection and a CPU core for the full ten minutes; with `MaxPoolSize=100`, a handful of concurrent requests exhausts the pool and denies service to the whole application. One pattern shape did not even need to execute: it exhausted memory while being **compiled**. |
| **EVIDENCE** | Measured against PostgreSQL 16 over a 20,000-row probe table. `^(a{1,120}){1,120}$` took **3,944.9 ms**, `^(a{1,64}){1,64}$` **1,385.4 ms**, `^(a{1,32}){1,32}$` **372.3 ms** — linear in the product of the bounds (14400, 4096, 1024). `^(a{1,200}){1,200}$` failed while compiling, attempting a **1.6 GB** allocation. The textbook payload was **disproved** as a threat on this engine: `^(a+)+$` returned in 16.8 ms amplified over 20,000 rows and in **0.5 ms** against a single adversarial 10,000-character subject, because PostgreSQL's hybrid DFA/NFA never takes the backtracking path for a boolean predicate. A `statement_timeout` of two seconds was confirmed to cancel a running regex scan at 2000.334 ms. |
| **REMEDIATION** | **Fixed** in two independent layers. A new `WebVella.Erp/Database/DbRegexPattern.cs` caps the **product** of explicit repetition bounds at 256 — admitting a worst case of ~107 ms per 20,000 rows — plus a length cap, a quantifier count cap, and refusal of back-references and stacked quantifiers. The bound is on the product rather than on nesting deliberately: a nesting ban also refused `\d+(\.\d+)*` and `^(a+)+$`, both measured harmless, while covering nothing extra. It is enforced at the predicate-generation seam, not in the controller, so the SDK filter page is covered without being modified. Second, a regex-carrying query now executes under a 60-second timeout in both `Find` and `Count`, while non-regex queries keep 600 seconds exactly; a client command timeout was chosen over `SET statement_timeout` because `CreateConnection` returns a transaction-bound shared connection, so a session-level setting could truncate an unrelated statement. The controller additionally reads the pattern defensively, closing the `KeyNotFoundException`. Verified by 73 assertions plus an end-to-end run against the live database: `^admin` still returned 1 of 2 users, the attack pattern was refused in 0 ms, and the refusal carried no pattern echo, stack trace or internal type name. Recorded as review finding `CR2-F-03`. |

#### P-10 — Anonymous developer page composed with Blazor detailed errors into a server-exception channel

| Field | Value |
| --- | --- |
| **FINDING** | The SDK host granted `/dev` an unconditional anonymous exemption, configured `CircuitOptions.DetailedErrors = true`, left the Blazor circuit endpoint anonymous, and served files of unrecognised type from its web root. Together these gave an unauthenticated caller a channel for full server exception text. |
| **SEVERITY** | Medium — information disclosure to an unauthenticated caller on one of seven hosts, with no privilege required. |
| **CWE** | [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html), [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html), [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html), [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html) |
| **LOCATION** | `WebVella.Erp.Site.Sdk/Startup.cs` — the `/dev` Razor Pages convention, the `AddServerSideBlazor` circuit options, the `UseStaticFiles` options and the `MapBlazorHub` endpoint registration |
| **DESCRIPTION** | The audit recorded the anonymous page alone, as `M-09`, and accepted it as a Medium compensating for nothing. Assessed in isolation that was correct; assessed in composition it was not. `/dev` renders a Blazor Server component, and `CircuitOptions.DetailedErrors` is precisely the switch deciding whether an unhandled exception inside a component is returned to the browser with its message and stack trace or replaced by an opaque circuit identifier. This host is the only one of the seven that configures Blazor Server at all, and it hard-coded that switch true in a host that ships to Production. `MapBlazorHub` carries no authorization metadata of its own and is a **separate endpoint** from the page that starts it, so gating the page alone would have left the hub — where component code and its exceptions actually execute — reachable anonymously. Separately, and uniquely among the seven hosts, `ServeUnknownFileTypes = true` with `DefaultContentType` unset meant any file under the web root whose extension is unmapped was served without a session and without a `Content-Type`. Maps to **OWASP A05:2021 Security Misconfiguration** and **A07:2021 Identification and Authentication Failures**. |
| **IMPACT** | An unauthenticated caller could obtain internal type names, absolute file paths and call stacks from a deployed host, and could open a server-side circuit that consumes a connection and executes component initialisation. The static-file divergence additionally meant anything a build step or operator left in the web root — `.config`, `.pem`, `.bak`, `.cs`, `.cshtml`, `.pdb`, all unmapped — was downloadable anonymously. |
| **EVIDENCE** | **The exposure was live, not latent**, which an anonymous fetch established rather than inferred: the `/dev` response carried a Blazor server component descriptor — `<!--Blazor:{"type":"server","prerenderId":"…","descriptor":"CfDJ8…"}-->` — the protected payload a client presents to `/_blazor` to open a circuit. The static-file divergence was confirmed **upstream** rather than remediation-introduced: `git show origin/master` shows six hosts setting `false` and only this one setting `true`. Verified after the fix against a published Production host: anonymous `GET /dev` → **302** to `/login?returnUrl=%2Fdev` with `content-length: 0` and the page's three marker strings counting **0** in the served body, live DOM and visible text; anonymous `POST /_blazor/negotiate` → **400** with a **0-byte** body and no `connectionId` or `connectionToken`. |
| **REMEDIATION** | **Fixed, with a deliberate Development residual.** `ConfigureServices` was handed no `IWebHostEnvironment` — which is why neither of its two disclosures could be made conditional — so the class now takes one by constructor injection, following the pattern `WebVella.Erp.Site/Startup.cs` already uses, and a single `IsDevelopment` expression serves all three decision points. It **fails secure**: any environment name that is not exactly `Development` selects the hardened branch. The `/dev` exemption is **gated rather than deleted**, honouring the plan's own refusal to remove it, so the SDK workflow survives on a developer machine while a deployed host falls back to deny-by-default; `DetailedErrors` follows the environment and is deliberately **not** configuration-driven, because a configuration key would let the disclosure be switched back on in Production; and `MapBlazorHub` requires authorization outside Development. `ServeUnknownFileTypes` is set `false` only after being **verified non-load-bearing**: of the 600 files in the published web root exactly one extension is unmapped, `.br`, every `.br` and `.gz` file has an uncompressed sibling, no asset references a `.br` URL, and compression is negotiated through `UseResponseCompression` rather than by extension. Authenticated behaviour was measured, not assumed: `/dev` still returns **200** with all three markers and the circuit endpoint still returns **200** with a well-formed negotiate payload, and a Development control host still serves both anonymously. Recorded as review finding `CR2-F-07`; the Development residual is `RISK-113`, which also closes `M-09`'s Production half. |

#### P-11 — Pre-login hook exception text reflected to the anonymous login page

| Field | Value |
| --- | --- |
| **FINDING** | The login page's pre-login hook `catch` assigned `ex.Message` directly into the page's own error banner, on a page marked `[AllowAnonymous]`. |
| **SEVERITY** | Medium — information disclosure on the authentication path, reachable without credentials. |
| **CWE** | [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html), [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html) |
| **LOCATION** | `WebVella.Erp.Web/Pages/login.cshtml.cs`, the `catch` around the `ILoginPageHook.OnPostPreLogin` loop in `OnPost` |
| **DESCRIPTION** | This is the same disclosure class as `H-13`, at the one place on the authentication path that still carried it, and it is **pre-existing**: `git show origin/master` shows the identical `catch (Exception ex) { Error = ex.Message; … }` block. Hooks are plugin extension points executing with full platform access, so their faults routinely carry connection strings, SQL fragments, absolute paths, internal type names and configuration keys — and an anonymous caller could provoke them at will simply by posting the login form. Because the message was also *distinct* from the two generic refusal messages the same handler already used, it doubled as an oracle. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Any unauthenticated visitor could harvest internal fault detail from the login form, and could distinguish "a hook faulted" from "those credentials are wrong" — a probe for plugin behaviour and, wherever a hook faults only for accounts that exist, a username-enumeration oracle. |
| **EVIDENCE** | The reflected sink was the page's own banner, rendered at `login.cshtml:13` as `<div class="alert alert-danger">@Model.Error</div>`. Verified after the fix in a real browser against a Production host: the banner reads exactly `Invalid username or password` (`textContent` equality true, length 28 of 28), and the page source contains **0** occurrences of `"   at "`, `Exception`, `Npgsql`, `.cs:line`, `StackTrace` and `Server=` in both the served body and the live DOM, with 23 further defensive probes also at 0 and neither the submitted address nor the submitted password echoed anywhere. |
| **REMEDIATION** | **Fixed.** The fault is recorded server-side through `SecurityAuditLog.RecordApiFault` and the response carries the platform's existing generic refusal message, so **the detail changed audience rather than being discarded**. `RecordApiFault` was chosen over a general log write for four properties specific to this site: it is **rate limited per source**, so an anonymous caller cannot amplify a repeated fault into unbounded log volume; it passes `DoNotNotify`, so it can never reach the mail path of `M-17` and turn this endpoint into an attacker-triggered mail bomb; it **cannot itself throw**, which matters in a catch block where a throwing audit call would replace the very fault being recorded; and it uses a fixed literal source, because `Log.GetLogs` filters source with `ILIKE` and a stable value is what keeps this queryable in the log viewer the platform already ships. Nothing legitimate is lost: the hook contract's channel for showing a message is to **return** an `IActionResult`, which the loop honours immediately, and a hook holds the page model so it can set `Error` itself — throwing was never that channel, and the platform's only `ILoginPageHook` implementation returns null and never throws. The message is byte-identical to the handler's two other refusals, deliberately, to remove the oracle. Recorded as review finding `CR2-F-08`. |

#### P-12 — Encryption key strength measured in characters while the derivation silently discarded it in bytes

| Field | Value |
| --- | --- |
| **FINDING** | The encryption key's length and character-variety floors counted **characters**, while `CryptoUtility` derived the AES key and initialisation vector through an ASCII projection that **substituted** every character above U+007F with `?` instead of failing. A key could therefore satisfy both floors and still derive to a single repeated byte. |
| **SEVERITY** | Medium — weak cryptography under the governing severity matrix, raised by the review as `CR2-F-09`. |
| **CWE** | [CWE-331: Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html), [CWE-176: Improper Handling of Unicode Encoding](https://cwe.mitre.org/data/definitions/176.html) |
| **LOCATION** | `WebVella.Erp/ErpSettings.cs`, the `Settings:EncryptionKey` acceptance chain and the shared `IsAcceptableSecretShape` floor; `WebVella.Erp/Utilities/CryptoUtility.cs`, `GetValidKey` and both return paths of `GetValidIV` |
| **DESCRIPTION** | This record is **dual-natured, and the two halves have different origins** — which is the reason it was invisible to both the audit and the first review round. The lossy sink is **pre-existing**: `git show origin/master` shows the identical `Encoding.ASCII.GetBytes` projection at all three sites, in a file whose `ErpSettings` counterpart was 125 lines long and validated the encryption key not at all beyond falling back to the misspelled `Settings:EncriptionKey` spelling. The **false assurance is remediation-introduced**: closing `C-04` and `M-2` added a 32-character length floor and an 8-distinct-character variety floor above that unchanged projection, and a comment justified measuring characters by asserting that these values are "consumed as strings, not as HMAC input" — an assertion that was false for this one setting. The remediation did not create the entropy loss; it created a control that appeared to prevent the entropy loss while measuring a quantity the derivation then discarded. Maps to **OWASP A02:2021 Cryptographic Failures**. |
| **IMPACT** | A deployment following the guidance to choose a strong, varied passphrase — rather than the recommended hexadecimal string — could supply a key that passed every check and protected data at rest with almost no key material. In the limiting case two entirely different keys produce byte-identical AES keys, so data encrypted under one decrypts under the other, and the initialisation vector collapses and collides with them because it is derived from the same text. Because the substitution is silent, nothing in the logs, the configuration or the start-up output would ever indicate it: the operator's evidence of a strong key is the key they typed. **The exposure is bounded at this commit, and the bound is stated rather than left flattering:** a census of the tree finds **no live caller** of the symmetric encrypt or decrypt surface — its only references outside its own file are two commented-out lines in the dead `AuthToken.cs` — and **no consumer** of `CryptKey` or `ErpSettings.EncryptionKey` anywhere else, so no in-tree code path encrypts stored data through it today. What was live is the other half: start-up validation runs on every host boot, and it would have accepted such a key and reported it as satisfying an eight-distinct-character variety floor. The realistic population at risk is therefore a deployment carrying its own plugin code, or an older build, that does use the primitive. |
| **EVIDENCE** | Measured against the built assembly before any change, not reasoned about. A 32-character key of 32 **distinct** non-ASCII characters satisfied `IsAcceptableSecretShape` and `HasSufficientCharacterVariety` and derived to `3f` repeated 32 times — **one** distinct byte where the variety floor demanded eight. A second, different key of the same shape derived **byte-identically**, and `GetValidIV` collapsed and collided with it. A realistic mixed passphrase, `Sécurité-Clé-2026-WebVella-ERP-x1`, lost one byte of key material per accent while containing no literal `?` of its own. The substitution granularity was established as **per UTF-16 code unit**, not per Unicode scalar: `U+1F600` derived to `3f3f` while the single-code-unit `U+4E2D` derived to `3f` — which is what makes the byte count always equal the character count, and therefore makes recovery length-preserving and exact. |
| **REMEDIATION** | **Fixed at both halves, by making the two layers agree rather than by duplicating one inside the other.** `CryptoUtility` routes all three projection sites through one helper that refuses non-ASCII material instead of substituting it, and `ErpSettings` requires the configured encryption key to be US-ASCII, under which one character is exactly one byte and the existing character-measured floors become byte-exact. Re-implementing the byte projection inside `ErpSettings` was rejected as the alternative: the derivation sizes itself from `SymmetricAlgorithm.LegalKeySizes`, so a copy would be a second thing to keep in step and would recreate this very finding in a new place. The false comment was **corrected in place rather than silently overwritten**, because that premise is what allowed the divergence. Both diagnostics name only the setting and the rule — never the value, its length, the offending character or its position — so neither can leak key material into a console or a crash report. Backward compatibility was verified by capture and re-derivation, not asserted: for an all-ASCII key the derived key bytes, the derived initialisation vector and the resulting ciphertext are **byte-identical** before and after the change, and ciphertext written before it still decrypts. Scoped deliberately to the encryption key and not to the connection string, whose password may legitimately be non-ASCII and which Npgsql consumes as a string rather than as key bytes. Recorded as review finding `CR2-F-09`; the recovery path for a deployment that already encrypted data under a non-ASCII key is `RISK-114`, and the accepted character set is documented in the secure configuration guide. |

#### P-13 — Two co-hosted hosts shared one authentication cookie name with no application-scoped key isolation

| Field | Value |
| --- | --- |
| **FINDING** | `WebVella.Erp.Site.MicrosoftCDM` and `WebVella.Erp.Site.Crm` both named their authentication cookie `erp_auth_crm`, and **no** Data Protection configuration existed anywhere in the repository, so the application discriminator and the key ring were both left at their framework defaults. |
| **SEVERITY** | Low — a minor misconfiguration under the governing severity matrix, raised by the review as `CR2-F-11`. |
| **CWE** | [CWE-1004: Sensitive Cookie Without HttpOnly Flag — related family](https://cwe.mitre.org/data/definitions/1004.html), [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html), [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| **LOCATION** | `WebVella.Erp.Site.MicrosoftCDM/Startup.cs` (the cookie name), `WebVella.Erp.Site.Crm/Startup.cs` (the colliding name), `WebVella.Erp.Web/ErpMvcExtensions.cs` (the absent Data Protection configuration) |
| **DESCRIPTION** | **Pre-existing, and proven so.** `git show origin/master` carries `erp_auth_crm` in *both* host startup files, so the collision was not introduced by the remediation; and a tree-wide search for `AddDataProtection`, `SetApplicationName`, `PersistKeysTo` or `ProtectKeysWithCertificate` returned no matches at all, so nothing had ever configured the stack that protects the cookie. The two facts compound. A cookie is scoped by domain and path and **not** by port or by application, so two hosts served from one host name see each other's cookie on every request; whether that is untidy or a cross-application authentication flaw depends solely on whether the second host can *decrypt* the first host's ticket. The framework's default discriminator happens to be derived from the content-root path, which provides accidental isolation for hosts in different directories — and no isolation at all for two hosts sharing a key ring and a path, while also silently invalidating every session whenever a host is republished to a new directory. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Two failure modes, one worse than the other. The visible one is a cookie-overwrite loop between the two hosts, which merely breaks sign-in. The unbounded one is a host accepting a ticket minted by a *different* application, which would let a session established against one host's permission model be replayed against another's. Separately, and affecting all seven hosts, transient default keys mean a container restart or a scale-out invalidates every issued cookie, producing intermittent, unattributable logouts that look like an application fault rather than a configuration one. |
| **EVIDENCE** | Verified at runtime rather than reasoned about, with two hosts published and run concurrently under `Production` over HTTPS and pointed **deliberately at one shared key directory** — the worst case, because a shared key ring removes the accidental isolation a default configuration would have supplied. Real logins produced `erp_auth_sdk` and `erp_auth_mscdm` respectively, each `Secure; SameSite=Lax; HttpOnly`. Each host accepted its own ticket (`200`) and refused the other's (`302` to `/login`), in both directions. A separate differential test isolated what the change actually buys: the same application republished to a **different content root**, against the same key ring, accepted a ticket minted at the original path (`200`) — the outcome the path-derived default would have turned into a forced sign-out for every user. A census of all seven hosts confirmed seven distinct cookie names with no duplicates. |
| **REMEDIATION** | **Fixed.** The colliding cookie is renamed to `erp_auth_mscdm` on the MicrosoftCDM host alone, because `erp_auth_crm` is the correct name for the CRM host and renaming both would be a gratuitous second sign-out. Data Protection is configured once, at the single canonical registration point, so all seven hosts inherit it: the application discriminator is bound to the host's application name — guarded against an empty value, since an empty discriminator would be worse than the default — and an **opt-in** `Settings:DataProtectionKeyDirectory` sets a durable key repository. The setting is opt-in rather than defaulted because a directory invented here would be no more durable than the framework default while being harder to reason about, and a path that cannot be created fails at start-up rather than being swallowed. No package was added; both controls come from the shared framework. Encrypting the key ring at rest is **not** attempted, because every supported encryptor needs deployment-provided certificate material, a Windows-only facility, or a new dependency the plan forbids; it is carried as `RISK-115` with the two ways to close it. Users are signed out once at the deployment that adopts this — on every host because the discriminator changed, and additionally on MicrosoftCDM because its cookie name changed — and that consequence is documented in the secure configuration guide rather than discovered in production. |

#### P-14 — Internal file-storage locations left populated in the tracked configuration files

| Field | Value |
| --- | --- |
| **FINDING** | All eight tracked `Config.json` files shipped a populated `FileSystemStorageFolder`, and the SDK host additionally shipped a populated `CloudBlobStorageConnectionString`. The values named an internal host by IP address in a UNC path and a local disk path — nine values across eight files that the credential scrub had passed over. |
| **SEVERITY** | Low — a minor misconfiguration and information disclosure under the governing severity matrix, raised by the review as `CR2-F-12`. |
| **CWE** | [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html), [CWE-1188: Insecure Default Initialization of Resource](https://cwe.mitre.org/data/definitions/1188.html) |
| **LOCATION** | `WebVella.Erp.Site/Config.json`, `WebVella.Erp.Site.Crm/Config.json`, `WebVella.Erp.Site.Mail/Config.json`, `WebVella.Erp.Site.MicrosoftCDM/Config.json`, `WebVella.Erp.Site.Next/Config.json`, `WebVella.Erp.Site.Project/Config.json`, `WebVella.Erp.Site.Sdk/Config.json` (two values), `WebVella.Erp.ConsoleApp/Config.json` |
| **DESCRIPTION** | **Pre-existing, and it survived the remediation for an instructive reason.** The values are present at `origin/master`, and the H-04, H-05 and H-12 scrub cleared *credentials* — connection strings, signing keys, mail passwords, encryption keys — and stopped there. A UNC path is not a credential, so a credential-shaped sweep does not see it; it is internal-topology disclosure, which is a different weakness class that happens to live in the same files. This is the second finding in this review round whose root cause is a control that measured the wrong quantity. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | A published repository disclosed an internal host address, a share name and a directory layout — reconnaissance that shortens the path from an initial foothold to a file server, and that is disclosed to everyone who clones the repository rather than only to an attacker who reached the host. One of the two settings is additionally credential-bearing: `CloudBlobStorageConnectionString` is a connection string, so committing a real value there discloses a credential outright rather than only a location. |
| **EVIDENCE** | All nine values were located by regex with a strict one-occurrence-per-key assertion per file, replaced, and re-verified: every file still parses after comment stripping, every BOM and the absence of a trailing newline were preserved byte-for-byte, and a per-file diff shows exactly one changed line each (two for the SDK host). A whole-worktree sweep then found the internal address still printed in full **inside the security documentation**, which would have relocated the disclosure rather than removed it; it was redacted there too, and the sweep now returns zero hits across tracked and untracked files alike. A published host was run under `Production` with all nine values blank and reached HTTP 200 with **zero** start-up errors. |
| **REMEDIATION** | **Fixed.** All nine values are blank in the tracked files and are supplied externally when the feature is used, with both keys and their environment-variable forms documented in the secure configuration guide. Blanking is safe because `ErpSettings` substitutes a placeholder for a blank storage folder and both `EnableFileSystemStorage` and `EnableCloudBlobStorage` are `false` in every shipped configuration, so no host reads either value in its default posture — verified by running one. The documentation copy carries no address at all: it is written as `[REDACTED — host:port, SHA-256 prefix 72858cca8cb5df2d]` under [the redaction convention](#how-compromised-historic-values-are-written-in-this-document-set), which replaced an earlier partial abbreviation. Redacting an address in the current revision does not undo its original disclosure: any internal name or address that was ever committed should be treated as public and restricted at the network layer. Recorded as review finding `CR2-F-12`. |

#### P-15 — A closed toolchain-pin finding was reopened by a later change to the same setting

| Field | Value |
| --- | --- |
| **FINDING** | `global.json` carried `"rollForward": "latestPatch"`, allowing the build to select an SDK patch that no one had reviewed. The same setting had already been remediated once, under finding `M-6`, whose record reads *"Fixed. Roll-forward disabled"*. |
| **SEVERITY** | Low — a minor misconfiguration under the governing severity matrix, raised by the review as `CR2-F-13`. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components — reproducibility family](https://cwe.mitre.org/data/definitions/1104.html), [CWE-1188: Insecure Default Initialization of Resource](https://cwe.mitre.org/data/definitions/1188.html) |
| **LOCATION** | `global.json`, the `rollForward` value and the comment that justified it |
| **DESCRIPTION** | This record exists because the interesting fact is not the setting but the **regression**. `M-6` was raised, fixed by disabling roll-forward, and closed. A later change reintroduced the band under a reasoned comment arguing that a patch band was preferable because it kept the toolchain receiving fixes. That argument is defensible in general and wrong for this repository specifically, because this build *is* the security gate: `Directory.Build.props` promotes the NuGet audit diagnostics to errors and enables the analyzer set, so the SDK version determines which advisories are reported and which analyzer rules run. A gate whose ruleset can change without review produces evidence that cannot be reproduced, and a green run stops meaning what it claimed. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Two builds of the same commit could apply different analyzer rulesets and different audit behaviour, so the audit evidence recorded in this report was not reproducible by construction. A regression to a *newer* patch is also silent: nothing fails, the ruleset simply differs, which is the failure mode hardest to notice and easiest to mistake for a fixed baseline. |
| **EVIDENCE** | The regression was established from the repository's own history rather than inferred: the remediation log already recorded roll-forward being changed *to* `disable` under `M-6`, while five other passages across four documents actively defended `latestPatch`, and the audit report's `M-6` record still read *"Roll-forward disabled"*. Six documented positions on one setting, in mutual contradiction. After the change, `dotnet --version` reports exactly `10.0.302`, solution restore exits `0`, and a full `-t:Rebuild` of all seventeen solution members plus both explicitly-gated projects exits `0` with zero errors and **zero** authoritative `(file,rule)` analyzer differences against the previous baseline. |
| **REMEDIATION** | **Fixed, and the contradiction removed rather than left standing.** `rollForward` is `disable`, so a mismatched SDK fails loudly instead of substituting a different ruleset, and the comment now records the band argument as considered and rejected with the reason. Eight passages across five documents were reconciled to one account: the risk register entry that accepted the band is closed and annotated with *why that acceptance was wrong* — it accepted drift in the very gate that produces the audit evidence — and a re-baseline procedure is documented so adopting a newer SDK is a reviewed step rather than an accident. Recorded as review finding `CR2-F-13`. |

#### P-16 — The secrets gate aborted on unbound variables and had never completed a run

| Field | Value |
| --- | --- |
| **FINDING** | The Gate 3 secrets step in `.github/workflows/security-scan.yml` was a splice of three different implementations of the same sweep. It expanded `$want`, `$sweep_dir` and `$engine` — none of which any surviving line assigns — carried an orphaned `<<'EXPECT'` heredoc of seventeen probe pairs belonging to a deleted implementation, and ended with a duplicated `exit "$status"`. Under `set -u` the step aborted partway through and could never report a verdict. |
| **SEVERITY** | Major — the secrets validation gate, one of the five mandated gates, did not run. Raised by the review as `CR2-F-05`. |
| **CWE** | [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html), [CWE-1120: Excessive Code Complexity](https://cwe.mitre.org/data/definitions/1120.html) |
| **LOCATION** | `.github/workflows/security-scan.yml`, the step `Sweep for hardcoded credentials` — the spliced region and its duplicated terminator |
| **DESCRIPTION** | The step's *detector* was sound; its *driver* was not. Successive revisions had each rewritten the per-layer sweep loop without removing the previous one's variables, so the file accumulated references to state that no longer existed. This is the failure mode a security gate is least able to tolerate, because a gate that aborts looks from a distance like a gate that is merely noisy: the log contains real `PASS` lines from the self-test and the configuration-file assertion before the abort, so a reader skimming for green sees green. It was also the substrate of a false evidence claim: `LIBRARIES.md` asserted that every workflow shell step had been executed and exited `0`, which this step made impossible. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Gate 3 of the mandated five — *secrets scan: 0 hardcoded credentials* — produced no verdict, so no run of this workflow had ever demonstrated the property it claims. Because the step aborted **after** its self-test passed, the log positively suggested a working detector. A credential committed while the step was in this state would have been reported by nothing. |
| **EVIDENCE** | Reproduced rather than read: the step was extracted from the YAML with its job-level and step-level environment and executed under `bash`, giving exit `1` with `line 124: want: unbound variable` after the self-test and the repository sweep had already run. A static audit of assignments against expansions returned exactly `['engine', 'sweep_dir', 'want']`. Before deleting the dead region, an assertion confirmed all three variables were confined to it and survived nowhere in what remained. The rewritten step then exited `0`. Its ability to fail was proved separately by staging a probe file that assigns a string literal to a constant named `Password` into the git index, which produced exit `1`. |
| **REMEDIATION** | **Fixed.** The three spliced implementations were replaced by one, and the duplicated terminator removed. The single credential-shaped location the sweep legitimately found — a commented-out connection-string *template* whose every value is angle-bracketed — was carried in a reviewed allow-list keyed by layer, path and an exact occurrence count, so a new match in an already-reviewed file still fails; that template has since been removed from `WebVella.Erp.Site/Config.json`, so the sweep now reports **0 credential-shaped locations and 0 tolerated** and the allowance is inert. Narrowing the pattern instead was considered and rejected as a fail-open: a real credential containing `<` would then be invisible, and a live connection string is caught independently by three of the five layers. Because a count alone would not notice a placeholder being replaced by a real value, the *property* is also asserted on every run: every security-relevant field on the accepted line must still be angle-bracketed. Recorded as review finding `CR2-F-05`, with the residual as `RISK-116`. |

#### P-17 — The secrets gate copied the credentials it found into its own log and uploaded artifact

| Field | Value |
| --- | --- |
| **FINDING** | On detecting a credential literal in tracked source, the Gate 3 step printed the full matched line. That output is echoed to the CI log and appended to `secret-sweep.txt`, which the workflow's final step uploads as a build artifact. |
| **SEVERITY** | Medium — information disclosure under the governing severity matrix. Raised by the review as `CR2-F-10`. |
| **CWE** | [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) |
| **LOCATION** | `.github/workflows/security-scan.yml`, the source-regression sweep inside `Sweep for hardcoded credentials` |
| **DESCRIPTION** | The detector turned into a disclosure at exactly the moment it succeeded. A credential sitting in a source file is exposed to whoever can read the repository; the same credential printed into a CI log and a downloadable artifact is exposed to a different and often wider audience, and to retention policies that outlive the fix. The perverse consequence is that remediating the source file does not remediate the artifact. Maps to **OWASP A09:2021 Security Logging and Monitoring Failures**. |
| **IMPACT** | Every credential the gate found was copied into two further locations, both more widely readable and longer-lived than the commit that carried it, and neither cleaned by fixing the source. A contributor needs a location to act on, never the secret itself. |
| **EVIDENCE** | Proved by planting: a probe source file declaring a constant named `Password` and assigning it a distinctive string literal was staged into the git index, the step was run, and it correctly failed with exit `1`. The assignment is described here rather than reproduced, because this document is itself inside the sweep's envelope and writing the syntax out trips the gate — which it did while this record was being drafted, incidentally re-proving the sweep's breadth. The planted literal then appeared **zero** times in the captured CI output and **zero** times in `secret-sweep.txt`, while the report still named the path, the line number and `property=Password`. The working tree was confirmed byte-identical afterwards. |
| **REMEDIATION** | **Fixed.** The step emits `path:line property=<Name>` only; the matched line is never printed. The same discipline was applied to the per-layer sweep loop above it, which reports locations rather than lines for the same reason. A comment at each site names CWE-532 and records that this step's output reaches both the log and an uploaded artifact, so the constraint is not re-loosened by someone adding a diagnostic print. Recorded as review finding `CR2-F-10`. |

#### P-18 — Two WebAssembly projects were enrolled in the solution against the plan's frozen scope, and the workflow then described one graph three ways

| Field | Value |
| --- | --- |
| **FINDING** | `WebVella.Erp.WebAssembly/Server` and `.../Shared` had been added to `WebVella.ERP3.sln`, although the frozen plan authorises exactly one change to that file — the H-19 project-path casing correction. The workflow simultaneously carried three incompatible accounts of the resulting coverage: a job-level list declaring two explicitly-gated projects, a hard-coded empty set of non-members in the assertion beside it, and a closing note claiming coverage was *complete at 19 of 19* solution members. |
| **SEVERITY** | Major — a scope breach in a build-integrity file, plus a security artefact that misdescribed its own coverage. Raised by the review as `CR2-F-06`. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components — audit-coverage family](https://cwe.mitre.org/data/definitions/1104.html), [CWE-710: Improper Adherence to Coding Standards](https://cwe.mitre.org/data/definitions/710.html) |
| **LOCATION** | `WebVella.ERP3.sln`, the two project entries and their eight configuration lines; `.github/workflows/security-scan.yml`, the non-member declaration, the membership assertion and the closing coverage note |
| **DESCRIPTION** | This is the **second** regression of an already-closed decision in this review round. An earlier commit had removed these same enrollments, citing the plan section that scopes the solution file to the casing repair and noting that `Directory.Build.props` is directory-scoped so both projects inherit the gate regardless; a later commit re-added them with fresh GUIDs. The deeper defect is the one the three contradictory descriptions expose: the coverage model was *stated* in three places instead of being *declared once and read*, so correcting any one statement left the other two free to disagree. A security document that cannot describe its own coverage consistently cannot be relied upon to bound it. Maps to **OWASP A05:2021 Security Misconfiguration** and **A08:2021 Software and Data Integrity Failures**. |
| **IMPACT** | A build-integrity file diverged from its authorised change set, so the one edit that is genuinely load-bearing there — the casing repair that keeps the core project inside the scan graph — sat among unauthorised ones and became harder to review. Independently, a reader of the workflow could not determine which projects the gates actually reach, and the assertion meant to prevent exactly that drift had been given an empty set to compare against, so it asserted nothing. |
| **EVIDENCE** | The reversal is exact and measurable: after removing twelve lines, `git diff origin/master -- WebVella.ERP3.sln` reduces to **precisely the one authorised casing line**, `dotnet sln list` returns `17`, every member still resolves on disk, and the regression history was read from the two commits themselves rather than inferred. Coverage is unchanged and was re-measured: 19 tracked projects, 17 enumerated by the solution and 2 by dedicated steps; a full `-t:Rebuild` after the removal produced `3096` warnings and `0` errors with **622** `(file,rule)` diagnostic pairs on both sides of the change, zero count differences and zero added or removed pairs even line-position-sensitive — the removed projects contribute no diagnostics of their own. The rewritten assertion was proved in both directions: it passes today and it fails, naming the file, when a project is added to neither set. |
| **REMEDIATION** | **Fixed.** The enrollments are reverted and the solution file is back to its authorised single-line diff. The coverage model is now declared exactly once, in the job-level `EXPLICITLY_GATED_PROJECTS`, which the assertion *derives* from rather than restates, and which fails closed if it is empty. The assertion fails in three directions: a tracked project in neither set has escaped every gate; a project in both is gated twice while every coverage claim describes it wrongly; and a declared project absent from the tree means its dedicated steps run against nothing. The closing note now states the two numbers that are not interchangeable — coverage is 19 of 19, the *solution* is 17 of 19 — and records why widening the solution is an owner decision rather than an agent one. Recorded as review finding `CR2-F-06`; the residual command-coverage split is carried openly as `RISK-030`, reopened. |

#### P-19 — The static-analysis gate could never pass, because its diagnostic parse captured MSBuild's parallel-node prefix

| Field | Value |
| --- | --- |
| **FINDING** | Gate 1 reduced each analyzer diagnostic to a `(rule, file)` pair with a capture of everything preceding the first parenthesis. On a parallel MSBuild that text includes the line's indentation **and** the node identifier, as in `    17>/abs/path/File.cs(12,3): warning CA2100: …`, so every parsed file field was prefixed with whitespace and a node number and could never equal its allow-list entry. |
| **SEVERITY** | Major — the static-analysis gate, another of the five mandated gates, could not pass regardless of how clean the tree was. Found during this remediation; **not** reported by the review. |
| **CWE** | [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html) |
| **LOCATION** | `.github/workflows/security-scan.yml`, the diagnostic normalisation inside `Gate 1 - fail on unreviewed security analyzer diagnostics` |
| **DESCRIPTION** | Found only by running the gate end to end, which no previous pass had done. The symptom was self-refuting and therefore diagnostic: the step reported **42 unreviewed diagnostics and 21 stale allow-list entries simultaneously**. A real tree cannot produce both at once — an entry is stale precisely when nothing matches it, and a diagnostic is unreviewed precisely when no entry matches it — so the fault had to be in the comparison rather than in the tree. The node prefix also duplicated every pair once per node that reported it, which is why the count was exactly double the true residual set. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Gate 1 of the mandated five — *SAST scan: 0 Critical, 0 High* — was structurally incapable of a green verdict, so the workflow as a whole could never pass and the adjudication recorded in the allow-list was never actually applied to anything. A gate that always fails is as uninformative as one that always passes: both stop carrying signal, and the second failure mode is what an always-failing gate degrades into once contributors learn to ignore it. |
| **EVIDENCE** | Measured before the fix was applied, not after: the real analyzer log carried node prefixes up to `17>`, `6240` CA diagnostic lines, all paths absolute and none backslashed. Adding the normalisation moved the counts from `pairs=42 unreviewed=42 stale=21` to `pairs=21 unreviewed=0 stale=0`, and collapsed the all-category set from `1324` to `650` pairs by removing per-node duplicates. Gate 1 then passed with 21 accepted residuals and zero unreviewed. The count is identical whether or not the two non-solution projects' output has been appended, confirming they contribute no Security-category diagnostic. |
| **REMEDIATION** | **Fixed.** A normalisation step strips the indentation and the optional `<n>>` node prefix from the file field, under a comment recording that it is load-bearing rather than cosmetic and describing the exact failure it replaced. Because a silent regression here would restore the original condition — every comparison missing, invisibly — a fail-closed guard now rejects the parsed file if any record still begins with a node prefix or stray whitespace, with an error telling the reader to fix the normalisation rather than the allow-list. The guard was verified to fire on both `CA2100 2>path` and a double-spaced `CA2100  path`, and to stay silent on a well-formed record. Reported here as an additional fix beyond the review's findings. |

#### P-20 — A licence posture no engineer may settle was disclosed but not made unshippable

| Field | Value |
| --- | --- |
| **FINDING** | `WebVella.Erp` pins `AutoMapper` at `[15.1.3]`, which is published under the Reciprocal Public License 1.5, while the same manifest declares `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>` and the package is published to nuget.org. The conflict was documented at both sites, but nothing prevented the unratified claim from being packaged and published, and the surrounding documentation had recorded the owner's decision as already taken. |
| **SEVERITY** | Major — an owner decision recorded as made, on a claim that becomes irrevocable the moment a consumer resolves the package version. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) — the governance sibling of the H-01 advisory, whose licensing consequence this record covers. |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj` — the `<PackageLicenseExpression>` (`:L32`) and the `AutoMapper` pin (`:L88`); `Directory.Build.props`, which now carries the enforcing target; and the disposition as previously recorded in `docs/security/risk-register.md` (`RISK-001`), `docs/security/remediation-log.md`, `docs/security/security-audit-report.md`, `docs/security/secure-configuration.md`, `SECURITY.md` and `LIBRARIES.md`. |
| **DESCRIPTION** | Two distinct defects, one root cause. *First,* the documentation had converged on the sentence *"Decided — advisory closed; licence obligation accepted as a residual"*, adopted verbatim across six documents to remove an earlier contradiction. It removed the contradiction in the wrong direction: an automated remediation recorded itself as having accepted a reciprocal-licence obligation on the repository owner's behalf, which is precisely the escalation the governing plan forbids absorbing. *Second,* the disclosure was inert. A comment and a register entry do not stop `dotnet pack`, and the build was green, so the path of least resistance — publish, because nothing objected — remained open. Maps to **OWASP A06:2021 Vulnerable and Outdated Components** and **A05:2021 Security Misconfiguration**. |
| **IMPACT** | Publishing a package that declares Apache-2.0 over a dependency graph reaching RPL-1.5 code states a licence the package does not carry, to every downstream consumer, and a package version cannot be recalled from nuget.org once consumers have resolved it. The reputational and legal exposure falls on the repository owner, who had not been asked. The second-order impact is worse than the first: a remediation that settles owner questions in order to make its own gates green teaches the reader that "recorded" and "decided" are interchangeable. |
| **EVIDENCE** | The contradiction was read directly rather than inferred: the manifest comment said `RISK-001, OPEN, OWNER DECISION REQUIRED` while the register's Status field said *Decided*. Nothing blocked packaging: `dotnet pack` on the core project exited **0** and produced a `.nupkg`. The bypass was then measured too — with the first fix placed in the core manifest only, `dotnet pack` on `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Mail` and `WebVella.Erp.Plugins.SDK` each exited **0** and produced a package with no diagnostic, and the emitted `WebVella.Erp.Web.nuspec` was opened and carries `<license type="expression">Apache-2.0</license>` beside a `WebVella.Erp` dependency, which itself depends on `AutoMapper`. Four manifests declare that expression; three of them reference the core. Registry facts unchanged and re-confirmed: `14.0.0` is the last MIT release, there is no `14.0.1`, and the advisory fix begins at `15.1.1`. |
| **REMEDIATION** | **Fixed as an escalation, not as a decision — and enforced rather than asserted.** The declared expression was **not** rewritten, no `PackageLicenseFile` was substituted for it, and the pin was **not** reverted, because each of those would be the agent answering the owner's question by another route. Instead: (1) both sites in the manifest carry a comment naming the threat, stating why only the owner may settle it, and pointing at the gate; (2) the target `ErpAssertAutoMapperLicenceDecisionRecorded` in `Directory.Build.props` runs `BeforeTargets="GenerateNuspec"` and fails packaging with `ERPLIC001` until the decision is recorded as one committed, attributable line in `docs/security/risk-register.md` — review finding `GOV-01`, which correctly held that a transient `dotnet pack -p:...` property is not durable authenticated approval — with `ERPLIC002` refusing a declination that leaves the RPL pin in place, `ERPLIC003` refusing a record that is present but malformed so a typo cannot read as consent, `ERPLIC004` refusing to pass when the pin cannot be read at all, `ERPLIC005` refusing the retired transient property rather than ignoring it, `ERPLIC006` refusing to pass when the record file cannot be read, and `ERPLIC007` refusing two contradictory records rather than resolving them by order; (3) all six documents now record the disposition as **open, pending owner ratification**, each stating what it previously claimed and why that was withdrawn; and (4) `RISK-001` carries both options with the exact execution steps for each, plus the fourth path — publish as-is because the build was green — named explicitly as the one now closed. Verified in ten directions across all four packable manifests, 26 invocations: `restore`, `build`, `publish`, `dotnet list package` and all 13 CI gate steps stay silent and green; `dotnet pack` fails for 4 of 4 unresolved, 4 of 4 on a declination that is not complete, and 4 of 4 on a typo; an unreadable pin fails closed; and the gate self-disables when the pinned version is declared permissive, so it stops applying the moment it stops being true. |

#### P-21 — Stored cross-site scripting through every text value on the shared page header

| Field | Value |
| --- | --- |
| **FINDING** | `WvPageHeader`, the tag helper that renders the banner at the top of roughly fifty administrative screens, wrote its `AreaLabel`, `AreaSubLabel`, `Title`, `SubTitle` and page-switch item `Label` values to the response through `IHtmlContentBuilder.AppendHtml`, which performs no encoding. Every one of those values is database text. |
| **SEVERITY** | Major — stored cross-site scripting executing on the application's own origin for any user who opens an affected record, reachable in one click from a list screen that had already been remediated. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **LOCATION** | `WebVella.Erp.Web/TagHelpers/WvPageHeader/WvPageHeader.cs` — seven sinks: `AreaLabel`, `AreaSubLabel`, `Title` in the page-switch branch, the page-switch item `Label`, `SubTitle` in the page-switch branch, `Title` in the plain branch, and `SubTitle` in the plain branch. Reached, among many other routes, from `WebVella.Erp.Plugins.SDK/Pages/data_source/details.cshtml` where `Model.DataSourceObject.Name` is bound to `title`. |
| **DESCRIPTION** | H-06 was scoped to the views that emit stored text and to the composition code behind the Project widgets. It did not reach the shared page header, and the header is the single highest-blast-radius sink in the presentation layer precisely because it is shared: one tag helper renders the title of every entity, page, application, data source, user, role and record screen in the product. The route the audit's own fixtures had left behind made the gap visible — a data source named with a script tag rendered as inert text in the remediated *grid*, then executed on the *details* page one click away. **Two path corrections matter for anyone re-testing this.** The tag helper is at `TagHelpers/WvPageHeader/WvPageHeader.cs`, not `TagHelpers/WvPageHeader.cs`; and `details.cshtml` was never modified by this remediation, so the defect is pre-existing in the product even though the file that contains it was edited here for an unrelated return-URL fix. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Any user who can name a record — which for most entities is an ordinary authenticated user — could execute script in the browser of every colleague who subsequently opened that record, inside an authenticated session, with no interaction beyond navigation. Because the header also renders the area label and the page-switch list, a single poisoned page label would fire on every screen that offered a switch to it. |
| **EVIDENCE** | Reproduced against a live database before the change, at the level of raw HTTP response bytes rather than a parsed DOM: the details page emitted `<span class="text">QaXss1<script>alert('DS1')</script>` verbatim, and a second fixture emitted `QaXss2"><img src=x onerror=alert('DS2')>`. In a browser the first fired a real `alert` dialog and the second created a live `img` element. After the change the same bytes read `QaXss1&lt;script&gt;alert(&#x27;DS1&#x27;)&lt;/script&gt;` and `QaXss2&quot;&gt;&lt;img src=x onerror=alert(&#x27;DS2&#x27;)&gt;`; a browser session recorded a total dialog count of **0**, zero `img[src="x"]`, zero inline scripts calling `alert`, zero elements carrying `onerror` or `onmouseover`, and zero console errors across 204 requests all returning 200. |
| **REMEDIATION** | **Fixed in two measured stages.** First, the seven value-bearing text sinks named above moved from `AppendHtml` to `Append`, so the framework encodes them. Nothing was added — no helper, no dependency, no new markup — and structural `AppendHtml` calls that emit `TagBuilder` instances and compile-time literals remain untouched. One sink that concatenated a hard-coded `<i class='icon fas fa-ellipsis-v'></i>` with `Title` was split so the icon stays a real element and the title becomes a separate encoded text node. Second, review finding `F-02` retracted this row's former claim that `Description` was a by-design raw channel with only one non-literal supplier. `WebVella.Erp.Web/Components/PcPageHeader/PcPageHeader.cs` is a second, data-bound supplier, so the ordinary `description` attribute now renders through `InnerHtml.Append`; a separate, explicitly named `description-html` attribute is the trusted-markup channel; and the five SDK list views that intentionally pass `PageUtils.GenerateListPageDescription` use that channel. Behaviour preservation was proven rather than asserted: the original `P-21` verification kept legitimate header output byte-identical, and the `F-02` browser pass showed zero child elements and no execution for a hostile data-bound description while all five list pages retained their real `ul`/`li`/`strong` markup. The back button, page-switch dropdown, icons and labels remain operational. |

#### P-22 — Reflected cross-site scripting through the list-page description builder

| Field | Value |
| --- | --- |
| **FINDING** | `PageUtils.GenerateListPageDescription` composes the page header's description as markup and interpolated two attacker-supplied values into it without encoding: the `sortBy` query-string value, and the name of every active filter — itself a regular-expression capture taken out of the query key. |
| **SEVERITY** | Major — reflected cross-site scripting on every list screen in the product, triggered by a crafted link. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **LOCATION** | `WebVella.Erp.Web/Utils/PageUtils.cs` — the sort-term and filter-name interpolations inside `GenerateListPageDescription`. At the time this finding was closed, the composed markup was rendered through the raw `description` channel. Review finding `F-02` subsequently split that contract: the five SDK list views now pass this trusted builder output through `description-html`, while ordinary `description` values are encoded. |
| **DESCRIPTION** | This is the counterpart to `P-21` and the reason a builder that intentionally produces markup cannot be fixed by blindly encoding its **whole result**. The builder emits an inline `ul`/`li` list wrapping a bold `sorted by` and `filtered by`, so encoding that complete string would show the product's own tags as literal text. Its two interpolated values, however, came straight off the query string and had to be encoded before composition. At this checkpoint the tag helper exposed only one description channel; `F-02` later corrected that design by separating encoded `description` from trusted `description-html`. `PageUtils.cs` was edited by this remediation for the return-URL work, so the file was in scope while this function was left untouched. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Any list screen became a reflected cross-site-scripting vector reachable by sending a signed-in user a link — no stored data and no write access required. The affected screens are the platform's own administrative lists, so the likely victim is a privileged user. |
| **EVIDENCE** | Reproduced live at HTTP 200 before the change: `?sortBy=name<script>alert('SORTXSS')</script>` emitted `<strong>sorted by</strong> name<script>alert('SORTXSS')</script>` verbatim, and `?q_XX<b>hi</b>YY_v=abc` emitted `<strong>filtered by</strong> XX<b>hi</b>YY` verbatim. After the change both render entity-encoded, and five further payloads — an attribute-breakout `"><svg onload=alert(1)>`, a quote-breaking `'-alert(1)-'`, a tag-closing `</strong><script>alert(2)</script>`, an `img`/`onerror` filter name and a `javascript:` scheme — are all inert, with zero raw `svg` and zero raw `script` in the response. A browser session confirmed zero dialogs and zero live `script` elements inside the description. |
| **REMEDIATION** | **Fixed at the builder, then narrowed at the tag-helper boundary by `F-02`.** `PageUtils.GenerateListPageDescription` encodes only the two interpolated values through `HtmlEncoder.Default`, so every literal in the builder — the `ul`, `li`, comma separator and both `strong` wrappers — stays unchanged. `F-02` then moved the five SDK views that intentionally consume this builder output to the explicit `description-html` channel and made ordinary `description` encoded by default; the general description sink therefore does **not** stay raw. Both halves were verified independently: hostile query values are inert, while the feature remains a real `ul.list-inline` with two `li.list-inline-item` elements and a real `strong` around `sorted by`. Legitimate output is byte-identical to the pre-change bytes. One measurement is recorded so it is not later misread as a regression: that `strong` computes to `font-weight: 400`, because `WebVella.Erp.Web/Theme/styles.css` normalises `strong` inside `.description` — a 2019 design decision in a file no security commit has touched, reproducing identically on a payload-free page. |

#### P-23 — Stored cross-site scripting through select-option metadata at the platform's `WvSelectOption` conversion boundary

| Field | Value |
| --- | --- |
| **FINDING** | `ModelExtensions.ToWvSelectOption` — the only place in the repository that constructs the third-party `WvSelectOption` — copied a stored select option's `icon_class` and `color` verbatim into it. The `WebVella.TagHelpers` 1.8.0 select component then concatenated both straight into a `class` attribute and a `style` attribute with no encoding, so a stored value containing a double quote closed the attribute and created attributes of its own, including an inline event handler. |
| **SEVERITY** | Major — stored cross-site scripting, privilege-gated at authoring but executing for every viewer, on every host that renders any select field. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html), and [CWE-83: Improper Neutralization of Script in Attributes](https://cwe.mitre.org/data/definitions/83.html) |
| **LOCATION** | `WebVella.Erp.Web/Utils/ModelExtensions.cs` — `ToWvSelectOption`. The sink itself is inside the third-party `WebVella.TagHelpers` 1.8.0 package, which the plan restricts to version updates, so the fix had to land at this boundary. Observed on `WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml` (the SDK entity data-list, which binds `((SelectField)field).Options.ToWvSelectOption()`) and on `WebVella.Erp.Web/Components/PcFieldSelect/Display.cshtml`, reached from any record details screen carrying a select field. |
| **DESCRIPTION** | This is the same value pair H-06 and `F-AA` had already chased through four Project-plugin render paths, one boundary further out. The reason none of those four fixes covered it is structural rather than an oversight of diligence: the allow-list helper lived in `WebVella.Erp.Plugins.Project`, and `WebVella.Erp.Web` cannot reference a plugin that references it, so a plugin-owned guard was incapable of covering the framework's own conversion boundary. That boundary serves **94** call sites across **65** files and **176** `wv-field-select` / `wv-field-multiselect` tag usages, which makes it the widest of the five paths, not the narrowest. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | An administrator who can edit a select field's options — the same tier that can already author a raw HTML block — could execute script in the browser of every user who subsequently viewed any record or list showing that field, on **every** host in the deployment, including hosts that do not contain the plugin the earlier fixes belonged to. |
| **EVIDENCE** | Reproduced before the change against a live database with the `task` entity's `priority` option poisoned, at the level of raw response bytes and then in a browser. The HTML parser produced `["class","onmouseover","\"","style"]` on an element the application only ever gave two attributes; the injected `color:red` computed as `rgb(255,0,0)`; and Chrome's own Content-Security-Policy engine logged *"Executing inline event handler"* against the live page, which it emits only when it has classified an attribute as an inline handler and reached its execution stage. The task-details page carried **1** such element, the SDK entity data-list **4** — one per affected row — on both a Project host and a host without the Project plugin. **One correction to the reported finding is recorded rather than smoothed over:** the payload as originally reported cannot actually fire, because its trailing ` x="` fragment leaves the handler body `alert('R3ICON3') x=` as invalid JavaScript (`SyntaxError: Unexpected identifier 'x'`), and the truncated class collapses the element to a 17.5 × 0 px box that no coordinate can hit. Exploitability was therefore established by control rather than by the original payload: reproducing the same server-side concatenation with those three characters removed produces a **callable** handler and a **real** browser dialog, while HTML-encoding the same value produces two attributes and no handler at all. A second weaponised fixture — valid handler body, real glyph class, hoverable box — was then seeded so the post-fix signal could not be ambiguous. |
| **REMEDIATION** | **Fixed at the boundary, with the guard relocated so it could reach it.** `SafeStyleValue` was **moved** — not copied — from `WebVella.Erp.Plugins.Project/Services/` to `WebVella.Erp.Web/Utils/`, keeping exactly one audited implementation, since duplicating security logic across two assemblies is the very pattern that produced the original miss; its three plugin call sites now consume it through a `using` and behave identically. `ToWvSelectOption` routes `Color` through `SafeStyleValue.CssColor` and `IconClass` through `SafeStyleValue.IconClass`. A rejected value becomes an empty string and the component then emits **no `<i>` element at all**, which is byte-identical to how an option with no icon and no colour has always rendered — the rejected state is an existing state of the product, not an invented fallback. The same edit closes a **second** sink that correct server-side encoding could not: the component's inline-edit path writes both values into `data-icon`/`data-color`, and the select2 script reads the **decoded** attribute back out of the DOM and re-inserts it as markup; because the value is emptied before it is ever written, what the script reads back is already safe. `SelectOption.Label` was raw at the same sink and this row previously recorded it as **deliberately left so**, on the grounds that the component already encodes it in edit mode, that encoding at the boundary would double-encode every legitimate label containing `&`, `'`, `<` or `>`, and that a label has no constrainable shape for an allow-list. **That disposition is retracted: the label channel is now closed as well, by review finding `F-01`.** The reasoning above was right about *encoding* and wrong to conclude that nothing could be done. Two measurements settled it: the vendor emits the same `Label` instance through `Append` on some paths and `AppendHtml` on others in a single render — four raw sites each in `WvFieldSelect` and `WvFieldMultiSelect`, and unconditional raw writes in `WvFieldCheckboxList` and `WvFieldRadioList` — so any pre-encoded value double-encodes somewhere; and all four select2 initialisations pass `escapeMarkup: function(markup){return markup;}` and re-inject the option's DOM-**decoded** text as `innerHTML`, so server-side entities are decoded before they reach that sink and encoding could not have covered it at all. The control that does work is the same one already applied to the icon and colour: **restriction**. `ToWvSelectOption` now passes the label through `SafeStyleValue.DisplayText`, which removes only `<` — the sole character that can begin a tag — and `"`, which breaks the `title="…"` attribute `WvFieldMultiSelect.inline-edit.js` builds client-side. `&`, `'` and `>` are untouched, so `R&D`, `Client's request` and `> 30 days` are unchanged, and the same instance is returned when nothing needs removing. All 150 `new SelectOption` sites were surveyed first and none carries markup, so nothing legitimate was taken away. Verified with the hostile label still seeded: no injected element, no `on*` attribute, no mutation recorded by an observer armed before page scripts, and no dialog across exhaustive hover and pointer sequences, while the legitimate control label read back at codepoint level as exactly `low R&D 'q'`. The surviving residuals are `RISK-127` (the guard is caller-side) and `RISK-129` (the option icon is still guarded character-level rather than token-level). Verified with the payload **still seeded**: every hostile token count fell from `onmouseover==4` / 4 live handlers to **0** on both hosts; `[onmouseover]` is 0 in display mode, in select2 edit mode and with the dropdown open; 340 and 756 dispatched pointer events plus real-mouse hovers over the weaponised option produced **0** dialogs; a `MutationObserver` armed before page scripts recorded **0** `on*` sightings; and CSP `script-src-attr` violations were **0** across 205 captured violations. That the guard discriminates rather than blanket-strips was proven twice: with the dropdown open select2 still injected a real `<i class="fa fa-fw fas fa-fw fa-arrow-circle-down" style="color:#4CAF50">` for the legitimate option, and with the fixture restored all six task rows render their real glyph and colour with `::before` codepoints U+F0AA, U+F056 and U+F0AB and every computed colour matching its inline style. The stale *"four independent render paths"* claim in the helper's own remarks, and a matching *"three sibling render paths"* comment in the tasks-queue widget, were both corrected, so no wrong path count survives in the source. |

### Findings `F-04`, `F-05` and `F-07` from the latest control review

`F-01`, `F-02` and `F-03` are recorded with the `H-06` correction above, and `F-06` is the
page-header style/class boundary recorded in the remediation log and as closed `RISK-123`. The three
remaining code findings from that same review concern the protected-file pipeline and the shared
transport-posture validator; they are recorded here in the same eight-field format as the audit.

#### F-04 — Authenticated file responses were explicitly public-cacheable

| Field | Value |
| --- | --- |
| **FINDING** | Every successful `/fs` response required authentication, and staged files additionally required owner or administrator access, but the action emitted `Cache-Control: public,max-age=2592000`. A shared cache could therefore serve protected bytes to a later caller without the request reaching either authorization check. |
| **SEVERITY** | High — protected-file disclosure through shared-cache reuse. |
| **CWE** | [CWE-525: Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html), with CWE-200 disclosure impact. |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs:L3742-L3799` (`isStagedFile`, conditional-request handling and the sole `/fs` cache-control assignment); the shared staged-path decision is `IsStagedFilePath` at `:L4573`. |
| **DESCRIPTION** | The controller's class-level authorization and per-row staged ownership check protected origin requests only. `public` explicitly invited a corporate proxy, CDN or reverse proxy to retain the authenticated response and reuse it for another caller. The staged `/tmp/` namespace was the highest-risk case because the repository treats it as short-lived private scratch space belonging to one client. Maps to **OWASP A01:2021 Broken Access Control**. |
| **IMPACT** | A user, administrator or background cache could cause another principal to receive file bytes they were never authorized to read. A browser on a shared machine could also restore protected bytes after logout or an account switch. |
| **EVIDENCE** | Before the change the only cache-control assignment in the action was `public,max-age=2592000`. After the change a staged file returned `private,no-store`, and an exact `If-Modified-Since` request returned **200**, never 304; a published file returned `private,max-age=2592000` and retained its **304** path. The same staged rule covered the resized-image branch, the published download branch retained attachment disposition, and an unauthenticated request still redirected to login. |
| **REMEDIATION** | **Fixed.** Every authenticated `/fs` response is now `private`. Published files retain the 30-day browser freshness window as `private,max-age=2592000`, preserving the existing image-performance behaviour without allowing shared-cache reuse. Staged files use `private,no-store`, and their conditional-304 short circuit is skipped so a validator cannot keep alive bytes that must never have been retained. `IsFileReadAuthorized` and the cache decision share one staged-path helper, preventing their definitions from drifting. |

#### F-05 — Destination authorization was not preserved across an overwrite move

| Field | Value |
| --- | --- |
| **FINDING** | `MoveFile` authorized one destination row — or the fact that the path was empty — but passed only the authorized source identifier into `DbFileRepository.Move`. The repository re-read the destination later and, on overwrite, could delete whichever row existed at mutation time rather than the row or absence the caller had authorized. |
| **SEVERITY** | High — destructive object-level authorization race. |
| **CWE** | [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html), under **OWASP A01:2021 Broken Access Control**. |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs:L4007-L4010` carries the authorized destination state; `WebVella.Erp/Database/DbFileRepository.cs` carries the transaction-bound row lock in `FindForUpdate` and re-verifies and mutates in `Move`, whose `enforceExpectedTarget` / `expectedTargetId` pair encodes the authorized destination state. |
| **DESCRIPTION** | A destination that was absent or caller-owned during the controller check could be replaced concurrently with another user's file before the repository's second read. The old implementation then pinned and deleted the replacement row's identifier — authorizing one object and mutating another. Source-ID pinning could not close this because the source was legitimate throughout the attack. |
| **IMPACT** | A raced overwrite could delete another user's file and take over its path. In the staged-withheld case, where `Find` intentionally returns null to a non-owner, the old path could also turn a deliberate denial into an unhandled uniqueness fault. |
| **EVIDENCE** | A deterministic PostgreSQL harness executed 34 assertions across eight cases. A destination pinned to a specific identifier refused when a different row replaced it; a destination authorized as absent refused when a row appeared; a missing expected row refused; a withheld staged row owned by another user refused without fault; and every victim and source remained intact. Positive controls proved an unchanged expected row still overwrites and an unpinned caller retains the previous behaviour. The HTTP path also completed both the expected-absent move and an authorized overwrite successfully. |
| **REMEDIATION** | **Fixed.** `Move` takes the authorized destination state as an explicit contract: `enforceExpectedTarget` states that the caller authorized a destination state at all, and `expectedTargetId` states which state — a specific row, or `null` to assert the path was empty — so "no destination expected" is never confused with "no expectation". The controller passes the exact authorized destination state. Inside one transaction, source and destination are re-read with `SELECT ... FOR UPDATE` in ordinal path order, avoiding opposite-direction deadlocks; any source or destination mismatch rolls back and returns null; and a destination delete is permitted only when the locked row is the same row the caller's authorization-aware read returned. The existing generic denial envelope is preserved. The optional parameter defaults to `Unpinned`, so the three existing callers with no destination authorization state keep their prior contract. The unreachable `DbFileRepository.Copy` analogue is documented separately as `RISK-130`. |

#### F-07 — Any nonblank HTTPS port was accepted as a usable redirect target

| Field | Value |
| --- | --- |
| **FINDING** | The shared transport-posture validator treated any nonblank `ASPNETCORE_HTTPS_PORT` / `HTTPS_PORT` value as proof that HTTPS redirection was usable. Values such as `0`, `-1`, `70000` and `not-a-port` bypassed the startup diagnosis even though the redirect middleware could not use them. |
| **SEVERITY** | Medium — configuration-validation failure causing a production availability and transport-enforcement gap. |
| **CWE** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) and [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html). |
| **LOCATION** | `WebVella.Erp.Web/ErpMvcExtensions.cs:L917-L921` validates the configured port; `:L936-L939` reports a rejected port when a trusted proxy supplies the usable path; `:L961-L1009` builds and enforces the shared diagnosis; `:L1036-L1068` contains the invariant parser, range check and non-echoing rejection sentence. |
| **DESCRIPTION** | On a plaintext-only Production host, an inert redirect lets the request reach MVC while the antiforgery cookie is Secure-only; form generation then fails and `/login` answers HTTP 500. The guard existed specifically to catch that topology, but its nonblank check accepted the one class of value guaranteed not to work. |
| **IMPACT** | A deployment could start apparently healthy while every form-bearing page failed at request time, and plaintext requests were forwarded unredirected. Health probes and header checks could still pass, concealing the outage. |
| **EVIDENCE** | An eleven-case runtime matrix forced a plaintext-only endpoint. `443` and whitespace-padded `007` started; `0`, `-1`, `70000` and `not-a-port` all aborted with the actionable reason; the malformed value also aborted in Development; a malformed value plus a trusted proxy started with exactly one warning; an absent value retained the pre-existing Production refusal and Development warning. A normal host with a declared HTTPS endpoint still started without a transport notice. |
| **REMEDIATION** | **Fixed.** The public-port channel is parsed with `NumberStyles.Integer` and `CultureInfo.InvariantCulture`, trimmed, and required to fall in **1-65535**. A rejected value is not evidence. It falls through so a trusted reverse proxy may still supply a genuine HTTPS path; in that case the host starts and reports the inert redirect. Without another path, the same shared transport diagnosis refuses startup in every environment, including Development. The message names the key and defect but never echoes the configured value. The secure-configuration guide now documents the range and both outcomes. |

## Part 4: The frontend and API seam review

A code review of the frontend and API seam at the final checkpoint raised **fourteen** findings — four
Critical, nine Major and one Minor. All fourteen are closed. Two further defects were found while closing
them, neither of which the review could have seen, and both are recorded here rather than folded silently
into the fourteen: one is a regression introduced **after** the checkpoint baseline by a commit inside this
engagement, and the other is a regression introduced **by one of these very remediations**, caught by
runtime verification of that remediation rather than by inspection.

**Why this part exists as its own inventory.** Parts 1 through 3 are a server-side audit and its reviews.
Every sink census, gate and assertion in them is expressed over C# and Razor. This seam is where that
expression runs out: a Blazor WebAssembly client composing its own request URLs, a third-party tag-helper
package whose JavaScript this repository cannot edit, and a pre-built Stencil bundle that assigns
`innerHTML`. Three of the four Criticals and the highest-impact Major were invisible to every control the
earlier parts established, and saying so plainly is more useful than absorbing them into Part 2's numbering.

**On identifiers.** These records use the `SR-` prefix, which was unused anywhere in this repository before
this part. It is deliberate rather than decorative: the review's own identifiers were `C-01`–`C-04`,
`M-01`–`M-09` and `L-01`, every one of which collides **exactly** with a Part 1 record — Part 1 already owns
`C-01`–`C-05`, `M-01`–`M-18` and `L-01`–`L-10`. Reusing them would have created fourteen ambiguous
identifiers in a document set whose workflow asserts identifier uniqueness on every run. The mapping from
the review's identifier to the identifier used here is given in the first field of every record, so a reader
holding the review can follow it without guessing.

**On severity.** Each record states the review's own grading first, because that is the source, and then the
tier the engagement's [severity matrix](#methodology) assigns, because that matrix is what decides
disposition. Where the two differ the difference is stated rather than reconciled away.

### Critical severity seam findings

#### SR-01 — WebAssembly token refresh could never resolve

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `C-01`.* The WebAssembly client composed its token-refresh URL with a duplicated `api/` segment, producing a path the server does not serve. Every refresh therefore returned 404, and the client's own error handling treated that 404 as the server having **rejected** the token: it deleted the stored credential. The result is that a user was signed out at the moment their token entered its refresh window, with no way to remain signed in. |
| **SEVERITY** | Critical as graded by the review. On the severity matrix this is not an authentication *bypass* — it grants nothing — but it is a total failure of the session-continuity mechanism, and it is Critical because the client's only means of holding a session is unusable. |
| **CWE** | [CWE-1188: Insecure Default Initialization of Resource](https://cwe.mitre.org/data/definitions/1188.html) for the misconfigured base address, with the observable outcome falling under [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) inverted — premature, unavoidable session loss. |
| **LOCATION** | `WebVella.Erp.WebAssembly/Client/Services/TokenManagerService.cs:L88`, resolved against the base address built in `WebVella.Erp.WebAssembly/Client/Program.cs`. The server route it was aiming at is `api/v3/en_US/auth/jwt/token/refresh` in `WebVella.Erp.Web/Controllers/WebApiController.cs`. |
| **DESCRIPTION** | `HttpClient.BaseAddress` already ended in `api/`, and the relative URL passed to the refresh call **also** began with `api/`, so `Uri` resolution produced `/api/api/v3/en_US/auth/jwt/token/refresh`. The correct convention was already present one file away: `AuthenticationService` used `v3/en_US/auth/jwt/` with no `api/` prefix for the login and logout calls, which is why those two worked and refresh did not. Maps to **OWASP A07:2021 Identification and Authentication Failures**. |
| **IMPACT** | No user of the WebAssembly client could hold a session across a refresh. Worse than a plain outage, because the failure mode **destroys** the stored token rather than retrying, so the user is silently signed out mid-session and any unsaved work in the client is lost. |
| **EVIDENCE** | Proven at runtime against a live host rather than by reading the resolution rules: `POST /api/v3/en_US/auth/jwt/token/refresh` returns **200**, while `POST /api/api/v3/en_US/auth/jwt/token/refresh` returns **405** — the catch-all, never the refresh action. An ad-hoc assertion additionally proves the old form contains the literal substring `/api/api/`, so the defect is a property of the composed string and not of the environment. |
| **REMEDIATION** | **Closed.** The route root is now a single shared constant, `WasmConstants.ApiAuthRoot = "v3/en_US/auth/jwt/"`, consumed by `TokenManagerService` for refresh and aliased by `AuthenticationService` for login and logout — so the two cannot diverge again, which is the actual root cause rather than the duplicated segment. A repository-wide search for the literal `"api/v3` in the client returns **zero** occurrences. Traces to the **Authentication Hardening** standard's secure-session-management clause. |

#### SR-02 — Bearer scheme compared case-sensitively, routing authenticated callers to the cookie handler

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `C-02`.* Two host pipelines selected their authentication handler by testing the `Authorization` header against the literal `"Bearer "` with an ordinal, **case-sensitive** comparison. RFC 7235 defines the scheme token as case-**insensitive**, so a standards-compliant `bearer <jwt>` was not recognised as a bearer credential and was forwarded to the **cookie** handler, which finds no cookie. A correctly authenticated API caller was therefore answered as anonymous — and because the cookie handler owns the challenge, it was issued a **login redirect** rather than a 401. |
| **SEVERITY** | Critical as graded by the review. |
| **CWE** | [CWE-178: Improper Handling of Case Sensitivity](https://cwe.mitre.org/data/definitions/178.html) |
| **LOCATION** | Server: `WebVella.Erp.Site/Startup.cs` and `WebVella.Erp.Site.Project/Startup.cs`, in each host's `ForwardDefaultSelector`. Client: `WebVella.Erp.WebAssembly/Client/ApiService/ApiService.System.cs`, which emitted the lower-case spelling **and** set it on the shared `DefaultRequestHeaders`, and `ApiService.Project.cs`, which dereferenced the null the authorized-client method returned. |
| **DESCRIPTION** | The finding has two halves that compound. The client emitted `bearer`; the server refused to recognise `bearer`. Either half alone would have been latent. Together they meant the WebAssembly client's authenticated calls were never authenticated. **The platform already contained the correct comparison**: `WebVella.Erp.Web/Middleware/JwtMiddleware.cs:L132-L133` compares the same prefix with `StringComparison.OrdinalIgnoreCase`, so the fix is bringing two outliers into line with the platform's own precedent rather than inventing a rule. Maps to **OWASP A07:2021 Identification and Authentication Failures**. |
| **IMPACT** | Any client emitting a lower-case or mixed-case scheme — which the standard permits, and which this repository's own client did — was treated as anonymous. Two secondary defects sat in the same code path: the authorized-client method **returned null** after starting a navigation, and `NavigateTo` does not abort the calling method, so every caller dereferenced that null immediately; and because there is exactly **one** `HttpClient` instance behind both the authorized and the "not authorized" accessor, the token set on `DefaultRequestHeaders` **persisted**, so once any authenticated call had been made every subsequent request the caller believed anonymous was in fact carrying the bearer token. |
| **EVIDENCE** | Driven against a live host, one header spelling at a time. With the fix in place: `Bearer`, `bearer`, `BEARER` and `BeArEr` each return **401**, proving all four reach the JWT handler; `Basic dXNlcjpwdw==` and the deliberate near-miss `Bearerx` each return **302**, proving the comparison was not over-broadened into matching any header that merely starts with those letters; and no header at all returns 302 to `/login`. A repository-wide search for the case-sensitive form `StartsWith("Bearer ")` returns **zero** occurrences. |
| **REMEDIATION** | **Closed, both halves.** Both selectors now compare with `StringComparison.OrdinalIgnoreCase`, each carrying an inline comment naming the threat and citing `JwtMiddleware` as the in-repository precedent. The client emits the canonical `Bearer` spelling, so neither half relies on the other's leniency. The authorized-client method now **throws** `ApiTokenException` instead of returning null — and, because a typed exception surfacing as an unhandled render fault is only half a fix, the anonymous path was additionally made *handled*: the home page requests the current user only when it has already established that a token exists, and `AppState` catches **only** `ApiTokenException` so that its pre-existing "no logged-in user" branch runs while any other failure still propagates. The non-authorized accessor now clears `Authorization`, closing the shared-instance token leak. Traces to the **Authentication Hardening** standard. |

#### SR-03 — WebAssembly client configured to call its API over cleartext

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `C-03`.* The WebAssembly client shipped `"serverUrl": "http://localhost:5000/"`, while the host serving it redirects to HTTPS. Two outcomes follow and both are defects: served over HTTPS, every API call is active mixed content and is **blocked**, so the client cannot function; served over plain HTTP, the same setting transmits the **bearer token in cleartext on every request**. |
| **SEVERITY** | Critical as graded by the review. |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) |
| **LOCATION** | `WebVella.Erp.WebAssembly/Client/wwwroot/appsettings.json` and the base-address composition in `WebVella.Erp.WebAssembly/Client/Program.cs`. |
| **DESCRIPTION** | The dangerous variant is the one that *works*. A blocked request is loud and self-announcing; a working cleartext request is silent and leaks a bearer token to anything on the path. The root cause is that a security-relevant property — the scheme of the API origin — was a free-text configuration value with an insecure shipped default. Maps to **OWASP A02:2021 Cryptographic Failures** and **A05:2021 Security Misconfiguration**. |
| **IMPACT** | A bearer token observable on the network is a full session credential. Because the client stores and reuses it, interception yields authenticated access for the token's remaining lifetime. |
| **EVIDENCE** | The exposure was **reachable, not theoretical**: a control probe confirmed a listener is live on `http://localhost:5000` and answers with a 302. After the fix, a headless-browser run recorded **zero** `http:` requests across 220 DevTools entries and 219 Resource Timing entries, with **zero** blocked requests; a provoked API call was confirmed as `:scheme: https`, `:authority: localhost:5031`, `sec-fetch-site: same-origin`; and `serverUrl` was confirmed empty with no `http://localhost:5000` string reachable in the served payload. A positive control was run in the same session to prove a mixed-content block *would* have been visible had one occurred. |
| **REMEDIATION** | **Closed by removing the setting from the trusted path rather than by correcting its value.** The API base address now defaults to `builder.HostEnvironment.BaseAddress` — the origin that served the client — which inherits the page's own scheme and therefore **cannot be weaker than the page**. A relative override is resolved against the serving origin and is scheme-safe by construction. An absolute override is still honoured for a genuinely separate API host, but an **insecure** absolute base under a secure page is refused with an actionable `InvalidOperationException` rather than attempted, because the only two possible outcomes of attempting it are a blocked request or a leaked token. The shipped `serverUrl` is now empty, with a sibling `//serverUrl` key documenting the policy in place. Traces to the **Cryptographic Standards** standard's TLS clause. |

#### SR-04 — Retired editor shell referencing roughly seventy assets absent from the repository

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `C-04`.* Two Razor Pages and their page models referenced approximately **seventy** `/jsadmin/**` AngularJS and CKEditor-4 assets that exist **nowhere** in this repository. Neither page could render. The remedy a naive reading suggests — ship the missing bundle — would have meant **adding two end-of-life vendor libraries** to a repository whose engagement forbids vendor code additions and whose whole purpose here is removing unsupported components. |
| **SEVERITY** | Critical as graded by the review. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) |
| **LOCATION** | `WebVella.Erp.Web/Pages/ckeditor/Index.cshtml` and `Index.cshtml.cs` (`JsAdminModel`), and `ImageFinder.cshtml` and `ImageFinder.cshtml.cs` (`JsAdminImageFinderModel`), together with their two `<Content Update>` entries in `WebVella.Erp.Web/WebVella.Erp.Web.csproj`. |
| **DESCRIPTION** | CKEditor 4 reached end of life in June 2023 and AngularJS in January 2022. Introducing either to satisfy a page that has never rendered would create new, permanently unpatched vulnerability surface in order to preserve a feature nobody can be using. Maps to **OWASP A06:2021 Vulnerable and Outdated Components**. |
| **IMPACT** | As shipped, none directly — the pages could not render. The risk was **prospective and structural**: dead routes referencing an EOL editor invite exactly the wrong repair, and a future maintainer restoring the bundle would introduce two unmaintained libraries into the request path of an authenticated admin surface. |
| **EVIDENCE** | Retirement was verified safe **before** removal, not after: `JsAdminModel`, `JsAdminImageFinderModel` and the `/ckeditor` page routes were referenced from **zero** other files anywhere in the repository. |
| **REMEDIATION** | **Closed by removal.** All four files were retired and both `<Content Update>` entries removed from the project file. **The live CKEditor 5 integration is untouched and still routed** — it uses the controller endpoints `/ckeditor/drop-upload-url` and `/ckeditor/image-upload-url`, which are unrelated to these pages, and this was confirmed explicitly rather than assumed. Two consequential documentation corrections were carried in the same change, because retiring files invalidates citations: `RISK-015` (the `/ckeditor/ImageFinder` HTTP 500 entry) is closed by removal, and the `M-5` locator table and the `remediation-log` encoding exemplar that cited `JsAdminImageFinderModel.CurrentTypeJsEncoded` are corrected with the reason visible rather than deleted. Traces to the **Dependency Updates** standard's replace-EOL-libraries clause. |

### High and Medium severity seam findings

#### SR-05 — Stored cross-site scripting through a client-side `innerHTML` sink in the Project plugin

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-01`.* Comment and timelog bodies were persisted **exactly as submitted**, serialized into a page attribute by three page components, and then assigned to `innerHTML` by a pre-built Stencil bundle. Feed subjects additionally interpolated a stored task key and subject into trusted markup. This is the chain that every control in Parts 1 through 3 missed, and the reason is structural: **the sink is not a Razor expression**, so no `Html.Raw(` census could ever have seen it. |
| **SEVERITY** | High. The severity matrix places *XSS (stored)* squarely in the High tier. Graded Major by the review, which is the same disposition. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **LOCATION** | Write side: `WebVella.Erp.Plugins.Project/Services/CommentService.cs` and `TimeLogService.cs`, in each `Create`. Feed-subject composition: `CommentService.cs:L182`, `TimeLogService.cs:L277` and `TaskService.cs:L412`. Read side: `WebVella.Erp.Plugins.Project/Components/PcPostList/PcPostList.cs`, `PcTimelogList/PcTimelogList.cs` and `PcFeedList/PcFeedList.cs`. The sink itself is in the shipped bundles `wwwroot/js/wv-post-list/p-700a7533.entry.js` and `wv-feed-list/p-lzwqwltl.entry.js`. |
| **DESCRIPTION** | The bundles bind `innerHTML` to both `.body` (eight references) and `.subject` (two references), which was confirmed by reading the built artifacts rather than inferring it from the component sources. The content-security policy ships **report-only**, so it does not block the execution. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Script executing on the application's own origin, stored, and rendered for every user who opens the affected project, task or feed view — including users who never interact with the attacker. The feed path widens it further: a poisoned task subject reaches every viewer of the activity feed. |
| **EVIDENCE** | Proven at runtime with the payloads **left in place**, which is the strongest available form of this evidence: after remediation the markup is still physically present in PostgreSQL and is still inert. A stored `<script>` marker never sets its global; a Python analysis of the rendered page found **0 of 53** live `<script>` blocks containing any marker; and the neutralised payload images fire genuine load-error events with nothing else happening. The composition half was proven by poisoning a real task subject with `Bad</a><script>…</script><img src=x onerror=…>` and observing the resulting feed subject fully entity-encoded inside the server's own surviving anchor. Legitimate rich text — bold, italic, links with safe `href` — still renders. |
| **REMEDIATION** | **Closed with an allow-list sanitizer, applied on both sides.** A new `WebVella.Erp.Web/Utils/HtmlSanitizer.cs` uses HtmlAgilityPack — already a direct dependency, so **no new package** — with strict tag, attribute and URL-scheme allow-lists, a drop-with-content set, unknown-element unwrapping that descends *before* deciding, comment removal, encode-on-parse-failure, and a de-entitizing, whitespace-stripping URL check that catches `&#106;avascript:`, `java<TAB>script:` and mixed case. It is applied on **write** in both `Create` methods, and again on **read** in all three page components so that already-stored payloads are neutralised without rewriting stored data — which the engagement's boundaries forbid. The read-side pass operates on **copies**, recursing into nested `"nodes"`, and runs *before* the feed's `GroupBy` so the serialized object graph is byte-identical for benign content. The three composition sites HTML-encode the interpolated key and subject. **One planned step was deliberately not taken**: encoding the feed *snippet* body. `RenderService.GetSnippetFromHtml` was tested and proven **not** to decode entities, so encoding it would have double-encoded into a visible regression — the pre-planning note asserting otherwise was wrong and is corrected here. Traces to the **Injection Prevention** standard. |

#### SR-06 — Open redirect in the WebAssembly login component

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-02`.* The WebAssembly login component read a `returnUrl` query parameter, URL-decoded it, and passed it to `NavigationManager.NavigateTo`, which accepts an **absolute** URI and will leave the application. The server-side Razor pages already enforced a local-path policy for exactly this parameter; the client did not. |
| **SEVERITY** | Medium on the severity matrix — an unvalidated forward is neither stored injection nor a credential compromise. Graded Major by the review. It is remediated rather than merely documented because it sits **on the authentication path**, which the **Authorization Enforcement** standard's deny-by-default clause reaches directly, and because the fix is a few lines with no behavioural cost. |
| **CWE** | [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html) |
| **LOCATION** | `WebVella.Erp.WebAssembly/Client/Components/General/WvLogin.razor.cs`, at **both** read sites — the first-render read and the already-signed-in early-return path — with the policy helper added to `WebVella.Erp.WebAssembly/Client/Utilities/NavigatorExt.cs`. |
| **DESCRIPTION** | The most convincing possible phishing hand-off: the victim is carried to an attacker's origin at the exact moment they have just authenticated, so the journey demonstrably began on this application and a credential prompt that follows looks like a routine re-login. **The already-signed-in path matters as much as the post-login one** and is easy to overlook — it fires on first render and needs no credential at all. Maps to **OWASP A01:2021 Broken Access Control**. |
| **IMPACT** | Credential phishing with the application's own reputation behind it, and a redirect primitive usable to launder links through a trusted origin. |
| **EVIDENCE** | Verified at runtime with a reachability control first — `example.com` was confirmed reachable from the browser, so a failure to navigate could not be mistaken for a network block. `location.href` was then sampled every 100 ms for 3.2 s after each of three attack shapes: exactly one distinct href each, never leaving localhost, with zero `example.com` requests confirmed at **both** the DevTools and the OS socket level. In-page evaluation confirmed `//example.com/pwned` genuinely resolves to `https://example.com/pwned`, so the input was a real bypass and not an inert string. The essential counter-check: `/dashboard` was **accepted**, proving the policy discriminates rather than denying everything. |
| **REMEDIATION** | **Closed with an allow-list.** `GetLocalReturnUrlFromQuery` accepts a value only if `IsLocalUrl` passes — a single leading `/`, not `//`, not `/\` — and otherwise returns the caller's default, with a fallback to `/`. Each rejected shape is a real bypass rather than a hypothetical: `//evil.example` is scheme-relative and navigates off-origin while looking like a path, `/\evil.example` is treated as scheme-relative because browsers normalise the backslash, and `https://evil.example` is simply absolute. The check runs **after** decoding, which is what makes `%2F%2Fevil.example` visible. Thirteen rejected and six accepted shapes are locked in by ad-hoc assertions. Traces to the **Authorization Enforcement** standard. |

#### SR-07 — Save redirect sent a page identifier to the application route

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-03`.* Saving a custom page with no `returnUrl` redirected to `/sdk/objects/application/r/{id}/` using the **page's** identifier. That route resolves its identifier as an *application*, so it could never match, and the user was left on a dead end after a successful save. |
| **SEVERITY** | Low on the severity matrix — a minor misconfiguration with no security consequence. Graded Major by the review on workflow-correctness grounds. Remediated because the fix is a single token and the sibling page already carried the correct form. |
| **CWE** | [CWE-670: Always-Incorrect Control Flow Implementation](https://cwe.mitre.org/data/definitions/670.html) |
| **LOCATION** | `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml.cs`, in the no-`returnUrl` branch of the POST handler. The correct form was already present at `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml.cs`. |
| **DESCRIPTION** | Both route definitions were confirmed from source rather than assumed: `/sdk/objects/page/r/{RecordId}` resolves to `Pages/page/details.cshtml`, while `/sdk/objects/application/r/{RecordId}` resolves to `Pages/application/details.cshtml` and looks its identifier up as an application. Not an OWASP category; recorded for completeness because the review raised it. |
| **IMPACT** | A successful save appeared to fail. No data loss and no security consequence — the save had already committed. |
| **EVIDENCE** | The before-and-after contrast is unusually clean and was measured, not reasoned: the **new** target `GET /sdk/objects/page/r/{id}/` returns **HTTP 200**, 17,236 bytes, page title *Page details*; the **old** target `GET /sdk/objects/application/r/{id}/` returns **HTTP 404 with a zero-length body**. The `returnUrl` branch was confirmed unchanged: posting with `?returnUrl=/sdk/objects/page/l/list` still redirects there. A browser run confirmed a genuine no-op save with breadcrumb *PAGES → Reports List → details*, zero console errors and zero failed requests. |
| **REMEDIATION** | **Closed.** The redirect now targets the page route, matching the sibling handler. The `LocalRedirect` `returnUrl` branch and the antiforgery behaviour are untouched. |

#### SR-08 — Client error model described a contract the server has never emitted

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-04`.* The WebAssembly client's error model declared `Type`, `Message`, `StackTrace` and `ValidationData`. The platform emits `timestamp`, `success`, `message`, `hash`, `errors` and `accessWarnings`. So `StackTrace` and `ValidationData` bound to null on **every** failure, and the absent `Type` discriminator defaulted to `0` — which happened to be the enum member the 400 branch handled. Validation errors therefore worked **by accident**, while a 500 fell through to `throw new Exception("Not supported ApiErrorType 0 …")`: the one case where the server had something useful to say was the one case where the client discarded it and reported its own parsing confusion to the user. |
| **SEVERITY** | Medium on the severity matrix, as an information-handling defect. Graded Major by the review. Remediated because two status codes were being treated as success. |
| **CWE** | [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html) |
| **LOCATION** | `WebVella.Erp.WebAssembly/Client/Models/ApiErrorModel.cs` and `WebVella.Erp.WebAssembly/Client/Utilities/HttpExt.cs`. The authoritative envelope is `WebVella.Erp/Api/Models/BaseModels.cs`. |
| **DESCRIPTION** | Worse than the lost message: **401 and 403 matched no branch at all** and so were returned as **SUCCESS**, meaning an unauthenticated or forbidden call surfaced later as a deserialization failure or a silent null, far from its cause. Maps to **OWASP A09:2021 Security Logging and Monitoring Failures** in its client-side aspect — a failure the operator cannot see is a failure they cannot act on. |
| **IMPACT** | Users saw the client's internal parsing complaint instead of the server's reason; a forbidden or expired-session call was mistaken for a successful one, producing misleading downstream behaviour and unactionable support reports. |
| **EVIDENCE** | Locked in by assertions over real captured server bodies, including the decisive pair **`500 PRESERVES the server message`** and **`500 does NOT report 'Not supported ApiErrorType'`**. Live corroboration arrived unprompted during runtime verification: the token endpoint returned `{"object":null,…,"success":false,"message":"Invalid email or password",…}` — exactly the envelope the new model binds. |
| **REMEDIATION** | **Closed by switching on the HTTP status rather than on a discriminator the server never sends**, because the status is the only part of the contract both ends agree on. 400 raises a validation exception carrying per-field errors grouped by key, with record-level errors kept under the empty key rather than discarded; **401 raises the token exception** the pipeline already uses, so callers need no new handling; **403 raises the generic API exception**, deliberately distinct from 401 because re-authenticating cannot help and it must not be routed to the sign-in flow; 404 and everything else, 500 included, raise the generic exception with the server's own message. Envelope reading **never throws** — a parse failure must not replace the real HTTP failure with a JSON error — and message resolution never returns empty, falling back to the reason phrase and then to the status code. The discriminator was deliberately **not** reintroduced. **A second defect of the same class was found in this very fix and corrected**: the access-warning model declared only `Message`, while the platform's carries `key`, `code` **and** `message`, so `System.Text.Json` was silently discarding two members — a miniature instance of the mismatch this finding exists to correct, made worse by a doc comment asserting completeness. All three members are now declared and asserted. |

#### SR-09 — Dead image-resize contract parsed on every file download

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-05`.* The file-download action parsed `action`, `mode`, `width`, `height` and an `isImage` flag from the query string and **never resized anything**. The parsing was inert, and its presence advertised a capability the endpoint does not have. |
| **SEVERITY** | Low on the severity matrix — a minor misconfiguration. Graded Major by the review. |
| **CWE** | [CWE-1164: Irrelevant Code](https://cwe.mitre.org/data/definitions/1164.html) |
| **LOCATION** | The download action in `WebVella.Erp.Web/Controllers/WebApiController.cs`. |
| **DESCRIPTION** | The only producer of `?action=resize` anywhere in the repository was `Pages/ckeditor/ImageFinder.cshtml` — **retired by `SR-04`** — so after that retirement the parsing had no caller at all. This was verified rather than assumed for the third-party path too: `WebVella.TagHelpers` 1.8.0 contains **zero** occurrences of `action=resize` or `?width=`, so the image field's `resize-action`, `width` and `height` attributes never compose a resize URL. Removing the parsing is therefore behaviour-identical. Not an OWASP category. |
| **IMPACT** | None directly. The risk is misleading: a maintainer reading the parsing would reasonably conclude server-side resizing exists and is a supported, tested path. |
| **EVIDENCE** | The producer census and the third-party scan above, plus the retirement of the single caller under `SR-04`. |
| **REMEDIATION** | **Closed.** The dead parsing is removed and the endpoint's actual contract — it serves the stored object at full size — is documented in place with a comment, and in the [secure configuration guide](secure-configuration.md) for operators. |

#### SR-10 — Upload allow-list and inline-download allow-list disagreed

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-06`.* The upload allow-list admitted nine image types; the inline-download allow-list admitted only four. The other five — `.bmp`, `.webp`, `.ico`, `.tif`, `.tiff` — could be uploaded successfully and were then served with `Content-Disposition: attachment`, so the platform's own image field rendered a **download prompt instead of an image**. |
| **SEVERITY** | Low on the severity matrix. Graded Major by the review, on the grounds that the platform's own components were visibly broken. |
| **CWE** | [CWE-1068: Inconsistency Between Implementation and Documented Design](https://cwe.mitre.org/data/definitions/1068.html) |
| **LOCATION** | The `ALLOWED_UPLOAD_EXTENSIONS` and `INLINE_DOWNLOAD_EXTENSIONS` sets in `WebVella.Erp.Web/Controllers/WebApiController.cs`. |
| **DESCRIPTION** | All five missing types are **passive raster** formats with no scripting capability, unlike `.svg`, `.html` and `.pdf`, so admitting them to the inline set widens no script surface — and `X-Content-Type-Options: nosniff` is emitted platform-wide, which is what makes that statement safe rather than hopeful. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | A functional defect in the image and file field components for five of the nine admitted types. |
| **EVIDENCE** | Confirmed at runtime by uploading and rendering each of `.bmp`, `.webp`, `.ico`, `.tif` and `.tiff` alongside `.jpg` and `.png`, and confirming the response carries **no** content-disposition; and by confirming `.svg` and `.html` are still refused outright at upload. |
| **REMEDIATION** | **Closed** by aligning the inline set with the passive-raster half of the upload set. `.svg`, `.html` and `.pdf` remain **excluded** by design, and the derivation is now stated in the comment so the two sets cannot drift apart again silently. One residual is recorded rather than hidden: no mainstream browser ships a TIFF decoder for `<img>`, so a stored `.tif` shows a broken image regardless of disposition — an owner decision, documented in the [risk register](risk-register.md). |

#### SR-11 — Third-party upload error handlers were themselves broken

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-07`.* The third-party tag-helper package's upload error callbacks read `JSON.parse(xhr.responseText).Message` — the envelope member is camelCase `message`, so this is always `undefined` — and referenced an **undeclared** `response` variable, which raises a `ReferenceError` that aborts the handler. The visible effect is that a refused upload left the control **frozen with no feedback at all**. |
| **SEVERITY** | Low on the severity matrix. Graded Major by the review, because a security refusal that produces no feedback trains users to retry rather than to correct. |
| **CWE** | [CWE-755: Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html) |
| **LOCATION** | The defect is inside `WebVella.TagHelpers` and **cannot be edited** — vendor code, version updates only. The remediation vector is `WebVella.Erp.Web/wwwroot/js/site.js`, which every page emits after jQuery. |
| **DESCRIPTION** | **Upgrading is not a remedy, and this was checked rather than assumed**: versions 1.8.1 and 1.8.2 were fetched from nuget.org and both still contain four `.Message` reads and four `+ response.message +` references. The vendor's own toast text is additionally a hardcoded generic string, so even without the `ReferenceError` it could never have shown the server's reason. Maps to **OWASP A09:2021 Security Logging and Monitoring Failures**. |
| **IMPACT** | Users could not tell a rejected upload from a hung one. Because the refusals here are the `SR-12` size and dimension bounds and the type allow-list, this silently undermined the visible half of three security controls. |
| **EVIDENCE** | Verified at runtime through the real UI, not simulated: `evil.svg`, `bomb.png` and `evil.html` each surfaced the exact server sentence on two channels. Causation was proven with two synthetic probes — a defect-bearing callback was **replaced** while a correct one was **left untouched**. `bomb.png` simultaneously demonstrated `SR-12`'s pixel bound firing through the real UI on a legitimate `.png`. |
| **REMEDIATION** | **Closed with a defensive `$.ajaxPrefilter` wrapper** that parses the real camelCase envelope, surfaces a visible message, and swallows exceptions thrown by the package's own callback so a control can never freeze — while never touching the success path. It was verified that this wrapper **pre-dated the checkpoint baseline**, so the correct disposition was to prove or disprove it at runtime rather than re-implement it. Doing so surfaced `SR-16`. |

#### SR-12 — Image dimension reading was Windows-only, and dimensions were unbounded

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-08`.* Image dimensions were read with `System.Drawing.Image.FromStream` behind a `CA1416` platform-warning suppression. On this Linux container that call throws `System.TypeInitializationException` from `Windows.Win32.PInvokeGdiPlus`. Because all three call sites sit inside `if (mimeType.StartsWith("image"))`, **every image upload failed on Linux**. Separately, no bound existed on pixel dimensions, so a small compressed file could demand an enormous decode. |
| **SEVERITY** | High. A decompression-bomb path is a denial-of-service primitive on an authenticated endpoint, and the platform dependency made the feature wholly non-functional on the target OS. Graded Major by the review. |
| **CWE** | [CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)](https://cwe.mitre.org/data/definitions/409.html) and [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) for the suppressed platform warning. |
| **LOCATION** | `WebVella.Erp/Utilities/Helpers.cs`, consumed at two sites in `WebVella.Erp.Web/Controllers/WebApiController.cs` and one in `WebVella.Erp.Web/Services/UserFileService.cs`. The shared refusal helper is in the same controller. |
| **DESCRIPTION** | The suppression is the tell: it silences the analyzer that was correctly reporting the API as Windows-only. Maps to **OWASP A05:2021 Security Misconfiguration**, with the amplification aspect under **A04:2021 Insecure Design**. |
| **IMPACT** | Image upload was unusable on the platform's supported OS. The unbounded path allowed a small upload to force a large allocation on the server. |
| **EVIDENCE** | The platform failure was **reproduced empirically** on a standalone `net10.0` project with `System.Drawing.Common` 10.0.1 on this container, throwing the type-initialization exception — it is not inferred from documentation. The crash even left a 65 MB core dump, which was removed during hygiene. |
| **REMEDIATION** | **Closed with a bounded, cross-platform, header-only dimension reader** covering PNG, JPEG, GIF, BMP, WEBP, ICO and TIFF, which never throws and returns absent dimensions rather than failing, with all three call sites handling absence without changing the record contract. The `CA1416` suppression is **deleted** rather than re-scoped, and `System.Drawing` is no longer referenced from any source file in the core or web projects. A pixel-dimension and total-pixel bound was added to the shared refusal helper that every upload action already calls, so all four actions return one bounded, standard refusal. Sixty-six assertions cover every admitted image type and the oversize refusal. Traces to the **Injection Prevention** standard's allow-list-validation clause. |

#### SR-13 — Security documentation asserted a state the code did not hold

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `M-09`.* This document set recorded *Highest-severity open item — none in the code* and an output-encoding row implying the cross-site-scripting sink census was complete, while sixteen defects — four of them Critical, and one a live stored-XSS chain — were present in the frontend and API seam. The risk register carried no entry for any of them. |
| **SEVERITY** | Medium — *information disclosure* in its inverse form: a security artefact that overstates its own coverage. Graded Major by the review. |
| **CWE** | [CWE-1059: Insufficient Technical Documentation](https://cwe.mitre.org/data/definitions/1059.html) |
| **LOCATION** | `docs/security/security-audit-report.md`, in the state-of-the-remediation table and the before-and-after evidence table; `docs/security/secure-configuration.md`, in the `H-06` closure guidance; and `docs/security/risk-register.md`. |
| **DESCRIPTION** | The failure mode is specific and worth naming, because it is the one this document set is most prone to: **a claim measured correctly at the time it was written, left standing as though it were unconditional.** *None in the code* was true of everything then reviewed; it was not true of the seam, which had not been reviewed. Maps to **OWASP A09:2021 Security Logging and Monitoring Failures**. |
| **IMPACT** | A reader — an operator deciding whether to deploy, or an auditor sampling the evidence — would conclude the platform carried no open Critical code defect while four were live. |
| **EVIDENCE** | The two claims are quoted at their locations, and the sixteen findings that contradicted them are `SR-01` through `SR-16` in this part. |
| **REMEDIATION** | **Closed by correction rather than by overwriting**, which is this document set's established convention: each stale claim is struck through and restated with the reason it was wrong, so a reader can see the drift rather than only its repair. The open-item row now states the qualifier that makes it checkable — it is bounded by what has been reviewed, not by what exists. The output-encoding row now states its own scope explicitly: **it counts Razor raw-output sites, not sinks**, which is precisely why a client-side `innerHTML` sink survived it. Risk-register entries were added for every residual and accepted decision arising from this pass. |

### Low severity seam findings

#### SR-14 — Stale API-contract sentence contradicted the remediation log

| Field | Value |
| --- | --- |
| **FINDING** | *Review identifier `L-01`.* The audit report's additional-acceptance-criteria list stated that the API contract changed in exactly **one** way — the removal of stack-trace text from two error bodies. The remediation log had already been corrected to state **four** intentional changes, one of which is an added route. The two artefacts contradicted each other. |
| **SEVERITY** | Low — a documentation inconsistency with no code consequence. Graded Minor by the review. |
| **CWE** | [CWE-1059: Insufficient Technical Documentation](https://cwe.mitre.org/data/definitions/1059.html) |
| **LOCATION** | `docs/security/security-audit-report.md`, in the additional acceptance criteria, against the authoritative statement in row 15 of `docs/security/remediation-log.md`. |
| **DESCRIPTION** | The remediation log had already caught and corrected its own version of this claim; the audit report's copy was not updated in the same change, so the corrected and the uncorrected form coexisted in one document set. Not an OWASP category. |
| **IMPACT** | A reader reconciling the two artefacts would find one of them wrong and have no way to tell which, which devalues both. |
| **EVIDENCE** | Both sentences quoted at their locations. |
| **REMEDIATION** | **Closed.** The audit report now carries the same four-item enumeration the remediation log carries, with the retracted absolute form quoted so the correction is visible. The narrower claim that *is* absolute — **no route template, verb or authorization attribute changed after the checkpoint baseline** — is stated separately and was **re-verified over this pass's changes as well**, by filtering the full diff for route, verb, authorization, endpoint-mapping and page-convention lines, which returns nothing. |

### Two defects found while remediating, which the review could not have seen

Recorded as findings in their own right rather than folded into the fourteen, because both were introduced
**after** the checkpoint the review examined — one by a commit inside this engagement, and one by a
remediation in this very pass. A reader auditing this work should be able to see both.

#### SR-15 — File move was broken by an unbound SQL parameter

| Field | Value |
| --- | --- |
| **FINDING** | A **post-baseline regression**, introduced by a commit inside this engagement and therefore invisible to the review. The move statement named `@expected_id` in its predicate but **never bound it**, while binding `@source_filepath` twice. PostgreSQL rejected the statement with error `42703`, so **every** file move failed. |
| **SEVERITY** | High by impact — a core data-path operation was wholly non-functional, and one of its five callers is the record-create promotion path. Not a confidentiality or integrity weakness. |
| **CWE** | [CWE-628: Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html) |
| **LOCATION** | `WebVella.Erp/Database/DbFileRepository.cs`, in the move implementation. |
| **DESCRIPTION** | The blast radius is far wider than the endpoint that exposed it, and enumerating the callers is what established that: `/fs/move/`, record **CREATE** promotion, record **UPDATE** promotion, and user-file promotion — **five call sites, every one of which passes a pinned source identifier**, so the broken branch was the *only* branch ever taken. Maps to **OWASP A04:2021 Insecure Design** only loosely; it is primarily a correctness defect on a security-relevant path. |
| **IMPACT** | No file could be promoted from staging to permanent storage. Uploads appeared to succeed and then did not materialise. |
| **EVIDENCE** | Reproduced directly against PostgreSQL, and the provenance established with `git show` against the checkpoint baseline rather than assumed — the defect is **absent** at the baseline and present at HEAD, which is what identifies it as a regression from this engagement rather than a pre-existing product defect. |
| **REMEDIATION** | **Closed at the root cause rather than by re-synchronising the two conditionals.** The method's own documentation already described the `id = @expected_id` conjunct as a **tautology**, and it is: the method refuses earlier when the resolved file's identifier differs from the expected one, and the `@id` it binds *is* that identifier. So the conditional SQL and conditional binding were removed entirely in favour of one unconditional statement. Repairing the binding would have restored a construct that was redundant *and* fragile; removing it eliminates the failure mode. The documentation comments were reconciled in the same change, and a hazard introduced by that edit — a wrapped comment line beginning `///fs/move/`, which the compiler would read as a misplaced doc comment — was caught and reflowed. |

#### SR-16 — A refusal message survived a later successful upload

| Field | Value |
| --- | --- |
| **FINDING** | A regression introduced **by the `SR-11` remediation itself**, found by runtime verification of that remediation rather than by inspection. The new error wrapper surfaced a refusal message correctly, but nothing cleared it — so after a user corrected the problem and uploaded successfully, the **stale refusal remained visible** beside a control that had just succeeded. |
| **SEVERITY** | Low — misleading feedback, no security consequence. Recorded because it is a user-visible defect created by a fix in this pass, and the zero-new-issues obligation makes it this pass's to resolve. |
| **CWE** | [CWE-1076: Insufficient Adherence to Expected Conventions](https://cwe.mitre.org/data/definitions/1076.html) |
| **LOCATION** | `WebVella.Erp.Web/wwwroot/js/site.js`. |
| **DESCRIPTION** | A one-directional control: it wrote a message on failure and had no path that removed one. Not an OWASP category. |
| **IMPACT** | A user who fixed the problem was told they had not. Worse than no message, because it makes a working control look broken. |
| **EVIDENCE** | Exercised in one session with no reload and a constant identifier: `400 → 200 → 400 → 200 (+200)`. After each success the refusal container is 0 total and 0 visible and the sentence is absent from raw `innerHTML`; and the essential counter-check passed — the refusal **re-appears** on the next genuine failure, so the fix clears rather than suppresses. Freshness was proven independently before the assertions, by confirming the reload actually hit the network. |
| **REMEDIATION** | **Closed** by extracting the field-anchor resolution and adding an explicit clear registered through `jqXHR.done(...)`. That mechanism was chosen deliberately over wrapping the request's success callback, for two measured reasons: jQuery installs the request's own success callback **after** prefilters run, so a prefilter cannot see it; and a `typeof === "function"` wrapper would silently discard an **array** of success handlers, which jQuery permits. |

## Part 5: The checkpoint code review of the remediation itself


A code review of the remediation at the final checkpoint raised **twenty-three** findings — one Critical,
three High, eight Medium, four Low and seven release or compliance blockers. All twenty-three are recorded
here. Sixteen are closed by code changes, two are documented-only under explicit AAP exclusions, one is a
governance decision whose mechanism is closed but whose answer belongs to the repository owner, and one is a
process failure that cannot be fixed retroactively and is instead complied with from this point.

**Why this part exists as its own inventory.** Parts 1 through 3 audit the product and review that audit;
Part 4 reaches the frontend and API seam. This part is different in kind: its subject is **the remediation**.
One of its findings is a Critical remote-code-execution path that the remediation's own gate could not see, and
four more are findings about the gates themselves — a vacuous dependency verdict, a verification matrix with no
scenario for the fixes most recently made, an analyzer suppression justified by a measurement of one project
and applied to nineteen, and a licence decision recorded nowhere. A gate that cannot detect the defect it
exists to detect is a finding in its own right, and grouping those five together is what makes that legible.

**On identifiers.** These records use the `CK-` prefix, unused anywhere in this repository before this part,
for the reason Part 4 chose `SR-`: the review's own identifiers include `CR-01`, which is one character from
the existing Part 2 record `CR-1`, and a document set whose workflow asserts identifier uniqueness on every
run should not carry two identifiers that differ only by a leading zero. The review's identifier is given in
the first field of every record, so a reader holding the review can follow it without guessing.

**On verification.** Where a record says a fix was *verified*, it was executed against a running host and a
live PostgreSQL instance, or in a real browser, or by extracting the workflow step and running it with negative
controls — never by reading the code and concluding it must work. Four of the fixes additionally carry a
committed, commit-bound attestation in `manual-verification-results.txt` as matrix scenarios `M26` through `M29`.

#### CK-01 — Authenticated remote code execution at the page-component render route

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `CR-01`. Authenticated remote code execution at the page-component render route. |
| **SEVERITY** | Critical — remote code execution reachable by any authenticated principal, of any role. |
| **CWE** | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html), [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html), [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html). OWASP A03:2021 Injection compounding A01:2021 Broken Access Control. |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs`, the `PageComponentRenderViews` action behind `POST api/v3.0/pc/{fullComponentName}/view/{renderMode}`. |
| **DESCRIPTION** | The action accepted a `[FromBody] JObject options` and passed it to the component under any render mode with no authorization check of its own. `PcHtmlBlock` resolved the supplied `Html` option through `PageDataModel.GetPropertyValueByDataSource`, which for a variable of type `CODE` calls `CodeEvalService.Evaluate` and thence `CSScript.Evaluator.LoadCode` with `ReferenceDomainAssemblies` set. The five page-node mutation actions that normally write those options were already administrator-gated; this route reached the same evaluator without persisting anything first, so the gate on those five was bypassable by going round them. The `SafeCodeDataVariable` flag is not a sandbox — it swallows faults, and only for the `options` mode. |
| **IMPACT** | Any authenticated principal could execute arbitrary C# inside the host process, with the platform's own assemblies referenced. That is not elevated data access: it is code execution as the application identity, so every credential, key and connection string the process can read is reachable. |
| **EVIDENCE** | Reproduced end to end against a running host. A payload of `{"IsVisible":"","Html":"{\"type\":1,\"string\":\"<C# implementing ICodeVariable>\"}"}` whose `Evaluate` wrote a marker file was posted to the route; the marker appeared on disk and the response body carried the payload's return value. |
| **REMEDIATION** | **Closed.** The three authoring render modes — `design`, `options` and `help` — and the node-less path now require `IsCodeAuthoringAuthorized`, returning the existing audited `CodeAuthoringForbidden` refusal. For `display` with a node the request body is **discarded**: the node is resolved from the page's own flat node list, binding `nid` to `pid` (CWE-639), its component name must equal the route's, and the options are read from `ParsePersistedNodeOptions(pagebodyNode.Options)`. Verified as matrix scenario `M26`: three modes and the node-less path refused 403, the persisted option rendered, a wrong-component and a cross-page `nid` refused 404, the administrator surface unchanged, and the marker never created — with a positive control proving the payload does compile and run for an administrator, so the refusals are refusals. Twelve audit rows were written, none containing the submitted source. **Accepted residual:** an administrator can still have request-supplied C# compiled through the authoring modes, which is what those modes are for. |

#### CK-02 — Session revocation was process-local, so it failed open on restart, on a second instance and under cache pressure

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `H-OPEN-01`. Session revocation was process-local, so it failed open on restart, on a second instance and under cache pressure. |
| **SEVERITY** | High — a revoked credential could be accepted again. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html), [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html). OWASP A07:2021 Identification and Authentication Failures. |
| **LOCATION** | `WebVella.Erp.Web/Services/SessionRevocationService.cs`, consumed by `AuthService`, the cookie ticket-validation hook in `ErpMvcExtensions` and both JWT hosts. |
| **DESCRIPTION** | Revocations lived only in a per-process `MemoryCache`. A restart emptied it, a second instance never saw it, capacity eviction could discard an unexpired entry, and a store that could not be consulted was indistinguishable from a clean one — so an outage granted every copied credential the benefit of the doubt. |
| **IMPACT** | A logout, or any other revocation, could be undone by a process restart, bypassed by reaching a different instance, or aged out under load. A stolen bearer token therefore remained usable for its full lifetime despite an explicit revocation. |
| **EVIDENCE** | Reproduced against the live database: a token refused after logout was accepted again by a freshly started process, and by a second instance on the same database. |
| **REMEDIATION** | **Closed with no schema change.** A new `DbSecurityStateRepository` provides an atomic, expiring, shared key/value store over the pre-existing `plugin_data` table under the reserved key prefix `wv_sec_`, on its own connection so it never enlists in an ambient business transaction. `SessionRevocationService` writes and reads there, keeps the process cache only as a positive-only fast path whose entry can never outlive the durable fact it mirrors, and **fails closed** when the store cannot be reached. Verified as matrix scenario `M27`, including 20,049 distinct revoked sessions driven through a mirror bounded at 20,000 with an early witness session still refused, and a live token refused while the store was renamed away. |

#### CK-03 — Login lockout counters were process-local and capacity-evictable, so the attempt budget could be handed back

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `H-OPEN-02`. Login lockout counters were process-local and capacity-evictable, so the attempt budget could be handed back. |
| **SEVERITY** | High — the mandated five-attempt lockout was avoidable. |
| **CWE** | [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html), [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html). OWASP A07:2021. |
| **LOCATION** | `WebVella.Erp.Web/Services/LoginThrottleService.cs`, wired at `ErpMvcExtensions` and consumed by `WebVella.Erp.Web/Pages/login.cshtml.cs`. |
| **DESCRIPTION** | Pre-lockout counters were held in a per-process cache at low eviction priority. A restart, a second instance or capacity pressure discarded a **partial count**, which returns the attempt budget to the attacker — the one failure mode a lockout must not have. |
| **IMPACT** | Credential stuffing could proceed indefinitely at five attempts per process lifetime, per instance, or per eviction cycle, while the audit trail recorded lockouts that were not in force. |
| **EVIDENCE** | Reproduced: five failures followed by a restart admitted five more. |
| **REMEDIATION** | **Closed with no schema change**, on the same durable store as `CK-02`. Account and address counters are incremented atomically with expiration under a row lock; the reservation-before-verification contract and the whole public surface are unchanged; only an **in-force lockout** is mirrored locally, and positively, so eviction can cost a database read but never a count. Verified as matrix scenario `M28`: the decisive test is three failures, a restart, then two more — the correct password is still refused, so no budget was handed back. Also verified across a second instance, under 20,050 competing store keys, fail-closed with the store unreachable, reset on success, and a 16-minute window lapse refused at minutes 1 to 14 and accepted at 15. |

#### CK-04 — SMTP transport encryption was optional, and the shipped default permitted a silent downgrade to cleartext

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `H-OPEN-03`. SMTP transport encryption was optional, and the shipped default permitted a silent downgrade to cleartext. |
| **SEVERITY** | High — relay credential and message content transmitted in the clear. |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html), [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html). OWASP A02:2021 Cryptographic Failures. |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` at all four `Connect` sites, `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` at the fifth, and the `connection_security` field seeded by `MailPlugin.20190215`. |
| **DESCRIPTION** | The field was seeded with `"1"` — `Auto` — which MailKit resolves to `StartTlsWhenAvailable` on every port but 465: it continues in cleartext when the relay does not advertise STARTTLS, a condition an active man-in-the-middle produces by stripping the advertisement from EHLO. The option list also offered `None` and `StartTlsWhenAvailable` as ordinary choices with nothing to say either is refused. On an unencrypted session the certificate validation restored by `H-11` never runs at all. |
| **IMPACT** | The relay credential and every message body could be read and modified in transit, and the mail plugin handles user-influenced recipient addresses. |
| **EVIDENCE** | Reproduced against a relay that advertises no STARTTLS: the pre-fix build completed AUTH and DATA in cleartext. |
| **REMEDIATION** | **Closed.** `SmtpService.ResolveConnectionSecurity` is applied immediately before all five `Connect` calls: outside Development it refuses `None` and any undefined value with an actionable, secret-free diagnostic, and raises `Auto` and `StartTlsWhenAvailable` to a mandatory encrypted mode; `RequireApprovedTransport` then verifies the session that resulted. Record validation refuses a cleartext-capable mode outside Development, the seed default becomes `StartTls`, and `MailPlugin.20260807` migrates the field default and option labels on installations already provisioned — **without rewriting stored rows**, deliberately, because a stored value is hardened or refused at send time and rewriting would hide an operator's explicit choice. Verified as matrix scenario `M29`: `None` refused with no TCP session opened at all; `Auto` against a no-STARTTLS relay refused with the transcript ending at EHLO and no AUTH or DATA; `Auto` and `StartTls` against a trusted relay delivered with AUTH strictly after the handshake; modes 0, 1 and 4 refused at the create page while 2 and 3 were accepted; and the Development escape hatch still delivering over plaintext. |

#### CK-05 — An image whose dimensions sat beyond the first 64 KiB was accepted unmeasured

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-01`. An image whose dimensions sat beyond the first 64 KiB was accepted unmeasured. |
| **SEVERITY** | Medium — decode-cost bound was bypassable. |
| **CWE** | [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html), [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html). OWASP A04:2021 Insecure Design. |
| **LOCATION** | `WebVella.Erp/Utilities/Helpers.cs` image-dimension readers and `WebApiController.GetUploadImageDimensionRejectionReason`. |
| **DESCRIPTION** | The readers stopped at a `MAX_IMAGE_HEADER_PROBE_BYTES` of 64 KiB. A JPEG whose SOF marker or a TIFF whose IFD sat past that point returned no dimensions, and the caller treated *unknown* as acceptable — so the pixel-dimension cap could be skipped by padding the header. |
| **IMPACT** | A file within the byte-size cap could still carry pixel dimensions large enough to make decoding expensive, and the control that existed to prevent that did not see it. |
| **EVIDENCE** | The cap was a compiled-in constant read by every reader; a size-bounded buffer was already available at every call site, so the truncation bought nothing. |
| **REMEDIATION** | **Closed.** The probe cap is removed and the full, already-size-bounded buffer is parsed; `Helpers.IsRecognisedImageContainer` admits only recognised containers, and an admitted container whose dimensions cannot be established is **rejected** rather than accepted. The byte-size cap still precedes any dimension probe on all five upload routes, so an oversized file is never decoded. Matrix scenario `M12` was extended to assert the dimension bounds and specifically the beyond-64-KiB SOF case. |

#### CK-06 — Cookie-authenticated API mutations and a mutating logout GET had no cross-origin request contract

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-02`. Cookie-authenticated API mutations and a mutating logout GET had no cross-origin request contract. |
| **SEVERITY** | Medium — cross-site request forgery. |
| **CWE** | [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html). OWASP A01:2021. |
| **LOCATION** | `WebVella.Erp.Web/Controllers/ApiControllerBase.cs`, `WebVella.Erp.Web/Pages/logout.cshtml.cs` and the two `<a href="/logout">` anchors in `UserNav.Default.cshtml`. |
| **DESCRIPTION** | The MVC API surface carried no antiforgery contract, and logout mutated session state on a GET. `SameSite=Lax` — the deliberate choice, because `Strict` breaks the return-URL round trip — does not stop a same-site sibling origin, and a top-level GET navigation carries the cookie. |
| **IMPACT** | A cross-site page could drive a state-changing API call, or log a user out, using the victim's ambient cookie. |
| **EVIDENCE** | The AAP explicitly declines antiforgery enforcement on this surface (`M-02`) because existing JavaScript clients post no verification token, so enforcement would break working functionality. |
| **REMEDIATION** | **Closed by a fetch-metadata resource-isolation control**, which needs no client change: a new `RequireSameOriginRequestAttribute` applied once on `ApiControllerBase` refuses a **cookie-authenticated state-changing** request whose `Sec-Fetch-Site` says it is cross-site, leaving bearer and anonymous token paths untouched. The logout GET is made non-mutating for cross-site and non-navigational requests while the anchors keep working, and the POST handler with its antiforgery token is retained. Verified in a real browser: same-origin AJAX mutations and the logout anchor still work, cross-site attempts are refused, bearer mutations unaffected. **Accepted residual:** no token plumbing is added, and a request with the header absent is allowed, so an older client is not broken — documented in the risk register. |

#### CK-07 — The diagnostic notification channel sent exception detail over an unencrypted, undisposed client before the log row was written

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-03`. The diagnostic notification channel sent exception detail over an unencrypted, undisposed client before the log row was written. |
| **SEVERITY** | Medium — information disclosure, and a lost audit record. |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html), [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html). OWASP A09:2021 Security Logging and Monitoring Failures. |
| **LOCATION** | `WebVella.Erp.Web/Services/MailService.cs`, its three callers in `WebVella.Erp.Web/Services/LogService.cs`, and the request URL composed in `WebVella.Erp/Diagnostics/Log.cs`. |
| **DESCRIPTION** | The notification used `System.Net.Mail.SmtpClient` with no TLS, was never disposed, had no timeout, swallowed its failure, carried the exception detail, and was sent **before** the log row was persisted. The logged request URL included the query string. |
| **IMPACT** | Exception detail left the host in cleartext to whoever could observe the path, and because the send preceded the write, a relay that hung meant the log record was never written at all — the diagnostic channel destroying the evidence it existed to carry. |
| **EVIDENCE** | Measured: with the relay black-holed the pre-fix build blocked for 100,281 ms and the log row was **absent**; after the fix the call returned in 15,287 ms with the row present within three seconds and the notification status recorded as `NotificationFailed`. |
| **REMEDIATION** | **Closed.** The log record is persisted **first**; the notification then carries only the severity, the source and the record identifier; the client requires validated TLS, is disposed, and is bounded by an explicit 15-second timeout; a mail failure is recorded against the log row rather than replacing the application result; and the query string is stripped from the logged request URL. Note for readers of an earlier revision: the risk register described this fix as *a two-line reordering with no signature change*, which is wrong — the delivered fix does change `MailService`'s public method signature. |

#### CK-08 — The compiled-script cache was unbounded and read outside its own lock

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-04`. The compiled-script cache was unbounded and read outside its own lock. |
| **SEVERITY** | Medium — unbounded growth and a data race. |
| **CWE** | [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html), [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html). OWASP A04:2021. |
| **LOCATION** | `WebVella.Erp.Web/Services/CodeEvalService.cs`. |
| **DESCRIPTION** | A plain `Dictionary` keyed by the full source text grew without limit, and reads happened outside the write lock, so a concurrent resize could be observed mid-flight. |
| **IMPACT** | Memory growth proportional to the number of distinct scripts ever evaluated, and an intermittent fault on a hot path. |
| **EVIDENCE** | A race probe against the pre-fix build recorded **279,971,733 reads and 599 writes producing 3 `KeyNotFoundException` faults**; the same probe after the fix recorded **284,729,456 reads and 578 writes with 0 faults**. |
| **REMEDIATION** | **Closed** by moving to `MemoryCache` with atomic get-or-add, `SizeLimit = 1000` and a one-day sliding expiry. The cache is still keyed by the source text deliberately — an earlier note in the source explains that keying by a digest of the input returns the wrong compiled code on collision. The observed bound peaked at exactly 1,000 entries. |

#### CK-09 — Cookie login and bearer issuance disagreed about the credential, so some valid passwords could never obtain a token

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-05`. Cookie login and bearer issuance disagreed about the credential, so some valid passwords could never obtain a token. |
| **SEVERITY** | Medium — inconsistent credential verification. |
| **CWE** | [CWE-1076: Insufficient Adherence to Expected Conventions](https://cwe.mitre.org/data/definitions/1076.html). OWASP A07:2021. |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs`, the bearer issuance path. |
| **DESCRIPTION** | The cookie path verified the submitted password verbatim while the token path verified `password?.Trim()`. A policy-valid password with leading or trailing whitespace could therefore sign in interactively but never obtain a bearer token. |
| **IMPACT** | Not an authentication bypass — trimming can only ever make the compared value shorter — but a silent divergence between two verifications of the same secret, which is the kind of inconsistency that hides real defects. |
| **EVIDENCE** | The two call sites differed by exactly the `Trim()` call. |
| **REMEDIATION** | **Closed** by removing the trim, so both paths verify the identical byte sequence. No behaviour changes for a password without edge whitespace, which is every password the policy is likely to see. |

#### CK-10 — Any fault in the SMTP-service lookup was treated as a missing service, permanently aborting the mail

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-06`. Any fault in the SMTP-service lookup was treated as a missing service, permanently aborting the mail. |
| **SEVERITY** | Medium — improper handling of exceptional conditions. |
| **CWE** | [CWE-755: Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html). OWASP A04:2021. |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` queue lookup and `WebVella.Erp.Plugins.Mail/Api/EmailServiceManager.cs`. |
| **DESCRIPTION** | The lookup caught every exception and concluded the service did not exist, moving the email to `Aborted` — a terminal state with no retry. A transient database fault therefore destroyed deliverable mail. |
| **IMPACT** | A momentary outage silently and permanently discarded queued mail, including security notifications. |
| **EVIDENCE** | The catch was unconditional; a proven-absent service and an unreachable database produced the same outcome. |
| **REMEDIATION** | **Closed** by declaring a dedicated not-found exception in `EmailServiceManager.cs` — no new file — so a **proven** missing service still aborts while an infrastructure failure preserves the `Pending` state and the existing `RetriesCount` / `MaxRetriesCount` / `RetryWaitMinutes` retry shape. Exercised at runtime through the real queue job. |

#### CK-11 — Synchronous IO remains globally enabled on every request

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-07`. Synchronous IO remains globally enabled on every request. |
| **SEVERITY** | Medium — documented, not fixed, under an explicit AAP exclusion. |
| **CWE** | [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html). OWASP A04:2021. |
| **LOCATION** | `WebVella.Erp.Web/Middleware/ErpMiddleware.cs`, where `AllowSynchronousIO` is set unconditionally before the database context is created. |
| **DESCRIPTION** | Permitting synchronous IO on the server lets a slow client occupy a thread-pool thread for the duration of a request body, which is a thread-exhaustion vector under load. |
| **IMPACT** | Availability under adversarial load, not confidentiality or integrity. |
| **EVIDENCE** | AAP 0.3.2 declines the removal as finding `M-11`, on the grounds that synchronous manager code paths depend on it. **That rationale is plausible but was not proven, and this review establishes new evidence:** no application-code consumer of synchronous *server-stream* IO exists — zero matches for `StreamReader` over `Request.Body`, `Request.Body.Read`, `Response.Body.Write` or `StreamWriter` over `Response.Body`, and no `Response.Body` or `FileStreamResult` anywhere. The only synchronous `StreamWriter` with a `Flush` is `WebApiController.GenerateStreamFromString`, which writes to a `MemoryStream` and never needs the allowance. The AAP text additionally cites `WebVella.Erp/Utilities/CodeEvalService.cs`, a path that does not exist; the file is at `WebVella.Erp.Web/Services/CodeEvalService.cs`. |
| **REMEDIATION** | **Documented with a concrete fix path**, not remediated, because AAP 0.3.2 excludes it. Ordered path: remove the assignment; build and exercise every upload, download and export route; convert any consumer the compiler or a runtime `InvalidOperationException` identifies to its asynchronous counterpart. The evidence above suggests the conversion set is empty, which makes this a low-risk change to schedule rather than a refactor. See the risk register for the full entry. |

#### CK-12 — Two client libraries load from a public CDN with no integrity attribute, at mismatched versions

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `M-OPEN-08`. Two client libraries load from a public CDN with no integrity attribute, at mismatched versions. |
| **SEVERITY** | Medium — documented, not fixed, under an explicit AAP exclusion. |
| **CWE** | [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html). OWASP A08:2021 Software and Data Integrity Failures. |
| **LOCATION** | `WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml`, the geography branch of an administrator-only page. |
| **DESCRIPTION** | Leaflet CSS at 1.6.0 and Leaflet JavaScript at 0.7.3 are fetched from cdnjs with no `integrity` attribute and no `crossorigin`, and the two versions do not match each other. A repository-wide sweep of views for remote script or stylesheet references returns exactly these two lines. |
| **IMPACT** | A compromised or substituted CDN response executes in the origin of an administrator-only page. Bounded by the page's audience, not by any control. |
| **EVIDENCE** | Advisory status was checked live rather than assumed: the GitHub Advisory Database returns **0** advisories for the `leaflet` npm package, and OSV returns **0** vulnerabilities for `leaflet@0.7.3` and `leaflet@1.6.0`. So the risk is substitution, not a known defect. **An adjacent defect the review did not name was found at the same site:** the tile layer is fetched over plaintext `http://a.tile.openstreetmap.org/...`, which is mixed content on an HTTPS page. |
| **REMEDIATION** | **Documented with the exact remediation**, not applied, because AAP 0.3.2 declines it as finding `M-15`. Align both assets on 1.9.4 and add the verified digests — CSS `sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H`, JS `sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH` — with `crossorigin="anonymous"`, and switch the tile URL to HTTPS. **Cross-finding interaction that must not be missed:** enforcing the mandated Content-Security-Policy (`default-src 'self'`) will refuse both cdnjs assets and break this page unless they are vendored first, so CSP enforcement has two blockers rather than one. |

#### CK-13 — Audit and job log retention was count-based rather than age-based

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `L-OPEN-01`. Audit and job log retention was count-based rather than age-based. |
| **SEVERITY** | Low — retention did not do what it was documented to do. |
| **CWE** | [CWE-1053: Missing Documentation for Design](https://cwe.mitre.org/data/definitions/1053.html). OWASP A09:2021. |
| **LOCATION** | `WebVella.Erp.Plugins.SDK/Services/LogService.cs` and `WebVella.Erp.Plugins.SDK/Jobs/ClearJobAndErrorLogsJob.cs`. |
| **DESCRIPTION** | Retention kept the newest 1,000 rows and ran only when the count exceeded 1,000 **and** the oldest row was over thirty days old. An installation under that threshold kept rows forever, and one over it discarded rows by count regardless of age. |
| **IMPACT** | Neither a retention guarantee nor a growth bound. Records the security controls rely on could be discarded while stale records were kept. |
| **EVIDENCE** | The review also stated the cleanup was unregistered; that is **factually wrong** and is corrected here — `SdkPlugin.SetSchedulePlans` does create the plan and the job type is discovered by attribute. The real defect was the retention rule. |
| **REMEDIATION** | **Closed.** Retention is now purely age-based: rows older than the stated window are deleted, parameterised, under a system scope, with the description corrected so code and documentation agree. **Behaviour change worth flagging to operators:** an installation that was silently keeping 1,000 rows forever will now delete rows older than the window. The operator-initiated *clear all* handlers are deliberately untouched — they already delete unconditionally and have no retention gap. |

#### CK-14 — The schema-version read and the version-gated migration were not serialised

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `L-OPEN-02`. The schema-version read and the version-gated migration were not serialised. |
| **SEVERITY** | Low — two simultaneous starts could both migrate. |
| **CWE** | [CWE-366: Race Condition within a Thread](https://cwe.mitre.org/data/definitions/366.html). OWASP A04:2021. |
| **LOCATION** | `WebVella.Erp/ERPService.cs`, the version read and the `if (currentVersion < 4)` block. |
| **DESCRIPTION** | Nothing prevented two hosts starting at the same moment from both reading the pre-migration version and both running the migration. |
| **IMPACT** | A duplicated or partially applied data migration on a multi-instance start. |
| **EVIDENCE** | A suitable helper, `DbConnection.AcquireAdvisoryLock`, already existed in the repository and was unused here. |
| **REMEDIATION** | **Closed** by taking a transaction-scoped advisory lock on a fixed key after `BeginTransaction()` and before `CheckCreateSystemTables()`, so the read and the gated block are serialised. Released on both the success and the failure path; a single-host start is unaffected. Proven by driving two simultaneous startups. |

#### CK-15 — External storage operations ran before the database commit with no compensation

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `L-OPEN-03`. External storage operations ran before the database commit with no compensation. |
| **SEVERITY** | Low — storage could diverge from the record. |
| **CWE** | [CWE-459: Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html). OWASP A04:2021. |
| **LOCATION** | `WebVella.Erp/Database/DbFileRepository.cs`, the move and delete paths. |
| **DESCRIPTION** | The storage-side operation was performed before the surrounding transaction committed. A failed commit therefore left the bytes moved while the row said otherwise. |
| **IMPACT** | Content silently misplaced relative to its record — invisible to any row-level check, because every row is correct. |
| **EVIDENCE** | The ordering was unconditional in both paths. |
| **REMEDIATION** | **Closed** for the move path by a compensating reverse-move when the pre-commit storage move is followed by a failed commit. Matrix scenario `M25` now asserts that after a refused mutation the bytes are readable at their **original** storage path, which is the only assertion that can catch a regression here. |

#### CK-16 — HTML-encoded values were interpolated into JavaScript string literals

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `L-OPEN-04`. HTML-encoded values were interpolated into JavaScript string literals. |
| **SEVERITY** | Low — wrong encoding for the context. |
| **CWE** | [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html). OWASP A03:2021. |
| **LOCATION** | `WebVella.Erp.Web/Components/ScreenMessage/Default.cshtml`. |
| **DESCRIPTION** | Message, title and type were HTML-encoded and then placed inside JavaScript string literals. HTML encoding is the wrong escaping for a script context: it mangles legitimate text and does not neutralise the characters that matter there. |
| **IMPACT** | Corrupted notification text in the ordinary case, and a broken statement in the adversarial one. |
| **EVIDENCE** | Measured in a real browser against both builds. Before: a backslash payload produced `Uncaught SyntaxError: missing ) after argument list` and the notification was **never delivered**; other payloads delivered entity text — `&quot;`, `&#x27;`, `&#xA;` and `&#x2022;` verified character by character, with no code 10 or 8226 present. After: zero console errors on all seven payloads, real characters delivered (backslash 92, quote 34, apostrophe 39, newline 10, bullet 8226, angle brackets 60 and 62), all entity substrings absent, and the plain payload byte-identical to before — so no user-visible change for ordinary messages. In **both** builds no injection occurred and the script-element count stayed at 3. |
| **REMEDIATION** | **Closed** by serialising the values as JSON rather than HTML-encoding them into the literal. Both branches of the emitter were exercised. Matrix scenario `M16` was extended to cover this channel, since a regression here would not be caught by the two by-design raw channels it previously named. |

#### CK-17 — The dependency licence decision was a transient build property rather than a durable record

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `GOV-01`. The dependency licence decision was a transient build property rather than a durable record. |
| **SEVERITY** | Release blocker — governance. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html). OWASP A08:2021. |
| **LOCATION** | `Directory.Build.props`, the `ErpAssertAutoMapperLicenceDecisionRecorded` target, and the four packable manifests. |
| **DESCRIPTION** | The pack-time gate existed but was satisfied by passing `-p:ErpAutoMapperLicenceDecision=` on the command line. A property supplied per invocation is not authenticated approval and leaves no reviewable trace, so the gate could be cleared by whoever ran the build. |
| **IMPACT** | A product whose manifests declare a permissive expression could be packaged while depending on a reciprocal-licensed library, with no record of who decided that. |
| **EVIDENCE** | The property was read directly by the target with no persistence of any kind. |
| **REMEDIATION** | **Mechanism closed; the decision itself remains an owner action.** The target now reads a decision-shaped record out of the tracked `docs/security/risk-register.md`, requiring the exact answer plus an `approver:`, an ISO `date:` and a `ref:`; a command-line property is **refused** rather than honoured. Verified by execution in eight states, each producing its own diagnostic code `ERPLIC001` through `ERPLIC007` — including that the register's own documentation of the record shape does not satisfy the gate. A workflow step additionally asserts the record is tracked, unmodified and singular. Absence exits zero with an explanation, because per AAP 0.6.5 the decision is escalated to the repository owner and must not be taken by an automated agent. |

#### CK-18 — The dependency-scan verdict was vacuous, its evidence unbound, and advisory drift unscanned

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `GATE-01`. The dependency-scan verdict was vacuous, its evidence unbound, and advisory drift unscanned. |
| **SEVERITY** | Release blocker — supply chain. |
| **CWE** | [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html). OWASP A06:2021 Vulnerable and Outdated Components. |
| **LOCATION** | `.github/workflows/security-scan.yml`, the dependency pipelines and the evidence publication step. |
| **DESCRIPTION** | `dotnet list package` can enumerate nothing and still exit zero, so a listing that covered no project reported clean. Failure status was not captured uniformly, the published artifact was not bound to a commit, and nothing re-scanned an unchanged tree against a changed advisory database. |
| **IMPACT** | A green tick that meant nothing, and no way to tell later which tree a clean result described. |
| **EVIDENCE** | Reproduced by extracting the step and running it: the original form passed with output no assertion examined. |
| **REMEDIATION** | **Closed.** Each listing captures its exit status explicitly, sweeps its own output for tool-error signatures, and asserts that **every** solution member appears — the member list derived from `dotnet sln list` so it cannot drift. A new step writes an `evidence-manifest.txt` carrying the commit, ref, event, run, timestamp, SDK version and a SHA-256 plus byte size per evidence file, and fails when a file is missing; the artifact name is commit-bound and `if-no-files-found` is an error. A weekly schedule provides drift scanning. The authoritative current run is retained: **17 of 17 solution members enumerated, 17 reporting no vulnerable packages, 2 more for the gated projects, and zero High or Critical advisories.** |

#### CK-19 — The manual verification matrix omitted the open Critical and High findings, and no attestation existed

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `GATE-02`. The manual verification matrix omitted the open Critical and High findings, and no attestation existed. |
| **SEVERITY** | Release blocker — verification. |
| **CWE** | [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html). OWASP A09:2021. |
| **LOCATION** | `.github/workflows/security-scan.yml`, the Gate 5 matrix and the release gate. |
| **DESCRIPTION** | The matrix declared 41 rows and had no scenario for the page-component render route, nor for the restart, multi-instance, capacity and transport-downgrade boundaries of the three open High findings. `manual-verification-results.txt` did not exist, so the release gate failed on every run and no row could ever be proven. |
| **IMPACT** | The gate that exists to prove Critical and High fixes work could not reach the ones most recently fixed. |
| **EVIDENCE** | The matrix's own row list was the evidence. |
| **REMEDIATION** | **Closed.** Four REQUIRED scenarios `M26` through `M29` were added, taking the declared total to 45, and **all four were executed** against running hosts and a live PostgreSQL database and attested in the tracked `manual-verification-results.txt` with a dated, attributable, commit-bound line each. Eight existing procedures that the remediation itself had invalidated were corrected, several of which would otherwise have failed a **correct** build — the report-only Content-Security-Policy name, the deliberately generic lockout message, five upload routes rather than four, and a mail relay that must now offer STARTTLS. Verified by extracting Gate 5 and the release gate and running them, with three negative controls proving the binding binds: a locally modified file, a stale scenario revision and a non-ancestor commit are each refused. **Twenty-five manual rows remain unexecuted and are honestly `DEFERRED`, so the release gate still blocks — neither gate was weakened.** |

#### CK-20 — The analyzer gate suppressed the taint family across all nineteen projects and could not see the render-route defect

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `GATE-03`. The analyzer gate suppressed the taint family across all nineteen projects and could not see the render-route defect. |
| **SEVERITY** | Release blocker — static analysis. |
| **CWE** | [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html). OWASP A03:2021. |
| **LOCATION** | `Directory.Build.props` analyzer configuration and the workflow's Gate 1. |
| **DESCRIPTION** | `AnalysisLevelSecurity=latest-all` armed the Security category, but `CA3001`–`CA3012` were suppressed unconditionally for every project on the strength of a measurement that implicated one. Gate 1 also had no assertion about the render route, so it could be green while remote code execution existed. |
| **IMPACT** | A gate that reported silence from rules that were not running, and that could not detect the reintroduction of the Critical finding. |
| **EVIDENCE** | Measured per project with the suppression overridden: **eighteen of nineteen complete in 0 to 6 seconds each with zero `CA3001`–`CA3012` diagnostics**, and `WebVella.Erp.Web` alone is killed at a 600-second bound. Summed baseline for the eighteen was 43 seconds against 45 seconds armed — within noise. A full solution build before and after produced **identical** diagnostics: 614 distinct (file, rule) pairs over 6,108 occurrences, 3,055 warnings, 0 errors. |
| **REMEDIATION** | **Closed.** The suppression is now conditioned on `MSBuildProjectName` and applies to `WebVella.Erp.Web` alone, with both values exposed as readable properties that Gate 1 reads back and asserts per project. The positive control was flipped from *must not fire* to **must fire**, so the eighteen zeros are provably an absence of defects. A new Gate 1 step asserts the render route still exists, carries seven exact authorization invariants, that the privilege check precedes component-type resolution by line number, and that the runtime-compilation inventory is unchanged — with comment lines excluded so a documentation edit cannot fail it. Three negative controls each fail the gate. |

#### CK-21 — The documentation claimed an administrator password is generated and printed

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `DOC-01`. The documentation claimed an administrator password is generated and printed. |
| **SEVERITY** | Release blocker — documentation accuracy. |
| **CWE** | [CWE-1053: Missing Documentation for Design](https://cwe.mitre.org/data/definitions/1053.html). OWASP A09:2021. |
| **LOCATION** | `README.md`, `docs/security/credential-migration.md`, `docs/security/secure-configuration.md`, `docs/security/remediation-log.md` and this report. |
| **DESCRIPTION** | Several passages described provisioning as generating a random administrator password and surfacing it once on standard error, and one document contradicted itself within a dozen lines. The code does neither: `ERPService.ResolveInitialAdministratorPassword` throws when `Settings:InitialAdministratorPassword` is blank, so provisioning is refused inside its own transaction. |
| **IMPACT** | An operator following the documentation would wait for a notice that never arrives and conclude the product is broken, or worse, look for a credential in logs that never contained one. |
| **EVIDENCE** | Verified against the source: the only remaining CSPRNG generator serves the local `system@webvella.com` background identity, whose value is hashed on write and never printed. |
| **REMEDIATION** | **Closed.** Every generated-and-printed claim is removed, the fail-closed behaviour is stated with the setting name, the settings inventory is corrected, the self-contradicting route in the migration guide is deleted, and the historical passages that record the interim generated-password revision are framed unambiguously as historical. A sweep of the whole documentation set now returns no present-tense generation claim. |

#### CK-22 — Authoritative status, count and control statements had drifted from the tree

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `DOC-02`. Authoritative status, count and control statements had drifted from the tree. |
| **SEVERITY** | Release blocker — documentation accuracy. |
| **CWE** | [CWE-1053: Missing Documentation for Design](https://cwe.mitre.org/data/definitions/1053.html). OWASP A09:2021. |
| **LOCATION** | `SECURITY.md`, `docs/index.md`, this report, `docs/security/risk-register.md` and `docs/security/remediation-log.md`. |
| **DESCRIPTION** | The gate tables described the analyzer scope, the matrix size and the process-compliance status as they had been several revisions earlier; the workflow shape was cited as 20 steps, 17 run steps and 41 rows; the risk register listed an SMTP setting that does not exist in the code while its own neighbouring paragraphs recorded its removal; and the compensating control for the four by-design raw channels was stated as though only privileged users could influence the rendered bytes. |
| **IMPACT** | A reader relying on these documents would over-estimate the coverage of the automated gate and mis-state the residual risk. |
| **EVIDENCE** | Each claim was checked against the tree rather than against a sibling document. The privileged-authoring claim is the substantive one: `PcHtmlBlock` resolves its option through `PageDataModel.GetPropertyValueByDataSource`, whose model exposes `Record`, `ParentRecord` and `CurrentUser`, so an administrator may point a raw channel at a record field an ordinary user can write. |
| **REMEDIATION** | **Closed.** The gate table now records the analyzer scope as one excluded project rather than eleven absent families, and Gate 5 as 45 rows with four attested and twenty-five deferred; the workflow shape reads 23 steps, 20 run steps, 21 published evidence paths and 45 rows; `RISK-051` is restated with its previous framing preserved as a superseded statement per the register's own convention; the nonexistent SMTP key is marked as such wherever it appeared; and the compensating control is restated precisely — **a privileged role decides what is rendered raw, not who supplies it**, which is why the Content-Security-Policy is the load-bearing half. Eight further contradictions surfaced while checking each cited line against the tree rather than against a sibling document, and all eight are closed in the same pass: the *Freshly measured evidence* table's row recording seven security families as silent **because they did not run** now records four of them reporting real diagnostics, since `AnalysisLevelSecurity` was added after that measurement; the Gate 1 detail subsection said four families execute and eleven are disabled, and now baselines twelve totalling 55 diagnostics with the two genuine gaps named; `RISK-027`'s summary row and Status field said *Accepted* and *no change-required-on-first-login marker* while its own body recorded the residual as discharged and the marker exists in `ErpUserPreferences.PasswordChangeRequired`; the login throttle was described as per-instance and cleared by a restart in `SECURITY.md`, the secure-configuration guide and the credential-migration guide, which `H-OPEN-02` reversed; the secure-configuration guide asserted **no** `AnalysisLevelSecurity` upgrade, contradicting `SECURITY.md` and the tree; it described the diagnostic notification client as negotiating no TLS at all, which `M-OPEN-03` reversed; it told an operator that a cleartext `connection_security` row *delivers*, which `H-OPEN-03` reversed to a refusal; and its own reproducible key sweep returns 39 lines against the 40 keys it documents, because two are read section-relative and the pattern cannot see them — the arithmetic is now stated rather than left to look like an error. One claim in a working note was **corrected upward**: `ErpErrorHandlingMiddleware` is not unregistered; all seven hosts call it inside the non-Development branch, so its two empty handlers are live in production and inert in development. |

#### CK-23 — Historical commits mixed vulnerability classes

| Field | Value |
| --- | --- |
| **FINDING** | Review identifier `PROC-01`. Historical commits mixed vulnerability classes. |
| **SEVERITY** | Release blocker — process. |
| **CWE** | [CWE-1164: Irrelevant Code](https://cwe.mitre.org/data/definitions/1164.html). Not an OWASP category. |
| **LOCATION** | The commit history of the remediation. |
| **DESCRIPTION** | Minimal Change guideline 9 requires one atomic commit per vulnerability class. Seven of thirteen commits in the original remediation carry more than one class. |
| **IMPACT** | A reviewer cannot revert or audit a single vulnerability class when it is entangled with others in one commit. |
| **EVIDENCE** | The commit history is the evidence, and it cannot be rewritten without discarding the audit trail the finding exists to protect. |
| **REMEDIATION** | **Cannot be fixed retroactively; complied with from this review onward.** Every commit made while closing these findings carries exactly one vulnerability class — eighteen consecutive single-class commits at the time of writing, each naming its class and its finding identifiers in the message. The historical failure is retained rather than erased, because acknowledging it is not the same as complying with it and erasing it would be worse than either. |
## Residual coverage gap

Stated plainly rather than implied away, because the alternative is a reader believing the automated gate
covers all nineteen projects uniformly. It does not, and the reason is structural.

**Two projects are not members of the solution.** `WebVella.Erp.WebAssembly/Server` and
`WebVella.Erp.WebAssembly/Shared` are absent from `WebVella.ERP3.sln`; only the Client project appears
there. Measured at this commit: the solution file contains nineteen `Project(` entries but only
**seventeen** `.csproj` members, the other two entries being solution folders, and a search of the
solution for either WebAssembly Server or Shared returns nothing. A solution-level restore, build or
vulnerability listing therefore **never reaches those two projects**, and neither would a workflow that
drove the solution alone.

Two things follow, and they pull in opposite directions, so both are recorded.

*What is closed.* Gate reach does not depend on solution membership, because `Directory.Build.props` is
inherited by **directory location**: all six gate properties evaluate on 19 of 19 projects. Command
coverage is closed deliberately rather than by editing the solution — the security workflow drives the
solution once and then drives each of the two non-member projects by name, restoring, building and
listing vulnerable packages for each, and additionally asserting each one's `TargetFramework` per project,
which is an assertion a solution-level command cannot make. That is why the dependency result quoted in
[Gate 2](#validation-gates) takes three commands rather than one.

*Why the projects were not simply enrolled.* An earlier revision added them to `WebVella.ERP3.sln` and
then described one dependency graph three different ways in consequence. The enrolment was withdrawn: the
change boundary for this engagement authorises the `H-19` casing repair to the solution file and nothing
else, and enrolling two projects is a structural change to the build graph rather than a security fix.
Adding them remains the right long-term answer and is recorded as a recommendation in the
[risk register](risk-register.md), not performed here.

**One defect in this area is now closed, and the correction is stated as measured rather than repeated
from expectation.** At the audit baseline `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj:L14`
declared `<ProjectReference Include="..\Client\WebVella.Erp.WebAssembly.Client.csproj" />` — **a file that
does not exist**. The real Client manifest is
`WebVella.Erp.WebAssembly/Client/WebVella.Erp.WebAssembly.csproj`, with no `.Client` suffix, which the
solution file had always referenced correctly. The Server project was therefore not merely unscanned but
**structurally unbuildable**, and an earlier revision of this report recorded it as such. Re-verified at
this commit: the reference now reads `..\Client\WebVella.Erp.WebAssembly.csproj` and the project builds —
exit 0, **0 errors**. It was repaired by the same change that retargeted both projects off the end-of-life
framework for `H-18`. What remains open is only the solution membership described above.

## Before and after evidence

Every Critical and High finding is evidenced by tool output or by an exact file-and-line locator, never by
narrative assertion. The **before** construct for each is in its own record in
[Part 1](#part-1-the-audit-inventory), read from the audit baseline; the **after** state is the changed
construct plus the gate output that demonstrates closure. What follows is the evidence chain per class,
so that a reader can reproduce it rather than take it on trust.

| Class of finding | Before — how it was reproduced | After — what demonstrates closure |
| --- | --- | --- |
| Dependency advisories (`H-01`, `H-20`) | A live reproduction was available for the mail advisories immediately: listing vulnerable packages **for the mail project alone** reported both the MailKit and MimeKit advisories, because both are reachable from a single-project restore. The object-mapping advisory behaves differently and the difference is the whole point of `H-19` — it surfaces only on a **solution-wide** restore, and only after the casing repair. The transcript of the negative control is recorded in the dependency inventory: `error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability` | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports nothing, plus one per-project invocation for each of the two non-member projects. `NU1901`–`NU1904` are build errors, so a regression cannot merely warn |
| Build-graph integrity (`H-19`) | A solution-wide restore failed on a case-sensitive filesystem while a per-project restore of `WebVella.Erp.Site` succeeded — the contrast that proved the defect, since that host's reference was the one already-correct instance | `dotnet restore WebVella.ERP3.sln` exits 0 with zero `NU19xx`, and `dotnet build WebVella.ERP3.sln` exits 0 with 0 errors. The core project is back in the graph, which is what makes every row above it meaningful |
| End-of-life framework (`H-18`) | Manifest census: 17 × `net10.0`, 2 × `net7.0` | Census re-run: **19 × `net10.0`**, asserted per project by the workflow rather than inferred |
| Secrets (`C-01`, `C-04`, `H-04`, `H-05`) | The literal values read directly from the eight `Config.json` files, from `CryptoUtility.cs:L16`, from `ErpSettings.cs:L118` and from `ERPService.cs:L467`, at the locators in each record | The Gate 3 signature sweep over the tracked tree, plus the **negative test**: start-up fails fast with an actionable message when a required secret is absent, which is what proves the fallback was removed rather than relocated. Every truncated literal quoted in this report **remains in repository history and is therefore permanently compromised — rotation is mandatory, not optional** |
| Credential storage (`C-03`, `H-17`, and `M-05`, `M-06` closed with them) | The primitive read from `PasswordUtil.cs` and the predicate read from `SecurityManager.cs:L85` | The stored format is salted and non-deterministic, verification is fixed-time, the SQL predicate carries no password term, and all four call sites route through the new primitive. Cost measured rather than asserted, and the ratio rather than the absolute value is the finding. The analyzer independently reported the old primitive as `CA5351` |
| Authorization (`C-02`, `C-05`) | The grants and the absent field permissions read from `ERPService.cs` at the locators in each record | Administrator-only field permissions in the seed, encrypted-field values redacted from read projections, the version-4 migration carrying both to existing installations, and the two plugin patches corrected so replaying them cannot re-grant what the seed removed |
| Session and token (`H-02`, `H-03`, and `M-03`, `M-04` with them) | The `TokenValidationParameters` initialiser and the hundred-year ticket read from `AuthService.cs` | Bounded ticket lifetime, lifetime validation asserted with explicit clock skew, the sign-in call awaited, UTC timestamps, and validation failures logged rather than swallowed |
| Output encoding (`H-06`, `H-07`, and `M-18` with them) | The **original audit census** — 128 `Html.Raw(` occurrences across 69 files, classified rather than counted, with 55 excluded as server-generated markup and the genuine sinks enumerated per file and line | The current census is **114 invocation sites across 62 views** after confirmed text sinks were removed. Razor automatic encoding covers the text sinks; reflected values use validated or encoded paths; the editor callback is integer-validated and script-encoded; the defective encoder is replaced; and the later `F-01` through `F-03` review sinks are closed. Several were confirmed by driving the remediated build in a real browser, as recorded in [Part 3](#part-3-product-vulnerabilities-first-discovered-by-reviewing-the-remediation). **The `Html.Raw(` census was never the whole sink surface, and treating it as such is what let one chain survive every pass above.** The Project plugin renders comment, timelog and feed bodies through a **client-side `innerHTML` assignment inside a pre-built Stencil bundle** — a sink no Razor census can see, because no Razor expression is involved. It is closed as `SR-05` by an allow-listed server-side sanitizer applied on write and again on read, and it is the reason this row now states its own scope: **it counts Razor raw-output sites, not sinks** |
| Transport, headers and origin (`H-11`, `H-14`, `H-15`, and `M-01` with them) | The always-true certificate callback at five sites, the any-origin policy at two hosts, the cookie options block, and — later, as `F-07` — a public HTTPS port accepted on nonblank text alone | All seven mandated headers emitted with the mandated values on both a dynamic and a static response; zero live `AllowAnyOrigin()` anywhere; secure cookie attributes with an explicit expiry window; transport security and redirection guarded to non-Development; certificate validation secure by default with an explicit opt-in; and the public-port channel parsed invariantly and constrained to 1-65535, with malformed values refused or explicitly reported when a trusted proxy supplies the working path |
| Injection and deserialisation (`H-09`, `H-10`) | The six concatenated identifiers and the twenty `TypeNameHandling` sites, each read at its locator | Every one of the six identifiers validated and quoted through one audited helper; the binder attached at all fourteen in-scope sites, with the six out-of-scope sites named in `H-10` rather than quietly counted as covered |
| File pipeline (`H-08`, plus review findings `F-04` and `F-05`) | The four unconstrained uploads, the four unsanitised names, the dispositionless download, the two unauthorised actions, authenticated bytes marked `public` for caches, and a destination row re-resolved after authorization during overwrite | Extension allow-list, size cap, content-type check and name sanitisation on upload; attachment disposition on download; ownership enforced on move and delete; every authenticated response private, with staged files `no-store` and ineligible for 304; and source plus authorized destination state re-verified under transaction-bound row locks before an overwrite |
| Brute force (`H-16`) | The single synchronous login entry point with no attempt counter anywhere in the tree | A throttle service consulted at that entry point, framework rate limiting in each host pipeline. The store was an in-process cache with its single-instance scope documented rather than hidden; the checkpoint review rejected that as short of the mandated bound (`H-OPEN-02`) and it is now the existing `plugin_data` table, mutated atomically, so a lockout survives a restart and spans instances — see `CK-03` |
| Error handling (`H-12`, `H-13`) | The two unconditional `e.Message + e.StackTrace` assignments at `:L4287` and `:L4306`, and `DevelopmentMode` true in all eight configurations | Generic messages with the server-side log retained, extended to every response sink in the tree; `"DevelopmentMode": "false"` in all eight files and `Production` in `web.config` |

For the code findings the closing evidence is the analyzer families reporting clean across the remediated
files together with the corresponding line of the manual verification checklist in the
[remediation log](remediation-log.md). For the two findings whose remediation carries the greatest risk of
doing harm — the credential rehash and the redaction sentinel — the checklist entries are explicit: a
legacy credential must still authenticate and be transparently upgraded, and a full-record round-trip
update must not overwrite a stored hash with the sentinel.
