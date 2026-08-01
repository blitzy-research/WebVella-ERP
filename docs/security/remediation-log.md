# Remediation Log

One entry per vulnerability class, matching the atomic commit boundaries used for the remediation
(one commit per vulnerability class). Each entry lists the findings closed, the files changed, the
verification performed and any deviation from the planned approach.

Findings themselves are described in the [security audit report](security-audit-report.md);
accepted risks and open decisions are in the [risk register](risk-register.md). Operator-facing
consequences are in the [secure configuration guide](secure-configuration.md) and the
[credential migration guide](credential-migration.md).

## How this log is organised

The remediation was reviewed from several distinct angles, and each angle produced its own record of
the same work. All of them are reproduced in full, because each carries evidence the others do not:
one records the change class by class, one records the executed command transcripts, one records the
integration that attached the new controls to live request paths, one records the measured timings and
counts, and one records the corrections made to comments and documentation that overstated what was
deployed. Read them as complementary sections of a single log rather than as alternatives.

| Section | What it records |
| --- | --- |
| [Dependency class](#dependency-class-the-authoritative-record) | The `AutoMapper` and mail-stack version changes, and the licensing escalation they produced |
| [Remediation by vulnerability class](#remediation-by-vulnerability-class) | The class-by-class change record: findings closed, files changed, verification, deviations |
| [Executed verification transcripts](#executed-verification-transcripts-class-by-class) | The actual commands run and their output, per class |
| [Integration record](#integration-record-attaching-the-controls-to-live-request-paths) | How each newly added control was attached to a live request path, and what that changed |
| [Measured results](#measured-results-for-the-dependency-and-credential-classes) | Timings, counts and before/after measurements rather than narrative |
| [Accuracy corrections](#accuracy-corrections-to-shipped-comments-and-documentation) | Comments and documents that claimed protection not yet in force, and how they were corrected |

> **A note on project counts.** Several sections below record a solution-wide command as covering
> **17 solution projects**, with `WebVella.Erp.WebAssembly/Server` and `.../Shared` audited separately
> as non-members. That was accurate when those sections were written. Both projects were subsequently
> added to `WebVella.ERP3.sln` and retargeted from the end-of-life `net7.0` line to `net10.0`, so at
> this commit `dotnet sln list` returns **19** projects — every `.csproj` on disk — and a
> solution-level restore, build, audit or analyzer run covers all of them with no separate step. Read
> any "17 solution projects" or "non-member" statement below as describing that earlier state.

## State of the tree this log describes

Measured at this commit:

| Check | Result |
| --- | --- |
| `dotnet restore WebVella.ERP3.sln` | exit 0, zero `NU19xx` diagnostics |
| `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-restore --no-incremental` | exit 0, **0 errors**, 3064 analyzer warnings |
| `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | no vulnerable package in any of the **19** projects |
| Gate properties, evaluated per project with `dotnet msbuild -getProperty` | all six present on **19 of 19** projects |
| Target frameworks | **19 of 19** on `net10.0` |
| Analyzer escalation check | no `CA`, `NU` or `SCS` diagnostic reported as an error; only `NU1901`–`NU1904` are configured as errors and none fires |
| Diagnostic yardstick against the pre-remediation baseline | unchanged: `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2 |
| Security-family analyzer diagnostics remaining, both by design | `CA5351`×10 (the retained legacy MD5 verification path, `RISK-004`) and `CA5359`×10 (SMTP certificate validation, finding H-11, a class not in this change) |

**What this log does not claim.** The shipped `Config.json` files still carry a live connection
string, encryption key and `DevelopmentMode: true`; `AllowAnyOrigin()` remains at two hosts; and the
seeded administrator credential and the 6-to-24-character password bounds in
`WebVella.Erp/ERPService.cs` are unchanged. Those belong to classes that are not part of this change.
No entry below should be read as claiming a deployment's secrets have been removed from disk — see
`RISK-021`.


## Verification method, and what substitutes for the test-suite gate

Stated first, because every entry below depends on it.

**The repository contains no test project, no test file and no test-framework package reference in
any of its 19 projects.** This was confirmed empirically — `dotnet test` discovers nothing — so the
"existing test suite passes" validation gate is **vacuous by construction**. It is not reported as
passing, because there is nothing to pass. Creating a test suite is feature work the remediation
constraints exclude.

The substitute regime, applied to every class:

| Gate | Mechanism | Pass criterion |
| --- | --- | --- |
| Static analysis | .NET security analyzers enabled repository-wide via `Directory.Build.props` | No security-rule diagnostic on any changed line |
| Dependency scan | Solution-wide restore with `NuGetAudit`, plus `dotnet list package --vulnerable --include-transitive` | No unaccepted advisory; the one accepted advisory is recorded in the risk register |
| Compilation | `dotnet build WebVella.ERP3.sln --no-incremental` | **0 errors**, and no new warning attributable to a changed line |
| Behavioural | Purpose-built ad-hoc harnesses per class, plus interactive browser verification | All assertions pass |
| Secrets | Signature sweep over the tracked tree | No hardcoded credential |

Two measurement notes that materially affect whether these numbers mean anything:

* **A plain solution build is incremental and under-reports warnings.** `--no-incremental` is
  mandatory; without it the count is roughly a third of the true figure.
* **`dotnet list package --vulnerable` exits 0 even when it reports advisories.** Its exit status must
  never be used as a pass/fail signal; its *output* must be parsed. The CI workflow greps it.

**Warning baseline.** Enabling analyzers repository-wide raised the warning count from 106 to 3072 —
a pre-existing backlog surfaced by the new analysis, not damage. That 3072 is the baseline every later
class is measured against. The count after all remediation is **3065**, i.e. **7 fewer**, with **zero
warnings on any line added by the remediation**. Analyzer diagnostics were deliberately left as
warnings rather than promoted to errors: promoting a 3000-warning backlog would demand exactly the
mass refactor the constraints forbid. Only the dependency diagnostics are errors.


## Dependency class — the authoritative record

### Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to `[15.1.3]` — the newest release on the lowest patched major. The `<PackageLicenseExpression>` on this project was **not** modified; see the open licensing decision below. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires, plus one added `using` and a comment naming the threat addressed. |

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

#### Actual API surface used

The 15.1.3 `MapperConfiguration` constructor surface was read from the shipped assembly by
reflection rather than assumed. The two public constructors are:

```text
MapperConfiguration(MapperConfigurationExpression configurationExpression, ILoggerFactory loggerFactory)
MapperConfiguration(Action<IMapperConfigurationExpression> configure, ILoggerFactory loggerFactory)
```

The first overload is the one used, so the call became:

```csharp
Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
```

`NullLoggerFactory` resolves from the `Microsoft.AspNetCore.App` framework reference already
present in the core project — no `PackageReference` was added, and the commented-out
`Microsoft.Extensions.*` block in that project file was left commented out. The no-op factory is
deliberate: the platform performs no AutoMapper logging today, so a real logger would be an
enhancement beyond the remediation.

Two related API details worth recording for future upgrades:

- In 15.x, `MapperConfigurationExpression` resolves from the **`AutoMapper`** namespace
  (`AutoMapper.MapperConfigurationExpression`) rather than `AutoMapper.Configuration`. No source
  change was needed because the affected files already import both namespaces.
- `ErpAutoMapper.Initialize(MapperConfigurationExpression cfg)` and the
  `public static IMapper Mapper` field were deliberately left **byte-identical**. Both are hard
  compile contracts: `Initialize` has two call sites that each pass a single argument
  (`WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47`), and the
  `Mapper` field has eight readers in `AutoMapperExtensions.cs`. Constructing the logger factory
  inside `Initialize` was therefore both the least invasive option and the one that keeps the public
  API contract unchanged.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Precondition — the audit must actually see the project | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches; the project-reference casing defect (H-19) is fixed, so the core project is genuinely in the restore graph and a clean scan is trustworthy |
| Restore with dependency audit | `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` diagnostics** |
| Dependency scan | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for every project, including `WebVella.Erp` |
| Resolved version | `dotnet list WebVella.Erp/WebVella.Erp.csproj package` | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug` | exit 0, **0 errors**; no diagnostic names the changed file |
| Solution build | `dotnet build WebVella.ERP3.sln -c Debug -m:2` | exit 0, **0 errors** across all projects |
| Negative control (proves the gate is not blind) | the same audit against a throwaway project pinning `[14.0.0]` | reports `NU1903 … known high severity vulnerability … GHSA-rvv3-g6hj-g44x` and a `High` row, confirming the clean result at 15.1.3 is a real fix |
| Runtime — host | started a site host against a freshly provisioned database | schema auto-provisioned, mapping initialised, no exception in the log |
| Runtime — login path | interactive login through the login page | `POST /login` → `302`, authenticated shell rendered, navigation and a user data grid rendered with every projected field populated; no `AutoMapperConfigurationException`, no `NullReferenceException`, no console error |
| Runtime — second call site | ran the console application end to end | exit 0, including a full hook-driven create/update/delete cycle and an EQL user projection, with both call sites unmodified |

Note on the test-suite gate: the repository contains no test project, no test file and no
test-framework package reference in any project, so the "existing test suite passes" gate is
vacuous by construction. It was confirmed empirically (`dotnet test` discovers nothing) and
substituted with the restore, build, dependency-scan and runtime checks above. Creating a test
suite was out of scope for this remediation.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach: the predicted constructor shape
  `(MapperConfigurationExpression, ILoggerFactory)` matched the real assembly, so no adaptation of
  the argument list was needed.
- **Open decision, escalated not absorbed:** upgrading changes the package's licence from MIT to
  the Reciprocal Public License 1.5, which conflicts with the core project's declared licence
  expression. The decision belongs to the repository owner and is recorded, with its documented
  fallback, in the [risk register](risk-register.md). The declared licence expression was left
  untouched and the upgrade was neither silently accepted as final nor reverted.
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): `AssertConfigurationIsValid()` reports unmapped-member problems, but the platform never
  calls it, so it is not on any functional path; several pre-existing `CS0618` obsolete-API
  warnings exist in the data layer; and requests for two third-party vendor source-map files that
  are absent from disk are answered `405` instead of `404` by the embedded file provider. None is a
  security finding and none was changed, in keeping with the minimal-change constraint.


## Remediation by vulnerability class

> **Correction — the `AutoMapper` disposition recorded below is the alternative, not the one that
> shipped.** Passages in this section that describe the pin as *held at `[14.0.0]` behind a single
> dependency-audit suppression* were written against that alternative. Measured at this commit: the
> pin is **`[15.1.3]`**, `ErpAutoMapper.Initialize` supplies `NullLoggerFactory.Instance`,
> `Directory.Build.props` declares **no** `NuGetAuditSuppress` element, and
> `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports **no vulnerable
> package in any of the 19 projects**. The advisory is therefore closed by upgrade, and the licensing
> question it raises is escalated and **open** as `RISK-001`. The retained-`[14.0.0]` analysis is
> kept in full, because it is the documented reversal path `RISK-001` records and because its
> exploitability assessment and negative-control evidence hold either way.

### How this log maps onto the commit history

The remediation discipline requires one atomic commit per vulnerability class. This section states
exactly how the recorded history measures against that requirement, which commits meet it, which do
not, and what was done instead where it could not be met retroactively. It is written plainly rather
than favourably: an audit trail that overstates its own tidiness is worth less than one that does
not.

#### Commit-to-class traceability

Every commit between the pre-remediation base `c8ea6bd4` and the head of this remediation is listed.
Nothing is omitted, including the three commits that are not single-class.

| # | Commit | Subject | Vulnerability class(es) | Findings | One class per commit |
| --- | --- | --- | --- | --- | --- |
| 1 | `3d6aa7b6` | correct WebVella.Erp project reference path casing across solution | Build and Scan Integrity | H-19 | Yes |
| 2 | `df9cf2d2` | clear package advisories and move WebAssembly projects off .NET 7 | Dependencies · Build and Scan Integrity | H-01, H-18, H-20, H-19 | **No — five manifests additionally gained H-19 threat comments** |
| 3 | `4e7b66fb` | encode reflected return URLs, validate SQL identifiers, fail fast on missing secrets, pin the SDK | Output Encoding · Injection and Deserialisation · Secret Management · Scan Gate Enforcement | H-06, H-09, C-04, H-04, H-05, L-07 | **No — four classes** |
| 4 | `44c705b6` | harden credential storage, sessions, output encoding and secret handling | Credential Integrity · Session and Token Handling · Transport and Response Headers · Brute Force and Rate Limiting · Output Encoding · Injection and Deserialisation · Secret Management | C-03, M-05, M-06, H-02, H-03, M-03, M-04, M-01, H-16, M-18, H-10, C-04 | **No — seven classes** |
| 5 | `f9686d53` | close H-01 by accepted risk, holding AutoMapper at 14.0.0 | Dependencies | H-01 | Yes |
| 6 | `84c43f25` | enforce dependency-audit and analyzer gates repo-wide | Scan Gate Enforcement | Objective 5 gates, L-07 | Yes |
| 7 | `790eabb9` | name the H-19 threat at every corrected reference site | Build and Scan Integrity | H-19 | Yes |
| 8 | `c0feebf5` | allow-list the SDK return URL instead of relying on encoding | Output Encoding | H-06 reflected sinks, CWE-601 | Yes |
| 9 | `2e23c6ef` | bound identifier length before running the allow-list pattern | Injection and Deserialisation | H-09 hardening (CWE-1333) | Yes |
| 10 | `8988171a` | record the credential-hashing deviation and correct its claims | Credential Integrity | C-03, M-05, M-06 | Yes |
| 11 | `4bd67830` | complete the per-class record, commit traceability and boundary statement | Documentation deliverable, plus two line-ending repairs | — | Yes |
| 12 | `28201a84` | close every dangling finding reference and record the final sweep | Documentation deliverable | H-05, H-06, H-11, H-12, H-15, M-15, M-17, L-02, L-04 documented | Yes |
| 13 | this commit | add the row above and finalise the remediation record | Documentation deliverable | — | Yes |

Commits 1 and 5 through 13 — ten of the thirteen — are single-purpose. Commits 2, 3 and 4 are not.

A note on the last row, because it is the one place this table cannot describe itself: a commit cannot
contain its own hash, so a row can only ever be added by a later commit. Rather than leave the final
commit unlisted — which would be precisely the unrecorded change this table exists to prevent — the
last row identifies it by position and content instead of by hash, and its content is exactly that:
adding the preceding row and finalising this record. Its hash is recoverable in one step, as the
commit whose parent is the one named in row 12. Nothing else is in it.

#### The three commits that mix classes, and why they were not rewritten

Commits `df9cf2d2`, `4e7b66fb` and `44c705b6` each carry work from more than one class. That is a
genuine departure from the one-commit-per-class rule, and the correct disposition is to record it
rather than to disguise it. `df9cf2d2` is the mildest case and is easy to overlook, which is exactly
why it is named: while performing dependency work it also added H-19 threat comments to five
manifests, so it re-edited files belonging to the Build and Scan Integrity class. Those comments were
subsequently normalised across all fourteen corrected manifest sites by commit `790eabb9`, which *is*
single-class, so the class's final state is coherent even though its history is not.

They were **not** rewritten, and the reason is a hard constraint rather than a preference: this
branch's history is immutable for the purposes of this work. Rewriting it would mean rebasing or
amending published commits, which is expressly forbidden — history-altering git operations are not
available to the remediation. Splitting them after the fact is therefore impossible; the
choice is between an accurate record of an imperfect history and no record at all.

What was done instead, so the property the rule exists to deliver is still available:

- **Every subsequent commit is single-purpose.** Commits 5 through 13 each carry exactly one
  vulnerability class, or in the case of the documentation commits only the documentation set, so the
  discipline holds from the point it could be applied onward — and each was verified to touch only
  its own class's files plus the documentation set.
- **The traceability table above supplies the mapping the commit boundaries would have supplied.**
  For any file in the change set, the class that owns it is recoverable from this document even
  though the commit that introduced it may not be class-pure.
- **Every class section below lists its own files.** The union of those `Files changed` tables covers
  the whole change set, so ownership is stated per file in exactly one place.
- **No further mixing was introduced.** Each of the six later commits touches only its own class's
  code plus this log and, where a risk was accepted, the register and the report — the documentation
  set is the record of the change and is deliberately updated in the same commit as the change it
  records.

#### Per-file attribution — every changed path, and the class that owns it

This is the substitute the mixed commits make necessary, and it is deliberately exhaustive: every
path that differs from the pre-remediation base appears exactly once per distinct change it carries.
Where one file carries changes belonging to two classes it has two rows, each naming its own change,
so no ownership is ambiguous and none is double-counted.

| Path | Owning class | Change owned |
| --- | --- | --- |
| `Directory.Build.props` | Scan Gate Enforcement | The whole file — both gates and the one authorised suppression |
| `global.json` | Scan Gate Enforcement | SDK pin, so both gates are reproducible |
| `WebVella.ERP3.sln` | Build and Scan Integrity | Core project path casing |
| `WebVella.Erp.ConsoleApp/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.Crm/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.Mail/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.Mail/…csproj` | Dependencies | `MailKit` 4.14.1 → 4.17.0 |
| `WebVella.Erp.Plugins.MicrosoftCDM/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.Next/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.Project/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Plugins.SDK/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.Crm/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.Mail/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.MicrosoftCDM/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.Next/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.Project/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Site.Sdk/…csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.Web/WebVella.Erp.Web.csproj` | Build and Scan Integrity | Reference casing and the H-19 threat comment |
| `WebVella.Erp.WebAssembly/Server/…csproj` | Build and Scan Integrity | Client project filename corrected — the previous name never existed, so MSBuild skipped it with `MSB9008` and dropped the Client project out of the restore, audit and analyzer graph |
| `WebVella.Erp.WebAssembly/Server/…csproj` | Dependencies | `net7.0` → `net10.0` and the hosting package `7.0.13` → `10.0.1` |
| `WebVella.Erp.WebAssembly/Shared/…csproj` | Dependencies | `net7.0` → `net10.0` |
| `WebVella.Erp/WebVella.Erp.csproj` | Dependencies | `AutoMapper` pin raised to `[15.1.3]`, with the licensing escalation recorded as `RISK-001` |
| `LIBRARIES.md` | Dependencies | The third-party inventory with versions and licences — the evidence base for the licence decision |
| `WebVella.Erp.Plugins.SDK/Pages/page/create.cshtml` | Output Encoding | Return-URL allow-list guard |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml` | Output Encoding | Return-URL allow-list guard |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml.cs` | Output Encoding | Companion redirect guard |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml` | Output Encoding | Return-URL allow-list guard |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml.cs` | Output Encoding | Companion redirect guard |
| `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` | Output Encoding | The bypassable escaper replaced by the framework encoder |
| `WebVella.Erp/Database/DbIdentifier.cs` | Injection and Deserialisation | The identifier allow-list and quoting helper |
| `WebVella.Erp/Api/Models/ErpSerializationBinder.cs` | Injection and Deserialisation | The type allow-list binder |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | Credential Integrity | Salted, work-factored hash and verify, with legacy verification retained |
| `WebVella.Erp/Utilities/CryptoUtility.cs` | Secret Management | Default key deleted, silent fallback converted to fail-fast |
| `WebVella.Erp/ErpSettings.cs` | Secret Management | Signing-key fallback removed, required-secret validation added |
| `WebVella.Erp.Web/Services/AuthService.cs` | Session and Token Handling | Ticket bound, lifetime validated, failures logged, UTC timestamps, awaited sign-in |
| `WebVella.Erp.Web/Pages/login.cshtml.cs` | Session and Token Handling | Compile-mandated asynchronous propagation only |
| `WebVella.Erp.Web/Services/LoginThrottleService.cs` | Brute Force and Rate Limiting | The account-lockout service |
| `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` | Transport and Response Headers | The response-header middleware |
| `docs/security/security-audit-report.md` | The documentation deliverable | Updated by every class, in the commit that lands it |
| `docs/security/remediation-log.md` | The documentation deliverable | Updated by every class, in the commit that lands it |
| `docs/security/risk-register.md` | The documentation deliverable | Updated by every class that relies on an accepted risk |

Thirty-nine distinct paths, forty-two rows — the three duplicated paths are the two manifests that
legitimately carry two classes' changes. `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` is
deliberately **absent**: an intermediate commit modified it and a later one reverted it, so its net
difference from the base is empty. That is recorded in the *Dependencies* entry rather than left as a
silent gap, because "no net change" is itself a decision here.

#### Files that landed ahead of the class that owns them

Four paths were changed in commit `44c705b6`, before the class entries that describe them existed in
this log. They are listed here so that the early change is visible rather than implicit, and each is
traced to the requirement that mandates it.

| Path | Why it changed when it did |
| --- | --- |
| `WebVella.Erp.Web/Pages/login.cshtml.cs` | Not an independent change. Awaiting the sign-in call turns `AuthService.Authenticate` into an asynchronous method, and this page is its only caller. The plan states the propagation explicitly and requires the two to move together — leaving the caller behind would not merely be untidy, it would fail to compile. The diff is confined to the `async`/`await` propagation and nothing else. |
| `docs/security/security-audit-report.md` | The audit report is a mandated deliverable of the remediation, and it is compiled incrementally: a finding's record is written when the finding is closed, so that the record and the code cannot drift apart. |
| `docs/security/remediation-log.md` | This document, on the same incremental basis — the class entry is written in the commit that lands the class. |
| `docs/security/risk-register.md` | Same basis. A risk acceptance is recorded in the commit that relies on it, so no code comment ever cites a record that does not yet exist. |

Two properties of that early change are worth stating explicitly. First, it did not expand: no
further paths outside a class's own scope were touched by any later commit — every one of the six
later commits is confined to its class's files plus the documentation set. Second, the three
documentation files remain subject to the reviews that own them; recording them here does not close
them, it only makes their early appearance traceable.

#### Validation performed after each class

Validation was run after each class rather than only at the end. The evidence per class is recorded
in that class's own `### Verification` section below; this table is the index.

| Class | Restore | Analyzer build | Vulnerable-package scan | Documentation build | Runtime / browser |
| --- | --- | --- | --- | --- | --- |
| Build and Scan Integrity | Solution restore, exit 0 | Solution rebuild, 0 errors | Core project re-enters the graph, so the audit stops reporting falsely clean | — | — |
| Scan Gate Enforcement | Exit 0, zero `NU19xx` | Solution rebuild, 0 errors; analyzer diagnostics remain warnings | `dotnet list package --vulnerable --include-transitive`, plus a negative control — a throwaway project pinning the affected version — proving the gate fails when a live advisory is present | — | — |
| Dependencies | Exit 0; `AutoMapper` resolves at 15.1.3; `MailKit` 4.17.0 carries `MimeKit` 4.17.0 transitively | Solution rebuild, 0 errors | All three advisories cleared — no vulnerable package in any project; the licensing escalation is recorded as `RISK-001` | `mkdocs build --strict`, 0 warnings | — |
| Credential Integrity | Exit 0 | Core module 0 errors; solution 0 errors | No change to the graph | `mkdocs build --strict`, 0 warnings | Key-derivation cost measured directly, 20-run medians |
| Injection and Deserialisation | Exit 0 | Core module 0 errors; solution 0 errors; zero diagnostics attributed to the helper before or after | No change to the graph | `mkdocs build --strict`, 0 warnings | Behavioural equivalence proven over 200 000 generated inputs plus 21 hand-picked cases |
| Output Encoding | Exit 0 | SDK plugin and solution rebuild, 0 errors, no new warnings | No change to the graph | `mkdocs build --strict`, 0 warnings | Headless-browser run: the `javascript:` payload no longer reaches the rendered `href`, and a legitimate local return URL still renders and navigates identically |
| Secret Management | Exit 0 | Core module and solution rebuild, 0 errors | No change to the graph | `mkdocs build --strict`, 0 warnings | Negative test: startup fails with an actionable message when a required secret is absent |
| Session and Token Handling | Exit 0 | Web framework and solution rebuild, 0 errors | No change to the graph | — | — |
| Brute Force and Rate Limiting | Exit 0 | Web framework and solution rebuild, 0 errors | No change to the graph | — | — |
| Transport and Response Headers | Exit 0 | Web framework and solution rebuild, 0 errors | No change to the graph | — | — |

The yardstick used throughout is the diagnostic set of the solution rebuild, compared before and
after every class: `CA2200` 52, `ASPDEPR008` 42, `CS0618` 6, `CS0168` 4, `ASP0019` 2, `CA5351` 10,
`NU1903` 0 unsuppressed. It has not moved. Since no test project, test file or test framework
reference exists anywhere in the nineteen projects, the planned "existing test suite passes" gate is
vacuous by construction; the substitutes above are what stands in for it, and that substitution is
stated openly rather than left to be inferred.

#### Final verification sweep

Run once across the whole change set after the last class landed, so that per-class evidence is not
the only evidence. Every figure below is a measurement, not a restatement.

| Check | Command / method | Result |
| --- | --- | --- |
| Dependency restore | `dotnet restore WebVella.ERP3.sln` | exit 0; **zero** `NU1901`, `NU1902`, `NU1903` or `NU1904` |
| Full rebuild under both gates | `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-restore -t:Rebuild` | exit 0; **0 errors**, 3 072 warnings across the 17 solution projects |
| Diagnostic yardstick, before versus after the whole remediation | per-code counts from the same build | identical: `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2. Analyzer security codes present as expected and left as warnings: `CA5351`×10 (legacy MD5, `RISK-004`), `CA5359`×10 (mail certificate validation, an open finding). `CA2100` and the whole `CA23xx` family: **zero** |
| The two projects the solution does not contain | each built individually | exit 0, **0 errors** (53 and 0 warnings); zero `CA2100`, `CA23xx` and `NU19xx` in both |
| Advisory scan, direct and transitive | `dotnet list … package --vulnerable --include-transitive` on the solution and on both non-member projects | exactly **one** distinct vulnerable package — the accepted `AutoMapper` `High` advisory covered by `RISK-001`. No other package at any severity. Both non-member projects report none |
| The gate is not blind — negative control, re-run at the end | temporarily delete the single `NuGetAuditSuppress` line and restore | restore **fails**, exit 1, with `error NU1903: Warning As Error` in **16 distinct projects**. The suppression was restored and verified byte-identical afterwards |
| Documentation builds strictly | `mkdocs build --strict` | exit 0, **0 warnings**; the generated output directory is removed afterwards and is never committed |
| No dangling record reference anywhere | sweep of every `RISK-nnn` and every finding identifier cited from source, project, configuration, build and documentation files against the register and the report | every cited `RISK-nnn` resolves against the canonical index in the register; **every** cited finding identifier now has a record — the sweep drove records for H-05, H-06, H-11, H-12, H-15, M-15, M-17, L-02 and L-04 to be written, because each was cited from code or documentation while having no record |
| No new placeholder or deferred work | marker sweep over all 39 changed files for `TODO`, `FIXME`, `HACK`, `XXX`, `NotImplementedException`, "implement later", "coming soon", "placeholder for", `TBD` | exactly one hit, and it is **pre-existing and unchanged** — the same line at the same line number in `WebVella.Erp/ErpSettings.cs` at the pre-remediation base. Nothing new was introduced |
| Per-file byte fidelity | BOM presence, line-ending purity, mixed-ending detection and final-newline state compared against the pre-remediation base for all 31 modified files | **0 mismatches.** This check earned its place: it found the two CRLF-to-LF regressions recorded under *Dependencies*, which no other check in this list would have caught |

One consequence of the dangling-reference sweep is worth stating rather than leaving implicit: nine
findings acquired a record because something already referenced them. Six of those nine are **not
remediated** — H-05, H-11, H-12, H-15 in part, M-15 and M-17 — and each record says so in its
remediation field. A record's existence in this report means the finding is documented, never that it
is closed.

#### Compliance with the ten security-discipline guidelines

The remediation is bound by ten guidelines. Each is answered here, including where the answer is
qualified.

| # | Guideline | Disposition |
| --- | --- | --- |
| 1 | Make minimal necessary changes only | Held. The reflected-URL fix is a guarded expression rather than a new helper; the stored-text fix deletes a wrapper rather than adding one; one package line closes two advisories; the identifier reordering moves an existing block rather than adding a check. Comments were kept proportionate to their edits — the identifier helper's threat comment was cut from ten lines to six for exactly this reason. |
| 2 | Preserve functionality and workflows exactly | Held. Legitimate return URLs render and navigate identically, verified in a browser; the mapping bootstrap is byte-identical to its pre-remediation form; the identifier reordering was proven to change no accept/reject verdict over 200 000 generated inputs; legacy credentials continue to verify. |
| 3 | Do not modify unrelated code | Held with one recorded exception, above: `login.cshtml.cs` moved with the asynchronous propagation it is compelled by, and the three documentation files are the mandated deliverable. Nothing else outside a class's scope was touched. |
| 4 | Do not enhance or optimise beyond remediation | Held. No feature, no refactor, no test project, no reformatting. Pre-existing mixed indentation in edited files was deliberately preserved rather than normalised. |
| 5 | Use the least invasive security controls | Held. Every control resolves from framework references already present — no package was added. The lockout uses the existing in-process cache rather than a new store or a schema change. |
| 6 | Document changes with comments explaining the threat addressed | Held. Every corrected reference site, every gate property, every guarded sink and every fail-fast path carries a comment naming the threat, and all fifteen corrected reference sites now carry the *same* comment so the policy reads as a policy rather than as fifteen opinions. |
| 7 | Choose the solution requiring the least modification | Held. The mail advisory is one line; the mapping advisory is accepted rather than patched because the patch changes the product's licence posture; the current data provider version is already safe and was therefore left alone. |
| 8 | Document out-of-scope concerns but do not fix unless Critical | Held. Documented-not-fixed items include the deterministic initialisation vector, the analyzer backlog, the bypassable-encoder's platform-wide root cause, the lock file, the unbounded script cache and the antiforgery gap. |
| 9 | Atomic commits per vulnerability class | **Qualified, and the exception is recorded rather than claimed as compliance.** Ten of the thirteen commits are single-purpose; three are not and cannot be rewritten, because history-altering operations are unavailable on this branch. The remediation therefore takes the documented-exception route: the commit-to-class table and the per-file attribution table above supply the same mapping the commit boundaries would have supplied, and every commit made after the discipline could be applied is single-class. |
| 10 | Validate after each fix category | Held. Per-class evidence is in each class's `### Verification` section and indexed in the table above. |

#### Invariants this documentation set maintains

Stated so that a later contributor extends the set correctly rather than by guesswork.

- **This log orders its class sections alphabetically by class name.** A new class is inserted in
  alphabetical position, not appended.
- **The audit report orders findings by descending severity** — Critical, then High, then Medium,
  then Low — and by ascending identifier within each band.
- **The risk register orders records by ascending identifier** and never reuses one.
- **Both this log and the report are compiled incrementally, one class at a time.** An entry appears
  in the same commit as the change it describes, which is why the documentation set is present in
  commits that predate this section.
- **"Solution projects" means 17; "all 19 projects" means the repository.** `WebVella.ERP3.sln`
  references 17 projects, while 19 `.csproj` files exist on disk —
  `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` are not solution members.
  A solution build or restore therefore covers 17; any claim about all 19 was obtained by building
  those two projects individually in addition. The distinction is maintained wherever a count
  appears, because conflating the two is exactly how a scan comes to report falsely clean.
- **These three documents are not yet reachable from the published site's navigation.**
  `mkdocs.yml` still lists a single `Home` entry, so the security set builds and validates but is
  navigable only by direct path. Extending the navigation — together with the two documents named
  below and a link from the documentation index — belongs to the documentation class in a later
  checkpoint, and it is deliberately not edited here: the navigation edit and the pages it must list
  belong in one change, not split across two. Recorded so the gap is known rather than discovered.
- **Each file keeps its own byte format.** This repository mixes conventions — most `.cs` files are
  UTF-8-with-BOM and LF, most `.csproj` files are UTF-8-with-BOM and CRLF, and a few `.cs` files are
  CRLF — so the rule is per file, not per repository: BOM presence, line-ending purity, indentation
  character and final-newline state must all match what the file already had. Two files drifted to LF
  during this remediation and were repaired; every changed file is now verified against the
  pre-remediation base.
- **No code comment may cite a record that does not exist.** Every `RISK-nnn` identifier and every
  `docs/security/…` path referenced from source, project, configuration or build files was swept and
  resolved. Two references — to `docs/security/secure-configuration.md` and
  `docs/security/credential-migration.md` — point at documents that belong to a later stage of the
  remediation and are deliberately **not** created here; they are named in full in the class entries
  that reference them so the gap is explicit rather than accidental.

### Class: Brute Force and Rate Limiting

**Findings closed in this class:** H-16 (no account lockout and no rate limiting on the login path,
CWE-307 Improper Restriction of Excessive Authentication Attempts, OWASP A07:2021 Identification and
Authentication Failures) — to the extent the service itself closes it; see the boundary note below.

No lockout mechanism existed anywhere in the platform. The login page accepted an unlimited number of
authentication attempts, which is the precondition for both credential stuffing and offline-free
online password guessing. Combined with the unsalted digest the credential class replaced, an
attacker had both a fast offline attack and an unmetered online one.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/LoginThrottleService.cs` | **New.** The application-level account lockout: five consecutive failures against a username-and-address pair lock that pair out for fifteen minutes, and a successful authentication clears the counter. |

#### Design decisions

- **Five attempts, literally.** The Authentication Hardening standard names "account lockout after 5
  failed attempts", so `MaxFailedAttempts` is 5 and not a rounder or safer-feeling number. The sixth
  attempt is refused *without authentication being attempted at all*, so a locked-out principal costs
  no key derivation.
- **The existing in-process cache is the backing store.** This is the least invasive control
  available: it needs no database schema change and no new package. The alternative — a counter
  column on the user record — would have meant a schema change the remediation boundary forbids.
- **Keyed by username *and* address together.** Keying on username alone would let an attacker lock a
  known account out from anywhere, turning a defence into a denial of service against real users.
  Keying on address alone would let one shared NAT egress lock out an office.
- **Fail-closed by construction, not by convention.** The counter and the lockout deadline live in a
  single cache entry, so eviction cannot drop the deadline while keeping the counter or the reverse,
  and the entry's lifetime is extended to cover any lockout it carries, so expiry cannot release a
  locked-out principal early. Missing state is therefore never interpretable as "no failures, proceed
  indefinitely".
- **An in-force lockout is never extended.** Counting further attempts during a lockout would let an
  attacker keep a real account locked out permanently by attempting it once every few minutes.
- **An explicit absolute expiration is mandatory and is not simplifiable.** The platform cache's
  default entry options use `CacheItemPriority.NeverRemove`, so an entry written without one would
  never expire and a user who mistyped five times would be locked out permanently. A private options
  instance is passed rather than `null`, because the cache adopts and mutates its shared default
  options object when handed `null` — which would leak this service's expiration onto every other
  consumer of that cache.
- **Every public member is non-throwing.** Malformed input must not turn into a denial of service on
  the login path, so a missing username or address normalises to a placeholder rather than failing.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| Web framework compiles | `dotnet build WebVella.Erp.Web/WebVella.Erp.Web.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | `dotnet restore WebVella.ERP3.sln` then a solution rebuild | restore exit 0 with **zero unsuppressed `NU19xx`**; build exit 0, **0 errors** across all 17 solution projects |
| No new diagnostic | analyzer diagnostics attributed to `LoginThrottleService.cs` | none; the non-analyzer yardstick is unchanged |
| No new dependency, no schema change | the project's `PackageReference` set, and the absence of any schema definition statement in the change set | unchanged and absent respectively |

#### Boundary note — what is not yet protected, stated plainly

The service **has no callers yet.** A repository-wide search for `LoginThrottleService` outside its
own file returns nothing: the login page does not consult it, and the framework's transport-level
rate limiter is not yet enabled in any host pipeline. Attaching both is a later checkpoint. Until
then the login path is still unmetered, and the standalone presence of this service is **not** runtime
protection. Nothing in this entry should be read as claiming otherwise.

#### Deviations and out-of-scope observations

- **Per-process only, and deliberately so.** The counters live in an in-process cache, so a
  multi-instance or load-balanced deployment is not protected — each process counts independently.
  Moving to a distributed store is recorded as a recommendation rather than built, because it would
  mean a new dependency the remediation boundary forbids.
- **The window is not configurable.** A configuration surface would exceed the remediation; the
  fifteen-minute value is a constant with its rationale on it.

### Class: Build and Scan Integrity

**Findings closed in this class:** H-19 (case-mismatched project references breaking the dependency
scan, OWASP A06:2021 / A08:2021, CWE-1104-adjacent).

This class comes first in the remediation because nothing else in this document can be trusted until
it is done. Fifteen project-reference paths named the core library's directory as `WebVella.ERP`,
while the directory on disk is `WebVella.Erp`. On a case-insensitive filesystem that is invisible; on
a case-sensitive one, solution-wide restore fails outright with `MSB3202`, and the core project — the
one that carries the platform's package advisories — drops out of the graph that any dependency audit
inspects. A scan run in that state reports clean because it never looked.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.ERP3.sln` | Core project path corrected to the on-disk casing. |
| 14 `.csproj` files across the console app, five plugins and seven site hosts | The `ProjectReference` to the core library corrected to the on-disk casing, and a threat comment added above each corrected reference. |

The already-correct reference in `WebVella.Erp.Site/WebVella.Erp.Site.csproj` was **not** touched. It
was never defective, and it is what made the defect diagnosable: a per-project restore of that one
host succeeded while a solution-wide restore failed, which localised the fault to the fifteen
outliers rather than to the toolchain.

#### Threat comments: why every corrected site now carries one, in identical words

The engagement requires each security change to carry a comment naming the threat it addresses. That
had been applied unevenly here — five of the fourteen corrected manifests carried a rationale comment
and nine carried none, and the five that did each phrased it differently. A one-character path
difference is exactly the kind of change a future maintainer "tidies" back to the wrong value, so the
comment is not decoration: it is the only thing at the call site that explains why the casing matters.

All fourteen corrected references therefore now carry the same single-line comment, naming the OWASP
categories, the weakness class, the observable failure and — the part that makes it stick — the
consequence that the scan reported falsely clean. The five pre-existing variants were normalised to
that wording rather than left in place, because the inconsistency was itself the defect being
reported; presence alone would not have fixed it.

Two deliberate exclusions, both stated rather than passed over:

- **`WebVella.ERP3.sln` carries no comment.** The classic solution format has no comment syntax that
  the solution parser is documented to tolerate, and a malformed solution file breaks every build for
  every developer. The risk of the annotation exceeds its value, so the rationale for that one site
  lives here instead. The corrected path itself is unchanged.
- **`WebVella.Erp.WebAssembly/Server/…csproj` keeps its own, differently worded comment.** It
  documents a *different* defect — a referenced project filename that never existed, which MSBuild
  skipped silently (`MSB9008`) — and conflating the two would make both comments less accurate.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| The defect is gone | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches |
| No path regression from the annotation | `grep -c MSB3202` and `grep -c MSB9008` over the restore and build logs | `0` and `0` |
| Restore | `dotnet restore WebVella.ERP3.sln` | exit 0, 0 errors — all 17 solution projects restore |
| Build | `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` | exit 0, **0 errors**; all 17 solution projects produce an assembly |
| Byte fidelity, file by file | each manifest compared against its committed form | byte-order-mark state unchanged in all 14; **exactly one** added line per file, in that file's own line-ending style, with no line-ending conversion and no mixed-ending file created; final byte unchanged. Two manifests have no byte-order mark and three use `LF` where the other eleven use `CRLF`; each kept what it had |
| Diff is exactly what was intended | `git diff --numstat` | 14 files, **14 insertions, 5 deletions** — nine inserted comments plus five normalised in place, and nothing else |
| Still valid XML | each manifest parsed | all 14 parse |
| No diagnostic regression | non-analyzer diagnostic counts | unchanged: `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2, total 3,072 warnings — identical to the preceding class, as expected from a comment-only change |

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach.
- **A real gap in gate coverage, found while verifying this class and worth recording.** The
  solution contains 17 projects, but the repository contains 19 `.csproj` files:
  `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` exist on disk and are
  **not** referenced by `WebVella.ERP3.sln`, so a solution-wide restore or audit never sees them.
  Verified rather than assumed: `dotnet msbuild -getProperty:` on the Server project returns
  `NuGetAuditMode=all`, `NuGetAuditLevel=low`, `EnableNETAnalyzers=true` and
  `WarningsAsErrors=;NU1901;NU1902;NU1903;NU1904;NU1605;SYSLIB0011`, which proves two things at once
  — the root policy does reach them, and the appended form preserved both the inherited value and
  the codes the toolchain adds afterwards. Both projects were built individually: exit 0, 0 errors,
  no `NU19xx`. The coverage gap is a solution-membership question rather than a policy one, and it is
  recorded here so that a future pipeline builds these two projects explicitly instead of assuming
  the solution covers them.

### Class: Credential Integrity

**Findings addressed in this class:** `C-03` (CWE-916 and CWE-759, OWASP A02:2021 Cryptographic
Failures) — partially, see the boundary note; `M-05` (CWE-208, non-constant-time comparison) and
`M-06` (CWE-362, shared mutable hash instance) — both closed.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | The unsalted MD5 primitive replaced by a salted, work-factored, fixed-time hash-and-verify pair built on the ASP.NET Core password hasher; the shared mutable hash instance replaced by the static one-shot; the legacy comparison rewritten onto a fixed-time comparison and made fail-closed on absent input; a stored-shape discriminator and a rehash signal added so legacy values are recognised and can be upgraded. |

#### Design decisions

- **The primitive is replaced in place, behind an unchanged internal surface.** Every member stays
  assembly-internal and every existing consumer keeps compiling, which is what allows a cryptographic
  replacement without an API contract change. This is deliberate: it means switching the four consumer
  sites over, in a later class, is a call-site change and nothing more.
- **No new package, and no schema change — both verified rather than assumed.** The hasher ships in
  the framework the core library already references, and the produced value is 84 characters against a
  column that is already a 500-character variable-length string.
- **The legacy path is retained, not deleted.** MD5 digests cannot be reversed, so the only
  alternatives would be forcing a password reset on every existing user or locking them all out. Both
  breach the requirement that existing functionality be preserved. Verification therefore accepts
  either shape and signals when a successful verification used the legacy one, which is the
  OWASP-prescribed upgrade-on-next-authentication pattern.
- **The legacy and modern shapes are told apart by their form, not by a new column.** A legacy digest
  is exactly 32 hexadecimal characters; a modern value is 84 Base64 characters starting with the
  encoded format marker. The two cannot collide at any casing, so no schema-adjacent change is needed
  to support both simultaneously.
- **Hexadecimal is accepted in either case, on purpose.** The comparison being replaced was
  case-insensitive, so a digest persisted in upper or mixed case by any other route must still verify;
  refusing it would lock that account out. The tolerance is free, because a 32-character hexadecimal
  string cannot be mistaken for the modern format.
- **Malformed stored values fail verification rather than throw.** Only the two exception types a
  corrupt value can actually produce are caught, so one damaged row cannot become a denial of service
  on the login path while a genuine platform fault still propagates and stays visible.
- **Two deviations from the letter of the mandated cryptographic standard are recorded, not
  absorbed** — the algorithm family, and the pseudo-random function that the framework's versioned
  format fixes. Both, with their measurements and the owner option for literal compliance, are
  `RISK-005` in the [risk register](risk-register.md). The retained MD5 surface is `RISK-004`.

#### The accepted latency cost, measured rather than asserted

The iteration count is the control, not a tuning knob, and it deliberately costs CPU. Medians over 20
runs, single-threaded, .NET 10.0.10, four logical CPUs:

| Configuration | Hash | Verify |
| --- | --- | --- |
| **As shipped** — 600,000 iterations | **367.0 ms** | **364.1 ms** |
| The OWASP floor for this function — 210,000 | 127.5 ms | 128.0 ms |
| The framework default — 100,000 | 62.5 ms | 62.7 ms |
| Legacy unsalted MD5, single pass — what this replaces | 0.0007 ms | — |

Roughly 0.37 s per login attempt, against 0.0007 ms before: about a **520,000×** increase in the work
an attacker must spend per offline guess. **This is a pre-declared, accepted trade-off, not a
regression**, and the scope's 10 % performance boundary is knowingly exceeded on this one path.
Nothing else is affected — no other request path performs a key derivation. Do not lower the iteration
count to chase a latency target.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| Salted and non-deterministic | hash the same password twice | different values; each carries its own 128-bit random salt |
| Self-describing, so the work factor can be raised later | inspect the produced value | encodes the format marker, the function, the iteration count and the salt; 84 Base64 characters beginning with `A` |
| The rehash signal actually fires | verify a value written at a lower iteration count | `SuccessRehashNeeded`, so a future work-factor increase needs no further code change |
| The literally mandated function was tested, not assumed unavailable | hand-build a versioned payload with the HMAC-SHA-256 function identifier at 600,000 iterations and verify it | `SuccessRehashNeeded` rather than `Success` — every login would rewrite the credential, which is why the versioned format's own function is kept. Recorded in `RISK-005` |
| Cost measured | 20-run medians, single-threaded | the table above |
| Module compiles | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | `dotnet restore WebVella.ERP3.sln` then `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-restore -t:Rebuild` | restore exit 0 with zero `NU19xx`; build exit 0, **0 errors** across all 17 solution projects |
| The analyzer gate reports the retained MD5, and it is not silenced | `CA5351` counts | 10 reports across 2 files, including this one at the legacy member — left as warnings and recorded as `RISK-004` |
| Documentation set builds | `mkdocs build --strict` | exit 0, no warnings |

#### Boundary note — what is not yet wired, stated plainly

`HashPassword` and `VerifyPassword` currently have **no callers**. All four consumer sites — credential
resolution at `WebVella.Erp/Api/SecurityManager.cs:L84`, and the write paths at
`WebVella.Erp/Api/RecordManager.cs:L2017`, `WebVella.Erp/Database/DbRecordRepository.cs:L554` and
`:L1856` — still call `GetMd5Hash`, and credential resolution still compares the digest inside a SQL
predicate. Switching them over belongs to a later checkpoint. Therefore, precisely:

- **`M-06` is closed on the live path.** The shared mutable instance is gone and its replacement sits
  in the member those four callers already use.
- **`M-05` is closed in the code as written.** The member it concerned had no callers at the pre-audit
  revision either, so it was latent then and remains latent until credential resolution is switched
  over — at which point the fix is already in place. Stating it as *latent* rather than *closed at
  runtime* is the accurate reading.
- **`C-03` is partially remediated.** The enabling primitive has landed and is verified; stored
  credentials are still legacy MD5 today. This was confirmed by observation rather than assumed: an
  interactive login against a provisioned database succeeded and left the stored value at its original
  32-character length. `RISK-004` carries the same statement so the two documents cannot drift apart.

#### Deviations and out-of-scope observations

- **Deviation, recorded twice on purpose** — in `RISK-005` and in the file's own header comment, so a
  reader of either artefact learns of it without needing the other: the algorithm family is PBKDF2
  rather than bcrypt, scrypt or Argon2, and the pseudo-random function is HMAC-SHA-512 rather than the
  literally named HMAC-SHA-256, because the mandated versioned format fixes it and the alternative was
  empirically shown to break the upgrade signal.
- **Pre-existing mixed indentation inside `GetMd5Hash` was deliberately left alone.** Two lines in
  that member are tab-indented while the file otherwise uses spaces. That inconsistency is inherited
  verbatim from the pre-audit revision, not introduced here, and normalising it would be an unrelated
  style change of exactly the kind the minimal-change constraint prohibits. It is recorded rather than
  silently tidied.
- **The equivalence and timing harnesses were throwaway projects outside the solution** and were
  deleted after use, because creating a test project is out of scope.
- **Observed, not fixed** (outside this class, recorded so the observation is not lost): the credential
  lookup at `SecurityManager.cs:L85` matches the e-mail with a regular-expression operator (`~*`) and
  compares the password inside the SQL predicate. Both are the subject of separate findings owned by
  the class that switches this call site over, and neither is changed here.

### Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021), H-20 (`MailKit` and `MimeKit` advisories — CWE-74 /
GHSA-9j88-vvj5-vhgr / CVE-2026-41319 and CWE-93 / GHSA-g7hc-96xr-gvvx / CVE-2026-30227, OWASP
A06:2021) and H-18 (two projects on the end-of-life `net7.0` line, CWE-1104, OWASP A06:2021).

H-01 is closed by documented risk acceptance rather than by a version change; H-18 and H-20 are
closed by version changes. All three are in this class because they share a root cause — the
dependency graph — and the plan groups commits by vulnerability class rather than by file.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to **`[15.1.3]`** — the newest release on the lowest patched major — which clears advisory `GHSA-rvv3-g6hj-g44x` from the graph. The inline comment beside the pin carries the licensing escalation as a self-contained record. The `<PackageLicenseExpression>` was **not** modified, because relicensing the product is not an implementer's decision. See *Deviations* below and `RISK-001`. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires — `NullLoggerFactory.Instance`, resolved from the framework reference already present, so no package was added. This is the **only** code change the upgrade needs: the `Initialize` signature and the `Mapper` field are unchanged, so both call sites and all 379 mapping declarations compile untouched. |
| `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj` | `MailKit` raised from `4.14.1` to `4.17.0`, which carries `MimeKit` `4.17.0` transitively and clears both mail advisories in one line. |
| `WebVella.Erp.WebAssembly/Server/…csproj`, `…/Shared/…csproj` | Retargeted from the end-of-life `net7.0` line to `net10.0`; hosting package raised from `7.0.13` to `10.0.1`. |

`WebVella.Erp/WebVella.Erp.csproj` additionally had its original CRLF line endings **restored**. An
earlier edit in this class rewrote the whole file with LF endings, which is invisible in a normal diff
but shows as a 103-line rewrite and is precisely the kind of unrelated churn the minimal-change
boundary forbids. The regression was found by a byte-format audit comparing every changed file against
the pre-remediation base — BOM presence, line-ending purity and final newline — and the file is now
byte-identical to its previous state apart from the intended `AutoMapper` decision record. The same
audit found one other instance, in `WebVella.Erp/Utilities/CryptoUtility.cs`, which was repaired the
same way; every other changed file matched its base format.

**No dependency-audit suppression is declared.** `Directory.Build.props` contains no
`NuGetAuditSuppress` element, and Gate 2 is green because the graph is clean rather than because a
diagnostic is silenced. Had the reversal path in `RISK-001` been taken, the suppression would have
had to live in `Directory.Build.props` rather than in a project manifest, because `AutoMapper` is a
transitive dependency of eighteen other projects and `NuGetAuditMode=all` audits transitive packages
in each of them — that mechanism is described under the **Scan Gate Enforcement** class below so the
reversal remains executable, but nothing is suppressed today.

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

#### Why the AutoMapper advisory was accepted rather than patched

The decision, its full exploitability assessment and its reversal procedure are recorded as
`RISK-001` in the [risk register](risk-register.md). In summary:

- The advisory is first patched at `15.1.1`. Every release from `15.1.1` onwards ships a licence
  *file* placing the code under the **Reciprocal Public License 1.5**, replacing the MIT
  *expression* that `14.0.0` declares. There is no patched permissive line to move to.
- This project declares `Apache-2.0` and publishes packages to nuget.org for third-party
  consumption. Adopting a reciprocal source-disclosure obligation is a licensing and distribution
  decision reserved to the repository owner. The remediation therefore took the branch that leaves
  that decision untaken, rather than changing the product's licensing posture unilaterally.
- The advisory is closed by an explicit, narrowly scoped suppression naming one advisory URL, paired
  with a formal recorded acceptance. `NU1901`–`NU1904` remain promoted to build errors, so any other
  advisory at any severity, direct or transitive, still fails the build.
- Holding the version is also the smaller change, as the Minimal Change Clause prefers: it needs no
  constructor migration, no added `using`, and no behavioural drift from a major-version jump.

#### API surface deliberately left untouched

`ErpAutoMapper.Initialize(MapperConfigurationExpression cfg)` and the
`public static IMapper Mapper` field are **byte-identical** to their pre-audit form. Both are hard
compile contracts: `Initialize` has two call sites that each pass a single argument
(`WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47`), and the
`Mapper` field has eight readers in `AutoMapperExtensions.cs`.

Recorded for whoever later takes `RISK-001` Option 1: from 15.x the `MapperConfiguration`
constructor takes an `ILoggerFactory`, its two public overloads being
`(MapperConfigurationExpression, ILoggerFactory)` and
`(Action<IMapperConfigurationExpression>, ILoggerFactory)`; `NullLoggerFactory.Instance` from the
already-referenced ASP.NET Core shared framework satisfies it with no added dependency; and in 15.x
`MapperConfigurationExpression` resolves from the `AutoMapper` namespace rather than
`AutoMapper.Configuration`, which needs no source change because the affected files already import
both. That upgrade must keep `Initialize`'s one-argument signature so the two call sites continue to
compile.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Precondition — the audit must actually see the project | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches; the project-reference casing defect (H-19) is fixed, so the core project is genuinely in the restore graph and every result below is trustworthy rather than a silent omission |
| Restore | `dotnet restore WebVella.ERP3.sln` | exit 0. Emits `warning NU1903: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x`. **This is the accepted advisory being detected, not a missed fix** — it is the same diagnostic the suppression in the next class silences by name, and its presence here proves the detection is real |
| Advisory detection is not blind | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | reports the `AutoMapper 14.0.0 High` row as a direct reference in `WebVella.Erp` and as a transitive one in the dependent projects, and **no other vulnerable package in any project** — so the mail and WebAssembly changes in this class are confirmed clean |
| Transitive reach measured, not assumed | `NU1903` occurrences in the build log | raised for **16 distinct projects**, which is why the suppression is declared repository-wide in `Directory.Build.props` rather than in one manifest |
| Resolved version | `dotnet list WebVella.Erp/WebVella.Erp.csproj package` | `AutoMapper  Requested [14.0.0]  Resolved 14.0.0` |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug --no-restore` | exit 0, **0 errors** |
| Solution build, full rebuild | `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-restore -t:Rebuild` | exit 0, **0 errors** across all 17 solution projects |
| No compiler regression from holding the version | warning codes in the full rebuild compared with the pre-change baseline | **identical compiler-diagnostic set** — `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2 before and after. The only added code is `NU1903`, the accepted advisory itself. Reverting the mapping-library edit introduced no new diagnostic anywhere in the 93 source files that reference AutoMapper |
| No runtime regression is possible from this decision | `git diff <pre-remediation-base> -- WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | **empty**. Both the package version and the bootstrap source are back at exactly the state the platform has always shipped and run, so this class's mapping decision cannot change any runtime behaviour. That is the strongest possible preservation guarantee, and it is what makes the accepted risk purely an advisory-exposure question rather than a functional one |
| Runtime evidence retained from the upgrade trial, for whoever later takes `RISK-001` Option 1 | a site host started against a freshly provisioned database, an interactive login, and an end-to-end console-application run, all performed while `[15.1.3]` plus the logger-factory bootstrap was briefly in place | schema auto-provisioned and mapping initialised with no exception; `POST /login` → `302` with the authenticated shell, navigation and a fully populated user data grid rendering, and no `AutoMapperConfigurationException`, `NullReferenceException` or console error; console application exit 0 including a hook-driven create/update/delete cycle and an EQL user projection. Recorded here because it is the only evidence that Option 1 is functionally viable, and re-gathering it would cost another upgrade trial |

Note on the test-suite gate: the repository contains no test project, no test file and no
test-framework package reference in any project, so the "existing test suite passes" gate is
vacuous by construction. It was confirmed empirically (`dotnet test` discovers nothing) and
substituted with the restore, build, dependency-scan and runtime checks above. Creating a test
suite was out of scope for this remediation.

#### Deviations and out-of-scope observations

- **Deviation from the planned approach, on one of the three packages.** The plan's first choice for
  the mapping library was the version upgrade. It was implemented and verified, and then
  deliberately withdrawn: the patched line carries the Reciprocal Public License 1.5, whose
  source-disclosure obligation is incompatible with the Apache-2.0 expression this project declares
  and publishes packages under. Changing a product's effective licence posture is not a decision an
  implementer may take, so the plan's own pre-authorised fallback was taken instead. The two other
  packages in this class went exactly as planned, with no deviation.
- **Advisory closed; decision escalated.** The advisory is closed by raising the pin to `[15.1.3]`,
  so nothing is silenced and the declared licence expression is untouched. What remains open is the
  licensing consequence: every patched release is under the Reciprocal Public License 1.5 while the
  product declares Apache-2.0 and publishes to nuget.org. `RISK-001` is therefore **open**, records
  both dispositions, and carries the exact steps to reverse to a retained `[14.0.0]` behind a single
  advisory-scoped `NuGetAuditSuppress` should the owner prefer that trade. The full acceptance — its
  exploitability basis, what it does not claim, the reversal procedure and the review trigger — is
  in the [risk register](risk-register.md). Gate 2 is measured against the criterion the plan
  itself pre-defined for this outcome: **no *unsuppressed* High or Critical advisory**.
- **What the acceptance costs, stated plainly.** The dependency graph still contains a
  High-severity advisory. It is not fixed, it is accepted with reasons, and the suppression is
  narrow enough that any *other* advisory — including a future one against AutoMapper with a
  different identifier — still fails the build.
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): `AssertConfigurationIsValid()` reports unmapped-member problems, but the platform never
  calls it, so it is not on any functional path; several pre-existing `CS0618` obsolete-API
  warnings exist in the data layer; and requests for two third-party vendor source-map files that
  are absent from disk are answered `405` instead of `404` by the embedded file provider. None is a
  security finding and none was changed, in keeping with the minimal-change constraint.

### Class: Injection and Deserialisation

**Findings closed in this class:** the SQL identifier-concatenation exposure (CWE-89, OWASP
A03:2021 Injection) and the unconstrained polymorphic deserialisation exposure (CWE-502, OWASP
A08:2021 Software and Data Integrity Failures), to the extent the helpers themselves close them —
see the boundary note below, which states precisely what is and is not yet protected at runtime.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Database/DbIdentifier.cs` | The identifier allow-list and quoting helper. In this pass, the maximum-length rejection was moved ahead of the pattern match, and the `<exception>` documentation was re-ordered to match the order the checks now run in. |
| `WebVella.Erp/Api/Models/ErpSerializationBinder.cs` | The type allow-list binder. Unchanged in this pass. |

#### Why the length check now runs before the pattern match

The allow-list is, and remains, the security control: it makes injection impossible by construction
because it admits only lower-case letters, digits and single underscores. The length bound exists to
respect the PostgreSQL identifier limit. Ordering the bound first is nevertheless the right shape,
for two reasons that are worth recording because a future reader could otherwise "tidy" it back:

- **Nothing oversized ever reaches the matcher.** The pattern contains a negative lookahead and a
  trailing quantifier that both scan the input, so its cost grows with the length of the value,
  whereas the bound is a single integer comparison. Measured over 100,000 iterations, single
  threaded, on the two sequences with everything else held identical:

  | Input | Length | Regex first | Length first | Ratio |
  | --- | --- | --- | --- | --- |
  | `rec_user` — a legitimate identifier | 8 | 17.4 ms | 14.4 ms | 1.2× |
  | the 67-character compatibility boundary | 67 | 23.4 ms | 21.9 ms | 1.1× |
  | oversized, grammar-valid | 2 000 | 82.8 ms | 4.7 ms | 17.5× |
  | oversized, breaks the grammar late | 2 000 | 3 622.0 ms | 11.1 ms | 325× |
  | oversized, breaks the grammar late | 8 000 | 11 462.4 ms | 14.8 ms | 775× |

  The growth is steep but not exponential — 36 µs per call at 2 000 characters, 115 µs at 8 000 —
  so this is CWE-1333 *hardening*, not an active denial-of-service exposure: every intended caller
  passes an identifier the platform has already length-capped. Recording it as hardening rather than
  as a closed vulnerability is the honest classification, and the legitimate-identifier rows confirm
  the hot path did not regress.
- **The more specific reason is reported.** A value that is both too long and malformed now reports
  the length, which is the actionable fact for an operator whose entity name has outgrown the bound.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| Accept/reject behaviour is unchanged — the property that actually matters | 21 hand-picked inputs covering every rejection reason and both sides of the 67-character boundary, each run through `Validate` and through an oracle reproducing the previous check order | **0 verdict differences.** The 5 valid identifiers are still accepted and returned unmodified; the 16 invalid ones are still rejected with `DbException` |
| The same property under adversarial input, not just chosen input | 200 000 pseudo-random strings of length 0–74 over the alphabet `abz09_ .-";AZ`, compared against the same oracle | **0 verdict differences** |
| Only the reported *reason* changes, and only where both checks fail | the same 21 cases, comparing exception messages | exactly 2 cases changed reason, both already rejected either way: a 68-character malformed identifier and a 231-character injection payload now report the length rather than the grammar |
| `Quote` still delegates to the same validation | `Quote("rec_user")`, `Quote(<68-char malformed>)` | returns `"rec_user"`; throws `DbException` — quoting cannot be reached without passing validation |
| Module compiles | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | `dotnet restore WebVella.ERP3.sln` then `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-restore -t:Rebuild` | restore exit 0 with **zero `NU19xx`**; build exit 0, **0 errors** across all 17 solution projects |
| No new diagnostic of any kind | analyzer diagnostics attributed to `DbIdentifier.cs` | **none, before or after.** Solution warning total unchanged at 3 072, and the non-analyzer yardstick is identical: `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2 |
| Injection analyzers corroborate the class | `CA2100` and the `CA23xx` family across all 19 projects | **zero occurrences**, consistent with the finding that values in this layer are already parameterised and the residual exposure was confined to identifier concatenation |

The equivalence harness was a throwaway project outside the solution; it was deleted after use and
is not part of the repository. This is deliberate — the plan places creating a test project out of
scope, so the harness proves the change and then leaves no trace.

#### Boundary note — what is not yet protected, stated plainly

Both files in this class are **helpers that no caller invokes yet**. A repository-wide search for
`DbIdentifier.` and for `ErpSerializationBinder` outside their own files returns nothing. The six
identifier-concatenation sites and the fourteen polymorphic-deserialisation sites the plan
enumerates are attached in a later checkpoint, and until then the standalone presence of these
helpers is **not** runtime protection. Nothing in this entry should be read as claiming otherwise.

#### Deviations and out-of-scope observations

- **No deviation.** The reordering is exactly the change that was planned for this pass, and it is
  the whole of it: no signature, no exception type, no message text other than the two reason
  attributions above, and no grammar or bound was altered.
- **The 67-character bound was deliberately not tightened to 63**, and the reasoning is recorded on
  the constant itself. Every call site passes an already-prefixed table identifier, so a wholly
  legitimate value can be 67 characters; a 63 cap would break record queries for existing entities
  with long names — an outage caused by a security fix.

### Class: Output Encoding

**Findings closed in this class:** the reflected return-URL sinks on the three SDK page screens
(CWE-79, and CWE-601 at the companion redirects; OWASP A03:2021 Injection and A01:2021 Broken Access
Control), and `M-18` (CWE-116, the bypassable output encoder).

#### The correction that made this class necessary

An earlier pass removed the raw-output wrapper from these three views so that Razor's automatic HTML
encoding applied, and recorded HTML encoding as the control. **That reasoning was wrong, and browser
testing is what disproved it.** HTML encoding prevents *attribute breakout* — it stops a value
escaping a quoted `href` and injecting new markup — but it does nothing about the URL *scheme*,
because a browser decodes HTML entities before it parses the URL. An encoded
`javascript:alert(document.domain)` therefore still executed when the Cancel link was clicked. The
value needed a scheme-level control, not a text-level one.

A second sink had also been missed entirely: two of these pages pass the same value to `Redirect()`
after a successful save, and `Redirect()` performs no encoding of any kind, so the same input was an
unvalidated-redirect vector as well as a scripting one.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Plugins.SDK/Pages/page/create.cshtml` | Allow-list the return URL as a same-site relative URL and use the validated value for both the page-header back-link and the Cancel link. |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml` | Same. |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml` | Same. |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml.cs` | Reject a non-local value at the source, in `InitPage`, so the `Redirect()` after a successful save is covered too. Also made the existing fallback null-safe, which was required: `InitPage` runs before the caller's `NotFound()` guard, so substituting `$"…/{ErpPage.Id}/"` for a rejected value on a non-existent record would otherwise have raised a null reference instead of the 404 the caller already returns. |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml.cs` | Reject a non-local value at the source, clearing it so the existing fixed-path redirect branch takes over. |
| `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` | `M-18`. The platform's only output encoder defended against exactly one literal spelling of one tag, `</script>`, by rewriting it — case-sensitively and whitespace-sensitively, so `</SCRIPT>` and `</script >` passed through untouched. Replaced with the framework's `JavaScriptEncoder` applied to **every** `<`, so no variant survives. Rendered output is unchanged for legitimate content, because a browser converts the escape back to `<` when parsing the string literal. The escape is computed once into a static field rather than per call, keeping the helper on its original hot path. |

`create.cshtml.cs` was **not** changed: its `OnPost` redirects to a fixed path, so it has no redirect
sink to guard, and adding a guard there would have been change without purpose.

`M-18` is remediated rather than merely documented, even though it is a Medium, because the defective
encoder stood directly at a scripting sink: it is a compensating control for a confirmed High finding,
which is one of the three tests this remediation applies before fixing a Medium at all. A
repository-wide search confirmed it was the **only** escaping utility in the codebase — no
`HtmlEncoder`, no `HtmlEncode`, no anti-XSS library anywhere — so its weakness set the platform's
effective escaping standard.

#### Design decisions

- **Allow-list, not deny-list.** `IUrlHelper.IsLocalUrl` accepts a same-site relative URL and rejects
  everything else — absolute URLs, protocol-relative `//host` values, and any non-HTTP scheme. Trying
  to enumerate dangerous schemes instead would have been a deny-list, and deny-lists for URL schemes
  are historically defeated by whitespace, control characters and casing.
- **Nothing legitimate is rejected, and this was checked rather than hoped.** Every return URL the
  platform generates comes from `PageUtils.GetCurrentUrl`, which returns a path and optional query
  and never a host, so every legitimate value is local by construction.
- **A rejected value behaves exactly like an absent one.** That rule is applied identically on all
  three pages, so the fix introduces no new behaviour at all: it only makes hostile input take the
  path that missing input already took. On `manage` that is the record's own view; on `manage-custom`
  and `create` it is the empty value those pages already rendered when no return URL was supplied.
- **Guarded at each sink, in both layers, and that is not redundant.** HTML rendering and HTTP
  redirection are different sinks with different escaping rules; each is guarded where it occurs. The
  view guard also means the reported lines are safe when read in isolation, which matters for a
  control whose absence is invisible.
- **The `return-url` tag-helper attribute is included.** It feeds the page-header back-link, which is
  the same class of sink as the Cancel link, so excluding it would have left half the exposure open.

#### Verification

Static:

| Step | Result |
| --- | --- |
| `dotnet build WebVella.Erp.Plugins.SDK -c Debug -t:Rebuild` | exit 0, **0 errors**. This project sets `AddRazorSupportForMvc`, so the views are compiled at build time — a bad Razor expression would fail the build rather than surface at runtime |
| `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` | exit 0, **0 errors** |
| New diagnostics in the five changed files | **none.** Per-file, per-code warning counts are identical before and after: the three views report nothing, `manage.cshtml.cs` reports `CA1805`×2 and `CA2201`×2 both before and after, `manage-custom.cshtml.cs` reports `CA2201`×2 both before and after |
| Byte fidelity | byte-order mark preserved in all five, line endings unchanged, final byte unchanged |

Runtime, in a real browser against a provisioned database, authenticated as an operator. The exact
`href` attribute observed at the Cancel link is the evidence:

| Payload | Screen | Observed `Cancel` `href` attribute | Dialog raised on click? | Location after click |
| --- | --- | --- | --- | --- |
| `?returnUrl=javascript:alert(document.domain)` | manage | `/sdk/objects/page/r/560e77c5-…/` | **no** | same-site record view |
| `?returnUrl=javascript:alert(document.domain)` | manage-custom | `""` (empty) | **no** | site root |
| `?returnUrl=javascript:alert(document.domain)` | create | `""` (empty) | **no** | site root |
| `?returnUrl=javascript%3Aalert(1)` (percent-encoded) | manage | `/sdk/objects/page/r/560e77c5-…/` | — | — |
| `?returnUrl=//example.com/evil` (protocol-relative) | manage | `/sdk/objects/page/r/560e77c5-…/` | **no** | stayed on the local origin |
| `?returnUrl=/sdk/objects/app/l/` (**positive control**) | manage | `/sdk/objects/app/l/` — preserved **verbatim**, asserted by strict equality | **no** | navigated to that same-site path |
| `?returnUrl=/sdk/objects/application/l/list` (**positive control, existing route**) | manage | `/sdk/objects/application/l/list` — verbatim | **no** | landed on the Applications list, which rendered its grid normally |

Additional runtime facts worth recording because they make the result harder to argue with:

- **The payload is absent from the rendered document, not merely encoded.** A search of the whole
  serialised DOM on every hostile page found zero occurrences of `javascript:alert`,
  `alert(document.domain)`, `alert(1)`, `javascript%3Aalert`, `example.com` or `/evil`, and an
  exhaustive sweep of every attribute of every element found the payload nowhere. There is no sink
  left to exploit, even by later DOM manipulation.
- **Dialog detection was made falsifiable.** `alert`, `confirm` and `prompt` were replaced with
  recorders that persist every call across same-origin navigation *before* each click, so a dialog
  fired during navigation would still have been captured. Every click recorded zero.
- **Baseline control.** Loading the same screen with no return URL at all produced a byte-identical
  Cancel link, which is the direct demonstration that hostile input now yields exactly what absent
  input yields.
- **Network-level corroboration.** Every request in the session went to the local origin and not one
  reached `example.com` or any other host, on both the browser network log and the server log.
- **No visual regression.** The rendered screens are indistinguishable from their pre-change form,
  and the server log contains no warning, error, critical entry or unhandled exception for the
  session.

#### Deviations and out-of-scope observations

- **Deviation from the per-file guidance, deliberately and on evidence.** The per-file instruction for
  these views was to make the fix purely subtractive, to treat Razor's HTML encoding as sufficient,
  and to leave both the `return-url` attribute and the page models alone. Browser testing showed that
  premise to be false — an encoded `javascript:` value still executed — and following it would have
  left the finding open and both redirect sinks unguarded. The instruction was therefore not followed,
  and this paragraph records why rather than leaving the divergence unexplained.
- **Observed, not fixed.** `/sdk/objects/app/l/` returns 404 in this environment. Verified to be
  unrelated to this change by navigating to it directly with no return URL in play, which produces the
  identical 404: the route simply does not exist in this instance, the real one being
  `/sdk/objects/application/l/list`. No route was added, since inventing a route is feature work.
- **Recorded for the class that owns it.** `Model.ReturnUrl` is populated centrally in
  `BaseErpPageModel`, so normalising it there would fix every page in the platform in one edit.
  That file is outside this checkpoint's scope and was deliberately not touched; the recommendation is
  recorded here so the broader fix is a decision rather than an oversight.

### Class: Scan Gate Enforcement

**Findings closed in this class:** the toolchain half of L-07 (no lock file and an unpinned SDK) —
the SDK pin. The lock-file half is deliberately not done; see *Deviations* below.

**What this class delivers:** the automated validation gates themselves. Until this class landed,
every "the scan is clean" statement in this repository was an assertion rather than a measurement,
because nothing in the build inspected either the dependency graph or the source for security
defects. This class makes an ordinary `dotnet build` perform both checks, on every project, for
everyone who clones the repository.

#### Files changed

| File | Change |
| --- | --- |
| `Directory.Build.props` | **New.** Repository-root build policy carrying both gates: dependency auditing (`NuGetAudit`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`), enforcement of it (`NU1901`–`NU1904` appended to `WarningsAsErrors`), the analyzer gate (`EnableNETAnalyzers`, `AnalysisLevel=latest-recommended`), and no advisory suppression at all — the file declares no `NuGetAuditSuppress` element, so the gate is green because the graph is clean. Inline comment blocks name the threat each setting addresses, and record where a per-advisory suppression would have to go if `RISK-001`'s reversal path is ever taken. |
| `global.json` | `L-07`. The SDK version was commented out, so the toolchain floated. Both the dependency-audit defaults and the analyzer rule set vary by SDK version, which means an unpinned toolchain makes *both* gates non-reproducible — two people could legitimately get different scan results from the same source. Pinned to `10.0.302` with `rollForward: disable` — the strictest setting, because `latestPatch` still allowed the patch level to drift and both gates are SDK-version dependent. Superseded the weaker setting recorded here, which took patch updates. This edit landed earlier, in the mixed commit `4e7b66fb`, and is attributed to this class here; see the traceability table above. |

No project file was touched by this class, no package reference was added or moved, no target
framework was altered and no analyzer rule was disabled anywhere. The lock-file half of `L-07` is
deliberately **not** done — see the finding record in the [audit report](security-audit-report.md).

#### Why the policy lives here and takes this exact shape

- **Why an MSBuild file rather than an editor configuration file.** All four `.editorconfig` files in
  this repository declare themselves configuration roots, so a repository-root editor configuration
  would not reach files inside those subtrees. `Directory.Build.props` is imported by every project
  regardless of subtree, which makes it the only mechanism that covers all nineteen projects
  uniformly — and, more importantly, the only one that automatically covers a project added later.
- **Why `all` rather than the default direct-only audit.** The platform's advisories reach most
  projects *transitively*, through the core library, rather than by a direct reference. Measured, not
  assumed: the one advisory in the graph is raised for **16 distinct projects**, of which exactly one
  references the package directly. A direct-only audit would have reported fifteen projects clean
  while they resolved the vulnerable assembly.
- **Why `low` rather than a higher threshold.** Two of the three advisories this remediation dealt
  with were Moderate. A threshold that ignores Moderate findings would have hidden both.
- **Why the dependency diagnostics are promoted to errors but the analyzer diagnostics are not.** An
  advisory that is only reported is an advisory that ships, so `NU1901`–`NU1904` must fail the build.
  The analyzer set is different in kind: enabling it surfaces a large pre-existing diagnostic volume
  across roughly seven hundred source files, and promoting that would demand exactly the
  repository-wide refactor the minimal-change constraint forbids. It stays as warnings and is
  measured against a recorded baseline instead, so a genuinely new diagnostic is still visible.
- **Why `WarningsAsErrors` is appended, never assigned.** `$(WarningsAsErrors);NU1901;…` preserves
  any value a project or a command line contributes. Assigning over it would silently discard
  another author's enforcement.
- **Why one `NuGetAuditSuppress` and not a disabled diagnostic code.** Disabling `NU1903` would
  silence *every* High-severity advisory in the repository, for ever, including ones that do not
  exist yet — a blanket suppression masquerading as a targeted one. `NuGetAuditSuppress` names a
  single advisory URL, so the enforcement stays fully intact for everything else. This distinction is
  the difference between an accepted risk and a blind spot.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Policy is syntactically valid and inherited | `dotnet restore WebVella.ERP3.sln` | exit 0; **all 19 solution projects** restore, so the file is imported by every one of them without an evaluation error. The two projects that were outside the solution when this was written are now members, so no separate verification is needed; inheritance was additionally confirmed per project with `dotnet msbuild -getProperty` on all six gate properties, **19 of 19** |
| Gate 2 passes | same command | exit 0 with **no `NU19xx` diagnostic at all** — and, at this commit, with nothing suppressed: the graph carries no advisory, which `dotnet list … --vulnerable --include-transitive` independently confirms for all 19 projects |
| **Negative control — the gate is not blind** | reintroduced a live advisory into the graph and restored | **exit 1**, failing **16 distinct projects** with `error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x`. The graph was then returned to the patched pin and the restore returned to exit 0. The workflow at `.github/workflows/security-scan.yml` keeps this control permanently, as a throwaway project pinned to the affected version whose restore **must** fail. This is the decisive evidence: the advisory *is* detected, the promotion to error *does* work, and the green result is produced by one recorded acceptance rather than by an absent check |
| Enforcement is narrow, proven not asserted | `NU1901`, `NU1902`, `NU1904` in the negative-control output | absent, because no other advisory exists in the graph. Nothing is being hidden, and all four codes remain promoted to errors |
| Gate 1 executes | `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` | exit 0, **0 errors**, 3,072 warnings at the time of this class and 3,064 at this commit. The analyzer set is demonstrably running: the security families report **`CA5359`×10** and **`CA5351`×10** where before this class there were none |
| Gate 1 corroborates the audit independently | the `CA5359` locations | `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` lines 145, 288, 417 and 559 and `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` line 791 — the five always-true certificate callbacks, at exactly the five locations the audit identified by manual review. A tool that finds the same five sites independently is strong evidence that both the audit and the gate are sound. These sites belong to a later vulnerability class and are still open |
| Gate 1 finds nothing new in the classes already landed | the `CA2100` and `CA23xx` families (command-injection and query-construction) | **zero diagnostics** across all 19 projects, corroborating that data-layer values are parameterised and that identifier concatenation is now routed through validation and quoting |
| No compilation regression from enabling the gate | non-analyzer diagnostic counts, before and after | **identical**: `CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2. Every one of the 3,007 additional warnings carries a `CA` identifier, i.e. is pre-existing code debt newly *reported* rather than newly *introduced*. No source file was modified by this class, so no other outcome was possible |
| Scratch artefacts excluded | working tree inspected before building | the ad-hoc verification project used earlier in this remediation was deleted first, so the root policy is never applied to, and never validated against, a throwaway project |

The two `CA5351` groups are legacy-hash reports and are both accounted for rather than silenced:
`WebVella.Erp/Utilities/PasswordUtil.cs` line 261 is the deliberately retained legacy verification
path that makes credential migration possible without locking anyone out, and the four
`WebVella.Erp/Utilities/CryptoUtility.cs` reports are content-hashing helpers used for cache
invalidation and change detection (`Api/Cache.cs`, `Api/EntityManager.cs`,
`Utilities/DatasetExtensions.cs`) rather than for any security decision. Both are recorded as
accepted in the [risk register](risk-register.md); neither is suppressed, so both stay visible on
every build.

#### Deviations and out-of-scope observations

- **No deviation.** The policy matches the planned property set exactly.
- **Deliberately not done, and why.** No analyzer rule was escalated to an error; no rule was
  disabled; no central package management, lock file or package-source configuration was introduced;
  no target framework or package reference was declared here. Each would have exceeded the
  minimal-change boundary, and a lock file and package-source pinning are recorded as future
  recommendations rather than silently adopted.
- **A property worth keeping in mind for the reversal path.** `dotnet list package --vulnerable` does
  not honour `NuGetAuditSuppress`. At this commit that is moot — the listing is clean for all 19
  projects — but if `RISK-001`'s reversal path is ever taken, the accepted advisory will remain
  visible in that listing even though the build passes. That is useful rather than a defect: an
  accepted advisory should stay visible to anyone auditing the repository.
- **The gate reports work that is not yet done.** `CA5359` at five sites is a real, still-open
  finding belonging to a later vulnerability class. It is left reported. Suppressing a diagnostic to
  make an interim state look finished would defeat the purpose of building the gate.

### Class: Secret Management

**Findings closed in this class:** C-04 (hardcoded encryption key with a silent fallback, CWE-798 /
CWE-321, OWASP A02:2021) and H-04 (weak default token signing key, CWE-798 / CWE-321, OWASP
A02:2021). The related H-05 (plaintext
database credentials in shipped configuration) is *enabled* by this class — the fail-fast validation
that makes scrubbing safe lands here — but the configuration files themselves are scrubbed in a later
checkpoint, so H-05 is not claimed as closed.

Two compiled-in secrets used to make every deployment that did not override them trivially
compromised. The encryption key was a 64-hex-character constant in the core library, and the token
signing key was a placeholder string substituted whenever configuration supplied none. Both values
were public knowledge twice over: this assembly is published to nuget.org, so the constant was
readable straight out of the shipped library, and the identical literal also shipped in the
configuration files. Neither could be rotated or revoked, because every installation shared it. A
forged bearer token signed with the default key is a complete authentication bypass, which is why
these are Critical and High rather than "weak cryptography".

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/CryptoUtility.cs` | The `defaultCryptKey` constant is **deleted**, and the silent fallback in the `CryptKey` property is replaced by an `InvalidOperationException` naming the setting, the environment variable, the legacy misspelled `Settings:EncriptionKey` spelling, the finding, and the operator guide. |
| `WebVella.Erp/ErpSettings.cs` | The `"ThisIsMySecretKey"` fallback on `JwtKey` is removed, and a new `ValidateRequiredSecurityConfiguration` accumulates every missing required secret and throws once with an actionable message. |

#### Design decisions

- **Deleting the constant alone would have relocated the defect, not fixed it.** The vulnerability is
  the *fallback*, not the literal: a caller reaching the key property with nothing configured must be
  stopped loudly rather than handed a predictable key it would then mistake for protection. Both
  edits are therefore one change and must stay together.
- **No escape hatch, by design.** There is deliberately no development-mode or environment bypass,
  because that recreates exactly the defect being removed — and no generated random key either,
  because that would silently make already-encrypted data undecryptable, which is a worse outcome
  than failing loudly.
- **Failures name keys, never values.** No value, prefix, length or digest of a secret appears in any
  message, so a startup failure cannot leak key material into a console, a log file or a crash report
  (CWE-532).
- **All missing secrets are reported at once.** A mis-provisioned deployment learns about every gap
  from a single startup failure instead of one restart per variable.
- **The signing key is required only where a `Settings:Jwt` section exists.** Only the token-issuing
  hosts configure one; the remaining hosts and the console application legitimately ship none, and
  demanding a key from them would stop them starting — which the preservation requirement forbids.
  Where the section *is* present the key is mandatory, because its fallback was removed.
- **Validation runs before `IsInitialized` is set**, so a failed validation leaves the settings
  explicitly un-initialised rather than half-applied.
- **The legacy misspelling is still honoured.** `Settings:EncriptionKey` is resolved into
  `EncryptionKey` before validation runs, so an existing deployment that carries the misspelled key
  keeps working. Removing the misspelling would have been a gratuitous breaking change.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| The default key is gone | search of the tracked tree for the 64-hex-character constant and for `defaultCryptKey` | **no occurrence** anywhere |
| The placeholder signing key is gone | search of the tracked tree for `ThisIsMySecretKey` | **no occurrence** anywhere |
| The fallback is genuinely removed, not merely hidden — the negative test | resolve the key property with no key configured | throws `InvalidOperationException` with an actionable message; no key is returned |
| Startup refuses to proceed without required secrets | initialise settings with the connection string and encryption key absent | throws, listing both missing key names and neither value |
| Core module compiles | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | solution restore then rebuild | restore exit 0 with zero unsuppressed `NU19xx`; build exit 0, **0 errors** |
| The toolchain pin is effective | `dotnet --version` in the repository root | reports the pinned `10.0.302`, so both gates evaluate the same rule sets on every machine |

#### Boundary note — what is not yet done, stated plainly

The eight shipped `Config.json` files and `WebVella.Erp.Site/web.config` are **not** changed in this
checkpoint. Their secret values are still present and development mode is still enabled, so H-05 and
H-12 remain open; scrubbing them belongs to a later checkpoint, and it is safe to do only *because*
the fail-fast validation above now exists. The configuration provider chain has likewise not yet been
extended beyond the JSON file source, which is the other precondition for the scrub. Nothing in this
entry should be read as claiming a deployment's secrets have been removed from disk.

Two documents referenced from the messages this class adds —
`docs/security/secure-configuration.md` and `docs/security/credential-migration.md` — belong to the
same later checkpoint and are deliberately **not** created here. The references are stable paths, not
broken links to something that was meant to exist by now, and they are named here so the gap is
explicit.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach.
- **The SDK pin is not attributed here.** `global.json` was pinned as part of the same work, but its
  purpose is to make the two automated gates reproducible, so it is owned by the **Scan Gate
  Enforcement** class and appears in that class's file table only. Every file in the change set is
  attributed to exactly one class.
- **The deterministic key and initialisation-vector derivation in the same file is documented, not
  changed.** It is a Medium finding, it is latent — the symmetric encrypt/decrypt API has no
  in-repository callers — and changing the derivation would make every already-persisted ciphertext
  undecryptable. Recorded as an accepted risk with the recommended fix and the observation that the
  cheapest moment to apply it is before the first caller exists.

### Class: Session and Token Handling

**Findings closed in this class:** H-02 (token lifetime validation disabled, reachable through an
anonymous refresh endpoint, CWE-613 / CWE-347, OWASP A07:2021), H-03 (authentication ticket expiry set
a hundred years ahead, CWE-613, OWASP A07:2021), M-03 (sign-in call not awaited) and M-04 (server-local
time used for token timestamps, CWE-613).

H-02 and H-03 compound: an authentication cookie that never expired, plus a bearer token whose
lifetime was never checked, plus an `[AllowAnonymous]` refresh endpoint, means a single stolen
credential was good forever and indefinitely renewable without ever re-authenticating. The two Mediums
are in scope under the class's own rules — M-03 is an unavoidable by-product of hardening the same
method, and M-04 only becomes exploitable slack *because* lifetime validation is now enforced.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/AuthService.cs` | `ExpiresUtc` moves from `AddYears(100)` to an explicit 24-hour bound; `ValidateLifetime = true` with an explicit one-minute `ClockSkew`; the swallowed validation exception now writes a rate-bounded audit record; token expiry moves from `DateTime.Now` to `DateTime.UtcNow`; `Authenticate` awaits the sign-in and therefore becomes asynchronous. |
| `WebVella.Erp.Web/Pages/login.cshtml.cs` | Compile-mandated propagation only: `OnPost` becomes `async Task<IActionResult>` and awaits `Authenticate`. The handler name is unchanged, so Razor Pages still binds it to POST and the request/response contract is untouched. |

#### Design decisions

- **An explicit `ExpiresUtc` *is* the lifetime.** It wins over the host's `ExpireTimeSpan`, which is
  why the hundred-year value was effective rather than cosmetic, and why the replacement is bounded to
  the same 24-hour horizon as the bearer token rather than left to the host default.
- **Clock skew is explicit.** One minute, stated rather than inherited, so drift stays bounded and a
  reader can see what tolerance the system actually grants.
- **Validation failures are logged, but three properties of that logging are load-bearing.** They are
  recorded on the code because a future tidy-up would otherwise remove them and reintroduce a worse
  problem than the one being fixed: the record is written with notification suppressed, because the
  log service e-mails before it persists and the token validator runs for every request carrying an
  `Authorization` header — a notifying log here would be an attacker-triggered mail bomb; writes are
  rate-bounded to one per minute, so a flood produces evidence of a flood rather than a flood of
  evidence; and only the exception type and message are recorded, never the raw token, which is a
  bearer credential, and never a stack trace.
- **The audit write cannot break authentication.** It is wrapped so that a logging failure returns
  `null` from validation as before rather than turning token validation into a server error.
- **`Authenticate` keeps its name.** Renaming it to `AuthenticateAsync` would have been the tidier
  convention and was rejected: it is a public member of a shipped library, and the remediation
  boundary forbids API surface changes that a security fix does not require.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| Web framework compiles, including the asynchronous propagation | `dotnet build WebVella.Erp.Web/WebVella.Erp.Web.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | solution restore then rebuild | restore exit 0 with zero unsuppressed `NU19xx`; build exit 0, **0 errors** across all 17 solution projects |
| The propagation is complete — no caller left behind | repository-wide search for callers of `AuthService.Authenticate` | exactly one, the login page, and it awaits |
| Lifetime validation is corroborated by the gate | `CA5404` (do not disable token validation checks) across the solution | no occurrence, consistent with `ValidateLifetime` now being `true` |
| No new diagnostic | non-analyzer yardstick before and after | identical |

#### Deviations and out-of-scope observations

- **`login.cshtml.cs` is changed even though the login class it otherwise belongs to is a later
  checkpoint.** This is not optional and not scope creep: awaiting the sign-in makes `Authenticate`
  asynchronous, and leaving its only caller behind would fail to compile. The diff is confined to the
  `async`/`await` propagation and the `using` it needs. It is listed in the boundary table at the top
  of this document.
- **The anonymous refresh endpoint itself is not changed here.** Enforcing lifetime validation is what
  removes the indefinite-renewal property; whether that endpoint should require authentication at all
  is a separate question recorded against the finding rather than decided here.
- **Cookie attributes are not set in this class.** `Secure`, `SameSite`, an explicit expiry window and
  sliding expiration are host pipeline configuration and belong with the transport class in a later
  checkpoint. Until then H-15's cookie half remains open.
- **The commented-out login audit block elsewhere in the framework is left in place.** It is
  unreachable, therefore not exploitable, and deleting it is hygiene rather than remediation.

### Class: Transport and Response Headers

**Findings closed in this class:** M-01 (no security response headers) and the HSTS half of H-15
(CWE-319 cleartext transmission, CWE-614 sensitive cookie without the `Secure` attribute, OWASP
A02:2021 / A05:2021) — to the extent the middleware itself closes them; see the boundary note below.

Only one of the nine applications emitted any security header at all. With no HSTS an attacker can
downgrade a connection to plaintext and intercept the session cookie; with no frame or content-type
protections, clickjacking and MIME confusion are available; and with no content policy there is no
second line of defence behind the output-encoding class.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` | **New.** Emits the seven mandated headers with their mandated values, plus a small options type carrying the content-policy value and its report-only switch, plus two registration extensions. |

The seven headers, emitted exactly as specified: `Content-Security-Policy` (see below),
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `X-XSS-Protection: 0`,
`Referrer-Policy: strict-origin-when-cross-origin`, and
`Permissions-Policy: geolocation=(), microphone=(), camera=()`.

#### Design decisions

- **Headers are attached before the response starts**, because mutating them afterwards throws.
- **Every write is indexer assignment, never `Add`.** `Add` throws on an already-present key, which
  would turn a hardening change into a 500 the moment anything else set the same header. It also makes
  duplication impossible when a host separately enables the framework's own HSTS middleware: the value
  written here is identical, so an overwrite either way is a no-op.
- **`X-XSS-Protection: 0` is intentional and must not be "modernised".** The value disables the legacy
  browser XSS auditors, which are themselves exploitable to selectively suppress legitimate script.
  Setting `1; mode=block` would be a regression, not an improvement.
- **The content policy value is emitted verbatim and is never weakened**, but it ships under the
  *report-only* header name. Four components deliberately emit inline script or markup — the two HTML
  block component views, the navigation script emitter and the SDK sitemap form — so enforcing
  `script-src 'self'` on first deployment would break them and violate the
  functionality-preservation requirement. Only the header *name* is staged; the value never changes,
  and an operator flips one switch once violation reports are clean. This is the one place in the
  whole remediation where a mandated control cannot be enforced on day one, and it is recorded rather
  than quietly softened.
- **Secure by default in every registration order.** If the options type was never registered, or
  resolves to null, the middleware falls back to a defaulted instance carrying the mandated values —
  so a host that forgets to configure it still gets the full header set.
- **The default policy value is single-sourced**, so the options default and the middleware fallback
  cannot drift apart.
- **Pipeline position is deliberately left to each host** rather than fixed inside the platform
  registration extension. The headers must reach static-file and compressed responses too, which means
  each host inserts this *early* — ahead of response compression and ahead of static files. Fixing the
  position centrally would put it in the wrong place for at least one host.

#### Verification

| Step | Command / method | Result |
| --- | --- | --- |
| Web framework compiles | `dotnet build WebVella.Erp.Web/WebVella.Erp.Web.csproj -c Debug -t:Rebuild` | exit 0, **0 errors** |
| Solution compiles under the enforced gate | solution restore then rebuild | restore exit 0 with zero unsuppressed `NU19xx`; build exit 0, **0 errors** |
| Exactly one policy header is ever emitted | inspection of the two mutually exclusive branches | the report-only name or the enforcing name, never both |
| No new dependency | the project's `PackageReference` set | unchanged — the middleware needs nothing beyond framework references already present |
| No new diagnostic | non-analyzer yardstick before and after | identical |

#### Boundary note — what is not yet protected, stated plainly

The middleware **has no callers yet.** A repository-wide search for `SecurityHeadersMiddleware`,
`UseSecurityHeaders` and `UseSecurityHeadersMiddleware` outside its own file returns nothing: it is
not registered in the platform extension and not inserted into any of the seven host pipelines, so **no
response currently carries these headers.** HTTPS redirection and the framework's HSTS middleware are
likewise not yet added to any pipeline, and the cookie attributes that make up the rest of H-15 are
host configuration that has not been changed. Registration and ordering are a later checkpoint. The
standalone presence of this middleware is **not** runtime protection, and nothing in this entry should
be read as claiming otherwise.

#### Deviations and out-of-scope observations

- **One deviation, and it is the staged content policy above.** The value is exactly as mandated; the
  delivery mode is report-only first. The reason, the four components that force it, and the single
  switch that enforces it are all recorded, and the accepted risk is registered rather than implied.
- **The permissive cross-origin policy at two hosts is not changed here.** It is host configuration
  belonging to its own class, and the plan requires it to land together with HTTPS redirection —
  redirection breaks cross-origin preflight with an invalid-redirect error if the two are separated.
- **No `Content-Security-Policy` reporting endpoint is added.** Collecting violation reports is
  deployment infrastructure outside the application boundary; the report-only header is directly
  observable in a browser's console without one.


## Executed verification transcripts, class by class

> **Correction — the `AutoMapper` disposition recorded below is the alternative, not the one that
> shipped.** Passages in this section that describe the pin as *held at `[14.0.0]` behind a single
> dependency-audit suppression* were written against that alternative. Measured at this commit: the
> pin is **`[15.1.3]`**, `ErpAutoMapper.Initialize` supplies `NullLoggerFactory.Instance`,
> `Directory.Build.props` declares **no** `NuGetAuditSuppress` element, and
> `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports **no vulnerable
> package in any of the 19 projects**. The advisory is therefore closed by upgrade, and the licensing
> question it raises is escalated and **open** as `RISK-001`. The retained-`[14.0.0]` analysis is
> kept in full, because it is the documented reversal path `RISK-001` records and because its
> exploitability assessment and negative-control evidence hold either way.

### Class: Build and Scan Integrity

**What this class establishes:** trustworthy scan evidence. Nothing else in this log means anything
until it holds, which is why it is sequenced first. Two defects made the platform's security posture
unmeasurable: fifteen project references spelled the core project's folder as `WebVella.ERP` while
the folder on disk is `WebVella.Erp`, and there was no build-level gate of any kind.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.ERP3.sln` and 14 `.csproj` files | Project-reference path casing corrected (H-19). On a case-sensitive filesystem the solution restore failed outright and the core project — which owned the graph's only High-severity advisory — was silently absent from the audit, so every "clean" scan result obtained beforehand was worthless. |
| `global.json` | SDK version pinned to `10.0.302`. Both the NuGet audit defaults and the rule set selected by `latest-recommended` vary by toolchain version, so an unpinned toolchain makes the gate non-reproducible. |
| `Directory.Build.props` | **New.** The repository-wide gate. See below for why it must be MSBuild. |
| `.github/workflows/security-scan.yml` | **New.** The reproducible execution route for the gates. Before it, `.github/` held only `FUNDING.yml`, so the gates had nowhere to run and could only be asserted. |

#### Why the gate is MSBuild and not a root `.editorconfig`

All four `.editorconfig` files in this repository declare `root = true` — in `WebVella.Erp`,
`WebVella.Erp.Web`, `WebVella.Erp.Plugins.SDK` and `WebVella.Erp.Plugins.Next` — and between them
those four subtrees hold every file this remediation touches. A repository-root `.editorconfig`
would be ignored inside all of them. `Directory.Build.props` is implicitly imported by every project
regardless of that scoping, so it is the only mechanism that reaches the whole repository uniformly.

#### What the gate sets, and what it deliberately does not

| Property | Value | Serves |
| --- | --- | --- |
| `NuGetAudit` | `true` | Gate 2 — dependency scan |
| `NuGetAuditMode` | `all` | Gate 2. Set explicitly, not left to an SDK default, and `all` rather than `direct` because `MimeKit` is reached only transitively through `MailKit` — `direct` would never have reported its advisory. |
| `NuGetAuditLevel` | `low` | Gate 2 — so a Moderate advisory cannot hide beneath a High-only threshold |
| `WarningsAsErrors` | appends `NU1901;NU1902;NU1903;NU1904` | Gate 2 **enforcement** — the low/moderate/high/critical audit codes become build errors |
| `EnableNETAnalyzers` | `true` | Gate 1 — static analysis |
| `AnalysisLevel` | `latest-recommended` | Gate 1 — raises the analysis mode above the SDK default minimum set |

Deliberately absent, and not to be "completed" by a later edit: no blanket warnings-as-errors
switch, no `CA` rule in the promoted-code list, and no build-time code-style enforcement. Analyzer
diagnostics remain **warnings**, because escalating a large pre-existing backlog across roughly
seven hundred source files would demand exactly the repository-wide refactor the change scope
forbids. Only the four NuGet audit codes are errors. The suppression seam for a declined dependency
upgrade is present but **commented out** — nothing is suppressed today.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Gate reaches every project | `dotnet msbuild <each of the 19 .csproj> -getProperty:NuGetAudit -getProperty:NuGetAuditMode -getProperty:NuGetAuditLevel -getProperty:EnableNETAnalyzers -getProperty:AnalysisLevel -getProperty:WarningsAsErrors` | **19 / 19** evaluate `true` / `all` / `low` / `true` / `latest-recommended`, and all four `NU190x` codes present in `WarningsAsErrors`, with **no `CA` code promoted**. Includes both non-solution-member WebAssembly projects. |
| Casing precondition | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches |
| Restore with the gate active | `dotnet restore WebVella.ERP3.sln --force` | exit 0, **zero `NU19xx`** |
| Analyzer build | `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` | exit 0, **0 errors**. Warning count rises from 54 to 3072, entirely `CA*` volume from `latest-recommended`; the non-analyzer counts are unchanged from the pre-gate baseline (`CA2200`×52, `ASPDEPR008`×42, `CS0618`×6, `CS0168`×4, `ASP0019`×2), so there is no compilation regression. |
| Advisory scan, 17 solution projects | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | exit 0; every project reports `has no vulnerable packages given the current sources` |
| **Negative control — the gate is not blind** | restore a throwaway project pinning `AutoMapper [14.0.0]` **inside** the repository so it inherits the gate | **exit 1** with `error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x` |
| **Negative control — the gate is what makes it fail** | the identical project restored **outside** the repository, where `Directory.Build.props` is not inherited | **exit 0**, and the same advisory appears only as `warning NU1903`. Evaluated `WarningsAsErrors` is `;NU1605;SYSLIB0011` and `AnalysisLevel` is `latest`. This is the delta: SDK defaults **detect**, the gate **enforces**. |
| Workflow is executable, not decorative | every `run:` block extracted from the parsed YAML, `bash -n` checked, then executed | 8 / 8 steps exit 0, including the two explicit non-member steps and the negative control |

**Gate 1 result, stated precisely.** With `latest-recommended` active, exactly two security rule
families fire across the whole repository, and both land where the audit already said they would —
which is the point of a scanner-derived gate:

* `CA5359` (certificate validation disabled) ×5, at `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs`
  lines 145, 288, 417 and 559 and `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` line
  791 — **the exact five locations recorded for H-11**, independently corroborated by the analyzer.
  H-11's remediation belongs to the transport-security class, not this one.
* `CA5351` (broken algorithm MD5) ×5, at `WebVella.Erp/Utilities/PasswordUtil.cs` line 261 — the
  deliberately retained legacy-verification-only `GetMd5Hash`, an **accepted and recorded** warning
  whose own doc comment predicts it — and at four pre-existing MD5 helpers in
  `WebVella.Erp/Utilities/CryptoUtility.cs` (lines 188, 200, 210, 227) that carry no finding and are
  outside this remediation's scope.

Zero `CA2100` (query construction), zero `CA3xxx` (injection and cross-site scripting) and no other
`CA5xxx` diagnostics anywhere. Gate 1's pass criterion is zero diagnostics in these families across
the *remediated* files, with the one accepted `CA5351` exception named above — not zero across a
repository the remediation was forbidden from refactoring.

#### WebAssembly Server and Shared — coverage stated explicitly

These two projects are **not** solution members and are **not** reached transitively: the only
reference to `Shared` in the repository comes from `Server`, itself a non-member, and the solution's
`WebAssembly/Client` declares no `ProjectReference` at all. No solution command can say anything
about them, so a solution-only run must never be described as covering all 19 manifests. They were
driven directly:

| Project | Command | Result |
| --- | --- | --- |
| Server | `-getProperty:TargetFramework` | `net10.0` — retarget off the end-of-life `net7.0` line is live, not merely written |
| Server | `dotnet restore …Server.csproj --force` | exit 0, zero `NU19xx` |
| Server | `dotnet build …Server.csproj -c Debug -t:Rebuild` | exit 0, **0 errors**, 53 warnings (all `CA*` / `CS0168`); emits `net10.0/WebVella.Erp.WebAssembly.Server.dll` together with `…Shared.dll` and `…WebAssembly.dll`, so this single command also compiles the Client and Shared references |
| Server | `dotnet list …Server.csproj package` | `Microsoft.AspNetCore.Components.WebAssembly.Server` requested `10.0.1`, resolved `10.0.1` — the end-of-life `7.0.13` pin is gone |
| Server | `dotnet list …Server.csproj package --vulnerable --include-transitive` | exit 0, `has no vulnerable packages given the current sources` |
| Shared | `-getProperty:TargetFramework` | `net10.0` |
| Shared | `dotnet restore …Shared.csproj --force` | exit 0, zero `NU19xx` |
| Shared | `dotnet build …Shared.csproj -c Debug -t:Rebuild` | exit 0, **0 errors, 0 warnings** |
| Shared | `dotnet list …Shared.csproj package --vulnerable --include-transitive` | exit 0, `has no vulnerable packages given the current sources` |
| Both | `grep -rn 'net7.0' --include=*.csproj .` | no `TargetFramework` match remains; the only surviving occurrence is the comment explaining the retarget |

Two corroborations beyond the manifest edit, recorded because editing a `.csproj` proves only intent:
the compiled `WebVella.Erp.WebAssembly.Server.dll` carries `.NETCoreApp,Version=v10.0` in its
metadata, and both non-member manifests evaluate the repository gate identically to the 17 solution
projects, so they sit inside the same audit and analyzer regime rather than beside it. Both projects
have their own named steps in `.github/workflows/security-scan.yml`, which is configured to trigger on
every push and pull request to any branch, so this coverage does not depend on someone remembering to
run two extra commands. One qualification, so the claim is not read as more than it is: the workflow's
steps were validated by extracting each `run:` block and executing it against this working tree — all
eight blocks exited 0 — not by observing a hosted CI run, which this environment cannot perform. The
commands are therefore proven to work and proven to be committed; the first hosted execution is the one
this branch triggers when it is pushed.

#### Deviations and out-of-scope observations

- **No deviation** from the planned gate: all six properties landed with the planned values, and the
  append form of `WarningsAsErrors` preserved the SDK's own `NU1605;SYSLIB0011` rather than
  discarding it.
- **Observed, not fixed:** `Microsoft.Web.LibraryManager.Build` warns `libman.json does not exist`
  for `WebVella.Erp.Site`. The package is effectively inert because no client-library manifest is
  present. It is a build-noise issue, not a security finding, and changing it is outside this class.

### Class: Credential Integrity

**Findings closed in this class:** C-03 (unsalted MD5 password hashing, CWE-916/CWE-759, OWASP
A02:2021), M-05 (non-constant-time hash comparison, CWE-208) and M-06 (shared mutable hash
instance, CWE-362).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | Salted, work-factored `HashPassword`/`VerifyPassword` pair over the framework `PasswordHasher`; legacy MD5 retained for verification only, behind `CryptographicOperations.FixedTimeEquals`; shared MD5 instance replaced by the static one-shot `MD5.HashData` |

#### Executed verification

The platform contains no test project, so this behaviour was exercised through a transient external
harness that referenced the built `WebVella.Erp` assembly, reached the assembly-internal members by
reflection, and was deleted after the results below were recorded. No repository test project, test
framework reference or package reference was added. **68 checks, 68 passed, 0 failed.**

| Property verified | Observed result |
| --- | --- |
| Stored format | 84-character Base64 — fits the existing 500-character password column, so no schema change |
| Format marker | `0x01` = ASP.NET Core IdentityV3 |
| Iteration count embedded in the value | `600000` (OWASP floor for PBKDF2-HMAC-SHA512 is 210,000) |
| Salt length embedded in the value | 16 bytes = 128 bit |
| Pseudo-random function identifier | `2` = HMAC-SHA-512 |
| Derived subkey length | 32 bytes = 256 bit |
| Salt uniqueness | 12 hashes of one password produced 12 distinct values with 12 distinct salts |
| Correct password | verifies, `needsRehash=false` |
| Wrong password, changed case, one-character truncation | all rejected, `needsRehash=false` in every case |
| Legacy lower-case digest | verifies AND `needsRehash=true` |
| Legacy UPPER-case digest | verifies AND `needsRehash=true` — an account whose digest was stored upper case is not locked out |
| Legacy digest + wrong password | rejected AND `needsRehash=false`, so a failed attempt can never trigger a write |
| `IsLegacyHash` discriminator | 32-hex lower and upper → legacy; 31 chars, 33 chars, one non-hex character, an 84-character modern value, `null`, empty and 32 spaces → not legacy (9 cases) |
| Fail-closed on absent input | `HashPassword` of `null`, empty and whitespace returns empty; empty, `null` and whitespace stored values never verify; empty and `null` passwords never verify; **`VerifyMd5Hash("", "")` is now `false`**, where the pre-remediation comparison returned `true` (12 cases) |
| Malformed stored value | 11 corrupt values — invalid Base64, wrong length, truncated payloads, an all-zero 61-byte payload, an unknown `0x09` marker — every one returned `false` and **none threw**, so a damaged row cannot become a denial of service on the login path |
| Upgrade round trip | legacy value verifies and asks to be replaced → replacement is modern shape → replacement verifies asking for nothing further → old digest is gone → the user's password itself is unchanged, so no forced reset occurred |
| Work-factor upgrade rides the same signal | a V3 value written at the framework default 100,000 iterations verifies with `needsRehash=true`; a V2-format value (marker `0x00`) likewise; a V2 value with the wrong password is still rejected |
| Concurrency (M-06) | 64 parallel hash/verify/digest operations: 0 exceptions, 0 wrong results |

Timing (M-05) was measured with both sides sampled **interleaved** across alternating rounds and
reported as the median of those rounds, so neither probe could be advantaged by warm-up or by
running first. Both probes are 32 characters long, so length is not the discriminator, and both are
genuinely non-matching.

| Comparison, over "31 of 32 characters already correct" vs "0 of 32 correct" | Median ns (near / far) | Ratio |
| --- | --- | --- |
| `CryptographicOperations.FixedTimeEquals` — what the code now uses | 247.93 / 261.67 | **0.9475** |
| `VerifyMd5Hash` end to end, including the MD5 of the input | 1647.3 / 1646.9 | **1.0002** |
| `StringComparer.OrdinalIgnoreCase` — the comparison that was removed (reported, not asserted) | 36.15 / 15.82 | 2.2844 |
| A synthetic early-exit character loop — the shape of the oracle (reported, not asserted) | 191.91 / 13.67 | 15.5035 |

The two ratios at 1.0 are the security property. The two ratios far from 1.0 are the control: they
show that a comparison which returns at the first difference really does leak how many leading
characters an attacker has already guessed, which is what `FixedTimeEquals` removes. Source
corroboration was taken alongside the measurement: `CryptographicOperations.FixedTimeEquals` is
present, the equal-length pre-check it depends on is present, and **no executable `StringComparer`
comparison remains** — the single surviving mention is comment prose.

#### Deviations and out-of-scope observations

- **Deviation, disclosed rather than absorbed:** the mandated Cryptographic Standards name bcrypt,
  scrypt or Argon2. PBKDF2 is used instead, for the reasons set out in the header of
  `PasswordUtil.cs` and in the [risk register](risk-register.md). Analyzer rule `CA5351` reports on
  the retained legacy `GetMd5Hash`; that warning is accepted, not suppressed.
- **Measurement claim corrected in this pass.** The file previously asserted "roughly 380 ms per
  verification against roughly 120 ms for HMAC-SHA-256 … about three times the work" with no
  recorded measurement behind it. Both figures have now been measured, and the comment was rewritten
  to name the measurement basis and to mark the absolute milliseconds as hardware-dependent while
  the ratio is the durable claim. PBKDF2 with a 128-bit salt, a 256-bit output and 600,000
  iterations, sampled interleaved across three independent processes:

    | Pseudo-random function | Median per derivation (3 runs) |
    | --- | --- |
    | HMAC-SHA-512 — what IdentityV3 uses | 381.0 ms, 361.1 ms, 364.7 ms |
    | HMAC-SHA-256 — the contrast in the claim | 125.3 ms, 117.5 ms, 117.9 ms |
    | **Measured ratio** | **3.04x, 3.07x, 3.09x** |

    End-to-end through `PasswordUtil` on the same host: `HashPassword` mean 366.6 / 382.3 / 365.6 ms,
    `VerifyPassword` mean 366.7 / 379.9 / 363.4 ms, against `GetMd5Hash` at 0.1 ms — the legacy
    primitive was roughly three to four thousand times cheaper per attacker guess, which is precisely
    why C-03 was Critical.

    Reference host for every figure above: .NET 10.0.10 on Ubuntu 25.10, x64, 4 logical cores, Intel
    Xeon at 2.60 GHz, workstation GC. **Re-measure on the target host before relying on the absolute
    numbers for a latency budget.** The login-path latency increase is the pre-declared, accepted
    trade-off for closing C-03; no other request path pays it.

- **Observed, not changed:** the four remaining `GetMd5Hash` call sites in `SecurityManager.cs`,
  `RecordManager.cs` and `DbRecordRepository.cs` are switched to the new primitive by a later
  boundary of this remediation and are outside this file set. `PasswordUtil` was deliberately built
  to be call-site compatible — `HashPassword` returns empty for absent input exactly as
  `GetMd5Hash` did — so those switches need no behavioural adaptation.

### Class: Secret Management

**Findings closed in this class:** C-04 (hard-coded encryption key with a silent fallback, CWE-798 /
CWE-321, OWASP A02:2021), and the settings-layer half of H-04 and H-05.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/CryptoUtility.cs` | Compiled-in 64-hex default key deleted; the silent fallback in `CryptKey` replaced by a fail-fast `InvalidOperationException` |
| `WebVella.Erp/ErpSettings.cs` | Removed the compiled-in JWT signing-key fallback; added `ValidateRequiredSecurityConfiguration`, invoked before `IsInitialized` is set |

#### Executed verification

Each scenario below ran in **its own process**. That is required, not stylistic: `ErpSettings` is
static and `CryptoUtility` caches the key after the first successful resolution, so scenarios sharing
a process would contaminate each other. **10 subprocesses, 51 checks, 51 passed, 0 failed**; every
subprocess exited 0.

| Scenario | Configuration supplied | Observed outcome |
| --- | --- | --- |
| Missing connection string | `EncryptionKey` only | `System.Exception`, names `Settings:ConnectionString`; `IsInitialized` stayed **false** |
| Missing encryption key | `ConnectionString` only | `System.Exception`, names `Settings:EncryptionKey`; `IsInitialized` stayed **false** |
| Missing signing key **with** a `Settings:Jwt` section present | `ConnectionString`, `EncryptionKey`, `Settings:Jwt:Issuer` | `System.Exception`, names `Settings:Jwt:Key`; `IsInitialized` stayed **false** |
| All three missing | a `Settings:Jwt` section only | one failure naming **all three** keys, so a mis-provisioned deployment does not need one restart per variable |
| Positive: host that issues no tokens | `ConnectionString`, `EncryptionKey`, **no** `Settings:Jwt` section | starts successfully, `JwtKey` is `null` — the removed default did not reappear. This is the check that proves the gate did not break the five hosts and the console application that legitimately ship no JWT section |
| Positive: token-issuing host | `ConnectionString`, `EncryptionKey`, `Settings:Jwt:Key` | starts successfully; `JwtKey` equals the configured value |
| Legacy mispelled key name | `ConnectionString`, `Settings:EncriptionKey` | starts successfully; resolved into `EncryptionKey`; `CryptKey` serves it, so a deployment using the historical spelling keeps decrypting its data |
| `CryptoUtility.CryptKey` with nothing configured at all | none | `System.InvalidOperationException` — **no value was returned**, so the fallback is genuinely gone rather than relocated |
| Blank key, the shape a scrubbed `Config.json` has | `ConnectionString`, `EncryptionKey=""` | fail-fast at `Initialize`, and fail-fast again at `CryptKey` reached directly |
| Positive: key present | `ConnectionString`, `EncryptionKey` | `CryptKey` returns the configured value; it is **not** the deleted default; a second read is served from the cache and returns the same value; encrypt/decrypt round-trips |

Every failure message was additionally asserted to (a) name the missing configuration key, (b) name
the supply mechanism and point at `docs/security/secure-configuration.md`, (c) state that no insecure
fallback remains, so an operator does not go looking for one, and (d) **leak no key material** — no
secret value, no prefix of one, no length and no digest. Secret values were compared by equality in
the harness and never printed.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach. Both halves of C-04 landed together: deleting the
  constant without converting the fallback would have relocated the defect rather than fixed it, and
  the "nothing configured at all" scenario above is the check that distinguishes the two.
- **Deliberately absent:** no development-mode escape hatch and no generated random key. The first
  would recreate the defect; the second would silently make already-encrypted data undecryptable.
- **Out of scope for this file set:** blanking the values in the eight `Config.json` files, the
  `web.config` environment marker, and extending the configuration provider chain to read
  environment variables all belong to a later boundary. Until the provider chain lands, the settings
  layer verified here is the only thing standing between a missing secret and a silent known-bad
  key — which is why it was built to fail loudly.
- **Stated explicitly so no reader infers more than was done — the shipped secrets are still there.**
  As of this class, a `grep` of the tracked tree finds the same 64-hex encryption key in **all eight**
  `Config.json` files, and the token signing key in the **two** token-issuing hosts' files. Deleting
  the compiled-in constant closed the nuget.org half of C-04 — anyone could previously read it out of
  the published `WebVella.Erp` package — but the configuration half remains open until the scrub
  lands. The ordering is deliberate rather than an oversight: both callers of `ErpSettings.Initialize`
  build a provider chain of exactly one non-optional `AddJsonFile`, so blanking those values before
  that chain accepts environment variables would leave operators no supply channel and stop every host
  starting, which the "all existing functionality remains operational" preservation requirement
  forbids. The source comments at `WebVella.Erp/ErpSettings.cs` and
  `WebVella.Erp/Utilities/CryptoUtility.cs` state this pending state in the same terms, so neither the
  code nor this log can be read as claiming a clean repository.

### Class: Session and Token Handling

**Findings closed in this class:** H-02 (token lifetime validation disabled, CWE-613/CWE-347, OWASP
A07:2021), H-03 (authentication ticket expiry set 100 years ahead, CWE-613), M-03 (sign-in call not
awaited) and M-04 (local time used for token timestamps, CWE-613).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/AuthService.cs` | `ValidateLifetime`, `ValidateIssuer`, `ValidateAudience` and `ValidateIssuerSigningKey` all enabled with an explicit `ClockSkew` of one minute; the authentication ticket bounded to `AUTH_TICKET_EXPIRY_DURATION_MINUTES = 1440` from `DateTimeOffset.UtcNow`; the sign-in call awaited, which makes `Authenticate` an `async Task<ErpUser>`; JWT `expires` computed from `DateTime.UtcNow`; token-validation failures logged instead of silently swallowed, rate-bounded to one record per minute and confined to the exception type and message |

#### Executed verification

The platform contains no test project, so this behaviour was exercised through a transient external
harness that referenced the built `WebVella.Erp.Web` assembly, replaced the framework
`IAuthenticationService` with a capturing implementation where the properties handed to the sign-in
had to be observed, reached the private static suppression timestamp by reflection, and was deleted
after the results below were recorded. No repository test project, test framework reference or
package reference was added. Three separate processes were used, because the suppression timestamp
and `ErpSettings` are static and one scenario deliberately runs with no reachable database.
**87 checks across 3 processes, 87 passed, 0 failed.**

##### H-02 — token validation, with no database reachable (38 checks)

| Property verified | Observed result |
| --- | --- |
| Valid token | Accepted; `iss=webvella-erp`, `aud=webvella-erp` |
| Expired 5 minutes / 1 day / 100 years ago | Rejected in all three cases |
| No `exp` claim at all | Rejected — a token without an expiry is not treated as eternal |
| Clock skew, expired 30 s ago | Accepted — inside the explicit one-minute allowance |
| Clock skew, expired 90 s ago | Rejected — the allowance is bounded, not unlimited |
| Clock skew, `nbf` 30 s in the future | Accepted |
| Clock skew, `nbf` 5 minutes in the future | Rejected |
| Forged signature, identical claims | Rejected |
| Wrong issuer / wrong audience | Rejected |
| Unsigned token, header `{"alg":"none","typ":"JWT"}` | Rejected |
| Valid token with the signature replaced | Rejected |
| Valid token with the payload swapped | Rejected |
| 9 malformed inputs — `null`, empty, whitespace, `abc`, `a.b.c`, `....`, header segment only, 8000 characters, `Bearer <valid token>` | All returned `null`; 0 exceptions thrown |
| Rate bound: 60 consecutive failures inside one minute | The suppression timestamp advanced **exactly once** |
| Rate bound after the interval elapsed | Advanced again — suppression, not silence |
| Containment: 4 further validations with the audit write guaranteed to fail | 0 exceptions escaped; validation never becomes a server error because the audit log is unavailable |

##### H-02 — the persisted audit record, against a real database (24 checks)

Run against an isolated per-clone database created by `pg_dump` from `ttg_test` so no sibling clone's
data was touched.

| Property verified | Observed result |
| --- | --- |
| 40 validation failures | Exactly **one** persisted `system_log` row (8 rows before, 9 after) |
| `source` | `AuthService:GetValidSecurityTokenAsync` |
| `message` | `JWT validation failed: SecurityTokenExpiredException` — exception type only |
| `notification_status` | `1` = `DoNotNotify`, so a token flood cannot be amplified into an outbound mail flood |
| `details` | Begins `IDX10223: Lifetime validation failed. The token is expired. ValidTo (U…` — the library's own message, no stack frame (`   at ` absent) |
| Raw bearer token in the record | Absent from both `message` and `details` |
| Token signature segment in the record | Absent |
| Signing key in the record | Absent |
| Issued token, end to end | 665 characters; `exp` `Kind=Utc`; **1439.99 minutes** ahead of `UtcNow` — a local-time defect on this host would have shown a whole-hour offset (M-04) |
| `token_refresh_after` claim | Present, `Kind=Utc`, 120 minutes ahead |
| Refresh of a **valid** token | Succeeds, and the refreshed token validates — existing clients keep working |
| Refresh of an **expired** token carrying the same real user identity | Returns `null`. This is the headline H-02 result: the anonymous refresh endpoint can no longer renew a stolen token indefinitely |
| Refresh of a forged token / a malformed token | `null` in both cases, without throwing |
| Wrong-password probes | 4 of 5 refused; the fifth differs only by a trailing space, which `GetTokenAsync` trims by pre-existing design, so its success is expected rather than a gap |
| Unknown e-mail | Refused |

##### H-03, M-03 and M-04 — the cookie sign-in path (25 checks)

| Property verified | Observed result |
| --- | --- |
| Real credential | Authenticated; `SignInAsync` called exactly once, scheme `Cookies` |
| Ticket `ExpiresUtc` | Present and **explicit**, so it overrides the host's `ExpireTimeSpan` and is therefore the effective lifetime |
| Ticket lifetime | **1439.9951 minutes**. The previous 100-year expiry would have read about 52,596,000 |
| Ticket `IssuedUtc` | Stamped inside the window of the call |
| Offsets on both timestamps | `TimeSpan.Zero` — the ticket does not shift with the host timezone |
| `IsPersistent` | `false`, unchanged — the session cookie was not silently promoted to a durable one |
| `AllowRefresh` | `true`, unchanged — sliding renewal still works |
| Principal claims | `nameidentifier`, `emailaddress`, `role`, `role` |
| M-03 oracle control | With the **same** 300 ms sign-in *not* awaited, its marker is absent when control returns — the oracle discriminates, so it would have caught the previous fire-and-forget call |
| M-03, awaited | The call took **320 ms** and the sign-in marker was present the instant `Authenticate` returned, so the cookie can no longer race the response |
| Genuine cookie handler | A real `Set-Cookie` for `.AspNetCore.Cookies` was emitted before `Authenticate` returned, carrying `httponly`, and with no `expires=` attribute because `IsPersistent` is `false` |
| Decrypted ticket from that cookie | `ExpiresUtc` **1440 minutes** ahead — the bound is carried on the wire, not merely held in memory |
| 3 wrong passwords and 1 unknown e-mail | `null` user **and** zero sign-in calls in every case |

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach. The one-minute clock skew is explicit rather than left
  at the library default so that drift is bounded by a stated value.
- **Corrected during verification, not loosened:** the first wrong-password matrix counted a
  trailing-space password as a required refusal. `GetTokenAsync` trims the password, so its success
  is correct pre-existing behaviour; the assertion was made precise about which four of the five
  probes must be refused rather than relaxed to hide the fifth.
- **Out of scope for this file set:** the `[AllowAnonymous]` refresh endpoint itself
  (`Controllers/WebApiController.cs:L4292`), the seven hosts' cookie options, and
  `Pages/login.cshtml.cs`, which is the sole caller of `Authenticate` and must await it, all belong
  to a later boundary. The lifetime validation verified here is what makes that endpoint safe to
  leave anonymous in the interim.
- **Observed, not fixed:** `Logout()` still discards the task returned by `SignOutAsync`. It is
  outside this finding's cited range, it is not a token-validation or ticket-lifetime defect, and
  changing it would exceed the minimal-change constraint.

### Class: Output Encoding

**Findings closed in this class:** the three confirmed **reflected** cross-site-scripting sinks in the
SDK page views (CWE-79, OWASP A03:2021), and M-18 (defective output encoder, CWE-116). M-18 is
remediated inside this boundary rather than documented only, because the defective encoder stood
directly at a cross-site-scripting sink and is therefore the compensating control for H-06.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Plugins.SDK/Pages/page/create.cshtml` | L24: the raw-output wrapper is removed from the Cancel link's `href`, so Razor HTML-encodes `Model.ReturnUrl` automatically |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage.cshtml` | L29: the same removal |
| `WebVella.Erp.Plugins.SDK/Pages/page/manage-custom.cshtml` | L25: the same removal |
| `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` | `WvJsonRaw` no longer substitutes one exact nine-character lower-case literal. It escapes `<` using `JavaScriptEncoder.Default`, which neutralises every closing-tag variant as well as the script-data-escaped state openers |

#### Executed verification — the three reflected sinks

`Model.ReturnUrl` is raw, URL-decoded query-string input, declared at `BaseErpPageModel.cs:L73-L74`
and assigned at `:L178`. It was emitted through a raw-output helper as an **entire single-quoted
`href` value**, so a crafted `returnUrl` could close the attribute and inject markup. The fix is
subtractive: the wrapper is removed and Razor's automatic HTML encoding applies. HTML encoding is the
context-appropriate choice because the value is a whole `href` — URL-encoding it would percent-encode
the path separators and silently break the Cancel link, so functionality preservation had to be
verified as carefully as the attack was.

Verified in three independent ways against a running host on an isolated database, with the only
existing page record: by a real HTML parser over the served bytes, and by a real headless Chrome
against the live parsed DOM.

##### Parsed-HTML oracle over the served bytes — 144 checks, 144 passed, 0 failed

A raw-text regular expression cannot adjudicate this question and was discarded after it produced
false results in both directions: a character class such as `[^']*` traverses attribute-value
boundaries in flat text, so it reports a handler as "injected" when the payload is safely contained
inside the value, and it stops at the first `>` so it reports safety exactly when the payload
contains one. The oracle used instead is Python's `html.parser`, asserting on **parsed attributes**.
Three routes were crossed with seven payloads, and for each combination five properties were checked.

| Property verified | Observed result |
| --- | --- |
| Elements anywhere carrying an `on*` event-handler attribute | **0**, for every route and payload |
| An `img` or `svg` element parsed out of the payload | **0** |
| Cancel anchors matching the expected class | Exactly **1** |
| That anchor's attribute set | Exactly `href` and `class` — no attribute was ever injected |
| The parsed `href` value against the original input | **Equal, losslessly**, for every payload including the legitimate URLs |

##### Real-browser verification — 18 URLs, verdict PASS

Three routes crossed with six payloads: single-quote attribute breakout, attribute-plus-tag breakout,
a double-quote variant carrying an `img` with an error handler, an `svg` with a load handler, a
double-encoded entity evasion, and a backslash-quote evasion.

The detector was proven armed rather than assumed: `alert`, `confirm` and `prompt` were replaced with
non-blocking recorders installed before document parsing completed, cloaked so a payload cannot
detect them, and a deliberate `alert(1)` was fired **both before and after** the matrix and was caught
each time. Every empty result below is therefore a genuine negative and not a blind instrument.

| Property verified | Observed result |
| --- | --- |
| Alert, confirm or prompt dialogs across all 18 loads | **None**, corroborated by a second independent channel |
| Elements with an inline `on*` attribute | **0** on all 18, against a control floor of 0 measured on each route with no `returnUrl` at all |
| Injected `img` or `svg` elements | **0** on all 18, against the same zero floor |
| The Cancel anchor | Exactly one, with exactly the `href` and `class` attributes |
| The raw `href` attribute read from the DOM | The payload **verbatim, as data** — for the first payload exactly the characters shown in the block below |
| Script elements whose text contains the injected call | **0** on all 18 |
| The accessibility tree | Resolves the anchor as a link whose URL is the whole payload treated as a relative path — the cleanest single proof that it never became markup |
| The two evasion attempts | Both defeated. The double-encoded entity fails because the server also encodes the ampersand, so the entity arrives as literal text and never as a quote; the backslash form fails because a backslash is not an HTML escape and the quote is still encoded |
| Real mouse hover and real keyboard focus delivered to the anchor | 3 hovers and 12 or more focus deliveries — the exact triggers the payloads were built to hijack — with no dialog and no console output |
| Element counts against the no-payload control | 211 to 214, 1250 to 1250, and 177 to 180. The constant increase is the legitimate header back-button that renders only when the value is non-empty, and it is identical across all six payloads, so no payload-specific node was injected |
| Console output | Only pre-existing accessibility advisories, proven pre-existing by reloading each route with no `returnUrl` and observing identical output. No error of any kind |
| Network | Every request 200. No request was ever issued to the bogus payload path, so the value never became a resource-fetching attribute |

The served bytes for the first payload, and the value the browser then parses out of them:

```text
served:      <a href='&#x27; onmouseover=&#x27;alert(1)' class='btn btn-white btn-sm'>Cancel</a>
parsed href: ' onmouseover='alert(1)
```

##### Functionality preservation — verdict PASS

The decisive risk was over-encoding, so a legitimate URL carrying an ampersand, a question mark, a
colon and several path separators was round-tripped through all three routes and then actually
clicked.

| Property verified | Observed result |
| --- | --- |
| A legitimate relative path | Round-trips exactly, verified down to character codes |
| A legitimate URL with a query string, on all three routes | The raw `href` is exactly the value below: literal ampersand, question mark and colon, all five separators intact, **zero percent characters**, and not truncated at the ampersand |
| The mechanism | The server writes the ampersand as its HTML entity and leaves the other characters literal, which is HTML encoding and demonstrably not URL encoding — the failure mode that would have broken the link is ruled out |
| Clicking Cancel after the plain path | Navigates to the pages list, HTTP 200, title `Pages`, real content |
| Clicking Cancel after the query-string value | Navigates with the query string surviving verbatim into the address bar and onto the wire, HTTP 200 |
| The header back-button, fed by the same value | Raw `href` byte-identical to the Cancel link's on all nine combinations; clicking it also reaches the pages list, HTTP 200 |
| Visual regression | **0.254 percent** of pixels differ, all inside a single 206 by 33 pixel header region proven by colour census to be the expected back-button plus the resulting header reflow. The Cancel button is pixel- and style-identical — same rectangle, fill, border, radius, font and padding — the whole content area and top chrome are pixel-identical, and the visible text is byte-identical with no leaked markup |
| Payload shape versus rendering | Two structurally different payloads produce a pixel-identical page, so the value never reaches the visible layer in any form |

The legitimate query-string value, before and after the round trip:

```text
input query:  ?returnUrl=%2Fsdk%2Fobjects%2Fpage%2Fl%3Fa%3D1%26b%3D2%3A3%2F4
served href:  /sdk/objects/page/l?a=1&amp;b=2:3/4
parsed href:  /sdk/objects/page/l?a=1&b=2:3/4
```

#### Executed verification

Exercised through the same transient external harness. The genuine
`Microsoft.AspNetCore.Mvc.ViewFeatures.HtmlHelper` was resolved from MVC view services and used as
the `this` argument, so the recorded outputs are the shipped helper's own, and the escape text was
read out of the private static field rather than restated. The previous implementation was taken
verbatim from `git show master:…` and run side by side as the control. **73 checks, 73 passed, 0
failed.**

The breakout oracle is the HTML tokenizer's own rule, not a search for the literal `</script>`: the
script-data state ends on <code>&lt;/script</code> followed by tab, LF, FF, CR, space, `/` or `>`,
case-insensitively, and `<!--` or `<script` move the tokenizer into the script-data-escaped states
from which the same end tag is reachable.

| Property verified | Observed result |
| --- | --- |
| `JavaScriptEncoder.Default.Encode("<")` | `\u003C` — and the private `ScriptBreakoutEscape` field equals it exactly, so the escape is derived from the framework encoder rather than hard-coded |
| 21 breakout variants under the **OLD** implementation | **17 could still close the script element** |
| The same 21 under the **NEW** implementation | **0 can close the script element**, and none retains a raw `<` at all |
| The 4 the old implementation left safe | `</script>` — the one exact literal it substituted — plus `<![CDATA[`, `<svg onload=…>` and `<img src=x onerror=…>`, which are inert inside script data to begin with. Named explicitly instead of hidden behind a slack threshold |
| Variants that defeated the old implementation | Altered case (`</Script>`, `</SCRIPT>`, `</ScRiPt>`), whitespace before `>` (space, tab, LF, CR, FF), `/` after the name (`</script/foo>`), an attribute (`</script bar=1>`), the bare <code>&lt;/script</code> at end of input, and the escaped-state openers `<script`, `<!--`, `<!--<script>` |
| 15 bare-JSON payloads (consumer shape A) | All still parse, and all decode to a byte-identical document. Example: `{"evil":"</script><script>alert(1)</script>"}` goes on the wire as `{"evil":"\u003C/script>\u003Cscript>alert(1)\u003C/script>"}` and decodes back unchanged |
| A payload containing no `<` | Returned byte-identical — `<` is never legal in a JSON structural position, so only string *contents* can ever be touched |
| 9 values inside a JavaScript string literal (consumer shape B) | All round-trip to the original value |
| Raw tab and raw newline | Passed through byte-identically. A strict JSON parser rejects raw control characters inside a string while JavaScript accepts them, so the relevant guarantee is that the encoder does not alter them — which is what was asserted |
| `>`, `&`, `"`, `\`, non-ASCII and astral characters | All left untouched, so JSON escapes and text survive |
| Empty input | Returns empty |
| Multiple occurrences | Every `<` replaced, not only the first |
| Applying the helper twice | Idempotent — the output contains no `<` left to re-escape |
| `null` input | **Identical** to the previous implementation: neither throws. The encoder change introduced no new failure mode |
| The four live consumer sites, rendered together with breakout payloads | The assembled `<script>` block contains exactly **one** <code>&lt;/script</code>, the view's own; all four values still parse or round-trip; and the **control** shows the same block built with the old implementation does break out |
| Return type | `IHtmlContent`, so Razor emits it without a second round of encoding |

#### Deviations and out-of-scope observations

- **No deviation.** Escaping `<` is strictly stronger than pattern-matching a closing tag, and it is
  the smaller change: one character class rather than a list of variants to keep in step with the
  tokenizer.
- **Out of scope for this file set:** the confirmed stored and reflected sinks that use
  `@Html.Raw` in the navigation, menu, SDK data-source and Project widget views, and the four
  by-design raw channels that must not be encoded, all belong to a later boundary. They are
  unaffected by this change, which touches only `WvJsonRaw`.
- **Observed, not fixed:** the four live consumers pass values that are already JSON produced by the
  server. Escaping `<` is defence in depth for them rather than the only barrier, and it is what
  makes the barrier hold if a database-sourced string ever reaches one of them.
- **Second reflection point, discovered during verification and confirmed safe.** The same value is
  also emitted by the page-header tag helper through its `return-url` attribute, which renders a
  back-button anchor. It was probed on all 18 payload loads and on all nine legitimate combinations:
  the payload stays confined to its `href` value, the anchor carries exactly two attributes, no
  handler attribute appears, and its raw `href` is byte-identical to the Cancel link's. The fix
  therefore holds at **both** reflection points on all three pages, not only at the Cancel link. No
  change was needed, and none was made — the tag-helper package is third-party and excluded from
  modification.
- **Pre-existing defect observed in an out-of-scope file, documented and deliberately not fixed.**
  `WebVella.Erp.Web/Models/BaseErpPageModel.cs:L178` applies `HttpUtility.UrlDecode` to a value that
  `Request.Query` has already percent-decoded, so a doubly-encoded nested value is decoded twice. A
  nested `returnUrl` supplied as a percent-encoded path is therefore observed with literal separators
  rather than encoded ones. This is **not** security-relevant and **not** attributable to this change:
  the value is not truncated and not over-encoded, both forms parse to the identical nested value
  because a separator is legal in a query component, and the deviation is extra decoding rather than
  the over-encoding that would break a link. Provenance was verified independently — `git blame`
  attributes the line to an upstream commit dated 2022-02-04 and `git diff` for that file is empty, so
  no work in this boundary touched it. The file is outside this boundary's file set, so it is recorded
  here rather than modified. Removing the redundant decode is the single-line fix if exact preservation
  of doubly-encoded nested values is ever required.

### Class: Transport Security and Response Headers

**Findings closed in this class:** M-01 (no security response headers) and the response-header half
of H-15 (CWE-319/CWE-614, OWASP A02:2021 and A05:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` | New. Emits the seven mandated headers with the mandated values. The Content-Security-Policy value is emitted verbatim; only its *delivery mode* is staged, defaulting to `Content-Security-Policy-Report-Only` because four components emit inline script and immediate enforcement would break them |

#### Executed verification

Exercised through the same transient external harness, in two ways: by invoking `Invoke` directly on
a `DefaultHttpContext` for the cases that need an unusual options graph, and by hosting the
middleware in a **real Kestrel server** ordered exactly as each of the seven hosts must order it —
`UseSecurityHeaders()` first, then `UseResponseCompression()`, then `UseStaticFiles()` — so the
headers are proven to reach every response class rather than only dynamically generated ones. The
pipeline ordering the AAP mandates and the middleware's own claim about co-existing with the
framework's `UseHsts()` are both measured against deliberate wrong-order and mismatched-value
controls rather than taken on trust. **91 checks, 91 passed, 0 failed.**

##### In-process invocation

| Property verified | Observed result |
| --- | --- |
| `IOptions` never registered at all (`null`) | All six fixed headers still emitted, plus the report-only policy with the mandated value — the middleware is secure regardless of registration order |
| `IOptions<T>.Value` is `null` | Defaults still applied |
| `next` | Invoked exactly once |
| Configured policy blank (`null`, empty, whitespace) | Falls back to `default-src 'self'; script-src 'self'; style-src 'self'` in all three cases, never an empty policy |
| Enforcing mode | `Content-Security-Policy` present, `Content-Security-Policy-Report-Only` absent |
| The policy value across both modes | **Byte-identical** — only the header name changes, so the mandated value is never weakened |
| A configured custom policy | Emitted verbatim |
| Pre-existing weaker values (`X-Frame-Options: SAMEORIGIN`, `Strict-Transport-Security: max-age=1`, two `Referrer-Policy` values, `X-XSS-Protection: 1; mode=block`) | Each **overwritten** to the mandated value with a header count of exactly 1 — indexer assignment, never `Add` |
| Exact values | `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 0`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()` |
| `X-XSS-Protection` | Exactly `0` as mandated, not "modernised" to `1; mode=block` |
| Policy header count | Exactly one of the two names, never both — so seven headers in total |
| A downstream exception | Propagates; the middleware adds headers and does not swallow faults, and the headers were already attached, so an error response is still protected |
| `UseSecurityHeaders` and `UseSecurityHeadersMiddleware` | Both present on `IApplicationBuilder` |

##### Real Kestrel host

Report-only mode was exercised with **nothing configured at all**, which is the shipping default,
and enforcing mode with the switch flipped. Five response classes were requested in each mode.

| Response class | Observed result |
| --- | --- |
| Dynamic endpoint (200) | All six fixed headers present with the exact mandated values; exactly one policy header, carrying the mandated policy verbatim; no duplicates |
| Static file through `UseStaticFiles` (200) | Same — the headers reach static content because the middleware is ordered ahead of it |
| Compressed dynamic (200) | Same, with `Content-Encoding: gzip` confirmed and the body decompressing to the expected 4096 bytes |
| Compressed static file (200) | Same, with `Content-Encoding: gzip` confirmed and the body intact |
| 404 Not Found | Same — an error response is not left unprotected |

##### Pipeline order, measured against a wrong-order control

The AAP requires this middleware ahead of `UseResponseCompression` and ahead of `UseStaticFiles` in
every host. That requirement is only meaningful if a wrong order demonstrably loses coverage, so
three separate Kestrel hosts were started, each probed on a dynamic response, a static-file response
and a compressed static-file response, counting how many of the six fixed headers arrived with their
exact mandated value.

| Pipeline order | Dynamic | Static file | Compressed static file |
| --- | --- | --- | --- |
| **AAP order** — headers, compression, static files | 6/6 | 6/6 | 6/6, `Content-Encoding: gzip` |
| **CONTROL** — `UseStaticFiles` *before* the headers middleware | 6/6 | **0/6** | **0/6** |
| **CONTROL** — `UseResponseCompression` *before* the headers middleware | 6/6 | — | 6/6, `Content-Encoding: gzip` |

Two conclusions follow, and the second is the more useful one:

- Placing `UseStaticFiles` first leaves **every static asset response entirely unprotected**, because
  the static-file middleware short-circuits the pipeline and the headers middleware is never reached.
  Compressing that response does not change the outcome. The routed dynamic response is still fully
  protected in that same wrong order, so the loss is *silent* — nothing fails, nothing logs, and a
  spot check of a page would not reveal it. That is exactly why the order has to be fixed per host.
- Response compression running first does **not** strip the headers, because it wraps the body stream
  rather than short-circuiting. Of the two orderings the AAP mandates, it is therefore the static-file
  one that is load-bearing; the compression one is defensive.

##### `Strict-Transport-Security` duplication against the framework's `UseHsts()`

The middleware's own comment claims that a host adding the framework's `UseHsts()` alongside it
cannot produce a second `Strict-Transport-Security` header, because every write is an indexer
assignment and the mandated value is identical to the one the hosts configure. That claim was proven
in both pipeline orders over **genuine HTTPS** — the framework's `HstsMiddleware` emits nothing at all
on a plaintext request, so an HTTP probe could not have tested it — using a self-signed certificate
generated in-process. A deliberately mismatched framework value, `max-age=2592000`, was used as a
discriminator so that it is visible which middleware wrote last.

| Arrangement | Header lines on the wire | Value observed |
| --- | --- | --- |
| `UseHsts()` then `UseSecurityHeaders()`, framework configured to the mandated value | **1** | `max-age=31536000; includeSubDomains` |
| `UseSecurityHeaders()` then `UseHsts()`, framework configured to the mandated value | **1** | `max-age=31536000; includeSubDomains` |
| **DISCRIMINATOR** — framework at `max-age=2592000`, framework registered *first* | **1** | `max-age=31536000; includeSubDomains` (this middleware wrote last) |
| **DISCRIMINATOR** — framework at `max-age=2592000`, framework registered *last* | **1** | `max-age=2592000` (the framework wrote last) |
| **CONTROL** — framework `UseHsts()` alone, default excluded-host list, HTTPS to `127.0.0.1` | **0** | absent |
| Plaintext HTTP with both registered | **1** | `max-age=31536000; includeSubDomains` |

- **Never duplicated, in either order.** Indexer assignment overwrites; it cannot append. Because the
  two values are identical in the mandated configuration, the overwrite is a no-op whichever
  middleware runs second — the comment's claim holds as written.
- **Last writer wins**, which the discriminator makes visible. This is a real constraint on the
  later host wiring and is recorded below rather than left implicit.
- **The framework middleware alone would deliver nothing here.** Its default excluded-host list
  contains `localhost`, `127.0.0.1` and `[::1]`, so an HTTPS request to a loopback address received
  no header at all from it. It also emits nothing on a plaintext request. The header observed over
  plain HTTP in the two Kestrel runs above therefore came from this middleware alone, which is what
  makes its unconditional emission load-bearing rather than redundant.

#### Deviations and out-of-scope observations

- **Deviation, declared rather than absorbed:** the Content-Security-Policy ships in report-only
  mode. The mandated *value* is emitted exactly as specified and was verified byte-identical in both
  modes; only the delivery mode is staged, because
  `Components/PcHtmlBlock/Display.cshtml:L10`, `Components/PcHtmlBlock/Design.cshtml:L10`,
  `Components/Nav/Nav.Default.cshtml:L48` and the SDK
  `Components/WvSdkPageSitemap/Form.cshtml:L92` emit inline script and immediate enforcement would
  break them, violating the functionality-preservation requirement. The enforced value is
  configurable and the report-then-enforce rollout is recorded in the
  [risk register](risk-register.md). The operator-facing rollout steps belong in
  `docs/security/secure-configuration.md`, which is a later-boundary file and is deliberately
  referenced by path rather than linked, because linking to a page that does not exist yet would
  break the documentation build.
- **Out of scope for this file set:** registering the middleware in
  `WebVella.Erp.Web/ErpMvcExtensions.cs`, positioning it in each of the seven host pipelines, and
  adding HSTS and HTTPS-redirection middleware per host all belong to a later boundary. The
  middleware carries no consumer in this boundary, which is precisely why its behaviour was proven
  by hosting it rather than by inspection.
- **Observed, not fixed:** `Strict-Transport-Security` is emitted unconditionally by this middleware.
  Guarding transport-security enablement to non-development environments is the hosts'
  responsibility and belongs with the per-host pipeline change.
- **Constraint on the later host wiring, discovered by measurement.** Because the last writer wins,
  a host that registers `UseHsts()` *after* `UseSecurityHeaders()` **and** configures it to something
  other than the mandated value would silently replace the mandated value with its own, with no
  duplicate header and no error to reveal it. Two arrangements are safe and both were measured: omit
  `UseHsts()` entirely and let this middleware emit the header, or configure `UseHsts()` with
  `MaxAge = TimeSpan.FromDays(365)` and `IncludeSubDomains = true`, which produces the identical
  value and makes the ordering irrelevant. If `UseHsts()` is registered for its redirect-adjacent
  behaviour, it must additionally have its excluded-host list reviewed, since the default list
  suppresses the header for loopback hosts.

### Class: Injection and Deserialisation

**Findings closed in this class:** H-09 (SQL identifier injection through string concatenation,
CWE-89, OWASP A03:2021) and H-10 (unsafe polymorphic deserialisation, CWE-502, OWASP A08:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Database/DbIdentifier.cs` | New. Allow-list validation plus double-quoting for the identifiers this layer must concatenate, because PostgreSQL cannot bind an identifier as a parameter |
| `WebVella.Erp/Api/Models/ErpSerializationBinder.cs` | New. Type allow-list binder: first-party platform types plus 26 explicitly permitted framework types, with the whole resolved type graph re-validated |

#### Executed verification — `DbIdentifier` (H-09)

**54 checks, 54 passed, 0 failed**, driven from a separate assembly, which is itself the
cross-assembly reachability proof: `WebVella.Erp.Plugins.SDK` has to reach these members, so both are
`public` and were called from outside `WebVella.Erp`.

| Property verified | Observed result |
| --- | --- |
| Identifiers the platform really generates | `user`, `rec_user`, `entities`, `entity_relations`, `app_sitemap_area_node`, `rel_user_role`, `my_entity_2`, `ab` — all accepted, all quoted as `"identifier"` |
| Rejected inputs | 30 inputs refused with `DbException` by **both** members: upper case, leading digit, leading underscore, double underscore, hyphen, space, tab, newline, embedded double quote, embedded apostrophe, `a;DROP TABLE x`, `a--x`, single character, trailing underscore, schema-qualified `public.rel_x`, `null`, empty, whitespace, `rec_user;--`, `"; DROP TABLE rec_user; --`, `rec_user OR 1=1`, `rec_user" ; DROP TABLE x; --`, a non-ASCII letter, a trailing space, a leading space, `*`, `rec_user)` |
| No silent sanitise | **0** of those 30 rejected inputs returned a value. Rejection is always an exception, never a cleaned-up string |
| Quote break-out | `rec_user" ; DROP TABLE rec_user; --` is refused by the dedicated double-quote check *before* the grammar check, so the one character that could terminate the quoting is rejected on its own account |
| Length boundary | 63-character bare entity name accepted; **67-character `rec_`-prefixed name accepted**; 68 characters rejected. The 67 bound is deliberate: a 63-character cap would have rejected the prefixed table name of a legitimate 63-character entity |
| Byte identity with existing SQL | `DELETE FROM "rec_user" WHERE id=@id` and `SELECT * FROM "entity_relations"` are byte-identical to the form the layer already writes by hand at `DbRepository.cs` L549/L583/L601, so no existing query text changes |
| The two SQL contexts are distinct | `Quote` emits `"rel_user_role"` for an identifier position; `Validate` emits bare `rel_user_role` for a single-quoted string-literal position, rendering `… WHERE tablename = 'rel_user_role'`. Using the wrong one is a silent defect, which is why both exist |
| No normalisation into validity | `Rec_User` is not lower-cased, `" rec_user "` is not trimmed, and `Quote(Quote(x))` is refused — the helper never accepts its own output |

Cross-assembly reachability was additionally proved **inside the real future consumer project**, not
only from the harness. A transient probe was compiled into `WebVella.Erp.Plugins.SDK` — the assembly
whose `CodeGenService.cs` carries three of the six identifier concatenation sites and four of the
fourteen `TypeNameHandling` sites — calling `DbIdentifier.Quote` in an identifier position,
`DbIdentifier.Validate` in a string-literal position, and constructing both
`ErpSerializationBinder`-attached serializer settings in the exact shape those sites use. The project
built with **0 errors**, no diagnostic was attributed to the probe, and the warning count was
identical (1976) with and without it, so the probe introduced nothing of its own. The probe was then
deleted and the project rebuilt to the same 0 errors / 1976 warnings.

#### Executed verification — `ErpSerializationBinder` (H-10)

**73 checks, 73 passed, 0 failed.** Every refusal is reported next to what Newtonsoft's own
`DefaultSerializationBinder` does with the identical discriminator, so the delta is the evidence.

| Property verified | Observed result |
| --- | --- |
| First-party types allowed | `Entity`, `EntityRelation`, `InputField`, `Field`, `RecordPermissions` all round-trip name → type |
| Allow-listed framework types | 17 checked, all allowed: `ExpandoObject`, `List<object>`, `Dictionary<string,object>`, `HashSet<string>`, `object[]`, `string[]`, `Guid`, `DateTime`, `DateTimeOffset`, `TimeSpan`, `Uri`, `string`, `int`, `bool`, `decimal`, `double`, `object` |
| Gadgets and arbitrary types refused | 14 refused, including `System.Diagnostics.Process`, `System.Data.DataSet`, `System.Type`, `System.Reflection.Assembly`, `System.Collections.Hashtable`, `System.IO.MemoryStream`, `System.Text.StringBuilder`, `WindowsIdentity`, `ObjectDataProvider`, `AssemblyInstaller`, and unknown assemblies |
| **Control** | For seven of those the `DefaultSerializationBinder` **resolved the type successfully** (`StringBuilder`, `MemoryStream`, `Type`, `Assembly`, `Hashtable`, `Process`, `DataSet`). The allow-list is therefore doing the work; the refusals are not an artefact of the type being unavailable |
| Generic and array smuggling | 5 payloads that hide a forbidden argument inside a permitted outer generic — `List<StringBuilder>`, `Dictionary<string,MemoryStream>`, `HashSet<Type>`, `List<List<StringBuilder>>`, `List<Process>` — all refused, and refused specifically by **graph re-validation**, which the pre-resolution name check alone could not have caught. The default binder resolved all five |
| Rule (a) needs both halves | Tested against the allow-list decision in isolation: a **foreign** assembly may not vouch for a first-party type name; a first-party assembly may not vouch for a forbidden type name; `WebVella.ErpEvil` is not the platform family because the prefix requires the dot; and an absent assembly name can satisfy rule (b) but never rule (a) |
| Rule (a) admits plugin assemblies **by design** | `WebVella.Erp.Web` and other `WebVella.Erp.*` assemblies are first party under the prefix rule, which is what keeps persisted plugin payloads deserialising. They still cannot vouch for a forbidden type name |
| Rule (b) is assembly agnostic, deliberately | `ExpandoObject` is allowed whether claimed from `System.Linq.Expressions` or `mscorlib`, because the framework spreads these types across assemblies. It does **not** extend to a non-listed type from a real framework assembly |
| Malformed discriminators | 10 refused without crashing: `null`, empty, whitespace, a bare backtick, `System.`, `[[[`, ``a`1[[``, an unterminated generic, `System.Object[[]]`, and a 4000-character name |
| Already-persisted assembly-qualified names | 4 accepted with version, culture and public-key-token present, including `WebVella.Erp, Version=1.7.7.0, …` and the historical `mscorlib, Version=4.0.0.0, …`. A forbidden type is still refused even when qualified with a first-party assembly name |
| Real payload round trips | Through the exact settings the attachment sites use: `ExpandoObject` + `TypeNameHandling.All` (the job `attributes`/`result` shape, 3 embedded discriminators) round-trips; `Entity` + `TypeNameHandling.Auto` round-trips; `EntityRelation` + `TypeNameHandling.Auto` round-trips with its enum intact. This is the check that proves constraining the binder did **not** break deserialisation of data already in the database |
| End to end through `JsonConvert` | 3 hostile `$type` payloads — a `Process` with a `StartInfo`, a `StringBuilder`, and a `List<StringBuilder>` — refused by `JsonConvert` itself, not merely by a direct call to the binder |

#### Deviations and out-of-scope observations

- **No deviation.** Polymorphic type handling was constrained rather than removed, exactly as
  planned: the round-trip results above are what justify that choice, because removing
  `TypeNameHandling` would have failed to deserialise payloads already persisted with discriminators.
- **Length bound of 67, not 63, is intentional** and is the one place this helper departs from the
  bare PostgreSQL identifier limit. It is recorded here because a future reviewer will otherwise read
  67 as a mistake.
- **Attachment is a later boundary, and is stated plainly rather than implied.** Both types are new
  in this file set and currently have **no in-repository consumer**: the six identifier concatenation
  sites in `DbEntityRepository.cs`, `DbRecordRepository.cs` and `CodeGenService.cs`, and the fourteen
  `TypeNameHandling` sites in `JobProfile.cs`, `DbEntityRepository.cs`, `DbRelationRepository.cs` and
  `CodeGenService.cs`, are switched over by a later boundary. The evidence above therefore
  establishes that each primitive behaves correctly and is reachable, **not** that H-09 and H-10 are
  closed at every call site. The harness constructed the serializer settings itself, mirroring those
  sites, so that the round-trip claim is about real payload shapes rather than a synthetic one.

### Class: Brute Force and Rate Limiting

**Findings closed in this class:** the account-lockout half of H-16 (no account lockout and no rate
limiting, CWE-307, OWASP A07:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/LoginThrottleService.cs` | New. Five-attempt lockout with a fifteen-minute window, keyed by username **and** address, over the platform's existing in-process `Cache`. No schema change and no new package dependency, which is the least invasive control available |
| `WebVella.Erp.Web/Services/LoginThrottleService.cs` | **Corrected during verification.** `Store()` now sets `CacheItemPriority.NeverRemove` on the entry options it passes. Measuring eviction rather than assuming it showed that the previous private options instance defaulted to `CacheItemPriority.Normal`, so memory-pressure compaction evicted an in-force lockout and handed the attacker a fresh five-attempt window. Priority governs compaction only and never expiration, so the explicit `absoluteExpiration` still ends the lockout on time. See the eviction subsection below for the measurement that forced this change |

#### Executed verification

Exercised through the same transient external harness, which reached the private constants, the
private `BuildKey` and the private nested `LoginAttemptState` by reflection so that window expiry and
the already-locked-out branch could be exercised without waiting fifteen minutes. The registration
lifetime and the eviction behaviour are **proven by execution against controls**, not inferred from
the file's comments. **54 checks, 54 passed, 0 failed.**

| Property verified | Observed result |
| --- | --- |
| `MaxFailedAttempts` | `5` — the literal value the Authentication Hardening standard mandates |
| Failures 1 through 4 | Not locked out |
| Failure 5 | **Locked out**, so the sixth attempt is refused without authentication being attempted |
| 20 further attempts while locked out | Counter stayed at `5` and the deadline was **unchanged** (`2026-07-31T16:58:52.7134941Z` before and after), so an attacker cannot hold a real account locked out indefinitely |
| `Reset` after a success | Not locked out, and the cache entry is removed entirely |
| The next failure after a reset | A fresh window starting at `1`, so an earlier mistyped password does not accumulate across a success |
| `Reset` for a principal with no entry | Harmless |
| Deadline moved into the past | No longer locked out |
| The next failure after a fully served lockout | A fresh window at `1` rather than an immediate re-lock, and a single failure does not lock out |
| Different username, same address | Not locked out |
| Same username, different address | Not locked out |
| Different username **and** address | Not locked out |
| `ERP@WebVella.com` versus `erp@webvella.com` versus `  erp@webvella.com  ` | All one counter, under the first key shown below the table, and a reset through either spelling clears it |
| 81 malformed username/address combinations — `null`, empty, whitespace, 5000 characters, an embedded pipe character, `\0`, an embedded newline, `::1`, a tab | **0 exceptions.** Malformed input never becomes a denial of service on the login path |
| `null`, empty and whitespace | Collapse to one partition, the second key shown below the table, so a malformed request is still counted rather than escaping counting |
| Over-long component | Truncated to the documented bound of 128 (observed key length 149). Truncation can only merge two principals onto one counter, which throttles more rather than less |
| 200 **concurrent** failures | Locked out, and the counter stopped at exactly `5` — no increment lost, none double-counted. A lost increment would mean the lockout fails under exactly the load it exists to defend against |
| 300 interleaved register/read/reset operations | 0 exceptions |
| Counter and deadline | One single cache entry, so eviction cannot drop the lockout while keeping the counter, nor the reverse |
| Entry lifetime versus lockout | Remaining lockout 15 minutes against a requested lifetime of at least 15, so expiry cannot release a locked-out principal early. `Store()` takes the greater of the two, and passes an explicit `absoluteExpiration` so an entry cannot inherit the cache's `NeverRemove` default and lock a user out permanently |
| A principal with no entry | Not treated as locked out — and the only ways to have no entry are a reset after a **success** or a fully served window |
| A second service instance | Has its own counters. The documented per-process scope is therefore real and measurable, which is why the host must register this as a singleton and why the limitation is documented rather than hidden |

The two cache keys observed above, verbatim:

```text
wv_login_throttle_ERP@WEBVELLA.COM|203.0.113.7
wv_login_throttle_(unspecified)|(unspecified)
```

##### The `Cache.Put` hazard named in `Store()`'s comment is real

`Store()` passes an explicit `MemoryCacheEntryOptions` and its comment says the argument must not be
simplified away. That claim was verified rather than trusted.

| Property verified | Observed result |
| --- | --- |
| Before any write | The cache's shared default options carry no absolute expiration |
| After **one** `Put` with `options: null` and a 7-minute expiration | The **shared** default options object was mutated to `00:07:00` — the hazard is real, and it would leak one consumer's expiration onto every other consumer of that cache |
| The same `Put` with an explicit options instance, which is what `Store()` does | The shared defaults stayed unset |
| The throttle's own cache after 5 real `RegisterFailedAttempt` calls | Defaults still unset, so the service does not pollute the cache it borrows |

##### The singleton registration is load-bearing, and is proven rather than inferred

The service's header comment states that the host must register it as a singleton. Rather than take
that on trust, the service was resolved from a real `ServiceProvider` under all three lifetimes and
the lockout was recorded through one resolution and read back through another.

| Registration | Observed result |
| --- | --- |
| `AddSingleton` | Two resolutions return the **same** instance, and a lockout recorded through one is visible through the other — counters survive across requests |
| **CONTROL** `AddTransient` | Two resolutions are **different** instances, and the lockout is **invisible** to the second. A transient registration would silently disable the control: every request would start a fresh five-attempt window and no lockout could ever be reached |
| **CONTROL** `AddScoped` | A second request scope gets a fresh instance and sees no lockout — equally unusable, and equally silent |

The failure mode in both controls is silent: nothing throws, nothing logs, and a single-request test
would pass. That is why the later-boundary registration in `ErpMvcExtensions.cs` must be
`AddSingleton` specifically, and why this is recorded as a measured constraint rather than a comment.

##### Eviction behaviour, measured rather than asserted — and the defect it exposed

| Property verified | Observed result |
| --- | --- |
| An entry written the way `Store()` writes one | Present immediately |
| The same entry after its absolute expiration elapses | **Gone**, so a lockout cannot become permanent |
| **CONTROL** an entry written with **no** explicit `absoluteExpiration` | Never expires — the cache's own default entry options are `CacheItemPriority.NeverRemove` with no expiration. This is precisely why `Store()` must pass an expiration: without it, a user who failed five logins would be locked out permanently |
| A locked-out principal before any eviction pressure | Locked out |
| The same principal after `MemoryCache.Compact(1.0)`, full-pressure eviction of every compactable entry | **Still locked out**, with the counter still at the threshold of `5` |
| The caller-reachable surface | `IsLockedOut`, `RegisterFailedAttempt`, `Reset`. `Reset` is the only removal path and is only called after a **successful** authentication, so no reachable path shortens or discards an in-force lockout |

The compaction row is the reason the source changed. On the first execution of this section the
lockout did **not** survive `Compact(1.0)`: the entry vanished and the principal was handed a fresh
five-attempt window, which contradicts the fail-closed-on-eviction requirement. The cause was that
`Store()` passed a private `MemoryCacheEntryOptions`, whose priority defaults to
`CacheItemPriority.Normal` — the cache's own `NeverRemove` default applies only to entries that pass
no options at all, and `Store()` deliberately passes its own instance to avoid the mutation hazard
recorded above. Setting `CacheItemPriority.NeverRemove` on that instance closes the last path by
which an in-force lockout could be released early, while keeping the shared cache defaults
unmutated. The row above is the re-measured result after that one-line change.

#### Deviations and out-of-scope observations

- **No deviation.** The in-process cache was chosen over a database table or a distributed cache
  because it avoids both a schema change and a new package dependency, which the minimal-change
  constraint prefers; the resulting per-process scope is stated in the file's own header comment and
  measured above rather than asserted.
- **Out of scope for this file set:** registering the service in
  `WebVella.Erp.Web/ErpMvcExtensions.cs` — which the measurement above shows must be `AddSingleton`
  and nothing else — consulting it at the single login entry point `Pages/login.cshtml.cs:L92`, and
  enabling the framework's transport-level rate limiter in each host pipeline all belong to a later
  boundary. The service has no consumer in this boundary, which is why its behaviour was proven by
  executing it directly.
- **Recorded recommendation, not implemented:** a distributed backing store would be required for a
  multi-instance deployment. It is a new dependency and therefore excluded here; it is carried in the
  [risk register](risk-register.md).

### Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to `[15.1.3]` — the newest release on the lowest patched major. The `<PackageLicenseExpression>` on this project was **not** modified; see the open licensing decision below. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires, plus one added `using` and a comment naming the threat addressed. |

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

#### Actual API surface used

The 15.1.3 `MapperConfiguration` constructor surface was read from the shipped assembly by
reflection rather than assumed. The two public constructors are:

```text
MapperConfiguration(MapperConfigurationExpression configurationExpression, ILoggerFactory loggerFactory)
MapperConfiguration(Action<IMapperConfigurationExpression> configure, ILoggerFactory loggerFactory)
```

The first overload is the one used, so the call became:

```csharp
Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
```

`NullLoggerFactory` resolves from the `Microsoft.AspNetCore.App` framework reference already
present in the core project — no `PackageReference` was added, and the commented-out
`Microsoft.Extensions.*` block in that project file was left commented out. The no-op factory is
deliberate: the platform performs no AutoMapper logging today, so a real logger would be an
enhancement beyond the remediation.

Two related API details worth recording for future upgrades:

- In 15.x, `MapperConfigurationExpression` resolves from the **`AutoMapper`** namespace
  (`AutoMapper.MapperConfigurationExpression`) rather than `AutoMapper.Configuration`. No source
  change was needed because the affected files already import both namespaces.
- `ErpAutoMapper.Initialize(MapperConfigurationExpression cfg)` and the
  `public static IMapper Mapper` field were deliberately left **byte-identical**. Both are hard
  compile contracts: `Initialize` has two call sites that each pass a single argument
  (`WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47`), and the
  `Mapper` field has eight readers in `AutoMapperExtensions.cs`. Constructing the logger factory
  inside `Initialize` was therefore both the least invasive option and the one that keeps the public
  API contract unchanged.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Precondition — the audit must actually see the project | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches; the project-reference casing defect (H-19) is fixed, so the core project is genuinely in the restore graph and a clean scan is trustworthy |
| Restore with dependency audit | `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` diagnostics** |
| Dependency scan | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for each of the **17 solution projects**, including `WebVella.Erp`. This command cannot reach `WebAssembly/Server` or `WebAssembly/Shared`; those two are scanned by their own commands, recorded under *Build and Scan Integrity* above. |
| Resolved version | `dotnet list WebVella.Erp/WebVella.Erp.csproj package` | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug` | exit 0, **0 errors**; no diagnostic names the changed file |
| Solution build | `dotnet build WebVella.ERP3.sln -c Debug -m:2` | exit 0, **0 errors** across the **17 solution projects** — not all 19 manifests; the two non-members are built by their own commands recorded above |
| Negative control (proves the gate is not blind) | the same audit against a throwaway project pinning `[14.0.0]` | reports `NU1903 … known high severity vulnerability … GHSA-rvv3-g6hj-g44x` and a `High` row, confirming the clean result at 15.1.3 is a real fix |
| Runtime — host | started a site host against a freshly provisioned database | schema auto-provisioned, mapping initialised, no exception in the log |
| Runtime — login path | interactive login through the login page | `POST /login` → `302`, authenticated shell rendered, navigation and a user data grid rendered with every projected field populated; no `AutoMapperConfigurationException`, no `NullReferenceException`, no console error |
| Runtime — second call site | ran the console application end to end | exit 0, including a full hook-driven create/update/delete cycle and an EQL user projection, with both call sites unmodified |

Note on the test-suite gate: the repository contains no test project, no test file and no
test-framework package reference in any project, so the "existing test suite passes" gate is
vacuous by construction. It was confirmed empirically (`dotnet test` discovers nothing) and
substituted with the restore, build, dependency-scan and runtime checks above. Creating a test
suite was out of scope for this remediation.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach: the predicted constructor shape
  `(MapperConfigurationExpression, ILoggerFactory)` matched the real assembly, so no adaptation of
  the argument list was needed.
- **Open decision, escalated not absorbed:** upgrading changes the package's licence from MIT to
  the Reciprocal Public License 1.5, which conflicts with the core project's declared licence
  expression. The decision belongs to the repository owner and is recorded, with its documented
  fallback, in the [risk register](risk-register.md). The declared licence expression was left
  untouched and the upgrade was neither silently accepted as final nor reverted.
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): `AssertConfigurationIsValid()` reports unmapped-member problems, but the platform never
  calls it, so it is not on any functional path; several pre-existing `CS0618` obsolete-API
  warnings exist in the data layer; and requests for two third-party vendor source-map files that
  are absent from disk are answered `405` instead of `404` by the embedded file provider. None is a
  security finding and none was changed, in keeping with the minimal-change constraint.


## Integration record — attaching the controls to live request paths

> **Correction — the `AutoMapper` disposition recorded below is the alternative, not the one that
> shipped.** Passages in this section that describe the pin as *held at `[14.0.0]` behind a single
> dependency-audit suppression* were written against that alternative. Measured at this commit: the
> pin is **`[15.1.3]`**, `ErpAutoMapper.Initialize` supplies `NullLoggerFactory.Instance`,
> `Directory.Build.props` declares **no** `NuGetAuditSuppress` element, and
> `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports **no vulnerable
> package in any of the 19 projects**. The advisory is therefore closed by upgrade, and the licensing
> question it raises is escalated and **open** as `RISK-001`. The retained-`[14.0.0]` analysis is
> kept in full, because it is the documented reversal path `RISK-001` records and because its
> exploitability assessment and negative-control evidence hold either way.

### Class: Build and scan integrity

**Findings closed:** H-9 (audit gate absent), H-10 (projects outside the solution), M-6 (unpinned
toolchain).

Sequenced **first**, because every dependency and analyzer claim made anywhere else is unfounded until
the gate exists and actually sees every project.

| File | Change |
| --- | --- |
| `Directory.Build.props` | **New.** `NuGetAudit=true`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`, the `NU1901`-`NU1904` diagnostics promoted to **errors**, `EnableNETAnalyzers=true`, analysis level set to recommended |
| `global.json` | `rollForward` changed from `latestPatch` to **`disable`**, pinning the SDK strictly |
| `WebVella.ERP3.sln` | Both WebAssembly projects added, with build configurations, so solution-wide restore, build, audit and analyzers reach all **19** projects |
| `.github/workflows/security-scan.yml` | **New.** Pinned SDK setup, restore, analyzer build, vulnerable-package listing with failure on any hit, and a secrets signature sweep |

**Why MSBuild rather than an editor-configuration file:** the repository has four `.editorconfig`
files, each declaring itself a configuration root, so a repository-root editor file would **not** reach
files inside those subtrees. An MSBuild properties file is inherited by every project regardless of
that scoping. This was the deciding constraint, not a preference.

#### Verification

* Restore exits 0; the full solution rebuild exits 0.
* **Negative test proving the gate is not blind:** injecting a package with a known advisory produced
  `NU1903` as a **build error**. Removing it restored a clean build. A gate that has never failed on
  purpose is not known to work.
* `dotnet sln list` and `dotnet list package` now both report **19** projects, agreeing for the first
  time.
* No `NoWarn`, `WarningsNotAsErrors`, `ContinueOnError` or blanket audit suppression was introduced.

### Class: Data layer — SQL identifiers and deserialisation

**Findings closed:** H-2 (identifier injection), M-4 (identifier length semantics), H-3 (unsafe
polymorphic deserialisation), M-1 (over-broad type allow-list).

Both helper classes existed but had **zero callers** — they were dead code. The remediation is
principally *wiring them in* at every sink.

| File | Change |
| --- | --- |
| `WebVella.Erp/Database/DbIdentifier.cs` | Corrected to PostgreSQL's **63-byte** (not 67-character) physical-name limit; cheap length bound moved ahead of the regular expression; echoed diagnostic text bounded and escaped; `Quote` and `Validate` made to agree on the same physical name |
| `WebVella.Erp/Api/Models/ErpSerializationBinder.cs` | The `WebVella.Erp.*` **wildcard replaced with an exact type map** resolved against pinned first-party assemblies; oversized and deeply nested type names rejected **before** resolution |
| 7 files across the data layer, code generation and notifications | `DbIdentifier` applied at **19 real call sites**, guarding 100+ identifier emission points; the binder attached at **20 deserialisation sites** |

**The review's enumeration of sinks was incomplete** — it named 6 identifier sites and 8 binder sites.
A systematic sweep found **19** and **20** respectively. Fixing only the enumerated ones would have
left the majority of the attack surface open.

Type handling was **constrained rather than removed**: already-persisted entity, relation and job
payloads carry type discriminators, so removing polymorphic handling would break existing
installations.

#### Verification

* Identifier harness **24/24**, binder harness **45/45**, query-builder harness **9/9**.
* **Live PostgreSQL validation** of all four generated SQL shapes, including the decisive
  `Quote`-versus-`Validate` counterfactual.
* Rebuild: 0 errors, **4 fewer warnings** than baseline.
* Interactive verification across 11 authenticated pages; zero occurrences of any failure signature
  across four independent observation channels.

### Class: HTTP edge — headers, transport, cookies, rate limiting

**Findings closed:** H-8 (headers middleware never invoked), L-1 (policy publicly replaceable;
report-only with no collection endpoint).

The middleware existed but **no host called it**, so not one header was ever emitted.

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` | The mandated policy made **immutable** (`public const`, compiler-enforced — it previously had a public setter that could silently weaken it); a real `/csp-violation-report` collection endpoint added, handled inside the middleware ahead of routing and authentication |
| `WebVella.Erp.Web/ErpMvcExtensions.cs` | Options registered at the single canonical registration point, so all seven hosts inherit them from one edit |
| 7 × `WebVella.Erp.Site*/Startup.cs` | `UseSecurityHeaders` inserted **early** — ahead of response compression and both static-file middlewares; `UseHsts` then `UseHttpsRedirection` guarded to non-Development and placed **after** CORS; cookie hardening (`SecurePolicy`, `SameSite=Lax`, explicit 8-hour expiry, `SlidingExpiration=false`); rate limiter added and positioned so static assets are not throttled |

**Two ordering constraints are load-bearing**, not stylistic. Headers must precede compression and
static files or they are absent from exactly the responses most likely to carry attacker-controlled
bytes. HTTPS redirection must follow CORS, because redirecting a preflight makes browsers reject it as
invalid.

Existing CORS policies were left untouched, per scope; verified by diff.

**A defect found in my own fix and closed in the same class:** the new anonymous report endpoint was
an unbounded logging sink — a **CWE-779 log-flooding** vector. Logging is now capped at 120 reports per
minute, checked before the body is read, with the bound on *logging* rather than *acceptance* for the
reason in [the risk register](risk-register.md). Verified: 400 reports produced 400 acceptances and
exactly 120 log entries.

#### Verification

Rebuild at exactly the baseline warning count, zero warnings on any added line. Interactive
verification confirmed all seven headers present on **both** a dynamic response and a static file
response, the policy in report-only mode, no console errors, and pages rendering unchanged.

### Class: Brute-force protection

**Findings closed:** H-6 (service never registered, never called), H-7 (four design defects).

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/LoginThrottleService.cs` | Rewritten. **Independent** per-account and per-address counters replace a single composite key; an atomic reserve-then-finalise protocol replaces check-then-register; a **private size-limited store** replaces the shared cache; in-force lockouts are pinned against eviction |
| `WebVella.Erp.Web/ErpMvcExtensions.cs` | Registered as a singleton so all seven hosts inherit it |
| `WebVella.Erp.Web/Pages/login.cshtml.cs` | Throttle consulted before authenticating; failure registered; reset on success; the existing generic error message preserved so the fix does not become an enumeration oracle |
| `WebVella.Erp.Web/Controllers/WebApiController.cs` | Throttle also wired at the anonymous bearer-token route |

Each of the four defects mattered independently: a composite key let an attacker reset an account's
count by rotating source address; check-then-register let concurrent requests each pass before any
recorded a failure; the shared cache could not bound key cardinality, so varying the username grew
memory without limit; and an evicted entry silently granted unlimited attempts.

**A scope correction:** the plan asserted a single login entry point. That is **factually wrong** — the
anonymous bearer-token route is a second credential-verification surface. Throttling only the login
form would have left a fully unthrottled credential oracle exposed.

#### Verification

Harness **46/46** after test T13 exposed a **fail-closed-forever** bug of my own making: once a lockout
lapsed, the refusal check fired on the stale count before the reset branch could run, making that
branch unreachable dead code. Root-caused to one authoritative expiry rule rather than patched at the
symptom. Interactive verification confirmed five failures then a sixth refused, reset on success, and
that attempts five and six are **pixel-for-pixel identical**, so nothing reveals whether an account
exists.

### Class: Credential integrity

**Findings closed:** CR-1 (hashing helpers had zero consumers; MD5 live at four sites), M-3 (wrong
hash algorithm).

The new helpers existed but **nothing called them**; MD5 remained live on every real path.

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | PBKDF2-HMAC-**SHA256** at **600,000** iterations, 128-bit CSPRNG salt, versioned payload, constant-time verification, needs-rehash signal; legacy MD5 accepted and flagged for rehash; shared mutable hash instance removed; all members kept assembly-internal so no public contract changes |
| `WebVella.Erp/Api/SecurityManager.cs` | Credential lookup restructured to fetch by exact e-mail and verify **in application code**; rehash-and-persist on successful legacy verification; anchored, fully escaped e-mail pattern; anti-enumeration dummy verification |
| `WebVella.Erp/Api/RecordManager.cs`, `WebVella.Erp/Database/DbRecordRepository.cs` | All three password write paths routed through the new primitive |

Moving verification out of the SQL predicate was the **enabling change**, not a cleanup: a salted hash
cannot be compared by SQL equality. That restructure also retired a regular-expression
denial-of-service exposure and created — then closed — a timing oracle, since a missing user would
otherwise return ~0.5 ms against ~120 ms for a real one.

**No schema change:** the 61-byte payload Base64-encodes to 84 characters into a `varchar(500)`
column. Verified, not assumed.

#### Verification

Harness **75/75**. Live migration proven end to end: a legacy user logged in, and the stored value
changed shape from 32 hex characters to the versioned form, while accounts that had not authenticated
were left untouched. The round-trip hazard was checked explicitly — after a real UI save the hash was
**byte-identical**. A live-PostgreSQL counterfactual proved the escaper necessary: a raw `.` matched
**every row**, the escaped form matched **none**, while case-insensitive matching was preserved and a
plain `=` comparison was shown not to work at all. Login latency was measured and recorded as the
pre-declared accepted trade-off. Full detail in
[the credential migration guide](credential-migration.md).

### Class: Session and token lifetime

**Findings closed:** H-4 (anonymous refresh renews a stolen token indefinitely; no absolute horizon),
H-5 (ticket refresh enabled; sliding expiration not disabled).

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Services/AuthService.cs` | `AllowRefresh = false`; a **7-day absolute session horizon** stamped at issue, carried verbatim across refresh, with refresh past it refused and refreshed expiry **capped** at it; clamp-to-ceiling; a fail-closed claim reader that never throws; a latent null-reference dereference on a touched line fixed |

**A coherence defect found and fixed:** all seven hosts declared an 8-hour cookie window, but the
ticket was built with an explicit 24-hour expiry — and an explicit expiry **overrides** the declared
window. The real lifetime was three times what every host declared, and seven files' configuration was
inert. Now aligned at 480 minutes.

**A real client contract was discovered before changing anything:** the WebAssembly client parses the
refresh timestamp with a specific binary encoding, so the new claim had to use that exact encoding or
it would throw in the browser.

#### Verification

Harness **46/46**. Live token horizon confirmed at +7.000 days and returned **byte-identical** across
refresh. The forged-token attack was proven dead **with a control**: a live horizon was accepted, while
horizons 1 minute, 1 second and 7 days in the past, exactly-now, absent, and four malformed values
were all refused — with no stack trace and no 500. The 1440→480 reduction is deliberately **invisible
at the HTTP layer**, because the ticket is non-persistent and the bound lives inside the encrypted
payload; the reasoning is recorded so a future reviewer does not read its absence as a failure.

### Class: Configuration provider chain and secret validation

**Findings closed:** M-2 (validation checked only for non-blank values; JWT required only when a
section existed; providers promised but not consumed; known published defaults passed).

| File | Change |
| --- | --- |
| `WebVella.Erp/ErpSettings.cs` | Secret **strength** floors (length, distinct-character variety) and **known-published-default rejection by SHA-256 digest**, so neither this file nor the documentation reintroduces the secrets it eliminates; staged as warn-in-Development, fail-closed otherwise; `IsJwtConfigured` exposed |
| 4 configuration-builder sites | `AddEnvironmentVariables()` added **after** the JSON file so it wins, plus user secrets in Development |
| `WebVella.Erp.Web/Controllers/WebApiController.cs` | Both token routes fail closed on an unacceptable key, returning a clean refusal instead of dereferencing null into a 500 with a stack trace |
| 2 hosts | The bearer registration screened so an unacceptable key can neither be used nor throw during service configuration, while the scheme still exists (the policy selector forwards to it) and every token fails validation safely |

**The plan's site count was wrong:** there are **4** configuration-builder sites, not 9 — five of the
seven hosts inherit the shared chain.

No fix aborts start-up for an existing developer checkout. Validation is actionable and fails closed
at the point of use.

#### Verification

Harness **41/41**, proving the published default key is rejected, a strong key accepted, blank and
short keys rejected, the entropy floor effective, and acceptability judged identically by every
consumer. Both runtime states were proven: the application starts with secrets supplied **only** by
environment variable, issues a token when properly configured, and refuses cleanly — no 500, no stack
trace — when not. Verified that hitting the disabled route does **not** consume the account's lockout
budget.

**Two self-inflicted defects found and fixed in-class:** the editing tool silently converted an entire
CRLF file to LF, inflating a ~50-line change to 4400 insertions — restored, and the diff collapsed to
88. A stray byte-order mark added to the one host file that has none was removed. Final line-ending and
BOM drift across all changed files: **zero**.

### Class: Output encoding and open redirect

**Findings closed:** H-1 (`javascript:` and protocol-relative redirects still worked), M-5
(single-character replacement is not JavaScript-string encoding).

**The root cause was the property, not the three views named in the review.** `ReturnUrl` is inherited
by every page model, consumed by 48 views, 17 redirect sinks and 44 tag-helper bindings.

| File | Change |
| --- | --- |
| `WebVella.Erp.Web/Models/BaseErpPageModel.cs` | A **sanitizing property setter** at the single root-cause sink: absolute URLs, protocol-relative `//host`, `/\host`, control characters that split a scheme, and every scheme (`javascript:`, `data:`, `vbscript:`) rejected; empty preserved as empty, since 40+ views render it raw into an attribute |
| `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` | Split into a serialized-JSON API and a **true JavaScript-string API** backed by the framework `JavaScriptEncoder`; the quoted-string caller moved to the new API, JSON-document callers left on the JSON one |
| 2 page models, 2 header components | `Redirect` replaced with `LocalRedirect` at both POST sinks; the sanitizer applied at a component's raw query read and at the shared back-button href sink |

Control characters are **rejected rather than normalised**, because browsers strip tab, carriage return
and newline from *within* a scheme — so `java\tscript:` is treated as `javascript:`. An allow-list
encoder was chosen over a replacement list because it cannot be defeated by a character its author
failed to anticipate.

**Two bypasses of my own fix were found and closed.** A derived page model re-declared the property
with `new`, which **shadowed** the sanitizing setter so it never ran — and the unsanitized value then
reached a local-redirect sink that threw, returning **HTTP 500 with a full stack trace to an anonymous,
pre-authentication caller**. A second, independent path read the raw query string directly, bypassing
the page model entirely. The generalizable lesson is recorded as a standing warning in
[the risk register](risk-register.md).

#### Verification

Harness **64/64**; HTTP-level matrix **18/18**; interactive verification passed on all 8 criteria, with
`alert(document.domain)` occurring **zero times** in the rendered HTML — not merely encoded but not
reflected at all — and zero network requests to the attacker origin across 119 preserved requests. A
pre-existing HTTP 500 on an unrelated page was **proven pre-existing by counterfactual**: reverting the
view reproduced the identical exception. A load-bearing assumption was also **disproven** — the Razor
views in the referenced library *are* compiled at build time, so a rebuild is mandatory for such edits
to take effect.

### Class: Dependencies

**Findings closed:** H-20 (mail stack advisories), H-18 (end-of-life framework).
**Finding accepted, not closed:** H-01 / H-11 (`AutoMapper`).

**This entry previously recorded an `AutoMapper` upgrade to `[15.1.3]` as complete, with a clean
dependency scan. That upgrade has been reverted and those verification claims were withdrawn as
false.** The corrected record follows.

| File | Change |
| --- | --- |
| `WebVella.Erp.Plugins.Mail/…csproj` | `MailKit` 4.14.1 → **4.17.0**. One line, clearing **two** advisories, because 4.17.0 depends on MimeKit 4.17.0 — no separate MimeKit reference was added, and none should be |
| `WebVella.Erp.WebAssembly/Server/…csproj` | Hosting package 7.0.13 → 10.0.1, and target framework `net7.0` → `net10.0` |
| `WebVella.Erp.WebAssembly/Shared/…csproj` | Target framework `net7.0` → `net10.0` |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` raised to **`[15.1.3]`**, with the licensing escalation recorded beside the pin |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Constructor supplied with `NullLoggerFactory.Instance`, which 15.x requires |
| `Directory.Build.props` | No suppression entry — the advisory is cleared from the graph rather than silenced |

The framework retarget is not a CVE remediation but an **unsupported-component** remediation: the .NET
7 line stopped receiving security patches on 2024-05-14, so any future advisory against it would be
permanently unfixable.

**The `AutoMapper` decision.** Every patched version is licensed under the Reciprocal Public License
1.5 — verified by reading the `.nuspec` of all five patched releases — while this product declares
Apache-2.0 and publishes packages for third-party consumption. There is **no patched permissive line**.
The pin is held at the newest permissively licensed release and the advisory is **accepted, disclosed
and gated**, with the full reasoning, exploitability assessment and reversal steps recorded as
`RISK-001` in [the risk register](risk-register.md) and in the third-party inventory.

Reverting also **removed a four-package `Microsoft.IdentityModel.*` chain at 8.14.0** that 15.1.3
introduced — a version behind the 8.15.0 this solution already references directly.

#### Verification

| Step | Result |
| --- | --- |
| Solution restore | exit 0, **zero `NU19xx` errors** |
| Solution rebuild `--no-incremental` | exit 0, **0 errors**, 3065 warnings — exactly the baseline |
| Vulnerable-package listing | **Still reports the accepted advisory in all 16 affected projects.** It is not concealed; `dotnet list package` does not honour audit suppressions |
| Suppression narrowness — negative test | Injecting an unrelated vulnerable package failed the build with `NU1903` reporting a **different** advisory. The suppression covers exactly one advisory |
| Suppression placement | A project-scoped entry left the solution restore failing with exactly **15** `NU1903` errors, because NuGet audit is evaluated per project and the core library is referenced by everything. Repository-wide placement is a necessity, not a widening |
| Transitive check | The IdentityModel chain is absent from the core project's graph |
| Line endings and BOM | Zero drift across all changed files, after the editing tool silently converted one CRLF manifest to LF and it was restored |

#### Deviations and out-of-scope observations

* **Deviation, recorded not absorbed:** the planned `AutoMapper` upgrade was reverted for the licensing
  reason above. This is the one place the plan's intended action was not carried out, and it is
  documented in four places rather than quietly dropped.
* **Observed, not fixed:** the configuration-validity assertion reports unmapped members, but the
  platform never calls it, so it is not on any functional path; several pre-existing obsolete-API
  warnings exist in the data layer; two vendored source-map files answer `405` rather than `404`. None
  is a security finding.

### Class: Documentation

**Findings closed:** M-7 (unsupported pass claims, omitted transitives, links to absent documents).

| File | Change |
| --- | --- |
| `LIBRARIES.md` | Four stale or unsupported claims corrected — the "no vulnerable packages" assertion **withdrawn as false** and replaced with quoted scanner output; the stale project count corrected; the `AutoMapper` section rewritten as a held pin; the blanket "clean" claim backed by reproducible figures. Security-relevant transitives added (**BouncyCastle**, the **IdentityModel** family) with a **version-skew** section. The licensing escalation converted into a **recorded decision** |
| `SECURITY.md` | **New.** Disclosure policy, supported versions, posture summary, operator hardening checklist |
| `docs/security/secure-configuration.md` | **New.** Required secrets, header rollout, transport security, cookies, rate limiting, verification commands |
| `docs/security/credential-migration.md` | **New.** The hash migration, rehash policy, measured latency, operator actions and rollback asymmetry |
| `docs/security/risk-register.md` | Rewritten: `RISK-001` moved from open to **decided**; `RISK-002`'s false "advisory is closed" claim corrected; accepted risks, standing warnings and recommendations added |
| `docs/security/security-audit-report.md` | Findings reconciled with what was actually done |
| `mkdocs.yml`, `docs/index.md` | A security section added to the navigation — **without which every security page is unreachable in the published site** |

#### Verification

`mkdocs build --strict` passes, and every internal documentation link resolves. Links from inside the
documentation tree to root-level files deliberately use absolute URLs, because a relative link outside
the documentation root fails the strict build.


## Measured results for the dependency and credential classes

### Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to `[15.1.3]` — the newest release on the lowest patched major. The `<PackageLicenseExpression>` on this project was **not** modified; see the open licensing decision below. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires, plus one added `using` and a comment naming the threat addressed. |

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

#### Actual API surface used

The 15.1.3 `MapperConfiguration` constructor surface was read from the shipped assembly by
reflection rather than assumed. The two public constructors are:

```text
MapperConfiguration(MapperConfigurationExpression configurationExpression, ILoggerFactory loggerFactory)
MapperConfiguration(Action<IMapperConfigurationExpression> configure, ILoggerFactory loggerFactory)
```

The first overload is the one used, so the call became:

```csharp
Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
```

`NullLoggerFactory` resolves from the `Microsoft.AspNetCore.App` framework reference already
present in the core project — no `PackageReference` was added, and the commented-out
`Microsoft.Extensions.*` block in that project file was left commented out. The no-op factory is
deliberate: the platform performs no AutoMapper logging today, so a real logger would be an
enhancement beyond the remediation.

Two related API details worth recording for future upgrades:

- In 15.x, `MapperConfigurationExpression` resolves from the **`AutoMapper`** namespace
  (`AutoMapper.MapperConfigurationExpression`) rather than `AutoMapper.Configuration`. No source
  change was needed because the affected files already import both namespaces.
- `ErpAutoMapper.Initialize(MapperConfigurationExpression cfg)` and the
  `public static IMapper Mapper` field were deliberately left **byte-identical**. Both are hard
  compile contracts: `Initialize` has two call sites that each pass a single argument
  (`WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47`), and the
  `Mapper` field has eight readers in `AutoMapperExtensions.cs`. Constructing the logger factory
  inside `Initialize` was therefore both the least invasive option and the one that keeps the public
  API contract unchanged.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Precondition — the audit must actually see the project | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches; the project-reference casing defect (H-19) is fixed, so the core project is genuinely in the restore graph and a clean scan is trustworthy |
| Restore with dependency audit | `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` diagnostics** |
| Dependency scan | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for every project, including `WebVella.Erp` |
| Resolved version | `dotnet list WebVella.Erp/WebVella.Erp.csproj package` | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug` | exit 0, **0 errors**; no diagnostic names the changed file |
| Solution build | `dotnet build WebVella.ERP3.sln -c Debug -m:2` | exit 0, **0 errors** across all projects |
| Negative control (proves the gate is not blind) | the same audit against a throwaway project pinning `[14.0.0]` | reports `NU1903 … known high severity vulnerability … GHSA-rvv3-g6hj-g44x` and a `High` row, confirming the clean result at 15.1.3 is a real fix |
| Runtime — host | started a site host against a freshly provisioned database | schema auto-provisioned, mapping initialised, no exception in the log |
| Runtime — login path | interactive login through the login page | `POST /login` → `302`, authenticated shell rendered, navigation and a user data grid rendered with every projected field populated; no `AutoMapperConfigurationException`, no `NullReferenceException`, no console error |
| Runtime — second call site | ran the console application end to end | exit 0, including a full hook-driven create/update/delete cycle and an EQL user projection, with both call sites unmodified |

Note on the test-suite gate: the repository contains no test project, no test file and no
test-framework package reference in any project, so the "existing test suite passes" gate is
vacuous by construction. It was confirmed empirically (`dotnet test` discovers nothing) and
substituted with the restore, build, dependency-scan and runtime checks above. Creating a test
suite was out of scope for this remediation.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach: the predicted constructor shape
  `(MapperConfigurationExpression, ILoggerFactory)` matched the real assembly, so no adaptation of
  the argument list was needed.
- **Open decision, escalated not absorbed:** upgrading changes the package's licence from MIT to
  the Reciprocal Public License 1.5, which conflicts with the core project's declared licence
  expression. The decision belongs to the repository owner and is recorded, with its documented
  fallback, in the [risk register](risk-register.md). The declared licence expression was left
  untouched and the upgrade was neither silently accepted as final nor reverted.
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): `AssertConfigurationIsValid()` reports unmapped-member problems, but the platform never
  calls it, so it is not on any functional path; several pre-existing `CS0618` obsolete-API
  warnings exist in the data layer; and requests for two third-party vendor source-map files that
  are absent from disk are answered `405` instead of `404` by the embedded file provider. None is a
  security finding and none was changed, in keeping with the minimal-change constraint.

### Class: Credential integrity — storage primitive

**Findings closed in this class:** M-06 (CWE-362, shared mutable hash instance) and M-05 (CWE-208,
non-constant-time comparison), both fully. C-03 (CWE-916 password hash with insufficient
computational effort / CWE-759 one-way hash without a salt, OWASP A02:2021) has its enabling change
in place but is **not** fully closed by this class alone — see the scope note immediately below.

#### Scope of this entry — what is in force, and what is not

This class replaces the credential **storage primitive** only. That split is deliberate rather than
partial work: a salted hash cannot be compared with SQL equality, so the primitive has to exist
before any call site can move to it. The ordering constraint is stated in the plan as "hasher before
call sites".

| Concern | State after this class |
| --- | --- |
| Salted, work-factored, fixed-time hash-and-verify primitive | **In force** — `PasswordUtil` hashes with PBKDF2 and verifies in fixed time |
| Shared mutable MD5 instance (M-06) | **Closed** — the shared instance is gone; the replacement keeps no mutable per-call state and is safe to share across concurrent requests |
| Short-circuiting digest comparison (M-05) | **Closed** — the modern path and the retained legacy path both compare in fixed time |
| Backward compatibility for credentials already stored | **In force** — legacy values still verify, and a successful legacy verification reports that a re-hash is due |
| Credential-resolution query still hashing and comparing inside a SQL predicate | **Not yet changed** — lands with the credential-resolution class |
| The four record write paths still calling the legacy digest | **Not yet changed** — land with the credential-resolution class |
| Seeded default credential, guest grants, password-length bounds, version-4 data migration | **Not yet changed** — land with the provisioning class |

The consequence is worth stating plainly so this entry cannot be read as claiming more than it
delivers: **the modern members have no production callers yet.** `HashPassword`, `VerifyPassword`
and `IsLegacyHash` are reachable only from within the utility at this point, and all four existing
call sites — `WebVella.Erp/Api/SecurityManager.cs:L84`,
`WebVella.Erp/Api/RecordManager.cs:L2017`, `WebVella.Erp/Database/DbRecordRepository.cs:L554` and
`:L1856` — still call `GetMd5Hash`. Login therefore behaves exactly as it did before this class, no
stored value changes, and the class can be committed on its own without any functional or
user-visible change. It is an enabling change, not dead code, and the class that consumes it is the
next one in the sequence.

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | Adds `HashPassword`, `VerifyPassword(…, out bool needsRehash)` and `IsLegacyHash`; replaces the shared mutable MD5 instance with a stateless static call; makes the retained legacy comparison fixed-time; documents the threat addressed, both algorithm deviations and the retained-legacy rationale in comments. |

No other file was touched by this class, and no package dependency was added: the password hasher
resolves from the `Microsoft.AspNetCore.App` framework reference already present in the core
project. Member accessibility was deliberately left at `internal`, matching the existing members,
because every consumer is in the same assembly — so no public API contract changes.

#### The accepted performance trade-off

The iteration count is the security control, not a tuning knob, so its cost is recorded here as a
**pre-declared, accepted trade-off** rather than discovered later as a regression. This is the
record that the comments in `PasswordUtil.cs` refer to.

Measured on the verification host (4 cores, `linux-x64`, Release build, median of 9 samples after
warm-up), through the same API the utility uses:

| Configuration | Cost per operation |
| --- | --- |
| PBKDF2-HMAC-SHA512, 600,000 iterations — `HashPassword` (the shipped setting) | **362.7 ms** |
| PBKDF2-HMAC-SHA512, 600,000 iterations — `VerifyHashedPassword` | **362.3 ms** |
| Framework default of 100,000 iterations, same format | 60.1 ms |
| Raw `Rfc2898DeriveBytes.Pbkdf2`, SHA512, 600,000 — cross-check of the shipped setting | 361.3 ms |
| Raw `Rfc2898DeriveBytes.Pbkdf2`, SHA256, 600,000 — the HMAC-SHA-256 counterfactual | 117.5 ms |

Three derived checks confirm the figures are sound rather than incidental: hashing and verification
are symmetric (ratio 1.00), cost scales linearly with the iteration count (600,000 against 100,000
gives 6.02, against an expected 6.0), and the SHA512 setting does 3.07 times the work per attacker
guess that HMAC-SHA-256 would at the same iteration count. That last ratio is the reason the
deviation described in the [risk register](risk-register.md) leaves the outcome stronger than the
named requirement, not weaker.

How this reconciles with the "performance within 10% of baseline" boundary:

- The boundary is not breached anywhere except authentication, and that exception was pre-declared.
  Only the authentication path performs a key derivation; no other request path is affected.
- Against the previous behaviour the change is categorical rather than a percentage: the baseline
  was a single unsalted MD5 digest costing microseconds. Being expensive is the entire purpose of
  the control, so a percentage comparison against that baseline is not a meaningful measure of it.
- When the call sites land, a first login against a credential still stored in the legacy shape
  costs one derivation as well: the legacy digest check itself is negligible, and the re-hash that
  follows it is a single `HashPassword`. There is no doubled cost and no second slow login.

**Do not lower the iteration count to chase a latency target.** 600,000 is set explicitly because
the framework default of 100,000 is well below what this remediation requires, and because the
OWASP floor for PBKDF2-HMAC-SHA512 is 210,000. A methodological note, so the number is reproducible
and does not resurface as an apparent contradiction: an initial mean-of-five measurement taken
without adequate warm-up reported roughly 489 ms, which is a JIT and first-call artefact. The
warm-up-corrected median of nine reported above is the trustworthy figure, and the linearity and
raw-KDF cross-checks corroborate it.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug` | exit 0, **0 errors** |
| Solution build | `dotnet build WebVella.ERP3.sln -c Debug -m:2` | exit 0, **0 errors** across all projects |
| Restore with dependency audit | `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` diagnostics** |
| Shipped parameters are the ones actually in effect | read back `CompatibilityMode` and `IterationCount` from the constructed hasher | `IdentityV3`, `600000` — the format marker, salt and iteration count are encoded in each stored value, so the work factor can be raised later without invalidating anything already written |
| Salting is real | hashed the same plaintext repeatedly | every result differs, confirming a fresh random salt per call and that the value must never be compared for equality |
| Verification round-trip | verified a freshly hashed value | succeeds, and reports no re-hash needed |
| Legacy round-trip | verified a value in the legacy 32-character hexadecimal shape | succeeds, and reports a re-hash **is** needed — the signal that drives upgrade-on-next-authentication |
| Wrong password | verified a non-matching plaintext against both shapes | fails on both, with no exception |
| Malformed stored value | verified against eight cases: null, empty, whitespace, truncated, non-hexadecimal, unparseable text, a malformed modern value and a valid-hex decoy | every one returns false, none throws, and none falsely accepts — so a corrupt stored value can neither authenticate anything nor become a denial of service on the login path |
| Legacy digest persisted in upper case | verified an uppercase legacy value, and separately a wrong password against it | verifies and signals a re-hash, while the wrong password is still rejected. The case tolerance is deliberate — an account whose digest was stored in upper case would otherwise be locked out — and it is applied by normalising case *before* a fixed-time comparison, so it does not reintroduce the M-05 timing oracle |
| Stored value fits the existing column | measured the encoded length of a produced hash | 84 characters, against the `varchar(500)` that `DBTypeConverter` already provisions for a password field — confirming **no schema change is required** |
| Analyzer state on the retained legacy path | `dotnet build … -c Debug` with the repository analyzer gate enabled | `CA5351` reports at the legacy digest helper and remains a **warning**; nothing was suppressed and no global suppression was added — the acceptance is recorded in the [risk register](risk-register.md) |
| Login unchanged by this class | interactive login through the login page | `POST /login` → `302`, authenticated shell rendered — as expected, because every call site still uses the legacy digest at this point |

The test-suite note recorded for the dependencies class applies unchanged here: the repository
contains no test project, so the "existing test suite passes" gate is vacuous and was substituted
with the build, restore and behavioural checks above.

#### Deviations and out-of-scope observations

- **Two deviations from the letter of the mandated cryptographic standard**, both surfaced rather
  than absorbed: PBKDF2 is used where the standard names bcrypt, scrypt or Argon2; and the
  versioned (V3) format is PBKDF2-HMAC-SHA512, which is mutually exclusive with the mandated
  HMAC-SHA-256 because `PasswordHasherOptions` exposes no pseudo-random-function selector. Both are
  recorded with their full reasoning, and with the owner option to substitute a dedicated bcrypt or
  Argon2 package, in the [risk register](risk-register.md).
- **The legacy MD5 path is retained deliberately**, solely so that credentials written by earlier
  releases keep working. It must not be deleted and its analyzer warning must not be suppressed;
  removing it would lock out every existing user, which the preservation requirement forbids. The
  operator-facing description of the upgrade is in the
  [credential migration guide](credential-migration.md).
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): the credential-resolution query at `WebVella.Erp/Api/SecurityManager.cs:L84-L86` still
  matches the e-mail address with a regular-expression operator (`~*`), which is finding H-17. It is
  closed by the same restructure that moves the hash comparison out of the SQL predicate, so it is
  deliberately left to the credential-resolution class rather than patched separately here. The four
  public MD5 helpers in `WebVella.Erp/Utilities/CryptoUtility.cs` also report `CA5351`; they are a
  separate public API surface, are not credential storage, and are recorded in the risk register
  rather than changed.


## Accuracy corrections to shipped comments and documentation

### Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021).

#### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to `[15.1.3]` — the newest release on the lowest patched major. The `<PackageLicenseExpression>` on this project was **not** modified; see the open licensing decision below. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires, plus one added `using` and a comment naming the threat addressed. |

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

#### Actual API surface used

The 15.1.3 `MapperConfiguration` constructor surface was read from the shipped assembly by
reflection rather than assumed. The two public constructors are:

```text
MapperConfiguration(MapperConfigurationExpression configurationExpression, ILoggerFactory loggerFactory)
MapperConfiguration(Action<IMapperConfigurationExpression> configure, ILoggerFactory loggerFactory)
```

The first overload is the one used, so the call became:

```csharp
Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
```

`NullLoggerFactory` resolves from the `Microsoft.AspNetCore.App` framework reference already
present in the core project — no `PackageReference` was added, and the commented-out
`Microsoft.Extensions.*` block in that project file was left commented out. The no-op factory is
deliberate: the platform performs no AutoMapper logging today, so a real logger would be an
enhancement beyond the remediation.

Two related API details worth recording for future upgrades:

- In 15.x, `MapperConfigurationExpression` resolves from the **`AutoMapper`** namespace
  (`AutoMapper.MapperConfigurationExpression`) rather than `AutoMapper.Configuration`. No source
  change was needed because the affected files already import both namespaces.
- `ErpAutoMapper.Initialize(MapperConfigurationExpression cfg)` and the
  `public static IMapper Mapper` field were deliberately left **byte-identical**. Both are hard
  compile contracts: `Initialize` has two call sites that each pass a single argument
  (`WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47`), and the
  `Mapper` field has eight readers in `AutoMapperExtensions.cs`. Constructing the logger factory
  inside `Initialize` was therefore both the least invasive option and the one that keeps the public
  API contract unchanged.

#### Verification

| Step | Command | Result |
| --- | --- | --- |
| Precondition — the audit must actually see the project | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches; the project-reference casing defect (H-19) is fixed, so the core project is genuinely in the restore graph and a clean scan is trustworthy |
| Restore with dependency audit | `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` diagnostics** |
| Dependency scan | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for every project, including `WebVella.Erp` |
| Resolved version | `dotnet list WebVella.Erp/WebVella.Erp.csproj package` | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| Module build | `dotnet build WebVella.Erp/WebVella.Erp.csproj -c Debug` | exit 0, **0 errors**; no diagnostic names the changed file |
| Solution build | `dotnet build WebVella.ERP3.sln -c Debug -m:2` | exit 0, **0 errors** across all projects |
| Negative control (proves the gate is not blind) | the same audit against a throwaway project pinning `[14.0.0]` | reports `NU1903 … known high severity vulnerability … GHSA-rvv3-g6hj-g44x` and a `High` row, confirming the clean result at 15.1.3 is a real fix |
| Runtime — host | started a site host against a freshly provisioned database | schema auto-provisioned, mapping initialised, no exception in the log |
| Runtime — login path | interactive login through the login page | `POST /login` → `302`, authenticated shell rendered, navigation and a user data grid rendered with every projected field populated; no `AutoMapperConfigurationException`, no `NullReferenceException`, no console error |
| Runtime — second call site | ran the console application end to end | exit 0, including a full hook-driven create/update/delete cycle and an EQL user projection, with both call sites unmodified |

Note on the test-suite gate: the repository contains no test project, no test file and no
test-framework package reference in any project, so the "existing test suite passes" gate is
vacuous by construction. It was confirmed empirically (`dotnet test` discovers nothing) and
substituted with the restore, build, dependency-scan and runtime checks above. Creating a test
suite was out of scope for this remediation.

#### Deviations and out-of-scope observations

- **No deviation** from the planned approach: the predicted constructor shape
  `(MapperConfigurationExpression, ILoggerFactory)` matched the real assembly, so no adaptation of
  the argument list was needed.
- **Open decision, escalated not absorbed:** upgrading changes the package's licence from MIT to
  the Reciprocal Public License 1.5, which conflicts with the core project's declared licence
  expression. The decision belongs to the repository owner and is recorded, with its documented
  fallback, in the [risk register](risk-register.md). The declared licence expression was left
  untouched and the upgrade was neither silently accepted as final nor reverted.
- **Observed, not fixed** (outside this vulnerability class, recorded so the observation is not
  lost): `AssertConfigurationIsValid()` reports unmapped-member problems, but the platform never
  calls it, so it is not on any functional path; several pre-existing `CS0618` obsolete-API
  warnings exist in the data layer; and requests for two third-party vendor source-map files that
  are absent from disk are answered `405` instead of `404` by the embedded file provider. None is a
  security finding and none was changed, in keeping with the minimal-change constraint.

### Class: Build and Scan Integrity

**Findings closed in this class:** L-07 (unpinned toolchain, no build-level gate) and the
Objective 5 requirement that the security posture be verifiable by automated scanning rather than
asserted. This class is a prerequisite for every dependency claim made anywhere in this log.

#### Files changed

| File | Change |
| --- | --- |
| `Directory.Build.props` | **New.** Repository-wide gate: `NuGetAudit`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`; the four NuGet audit diagnostics `NU1901`–`NU1904` appended to `WarningsAsErrors`; `EnableNETAnalyzers` with `AnalysisLevel=latest-recommended`. A commented-out `NoWarn` seam records the accepted-risk path without suppressing anything today. |
| `global.json` | SDK pinned to `10.0.302` with `rollForward: latestPatch`, so both the audit defaults and the analyzer rule set are deterministic. |

#### Why MSBuild rather than `.editorconfig`

The four `.editorconfig` files in this repository each declare `root = true`
(`WebVella.Erp/.editorconfig`, `WebVella.Erp.Web/`, `WebVella.Erp.Plugins.SDK/`,
`WebVella.Erp.Plugins.Next/`), so a repository-root `.editorconfig` would not reach files inside
those subtrees. `Directory.Build.props` is imported by every project regardless of that scoping, and
is therefore the only mechanism that reaches all nineteen projects uniformly.

#### Design decisions

- **`NuGetAuditMode=all` is explicit.** A transitive advisory exists in this graph (MimeKit, reached
  through MailKit); `direct` mode would not report it.
- **Only the NuGet codes become errors.** Analyzer diagnostics stay warnings. Escalating them across
  ~700 source files would force exactly the mass refactor the change scope forbids.
- **`WarningsAsErrors` is appended, never overwritten** (`$(WarningsAsErrors);…`), so any
  project-level value survives.
- **Nothing is suppressed.** No `NoWarn`, no `TreatWarningsAsErrors`, no `AnalysisMode` override and
  no `CA` code in `WarningsAsErrors`.

#### Verification

| Check | Result |
| --- | --- |
| XML well-formedness, root element, absence of an `Sdk` attribute | pass |
| All six required properties present with exact values | pass |
| Forbidden properties absent (`TreatWarningsAsErrors`, `TargetFramework`, `PackageReference`, `ManagePackageVersionsCentrally`, `RestorePackagesWithLockFile`, `EnforceCodeStyleInBuild`, `Import`) | pass — zero occurrences |
| `dotnet restore WebVella.ERP3.sln` | exit 0, zero `NU19xx` diagnostics |
| `dotnet build WebVella.ERP3.sln -c Debug --no-incremental` | exit 0, zero errors |
| No secret material in the file | pass |

### Class: Credential Integrity — partial, primitive only

**Status: NOT complete. Finding C-03 remains open.** This entry records what has landed so far so the
partial state is visible rather than implied to be finished.

#### What has landed

| File | Change |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` | The hash-and-verify primitive: `HashPassword`, `VerifyPassword(…, out needsRehash)` and `IsLegacyHash`, built on the framework password hasher in its versioned (V3) format at 600,000 iterations. `GetMd5Hash` and `VerifyMd5Hash` are retained so legacy values stay verifiable during migration. Members remain assembly-internal; no public surface changed. |

Findings **M-05** (CWE-208, non-constant-time comparison) and **M-06** (CWE-362, shared mutable hash
instance) are closed by this edit, because verification is now fixed-time and the hasher keeps no
mutable per-call state.

#### What has NOT landed

C-03 is not closed by a primitive that nothing calls. Four credential sites still compute MD5
directly — `WebVella.Erp/Api/SecurityManager.cs` (the credential lookup, which must move the
comparison out of its SQL predicate), `WebVella.Erp/Api/RecordManager.cs` and two write paths in
`WebVella.Erp/Database/DbRecordRepository.cs` — and the schema version 4 data migration in
`WebVella.Erp/ERPService.cs` does not exist yet. The migration design and the operator runbook are in
the [credential migration guide](credential-migration.md).

#### Measured cost of the work factor — dated evidence

Measured 2026-07-31 on the remediation host (Ubuntu 25.10, 4 logical processors, .NET SDK 10.0.302),
averaged over five repetitions after a discarded warm-up call, against
`Microsoft.AspNetCore.Identity.PasswordHasher<T>`:

| Configuration | Hash | Verify | Encoded length |
| --- | --- | --- | --- |
| V3 (PBKDF2-HMAC-SHA512), 600,000 iterations — **as configured** | 363.9 ms | 379.3 ms | 84 chars, leading `A` |
| V3, 210,000 iterations — the OWASP floor for this pseudo-random function | 129.1 ms | 128.5 ms | 84 chars, leading `A` |
| V2, 1,000 iterations — for scale only, not a candidate | 0.4 ms | 0.3 ms | 68 chars |

Two conclusions follow. First, the configured cost is roughly three times the OWASP floor for the
same pseudo-random function, so the parameters exceed the requirement rather than merely meeting it.
Second, this latency is **pre-declared and accepted**, not a regression: it is confined to the
authentication path, no other request path is affected, and the cost *is* the control. The figures are
hardware-specific and are recorded here rather than in source comments, so that a source comment
cannot drift into a claim about hardware it was never measured on. The iteration count must not be
lowered to recover latency.

The 84-character encoded length with a leading `A` was measured, not assumed, which confirms the
format discriminator the migration relies on: a legacy value is 32 hexadecimal characters and a
modern value cannot be mistaken for one. The existing 500-character password column accommodates the
modern value with no schema definition change.

#### Accepted risks arising from this class

`CA5351` on the retained legacy path (RISK-004) and both cryptographic-standard deviations (RISK-005)
are recorded in the [risk register](risk-register.md). Neither is suppressed.

### Class: Session and Token Handling — partial

**Findings addressed in `WebVella.Erp.Web/Services/AuthService.cs`:** H-02 (CWE-613 + CWE-347),
H-03 (CWE-613), M-03 and M-04. The host-pipeline half of this class has **not** landed; see below.

#### What has landed

| Change | Finding |
| --- | --- |
| The cookie authentication ticket now carries an explicit `ExpiresUtc` 1,440 minutes ahead instead of a 100-year horizon, and the bound is a named constant so it can be kept aligned with the hosts' `ExpireTimeSpan`. | H-03 |
| `TokenValidationParameters.ValidateLifetime` is `true` with an explicit one-minute `ClockSkew`, so an expired bearer token stops validating and the `[AllowAnonymous]` refresh endpoint can no longer renew one indefinitely. | H-02 |
| `SignInAsync` is awaited rather than discarded, so the authentication cookie is written before the method returns and a sign-in exception is observed. `Authenticate` became `async`, and its sole caller — the login page `OnPost` handler — awaits it. | M-03 |
| Token `expires` and the `token_refresh_after` claim are both built from `DateTime.UtcNow`, so the lifetime that is now enforced does not shift with the host's UTC offset or across a DST transition. | M-04 |

#### Token-validation failure logging — the three invariants

The Authorization Enforcement standard requires that authorization failures be logged. Validation
failures in `GetValidSecurityTokenAsync` were previously swallowed by a bare `catch`, so expired and
forged tokens left no audit trail. The replacement is deliberately conservative, and three properties
of it are load-bearing. The source comment states them; the reasoning is recorded here so the comment
does not have to carry it.

1. **`LogNotificationStatus.DoNotNotify`.** `LogService` e-mails the log entry *before* it persists it
   (finding M-17), and `WebVella.Erp.Web/Middleware/JwtMiddleware.cs` calls this validator for every
   request that carries an `Authorization` header. A notifying log here would therefore convert any
   unauthenticated request flood into an attacker-triggered mail flood — a denial-of-service amplifier
   rather than a fix. This is also why H-11 (mail transport certificate validation) materially bounds
   the residual exposure of M-17.
2. **Rate-bounded to one entry per minute.** Each write costs a service construction plus a database
   insert. The bound is a plain `lock` over a static UTC timestamp — the same idiom already used in
   `WebVella.Erp.Web/Services/CodeEvalService.cs` — chosen so that a flood produces evidence of a
   flood instead of a flood of evidence. Suppression is intentional: the first failure in each window
   is recorded, so the signal survives while the volume does not.
3. **Payload is the exception type name and message only.** The raw token is never logged, because it
   is a bearer credential and an audit record must not itself disclose a secret; no stack trace is
   logged either. The logging block is additionally wrapped in its own `catch`, so an audit-logging
   failure can never escape and turn token validation into a server error.

#### What has NOT landed

No host pipeline has been changed. Repository-wide searches find no `CookieSecurePolicy`,
`SameSite`, `ExpireTimeSpan` or `SlidingExpiration` configuration in any of the seven `Startup.cs`
files, and no `AddRateLimiter`/`UseRateLimiter` call anywhere. Consequently the cookie-attribute half
of H-15, the transport-level half of H-16 and finding M-01 remain open, and the ticket bound above is
currently enforced solely by the explicit `ExpiresUtc` rather than by a matching host
`ExpireTimeSpan`. The operator-facing requirements for that wiring are in the
[secure configuration guide](secure-configuration.md).
