# Third-party libraries

This is the third-party dependency inventory referenced from the `### Third party libraries` section of [README](https://github.com/WebVella/WebVella-ERP/blob/master/README.md). It lists every library the platform actually builds against, with the version in use, the project that declares it, what it is used for, and its licence.

The inventory was produced by parsing **all 19 project manifests in the repository with XML comments stripped first**, so that commented-out entries could never be mistaken for live references. That distinction matters enough to be called out twice in this document: 15 `PackageReference` entries in this repository sit inside XML comments and are therefore absent from the build graph. They are listed separately, under *Commented-out package references*, and must not be read as dependencies of this product.

Scope and currency:

* **As of 2026-07-31**, reflecting the repository state after the OWASP Top 10 (2021) security audit and remediation. Four dependency versions changed as part of that work; every changed row is marked in the table below and explained under *Security-driven dependency changes*.
* **In scope:** NuGet package references (direct and the one transitive package worth naming), the shared framework reference, and committed native binaries.
* **Out of scope:** browser-side assets. The repository contains 188 `.js` and 5 `.css` files and no `libman.json` or `package.json`, so client libraries are vendored or CDN-loaded rather than version-managed. One CDN-loaded library carries no integrity attribute; that is recorded as finding M-15 in [the security audit report](docs/security/security-audit-report.md) rather than here, because it is not a managed dependency.
* This document is also the evidence base for one unresolved licensing question. See *Licensing escalation: AutoMapper*.

## How to reproduce this inventory

Every claim below is meant to be falsifiable. From the repository root:

```bash
# 1. Restore the whole solution first. Nothing downstream is trustworthy without this.
dotnet restore WebVella.ERP3.sln

# 2. Direct and transitive packages, per project.
dotnet list WebVella.ERP3.sln package --include-transitive

# 3. Advisory check, including transitive dependencies.
dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive

# 4. Raw manifest sweep. Note that this form does NOT strip XML comments,
#    so it returns commented-out entries too - compare against the two
#    tables in this document rather than treating its output as the live set.
grep -rhno 'PackageReference Include="[^"]*" Version="[^"]*"' --include=*.csproj .
```

Two preconditions decide whether the output of steps 2 and 3 means anything at all.

* **The project-reference path casing must be correct.** Until finding H-19 was fixed, 15 project references spelled the core project's folder as `WebVella.ERP` while the folder on disk is `WebVella.Erp`. On a case-sensitive filesystem the solution restore failed outright, and the core project - which owned the graph's only High-severity advisory - was silently absent from the audit. Any "clean" dependency-scan result obtained before that fix was worthless. The casing is corrected in the solution file and all 14 affected project files.
* **The solution does not contain every project.** `dotnet sln WebVella.ERP3.sln list` returns **17 of the 19** projects: `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` are not solution members. Solution-wide commands therefore skip them, and they must be listed explicitly:

```bash
dotnet list WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj package --vulnerable --include-transitive
dotnet list WebVella.Erp.WebAssembly/Shared/WebVella.Erp.WebAssembly.Shared.csproj package --vulnerable --include-transitive
```

With both preconditions satisfied, the advisory check reports no vulnerable packages for all 17 solution projects and for the two non-member projects listed separately. The toolchain used is the .NET SDK version pinned in `global.json`; the pin exists precisely so that audit defaults and analyzer rule sets are reproducible rather than dependent on whatever SDK happens to be installed.

## This project's own licence

WebVella ERP is licensed under the **Apache License 2.0**.

* [`LICENSE.txt`](LICENSE.txt) at the repository root carries the Apache License 2.0 notice - the standard short-form grant referring to <http://www.apache.org/licenses/LICENSE-2.0>, with the AS IS warranty disclaimer. It is a notice, not a verbatim copy of the full licence text.
* Every packable project declares the licence in its manifest as `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`: `WebVella.Erp/WebVella.Erp.csproj:L14`, `WebVella.Erp.Web/WebVella.Erp.Web.csproj:L13`, `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L10` and `WebVella.Erp.Plugins.SDK/WebVella.Erp.Plugins.SDK.csproj:L10`.
* These projects are published to nuget.org for third-party consumption, which is why the licence of any dependency that carries a reciprocal source-disclosure obligation is a product decision and not merely a technical one.

For completeness, and without proposing a change to it: the licence badge in `README.md` reads `MIT` while the file it links to is the Apache-2.0 notice. That inconsistency predates this inventory and is recorded here as an observation only.

## Active package references

The 33 packages below are the complete set of direct `PackageReference` entries that are in the build graph. Versions in square brackets are exact pins; the rest are minimum-version references. Licences are as recorded in each package's own NuGet metadata (see *Method and limitations*).

| Package | Version | Declared in | Purpose | Licence |
|---|---|---|---|---|
| AutoMapper | `[15.1.3]` exact pin - **changed**, was `[14.0.0]` | WebVella.Erp | Object-to-object mapping between database, domain and view models | Reciprocal Public License 1.5, or a commercial agreement - **see the licensing escalation below** |
| Blazored.LocalStorage | 4.5.0 | WebVella.Erp.WebAssembly/Client | Browser local-storage access for the WebAssembly client | MIT |
| CS-Script | 4.13.1 | WebVella.Erp.Web | Runtime C# script compilation for page-component code hooks | MIT |
| CsvHelper | 33.1.0 | WebVella.Erp | CSV import and export of records | MS-PL OR Apache-2.0 |
| HtmlAgilityPack | 1.12.4 | WebVella.Erp.Web | Server-side HTML parsing | MIT |
| Ical.Net | 5.1.4 | WebVella.Erp | iCalendar generation for calendar features | MIT |
| Irony.NetCore | 1.1.11 | WebVella.Erp | Grammar and parser engine underpinning the entity query language | MIT |
| MailKit | 4.17.0 - **changed**, was 4.14.1 | WebVella.Erp.Plugins.Mail | SMTP and IMAP client for the mail plugin | MIT |
| Microsoft.AspNetCore.Authentication.JwtBearer | 10.0.1 | WebVella.Erp.Site, WebVella.Erp.Site.Project | Bearer-token authentication handler | MIT |
| Microsoft.AspNetCore.Components | 10.0.1 | WebVella.Erp.Plugins.MicrosoftCDM | Razor component model | MIT |
| Microsoft.AspNetCore.Components.Web | 10.0.1 | WebVella.Erp.Plugins.MicrosoftCDM | Web-specific component bindings | MIT |
| Microsoft.AspNetCore.Components.WebAssembly | 10.0.1 | WebVella.Erp.WebAssembly/Client | WebAssembly client runtime | MIT |
| Microsoft.AspNetCore.Components.WebAssembly.Authentication | 10.0.1 | WebVella.Erp.WebAssembly/Client | Client-side authentication for the WebAssembly app | MIT |
| Microsoft.AspNetCore.Components.WebAssembly.DevServer | 10.0.1 | WebVella.Erp.WebAssembly/Client | Development-time static host for the WebAssembly client | MIT |
| Microsoft.AspNetCore.Components.WebAssembly.Server | 10.0.1 - **changed**, was 7.0.13 | WebVella.Erp.WebAssembly/Server | Server-side hosting of the WebAssembly client | MIT |
| Microsoft.AspNetCore.Mvc.NewtonsoftJson | 10.0.1 | WebVella.Erp.Web, WebVella.Erp.Site, WebVella.Erp.Site.Crm, WebVella.Erp.Site.Mail, WebVella.Erp.Site.MicrosoftCDM, WebVella.Erp.Site.Next, WebVella.Erp.Site.Project, WebVella.Erp.Site.Sdk, WebVella.Erp.Plugins.Project (9 projects) | Newtonsoft-based JSON formatter | MIT |
| Microsoft.AspNetCore.Mvc.Razor.RuntimeCompilation | 10.0.1 | WebVella.Erp.Web | Runtime Razor view compilation | MIT |
| Microsoft.CodeAnalysis.CSharp | 5.0.0 | WebVella.Erp.Web | Roslyn compiler services for code generation | MIT |
| Microsoft.CodeAnalysis.CSharp.Scripting | 5.0.0 | WebVella.Erp.Web | Roslyn scripting host | MIT |
| Microsoft.CodeAnalysis.CSharp.Workspaces | 5.0.0 | WebVella.Erp.Web | Roslyn workspace APIs | MIT |
| Microsoft.CodeAnalysis.Common | 5.0.0 | WebVella.Erp.Web | Shared Roslyn primitives | MIT |
| Microsoft.Extensions.FileProviders.Embedded | 10.0.1 | WebVella.Erp.Web | Embedded static asset serving from the web library | MIT |
| Microsoft.Extensions.Http | 10.0.1 | WebVella.Erp.WebAssembly/Client | Typed HTTP client factory for the WebAssembly client | MIT |
| Microsoft.Web.LibraryManager.Build | 3.0.71 | WebVella.Erp.Site | Client-library restore at build time. No `libman.json` manifest exists anywhere in the repository, so it is effectively inert | MIT |
| MimeMapping | 3.1.0 | WebVella.Erp, WebVella.Erp.Site | MIME type resolution for file storage and download | MIT |
| Newtonsoft.Json | 13.0.4 | WebVella.Erp, WebVella.Erp.Web, WebVella.Erp.Site | JSON serialisation across the platform | MIT |
| Npgsql | `[9.0.4]` exact pin | WebVella.Erp | PostgreSQL data provider | PostgreSQL |
| Storage.Net | 9.3.0 | WebVella.Erp | Storage abstraction layer | Not verified in this environment - the package publishes no licence metadata |
| System.Drawing.Common | 10.0.1 | WebVella.Erp | Image handling | MIT |
| System.IdentityModel.Tokens.Jwt | 8.15.0 | WebVella.Erp.Web, WebVella.Erp.WebAssembly/Client | JSON Web Token creation and validation | MIT |
| Wangkanai.Detection | 8.20.0 | WebVella.Erp.Web | Device and browser detection | Apache-2.0 |
| WebVella.TagHelpers | 1.8.0 | WebVella.Erp.Web | First-party Razor tag-helper library supplying the platform's UI primitives | MIT |
| morelinq | 4.4.0 | WebVella.Erp.Site | LINQ extension operators | Apache-2.0 |

## Transitive dependencies of note

Only one transitive package is called out by name, because it is the subject of an advisory that the manifests do not mention directly.

| Package | Version | Resolved through |
|---|---|---|
| MimeKit | 4.17.0 - **changed**, was 4.14.0 | MailKit |

MimeKit has no `PackageReference` of its own anywhere in the repository and deliberately still does not: MailKit 4.17.0 declares a dependency on MimeKit 4.17.0, so raising the MailKit line raised MimeKit with it. Verify with:

```bash
dotnet list WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj package --include-transitive
```

## Shared framework reference

Seven projects declare `<FrameworkReference Include="Microsoft.AspNetCore.App" />` - `WebVella.Erp` (`WebVella.Erp/WebVella.Erp.csproj:L43`), `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Crm`, `WebVella.Erp.Plugins.Mail` (`WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L24`), `WebVella.Erp.Plugins.Next`, `WebVella.Erp.Plugins.Project` and `WebVella.Erp.Plugins.SDK`.

That single reference is the reason the security remediation added **no new package dependency at all**. The ASP.NET Core shared framework already supplies every control the remediation needed:

* the password hasher used to replace unsalted hashing,
* the rate limiter and the request-throttling primitives,
* antiforgery services,
* HTTP Strict Transport Security and HTTPS-redirection middleware,
* the data-protection stack,
* the web encoders used to fix output encoding,
* and the null logger factory supplied to the mapping configuration once AutoMapper 15.x began requiring one.

It is also why a block of framework extension packages could be commented out of the manifests without breaking the build: the shared framework already carries those assemblies, so the explicit package references were redundant. That is the mechanical explanation for the next section.

## Commented-out package references (not in the build graph, finding L-02)

The 15 entries below exist only inside XML comments in the manifests. **They are not restored, not compiled against, and not shipped. Advisories affecting them do not apply to this build.** They are recorded here for completeness and as a hygiene note (finding L-02); they are deliberately left in place rather than deleted, because removing them is code hygiene rather than security remediation.

| Package | Version in comment | File |
|---|---|---|
| Microsoft.AspNetCore.Http.Abstractions | 2.2.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Caching.Abstractions | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Caching.Memory | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Configuration.Json | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Hosting.Abstractions | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Logging | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Logging.Console | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.Extensions.Logging.Debug | 10.0.0 | WebVella.Erp/WebVella.Erp.csproj |
| Microsoft.AspNetCore.Mvc.ViewFeatures | 2.2.0 | WebVella.Erp.Web/WebVella.Erp.Web.csproj |
| Microsoft.AspNetCore.StaticFiles | 2.2.0 | WebVella.Erp.Web/WebVella.Erp.Web.csproj |
| SixLabors.ImageSharp | 3.1.6 | WebVella.Erp.Web/WebVella.Erp.Web.csproj |
| SixLabors.ImageSharp.Drawing | 2.1.5 | WebVella.Erp.Web/WebVella.Erp.Web.csproj |
| Microsoft.AspNetCore.ResponseCompression | 2.2.0 | WebVella.Erp.Site/WebVella.Erp.Site.csproj |
| System.Linq | 4.3.0 | WebVella.Erp.Site/WebVella.Erp.Site.csproj |
| System.Threading | 4.3.0 | WebVella.Erp.Site/WebVella.Erp.Site.csproj |

### Correction recorded so the audit does not carry false findings

An earlier pass of the audit provisionally treated some of these entries as live High-severity findings: the four end-of-life ASP.NET Core 2.2.0 entries, the two 4.3.0 system entries, and `SixLabors.ImageSharp` 3.1.6, which carries a genuine out-of-bounds-write advisory.

Because all of them are commented out, **none of those advisories applies to this build**, and reporting them as High would have placed false findings in the audit report. Stripping XML comments before parsing the manifests is what surfaced the mistake, which is why the reproduction instructions above insist on it. The `grep` form given in step 4 does *not* strip comments, and its output must be reconciled against both tables rather than read as the live dependency set.

## Committed native binaries

One third-party artefact is committed directly to the repository rather than acquired through a package manager.

| Artefact | Size | Type | Version | Licence |
|---|---|---|---|---|
| `ExternalLibraries/libwkhtmltox.dll` | 29,765,120 bytes | PE32+ Windows DLL, x86-64 (native, unmanaged) | Not recorded anywhere in the repository | Not verified in this environment |

This is finding **L-04**, documented only and deliberately not removed - deleting it is repository hygiene, not security remediation. The supply-chain concern is precisely that it carries no version metadata, no package manifest and no provenance record, so it cannot be matched against an advisory database the way a `PackageReference` can, and it cannot be updated by any automated mechanism.

For accuracy: the binary is currently inert. Nothing in the build consumes it. The only thing that ever did was an `XCOPY` post-build target in `WebVella.Erp.Site/WebVella.Erp.Site.csproj` (around lines 65-68), and that target is itself commented out. No project declares a managed reference to it.

## Security-driven dependency changes

Four version changes were made during the OWASP Top 10 (2021) audit remediation. They are the *only* dependency changes: **no package was added and no package was removed.** Each change below names the advisory it closes, the weakness class, the exact declaration site, and why that specific target version was chosen rather than a newer one.

### AutoMapper `[14.0.0]` to `[15.1.3]`

* **Declaration site:** `WebVella.Erp/WebVella.Erp.csproj` (the `AutoMapper` `PackageReference`, at line 47 before the change and line 52 after it, the shift being the inline justification comment that accompanies the pin).
* **Advisory:** `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933` - denial of service through uncontrolled recursion, **CWE-674**. Severity **High**; this was the only High-severity advisory anywhere in the dependency graph.
* **Affected range:** all versions below 15.1.1, and separately the 16.0.0 line below 16.1.1.
* **Why 15.1.3:** it is the newest release on the *lowest patched major*. That minimises behavioural drift while still satisfying the requirement of zero High-severity findings. Jumping to the 16.x line would have imported a second major-version migration for no additional security benefit.
* **Code consequence, and its true size:** from 15.x the `MapperConfiguration` constructor requires an `ILoggerFactory`. The repository has exactly **one** construction site - `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` - which now passes a no-op logger factory. That preserves the prior behaviour, since no logger was supplied, and therefore none consumed, before. `ErpAutoMapper.Initialize`'s signature is unchanged, so both of its call sites - `WebVella.Erp.Web/ErpMvcExtensions.cs:L76` and `WebVella.Erp.ConsoleApp/Program.cs:L47` - needed no edit at all. The 379 `CreateMap<...>` declarations across 32 `Profile` subclasses, in 93 source files that reference AutoMapper, are untouched.
* **Licence consequence:** 14.0.0 declared an MIT expression; 15.1.3 ships a licence *file* placing the code under the **Reciprocal Public License 1.5**, with a commercial agreement as the alternative. This is an unresolved repository-owner decision, set out in full under *Licensing escalation: AutoMapper*.

The blast radius is measurable rather than asserted:

```bash
grep -rho 'CreateMap<' --include='*.cs' . | wc -l                    # 379
grep -rhoP 'class\s+\w+\s*:\s*Profile\b' --include='*.cs' . | wc -l  # 32
grep -rl 'AutoMapper' --include='*.cs' . | wc -l                     # 93
grep -rn 'new MapperConfiguration(' --include='*.cs' .                # exactly one site
```

The trailing parenthesis in the last command is deliberate: without it the pattern also matches the three `new MapperConfigurationExpression()` sites, which are mapping *registries* and were not affected by the constructor change.

### MailKit 4.14.1 to 4.17.0

* **Declaration site:** `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L28`.
* **Advisory:** `GHSA-9j88-vvj5-vhgr` / `CVE-2026-41319` - STARTTLS response injection through an unflushed stream buffer, enabling an authentication-mechanism downgrade, **CWE-74**. First patched in 4.16.0.
* **Why this shape of fix:** this single line edit clears **two** advisories, because MailKit 4.17.0 depends on MimeKit 4.17.0. No separate MimeKit `PackageReference` was added, and none should be: adding one would duplicate a constraint the mail library already expresses, and would then have to be maintained in lockstep with it.

### MimeKit 4.14.0 to 4.17.0, transitively

* **Declaration site:** none. It is resolved through MailKit, as described above.
* **Advisory:** `GHSA-g7hc-96xr-gvvx` / `CVE-2026-30227` - CRLF injection in a quoted local part, enabling SMTP command injection and message forgery, **CWE-93**. First patched in 4.15.1.
* **Why it matters here specifically:** the mail plugin handles user-influenced recipient addresses, *and* it disabled transport certificate validation at five sites (finding H-11). An injection flaw compounding with an absent certificate check is materially worse than either weakness alone, which is why the mail stack was treated as a priority rather than a routine version bump.

### Microsoft.AspNetCore.Components.WebAssembly.Server 7.0.13 to 10.0.1 (finding H-18)

* **Declaration site:** `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` (line 10 before the change, line 12 after it), accompanied by retargeting both `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` from `net7.0` to `net10.0`.
* **Weakness class:** **CWE-1104**, use of unmaintained components. This is not a CVE remediation; no advisory is outstanding against the 7.0.13 package. It is an *unsupported-component* remediation: the .NET 7 line stopped receiving security patches on **2024-05-14**, so any future advisory raised against it would be permanently unfixable.
* **Context:** 17 of the 19 projects already targeted `net10.0`; only these two lagged. After the retarget all 19 projects target the same supported framework line, which also brings the two former stragglers into the same dependency-audit and analyzer regime as the rest of the solution.

### Packages deliberately not changed

The remaining 30 active packages were each checked against the advisory database and are **clean**. No upgrade is proposed for any of them, because the remediation guideline in force is to choose the solution requiring the least modification, and a version change with no security justification is a gratuitous change.

Three cases are worth stating explicitly, since each has a *newer* version available and each was still left alone on purpose:

* **Npgsql `[9.0.4]`** - a newer release of the data provider exists, but the pinned version is already safe; its only advisory does not reach the 9.x line at all.
* **Newtonsoft.Json 13.0.4** - well past both of its historical advisories.
* **System.IdentityModel.Tokens.Jwt 8.15.0** - far beyond the versions its advisories affect.

## Licensing escalation: AutoMapper

**This is an open repository-owner decision. It was not decided by the remediation, and nothing in this document should be read as having settled it.**

The facts, all verifiable from package metadata:

* **AutoMapper 14.0.0**, the version previously pinned, declares `<license type="expression">MIT</license>`.
* **AutoMapper 15.1.3**, the version required to close `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933`, declares `<license type="file">LICENSE.md</license>` instead. That file states that the code is governed by the **Reciprocal Public License 1.5** (<https://opensource.org/license/rpl-1-5/>), and offers a separate commercial License Agreement as the alternative for anyone unwilling to release the source of software built with it.
* **This repository declares Apache-2.0** at `WebVella.Erp/WebVella.Erp.csproj:L14`, ships a matching `LICENSE.txt`, and publishes packages to nuget.org for third-party consumption.

The conflict is therefore substantive rather than cosmetic. A reciprocal licence's source-disclosure obligation is incompatible with distributing packages under a permissive expression to unknown downstream consumers. And there is **no patched MIT-licensed line to retreat to**: the fix begins at 15.1.1, which is already under the new terms.

Two options exist. Both are legitimate; choosing between them is the owner's call, not an automated agent's.

1. **Keep the upgrade at `[15.1.3]`** - the current state of the repository. The High-severity advisory is closed and the dependency gate passes, at the cost of accepting the Reciprocal Public License 1.5 terms (or entering the commercial agreement) and reconciling that with the project's own Apache-2.0 declaration and its published packages.
2. **Revert to `[14.0.0]` behind a narrowly scoped audit suppression** carrying an inline justification, together with a formally recorded risk acceptance. The acceptance would rest on this exploitability assessment: every mapping in this codebase is statically declared in source, and no user-controlled mapping configuration or type graph reaches the configuration builder, so the recursion path is reachable only through a self-referential mapping that the project's own developers would have to author. Real-world exposure is low despite the High rating. This keeps the build gate green **without pretending the advisory does not exist** - the suppression is explicit, justified in place, and auditable.

Whichever option is taken must be recorded in [the risk register](docs/security/risk-register.md), which is where the decision and its rationale belong; the open entry there is **`RISK-001`**, which states the same facts as this section with both options set out in full and records the decision as unresolved. The dependency gate promotes advisory diagnostics to build errors, so this decision blocks the build turning green and cannot simply be deferred.

## Method and limitations

Stated plainly, so that the confidence attached to each claim is visible:

* **The manifest inventory is first-hand.** All 19 `.csproj` files were parsed with XML comments stripped, and the resulting live set (33 packages) and commented set (15 entries) are reproduced above exactly, including which project declares each reference.
* **The advisory state is scanner-derived.** `dotnet list package --vulnerable --include-transitive` was run solution-wide and, separately, against the two non-member WebAssembly projects. Nothing in the advisory sections rests on narrative assertion.
* **Licences are as recorded in each package's own NuGet metadata**, read from the package `.nuspec` and, where the metadata points at a licence file rather than an SPDX expression, from that file's text. This is how the Reciprocal Public License 1.5 finding for AutoMapper 15.1.3 was established, and how the MIT status of Irony.NetCore, `Microsoft.Web.LibraryManager.Build` and the Apache-2.0 status of morelinq were confirmed. Four packages declare a licence *file* rather than an SPDX expression, and the table above reports the resolved licence rather than the file name: AutoMapper 15.1.3 (`LICENSE.md`), Irony.NetCore (`LICENSE`), `Microsoft.Web.LibraryManager.Build` (`License.txt`) and morelinq (`COPYING.txt`). AutoMapper is the only one of the four whose file resolves to anything other than a permissive licence, which is why it is the only one escalated.
* **Unverified rows are marked as such rather than guessed.** `Storage.Net` 9.3.0 publishes no licence element and no licence URL in its `.nuspec`, so its row reads `Not verified in this environment`. `ExternalLibraries/libwkhtmltox.dll` carries no metadata at all and is marked the same way. An invented licence string in the document that serves as the evidence base for a licensing escalation would be worse than an honest gap.
* **Advisory identifiers, severities, weakness classes and first-patched versions** were obtained by direct retrieval from the GitHub Advisory REST API, and package version availability and dependency metadata from the NuGet flat-container API. The `web_search` facility returns empty results in this environment, so no claim here rests on it. Where a figure could not be substantiated, it was omitted rather than estimated.
* **Line references** point at the post-remediation state of each file unless a "before the change" line is given explicitly. Line numbers drift as files are edited; the surrounding declaration name is the durable locator.

## Related documents

* [`SECURITY.md`](SECURITY.md) - disclosure policy, supported versions and security posture summary.
* [Security audit report](docs/security/security-audit-report.md) - all findings in the mandated eight-field format, including the dependency findings summarised here.
* [Remediation log](docs/security/remediation-log.md) - what changed per vulnerability class, including the dependency class recorded in this document.
* [Risk register](docs/security/risk-register.md) - accepted risks and open decisions, including the AutoMapper licensing escalation above as entry `RISK-001`.
* [Secure configuration guide](docs/security/secure-configuration.md) - operator guidance for running the platform securely.
* [Credential migration guide](docs/security/credential-migration.md) - the credential-hash migration and its operator actions.
* [`LICENSE.txt`](LICENSE.txt) - this project's own licence.
