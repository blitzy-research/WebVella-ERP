# Third-party libraries

This is the third-party dependency inventory referenced from the `### Third party libraries` section of [README](https://github.com/WebVella/WebVella-ERP/blob/master/README.md). It lists the platform's **direct** package references, the one transitive package that carries a security advisory, the shared framework reference, and the one committed native binary - each with the version in use, the project that declares it, what it is used for, and its licence.

It is deliberately **not** a full transitive closure. Enumerating every package the restore graph resolves would bury what this product actually declares, which is the question this document exists to answer. *Scope and currency* below states the boundary exactly, and step 2 of *How to reproduce this inventory* gives the command that produces the complete closure for anyone who needs it.

The inventory was produced by parsing **all 19 project manifests in the repository with XML comments stripped first**, so that commented-out entries could never be mistaken for live references. That distinction matters enough to be called out twice in this document: 15 `PackageReference` entries in this repository sit inside XML comments and are therefore absent from the build graph. They are listed separately, under *Commented-out package references*, and must not be read as dependencies of this product.

Scope and currency:

* **As of 2026-07-31**, reflecting the repository state after the OWASP Top 10 (2021) security audit and remediation. Four dependency versions changed as part of that work; every changed row is marked in the table below and explained under *Security-driven dependency changes*.
* **In scope:** direct NuGet package references, the one transitive package that carries a security advisory (MimeKit), the shared framework reference, and committed native binaries. Transitive packages other than that one are out of scope by design, per the note above.
* **Out of scope:** browser-side assets. The repository contains 188 `.js` and 5 `.css` files and no `libman.json` or `package.json`, so client libraries are vendored or CDN-loaded rather than version-managed. One CDN-loaded library carries no integrity attribute. That is classified as finding **M-15**, a documented-only Medium, and it belongs in [the security audit report](docs/security/security-audit-report.md) rather than here, because it is not a managed dependency. That report is compiled incrementally - one vulnerability class per commit - so M-15 has not been written up there yet; the classification is stated here so the gap is visible rather than implied.
* This document is also the evidence base for one unresolved licensing question. See *Licensing escalation: AutoMapper*.

> **⚠ Open licensing decision - `AutoMapper`.** The security fix for `GHSA-rvv3-g6hj-g44x` moves this
> package onto a line licensed under the **Reciprocal Public License 1.5**, which is not compatible on
> its face with the `Apache-2.0` expression this repository declares and publishes under. The advisory
> is **closed**; the licence question is **open and belongs to the repository owner**, and neither
> outcome has been assumed - the declared licence expression was not changed and the upgrade was not
> reverted. Full reasoning, registry evidence and both options are under *Licensing decision:
> AutoMapper* below, and as `RISK-001` in [the risk register](docs/security/risk-register.md).

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

* **The project-reference path casing must be correct.** Until finding H-19 was fixed, **15 path occurrences** spelled the core project's folder as `WebVella.ERP` while the folder on disk is `WebVella.Erp`: **one project entry in `WebVella.ERP3.sln`, and 14 `<ProjectReference>` elements** spread across project files. Only those 14 are project references in the MSBuild sense - the solution entry is a project registration, and it is the one that breaks a solution-wide restore. On a case-sensitive filesystem that restore failed outright, and the core project - which owned the graph's only High-severity advisory - was silently absent from the audit. Any "clean" dependency-scan result obtained before that fix was worthless. All 15 occurrences are corrected; `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` now returns nothing.
* **The solution must contain every project.** This precondition was previously *unmet* and is now satisfied. `dotnet sln WebVella.ERP3.sln list` formerly returned only 17 of the 19 projects, because `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` were not solution members - so every solution-wide restore, build, audit and analyzer pass silently skipped them, including the two projects that were still on an end-of-life framework. Both were added to the solution as the fix for finding **H-10**, and the count is now **19 of 19**:

```bash
dotnet sln WebVella.ERP3.sln list | grep -c csproj    # 19
dotnet list WebVella.ERP3.sln package --include-transitive | grep -c "^Project"    # 19
```

  Because both figures now agree, no project needs to be scanned separately, and a solution-wide command is sufficient. The toolchain used is the .NET SDK version pinned in `global.json` with `"rollForward": "disable"`; the pin exists precisely so that audit defaults and analyzer rule sets are reproducible rather than dependent on whatever SDK happens to be installed.

### Recorded results

Run on the .NET SDK version pinned in `global.json` (`10.0.302`; `dotnet --info` confirms `global.json` is what resolves it). The pin exists precisely so that audit defaults and analyzer rule sets are reproducible rather than dependent on whatever SDK happens to be installed. Solution-wide rows and non-member rows are reported separately on purpose, because they are separate commands with separate coverage.

| Scope | Command | Recorded result |
| --- | --- | --- |
| Precondition | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches - the casing defect is fixed, so the core project really is in the graph |
| Precondition | `dotnet sln WebVella.ERP3.sln list` | 19 projects; `WebAssembly.Server` and `WebAssembly.Shared` are now solution members, so a solution-wide command reaches the whole graph |
| All 19 solution projects | `dotnet restore WebVella.ERP3.sln` | exit 0, zero `NU19xx` diagnostics |
| All 19 solution projects | `dotnet build WebVella.ERP3.sln -c Debug -t:Rebuild` | exit 0, **0 errors** |
| All 19 solution projects | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | exit 0; every project reports `has no vulnerable packages given the current sources` |
| **WebAssembly Server** | `dotnet msbuild … -getProperty:TargetFramework` | `net10.0` - the retarget off the end-of-life `net7.0` line is live, not merely written |
| **WebAssembly Server** | `dotnet restore …Server.csproj --force` | exit 0, zero `NU19xx` diagnostics |
| **WebAssembly Server** | `dotnet build …Server.csproj -c Debug -t:Rebuild` | exit 0, **0 errors**, 53 warnings (all `CA*`/`CS0168`); emits `net10.0/WebVella.Erp.WebAssembly.Server.dll`, and alongside it `WebVella.Erp.WebAssembly.Shared.dll` and `WebVella.Erp.WebAssembly.dll`, confirming this one command also compiles the Client and Shared references |
| **WebAssembly Server** | `dotnet list …Server.csproj package` | `Microsoft.AspNetCore.Components.WebAssembly.Server` requested `10.0.1`, resolved `10.0.1` - the end-of-life `7.0.13` pin is gone |
| **WebAssembly Server** | `dotnet list …Server.csproj package --vulnerable --include-transitive` | exit 0; `The given project 'WebVella.Erp.WebAssembly.Server' has no vulnerable packages given the current sources.` |
| **WebAssembly Shared** | `dotnet msbuild … -getProperty:TargetFramework` | `net10.0` |
| **WebAssembly Shared** | `dotnet restore …Shared.csproj --force` | exit 0, zero `NU19xx` diagnostics |
| **WebAssembly Shared** | `dotnet build …Shared.csproj -c Debug -t:Rebuild` | exit 0, **0 errors, 0 warnings**; emits `net10.0/WebVella.Erp.WebAssembly.Shared.dll` |
| **WebAssembly Shared** | `dotnet list …Shared.csproj package --vulnerable --include-transitive` | exit 0; `The given project 'WebVella.Erp.WebAssembly.Shared' has no vulnerable packages given the current sources.` |
| Both WebAssembly projects | `grep -rn 'net7.0' --include=*.csproj .` | no `TargetFramework` match remains; the only surviving occurrence is inside the comment that explains the retarget |

Two independent corroborations of the retarget, recorded because a `.csproj` edit alone proves only intent: the compiled `WebVella.Erp.WebAssembly.Server.dll` carries `.NETCoreApp,Version=v10.0` in its metadata, and both WebAssembly manifests evaluate the repository gate (`NuGetAuditMode=all`, `AnalysisLevel=latest-recommended`) exactly as the other 17 projects do, so they are inside the same audit and analyzer regime rather than beside it. Since they are solution members as well, the solution-wide commands above now reach them without a separate invocation.

These commands are not left to be run by hand. `.github/workflows/security-scan.yml` runs every one of them, so the coverage described here is reproducible rather than a one-off local observation. Two honest qualifications on that. First, the workflow does not restate the SDK version: it resolves the toolchain with `global-json-file: global.json`, so the pin has exactly one home and cannot drift out of step with the build. Second, its steps were validated by parsing the YAML, extracting all **eight** `run:` steps - the file declares eleven steps, of which three are `uses:` actions rather than shell - and executing each of the eight in order against this working tree. **8 / 8 exited 0.** That includes the Gate 1 step, whose `--configuration Release --no-incremental` build of the whole solution reported **0 errors**; the Gate 3 sweep, which reported no secret material outside the documented finding inventory; and above all the negative-control step, which is the one that must observe `error NU1903: ... Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x` and would fail if the gate ever stopped firing - it did observe exactly that. None of this is a substitute for a hosted CI run, which this environment cannot perform. So the commands are proven to work and proven to be committed; the first *hosted* execution will be the one triggered after this branch is pushed.

## Where the dependency gate lives

Nobody has to run the commands above by hand for the audit to have teeth: it is enforced on every build by [`Directory.Build.props`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/Directory.Build.props) at the repository root. That file is the mechanism behind the statements later in this document that the dependency gate *passes* and that it *promotes advisory diagnostics to build errors*.

| Property | Value | Effect |
|---|---|---|
| `NuGetAudit` | `true` | Runs the dependency audit as part of restore. |
| `NuGetAuditMode` | `all` | Audits transitive packages as well as direct ones - which is what makes the MimeKit advisory visible at all, since this repository only ever resolves MimeKit transitively. |
| `NuGetAuditLevel` | `low` | Reports at every severity rather than only High and above. |
| `WarningsAsErrors` | appends `NU1901;NU1902;NU1903;NU1904` | Turns any advisory diagnostic into a **build error**. The value appends to `$(WarningsAsErrors)` rather than replacing it, so nothing already set is discarded - the .NET SDK's own escalations (`SYSLIB0011`, `NU1605`) are still appended after these four and survive intact. This is the only place in the repository that sets the property. |
| `EnableNETAnalyzers` / `AnalysisLevel` | `true` / `latest-recommended` | Enables the built-in .NET analyzers, which stand in for an external static-analysis scanner. Analyzer diagnostics stay **warnings**; only the four dependency codes above are errors. Coverage is partial and was measured, not assumed: the non-dataflow security rules run (`CA5351` and `CA5359` report at real sites), while the dataflow rules such as `CA5390` and `CA5401` are not enabled at this level - so their silence is **not** evidence the corresponding weaknesses are absent. The boundary is set out in the [secure configuration guide](docs/security/secure-configuration.md). |

A repository-root MSBuild properties file is the right mechanism here rather than an `.editorconfig`: four `.editorconfig` files in this repository declare `root = true`, which would stop a root-level style file from reaching their subtrees. `Directory.Build.props` is inherited by all 19 projects regardless of that scoping - including the two that are not solution members.

Two properties of the gate are worth stating, because a gate nobody has tested is indistinguishable from no gate:

* **It contains no active suppressions.** No advisory diagnostic is silenced, in this file or in any project manifest. One caveat keeps the claim honest: a plain `grep -nE 'NoWarn|WarningsNotAsErrors|NuGetAuditSuppress' Directory.Build.props` returns **one** line - `<NoWarn>$(NoWarn);NU1903</NoWarn>` at `Directory.Build.props:L157` - which sits **inside an XML comment**. It is a documented, deliberately inert *suppression seam*: the only sanctioned shape a future suppression may take, one narrowly scoped code, and the surrounding comment requires a named risk acceptance in `docs/security/risk-register.md` before it may ever be uncommented. Three measurements establish that nothing is suppressed today:

    ```bash
    # 1. Strip the XML comments and nothing matches at all:
    python3 -c "import re;t=open('Directory.Build.props',encoding='utf-8-sig').read();\
    print(re.findall(r'NoWarn|WarningsNotAsErrors|NuGetAuditSuppress',re.sub(r'<!--.*?-->','',t,flags=re.S)))"
    #   []

    # 2. The effective NoWarn any project inherits is only the SDK's own doc-comment pair:
    dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NoWarn          # 1701;1702
    dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:WarningsAsErrors
    #   ;NU1901;NU1902;NU1903;NU1904;NU1605;SYSLIB0011
    #   - the four audit codes are promoted, and the SDK's own NU1605/SYSLIB0011 survive,
    #     which is what proves the property appends rather than replaces.

    # 3. No project manifest suppresses anything either:
    grep -rnE 'NuGetAuditSuppress|NoWarn' --include='*.csproj' .                 # no matches
    ```
* **It has been confirmed not blind.** Pointing a throwaway project at the pre-remediation `AutoMapper [14.0.0]` makes restore fail with `error NU1903: ... has a known high severity vulnerability`. The clean result on the real solution is therefore a real result, not an inert check.

```bash
# The gate's properties as any project sees them after inheritance:
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NuGetAuditMode      # all
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NuGetAuditLevel     # low
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:AnalysisLevel       # latest-recommended
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:WarningsAsErrors    # contains NU1901;NU1902;NU1903;NU1904
```

## This project's own licence

WebVella ERP is licensed under the **Apache License 2.0**.

* [`LICENSE.txt`](LICENSE.txt) at the repository root carries the Apache License 2.0 notice - the standard short-form grant referring to <http://www.apache.org/licenses/LICENSE-2.0>, with the AS IS warranty disclaimer. It is a notice, not a verbatim copy of the full licence text.
* **Four projects declare the licence in the manifest** as `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`: `WebVella.Erp/WebVella.Erp.csproj:L14`, `WebVella.Erp.Web/WebVella.Erp.Web.csproj:L13`, `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L10` and `WebVella.Erp.Plugins.SDK/WebVella.Erp.Plugins.SDK.csproj:L10`.
* **Those four are not the only packable projects.** Ten of the 19 projects are packable. The other six - `WebVella.Erp.ConsoleApp`, `WebVella.Erp.Plugins.Crm`, `WebVella.Erp.Plugins.MicrosoftCDM`, `WebVella.Erp.Plugins.Next`, `WebVella.Erp.Plugins.Project` and `WebVella.Erp.WebAssembly/Shared` - declare no licence expression at all, so a package built from any of them would ship without licence metadata. The nine non-packable projects (the seven site hosts, the WebAssembly client and the WebAssembly server) are not affected, because they are never packed. This is a packaging-metadata gap rather than a security finding; it is recorded as an observation and no change to it is proposed here. Verify with:

```bash
for f in $(find . -name '*.csproj' | sort); do
  printf '%-72s packable=%-6s lic=%s\n' "$f" \
    "$(dotnet msbuild "$f" -getProperty:IsPackable -nologo)" \
    "$(grep -o '<PackageLicenseExpression>[^<]*' "$f" | sed 's/.*>//' | head -1)"
done
```
* These projects are published to nuget.org for third-party consumption, which is why the licence of any dependency that carries a reciprocal source-disclosure obligation is a product decision and not merely a technical one.

For completeness, and without proposing a change to it: the licence badge in `README.md` reads `MIT` while the file it links to is the Apache-2.0 notice. That inconsistency predates this inventory and is recorded here as an observation only.

## Active package references

The 33 packages below are the complete set of direct `PackageReference` entries that are in the build graph. Versions in square brackets are exact pins; the rest are minimum-version references. Licences are as recorded in each package's own NuGet metadata (see *Method and limitations*).

| Package | Version | Declared in | Purpose | Licence |
|---|---|---|---|---|
| AutoMapper | `[15.1.3]` exact pin - raised from `[14.0.0]` to close `GHSA-rvv3-g6hj-g44x` | WebVella.Erp | Object-to-object mapping between database, domain and view models | Reciprocal Public License 1.5, declared as a licence file - **see the licensing decision below** |
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

A previous revision of this document named only one transitive package. That was too narrow: a dependency inventory that omits the cryptography and token-handling libraries the platform actually loads is not an adequate basis for a security review, even when none of them carries an advisory. Every transitive package below is either security-relevant by function, changed by this remediation, or resolved at a version that differs from another copy of itself in the same solution.

| Package | Version | Resolved through | Why it is named |
|---|---|---|---|
| MimeKit | 4.17.0 - **changed**, was 4.14.0 | MailKit | Subject of an advisory the manifests do not mention directly |
| BouncyCastle.Cryptography | 2.6.2 | MailKit / MimeKit | **Cryptographic implementation library.** No advisory outstanding, but it performs the mail stack's S/MIME and TLS-adjacent cryptography, so it belongs in any security-relevant inventory |
| Microsoft.IdentityModel.JsonWebTokens | 8.15.0 | System.IdentityModel.Tokens.Jwt | Token parsing and validation - directly load-bearing for the bearer-token authentication path |
| Microsoft.IdentityModel.Tokens | 8.15.0 | System.IdentityModel.Tokens.Jwt | Signing-key and token-validation primitives |
| Microsoft.IdentityModel.Logging | 8.15.0 | System.IdentityModel.Tokens.Jwt | Emits token-validation diagnostics |
| Microsoft.IdentityModel.Abstractions | 8.15.0 | System.IdentityModel.Tokens.Jwt | Shared identity abstractions |
| Microsoft.IdentityModel.Protocols | **8.0.1** | Microsoft.AspNetCore.Authentication.JwtBearer | **Version skew** - see below |
| Microsoft.IdentityModel.Protocols.OpenIdConnect | **8.0.1** | Microsoft.AspNetCore.Authentication.JwtBearer | **Version skew** - see below |

Reproduce the whole set, including the owning project of each row:

```bash
dotnet list WebVella.ERP3.sln package --include-transitive
dotnet list WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj package --include-transitive
```

MimeKit has no `PackageReference` of its own anywhere in the repository and deliberately still does not: MailKit 4.17.0 declares a dependency on MimeKit 4.17.0, so raising the MailKit line raised MimeKit with it. BouncyCastle.Cryptography arrives the same way and appears only in `WebVella.Erp.Plugins.Mail` and `WebVella.Erp.Site.Mail` - it is not loaded by any host that does not use the mail plugin.

### Version skew

**Eight** packages resolve at **two different versions** within the same solution - the four `Microsoft.Extensions.*` abstractions and the four-package `Microsoft.IdentityModel.*` core family - and one further identity pair sits behind that family at a single version. None is an advisory, and none is being changed here - a version change with no security justification is exactly the gratuitous change the remediation guideline forbids. They are recorded because unnoticed skew is how a patched package silently coexists with an unpatched copy of itself.

Which version a project sees depends on whether that project declares the ASP.NET Core shared framework. `WebVella.Erp` declares `<FrameworkReference Include="Microsoft.AspNetCore.App" />`, so the four `Microsoft.Extensions.*` abstractions are supplied by the framework and are **not packages in its graph at all**. Exactly three projects resolve them as packages: `WebVella.Erp.Plugins.MicrosoftCDM` and the WebAssembly client (`WebVella.Erp.WebAssembly/Client/WebVella.Erp.WebAssembly.csproj`) reach the **10.0.1** line through their own `Microsoft.AspNetCore.Components 10.0.1` references, while `WebVella.Erp.ConsoleApp` - which declares no `PackageReference` of its own and only the `Microsoft.NETCore.App` framework - inherits whatever floor the core library's package graph imposes, which is the **8.0.x** line. Every attribution in the table below was read out of `WebVella.Erp.ConsoleApp/obj/project.assets.json`, which records the requesting package and the requested range for every resolved dependency.

| Package | Versions resolved | Note |
|---|---|---|
| Microsoft.IdentityModel.Protocols / .Protocols.OpenIdConnect | **8.0.1** | Behind the rest of the IdentityModel family, which resolves at 8.15.0 in the sixteen projects that reference it directly. Reached only through `Microsoft.AspNetCore.Authentication.JwtBearer` in `WebVella.Erp.Site` and `WebVella.Erp.Site.Project`; the OpenID Connect protocol path is not used by this platform, which authenticates with its own token endpoint and a cookie scheme |
| Microsoft.Extensions.Options | 10.0.1 and 8.0.0 | The 8.0.0 copy is requested by **AutoMapper 15.1.3** and by nothing else, and it materialises only in `WebVella.Erp.ConsoleApp`. AutoMapper 14.0.0 declared this package as its *one* dependency; 15.1.3 still declares it at the same 8.0.0, so the version decision neither introduced nor moved this row |
| Microsoft.Extensions.Primitives | 10.0.1 and 8.0.0 | The 8.0.0 copy is requested only by `Microsoft.Extensions.Options 8.0.0`, so it follows the row above rather than being pulled by anything in this repository |
| Microsoft.Extensions.Logging.Abstractions | 10.0.1 and 8.0.2 | Three packages request the 8.x line inside `WebVella.Erp.ConsoleApp`: AutoMapper 15.1.3 and `Microsoft.IdentityModel.Tokens 8.14.0` each ask for 8.0.0, and **`Npgsql 9.0.4` asks for 8.0.2**. The highest floor wins, so 8.0.2 is resolved - the 8.0.2 is Npgsql's, not the mapper's |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.1 and 8.0.2 | The 8.0.2 copy is requested by `Microsoft.Extensions.Logging.Abstractions 8.0.2` (the row above); `Microsoft.Extensions.Options 8.0.0` asks only for 8.0.0 |
| Microsoft.IdentityModel.Abstractions / .JsonWebTokens / .Logging / .Tokens | 8.14.0 and 8.15.0 | 8.15.0 in the sixteen projects reached by the direct `System.IdentityModel.Tokens.Jwt 8.15.0` reference in `WebVella.Erp.Web` and in the WebAssembly client. **8.14.0** in the two projects that carry no such direct reference - `WebVella.Erp` and `WebVella.Erp.ConsoleApp` - where the family arrives through AutoMapper 15.1.3's dependency on `Microsoft.IdentityModel.JsonWebTokens 8.14.0`. This is the one skew row the version decision did introduce; the chain is set out immediately below |

Reproduce:

```bash
dotnet list WebVella.ERP3.sln package --include-transitive \
  | awk '/>/ {print $2, $NF}' | sort -u | awk '{c[$1]++} END {for (p in c) if (c[p]>1) print p, c[p]}' | sort
#   Microsoft.Extensions.DependencyInjection.Abstractions 2
#   Microsoft.Extensions.Logging.Abstractions 2
#   Microsoft.Extensions.Options 2
#   Microsoft.Extensions.Primitives 2
#   Microsoft.IdentityModel.Abstractions 2
#   Microsoft.IdentityModel.JsonWebTokens 2
#   Microsoft.IdentityModel.Logging 2
#   Microsoft.IdentityModel.Tokens 2
# -> eight rows, which is the count stated above.

# And to read the requesting edge rather than only the resolved version:
python3 -c "import json;a=json.load(open('WebVella.Erp.ConsoleApp/obj/project.assets.json'));\
t=a['targets']['net10.0'];\
print([(k,d,r) for k,v in t.items() for d,r in (v.get('dependencies') or {}).items() if d.startswith('Microsoft.Extensions.')])"
```

### A transitive chain the upgrade introduces

Raising AutoMapper to `[15.1.3]` adds **four `Microsoft.IdentityModel.*` packages at version 8.14.0** to the core library's graph, because 15.1.x declares a dependency on `Microsoft.IdentityModel.JsonWebTokens`. AutoMapper 14.0.0 declared **one** dependency - `Microsoft.Extensions.Options 8.0.0`. On the dependency group that actually applies to a `net10.0` project, which is its `net9.0` group, 15.1.3 declares **three**: `Microsoft.Extensions.Logging.Abstractions 8.0.0`, `Microsoft.Extensions.Options 8.0.0` and `Microsoft.IdentityModel.JsonWebTokens 8.14.0`. Its `netstandard2.0` group declares five, adding `Microsoft.Bcl.HashCode` and `System.Reflection.Emit`, but no project here resolves that group. This is recorded as a measured cost of the version decision rather than discovered later:

* An object-mapping library pulling a JSON Web Token stack into the graph is unexpected, and it widens the graph that has to be audited.
* The version it pulls - **8.14.0** - sits *behind* the **8.15.0** that the solution already references directly through `System.IdentityModel.Tokens.Jwt`, so it applies downward pressure on the resolved version of the platform's own token-validation library. It does not win *where that direct reference is present*: in the sixteen projects that see `System.IdentityModel.Tokens.Jwt 8.15.0`, NuGet resolves to the higher 8.15.0. In the two projects that do not - `WebVella.Erp` itself and `WebVella.Erp.ConsoleApp` - **8.14.0 is the resolved version**, which is precisely the 8.14.0-and-8.15.0 row recorded in the version-skew table above. The chain therefore produces a skew, not a downgrade: no project ends up with a token library older than the one it asked for.

Measured, not asserted:

```bash
# The core library's complete transitive graph - eight packages, half of them the token family:
dotnet list WebVella.Erp/WebVella.Erp.csproj package --include-transitive
#   > Microsoft.IdentityModel.Abstractions       8.14.0
#   > Microsoft.IdentityModel.JsonWebTokens      8.14.0
#   > Microsoft.IdentityModel.Logging            8.14.0
#   > Microsoft.IdentityModel.Tokens             8.14.0
#   > Microsoft.IO.RecyclableMemoryStream        1.3.2
#   > Microsoft.Win32.SystemEvents               10.0.1
#   > NetBox                                     2.3.5
#   > NodaTime                                   3.2.2

# The declared edges, read from the package manifest rather than inferred:
grep -o '<dependency id="[^"]*" version="[^"]*"' \
  ~/.nuget/packages/automapper/15.1.3/automapper.nuspec | sort -u
#   <dependency id="Microsoft.Bcl.HashCode" version="6.0.0"
#   <dependency id="Microsoft.Extensions.Logging.Abstractions" version="8.0.0"
#   <dependency id="Microsoft.Extensions.Options" version="8.0.0"
#   <dependency id="Microsoft.IdentityModel.JsonWebTokens" version="8.14.0"   <- the head of the chain
#   <dependency id="System.Reflection.Emit" version="4.7.0"
# Five distinct ids across all groups; the first and last belong to the netstandard2.0
# group only, so a net10.0 project sees the middle three.
```

None of the four carries an advisory, so this is a graph-surface observation and not a finding. It is one of the inputs to `RISK-001`: holding the pin would remove all four, which is a real if secondary argument on that side of the decision.

## Shared framework reference

Seven projects declare `<FrameworkReference Include="Microsoft.AspNetCore.App" />` - `WebVella.Erp` (`WebVella.Erp/WebVella.Erp.csproj:L43`), `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Crm`, `WebVella.Erp.Plugins.Mail` (`WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L24`), `WebVella.Erp.Plugins.Next`, `WebVella.Erp.Plugins.Project` and `WebVella.Erp.Plugins.SDK`.

That single reference is the reason the security remediation added **no new package dependency at all**. The ASP.NET Core shared framework already supplies every control the remediation needed:

* the password hasher used to replace unsalted hashing,
* the rate limiter and the request-throttling primitives,
* antiforgery services,
* HTTP Strict Transport Security and HTTPS-redirection middleware,
* the data-protection stack,
* the web encoders used to fix output encoding - specifically `JavaScriptEncoder`, which replaced a hand-written single-character replacement in `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs`,
* and the fixed-time comparison and key-derivation primitives (`CryptographicOperations.FixedTimeEquals`, `Rfc2898DeriveBytes`) used to replace unsalted hashing.

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
| `ExternalLibraries/libwkhtmltox.dll` | 29,765,120 bytes | PE32+ Windows DLL, x86-64 (native, unmanaged) | **0.12.4** - recovered from the binary itself; not declared anywhere in the repository | Not declared in the repository. The binary embeds GNU LGPL v3 licence text - see the note below |

This is finding **L-04**, documented only and deliberately not removed - deleting it is repository hygiene, not security remediation.

**The version is recoverable, and this document previously said it was not.** The binary carries Windows version resources, and three independent sources inside it agree on `0.12.4`:

```bash
strings -a ExternalLibraries/libwkhtmltox.dll | grep -iE '^wkhtmltopdf [0-9]'   # wkhtmltopdf 0.12.4
strings -a -el ExternalLibraries/libwkhtmltox.dll | grep -A1 -x 'FileVersion'   # 0.12.4.0
strings -a -el ExternalLibraries/libwkhtmltox.dll | grep -A1 -x 'OriginalFilename'  # wkhtmltox.dll
```

* The embedded product banner reads `wkhtmltopdf 0.12.4`.
* The `VS_FIXEDFILEINFO` structure (signature `0xFEEF04BD`) gives **FileVersion `0.12.4.0`** and **ProductVersion `0.12.4.0`**; the `StringFileInfo` block gives `FileVersion` `0.12.4.0`, `OriginalFilename` `wkhtmltox.dll` and `ProductName` `wkhtmltox`.
* The PE optional header's image-version field, at offset `+44`/`+46` from the start of the optional header, reads `0.124` - the same version stamped by the linker. The adjacent field at `+40`/`+42` is the *operating-system* version (`6.0`) and must not be mistaken for it.

**What genuinely is missing** is everything needed to *manage* the artefact, which is the real supply-chain concern:

* no package manifest, so there is no package identity to match against an advisory database the way a `PackageReference` can be matched;
* no recorded provenance - no upstream URL, no build record and no checksum committed alongside it, so its integrity cannot be attested;
* no update mechanism, automated or otherwise.

Because the version *is* known, the artefact can at least be checked against upstream advisories by hand. Anyone doing so should note that `0.12.4` is an old release of a project that is itself no longer actively maintained upstream.

**On the licence.** The binary embeds the verbatim text of the **GNU Lesser General Public License version 3**, which is consistent with wkhtmltopdf's own published licensing. That is reported here as observed evidence, not as a determination: this DLL statically bundles Qt, which is also LGPL-licensed, so the embedded text cannot be attributed to one component from the binary alone, and no licence or attribution file is committed next to it (`ExternalLibraries/` contains only the DLL). An LGPL-family artefact shipped inside an Apache-2.0 repository with no accompanying notice carries attribution obligations that deserve an owner review; that review is a legal question and is deliberately not answered here.

For accuracy: the binary is currently inert. Nothing in the build consumes it. The only thing that ever did was an `XCOPY` post-build target in `WebVella.Erp.Site/WebVella.Erp.Site.csproj` (around lines 65-68), and that target is itself commented out. No project declares a managed reference to it.

## Security-driven dependency changes

Four version changes were made during the OWASP Top 10 (2021) audit remediation. They are the *only* dependency changes: **no package was added and no package was removed.** Each change below names the advisory it closes, the weakness class, the exact declaration site, and why that specific target version was chosen rather than a newer one. A fourth change - AutoMapper - closes the graph's only High-severity advisory but carries an unresolved licensing question, and it is recorded first because a change with a legal consequence needs more justification than a routine one, not less.

### AutoMapper `[14.0.0]` to `[15.1.3]` (finding H-01)

* **Declaration site:** `WebVella.Erp/WebVella.Erp.csproj` (the `AutoMapper` reference, now preceded by the inline decision record that accompanies the pin).
* **Advisory:** `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933` - denial of service through uncontrolled recursion, **CWE-674**. Severity **High**; this is the only High-severity advisory anywhere in the dependency graph.
* **Affected range:** all versions below 15.1.1, and separately the 16.0.0 line below 16.1.1. **There is no patched release under a permissive licence** - the fix begins at 15.1.1, which is already under the Reciprocal Public License 1.5.
* **Why `[15.1.3]` and not something newer:** it is the newest release on the *lowest* patched major, so it closes the advisory with the least behavioural drift. The 16.x line clears the advisory as well, from 16.1.1, but crosses a second major boundary for no additional security benefit.
* **How the advisory is closed:** by the version change itself, not by suppressing the detector. `dotnet restore WebVella.ERP3.sln` completes with zero `NU19xx` diagnostics and `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports no vulnerable packages. **`Directory.Build.props` contains no `NuGetAuditSuppress`, no `NoWarn` and no `WarningsNotAsErrors`** - verify with `grep -nE 'NoWarn|WarningsNotAsErrors|NuGetAuditSuppress' Directory.Build.props`, which returns nothing.
* **What remains open is the licence, not the advisory.** 15.1.3 declares its terms as a licence *file* that resolves to the Reciprocal Public License 1.5, while this repository declares `Apache-2.0` in four packable manifests and publishes packages to nuget.org for unknown downstream consumers. Accepting reciprocal source-disclosure terms - or entering the vendor's commercial agreement - changes a product's effective licensing posture, which is an owner decision and not an engineering one. It is therefore escalated rather than absorbed, and recorded as **`RISK-001`, open**, in [the risk register](docs/security/risk-register.md). The declared licence expression was **not** changed.
* **Code consequence: one argument, at one site.** From 15.x the `MapperConfiguration` constructor requires an `ILoggerFactory`, and this repository has exactly one construction site - `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` - which now passes `NullLoggerFactory.Instance` because the platform performs no AutoMapper logging. `ErpAutoMapper.Initialize`'s signature is unchanged, so neither of its call sites in `WebVella.Erp.Web/ErpMvcExtensions.cs` and `WebVella.Erp.ConsoleApp/Program.cs` was touched, and the 379 `CreateMap<...>` declarations across 32 `Profile` subclasses in 93 source files are untouched.
* **Exploitability, for the licence decision rather than for the advisory:** every mapping is declared statically in source, no user-controlled mapping configuration or type graph reaches the configuration builder, and the impact class is availability at start-up rather than disclosure or execution. That assessment is what makes the fallback option - holding the pin behind a recorded acceptance - defensible if the owner declines the terms. It is context for a decision, not a substitute for one.

The blast radius that an upgrade *would* have had is measurable rather than asserted, and is recorded here so the owner can size the decision:

```bash
grep -rho 'CreateMap<' --include='*.cs' . | wc -l                    # 379
grep -rhoP 'class\s+\w+\s*:\s*Profile\b' --include='*.cs' . | wc -l  # 32
grep -rl 'AutoMapper' --include='*.cs' . | wc -l                     # 93
grep -rn 'new MapperConfiguration(' --include='*.cs' .                # exactly one site
```

The trailing parenthesis in the last command is deliberate: without it the pattern also matches the three `new MapperConfigurationExpression()` sites, which are mapping *registries* rather than configuration constructions.

**The gate reports advisories individually, and that was tested rather than assumed.** Injecting an unrelated vulnerable package (`Newtonsoft.Json 9.0.1`) into the core manifest made the build fail with `NU1903` naming a *different* advisory, `GHSA-5crp-9r3c-p9vr`; removing it restored a clean restore. So a clean result is not a blanket silence that would mask the next advisory - each one is reported on its own terms, and the AutoMapper advisory disappeared from the output because the package version changed, not because the detector was told to ignore it.

**Why the inert seam sits in `Directory.Build.props` rather than in the core manifest.** This matters only if the owner ever decides `RISK-001` the other way, so it is recorded now while the measurement is fresh. NuGet audit runs **per project**, and `WebVella.Erp` is referenced by every other project, so AutoMapper is present in 16 project graphs transitively. While the vulnerable version was still pinned, a project-scoped suppression placed in `WebVella.Erp.csproj` silenced only that one project and the solution restore still failed - measured at exactly 15 `NU1903` errors, one per remaining affected project. Repository-wide placement would therefore be a necessity of how the audit is scoped rather than a widening of scope; the seam still names exactly one advisory code and no wildcard. None of it is in force: the pin is at `[15.1.3]` and the seam remains commented out.

### MailKit 4.14.1 to 4.17.0 (finding H-20)

* **Declaration site:** `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L28`.
* **Advisory:** `GHSA-9j88-vvj5-vhgr` / `CVE-2026-41319` - STARTTLS response injection through an unflushed stream buffer, enabling an authentication-mechanism downgrade, **CWE-74**. First patched in 4.16.0.
* **Why this shape of fix:** this single line edit clears **two** advisories, because MailKit 4.17.0 depends on MimeKit 4.17.0. No separate MimeKit `PackageReference` was added, and none should be: adding one would duplicate a constraint the mail library already expresses, and would then have to be maintained in lockstep with it.

### MimeKit 4.14.0 to 4.17.0, transitively (finding H-20)

* **Declaration site:** none. It is resolved through MailKit, as described above.
* **Advisory:** `GHSA-g7hc-96xr-gvvx` / `CVE-2026-30227` - CRLF injection in a quoted local part, enabling SMTP command injection and message forgery, **CWE-93**. First patched in 4.15.1.
* **Why it matters here specifically:** the mail plugin handles user-influenced recipient addresses, *and* it disabled transport certificate validation at five sites (finding H-11). An injection flaw compounding with an absent certificate check is materially worse than either weakness alone, which is why the mail stack was treated as a priority rather than a routine version bump.

### Microsoft.AspNetCore.Components.WebAssembly.Server 7.0.13 to 10.0.1 (finding H-18)

* **Declaration site:** `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` (line 10 before the change, line 12 after it), accompanied by retargeting both `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` from `net7.0` to `net10.0`.
* **Weakness class:** **CWE-1104**, use of unmaintained components. This is not a CVE remediation; no advisory is outstanding against the 7.0.13 package. It is an *unsupported-component* remediation: the .NET 7 line stopped receiving security patches on **2024-05-14**, so any future advisory raised against it would be permanently unfixable.
* **Context:** 17 of the 19 projects already targeted `net10.0`; only these two lagged. After the retarget all 19 projects target the same supported framework line. They also sit under the same dependency-audit and analyzer regime as the rest of the repository, because that regime comes from `Directory.Build.props` at the root - which is inherited by project location, not by solution membership. One caveat survives the retarget and is easy to miss: these two projects are still **not solution members**, so solution-wide commands continue to skip them and they must be audited explicitly, exactly as shown under *How to reproduce this inventory*.

### Packages deliberately not changed

Every other active package is **advisory-free**, and that is a scanner result rather than an assertion. The evidence is the same two figures given under *What the advisory check actually reports*: the vulnerable-package listing names exactly **one** advisory identifier across the whole solution, and that one identifier is AutoMapper's. Any second unpatched package would necessarily add a second identifier to that output.

No upgrade is proposed for any of them, because the remediation guideline in force is to choose the solution requiring the least modification, and a version change with no security justification is a gratuitous change.

The honest limit on this claim: `dotnet list package --vulnerable` reports what the GitHub Advisory Database knew at the time it was run, for packages that have a published advisory. It cannot speak to unreported vulnerabilities, to the committed native binary described above, or to the browser-side assets that are out of scope for this inventory. It is a floor, not a proof of safety.

Three cases are worth stating explicitly, since each has a *newer* version available and each was still left alone on purpose:

* **Npgsql `[9.0.4]`** - a newer release of the data provider exists, but the pinned version is already safe; its only advisory does not reach the 9.x line at all.
* **Newtonsoft.Json 13.0.4** - well past both of its historical advisories.
* **System.IdentityModel.Tokens.Jwt 8.15.0** - far beyond the versions its advisories affect.

## Licensing decision: AutoMapper

**RECORDED ESCALATION - the advisory is closed; the licensing question is open and belongs to the repository owner.** The pin is raised to `[15.1.3]`, so `GHSA-rvv3-g6hj-g44x` no longer appears anywhere in the dependency graph and the gate passes on its own terms rather than by suppression. What is *not* settled here is whether this project accepts the licence those patched versions ship under, because that is a decision about the product's licensing posture and not an engineering one.

The escalation, in one paragraph: **an automated remediation may close an advisory, but it must not silently change the effective licence of a product that publishes packages to third parties.** Every version of AutoMapper that patches `GHSA-rvv3-g6hj-g44x` is licensed under the Reciprocal Public License 1.5, whose source-disclosure obligation sits uneasily with a project that declares Apache-2.0 and publishes to nuget.org for unknown downstream consumers. The security fix is therefore applied and visible, the licence conflict is stated rather than absorbed, and the choice between accepting those terms, entering the vendor's commercial agreement, relicensing, or formally accepting the advisory instead is recorded as `RISK-001`, **open**.

The facts, all verifiable from package metadata:

* **AutoMapper 14.0.0**, the version previously pinned, declares `<license type="expression">MIT</license>`.
* **AutoMapper 15.1.3**, the version required to close `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933`, declares `<license type="file">LICENSE.md</license>` instead. That file states that the code is governed by the **Reciprocal Public License 1.5** (<https://opensource.org/license/rpl-1-5/>), and offers a separate commercial License Agreement as the alternative for anyone unwilling to release the source of software built with it.
* **This repository declares Apache-2.0** at `WebVella.Erp/WebVella.Erp.csproj:L14`, ships a matching `LICENSE.txt`, and publishes packages to nuget.org for third-party consumption.

The conflict is therefore substantive rather than cosmetic. A reciprocal licence's source-disclosure obligation is incompatible with distributing packages under a permissive expression to unknown downstream consumers. And there is **no patched MIT-licensed line to retreat to**: the fix begins at 15.1.1, which is already under the new terms.

**The current state of the repository is the upgrade at `[15.1.3]`.** The High-severity advisory is closed and the dependency gate passes - verified by `dotnet restore WebVella.ERP3.sln` completing with zero `NU19xx` diagnostics and by `dotnet list ... --vulnerable --include-transitive` reporting no vulnerable packages. The cost of that position is accepting the Reciprocal Public License 1.5 terms (or entering the vendor's commercial agreement) and reconciling them with the project's own Apache-2.0 declaration and its published packages. The declared licence expression was **not** changed and the upgrade was **not** reverted, so the conflict is visible and undecided rather than silently absorbed in either direction.

If the owner is unwilling to accept those terms, the alternatives are a matter of formal risk governance rather than something this inventory should prescribe. This document deliberately **does not set out a procedure for downgrading to a version with a known High-severity advisory, or for suppressing the gate that detects one** - publishing a ready-made way around a security control belongs in neither a dependency inventory nor any other document a reader might follow without the accompanying decision record. Any outcome other than the current one requires a formally recorded, justified risk acceptance, and that process is governed in [the risk register](docs/security/risk-register.md).

The relevant entry there is **`RISK-001`**, which records the decision as **open**, sets out the available options with the reasoning behind each, and carries the exploitability assessment for this codebase - namely that every mapping is statically declared in source and no user-controlled mapping configuration or type graph reaches the configuration builder, so real-world exposure is low despite the High rating. That assessment is context for a decision, not a licence to skip one.

One consequence should be stated plainly: because the gate promotes advisory diagnostics to build errors, this decision cannot simply be left to drift. Whatever is decided has to be recorded in the risk register, which is where the decision and its rationale belong.

### There is no patched permissive line to retreat to

This is the fact that turns a routine version bump into an owner decision, and it was established against the package registry rather than assumed. AutoMapper has 235 published versions, of which 8 are at or after the first patched release. The `.nuspec` of **every** patched version was read:

| Version | Licence declaration | Patched? |
|---|---|---|
| 14.0.0 | `<license type="expression">MIT</license>` | No - the pre-audit pin |
| 15.1.1 | `<license type="file">LICENSE.md</license>` - RPL 1.5 | Yes |
| 15.1.2 | `<license type="file">LICENSE.md</license>` - RPL 1.5 | Yes |
| 15.1.3 | `<license type="file">LICENSE.md</license>` - RPL 1.5 | Yes - **current pin** |
| 16.1.1 | `<license type="file">LICENSE.md</license>` - RPL 1.5 | Yes |
| 16.2.0 | `<license type="file">LICENSE.md</license>` - RPL 1.5 | Yes |

Reproduce for any version:

```bash
curl -s https://api.nuget.org/v3-flatcontainer/automapper/index.json                     # 235 versions
curl -s https://api.nuget.org/v3-flatcontainer/automapper/15.1.3/automapper.nuspec | grep -i license
```

So the choice was never "patched versus unpatched at equal licensing cost". It was "unpatched under MIT, or patched under a reciprocal licence". There is no third option available from the registry.


## Method and limitations

Stated plainly, so that the confidence attached to each claim is visible:

* **The manifest inventory is first-hand.** All 19 `.csproj` files were parsed with XML comments stripped, and the resulting live set (33 packages) and commented set (15 entries) are reproduced above exactly, including which project declares each reference.
* **The advisory state is scanner-derived, and the coverage split is stated rather than glossed.** `dotnet list package --vulnerable --include-transitive` was run solution-wide, and since the two WebAssembly projects were added to the solution it reaches all **19** projects, so nothing has to be scanned separately any more. Each of those runs, together with its restore and build result and the resolved framework target, is recorded verbatim in *Recorded results* under *How to reproduce this inventory*, so nothing in the advisory sections rests on narrative assertion and every row can be re-executed. Where an earlier revision of this document said a solution command reached only 17 projects, that was true of the solution as it then stood and is no longer true of the corrected one.
* **Detection versus enforcement - these are different claims, and this document keeps them apart.** The .NET SDK already *detects* advisories on its own: `NuGetAudit`, `NuGetAuditMode=all` and `NuGetAuditLevel=low` are SDK defaults, so a vulnerable package produces an `NU19xx` diagnostic with no repository configuration whatsoever. But an SDK-default diagnostic is only a **warning**, and a warning stops nothing - a build with one still succeeds and a pipeline built on it still reports green. What the repository adds is *enforcement*: `Directory.Build.props` appends `NU1901;NU1902;NU1903;NU1904` to `WarningsAsErrors`, which every project inherits (evaluated `WarningsAsErrors` is `;NU1901;NU1902;NU1903;NU1904;NU1605;SYSLIB0011`), turning any advisory at any severity into a restore failure. Wherever this document says the gate *passes*, it means the enforced form: restore exits 0 **and** would have exited non-zero had an advisory been present.

	That promotion was verified by differential control rather than assumed, because the only way to prove a gate fires is to make it fire. The same throwaway project pinning the same known-vulnerable package was restored twice on the same SDK, with `Directory.Build.props` inheritance as the single variable:

	```text
	# inside this repository - inherits Directory.Build.props
	negctl.csproj : error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a
	                known high severity vulnerability, GHSA-rvv3-g6hj-g44x
	Failed to restore negctl.csproj (in 194 ms).          -> exit code 1

	# same project, same SDK, in a directory outside this repository - no inheritance
	negctl.csproj : warning NU1903: Package 'AutoMapper' 14.0.0 has a known high
	                severity vulnerability, GHSA-rvv3-g6hj-g44x
	Restored negctl.csproj (in 251 ms).                   -> exit code 0
	```

	`error` versus `warning` and exit 1 versus exit 0, from one variable, is the whole distinction. Note also what the control implies about scope: enforcement covers only the advisory diagnostics. `EnableNETAnalyzers` and `AnalysisLevel=latest-recommended` are enabled repository-wide, but their `CA*` diagnostics deliberately remain warnings - promoting a pre-existing backlog of that size to errors would demand exactly the wide refactor the remediation's minimal-change constraint forbids. No claim of an enforced *static-analysis* gate is made anywhere in this document.
* **Licences are as recorded in each package's own NuGet metadata**, read from the package `.nuspec` and, where the metadata points at a licence file rather than an SPDX expression, from that file's text. This is how the Reciprocal Public License 1.5 finding for AutoMapper 15.1.3 was established, and how the MIT status of Irony.NetCore, `Microsoft.Web.LibraryManager.Build` and the Apache-2.0 status of morelinq were confirmed. Four packages declare a licence *file* rather than an SPDX expression, and the table above reports the resolved licence rather than the file name: AutoMapper 15.1.3 (`LICENSE.md`), Irony.NetCore (`LICENSE`), `Microsoft.Web.LibraryManager.Build` (`License.txt`) and morelinq (`COPYING.txt`). AutoMapper is the only one of the four whose file resolves to anything other than a permissive licence, which is why it is the only one escalated.
* **Unverified rows are marked as such rather than guessed.** `Storage.Net` 9.3.0 publishes no licence element and no licence URL in its `.nuspec`, so its row reads `Not verified in this environment`. An invented licence string in the document that serves as the evidence base for a licensing escalation would be worse than an honest gap.
* **The committed native binary was inspected directly, and an earlier claim about it was wrong.** A previous revision of this document stated that `ExternalLibraries/libwkhtmltox.dll` carried no metadata at all. That is not correct: it carries Windows version resources that identify it as version `0.12.4`, and it embeds LGPL v3 licence text. Its row and the *Committed native binaries* section now record the version as a fact with the reproduction commands beside it. What remains genuinely unrecorded is the artefact's **provenance and its applicable licence** - there is no manifest, no checksum, no upstream reference and no licence file committed with it - so those, and only those, are still marked unverified. The correction is called out rather than quietly applied, because a document whose purpose is to be falsifiable should show where it was falsified.
* **Advisory identifiers, severities, weakness classes and first-patched versions** were obtained by direct retrieval from the GitHub Advisory REST API, and package version availability and dependency metadata from the NuGet flat-container API. The `web_search` facility returns empty results in this environment, so no claim here rests on it. Where a figure could not be substantiated, it was omitted rather than estimated.
* **Line references** point at the post-remediation state of each file unless a "before the change" line is given explicitly. Line numbers drift as files are edited; the surrounding declaration name is the durable locator.

## Related documents

* [`SECURITY.md`](SECURITY.md) - disclosure policy, supported versions and security posture summary.
* [Security audit report](docs/security/security-audit-report.md) - findings in the mandated eight-field format (FINDING, SEVERITY, CWE, LOCATION, DESCRIPTION, IMPACT, EVIDENCE, REMEDIATION). It is **compiled incrementally**, one vulnerability class per commit, so it covers the classes committed so far rather than the full finding inventory: at present the only finding with a full eight-field record there is **H-01**. The other dependency findings summarised in this document - H-18, H-19 and H-20 - are described here but do not yet have records of their own there. H-19 does appear in that report, but only as a stated precondition of the H-01 verification rather than as its own finding.
* [Remediation log](docs/security/remediation-log.md) - what changed per vulnerability class, on the same incremental basis. It currently records the **Dependencies** class, which is the class this document summarises, and the **Credential integrity** class.
* [Risk register](docs/security/risk-register.md) - accepted risks and open decisions. The AutoMapper licensing escalation above is the open entry `RISK-001`; the register also records the residual AutoMapper exploitability assessment, the credential-hashing algorithm deviations, the analyzer warnings deliberately left unsuppressed, and the deterministic initialisation vector (M-08).
* [Secure configuration guide](docs/security/secure-configuration.md) - operator guidance for running the platform securely.
* [Credential migration guide](docs/security/credential-migration.md) - the credential-hash migration and its operator actions.
* [`LICENSE.txt`](LICENSE.txt) - this project's own licence.

Referenced by path rather than linked, because they are later deliverables of the same remediation and are **not present yet**. A link would imply they exist; and for a page inside `docs/` a link to a missing file also fails `mkdocs build --strict`, which is why this path-reference form is used consistently across the security documentation rather than only here:

* `SECURITY.md` - disclosure policy, supported versions and security posture summary.
* `docs/security/secure-configuration.md` - operator guidance for running the platform securely, including how each required secret is supplied. This is the most consequential of the three gaps: the startup failure messages in `WebVella.Erp/ErpSettings.cs` and `WebVella.Erp/Utilities/CryptoUtility.cs` already send an operator to this path, so a deployment that trips one of those gates is directed at a document that is not there yet.
* `docs/security/credential-migration.md` - the credential-hash migration and its operator actions.
