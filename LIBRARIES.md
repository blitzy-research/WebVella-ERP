# Third-party libraries

This is the third-party dependency inventory referenced from the `### Third party libraries` section of [README](https://github.com/WebVella/WebVella-ERP/blob/master/README.md). It lists the platform's **direct** package references, the one transitive package that carries a security advisory, the shared framework reference, and the one committed native binary - each with the version in use, the project that declares it, what it is used for, and its licence.

> **Status authority.** This document is **not** the authority for the security posture's status.
> Exactly one surface is: the audit report's
> [Status at this revision, gate by gate](docs/security/security-audit-report.md#status-at-this-revision-gate-by-gate) section. Where any statement here disagrees
> with it, that section governs and this one is superseded. This page is authoritative only for the dependency inventory itself.
> Recorded under code-review findings `MAJ-06` and `MAJ-12`.

It is deliberately **not** a full transitive closure. Enumerating every package the restore graph resolves would bury what this product actually declares, which is the question this document exists to answer. *Scope and currency* below states the boundary exactly, and step 2 of *How to reproduce this inventory* gives the command that produces the complete closure for anyone who needs it.

The inventory was produced by parsing **all 19 project manifests in the repository with XML comments stripped first**, so that commented-out entries could never be mistaken for live references. That distinction matters enough to be called out twice in this document: 15 `PackageReference` entries in this repository sit inside XML comments and are therefore absent from the build graph. They are listed separately, under *Commented-out package references*, and must not be read as dependencies of this product.

Scope and currency:

- **Currency is stated as a tree state rather than a date.** This inventory reflects the repository as this commit publishes it — the state after the OWASP Top 10 (2021) security audit and remediation. An earlier revision carried "As of 2026-07-31", which was already stale when this document was next reviewed: evidence gathered in August was added beneath a July currency line, so the date asserted a freshness the content no longer had. A date is the wrong unit for a file that is edited alongside the manifests it describes, so it is withdrawn rather than moved forward. Reproduce the inventory against any checkout with the parsing command named in the paragraph above; the manifests, not a date, are the authority. Four dependency versions changed as part of that work; every changed row is marked in the table below and explained under *Dependency changes made by the security remediation*.
- **In scope:** direct NuGet package references, the one transitive package that carries a security advisory (MimeKit), the shared framework reference, and committed native binaries. Transitive packages other than that one are out of scope by design, per the note above.
- **Out of scope:** browser-side assets. The repository contains 188 `.js` and 5 `.css` files and no `libman.json` or `package.json`, so client libraries are vendored or CDN-loaded rather than version-managed. One CDN-loaded library carries no integrity attribute. That is classified as finding **M-15**, a documented-only Medium, and it belongs in [the security audit report](docs/security/security-audit-report.md) rather than here, because it is not a managed dependency. An earlier revision of this line said M-15 "has not been written up there yet"; **that is no longer true** - M-15 now carries its own eight-field record in that report. The classification is still stated here so the boundary between the two documents is explicit rather than implied.
- This document is also the evidence base for the **open** licensing escalation on `AutoMapper` - the registry facts an owner needs in order to decide it. See *Licensing decision required: AutoMapper*.

> **⚠ Open licensing escalation - `AutoMapper`.** The security fix for `GHSA-rvv3-g6hj-g44x` moves
> this package onto a line licensed under the **Reciprocal Public License 1.5**, which is not
> compatible on its face with the `Apache-2.0` expression this repository declares and publishes
> under. The advisory is **closed** by the upgrade. The licence consequence is **not** closed: it is
> **OPEN, pending owner ratification**, because only the repository owner may decide what licence a
> product declares to third parties. An earlier revision of this note called that consequence
> "decided" and described the reciprocal obligation as an accepted residual. That framing was
> withdrawn under `CR2-F-04`: an agent recording its own disposition as settled is absorption wearing
> the vocabulary of disclosure. There is still no patched release under permissive terms to retreat
> to, and the reversal path would still require a repository-wide `NU1903` suppression that the CI
> negative control also inherits - which would disable the only proof that the dependency gate can
> fail. Those facts frame the decision; they do not make it. The declared expression was not changed
> and the upgrade was not reverted, so the contradiction is visible rather than resolved in either
> direction - and, because visible is not the same as cannot ship, `dotnet pack` now fails with
> `error ERPLIC001`, for every one of the four packages this repository publishes, until an owner
> records a decision. `restore`, `build`, `publish`,
> `run` and every CI gate step are unaffected. Full reasoning, registry evidence, both options and
> the exact execution steps for each are under *Licensing decision required: AutoMapper* below, and as
> `RISK-001` in [the risk register](docs/security/risk-register.md).

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

- **The project-reference path casing must be correct.** Until finding H-19 was fixed, **15 path occurrences** spelled the core project's folder as `WebVella.ERP` while the folder on disk is `WebVella.Erp`: **one project entry in `WebVella.ERP3.sln`, and 14 `<ProjectReference>` elements** spread across project files. Only those 14 are project references in the MSBuild sense - the solution entry is a project registration, and it is the one that breaks a solution-wide restore. On a case-sensitive filesystem that restore failed outright, and the core project - which owned the graph's only High-severity advisory - was silently absent from the audit. Any "clean" dependency-scan result obtained before that fix was worthless. All 15 occurrences are corrected; `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` now returns nothing.
- **Every project must be covered, and coverage is complete at 19 of 19 - by two routes, not one.** `dotnet sln WebVella.ERP3.sln list` returns **17** projects of the **19** tracked `.csproj` files. The remaining two, `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared`, are deliberately **not** solution members and are covered by their own named restore, build and advisory steps, whose output is appended to the same evidence files. So coverage is 19 of 19 while the *solution* is 17 of 19, and the two numbers are not interchangeable - a distinction this section previously collapsed.

  **Why the solution is not simply widened to 19.** The frozen plan authorises exactly one change to `WebVella.ERP3.sln`: the H-19 project-path casing correction (plan section 0.7.1, group 1). Altering solution membership is not a security fix, so enrolling further projects is out of scope however convenient a single-command scan would be. An earlier revision enrolled them anyway and this document recorded that as the intended model; review finding `CR2-F-06` rejected both, the enrollment has been reverted, and the solution file's diff against its base is now exactly the one authorised casing line. Non-membership is a scope boundary, not a coverage gap: `Directory.Build.props` is *directory*-scoped, so both projects inherit the audit and analyzer settings identically, and their dedicated build step asserts each resolved `TargetFramework` by name - which is how finding **H-18**, the end-of-life `net7.0` line both of them once sat on, is re-proved on every push rather than by out-of-band verification.

  What keeps the split honest is the workflow step `Assert solution membership matches the declared coverage model`, which fails in three directions: a tracked project in neither the solution nor the declared list has escaped every gate; a project in both is gated twice and described wrongly here; and a declared project missing from the tree means its explicit steps are running on nothing. The declared list has exactly one home, the job-level `EXPLICITLY_GATED_PROJECTS`, which the assertion reads rather than restates. The measured counts:

```bash
dotnet sln WebVella.ERP3.sln list | grep -c csproj    # 17  <- solution members
git ls-files '*.csproj' | wc -l                       # 19  <- tracked manifests
find . -name '*.csproj' -not -path '*/obj/*' | wc -l  # 19  <- manifests on disk
dotnet list WebVella.ERP3.sln package --include-transitive | grep -c "^Project"    # 17
```

  That 17 and 19 differ by exactly the two declared projects is the point, and it is asserted rather than assumed: 19 tracked manifests, 17 reached by solution-wide commands, 2 reached by dedicated steps, none in neither set and none in both. The toolchain used is the .NET SDK version pinned in `global.json` with `"rollForward": "disable"`, so the toolchain producing these figures is exact and they are reproducible by construction. `"latestPatch"` was carried for a time, on the argument that the `10.0.3xx` feature band selects the audit-mode default and the analyzer rule set; review finding `CR2-F-13` rejected it, because a band bounds the rule set but not rule content or default severities, so an unreviewed patch could change what the gate reports while these figures still claimed to describe it. The accepted cost is that an absent pinned SDK stops the build; adopting a newer one is a deliberate re-baseline, documented in `docs/security/secure-configuration.md`.

### Recorded results

Run on the .NET SDK version pinned in `global.json` (`10.0.302`; `dotnet --info` confirms `global.json` is what resolves it). The pin exists precisely so that audit defaults and analyzer rule sets are reproducible rather than dependent on whatever SDK happens to be installed. The rows are split by scope on purpose: the solution-wide rows cover the 17 solution members, and the per-project WebAssembly rows are the **only** route to the remaining two, which are not members. Together they account for all 19 tracked manifests.

| Scope | Command | Recorded result |
| --- | --- | --- |
| Precondition | `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` | no matches - the casing defect is fixed, so the core project really is in the graph |
| Precondition | `dotnet sln WebVella.ERP3.sln list` | **17** projects of the 19 tracked `.csproj` files. The two WebAssembly rows below are therefore **required** coverage, not corroboration: they are the only route by which those projects are reached, and they additionally assert each resolved `TargetFramework` |
| 17 solution members | `dotnet restore WebVella.ERP3.sln` | exit 0, zero `NU19xx` diagnostics |
| 17 solution members | `dotnet build WebVella.ERP3.sln -c Debug --no-restore -t:Rebuild` | exit 0, **0 errors**, **3,055** warnings as re-measured at this revision, with all 17 members confirmed present in the log. The chain, because it has now moved six times: 3,096 while a repository-root `.globalconfig` armed additional rules; 3,044 once that file was removed; **3,096 again** once `AnalysisLevelSecurity=latest-all` armed the whole Security category through an SDK-shipped configuration instead - the same total by a different mechanism, with no `.globalconfig` in this repository; and **3,094** after the final regression pass replaced two `throw new Exception` statements in `WebVella.Erp/Database/DbFileRepository.cs` with `FileNotFoundException`, clearing two `CA2201` warnings that the file-mutation race fix had introduced; and **3,055** now. That last movement is a **fall of 39**, and it accompanies the checkpoint-review remediation commits `CK-01` through `CK-23` rather than any documentation change - a documentation commit cannot move an analyzer count, which is checkable by rebuilding. Nothing was suppressed to achieve it, and the one analyzer property those commits did touch moved in the **opposite** direction: `GATE-03` narrowed the `CA3001`-`CA3012` `NoWarn` from every project to `WebVella.Erp.Web` alone, which arms more rules rather than fewer. No `#pragma` and no `SuppressMessage` attribute was added anywhere in the range, which is checkable with `git diff 551a9437 a3e9c8ae -- '*.cs' '*.csproj' Directory.Build.props \| grep -E '^[+-].*(NoWarn\|#pragma\|SuppressMessage)'`. The fall therefore comes from code the remediation removed or rewrote, and the security half of it is held to its recorded baseline independently: Gate 1 asserts the 55-diagnostic security baseline has not grown and that the distinct `(rule, file)` pairs match the reviewed allow-list exactly. Unchanged by the reversion from 19 members to 17, measured rather than assumed: the two removed projects emit no diagnostic of their own, and the Client project their build also compiles remains a solution member |
| 17 solution members | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | exit 0; all **17** report `has no vulnerable packages given the current sources`, and the two dedicated rows below bring the audited total to 19 |
| **WebAssembly Server** | `dotnet msbuild … -getProperty:TargetFramework` | `net10.0` - the retarget off the end-of-life `net7.0` line is live, not merely written |
| **WebAssembly Server** | `dotnet restore …Server.csproj --force` | exit 0, zero `NU19xx` diagnostics |
| **WebAssembly Server** | `dotnet build …Server.csproj -c Debug -t:Rebuild` | exit 0, **0 errors**, 53 warnings - all `CA*`/`CS0168`, and every one attributed to a file in the **Client** project, which this command also compiles. The Server project emits none of its own, which is why enrolling Server and Shared in the solution left the solution-wide warning total unchanged. Emits `net10.0/WebVella.Erp.WebAssembly.Server.dll`, and alongside it `WebVella.Erp.WebAssembly.Shared.dll` and `WebVella.Erp.WebAssembly.dll`, confirming this one command also compiles the Client and Shared references |
| **WebAssembly Server** | `dotnet list …Server.csproj package` | `Microsoft.AspNetCore.Components.WebAssembly.Server` requested `10.0.1`, resolved `10.0.1` - the end-of-life `7.0.13` pin is gone |
| **WebAssembly Server** | `dotnet list …Server.csproj package --vulnerable --include-transitive` | exit 0; `The given project 'WebVella.Erp.WebAssembly.Server' has no vulnerable packages given the current sources.` |
| **WebAssembly Shared** | `dotnet msbuild … -getProperty:TargetFramework` | `net10.0` |
| **WebAssembly Shared** | `dotnet restore …Shared.csproj --force` | exit 0, zero `NU19xx` diagnostics |
| **WebAssembly Shared** | `dotnet build …Shared.csproj -c Debug -t:Rebuild` | exit 0, **0 errors, 0 warnings**; emits `net10.0/WebVella.Erp.WebAssembly.Shared.dll` |
| **WebAssembly Shared** | `dotnet list …Shared.csproj package --vulnerable --include-transitive` | exit 0; `The given project 'WebVella.Erp.WebAssembly.Shared' has no vulnerable packages given the current sources.` |
| Both WebAssembly projects | `grep -rn 'net7.0' --include=*.csproj .` | no `TargetFramework` match remains; the only surviving occurrence is inside the comment that explains the retarget |

**Re-verified at this revision, and the advisory state is zero rather than one.** Every row above was re-executed against the tree this commit publishes: `dotnet restore WebVella.ERP3.sln` exit 0 with zero `NU19xx`; `dotnet build … -t:Rebuild` exit 0 with **0 errors and 3,055 warnings** — the figure this row previously gave, 3,044, was measured before `AnalysisLevelSecurity=latest-all` armed the whole Security category and is superseded (review finding `MAJ-07`); `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reporting `has no vulnerable packages` for all **17** solution members with **no** row at any severity; and the two WebAssembly projects reporting the same, one invocation each. So **19 of 19 projects carry no advisory of any severity**. This is worth stating explicitly because the document set has described the graph as holding *one* High-severity advisory in some places and *none* in others, and both were true at different times: `GHSA-rvv3-g6hj-g44x` **was** the graph's only High-severity advisory before the pin moved to `[15.1.3]`, and the graph has held none since. Where a sentence elsewhere reads as present-tense about that advisory, it is describing the pre-remediation state.

Two independent corroborations of the retarget, recorded because a `.csproj` edit alone proves only intent: the compiled `WebVella.Erp.WebAssembly.Server.dll` carries `.NETCoreApp,Version=v10.0` in its metadata, and both WebAssembly manifests evaluate the repository gate exactly as the other 17 projects do, so they are inside the same audit and analyzer regime rather than beside it. Verified per project with `dotnet msbuild <csproj> -getProperty:`, which reports `TargetFramework=net10.0`, `NuGetAuditMode=all`, `AnalysisLevel=latest-recommended` and `AnalysisLevelSecurity=latest-all` for each — the last of those was absent from this sentence while the property was set, which review finding `MAJ-07` reported. That inheritance works because [`Directory.Build.props`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/Directory.Build.props) is *directory*-scoped rather than solution-scoped, which is precisely why it still governs these two projects even though they are **not** members of `WebVella.ERP3.sln`. The solution enumerates 17 projects; these two are covered by an explicit per-project restore, build and advisory listing in the workflow instead, so 17 members plus 2 explicitly gated non-members accounts for all 19 manifests on disk.

Both projects are deliberately **not** solution members. `WebVella.ERP3.sln` enumerates **17** `.csproj` entries and `dotnet sln WebVella.ERP3.sln list` confirms 17, against **19** tracked manifests, so `WebVella.Erp.WebAssembly.Server.csproj` and `WebVella.Erp.WebAssembly.Shared.csproj` are reached only by the per-project rows above - which is why those rows are required coverage rather than corroboration.

An intermediate revision enrolled both and this section was rewritten to present that as the intended model, describing the earlier 17-of-19 graph as a gap that had been "closed properly". Review finding `CR2-F-06` rejected that: the frozen plan authorises exactly one change to the solution file, the H-19 casing correction, so the enrollment was scope drift and the 17+2 split is the intended model rather than a shortfall. The enrollment has been reverted and this paragraph corrected in place rather than quietly replaced, because a security document that silently changes its own account of coverage is the problem the finding describes. Membership is asserted on every run by `Assert solution membership matches the declared coverage model`, which fails if a tracked project is in neither the solution nor the declared non-member list, if a project is in both, or if a declared project is missing from the tree.

The per-project restore, build and advisory steps also assert each resolved `TargetFramework` explicitly - an out-of-support target is something a successful solution build cannot rule out on its own - so H-18 is re-proved on every push despite non-membership.

These commands are not left to be run by hand. `.github/workflows/security-scan.yml` runs every one of them, so the coverage described here is reproducible rather than a one-off local observation. Two honest qualifications on that. First, the workflow does not restate the SDK version: it resolves the toolchain with `global-json-file: global.json`, so the pin has exactly one home and cannot drift out of step with the build. Second, its steps were validated by parsing the YAML and executing each `run:` step in order against this working tree under `bash`, which is the shell GitHub actually uses for a `run:` block. **The counts in this paragraph have moved four times and are re-measured at each revision rather than carried forward.** The file now declares **25** steps, of which three are `uses:` actions rather than shell, leaving **22** shell steps. Twenty of the twenty-two are the evidence-gathering gates, and all twenty were executed and **all twenty exited 0** at this revision, in a single ordered pass whose per-step exit codes were recorded; the remaining two are the matrix and release-gate steps described immediately below, which are red by design. Earlier revisions of this sentence read *eighteen steps, fifteen shell, fourteen evidence-gathering*, before that *sixteen*, and before this one *23 steps, 20 shell, nineteen evidence-gathering, all nineteen exiting 0* — superseded under code-review findings `MAJ-01` and `MAJ-03`, which added the terminating taint scan and the mandated-header compliance step. The figures are stated here so a reader can see the shape grow rather than find a silently updated number.

**Two shell steps are different in kind and must not be counted alongside the evidence-gathering ones.** `Gate 5 - record the AAP verification matrix with an evidence-derived status` and `Release gate - every mandatory manual scenario must be attested` are **expected to exit non-zero on this tree**, and the reason has changed since this paragraph was written. It used to be that **24 of the 28** mandatory manual scenarios were unattested; **that is superseded — all 32 manual scenarios are now executed and attested** in the tracked `manual-verification-results.txt`, each line bound to a commit, to the hash of its own scenario text and to a named environment, so `deferred=0` and no manual row blocks anything (review finding `MAJ-06`). What makes those two steps red now is a single row, `A17`: the mandated Content-Security-Policy is delivered under its **report-only** name, which does not satisfy a requirement for an enforced header set, and review finding `MAJ-03` refused the alternative of rewriting the check to accept the substitute name. So the matrix prints `RELEASE-READY=no` and the release gate exits non-zero **by design, over an acceptance criterion that is genuinely unmet and awaits an owner decision** — not over missing verification. That is the step working, not failing: before it existed every manual scenario could sit unproved while the job reported success, so a green workflow did not mean what a reader would reasonably take it to mean. Both are reported here as red-by-design rather than folded into the "all exited 0" count, because a document that averaged the two would recreate exactly the ambiguity the finding identified.

That sentence previously appeared here while **two** steps could not pass, which is review finding `CR2-F-05`, and the correction is recorded rather than simply overwritten because the failure mode was the evidence and not the gate:

- **Gate 3, the secret sweep, aborted before it finished.** Three separate implementations had been spliced into one step, and the surviving fragments referenced variables the others defined - `$want`, `$sweep_dir` and `$engine` - so under `set -u` the step died partway through with `want: unbound variable`. It has been rebuilt as one implementation: the capability self-test, the repository-wide layered sweep, one reviewed allow-list, the targeted C-04 and C-01 regression assertions, and the history audit.
- **Gate 1, the analyzer ratchet, had never been able to pass at all.** MSBuild compiles projects on parallel nodes and prefixes each diagnostic line with the node id, so the parse captured `    17>` and the leading indentation *into the file field*. Nothing could then equal its allow-list entry, and `comm` declared all 42 security diagnostics unreviewed and all 21 accepted residuals stale in the same breath. Stripping the node prefix reduces the parse to 21 pairs matching the allow-list exactly - 0 unreviewed, 0 stale - and collapses per-node duplicates, taking the all-category count down to the distinct `(rule, file)` pairs the gate actually compares - ~~**631** as re-measured on the tree this commit publishes, from 6,034 raw CA diagnostic lines~~, **re-measured under code-review finding `MAJ-07` as 641 distinct `(rule, file)` pairs from 6,056 raw CA diagnostic lines, which reduce to 3,028 unique `(file, line, column, rule)` diagnostics**. A fail-closed guard now stops the job if that normalisation ever regresses, because the symptom of the bug was a gate that could not pass however clean the tree was.

Neither was found by reading the file. Both were found by running it, which is the only reason this paragraph can now state an exit code rather than an intention.

The pass was then repeated after the documentation in this repository was reconciled, and the repetition earned its keep: Gate 3 failed, correctly, on **this very documentation set** - the drafted account of the negative test had reproduced the planted assignment verbatim, and the sweep's envelope covers `.md` files precisely because a credential published in prose is published exactly as surely as one in a `.cs` file. The prose was rewritten to name the property and the value separately, which is the documented remedy, and never the pattern narrowed. All fourteen evidence-gathering shell steps then exited 0 again. A gate that catches the document describing it is a gate that is actually reading the tree.

The measurements below are the recorded results of that pass.

> **They are labelled historical, and here is exactly what has moved since.** The run below was executed
> against the tree as it stood at `2026-08-04T05:39:57Z`, and it is retained unaltered because it is the
> evidence for the state it measured. Several of its figures no longer describe this revision: the workflow
> held **sixteen** steps then, then seventeen, then 23, and holds **25** now, of which **22** are `run:`
> blocks; the Gate 5 matrix declared **32** rows then, then 33, 41, 45, 48, and declares **50** now; and the
> published evidence set has grown from twenty paths to **24**. Its verdicts have moved too, in both
> directions. Gate 5 was recorded here as **DEFERRED** because **24** mandatory scenarios had not been
> executed; **that is superseded — all 32 manual scenarios are now executed and attested**, so `deferred=0`
> (review finding `MAJ-06`). What is *not* superseded is that release readiness is still gated: the matrix
> now carries a row that **fails by design** because the mandated Content-Security-Policy is delivered under
> its report-only name, so `RELEASE-READY` still prints `no` — for a genuinely unmet acceptance criterion
> rather than for missing verification (review finding `MAJ-03`). Current figures and the gate-by-gate status
> for this revision are stated once, each with the command that produces it, in
> [Status at this revision](docs/security/security-audit-report.md#status-at-this-revision-gate-by-gate) in
> the audit report; where that section and the table below disagree, the table is the older measurement.
>
> **The most recent full ordered pass is not the one below.** Every `run:` step of the current 25-step
> workflow was extracted from the parsed YAML and executed in order against the tree this commit publishes.
> **All 19 evidence-gathering shell steps exited 0**, and the release gate exited `1` by design. The results
> that matter for dependency governance are stated once, immediately after this table, under
> *The authoritative dependency result at this revision*.

That sequence was executed in workflow order against the tree as it stood at commit `daf4aa90`, completing at **2026-08-04T05:39:57Z** - the timestamp the last step stamps into `manual-verification-matrix.txt`, so the run is anchored to a machine-written record rather than to this sentence. An earlier pass of the same sequence completed at 2026-08-04T00:50:03Z against a partial tree; the later timestamp is the one that describes what this commit contains, and it is stated rather than the earlier one because a gate record must name the tree it actually read. It ran against the working tree at parent commit `daf4aa90465bfad856cf3afb4540d147b7026ded` plus the modifications that commit introduced - a gate run necessarily predates the commit it validates, so the hash the artifacts recorded is the parent's rather than that commit's. **All 14 evidence-gathering shell steps exited 0 in that pass, and the aggregate exit status across those fourteen was 0** - fourteen being the whole evidence-gathering set as the workflow then stood; it is nineteen now, and the current pass is recorded above. The release gate described above did not exist when this pass ran and is red by design until manual attestations are committed, so it is excluded from that aggregate rather than silently absorbed into it. Every figure in the table below was read back out of the evidence artifact its own step wrote during that run - none of it is restated from an earlier draft, and where a step no longer exists its row has been removed rather than left standing:

| Step | Recorded result of the 2026-08-04T05:39:57Z run, except where a row is marked re-measured |
|------|--------|
| Casing assertion (H-19) | no `WebVella.ERP\` reference survives in any `.sln` or `.csproj`; **45** `ProjectReference` targets across the 19 manifests all resolve case-sensitively against the paths on disk |
| Solution-membership assertion | 19 tracked `.csproj`, **17** solution members and **2** declared non-members, the two sets disjoint and together exhaustive - so no project can sit outside the audited graph, in either direction. The declared set has exactly one home, the job-level `EXPLICITLY_GATED_PROJECTS`, which the assertion reads rather than restates |
| `dotnet restore WebVella.ERP3.sln` | exit 0, zero `NU19xx` |
| `dotnet build … --no-restore --no-incremental` | *(historical: **3,055** at this revision, see the row above)* `Build succeeded.` **0 errors**, **3,093** warnings; every diagnostic a project-level warning, none promoted. The figure rose from 3,044 to 3,096 when `AnalysisLevelSecurity=latest-all` armed the whole Security category, then fell by two when the final regression pass cleared the `CA2201` warnings its own file-mutation race fix had introduced |
| WebAssembly Server + Shared, explicitly | restored, built and audited one project per invocation; both resolve `net10.0` and both report `has no vulnerable packages` |
| Supported-framework assertion (H-18) | every one of the **19** resolved `TargetFramework` values reads back as `net10.0` - the 17 solution members through the solution-scoped analyzer build, and the two gated non-members through `Build the explicitly gated projects and assert their target framework`, which reads each resolved value one project per invocation (passing two project arguments to a single `dotnet build` fails with `MSB1008`) and fails on anything outside the supported set |
| Gate 1 - SAST | 94 Security-category rule ids derived from the pinned SDK at run time - a **catalogue lookup** of which ids belong to the category, not a claim that all 94 ran. ~~Only four Security rules execute at `AnalysisLevel=latest-recommended` with no global analyzer config present~~ — **superseded under code-review finding `MAJ-07`:** `AnalysisLevelSecurity=latest-all` ships in `Directory.Build.props`, so the category is armed in full (and still promoted nowhere), and **five** rules report on this tree — `CA2100` 20 diagnostics across 8 files, `CA2326` 20 across 6, `CA2328` 9 across 4, `CA5351` 5 across 2, `CA5362` 1 across 1: **55 diagnostics over 21 `(rule, file)` pairs**, every pair carrying a written disposition and a resolvable `RISK-nnn` reference, with the unreviewed set empty and no stale entry. This remains a bounded gate and is described as one: the boundary is what the allow-list accepts, not which rules run |
| Gate 1 positive control | a throwaway project carrying nine deliberate defects was compiled and **all nine** rules were asserted present in the build log - `CA5350`, `CA5359`, `CA5364`, `CA2100`, `CA2326`, `CA2327`, `CA5390`, `CA5401` and `CA5404` - proving the analyzers report defects rather than merely running. Every assertion is **anchored to the probe's own file**, because `CA2100`, `CA2326` and `CA2327` have real occurrences elsewhere in this repository and an unanchored check would have been satisfied by those instead of by the deliberate defect. The control asserts **both directions**: those nine MUST fire, and `CA3001`-`CA3012` MUST NOT, against deliberate taint flows the probe also contains - flows measured to emit `CA3001` and `CA3003` when the exclusion is lifted, which is what makes the silence evidence rather than an absence of it. All are warnings, not errors, so the probe build exits zero; the assertion reads the LOG rather than the exit status either way, and a separate guard fails the step if the probe itself failed to compile, since a probe that did not compile makes every assertion vacuous. Measured details worth keeping: `CA5359` fires on `ServicePointManager.ServerCertificateValidationCallback` but **not** on `HttpClientHandler.ServerCertificateCustomValidationCallback`; and `CA5390` fires on the `CreateEncryptor(rgbKey, rgbIV)` overload taking a hard-coded key, **not** on assigning a literal array to `SymmetricAlgorithm.Key`. `CA5382`, `CA5383` and `CA5402` are armed but no probe has made them speak, so they are deliberately absent from the ratchet rather than baselined at zero - carried as `RISK-137`. |
| Gate 2 - `dotnet list package --vulnerable --include-transitive` | **RE-MEASURED at this revision and unchanged:** 19 of 19 projects report `has no vulnerable packages`, and no row matches `High` or `Critical` - the **17** solution members through the solution-wide listing and the **2** declared non-members through their own, so the total is reached by two routes. The listing now additionally asserts that every solution member actually appeared in its output, which is what makes the count non-vacuous; see *The authoritative dependency result at this revision* above |
| Gate 3 - secret sweep | the detector first proves itself against a synthetic credential planted for **every** layer across ten file formats - the required `(layer, fixture)` pairs must all fire and no layer may fire on the benign shapes this repository carries - and only then sweeps the tracked text tree, reporting **0 credential-shaped locations and 0 tolerated**. The same step asserts that exactly the **8** audited `Config.json` files are tracked *by name in both directions*, that each has its required keys present and empty with `DevelopmentMode` false, that `WebVella.Erp.Site/web.config` sets `ASPNETCORE_ENVIRONMENT=Production`, that no compiled-in key material or literal seed credential remains in source, and that the C-01 rotation migration is still implemented; it also audits the reachable commit history for exposure. Matched locations are reported as path and line only - never the matched text - so the gate cannot publish the credential it detects |
| Linux startup smoke (CFG-03) | **8 / 8** published artifacts - all seven hosts and the console application - resolved the exact `Config.json` from their own deployment directory and then stopped at the fail-fast secret validation |
| Gate 2 negative control | observed `error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x` |
| Gate 5 - AAP 0.9.1 verification matrix | **RE-MEASURED at this revision: 50 rows — 18 evidence-derived A-rows and 32 manual M-rows; `deferred=0` because every manual row is attested, and `RELEASE-READY=no` because row `A17` fails by design.** The 2026-08-04 run declared 32 rows; the figure went to 41, 45, 48 and now 50 as scenarios were added for controls that had none — most recently `A17` for the mandated-header-name compliance verdict (`MAJ-03`) and `A18` for the terminating taint scan of the excluded compilation (`MAJ-01`). **This row previously read *20 proven, 25 deferred*, which is superseded**: all 32 manual rows have since been executed against disposable hosts and live PostgreSQL databases and carry committed, commit-bound attestations, each additionally bound to the hash of the scenario text it was executed against — so rewriting a scenario invalidates its own attestation and forces re-execution, which is what happened to `M06` when `MAJ-03` corrected it. Each proven A-row cites the required lines it found in a named artifact from the same run. The one remaining failure is the acceptance criterion itself, not a gap in verification |

The controls are the important rows: every other assertion is green-when-clean, and a green run is indistinguishable from a gate that has silently stopped working. The Gate 2 negative control, the Gate 1 positive control and the Gate 3 self-test exist to make that distinction observable, and all three fired in the run above.

### The authoritative dependency result at this revision

The checkpoint review's finding `GATE-01` was that no *current* dependency status had been demonstrated, so a "zero Critical/High advisories" claim rested on narrative rather than on tool output. This is the answer to it, produced by extracting the workflow's own dependency steps from the parsed YAML and running them against the tree this commit publishes, with the network reaching `https://api.nuget.org/v3/index.json`:

| Assertion | Result |
|-----------|--------|
| Solution restore with `NuGetAudit` at `all`/`low`, the six `NU19xx` codes promoted to errors | exit 0, **zero** `NU19xx` diagnostics |
| `dotnet list package --vulnerable --include-transitive` over the solution | **all 17 solution members were enumerated by the listing**, and each reports `has no vulnerable packages`. The enumeration assertion is the non-vacuity half: a listing that silently covered fewer projects than the solution declares used to pass |
| The same listing for the two explicitly gated projects | `WebVella.Erp.WebAssembly.Server` and `WebVella.Erp.WebAssembly.Shared` each report `has no vulnerable packages` |
| Aggregate | `Gate 2 passed - no High or Critical advisory in the dependency graph of the solution or of the 2 tracked projects outside it.` **17 + 2 = 19 of 19, clean.** |
| Negative control, in the same pass | a throwaway project pinned to `AutoMapper 14.0.0` fails restore with `error NU1903`, proving the gate fails on advisories rather than merely printing them |

Two things this does **and does not** settle, stated plainly. It settles the advisory question: at this revision no package in any of the nineteen projects carries a published advisory at any severity, and the mechanism that would catch one is proven to fail rather than warn. It does **not** settle the AutoMapper **licence** question, which is a separate, open owner decision — the pin is on a patched version with nothing suppressed, and `dotnet pack` remains blocked by `ERPLIC001` until a decision record is committed. The `Assert the licence decision record is durable and attributable` step confirms that state rather than papering over it: `decision records: 0 in the working tree, 0 in the commit`.

The **twenty-three** artifacts that run retained - and that the workflow uploads, with an explicit thirty-day retention rather than an inherited default - are `analyzer-build-summary.txt`, `history-exposure-commits.txt`, `security-rule-ids.txt`, `all-ca-diagnostics.txt`, `security-diagnostics.txt`, `security-allowlist.txt`, `security-allowlist-justified.txt`, `security-unreviewed.txt`, `taint-scan-web.txt`, `header-compliance.txt`, `positive-control.txt`, `sln-members.txt`, `tracked-projects.txt`, `declared-non-members.txt`, `extra-projects.txt`, `vulnerable-packages.txt`, `vulnerable-packages-extra.txt`, `vulnerable-packages-wasm.txt`, `secret-sweep.txt`, `startup-smoke.txt`, `negative-control.txt`, `editorconfig-items.txt` and `manual-verification-matrix.txt`. An earlier revision of this paragraph said twelve, a later one said seventeen, then twenty, and, separately, a workflow comment claimed the raw analyzer log was "deliberately not published" under a filename that has never existed; all are corrected. **The three newest are the ones code-review findings `MAJ-01` and `MAJ-03` added**: the justified form of the Gate 1 allow-list, so a reader sees each accepted diagnostic's risk reference and disposition rather than only the tolerance; the terminating `CA3001`-`CA3012` scan of the one compilation the ordinary build excludes; and the mandated-header-name compliance verdict. **This paragraph no longer restates the count from prose** - the workflow derives it, so the sentence and the list are checked against each other by the evidence-completeness step rather than by a reader. The raw log IS withheld, deliberately and under its real name `analyzer-build.txt`: it carries roughly 3,100 diagnostics each stamped with an absolute runner path, so publishing it would broaden internal-path exposure (CWE-532) and bury the security signal in the pre-existing style backlog. What is published in its place is the derived `analyzer-build-summary.txt`, which Gate 1 asserts contains no path separator before it is uploaded - the property that makes it safe to publish - while the raw log is still written locally and is still what every assertion in that step parses, so no evidence is lost. Any failure-log tail the job prints is passed through a self-tested redactor first, so a publish cannot leak the material the gate exists to police. They are written into the workspace at run time and are deliberately **not** committed - `.gitignore` enforces that rather than leaving it to habit - because a committed copy would be a stale record vouching for commits it never saw, which is the failure mode this whole section exists to avoid. One of them, `manual-verification-matrix.txt`, stamps the run identity into its own header (`generated`, `commit`, `ref`, `run`, `release ctx`), so the citation above is traceable to a machine-written record rather than resting on this prose. **A further path has since been added to the upload — the twenty-fourth at this revision — and it is different in kind:** `evidence-manifest.txt` is written by the step `Assert the scan evidence is complete and bind it to the commit`, which refuses to let the publish proceed while any of the twenty-three is absent or empty, digests each one with SHA-256, and records the commit the digests belong to. Before it existed the publish would happily upload nothing and still be green. At this revision that step reports `Evidence complete - 23 file(s) present, each digested and bound to commit` — twenty-three evidence files plus the manifest that vouches for them, hence **24** published paths against a required set of twenty-three. **The count in that message is now DERIVED from the manifest rather than written into the step**, because the previous revision hard-coded "20 files" and the required set grew to 23 while the sentence did not — the same drift review findings `MAJ-06` and `MAJ-07` report across this documentation set, and a figure that is computed cannot repeat it.

**None of this is a substitute for a hosted CI run, which this environment cannot perform.** The commands are proven to work and proven to be committed; the first *hosted* execution will be the one triggered after this branch is pushed, and that run's own artifacts - not this document - are the authority for whatever commit it examines.

### Runtime verification, outside the gate

**Gate 5 defers no row at this revision, and this paragraph is retained as the record of how that state was reached rather than as a current status.** A workflow job has no database, browser or mail server, so every runtime scenario is deferred until somebody executes it and commits an attestation; when this paragraph was written **nineteen** rows were deferred, of which **seventeen** had been exercised by hand on this machine - twelve in full and five in part - against a published host running over HTTPS with a live PostgreSQL 16 instance and a real browser session, on 2026-08-03/04 UTC at the same commit. That work is recorded here because an unexecuted row and an executed one must not read alike - and because the gate itself still reports them DEFERRED, since an attestation is a statement about one deployment at one moment and is not committed for the same reason the artifacts are not.

This section previously said Gate 5 defers eighteen rows and enumerated M01 through M18, which is review finding `OBS-07`. The undercount was not arithmetic: **M19 was absent from this account altogether** while being present in the workflow matrix, so the one scenario covering the WebAssembly logout seam was invisible to a reader auditing coverage from this document. It is enumerated below.

Executed directly, and passing - eleven rows:

| Row | Recorded outcome |
| --- | --- |
| M01, M02 - legacy credential rehashes on login (C-03) | a planted 32-character MD5 value authenticated, the stored value was rewritten as an 84-character PBKDF2 hash in the same request, the next login succeeded against the rehashed value, and a deliberately malformed stored value produced an ordinary failed login rather than an exception |
| M03 - the historical seeded credential is invalidated on an upgraded installation (C-01) | proven on an isolated copy of the provisioned database with an A/B control. With the schema version at head the planted historical credential authenticated, which is what makes the negative attributable; with the version rolled back so the version-4 migration would run, the same credential was refused, the stored hash had been rotated to a CSPRNG-generated replacement that did authenticate, the account was flagged as requiring a password change, the version advanced again, and the one-time operator notice appeared in the host log. The isolated copy was dropped afterwards and the working database was never written to. One qualification: only the *upgrade* half was executed as its own scenario. The fresh-installation half is evidenced indirectly - the historical credential had to be planted before it could authenticate at all, which is possible only because fresh provisioning stored an operator-supplied credential instead, and Gate 3 separately asserts that no literal seed credential survives anywhere in source |
| M06 - the seven mandated headers (M-01, H-15) | present and correct on a dynamically generated response, on a static asset, and on the rate limiter's own refusal; 21 static assets were checked in the browser |
| M09 - the rate limiter refuses a burst (H-16) | a 700-request burst inside a single fixed window: exactly **600** served, the first refusal at request **601**, **100** refusals with status 429, all seven headers present on the refusal, no exception detail in the refusal body, and a request after the window elapsed served normally again |
| M10 - lockout and reset (H-16) | four failures were refused as ordinary failures and a successful login cleared the account counter; once the configured five-failure threshold was reached the account was locked so that even the correct password was refused, and the refusal was recorded server-side |
| M11 - token lifetime and signature binding (H-02, H-03) | a genuine token was accepted, and so was a byte-identical re-signing of it with the same key - the control that makes the negatives meaningful. The same payload with its timing claims shifted back two days was refused, as was the same payload signed with a different key, and the refresh endpoint would not launder the expired token |
| M12 - upload allow-list and download disposition (H-08) | `.svg` and `.html` were refused at upload, an `.svg` renamed to `.png` was refused by content verification rather than by extension, a `.txt` download was forced to `Content-Disposition: attachment` with `X-Content-Type-Options: nosniff`, and an image was still served inline |
| M14 - the two formerly unconditional error paths (H-13) | reproduced with a genuine unplanned server-side exception, not a synthetic one: the response carried a generic message with no stack trace, exception type or file path, while the retained server-side record carried the full stack trace with WebVella frames |
| M17 - a full-record round trip does not write the redaction marker (C-02 ripple) | the highest-risk ripple in the plan, proven in three directions: a round trip with the field as rendered saved and left the hash untouched; a round trip with the redaction marker posted back saved and left the hash untouched; and a control that genuinely changes the password did rotate it, which is what makes the first two non-vacuous |
| M18 - the deliberate key-derivation cost (C-03) | measured by decomposition, because the remediation makes a naive before/after impossible: a failed verification now pays the full derivation on purpose, to equalise timing. Login latency measured **139.2 ms** median; the PBKDF2-SHA256/600,000-iteration derivation measured **119.0 ms** in isolation; the MD5 it replaced computes in **0.000194 ms**, so the pre-change figure reconstructs to **20.2 ms** and the deliberate work factor is **+119.0 ms**. The residual 20.2 ms is corroborated independently by a credential-free `GET /login` at **9.0 ms** median. The same run showed legacy-shape, modern-shape and absent-account failures at 143.7, 139.2 and 134.1 ms - indistinguishable, which is the timing equalisation working |

Exercised in part, with the unexecuted half named rather than absorbed - six rows:

| Row | Executed | Not executed |
| --- | --- | --- |
| M04 - a guest-role account cannot create users or roles (C-05) | the authorization metadata was read back from the migrated database: the guest role id is absent from the read, create, update and delete permission sets on both the `user` and the `role` entity, and the password field is administrator-only for read and update, encrypted, security-enabled, with 12-128 length bounds | the behavioural half needs a guest-role account holding a credential; creating one is provisioning rather than verification, so it was not fabricated to close a row |
| M05 - no password hash in any response or projection (C-02) | every projection row returns the redaction sentinel in place of the hash, for an explicit `password` projection as well as `SELECT *`, with no PBKDF2 or 32-hex value anywhere in the responses; the same projection with no credential is refused outright | the per-role sweep covered administrator and anonymous only, for the same reason as M04 - no guest-role or regular-role credential exists in the installation |
| M07 - restrictive CORS at the two previously permissive hosts (H-14) | on `Site`: a listed origin is echoed, an unlisted one is not, no wildcard is emitted, and the `OPTIONS` preflight answers 204 with HTTPS redirection enabled | `Site.Project`, the second previously permissive host, was not published and run |
| M08 - HSTS and HTTPS redirection outside Development (H-15) | `Strict-Transport-Security: max-age=31536000; includeSubDomains` on the HTTPS response, and a plaintext request answered 307 to the `https` URL | the complementary assertion that the header is *absent* in Development - the host was only ever run with `ASPNETCORE_ENVIRONMENT=Production` |
| M16 - the by-design raw channels still render (H-06 exclusions) | the inline-script channel: the navigation and menu surfaces that emit generated inline script rendered and functioned, with no leaked markup, icons still rendering as glyphs, and a values list single-encoded rather than double-encoded | the HTML-block component half - no page in the seeded installation carries that component, and authoring one is content creation rather than verification |
| M19 - a token copied before logout is refused afterwards, for API use and for refresh (B3-SEAM-01, H-02, H-03) | the **server-side** half, which is the substantive one, was proven directly against a live host and PostgreSQL instance: a bearer token was issued and confirmed working, the session was then ended, and the same token was afterwards refused both for protected API use and at the refresh endpoint - so the sign-out revokes the server-side session rather than only clearing browser storage. The refusal is now recorded as forensic evidence, rate-accounted so that four replays of the same revoked token produced exactly one record carrying neither the token nor the session identifier | the half driven through the **shipped WebAssembly client's own logout control** in a browser. The end-to-end path was not exercised, so this row is reported as partial rather than complete; what was verified is the server-side revocation the client depends on, through the bearer revocation route and the Razor sign-out handlers, which share one implementation |

Not executed at all - two rows, and the reason in each case is a missing piece of infrastructure rather than a judgement that the row does not matter:

- **M13**, the file move and delete actions refused for a non-owner, needs a second file-owning principal.
- **M15**, mail delivery succeeding against a valid certificate and failing against a self-signed one without the explicit opt-in, needs two SMTP servers presenting different certificates.

Two further observations outside Gate 5's row set, with their provenance stated because they were not obtained the same way: the stored credentials in the provisioned database were **read back** and are all in the PBKDF2 form, 84 characters long with the expected version prefix; and the rate-limit partition key was **read out of the source** rather than probed - it maps an IPv4-mapped IPv6 address down to IPv4, so a caller cannot buy a second request budget by switching address family, and it substitutes a fixed label when the remote address is absent rather than leaving the partition unkeyed.

## Where the dependency gate lives

Nobody has to run the commands above by hand for the audit to have teeth: it is enforced on every build by [`Directory.Build.props`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/Directory.Build.props) at the repository root. That file is the mechanism behind the statements later in this document that the dependency gate *passes* and that it *promotes advisory diagnostics to build errors*.

| Property | Value | Effect |
|---|---|---|
| `NuGetAudit` | `true` | Runs the dependency audit as part of restore. |
| `NuGetAuditMode` | `all` | Audits transitive packages as well as direct ones - which is what makes the MimeKit advisory visible at all, since this repository only ever resolves MimeKit transitively. |
| `NuGetAuditLevel` | `low` | Reports at every severity rather than only High and above. |
| `WarningsAsErrors` | appends `NU1900;NU1901;NU1902;NU1903;NU1904;NU1905` | Turns any advisory diagnostic into a **build error**. **Six** codes, not four: the four severity codes `NU1901`-`NU1904`, plus the two data-availability codes `NU1900` and `NU1905`. Including those two is the load-bearing part - without them, an audit that cannot reach the advisory database reports a *warning* and the build goes green, which is a gate that fails open exactly when it matters. An earlier revision of this row listed only the four severity codes and understated the property. The value appends to `$(WarningsAsErrors)` rather than replacing it, so nothing already set is discarded - the .NET SDK's own escalations (`SYSLIB0011`, `NU1605`) are still appended after these six and survive intact. This is the only place in the repository that sets the property. |
| `EnableNETAnalyzers` / `AnalysisLevel` | `true` / `latest-recommended` | Enables the built-in .NET analyzers, which stand in for an external static-analysis scanner. The general categories run at the recommended set. Analyzer diagnostics stay **warnings** at the project level; only the six dependency codes above are build errors. Four rules of the Security category are active at this level and are measured, ratcheted and positively controlled by the workflow: `CA5350` and `CA5351` (weak and broken cryptographic algorithms), `CA5359` (certificate validation disabled) and `CA5364` (deprecated security protocols). Measured repository counts are `CA5350` 0, `CA5351` **5**, `CA5359` 0, `CA5364` 0. |
| No global analyzer config, and no Security-category upgrade | *(deliberately absent)* | Recorded here because their ABSENCE is a deliberate, load-bearing scope decision rather than an oversight, and an earlier revision of this table documented the opposite. Neither `AnalysisLevelSecurity` nor `DiscoverGlobalAnalyzerConfigFiles` is set, and there is no repository-root `.globalconfig`. A global analyzer configuration file is the only mechanism that can deliver a per-rule severity to all 19 projects - the SDK discovers it by walking every directory above each project, so unlike an `.editorconfig` it is unaffected by the four `root = true` files here - and that is precisely why it is not present: the remediation plan freezes this gate at dependency auditing plus the analyzers at the recommended level and states the escalation position explicitly, *only the dependency diagnostic codes become errors*. So the mechanism that would carry a per-rule promotion is absent too, no `EditorConfigFiles` item introduces one by the back door, and the workflow **asserts** on every run that no global analyzer config is being loaded and that `AnalysisLevel` still evaluates to `latest-recommended`. Two consequences follow and are stated plainly rather than left implicit. First, the Security category is **not** raised: only the four rules named in the row above execute, so the silence of `CA2100`, `CA2326`-`CA2328`, `CA5362`, `CA5382`, `CA5383`, `CA5390`, `CA5401`, `CA5402`, `CA5404` and the `CA3001`-`CA3012` dataflow family is **not** evidence about this repository - it means those rules did not run, and the risk register records that explicitly. Second, because the dataflow family never executes, no `interprocedural_analysis_kind` cost tuning is needed or present. |

A repository-root MSBuild properties file is the right mechanism here rather than an `.editorconfig`: four `.editorconfig` files in this repository declare `root = true`, which would stop a root-level style file from reaching their subtrees. `Directory.Build.props` is inherited by all 19 projects regardless of that scoping, because inheritance follows directory location rather than solution membership - and it is the *whole* build-level gate, since no `<CodeAnalysisRuleSet>` file and no global analyzer config accompany it. Confirmed additionally: none of the four `.editorconfig` files sets any `dotnet_diagnostic` severity, so no rule severity is overridden by them. Directory scoping is what makes the gate reach the two projects that are **not** solution members, so inheritance is deliberately broader than membership here; the workflow reconciles the two on every push, asserting that the solution holds exactly 17 projects and that the remaining 2 are explicitly gated.

Two properties of the gate are worth stating, because a gate nobody has tested is indistinguishable from no gate:

- **It contains no active suppressions.** No advisory diagnostic is silenced, in this file or in any project manifest. **Two corrections to an earlier revision of this bullet, both of which a later review caught.** First, it cited a commented-out *suppression seam* — `<NoWarn>$(NoWarn);NU1903</NoWarn>` — at `Directory.Build.props:L457`, and gave the file's length as 409 lines. Neither holds: no such line exists anywhere in the file under any spelling, and the file is **456** lines, so the locator pointed past the end of a file that never contained it. Second, and more consequentially, the file now carries **one genuinely active `<NoWarn>`**, so "no active suppressions" would be false if left unqualified.

  The claim, stated correctly: **no advisory diagnostic is suppressed.** All six `NU19xx` codes are promoted to errors and none is silenced, in this file or in any project manifest. What *is* suppressed is a single analyzer family, deliberately and for a measured reason: `<NoWarn>$(NoWarn);CA3001;…;CA3012</NoWarn>` excludes the interprocedural taint-dataflow rules, because armed and untuned the solution build produced no further output for over thirty-five minutes with 3 of 17 projects finished — `WebVella.Erp.Web` compiles 395 Razor views into a single compilation — while excluded it completes in about 106 seconds. That exclusion is asserted in **both** directions by the workflow: Gate 1 fails if any of the twelve leaves `NoWarn`, fails if any *other* `CA` code is added to it, and the positive control fails if any of the twelve fires against deliberate taint flows that provably emit `CA3001` and `CA3003` when the exclusion is lifted. It is carried as `RISK-138`. Three measurements establish what is and is not suppressed:

    ```bash
    # 1. Strip the XML comments and the only suppression mechanism left is the
    #    taint-family NoWarn - three hits, being the element's open tag, its
    #    $(NoWarn) self-reference and its close tag. No audit-suppression
    #    mechanism appears under any spelling:
    python3 -c "import re;t=open('Directory.Build.props',encoding='utf-8-sig').read();\
    print(re.findall(r'NoWarn|WarningsNotAsErrors|NuGetAuditSuppress',re.sub(r'<!--.*?-->','',t,flags=re.S)))"
    #   ['NoWarn', 'NoWarn', 'NoWarn']
    #   - this asserted output was '[]' until this revision, which was correct only
    #     before the taint family was excluded and contradicted measurement 2 below.
    #     NuGetAuditSuppress is absent from every tracked .csproj, .props and .targets
    #     in the repository, comments included, which is the property this step exists
    #     to establish and which measurement 3 confirms from the other direction.

    # 2. The effective NoWarn any project inherits is the taint family and nothing else -
    #    no NU code appears, so no advisory is silenced:
    dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NoWarn
    #   ;CA3001;CA3002;CA3003;CA3004;CA3005;CA3006;CA3007;CA3008;CA3009;CA3010;CA3011;CA3012
    dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:WarningsAsErrors
    #   ;NU1900;NU1901;NU1902;NU1903;NU1904;NU1905;NU1605;SYSLIB0011
    #   - all six audit codes are promoted - the four severity-graded ones plus
    #     NU1900/NU1905 so the gate cannot fail open - and the SDK's own
    #     NU1605/SYSLIB0011 survive, which is what proves the property appends
    #     rather than replaces.

    # 3. No project manifest suppresses anything either. The scan is driven by
    #    `git ls-files` rather than a bare recursive grep, so that it covers
    #    exactly the 19 tracked manifests and cannot be perturbed by an untracked
    #    scratch or probe project sitting in the working tree:
    git ls-files -z '*.csproj' | xargs -0 grep -nE 'NuGetAuditSuppress|NoWarn'   # no matches
    ```

    **A fourth measurement used to be recorded here, and it is withdrawn in full.** It read that
    `Action="None"` is *"a suppression by another name"* applying to the twelve dataflow rules
    `CA3001`-`CA3012`, that five further rules were *"held at `Warning` ... recorded rule-by-rule
    in the ruleset with their site counts"*, and that *"every other security rule in the file - 95
    of them - is an `Error`"*. **No such file exists, and no `Action="None"` exists anywhere in the
    tree.** Those sentences described a `.ruleset`-based regime that was evaluated and then removed,
    exactly as the `.globalconfig` was, and they survived the removal in the present tense - which
    made this bullet contradict the *No global analyzer config* row above, whose statement that the
    `CA3001`-`CA3012` silence *"means those rules did not run"* is the correct one. Reproduce the
    absence:

    ```bash
    grep -rn 'Action="None"' --include='*.props' --include='*.csproj' \
      --include='*.ruleset' --include='*.globalconfig' . | grep -v '/obj/'   # no matches
    ls *.ruleset .globalconfig                                              # no such file
    grep -rn 'CodeAnalysisRuleSet\|AnalysisLevelSecurity' --include='*.props' \
      --include='*.csproj' . | grep -v '/obj/'                              # no matches
    ```

    One fact inside the withdrawn paragraph is real, was independently measured, and is retained
    because it is the reason the dataflow family is not enabled by any mechanism: with all twelve
    `CA3001`-`CA3012` rules active a full-solution build did not finish inside 3,600 seconds,
    against 161 seconds without them, and only 5 of the 19 projects emitted a diagnostic before the
    timeout. That cost is why raising the Security category is out of scope here - not a suppression
    that closes the rules, but a level that never opens them. The consequence is the same either
    way and is recorded in the risk register: those twelve rules produce no evidence about this
    repository, so their silence must not be read as a clean result.

- **It has been confirmed not blind, on both gates.** For Gate 2, pointing a throwaway project at the pre-remediation `AutoMapper [14.0.0]` makes restore fail with `error NU1903: ... has a known high severity vulnerability`. For Gate 1, a throwaway project containing a weak hash, a disabled certificate-validation callback and a deprecated transport protocol is compiled and `CA5350`, `CA5359` and `CA5364` are each asserted present in the log. Both controls are steps in the workflow rather than one-off manual checks, and Gate 1 is additionally guarded in the *disarming* direction three ways, because a control that cannot detect its own removal is not a control. First, the same probe asserts that `CA5390` and `CA2100` do **not** appear: they do not execute at this analysis level, so if they ever did, the level had silently widened and every baseline here would be stale. Second, the job asserts `AnalysisLevel` still evaluates to `latest-recommended` and that no global analyzer config is being loaded by any route. Third, a liveness oracle fails the job if the build emits no `CA` diagnostic of any category - measured necessity, not theory: an incremental build reported **1** warning instead of the ~3,000 a full build emits, every baselined family counted zero, and the step would have reported an improvement while having compiled nothing. The clean result on the real solution is therefore a real result, not an inert check.

```bash
# The gate's properties as any project sees them after inheritance:
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NuGetAuditMode      # all
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:NuGetAuditLevel     # low
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:AnalysisLevel       # latest-recommended
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:WarningsAsErrors    # contains NU1900;NU1901;NU1902;NU1903;NU1904;NU1905

# AnalysisLevelSecurity and DiscoverGlobalAnalyzerConfigFiles are deliberately NOT set, so both
# evaluate to empty. Assert that emptiness rather than assuming it: a value in either one would
# widen the rule set past the level every baseline and allow-list entry here was measured at.
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:AnalysisLevelSecurity            # (empty)
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getProperty:DiscoverGlobalAnalyzerConfigFiles  # (empty)

# And assert that no global analyzer config reaches the compiler by any route - an untracked file at
# the repository root, or an explicit EditorConfigFiles item, would both show up here. Expect no
# 'globalconfig' line. This is the same check the workflow performs on every run.
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -getItem:EditorConfigFiles | grep -i globalconfig
```

## This project's own licence

WebVella ERP is licensed under the **Apache License 2.0**.

- [`LICENSE.txt`](LICENSE.txt) at the repository root carries the Apache License 2.0 notice - the standard short-form grant referring to <http://www.apache.org/licenses/LICENSE-2.0>, with the AS IS warranty disclaimer. It is a notice, not a verbatim copy of the full licence text.
- **Four projects declare the licence in the manifest** as `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`: `WebVella.Erp/WebVella.Erp.csproj:L32`, `WebVella.Erp.Web/WebVella.Erp.Web.csproj:L13`, `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L10` and `WebVella.Erp.Plugins.SDK/WebVella.Erp.Plugins.SDK.csproj:L10`.
- **Those four are not the only packable projects.** Ten of the 19 projects are packable. The other six - `WebVella.Erp.ConsoleApp`, `WebVella.Erp.Plugins.Crm`, `WebVella.Erp.Plugins.MicrosoftCDM`, `WebVella.Erp.Plugins.Next`, `WebVella.Erp.Plugins.Project` and `WebVella.Erp.WebAssembly/Shared` - declare no licence expression at all, so a package built from any of them would ship without licence metadata. The nine non-packable projects (the seven site hosts, the WebAssembly client and the WebAssembly server) are not affected, because they are never packed. This is a packaging-metadata gap rather than a security finding; it is recorded as an observation and no change to it is proposed here. Verify with:

```bash
for f in $(find . -name '*.csproj' | sort); do
  printf '%-72s packable=%-6s lic=%s\n' "$f" \
    "$(dotnet msbuild "$f" -getProperty:IsPackable -nologo)" \
    "$(grep -o '<PackageLicenseExpression>[^<]*' "$f" | sed 's/.*>//' | head -1)"
done
```

- These projects are published to nuget.org for third-party consumption, which is why the licence of any dependency that carries a reciprocal source-disclosure obligation is a product decision and not merely a technical one.

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

- An object-mapping library pulling a JSON Web Token stack into the graph is unexpected, and it widens the graph that has to be audited.
- The version it pulls - **8.14.0** - sits *behind* the **8.15.0** that the solution already references directly through `System.IdentityModel.Tokens.Jwt`, so it applies downward pressure on the resolved version of the platform's own token-validation library. It does not win *where that direct reference is present*: in the sixteen projects that see `System.IdentityModel.Tokens.Jwt 8.15.0`, NuGet resolves to the higher 8.15.0. In the two projects that do not - `WebVella.Erp` itself and `WebVella.Erp.ConsoleApp` - **8.14.0 is the resolved version**, which is precisely the 8.14.0-and-8.15.0 row recorded in the version-skew table above. The chain therefore produces a skew, not a downgrade: no project ends up with a token library older than the one it asked for.

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

Seven projects declare `<FrameworkReference Include="Microsoft.AspNetCore.App" />` - `WebVella.Erp` (`WebVella.Erp/WebVella.Erp.csproj:L61`), `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Crm`, `WebVella.Erp.Plugins.Mail` (`WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L24`), `WebVella.Erp.Plugins.Next`, `WebVella.Erp.Plugins.Project` and `WebVella.Erp.Plugins.SDK`.

That single reference is the reason the security remediation added **no new package dependency at all**. The ASP.NET Core shared framework already supplies every control the remediation needed:

- the password hasher used to replace unsalted hashing,
- the rate limiter and the request-throttling primitives,
- antiforgery services,
- HTTP Strict Transport Security and HTTPS-redirection middleware,
- the data-protection stack,
- the web encoders used to fix output encoding - specifically `JavaScriptEncoder`, which replaced a hand-written single-character replacement in `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs`,
- and the fixed-time comparison and key-derivation primitives (`CryptographicOperations.FixedTimeEquals`, `Rfc2898DeriveBytes`) used to replace unsalted hashing.

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

- The embedded product banner reads `wkhtmltopdf 0.12.4`.
- The `VS_FIXEDFILEINFO` structure (signature `0xFEEF04BD`) gives **FileVersion `0.12.4.0`** and **ProductVersion `0.12.4.0`**; the `StringFileInfo` block gives `FileVersion` `0.12.4.0`, `OriginalFilename` `wkhtmltox.dll` and `ProductName` `wkhtmltox`.
- The PE optional header's image-version field, at offset `+44`/`+46` from the start of the optional header, reads `0.124` - the same version stamped by the linker. The adjacent field at `+40`/`+42` is the *operating-system* version (`6.0`) and must not be mistaken for it.

**What genuinely is missing** is everything needed to *manage* the artefact, which is the real supply-chain concern:

- no package manifest, so there is no package identity to match against an advisory database the way a `PackageReference` can be matched;
- no recorded provenance - no upstream URL, no build record and no checksum committed alongside it, so its integrity cannot be attested;
- no update mechanism, automated or otherwise.

Because the version *is* known, the artefact can at least be checked against upstream advisories by hand. Anyone doing so should note that `0.12.4` is an old release of a project that is itself no longer actively maintained upstream.

**On the licence.** The binary embeds the verbatim text of the **GNU Lesser General Public License version 3**, which is consistent with wkhtmltopdf's own published licensing. That is reported here as observed evidence, not as a determination: this DLL statically bundles Qt, which is also LGPL-licensed, so the embedded text cannot be attributed to one component from the binary alone, and no licence or attribution file is committed next to it (`ExternalLibraries/` contains only the DLL). An LGPL-family artefact shipped inside an Apache-2.0 repository with no accompanying notice carries attribution obligations that deserve an owner review; that review is a legal question and is deliberately not answered here.

For accuracy: the binary is currently inert. Nothing in the build consumes it. The only thing that ever did was an `XCOPY` post-build target in `WebVella.Erp.Site/WebVella.Erp.Site.csproj` (around lines 65-68), and that target is itself commented out. No project declares a managed reference to it.

## Security-driven dependency changes

Four version changes were made during the OWASP Top 10 (2021) audit remediation. They are the *only* dependency changes: **no package was added and no package was removed.** Each change below names the advisory it closes, the weakness class, the exact declaration site, and why that specific target version was chosen rather than a newer one. A fourth change - AutoMapper - closes the graph's only High-severity advisory but carries a licensing consequence, now recorded as a decision rather than left unresolved, and it is placed first because a change with a legal consequence needs more justification than a routine one, not less.

### AutoMapper `[14.0.0]` to `[15.1.3]` (finding H-01)

- **Declaration site:** `WebVella.Erp/WebVella.Erp.csproj` - **two** sites, because the finding has two halves. The `AutoMapper` reference carries the inline escalation record that accompanies the pin, and the `<PackageLicenseExpression>` at L14 carries the same escalation from the licence side, so a reader arriving at either one is told about the other. What stops the open question from being shipped by accident is a third element, the `ErpAssertAutoMapperLicenceDecisionRecorded` target — and it deliberately does **not** live in this manifest. Four manifests declare the same `Apache-2.0` expression and publish to nuget.org (`WebVella.Erp`, `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Mail`, `WebVella.Erp.Plugins.SDK`), and the other three each reference the core, so each ships a dependency reaching AutoMapper. With the gate in this file alone, packing any of the other three exited 0 and produced a package with no diagnostic - measured, then fixed by moving the target to `Directory.Build.props`, which all four inherit.
- **Advisory:** `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933` - denial of service through uncontrolled recursion, **CWE-674**. Severity **High**; this is the only High-severity advisory anywhere in the dependency graph.
- **Affected range:** all versions below 15.1.1, and separately the 16.0.0 line below 16.1.1. **There is no patched release under a permissive licence** - the fix begins at 15.1.1, which is already under the Reciprocal Public License 1.5.
- **Why `[15.1.3]` and not something newer:** it is the newest release on the *lowest* patched major, so it closes the advisory with the least behavioural drift. The 16.x line clears the advisory as well, from 16.1.1, but crosses a second major boundary for no additional security benefit.
- **How the advisory is closed:** by the version change itself, not by suppressing the detector. `dotnet restore WebVella.ERP3.sln` completes with zero `NU19xx` diagnostics and `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports no vulnerable packages. **`Directory.Build.props` declares no active `NuGetAuditSuppress`, `NoWarn` or `WarningsNotAsErrors`.** Two earlier revisions of this bullet were wrong in opposite directions and both are corrected here rather than silently replaced. The first said `grep -nE 'NoWarn|WarningsNotAsErrors|NuGetAuditSuppress' Directory.Build.props` "returns nothing"; the second said it returns exactly one line at `L457`, in a file that was only 409 lines long - the seam it measured had never been written (review finding **F7**). It now exists and the grep returns **eight** lines, all inside the `SUPPRESSION SEAM` comment at `L403`-`L463`. Verify it the way the gate's own bullet above does - strip the XML comments first, and then nothing matches at all - and confirm the item form too with `-getItem:NuGetAuditSuppress`, which returns an empty list.
- **What the decision turned on was the licence, not the advisory.** 15.1.3 declares its terms as a licence *file* that resolves to the Reciprocal Public License 1.5, while this repository declares `Apache-2.0` in four packable manifests and publishes packages to nuget.org for unknown downstream consumers. Accepting reciprocal source-disclosure terms - or entering the vendor's commercial agreement - changes a product's effective licensing posture, which is an owner decision and not an engineering one. It was therefore escalated rather than absorbed, and is recorded as **`RISK-001`, open - pending owner ratification** - in [the risk register](docs/security/risk-register.md), which carries both options and the exact execution steps for each. The declared licence expression was **not** changed, and `dotnet pack` on this project fails with `error ERPLIC001` until an owner records a decision, so the open question cannot be shipped past without someone choosing to.
- **Code consequence: one argument, at one site.** From 15.x the `MapperConfiguration` constructor requires an `ILoggerFactory`, and this repository has exactly one construction site - `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` - which now passes `NullLoggerFactory.Instance` because the platform performs no AutoMapper logging. `ErpAutoMapper.Initialize`'s signature is unchanged, so neither of its call sites in `WebVella.Erp.Web/ErpMvcExtensions.cs` and `WebVella.Erp.ConsoleApp/Program.cs` was touched, and the 379 `CreateMap<...>` declarations across 32 `Profile` subclasses in 93 source files are untouched.
- **Exploitability, for the licence decision rather than for the advisory:** every mapping is declared statically in source, no user-controlled mapping configuration or type graph reaches the configuration builder, and the impact class is availability at start-up rather than disclosure or execution. That assessment is what makes the fallback option - holding the pin behind a recorded acceptance - defensible if the owner declines the terms. It is context for a decision, not a substitute for one.

The blast radius that an upgrade *would* have had is measurable rather than asserted, and is recorded here so the owner can size the decision:

```bash
grep -rho 'CreateMap<' --include='*.cs' . | wc -l                    # 379
grep -rhoP 'class\s+\w+\s*:\s*Profile\b' --include='*.cs' . | wc -l  # 32
grep -rl 'AutoMapper' --include='*.cs' . | wc -l                     # 93
grep -rn 'new MapperConfiguration(' --include='*.cs' .                # exactly one site
```

The trailing parenthesis in the last command is deliberate: without it the pattern also matches the three `new MapperConfigurationExpression()` sites, which are mapping *registries* rather than configuration constructions.

**The gate reports advisories individually, and that was tested rather than assumed.** Injecting an unrelated vulnerable package (`Newtonsoft.Json 9.0.1`) into the core manifest made the build fail with `NU1903` naming a *different* advisory, `GHSA-5crp-9r3c-p9vr`; removing it restored a clean restore. So a clean result is not a blanket silence that would mask the next advisory - each one is reported on its own terms, and the AutoMapper advisory disappeared from the output because the package version changed, not because the detector was told to ignore it.

**Why the inert seam sits in `Directory.Build.props` rather than in the core manifest.** This matters only if the owner ever decides `RISK-001` the other way, so it is recorded now while the measurement is fresh. NuGet audit runs **per project**, and `WebVella.Erp` is referenced by every other project, so AutoMapper is present in 16 project graphs transitively. While the vulnerable version was still pinned, a project-scoped suppression placed in `WebVella.Erp.csproj` silenced only that one project and the solution restore still failed - measured at exactly 15 `NU1903` errors, one per remaining affected project. Repository-wide placement would therefore be a necessity of how the audit is scoped rather than a widening of scope; the seam still names exactly one advisory - by URL in its preferred form - and no wildcard. None of it is in force: the pin is at `[15.1.3]`, both forms sit inside the `SUPPRESSION SEAM` comment at `Directory.Build.props:L480`-`L540`, and neither contributes a property or an item to any of the 19 projects - `-getItem:NuGetAuditSuppress` resolves to `[]` and the only live `NoWarn` any project inherits is the `CA3001`-`CA3012` taint family.

### MailKit 4.14.1 to 4.17.0 (finding H-20)

- **Declaration site:** `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj:L28`.
- **Advisory:** `GHSA-9j88-vvj5-vhgr` / `CVE-2026-41319` - STARTTLS response injection through an unflushed stream buffer, enabling an authentication-mechanism downgrade, **CWE-74**. First patched in 4.16.0.
- **Why this shape of fix:** this single line edit clears **two** advisories, because MailKit 4.17.0 depends on MimeKit 4.17.0. No separate MimeKit `PackageReference` was added, and none should be: adding one would duplicate a constraint the mail library already expresses, and would then have to be maintained in lockstep with it.

### MimeKit 4.14.0 to 4.17.0, transitively (finding H-20)

- **Declaration site:** none. It is resolved through MailKit, as described above.
- **Advisory:** `GHSA-g7hc-96xr-gvvx` / `CVE-2026-30227` - CRLF injection in a quoted local part, enabling SMTP command injection and message forgery, **CWE-93**. First patched in 4.15.1.
- **Why it matters here specifically:** the mail plugin handles user-influenced recipient addresses, *and* it disabled transport certificate validation at five sites (finding H-11). An injection flaw compounding with an absent certificate check is materially worse than either weakness alone, which is why the mail stack was treated as a priority rather than a routine version bump.

### Microsoft.AspNetCore.Components.WebAssembly.Server 7.0.13 to 10.0.1 (finding H-18)

- **Declaration site:** `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` (line 10 before the change, line 12 after it), accompanied by retargeting both `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` from `net7.0` to `net10.0`.
- **Weakness class:** **CWE-1104**, use of unmaintained components. This is not a CVE remediation; no advisory is outstanding against the 7.0.13 package. It is an *unsupported-component* remediation: the .NET 7 line stopped receiving security patches on **2024-05-14**, so any future advisory raised against it would be permanently unfixable.
- **Context:** 17 of the 19 projects already targeted `net10.0`; only these two lagged. After the retarget all 19 projects target the same supported framework line. They also sit under the same dependency-audit and analyzer regime as the rest of the repository, because that regime comes from `Directory.Build.props` at the root - which is inherited by project location, not by solution membership. That is measured rather than assumed: `dotnet msbuild <project> -getProperty:...` on each returns the same seven gate properties as a solution member, and `-getItem:EditorConfigFiles` lists no global analyzer configuration for either - correctly, because there is none in this repository, and the workflow asserts that absence on every run. One caveat does survive the retarget: these two projects are **not solution members**, so solution-wide commands do not reach them. An intermediate revision enrolled them and this bullet was rewritten to say the caveat no longer applied; the enrollment exceeded the one change the plan authorises in `WebVella.ERP3.sln` and was reverted under `CR2-F-06`, so the caveat stands. Coverage is closed instead by permanent per-project restore, build and advisory steps in the workflow - complete at 19 of 19 by two routes - and the coverage-model assertion fails if any tracked project is ever left in neither set.

### Packages deliberately not changed

Every other active package is **advisory-free**, and that is a scanner result rather than an assertion. The evidence is the same two figures given under *What the advisory check actually reports*: the vulnerable-package listing names exactly **one** advisory identifier across the whole solution, and that one identifier is AutoMapper's. Any second unpatched package would necessarily add a second identifier to that output.

No upgrade is proposed for any of them, because the remediation guideline in force is to choose the solution requiring the least modification, and a version change with no security justification is a gratuitous change.

The honest limit on this claim: `dotnet list package --vulnerable` reports what the GitHub Advisory Database knew at the time it was run, for packages that have a published advisory. It cannot speak to unreported vulnerabilities, to the committed native binary described above, or to the browser-side assets that are out of scope for this inventory. It is a floor, not a proof of safety.

Three cases are worth stating explicitly, since each has a *newer* version available and each was still left alone on purpose:

- **Npgsql `[9.0.4]`** - a newer release of the data provider exists, but the pinned version is already safe; its only advisory does not reach the 9.x line at all.
- **Newtonsoft.Json 13.0.4** - well past both of its historical advisories.
- **System.IdentityModel.Tokens.Jwt 8.15.0** - far beyond the versions its advisories affect.

## Licensing decision required: AutoMapper

**OPEN ESCALATION - the advisory is closed; the licensing consequence is not, and is mechanically blocked from shipping meanwhile.** The pin is raised to `[15.1.3]`, so `GHSA-rvv3-g6hj-g44x` no longer appears anywhere in the dependency graph and the gate passes on its own terms rather than by suppression. What those patched versions are licensed under is a question for the repository owner, and it is recorded as open in `RISK-001` rather than answered here. An earlier revision of this section opened with `RECORDED DECISION` and described the reciprocal obligation as accepted; `CR2-F-04` withdrew that, on the ground that the party which performed the upgrade is not the party entitled to accept its licensing consequence.

The escalation, in one paragraph: **an automated remediation may close an advisory, but it must not silently change the effective licence of a product that publishes packages to third parties.** Every version of AutoMapper that patches `GHSA-rvv3-g6hj-g44x` is licensed under the Reciprocal Public License 1.5, whose source-disclosure obligation sits uneasily with a project that declares Apache-2.0 and publishes to nuget.org for unknown downstream consumers. The security fix is therefore applied and visible, and the licence conflict is stated rather than absorbed. The choice between accepting those terms, entering the vendor's commercial agreement, relicensing, or formally accepting the advisory instead was escalated as `RISK-001` and is recorded there as **open, pending owner ratification**, with the exact execution steps for each option written out so that what the owner ratifies is a plan rather than a sentiment.

The facts, all verifiable from package metadata:

- **AutoMapper 14.0.0**, the version previously pinned, declares `<license type="expression">MIT</license>`.
- **AutoMapper 15.1.3**, the version required to close `GHSA-rvv3-g6hj-g44x` / `CVE-2026-32933`, declares `<license type="file">LICENSE.md</license>` instead. That file states that the code is governed by the **Reciprocal Public License 1.5** (<https://opensource.org/license/rpl-1-5/>), and offers a separate commercial License Agreement as the alternative for anyone unwilling to release the source of software built with it.
- **This repository declares Apache-2.0** at `WebVella.Erp/WebVella.Erp.csproj:L32`, ships a matching `LICENSE.txt`, and publishes packages to nuget.org for third-party consumption.

The conflict is therefore substantive rather than cosmetic. A reciprocal licence's source-disclosure obligation is incompatible with distributing packages under a permissive expression to unknown downstream consumers. And there is **no patched MIT-licensed line to retreat to**: the fix begins at 15.1.1, which is already under the new terms.

**The current state of the repository is the upgrade at `[15.1.3]`.** The High-severity advisory is closed and the dependency gate passes - verified by `dotnet restore WebVella.ERP3.sln` completing with zero `NU19xx` diagnostics and by `dotnet list ... --vulnerable --include-transitive` reporting no vulnerable packages. The cost of that position is accepting the Reciprocal Public License 1.5 terms (or entering the vendor's commercial agreement) and reconciling them with the project's own Apache-2.0 declaration and its published packages. The declared licence expression was **not** changed and the upgrade was **not** reverted, so the conflict is visible rather than silently absorbed in either direction - and because a visible contradiction can still be published by anyone who runs `dotnet pack` on a green build, packaging is refused with `error ERPLIC001` until an owner records a decision.

If the owner is unwilling to accept those terms, the alternatives are a matter of formal risk governance rather than something this inventory should prescribe. This document deliberately **does not set out a procedure for downgrading to a version with a known High-severity advisory, or for suppressing the gate that detects one** - publishing a ready-made way around a security control belongs in neither a dependency inventory nor any other document a reader might follow without the accompanying decision record. Any outcome other than the current one requires a formally recorded, justified risk acceptance, and that process is governed in [the risk register](docs/security/risk-register.md).

The relevant entry there is **`RISK-001`**, which records the question as **open, pending owner ratification**, sets out the available options with the reasoning and the exact execution steps behind each, and carries the exploitability assessment for this codebase - namely that every mapping is statically declared in source and no user-controlled mapping configuration or type graph reaches the configuration builder, so real-world exposure is low despite the High rating. That assessment is context for a decision, not a licence to skip one.

One consequence should be stated plainly: because the gate promotes advisory diagnostics to build errors, the *advisory* half could not simply be left to drift - a red gate is not a stable resting state, which is why it was closed first and separated from the licence half. The licence half **can** be left open, because it now has a resting state of its own: the tree restores, builds, publishes and runs, and only *packaging* is refused. The question and its rationale are recorded in the risk register, which is where they belong.

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

- **The manifest inventory is first-hand.** All 19 `.csproj` files were parsed with XML comments stripped, and the resulting live set (33 packages) and commented set (15 entries) are reproduced above exactly, including which project declares each reference.
- **The advisory state is scanner-derived, and the coverage split is stated rather than glossed.** `dotnet list package --vulnerable --include-transitive` was run solution-wide, which reaches the **17** solution members, and separately per project for the **2** declared non-members, so all **19** tracked manifests are audited - by two routes rather than one. Each of those runs, together with its restore and build result and the resolved framework target, is recorded verbatim in *Recorded results* under *How to reproduce this inventory*, so nothing in the advisory sections rests on narrative assertion and every row can be re-executed. An intermediate revision enrolled those two projects in the solution so that one command would reach all 19, and recorded that as the intended model; review finding `CR2-F-06` rejected the enrollment as scope drift, so the 17 + 2 split stands and is asserted on every run.
- **Detection versus enforcement - these are different claims, and this document keeps them apart.** The .NET SDK already *detects* advisories on its own: `NuGetAudit`, `NuGetAuditMode=all` and `NuGetAuditLevel=low` are SDK defaults, so a vulnerable package produces an `NU19xx` diagnostic with no repository configuration whatsoever. But an SDK-default diagnostic is only a **warning**, and a warning stops nothing - a build with one still succeeds and a pipeline built on it still reports green. What the repository adds is *enforcement*: `Directory.Build.props` appends `NU1900;NU1901;NU1902;NU1903;NU1904;NU1905` to `WarningsAsErrors`, which every project inherits (evaluated `WarningsAsErrors` is `;NU1900;NU1901;NU1902;NU1903;NU1904;NU1905;NU1605;SYSLIB0011`), turning any advisory at any severity - and any failure to obtain advisory data - into a restore failure. Wherever this document says the gate *passes*, it means the enforced form: restore exits 0 **and** would have exited non-zero had an advisory been present.

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

    `error` versus `warning` and exit 1 versus exit 0, from one variable, is the whole distinction. Note also what the control implies about scope: it proves enforcement of the *advisory* diagnostics specifically. Static analysis is enforced too, but by a different and narrower mechanism, and the two should not be conflated. `EnableNETAnalyzers` with `AnalysisLevel=latest-recommended` is enabled repository-wide and the great bulk of its `CA*` output deliberately remains **warnings** - promoting a pre-existing backlog of roughly 3,000 diagnostics to errors would demand exactly the wide refactor the remediation's minimal-change constraint forbids. What *is* enforced is narrower, and no rule is promoted to `error` anywhere - the remediation plan permits only the dependency codes to be errors. The Security-category rules run at `warning` against twelve baselines the workflow asserts must not grow — ~~the four that execute at `latest-recommended` (`CA5350` 0, `CA5351` **5**, `CA5359` 0, `CA5364` 0)~~ **superseded under `MAJ-07`: `AnalysisLevelSecurity=latest-all` arms the category, so the ratchet covers `CA2100` 20, `CA2326` 20, `CA2328` 9, `CA5351` 5 and `CA5362` 1 alongside the zero-count families `CA2327`, `CA5350`, `CA5359`, `CA5364`, `CA5390`, `CA5401` and `CA5404`** — so the zero-count families are ratchets rather than cleanup tasks; and separately, **any** Security-category diagnostic that fires must appear in a reviewed two-entry allow-list or the job fails. That assertion was itself verified by differential control, twice over: a build left incremental reports every family at zero and would otherwise pass having compiled nothing, so the workflow forces `--no-incremental` and additionally fails if *all* baselined families collapse to zero at once - an impossible result against a non-zero total baseline, and therefore a reliable signal that the analyzers did not run. So a bounded, enumerated static-analysis gate **is** claimed here; an exhaustive one is not.

    That is not the same as there being no static-analysis gate, and an earlier revision of this document overstated the point by saying so. **The static-analysis gate is enforced in the workflow rather than in the compiler.** A dedicated job step parses the analyzer log, extracts every diagnostic belonging to the Security category, and fails unless each `(rule, file)` pair appears in an inline, individually justified allow-list - currently 21 pairs, each additionally carrying a resolvable `RISK-nnn` reference so the justification is attributable to a recorded acceptance rather than to a bare sentence. The enforced claim is therefore *zero unreviewed Security-category diagnostics across all 19 projects*, which is narrower and more reviewable than "zero diagnostics", and it is accompanied by a positive control that fails the job if the analyzers stop reporting a deliberately planted defect. Both halves matter: the allow-list stops a new finding slipping in among the backlog, and the positive control stops the whole check passing because nothing ran.
- **Licences are as recorded in each package's own NuGet metadata**, read from the package `.nuspec` and, where the metadata points at a licence file rather than an SPDX expression, from that file's text. This is how the Reciprocal Public License 1.5 finding for AutoMapper 15.1.3 was established, and how the MIT status of Irony.NetCore, `Microsoft.Web.LibraryManager.Build` and the Apache-2.0 status of morelinq were confirmed. Four packages declare a licence *file* rather than an SPDX expression, and the table above reports the resolved licence rather than the file name: AutoMapper 15.1.3 (`LICENSE.md`), Irony.NetCore (`LICENSE`), `Microsoft.Web.LibraryManager.Build` (`License.txt`) and morelinq (`COPYING.txt`). AutoMapper is the only one of the four whose file resolves to anything other than a permissive licence, which is why it is the only one escalated.
- **Unverified rows are marked as such rather than guessed.** `Storage.Net` 9.3.0 publishes no licence element and no licence URL in its `.nuspec`, so its row reads `Not verified in this environment`. An invented licence string in the document that serves as the evidence base for a licensing escalation would be worse than an honest gap.
- **The committed native binary was inspected directly, and an earlier claim about it was wrong.** A previous revision of this document stated that `ExternalLibraries/libwkhtmltox.dll` carried no metadata at all. That is not correct: it carries Windows version resources that identify it as version `0.12.4`, and it embeds LGPL v3 licence text. Its row and the *Committed native binaries* section now record the version as a fact with the reproduction commands beside it. What remains genuinely unrecorded is the artefact's **provenance and its applicable licence** - there is no manifest, no checksum, no upstream reference and no licence file committed with it - so those, and only those, are still marked unverified. The correction is called out rather than quietly applied, because a document whose purpose is to be falsifiable should show where it was falsified.
- **Advisory identifiers, severities, weakness classes and first-patched versions** were obtained by direct retrieval from the GitHub Advisory REST API, and package version availability and dependency metadata from the NuGet flat-container API. The `web_search` facility returns empty results in this environment, so no claim here rests on it. Where a figure could not be substantiated, it was omitted rather than estimated.
- **Line references** point at the post-remediation state of each file unless a "before the change" line is given explicitly. Line numbers drift as files are edited; the surrounding declaration name is the durable locator.

## Related documents

- [`SECURITY.md`](SECURITY.md) - disclosure policy, supported versions and security posture summary.
- [Security audit report](docs/security/security-audit-report.md) - findings in the mandated eight-field format (FINDING, SEVERITY, CWE, LOCATION, DESCRIPTION, IMPACT, EVIDENCE, REMEDIATION). It carries a full eight-field record for **all 53** AAP findings, one per identifier in the ranges `C-01`-`C-05`, `H-01`-`H-20`, `M-01`-`M-18` and `L-01`-`L-10`, and **138** such records in total once the post-remediation review inventories in Parts 2 through 5 are included — 53 in Part 1, 20 in Part 2, 26 in Part 3, 16 in Part 4 and 23 in Part 5. *(This row read **96** until code-review finding `MED-04`; that was the measurement taken before Parts 4 and 5 existed, and it is corrected rather than quietly replaced. The workflow asserts a floor of 138 and that all 138 identifiers are distinct.)* An earlier revision of this row said **46** and added "with the remainder summarised by band"; that was true when written and is withdrawn rather than quietly replaced - every one of the 53 now has its own record, so nothing is summarised by band any longer. Reproduce both figures with `grep -c '^| \*\*FINDING\*\*' docs/security/security-audit-report.md` for the total and `grep -cP '^#### (C|H|M|L)-[0-9]{2} ' docs/security/security-audit-report.md` for the Part 1 per-finding count — which is the pattern the workflow's *Assert every audit-report finding identifier is unique* step uses, so this row and the gate cannot disagree. *(This row previously named `grep -cE '^#{1,6} [CHML]-[0-9]+ — '`, which returns **70** rather than 53 because it also matches Part 2's single-digit identifiers `H-1`–`H-9`, `M-1`–`M-7` and `L-1`. Corrected under code-review finding `MED-04` together with the total above; the two-digit anchor is what confines the count to the zero-padded Part 1 inventory.)*
- [Remediation log](docs/security/remediation-log.md) - what changed per vulnerability class, and the home of the per-class verification evidence. It records every class committed in this remediation, not just the **Dependencies** class this document summarises.
- [Risk register](docs/security/risk-register.md) - accepted risks and open decisions. The AutoMapper licensing escalation above is the open entry `RISK-001`; the register also records the residual AutoMapper exploitability assessment, the credential-hashing algorithm deviation, the analyzer warnings deliberately left unsuppressed, and the deterministic initialisation vector (M-08).
- [Secure configuration guide](docs/security/secure-configuration.md) - operator guidance for running the platform securely.
- [Credential migration guide](docs/security/credential-migration.md) - the credential-hash migration and its operator actions.
- [`LICENSE.txt`](LICENSE.txt) - this project's own licence.

All six documents above exist and are committed, and every link resolves. An earlier
revision of this section listed `SECURITY.md`, the secure configuration guide and the
credential migration guide a second time, as bare paths rather than links, under a note
saying they were "later deliverables of the same remediation" and **not present yet** -
while simultaneously linking all three a few lines above. Both halves could not be true.
The stale half is removed and the contradiction recorded here rather than silently
tidied away, because this document is the evidence base for a licensing escalation and
its self-consistency is part of what makes it usable as evidence. `mkdocs build --strict`
is the mechanical check: a link from a page inside `docs/` to a missing file fails it, so
the links being present and the build being clean are the same statement. This matters
operationally and not only editorially: the startup failure messages in
`WebVella.Erp/ErpSettings.cs` and `WebVella.Erp/Utilities/CryptoUtility.cs` send an operator
to `docs/security/secure-configuration.md`, so a missing page would strand a deployment that
had just been refused a start.
