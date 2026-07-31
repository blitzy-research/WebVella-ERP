# Security Audit Report

Audit of the WebVella ERP platform against the [OWASP Top 10 (2021)](https://owasp.org/Top10/)
taxonomy. Findings are classified by the engagement severity matrix (Critical, High, Medium, Low)
and each one is recorded in the mandated eight-field format: **FINDING, SEVERITY, CWE, LOCATION,
DESCRIPTION, IMPACT, EVIDENCE, REMEDIATION**.

The report is compiled incrementally: remediation is committed as one atomic commit per
vulnerability class, and each class contributes its findings to this report as it lands. The
sections below cover the classes committed so far. The companion documents are the
[remediation log](remediation-log.md) and the [risk register](risk-register.md).

## High severity findings

### H-01 — Object-mapping library carries a High-severity advisory

| Field | Value |
| --- | --- |
| **FINDING** | The `AutoMapper` package was pinned to a version affected by a published High-severity advisory: uncontrolled recursion leading to denial of service. |
| **SEVERITY** | High — *Vulnerable and outdated component with a published High-severity advisory.* |
| **CWE** | [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj:L47` (the package pin) and `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs:L15` (the single mapping-configuration construction site the upgrade required to change) |
| **DESCRIPTION** | The core library pinned `AutoMapper` with the exact-version notation `[14.0.0]`. Advisory [GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x) / CVE-2026-32933 affects every version below `15.1.1` (and, separately, the `16.0.0` line below `16.1.1`), classifying the defect as uncontrolled recursion (CWE-674). The advisory maps to **OWASP A06:2021 — Vulnerable and Outdated Components**. Because the pin used exact-version notation, no transitive resolution could lift the platform onto a patched version. |
| **IMPACT** | A mapping graph that recurses without bound exhausts the stack and terminates the hosting process, so the exposure is availability loss (denial of service) rather than disclosure or code execution. Every one of the seven site hosts and the console application resolves its object mapping through this single package, so the affected component sits on the request path of the whole platform. Real-world exploitability in this codebase is low and is assessed in full in the [risk register](risk-register.md): all mappings are statically declared in source, and no user-controlled mapping configuration or type graph reaches the configuration builder, so the recursion path is reachable only through a self-referential mapping the developers themselves would have to author. |
| **EVIDENCE** | Reproduced with the toolchain's own dependency audit against the affected version: `dotnet restore` reports `warning NU1903: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability, https://github.com/advisories/GHSA-rvv3-g6hj-g44x`, and `dotnet list package --vulnerable` reports the row `AutoMapper  [14.0.0]  14.0.0  High  https://github.com/advisories/GHSA-rvv3-g6hj-g44x`. Package metadata confirms the licence change described under REMEDIATION: `automapper.nuspec` declares `<license type="expression">MIT</license>` at 14.0.0 and `<license type="file">LICENSE.md</license>` at 15.1.3, where that licence file names the Reciprocal Public License 1.5. |
| **REMEDIATION** | The pin was raised to `[15.1.3]` — the newest release on the **lowest patched major**, chosen to minimise behavioural drift while still clearing the advisory. The upgrade requires exactly one code change: from 15.x the `MapperConfiguration` constructor takes an `ILoggerFactory`, so `ErpAutoMapper.Initialize` now supplies `NullLoggerFactory.Instance` (from the `Microsoft.AspNetCore.App` framework reference already present at `WebVella.Erp/WebVella.Erp.csproj:L43`, so **no new package dependency was added**). A no-op factory is used deliberately: the platform performs no AutoMapper logging, and introducing real logging would exceed the remediation scope. The `Initialize` signature and the `ErpAutoMapper.Mapper` field are unchanged, so both call sites and all mapping declarations, profiles and projection sites keep compiling untouched. Verification and the residual licensing decision are recorded in the [remediation log](remediation-log.md) and the [risk register](risk-register.md). |

#### Verification of the H-01 fix

| Check | Result |
| --- | --- |
| `dotnet restore WebVella.ERP3.sln` | exit 0, **zero `NU19xx` audit diagnostics** |
| `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` | "no vulnerable packages" for every project, **including `WebVella.Erp`** |
| Resolved package version | `AutoMapper  Requested [15.1.3]  Resolved 15.1.3` |
| `dotnet build WebVella.ERP3.sln -c Debug` | exit 0, **0 errors** across all projects |
| Scan trustworthiness precondition | The project-reference path casing defect (finding H-19) is already fixed, so `WebVella.Erp` is genuinely present in the restore graph and the clean result is not a silent omission. Verified with `grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln` returning nothing. |
| Runtime verification | A host and the console application both start, initialise mapping and serve traffic; interactive login succeeds (`POST /login` → `302`) and the authenticated pages render, exercising the `EntityRecord` → `ErpUser` projection that the login path depends on. No `AutoMapperConfigurationException`, no `NullReferenceException` and no mapping error in either process. |
