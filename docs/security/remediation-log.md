# Remediation Log

One entry per vulnerability class, matching the atomic commit boundaries used for the remediation
(one commit per vulnerability class). Each entry lists the findings closed, the files changed, the
verification performed and any deviation from the planned approach.

Findings themselves are described in the [security audit report](security-audit-report.md);
accepted risks and open decisions are in the [risk register](risk-register.md).

## Class: Dependencies

**Findings closed in this class:** H-01 (`AutoMapper`, CWE-674, GHSA-rvv3-g6hj-g44x /
CVE-2026-32933, OWASP A06:2021).

### Files changed

| File | Change |
| --- | --- |
| `WebVella.Erp/WebVella.Erp.csproj` | `AutoMapper` pin raised from `[14.0.0]` to `[15.1.3]` — the newest release on the lowest patched major. The `<PackageLicenseExpression>` on this project was **not** modified; see the open licensing decision below. |
| `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` | Supplies the `ILoggerFactory` that the 15.x `MapperConfiguration` constructor requires, plus one added `using` and a comment naming the threat addressed. |

No other file was touched by this class. In particular the mapping declarations, the AutoMapper
profiles, the resolvers, `AutoMapperExtensions.cs` and `AutoMapperConfiguration.cs` are all
unchanged, and no new package dependency was added anywhere.

### Actual API surface used

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

### Verification

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

### Deviations and out-of-scope observations

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
