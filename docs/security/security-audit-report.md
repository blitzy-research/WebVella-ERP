# Security Audit Report

Audit of the WebVella ERP platform against the [OWASP Top 10 (2021)](https://owasp.org/Top10/)
taxonomy. Findings are classified by the engagement severity matrix (Critical, High, Medium, Low)
and each one is recorded in the mandated eight-field format: **FINDING, SEVERITY, CWE, LOCATION,
DESCRIPTION, IMPACT, EVIDENCE, REMEDIATION**.

The companion documents are the [remediation log](remediation-log.md), the
[risk register](risk-register.md), the [secure configuration guide](secure-configuration.md) and the
[credential migration guide](credential-migration.md).

## How to read this report

The report carries **three finding inventories**, and they are complementary rather than alternative.
All are reproduced in full because they answer different questions.

| Part | Inventory | Question it answers |
| --- | --- | --- |
| [Part 1](#part-1-audit-inventory) | The audit of the platform as found | *What is wrong with the platform?* |
| [Part 2](#part-2-post-remediation-review-inventory) | The review of the controls as delivered | *Does the remediation actually work on a live request path?* |
| [Part 3](#part-3-remaining-inventory-findings-documented-for-completeness) | The identifiers neither part wrote up | *Where is every remaining finding recorded?* |

**The two parts number their findings independently, so an identifier alone is not unique.** Part 1
generally uses the two-digit form (`H-01`) and Part 2 the single-digit form (`H-1`), but that is a
convention rather than a rule and it does not hold everywhere: `H-10` and `H-11` occur in both parts
with entirely different subjects, and several source comments write a Part 2 identifier in zero-padded
form. Always resolve an identifier through the [identifier index](#identifier-index) below rather than
by its shape. Where a Part 2 record supersedes a Part 1 record it says so explicitly.

Part 2 exists because a control that compiles is not a control that runs. Five helpers had been added
to the codebase — the hashing utility, the SQL identifier validator, the deserialisation binder, the
response-headers middleware and the login throttle — and at the point of review **none of them was
reachable from any live path**. Part 2 is severity-rated on the vulnerability that remained open, not
on the quality of the unused helper. Every one of those five is now wired, and the wiring is recorded
in the [remediation log](remediation-log.md).

## State of the remediation at this commit

Measured against the tree at this commit, not asserted:

| Area | State |
| --- | --- |
| Solution restore and build | `dotnet restore WebVella.ERP3.sln` exit 0 with zero `NU19xx`; `dotnet build WebVella.ERP3.sln -c Debug -m:2 --no-incremental` exit 0, **0 errors**, 3,096 analyzer warnings, none escalated |
| Dependency gate | `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` reports **no vulnerable package in any of the 19 solution projects**, `AutoMapper` resolving at `15.1.3`. All 19 are reached by that **single** command. An earlier revision of this row said the result took **three** commands because the two WebAssembly projects were not solution members; they have since been enrolled, so that is superseded. The workflow still lists those two individually, but only to assert each one's `TargetFramework` (finding H-18), which a solution-level command cannot do |
| Build gate reach | All **seven** gate properties evaluate on **19 of 19** projects from `Directory.Build.props` — the six dependency-audit and analyzer properties plus `AnalysisLevelSecurity=latest-all`, added later to raise the whole Security category. Coverage never depended on solution membership — the props file and the repository-root `.globalconfig` are both directory-scoped — and the two questions now coincide in any case, all 19 projects being solution members |
| Target frameworks | **19 of 19** projects on `net10.0`; no project remains on an end-of-life framework |
| Credential storage | PBKDF2-HMAC-SHA256, 600,000 iterations, per-credential 16-byte CSPRNG salt, fixed-time verification, legacy values upgraded on next authentication — wired on all four call sites |
| Closed since this table was written | `AllowAnyOrigin()` is applied at **no** host. This row has been corrected twice, and both superseded readings are stated so the progression is auditable: it first said "two hosts", then "one host — `WebVella.Erp.Site.Project`". Both hosts have since been narrowed to the explicit origin allow-list each one's own commented-out policy documents. Verify with `git grep -n 'AllowAnyOrigin' -- '*.cs'`, which now returns explanatory comments only and no applied policy. `RISK-013` is closed in the [risk register](risk-register.md) |
| Closed since this table was written | The shipped `Config.json` files no longer carry a live connection string, encryption key, token signing key, storage connection string or mail password, and all eight set `"DevelopmentMode": "false"`; `WebVella.Erp.Site/web.config` sets `Production`; and the seeded administrator credential in `WebVella.Erp/ERPService.cs` is no longer a literal. `RISK-021` is closed for the tracked configuration files. **One availability defect that this scrub itself exposed has also been closed** (review finding `F30`): every configuration builder asked for a lower-case `config.json` while the build copies the capital-`C` `Config.json`, and because the JSON provider is deliberately **non-optional** it threw on a case-sensitive filesystem *before* the environment provider could supply any of the now-externalised secrets — so the very mechanism that replaced the embedded values could not be reached. All four builder sites now prefer `Config.json` and fall back to the lower-case name only when it is the sole file present (`RISK-049`); `WebVella.Erp.ConsoleApp` additionally resolves the file against `AppContext.BaseDirectory` instead of a Windows-only drive-letter expression, which is why it could not start on Linux at all rather than merely needing a copied file |
| Closed since the row below was written | The **password bounds** and the **guest-role create grants** in `WebVella.Erp/ERPService.cs` are no longer as this table described them. `PasswordMinLength` is **12** and `PasswordMaxLength` is **128**, closing M-13; the Guest CREATE grants on the user and role entities and the Guest READ grant on the user entity are removed from the seed, closing C-02 and C-05, and `RevokeGuestRecordPermissions4` carries the same revocation to already-provisioned installations rather than leaving them exposed. The Guest READ grant on the *role* entity, which an earlier revision of this row recorded as deliberately retained because the login page needed it, has since been removed from the seed as well (review finding `F17`) and is revoked on already-provisioned installations by a new schema version 5 migration, `MigrateSecurityDefaults5`, so no entity in a provisioned database grants the Guest role anything. The demo credential in the Blazor WebAssembly client page `Client/Pages/Index.razor.cs` is also **removed**; that page now defers to the real `/login` page, and `grep -c 'erp@webvella.com' WebVella.Erp.WebAssembly/Client/Pages/Index.razor.cs` returns 0 |
| Closed, having previously been recorded as open | `H-07` — the rich-text editor upload callback. An earlier revision of this index listed it here as "still open, and **not** by design … the one **High**-severity finding in this report that carries no remediation at this commit". That is no longer the case: the callback index is validated with `int.TryParse` and carried as an `int`, the URL and message are encoded with `JavaScriptEncoder.Default`, and the second sink no longer echoes exception text. Its record in [Part 3](#part-3-remaining-inventory-findings-documented-for-completeness) carries the detail. **No High-severity finding in this report is now unremediated.** |

## Identifier index

Every finding identifier cited from source, project, build or workflow files, and where it resolves.
The census was taken from the tree at this commit rather than from the plan, which is how the
zero-padded aliases in the third group were found.

### Cited identifiers that resolve to Part 1

| Identifier | Cited from | Subject |
| --- | --- | --- |
| `C-03` | `PasswordUtil.cs`, `SecurityManager.cs`, `RecordManager.cs`, `DbRecordRepository.cs` | Unsalted single-pass MD5 credential storage |
| `C-04` | `CryptoUtility.cs`, `ErpSettings.cs` | Hardcoded encryption key with a silent fallback |
| `H-04` | `ErpSettings.cs`, `WebVella.Erp.Site/Startup.cs`, `WebVella.Erp.Site.Project/Startup.cs` | Weak default token signing key |
| `H-05` | `ErpSettings.cs` | Plaintext database credentials in shipped configuration |
| `H-09` | `DbIdentifier.cs`, `DbEntityRepository.cs`, `DbRecordRepository.cs`, `DbRelationRepository.cs`, `DbRepository.cs`, `EqlBuilder.Sql.cs`, `CodeGenService.cs`, `security-scan.yml` | SQL identifier injection through string concatenation |
| `H-10` | `ErpSerializationBinder.cs`, `DbEntityRepository.cs`, `DbRelationRepository.cs`, `JobProfile.cs`, `JobDataService.cs`, `NotificationContext.cs`, `CodeGenService.cs` | Unsafe polymorphic deserialisation |
| `H-15` | the seven host `Startup.cs` files | No HTTPS enforcement, no HSTS, insecure cookie attributes |
| `H-16` | `LoginThrottleService.cs`, `login.cshtml.cs`, `WebApiController.cs`, `ErpMvcExtensions.cs` | No account lockout on repeated failed logins |
| `H-19` | `WebVella.ERP3.sln`, all 15 project manifests, `security-scan.yml` | Case-mismatched project references broke the dependency scan |
| `M-01` (in `SecurityHeadersMiddleware.cs`) | `SecurityHeadersMiddleware.cs:L16` | No security response headers |
| `M-04` | `AuthService.cs` | Local time used for token timestamps |
| `L-07` | `global.json` | No lock file and an unpinned SDK version |

### Cited identifiers that resolve to Part 2

| Identifier as cited | Part 2 record | Subject |
| --- | --- | --- |
| `H-1` | `H-1` | Open redirect and script-scheme injection through the return-URL parameter |
| `M-2` | `M-2` | Secret validation accepted known published defaults |
| `M-5` | `M-5` | Output helper performed replacement, not encoding |

### Zero-padded aliases — cited in Part 1 form but resolving to Part 2

These are the collisions the shape convention does not catch. They are recorded here rather than
renamed, because renaming them would mean rewriting source comments that are otherwise correct.

| Identifier as cited | Cited from | Actually resolves to | Subject |
| --- | --- | --- | --- |
| `H-08` | the seven host `Startup.cs` files | Part 2 `H-8` | Security headers middleware invoked by no host |
| `M-01` (in `ErpSerializationBinder.cs`) | `ErpSerializationBinder.cs:L76`, `:L380`, `:L694`, `:L879` — the four `SECURITY M-01` markers in the file | Part 2 `M-1` | Deserialisation allow-list too broad, and its resource bounds |
| `L-01` | `SecurityHeadersMiddleware.cs` | Part 2 `L-1` | Mandated policy publicly replaceable; report-only with nowhere to report |

### Cited identifiers recorded in Part 3

| Identifier | Cited from | Where it is recorded |
| --- | --- | --- |
| `L-10` | `.github/workflows/security-scan.yml:L3` | [Part 3](#part-3-remaining-inventory-findings-documented-for-completeness). *No CI/CD pipeline existed* — a Low-severity observation about the repository rather than a defect in the application, closed by the existence of the file that cites it. |


## Part 1 — Audit inventory

Findings against the platform as found, in the mandated eight-field format.

### Critical severity findings

#### C-03 — Passwords stored as an unsalted, single-pass MD5 digest

| Field | Value |
| --- | --- |
| **FINDING** | Account passwords were stored as an unsalted, single-pass MD5 digest, produced by a shared mutable hash instance, and the stored digest was compared for equality inside a SQL predicate. |
| **SEVERITY** | Critical. The engagement severity matrix places *data breach exposure* in the Critical tier, which is where this belongs: a leaked password column is recoverable wholesale. It is deliberately **not** filed under the Medium tier's "weak cryptography", because the consequence is disclosure of every credential rather than a theoretical algorithm weakness. |
| **CWE** | [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) and [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html). The comparison weakness and the shared-instance race are recorded separately as `M-05` and `M-06` below, because they are distinct weaknesses that happen to live in the same file. |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs` — the primitive. Consumed at `WebVella.Erp/Api/SecurityManager.cs:L84` (credential resolution), `WebVella.Erp/Api/RecordManager.cs:L2017` and `WebVella.Erp/Database/DbRecordRepository.cs:L554` and `:L1856` (the password write paths). |
| **DESCRIPTION** | `GetMd5Hash` computed a single MD5 pass over the UTF-8 bytes of the password and rendered it as 32 lower-case hexadecimal characters, with no salt, no iteration count and no per-credential parameterisation. There was no verification member: `SecurityManager` recomputed the digest and compared it to the stored column **inside the SQL statement** (`… AND password = @password`), which is what constrained the platform to a comparable — that is, unsalted — hash format. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | MD5 is fast by design, so an offline attacker holding the password column recovers weak and moderate passwords at negligible cost, and precomputed tables recover common passwords immediately. Because there is no salt, two accounts with the same password store the same digest, so one cracked value exposes every account sharing it and the column doubles as a password-reuse map. The cost asymmetry was measured rather than assumed: a single MD5 pass over a password takes **0.0007 ms** on the audit host, against **367 ms** for the replacement primitive — roughly a **520,000×** difference in the work an attacker must spend per guess. |
| **EVIDENCE** | At the pre-audit revision the file contained `private static MD5 md5Hash = MD5.Create();` as a single shared instance, `GetMd5Hash` calling `md5Hash.ComputeHash(...)`, and `VerifyMd5Hash` returning `0 == StringComparer.OrdinalIgnoreCase.Compare(hashOfInput, hash)`. The credential lookup at `SecurityManager.cs:L84-L86` computed the digest and passed it as an EQL parameter compared with `password = @password`. The analyzer gate independently reports the MD5 use as `CA5351` — *Do not use broken cryptographic algorithms*. |
| **REMEDIATION** | The primitive was replaced with a salted, work-factored, fixed-time hash-and-verify pair built on the ASP.NET Core `PasswordHasher` in its versioned (V3) format: a fresh 128-bit cryptographically random salt per credential, 600,000 PBKDF2 iterations, a 256-bit subkey, and the salt and iteration count encoded alongside the subkey so the work factor can be raised later without invalidating anything already stored. No new package was needed — the primitive ships in the framework the core library already references — and no schema change was needed, because the password column is already a 500-character variable-length string and the produced value is 84 characters. Legacy verification is retained deliberately, so credentials written by earlier releases keep working and are upgraded on next authentication rather than reset. Two documented deviations from the letter of the mandated cryptographic standard are recorded as `RISK-005` in the [risk register](risk-register.md), and the retained MD5 surface as `RISK-004`. |

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

One implementation detail differs from the wording of the original remediation note and is corrected
here rather than left to drift: the derivation is performed **in this file** with
`Rfc2898DeriveBytes.Pbkdf2` over `HashAlgorithmName.SHA256`, writing the same self-describing
versioned layout, rather than by delegating to the framework's `PasswordHasher`. The parameters are
the mandated ones either way — PBKDF2-HMAC-SHA256, 600,000 iterations, a 16-byte CSPRNG salt, a
32-byte subkey — and deriving in-file additionally keeps the core library free of an ASP.NET Core
dependency it does not otherwise need. A plaintext length bound of 128 characters is enforced at all
four entry points before any scan, encode, digest or derivation work is performed, so an oversized
submission to the anonymous login endpoint is refused for the cost of one integer comparison.


##### Verification of the C-03 primitive

| Check | Result |
| --- | --- |
| The stored format is salted and non-deterministic | Hashing the same password twice yields different values; each carries its own 128-bit random salt |
| The format is self-describing, so the work factor can be raised later | The value encodes the format marker, the pseudo-random function, the iteration count and the salt; 84 Base64 characters beginning with `A`, the encoding of the `0x01` marker |
| Fits the existing column with no schema change | 84 characters against a 500-character column |
| Legacy and modern values are distinguishable without a new column | A legacy digest is exactly 32 hexadecimal characters; a modern value is 84 Base64 characters — the two shapes cannot collide at any casing |
| Verification is fixed-time | The framework verifier compares in fixed time; the retained legacy comparison was rewritten onto `CryptographicOperations.FixedTimeEquals` |
| The upgrade signal works | A value written at a lower iteration count verifies as `SuccessRehashNeeded`, so a future work-factor increase is carried by the same mechanism with no further code change |
| A corrupt stored value cannot become a denial of service | Verification returns false for a malformed value; only `FormatException` and `ArgumentException` are caught, so a genuine platform fault still propagates |
| Cost measured, not asserted — but *contemporaneously*, and the transcript is not retained (see the [evidence-provenance table](remediation-log.md#evidence-provenance); treat the ratio, not the absolute value, as the finding) | Medians over 20 runs, single-threaded, .NET 10.0.10: hash **367.0 ms**, verify **364.1 ms** at 600,000 iterations. See `RISK-005` for the accepted trade-off and the comparison against the OWASP floor |
| Module and solution compile | `dotnet build WebVella.Erp/WebVella.Erp.csproj -t:Rebuild` and `dotnet build WebVella.ERP3.sln -c Debug -m:2 -t:Rebuild` — exit 0, **0 errors** |

#### C-04 — Hardcoded encryption key with a silent fallback

| Field | Value |
| --- | --- |
| **FINDING** | A 256-bit encryption key was compiled into the source as a constant, and the key accessor fell back to it silently whenever configuration supplied no key. |
| **SEVERITY** | Critical — the key is published in the source repository, so any data it protects is readable by anyone who can read the code, which is a data-breach exposure. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) and [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) |
| **LOCATION** | `WebVella.Erp/Utilities/CryptoUtility.cs` — the `defaultCryptKey` constant and the fallback branch in the key accessor. |
| **DESCRIPTION** | The constant `defaultCryptKey = "BC93B776…"` was present in source, and the accessor read `if (string.IsNullOrWhiteSpace(ErpSettings.EncryptionKey)) { cryptKey = defaultCryptKey; }`. A deployment that never configured a key therefore encrypted with a value published in a public repository, and did so **without any signal that it had done so**. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Anyone holding the ciphertext and the source recovers the plaintext. The silent fallback is what makes this Critical rather than merely poor practice: an operator had no way to discover the condition, because the platform started normally and encrypted successfully with a known key. |
| **EVIDENCE** | The constant and the fallback branch are both present verbatim at the pre-audit revision. |
| **REMEDIATION** | **Both halves were changed, because removing only the constant would have relocated the defect rather than closed it.** The constant is deleted, and the fallback is replaced by an `InvalidOperationException` naming the missing setting, the environment variable that supplies it, the legacy misspelled key name that is still honoured, and the finding identifier — so the failure is actionable rather than cryptic. Fail-fast validation was additionally added at settings initialisation so a missing key aborts startup rather than surfacing at the first encryption. The residual weakness in the same file — the deterministic initialisation vector — is a separate Medium finding recorded as `M-08` and accepted as `RISK-006`. |

### High severity findings

#### H-01 — Object-mapping library carries a High-severity advisory

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
| **FINDING** | Bearer-token validation was configured with lifetime validation switched off, so an expired token continued to be accepted indefinitely, and validation failures were swallowed without a trace. |
| **SEVERITY** | High — session hijacking. A captured token never stops working. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) and [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs` — the token validation parameters, and the surrounding `catch`. |
| **DESCRIPTION** | The validation parameters omitted `ValidateLifetime`, which defaults the handler into accepting any expiry, and the `catch (Exception)` around validation returned without recording anything. Compounding it, the token refresh endpoint is anonymous, so an indefinitely valid token was also indefinitely renewable. Maps to **OWASP A07:2021 — Identification and Authentication Failures**. |
| **IMPACT** | A token obtained once — from a log, a proxy, a browser history or a shared device — authenticates forever, so revocation by expiry does not exist. Silent failure handling additionally means an attacker probing with forged tokens leaves no evidence. |
| **EVIDENCE** | The pre-audit parameters contained no `ValidateLifetime` and no `ClockSkew`; the exception handler discarded the exception object entirely (`catch (Exception)`). |
| **REMEDIATION** | `ValidateLifetime = true` with an explicit `ClockSkew` of one minute — explicit rather than default, because the framework default of five minutes silently extends every token's usable life. Validation failures are now logged, with a one-minute rate limit on the log write so a token-flooding attempt cannot itself become a log-volume denial of service, and with the log write wrapped so that a logging failure can never turn into an authentication failure. **Corrected by review finding `F7`:** at the time this record was first written the explicit skew existed only in the platform's own validator — both hosts' `AddJwtBearer` registrations omitted `ClockSkew` and therefore kept IdentityModel's five-minute default, so an expired bearer principal could stay authorized around four minutes longer than this record implied. All three validators now read one member, `AuthService.JwtClockSkew`, so they cannot drift apart. **Also narrowed by review finding `F11`:** the outer catch was still `catch (Exception)`, which converted any defect inside validation into "invalid token" and wrote an audit record asserting a credential rejection that had never been judged. It now catches only `SecurityTokenException` and `ArgumentException`, and anything else propagates into the error pipeline. |

#### H-03 — Authentication ticket expiry set 100 years ahead

| Field | Value |
| --- | --- |
| **FINDING** | The authentication cookie ticket was issued with an expiry 100 years in the future. |
| **SEVERITY** | High — session hijacking. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs` — the authentication properties built at sign-in. |
| **DESCRIPTION** | `ExpiresUtc = DateTimeOffset.UtcNow.AddYears(100)`. A stolen cookie therefore remained valid for the lifetime of the deployment and beyond. Maps to **OWASP A07:2021**. |
| **IMPACT** | Effectively unbounded session lifetime: a cookie captured from a shared or compromised machine grants access permanently, and signing out on one device does not invalidate a copy taken from another. |
| **EVIDENCE** | The `AddYears(100)` call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | Replaced with a bounded lifetime expressed as a named constant of 1 440 minutes — one day — chosen to align with the cookie expiry window rather than invented, so the ticket and the cookie cannot disagree about when the session ends. |

#### H-04 — Weak default token signing key compiled into the settings

| Field | Value |
| --- | --- |
| **FINDING** | When no token signing key was configured, the platform substituted the compiled-in literal `"ThisIsMySecretKey"`. |
| **SEVERITY** | High — anyone knowing the default can mint valid tokens for any account, which is authentication bypass. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) and [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) |
| **LOCATION** | `WebVella.Erp/ErpSettings.cs` — the signing-key assignment. |
| **DESCRIPTION** | `JwtKey = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Key"]) ? "ThisIsMySecretKey" : configuration["Settings:Jwt:Key"];`. The fallback is both guessable and published. Maps to **OWASP A02:2021**. |
| **IMPACT** | A token signed with a known key is indistinguishable from a legitimate one, so an attacker forges a token carrying any identity and any role, including administrator. This is privilege escalation to administrator with no credential required. |
| **EVIDENCE** | The conditional with the literal fallback is present verbatim at the pre-audit revision. |
| **REMEDIATION** | The fallback is deleted — the key is now read straight from configuration and nothing is substituted — and fail-fast validation aborts startup with an actionable message when a signing key is required but absent. The validation is conditional on the `Settings:Jwt` section existing, so hosts that issue no tokens are not forced to configure a key they never use. The message names the setting, the environment variable that supplies it, and the finding, so an operator can act on it without reading the source. |

#### H-05 — Plaintext database credentials in eight shipped configuration files

| Field | Value |
| --- | --- |
| **FINDING** | Every shipped `Config.json` carries a live PostgreSQL connection string, including the database user name and password, and one also carries the mail account password. |
| **SEVERITY** | High — a repository read is enough to obtain database credentials for any deployment that kept the shipped values. |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **LOCATION** | All eight `Config.json` files: `WebVella.Erp.Site`, `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`, `WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next`, `WebVella.Erp.Site.Project`, `WebVella.Erp.Site.Sdk` and `WebVella.Erp.ConsoleApp`. |
| **DESCRIPTION** | The connection string, the encryption key, the token signing key and the mail password are all present as literal values in files that are tracked in version control. Each file carries them at different line positions, so no uniform patch applies. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Direct database access with the application's own privileges, which bypasses every application-level authorisation control the platform implements. Where the values were reused across environments, one leak compromises all of them. |
| **EVIDENCE** | The literal values are present verbatim in all eight files at the pre-audit revision. |
| **REMEDIATION** | **Fixed.** An earlier revision of this row said "partially remediated; the scrub itself is a later stage" and that the finding "remains open"; both are retracted - the scrub has landed. All eight shipped configuration files now carry **empty** values for the connection string, encryption key, token signing key and mail password, and the files are retained rather than deleted because the JSON configuration source is not optional and deleting them stops every host from starting. The precondition that made scrubbing safe rather than fatal landed first, in the required order: startup now fails fast, with an actionable message naming each missing setting and its environment variable, when a required secret is absent. Two further changes are required before the values can be removed, and both are deliberately out of this stage: the configuration provider chain must be extended beyond its single JSON source, because there is currently no other channel by which an operator could supply a secret; and the files must then be scrubbed rather than deleted, because the JSON source is not optional and deleting them stops every host from starting. Both have landed, so this finding is closed **in the working tree**. One thing must still not be read into it: scrubbing the working tree does **not** remove these values from committed history, so every secret that was ever committed must be treated as compromised and rotated. The rotation instruction is in [the secure configuration guide](secure-configuration.md). |

#### H-06 — Cross-site scripting through unencoded output

| Field | Value |
| --- | --- |
| **FINDING** | The raw-output helper is used at 128 sites across 69 Razor views. Three of them emit an unencoded, caller-supplied return URL into an `href` attribute; a further set render database text without encoding, including navigation and menu content that appears on every page of every host. |
| **SEVERITY** | High — stored cross-site scripting in navigation content executes for every user who loads any page. |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html), and [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html) for the return-URL sinks |
| **LOCATION** | Reflected: `WebVella.Erp.Plugins.SDK/Pages/page/create.cshtml`, `.../manage.cshtml` and `.../manage-custom.cshtml`. Stored: the shared navigation and menu views (`WebVella.Erp.Web/Pages/Shared/NavItem.cshtml`, `.../NavMenu.cshtml`, `WebVella.Erp.Web/Components/SiteMenu/SiteMenu.cshtml`), the SDK data-source listing, and the Project plugin widget views. The stored sinks' **root cause is not in those views at all**: the markup they render raw is composed in `WebVella.Erp.Web/Models/BaseErpPageModel.cs` (five sink blocks) and in the three Project widget builders `WebVella.Erp.Plugins.Project/Components/PcProjectWidgetTasksQueue/PcProjectWidgetTasksQueue.cs`, `.../PcProjectWidgetTimesheet/PcProjectWidgetTimesheet.cs` and `.../PcProjectWidgetTaskDistribution/PcProjectWidgetTaskDistribution.cs` (four sink lines). That is where the fix landed. |
| **DESCRIPTION** | Most of the 128 sites are **not** vulnerable and were proven so rather than assumed: roughly 55 render markup the server itself constructs from identifiers only, and four are by-design raw channels whose whole purpose is to emit author-supplied markup or script. Classifying every site by its argument was essential, because treating all 128 as defects would have produced a large volume of false findings. Maps to **OWASP A03:2021 Injection**. |
| **IMPACT** | Script executing on the application's own origin can read the session, act as the victim, and — because the navigation renders everywhere — reach every authenticated user of the platform. |
| **EVIDENCE** | The three reflected sinks emit the unencoded model property while sibling pages in the same area already use its encoded counterpart, which is what localised the defect. A headless-browser run confirmed the exploit: HTML encoding alone stops attribute breakout but a `javascript:` scheme URL still executes when the link is activated, because the browser decodes entities *before* parsing the scheme. |
| **REMEDIATION** | **Closed — the reflected and the stored sinks are both remediated; only the four by-design channels remain accepted.** Encoding was the wrong control for the reflected sinks and was replaced by validation: the return URL is now accepted only if it is a same-site local URL, and anything else falls back to a safe default. The same policy was applied to the two companion redirect sinks in the page models, which were a second, unencoded path to the same weakness. The stored sinks were then closed **where the markup is composed, not where it is rendered**, because composition is where the untrusted values enter it. In `WebVella.Erp.Web/Models/BaseErpPageModel.cs` the four `MenuItem.Content` composition sites — the multi-node area link, the two sitemap node links, the single-node area link and the site-page anchor — now HTML-encode every interpolated label and title, admit a node URL only when it is a local path, a fragment or an explicit `http`/`https` absolute URL (rejecting control characters and protocol-relative `//host` forms), constrain an icon class to letters, digits, spaces, hyphens and underscores, and percent-escape the site-page name before it becomes a path segment. The three `PcProjectWidget*` component builders no longer assemble markup at all: they publish structured text, image-path, icon-class and colour fields, and their six Design and Display views render literal `<img>`, `<i>` and `<a>` elements so Razor's automatic encoding applies to every value. The raw-output helper therefore remains in the navigation, menu and site-menu views — removing it would break the deliberate icon markup those views carry and the dropdown rewrite `NavItem` performs on the composed string — but it now has nothing executable left to emit, so the per-sink triage previously planned for those views is no longer required. The four by-design channels are still never encoded; they are covered by the compensating control of restricting markup authoring to privileged roles plus the content-security policy, and remain recorded as accepted risk under `RISK-023`, which is confined to those four channels alone. Additionally, the platform's only escaping utility — a case-sensitive string replacement, trivially defeated by altered casing — was replaced by the framework encoder; see M-18. |

#### H-09 — SQL identifier injection through string concatenation

| Field | Value |
| --- | --- |
| **FINDING** | Table identifiers derived from entity and relation names were concatenated directly into SQL text at six sites. |
| **SEVERITY** | High — SQL injection. |
| **CWE** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **LOCATION** | Six sites, each with the construct observed at the pre-remediation revision:<br>1. `WebVella.Erp/Database/DbEntityRepository.cs:L275` — `NpgsqlCommand command = con.CreateCommand("DELETE FROM entities WHERE id=@id; DROP TABLE rec_" + entity.Name);` — the most striking artefact in the audit, a `DROP TABLE` whose target is concatenated from data.<br>2. `WebVella.Erp/Database/DbRecordRepository.cs:L664` — `sql.AppendLine("SELECT " + columnNames + " FROM " + tableName);`<br>3. `WebVella.Erp/Database/DbRecordRepository.cs:L666` — the `SELECT DISTINCT` variant of the same statement.<br>4. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1018` — `$"SELECT * FROM rec_{entityName};"`<br>5. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1291` — `$"SELECT EXISTS(SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'rel_{relation.Name}');"`<br>6. `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1305` — `$"SELECT * FROM public.rel_{relation.Name}"`<br>The exposure is bounded to identifiers, not values: `WebVella.Erp/Database/DbRepository.cs:L517` and `L528-530` show every value in this layer bound as an `NpgsqlParameter`. The helper introduced to close these is `WebVella.Erp/Database/DbIdentifier.cs`. |
| **DESCRIPTION** | PostgreSQL cannot bind an identifier as a parameter, so identifiers are necessarily interpolated. Every *value* in this layer is already parameterised, which confines the exposure precisely to identifier interpolation — one of the six sites concatenates an entity name straight into a `DROP TABLE` statement. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | An identifier containing a statement separator would execute additional SQL with the platform's own database privileges. Reachability is constrained by the platform's own entity-name validation, but that validation is a different layer with a different purpose, so relying on it is relying on a control nobody declared. |
| **EVIDENCE** | The concatenations are present verbatim. **This cell previously recorded zero `CA2100` and zero `CA23xx` diagnostics and read that silence as corroboration that values are parameterised. Both halves of that were wrong and are corrected here.** The silence was an artefact of the analysis level: neither rule is enabled by `AnalysisLevel=latest-recommended`, so it could not have corroborated anything. Since `AnalysisLevelSecurity=latest-all` was added, the rules are enabled and they *do* report — `CA2100` at 20 sites and `CA2326`/`CA2328` at 20 and 9 — across all 19 projects. The parameterisation claim is instead established the way it always actually was: by direct reading of the data layer, where every *value* is bound through `NpgsqlParameter` and only identifiers are interpolated. Each reporting site is an individually justified entry in the workflow's Security-category allow-list; `CA2327` reports **zero**, which is the meaningful analyzer result here, because it confirms `ErpSerializationBinder` is attached at every `TypeNameHandling` site. |
| **REMEDIATION** | A single audited helper — `DbIdentifier` — validates against a strict allow-list (a leading lower-case letter, then only lower-case letters, digits and single underscores, anchored at both ends) and double-quotes the result, failing hard on rejection rather than sanitising, because a silent repair would reintroduce the exposure while making the finding read as closed. One reviewable implementation is used rather than six local patches. **The helper is now attached at every concatenation site** - an earlier revision of this row said it "has no callers yet", which is retracted. It is applied well beyond the six sites the finding enumerated: the record, entity and relation repositories, the EQL SQL builder, the SDK code-generation service and an SDK migration all route identifiers through it. `Validate` and `Quote` are used deliberately differently - `Validate` where the bare name is needed, such as inside a string literal compared against `pg_tables`, and `Quote` where the identifier is emitted into the statement itself. |

#### H-10 — Unsafe polymorphic deserialisation

| Field | Value |
| --- | --- |
| **FINDING** | Deserialisation was configured with unconstrained polymorphic type handling, so the type to instantiate was taken from the serialised payload. The plan enumerated **fourteen** sites; a systematic sweep of the tree found **twenty**. |
| **SEVERITY** | High. |
| **CWE** | [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |
| **LOCATION** | **Twenty sites across six files, all measured against the tree rather than taken from the plan.** Current line numbers are given because each site gained a threat comment, shifting every pre-remediation locator upward.<br><br>*The fourteen the plan enumerated:* `JobProfile.cs:L43, L54, L60, L101` (`All`, all four deserialise); `DbRelationRepository.cs:L58, L147` (`Auto`, serialise-only) and `:L201` (`Auto`, deserialise); `DbEntityRepository.cs:L64, L190` (`Auto`, serialise-only) and `:L246` (`Auto`, deserialise); `CodeGenService.cs:L969, L1011` (`Auto`, deserialise) and `:L9253, L9287` (`All`, deserialise).<br><br>*The six the plan did not:* `WebVella.Erp/Jobs/JobDataService.cs:L32, L101, L302, L351` (`All`, serialise-only — the write counterpart producing exactly the JSON `JobProfile.cs` reads) and `WebVella.Erp/Notifications/NotificationContext.cs:L115` (`Auto`, deserialise) and `:L160` (`Auto`, serialise-only).<br><br>Overall split: **11 deserialise, 9 serialise-only.** The binder introduced to close them is `WebVella.Erp/Api/Models/ErpSerializationBinder.cs`. |
| **DESCRIPTION** | Type handling was enabled in its permissive modes, which instructs the deserialiser to honour a type name embedded in the data. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | An attacker able to influence a persisted payload chooses which type is constructed during deserialisation, which is the standard route from data tampering to code execution via a gadget type reachable in the loaded assemblies. |
| **EVIDENCE** | The permissive type-handling settings were present at all fourteen sites the audit enumerated. Two things are now recorded that the original evidence could not state. **First, the site count is 20, not 14, and the discrepancy is a counting artefact rather than a missed exposure**: a repository-wide search for `TypeNameHandling` returns more hits than there are settings, because several are mentions inside comments. Restricted to lines that actually *assign* the property, `git grep -n 'TypeNameHandling *=' -- '*.cs'` returns **20**, of which **19 attach `ErpSerializationBinder.Instance` on the same line**; the twentieth, `WebVella.Erp/Database/DbEntityRepository.cs:246`, attaches it on the next line of the same object initialiser. **Second, and stronger than a search: the closure is machine-checked by an analyzer that is armed and silent.** `CA2327` fires precisely when `TypeNameHandling` is not `None` *and* no `SerializationBinder` is set. It is enabled by `AnalysisLevelSecurity=latest-all` and left at its default severity by the repository-root `.globalconfig`, and it raises **zero** diagnostics across all 19 projects — while a throwaway probe carrying an identical initialiser with the binder omitted *did* raise it, alongside `CA2326`. An enabled rule that demonstrably fires on the unbound shape and is silent on this repository is positive evidence that every polymorphic site is bound, rather than the absence of evidence a search alone would give. |
| **REMEDIATION** | A serialisation binder with an explicit type allow-list, exposed as a singleton and failing hard on any type outside the list. Resolution is an **exact lookup** in the allow-list map — never a namespace or assembly-name prefix test, which is the shape that admitted the behaviour-carrying types described below — and the resolved type is re-validated before it is returned, with delegate and `IDisposable` gadget shapes refused at **two** independent points: once while the map is built and once on the resolution path, so a type that somehow reached the map could still not be constructed. **Removing type handling outright was rejected**: already-persisted job arguments and entity and relation payloads carry type discriminators and would fail to deserialise, breaking existing installations — so constraining the binder preserves round-tripping while closing the weakness. `BindToName` is intentionally left unrestricted, because constraining serialisation *output* protects nothing and would break writing. **The binder is now attached at every site.** For `JobProfile.cs` this was measured rather than assumed, and the measurement is the evidence that the finding is closed there: with the binder absent, a `$type` nested in `JobResultWrapper.Result` — a member declared `dynamic` — **instantiated `System.Diagnostics.Process`**; with the binder attached, the same payload is refused with a `JsonSerializationException`. Eight further gadget discriminators are refused at an `object` target, each against a control confirming the default binder resolved them. Every legitimate payload at all five consumers reached through the four sites deserialises **byte-identically with and without the binder**, which is what demonstrates that constraining resolution preserved existing installations. **The allow-list has since been narrowed a second time, and that narrowing is part of this finding's closure rather than an enhancement.** Review finding `F-03` observed that the list, while no longer a name prefix, still admitted "service/repository/background types", and that was correct: built by scanning five namespaces *and their descendants*, it admitted a measured **268** types, of which **38 carry behaviour rather than data** — seven repositories, thirteen object-mapping profiles, eight converters, three attributes, two ambient contexts, two managers, a job pool, a job data service and an exception. That breadth was **verified reachable, not merely theoretical**: because `JobResultWrapper.Result` is declared `dynamic`, `DbRecordRepository`, `JobPool`, `JobManager` and `JobDataService` were all successfully instantiated through a discriminator in the `jobs.result` column, and two of them through a value nested in a dynamic record as well. The namespace scan is replaced by an explicit `typeof` inventory of **45** persisted types — the transitive closure, over data members only, of what the deserialisation sites actually read — so behaviour-carrying types admitted falls from 38 to **zero** while all nine round-trip shapes continue to pass and the 27 permitted framework types are unchanged. A latent break was closed in the same edit: `CurrencySymbolPlacement`, which a currency field genuinely reaches, sat outside all five scanned namespaces and was being refused. Two counts in this record are also corrected by measurement: the binder is attached at **20** sites rather than the fourteen originally enumerated — the six additional ones are four serialise-only settings in `JobDataService.cs` and two in `NotificationContext.cs`, the latter covering the PostgreSQL `NOTIFY` payload — and the permissive type handling those six sites carry was present before remediation, so the original site census undercounted the surface. See the remediation log for the full transcript, the before-and-after measurements and the recorded deviation from the planned rule-based mechanism. |

#### H-11 — SMTP certificate validation unconditionally bypassed

| Field | Value |
| --- | --- |
| **FINDING** | The mail plugin installs a certificate-validation callback that returns `true` unconditionally at five sites, so every SMTP connection accepts any certificate. |
| **SEVERITY** | High — transport authentication is removed entirely, which makes an active machine-in-the-middle attack on mail delivery trivial. |
| **CWE** | [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` at four sites, and `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` at one. |
| **DESCRIPTION** | The callback is not conditional on environment, configuration or host — it always accepts. Maps to **OWASP A02:2021 Cryptographic Failures**. |
| **IMPACT** | An attacker who can intercept the connection reads every outbound message and the SMTP credentials used to send it. This compounds with M-17, because exception detail is e-mailed before it is persisted, and with the mail-library injection advisories recorded as H-20. |
| **EVIDENCE** | Corroborated by the analyzer gate independently of manual review: at the pre-remediation revision `CA5359` (do not disable certificate validation) reported diagnostics at **exactly these five sites** on every build. At this commit the rule reports **none**, because a callback is installed only when the configuration-gated policy member allows it and the callback yields that member rather than a literal `true`. The diagnostic disappearing is itself evidence that the unconditional accept is gone. |
| **REMEDIATION** | **Remediated, and closed at all five sites.** The always-true callback was first replaced by an explicit configuration flag defaulting to secure, so a self-signed development server stays usable without an insecure default shipping to production; the flag was then narrowed so it is honoured **only** in Development posture. `SmtpService.AllowInvalidRemoteCertificates` yields `true` only when `Settings:EmailSMTPAllowInvalidCertificates` parses as `true` **and** `ErpSettings.DevelopmentMode` is set; otherwise it yields `false` and, when the setting was nevertheless enabled, reports the refusal once per process on standard error. Because that one member gates every callback site, the four `SmtpService.cs` sites and the one `SmtpInternalService.cs` site are covered by the same change, and `ErpSettings.DevelopmentMode` defaults to `false` so the policy fails closed before configuration is initialised. No analyzer diagnostic was suppressed to reach this state — `CA5359` stopped firing because the construct it reports is gone. **One consequence of enabling validation had to be remediated in turn**, and is recorded rather than smoothed over: MailKit checks certificate revocation by default and none of the five sites configured it, so a relay whose certificate is entirely valid but whose chain names no reachable CRL distribution point — an internal CA that publishes none, or a host whose egress filtering blocks the fetch — became unreachable, failing with a chain status of nothing but `unable to get certificate CRL`. Because the accept-any opt-out is deliberately inert in production it was no remedy, so all five sites now assign `client.CheckCertificateRevocation` from a second policy member, `SmtpService.CheckRemoteCertificateRevocation`, which reads `Settings:EmailSMTPCheckCertificateRevocation` and **defaults to checking**: only an explicit boolean `false` disables it, and absent, blank, `true` and unparseable values all leave it enabled. That member carries no posture gate, deliberately — disabling revocation still leaves the trust chain, validity dates, key usage and host name enforced, a far narrower relaxation than accepting any certificate, and a control that is inert in production cannot remedy a production outage. Operator guidance is in the [secure configuration guide](secure-configuration.md); the residuals — a Development installation still accepting any certificate, by design, and an installation that has knowingly disabled revocation checking — are recorded as `RISK-033` and `RISK-060` in the [risk register](risk-register.md). |

#### H-12 — Development mode enabled in every shipped configuration

| Field | Value |
| --- | --- |
| **FINDING** | All eight shipped `Config.json` files enable development mode, and one host's deployment manifest additionally forces the environment to `Development`. |
| **SEVERITY** | High — development mode turns on the developer exception page, which returns stack traces, source excerpts and configuration to any client that triggers an error. |
| **CWE** | [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html) and [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |
| **LOCATION** | All eight `Config.json` files, plus `WebVella.Erp.Site/web.config` where `ASPNETCORE_ENVIRONMENT` is set to `Development`. |
| **DESCRIPTION** | The environment marker is what selects the developer exception page in each host's pipeline, so the shipped defaults expose internal detail on any unhandled error in a production deployment that kept them. Maps to **OWASP A05:2021 Security Misconfiguration**. |
| **IMPACT** | Stack traces disclose file paths, type and method names, framework versions and query text, which materially shortens the reconnaissance phase of an attack against every other finding in this report. |
| **EVIDENCE** | The development-mode flag is present in all eight files and the environment variable is set in the deployment manifest at the pre-audit revision. |
| **REMEDIATION** | **Fixed.** An earlier revision of this row said "not yet remediated" and that the finding "remains open"; both are retracted. All eight shipped configuration files now set `"DevelopmentMode": "false"` explicitly, and the setting is evaluated as `IsNullOrWhiteSpace(value) ? false : bool.Parse(value)`, so removing the key would resolve to `false` as well — there is no state in which a missing value silently enables development behaviour; and `WebVella.Erp.Site/web.config` sets `ASPNETCORE_ENVIRONMENT` to `Production`. Note the residual operational hazard: an environment variable outranks the file, so a stray `Settings__DevelopmentMode=true` re-enables development behaviour - audit the environment, not only the files. Flipping the flags was a two-line change per file, but it must land with the provider-chain extension so that hosts remain startable. Two related error paths are worth separating out, because a configuration change alone will **not** fix them: two API error responses concatenate stack-trace text unconditionally, with no environment check at all, so those require a code change and are tracked with their own finding. The flags are flipped, so this finding is closed. |

#### H-15 — No HTTPS enforcement, no HSTS, and insecure cookie attributes

| Field | Value |
| --- | --- |
| **FINDING** | Eight of the nine applications enforced nothing about transport security: no HTTP Strict Transport Security, no redirection from plaintext, and authentication cookies without the `Secure` and `SameSite` attributes. |
| **SEVERITY** | High — an attacker positioned on the network downgrades the connection and reads the session cookie, which is session hijacking. |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) and [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html) |
| **LOCATION** | Cookie options in each host's `Startup.cs`; only `WebVella.Erp.WebAssembly/Server/Program.cs` used the framework's HSTS middleware. |
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
| **LOCATION** | Both credential-verification entry points: `WebVella.Erp.Web/Pages/login.cshtml.cs` and the anonymous bearer-token route `GetJwtToken` in `WebVella.Erp.Web/Controllers/WebApiController.cs`. The plan named only the first; the second is a second credential oracle and is throttled too. The service introduced to close it is `WebVella.Erp.Web/Services/LoginThrottleService.cs`. |
| **DESCRIPTION** | Nothing in the platform recorded a failed attempt, so an attacker could submit unlimited guesses against a known e-mail address at whatever rate the server would serve. Maps to **OWASP A07:2021**. |
| **IMPACT** | Credential stuffing and password guessing are unbounded. The exposure was worse before `C-03`, because the fast unsalted digest made server-side verification nearly free; the new key-derivation cost is itself a partial mitigation, but a cost is not a limit. |
| **EVIDENCE** | A repository-wide search of the pre-audit revision finds no attempt counter, no lockout state and no rate limiter. The one artefact whose name suggested it — an authentication cache — was entirely commented out. |
| **REMEDIATION** | A throttle service implementing the mandated five-attempt lockout with a fifteen-minute window, keyed on both the account and the client address, and backed by the platform's existing in-process cache so that **no schema change and no new dependency** is introduced — the least invasive control available. Every member is non-throwing by construction, so the throttle can never itself break the login path, and key components are length-bounded and normalised defensively. Its single-instance scope is a real limitation and is documented rather than hidden: behind a load balancer, each instance counts separately. **The service is now wired into the login page** - an earlier revision of this row said it "has no callers yet", which is retracted. `login.cshtml.cs` calls `TryBeginAttempt` before authenticating, then `RegisterFailedAttempt`, `RegisterSuccess` or `AbandonAttempt` on the corresponding outcome. Wiring reaches **both** credential entry points, not only the one this finding named: the anonymous bearer-token route in `WebApiController` follows the identical reserve-then-finalise sequence, and the token-refresh route — which presents no username to count against — uses the address-only `IsAddressRefusing` / `RegisterAddressFailure` pair. The framework's transport-level rate limiter is additionally enabled in all seven host pipelines, so the two controls layer rather than substitute for one another. |

#### H-18 — Two projects targeted an end-of-life framework

| Field | Value |
| --- | --- |
| **FINDING** | Two projects targeted .NET 7, which reached end of support on 14 May 2024 and therefore receives no security patches. |
| **SEVERITY** | High — an unsupported runtime cannot be patched, so any future advisory against it is permanently unfixed. |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) |
| **LOCATION** | `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` and `WebVella.Erp.WebAssembly/Shared/WebVella.Erp.WebAssembly.Shared.csproj` |
| **DESCRIPTION** | Both projects declared `<TargetFramework>net7.0</TargetFramework>` while the other seventeen projects in the repository targeted `net10.0`, and the Server project additionally pinned `Microsoft.AspNetCore.Components.WebAssembly.Server` to `7.0.13` — a package line on the same unsupported branch. Maps to **OWASP A06:2021 — Vulnerable and Outdated Components**. |
| **IMPACT** | This is not a specific exploitable defect; it is the absence of a route to fix one. Because the branch is out of support, a future advisory against the .NET 7 runtime or its ASP.NET Core packages would have no patched version to move to, so the exposure would become permanent rather than temporary. |
| **EVIDENCE** | At the pre-audit revision, `<TargetFramework>net7.0</TargetFramework>` appears at line 4 of both project files and the hosting package is pinned at `7.0.13`. |
| **REMEDIATION** | Both projects retargeted to `net10.0` and the hosting package lifted to `10.0.1`, bringing them onto the same supported target the other seventeen projects already use. No source change was required in either project. |

#### H-19 — Case-mismatched project references broke the dependency scan

| Field | Value |
| --- | --- |
| **FINDING** | Fifteen project references named the core project's directory as `WebVella.ERP` while the directory on disk is `WebVella.Erp`, so solution-wide restore failed on any case-sensitive filesystem and the core project silently dropped out of the dependency-audit graph. |
| **SEVERITY** | High. This is a build defect whose *security* consequence is that the vulnerability scan reported falsely clean, which is worse than reporting a finding: it produced confident, wrong assurance. |
| **CWE** | CWE-1104-adjacent — the effect is unaudited components rather than a code weakness. |
| **LOCATION** | `WebVella.ERP3.sln` and fourteen project files. The already-correct reference at `WebVella.Erp.Site/WebVella.Erp.Site.csproj` is the in-repository template the fix follows. |
| **DESCRIPTION** | MSBuild resolves the path literally, so on Linux the reference could not be found and restore failed with `MSB3202`. Because the core project owns the platform's only High-severity package advisory, its absence from the graph meant the advisory was never reported. Maps to **OWASP A06:2021** and **A08:2021**. |
| **IMPACT** | Every dependency-scan result obtained before this fix was unfounded, including any "no vulnerable packages" statement. The single host whose reference was already correct restored successfully, which is exactly what made the defect easy to miss: a per-project scan passed while the solution-wide scan failed. |
| **EVIDENCE** | The upper-cased segment appeared at fifteen sites; solution restore failed with `MSB3202` on a case-sensitive filesystem; the correct spelling was already present at one host, proving the fifteen were the outliers. |
| **REMEDIATION** | All fifteen paths corrected to match the on-disk casing — a no-op on case-insensitive filesystems and a repair on case-sensitive ones. Every one of the fourteen corrected project files now carries an identically worded comment naming the threat, so the constraint cannot be undone by a well-meaning edit; the solution file is excluded because its format tolerates no comment syntax. Verified: `grep -rn 'WebVella\.ERP\\'` returns nothing, and `MSB3202` and `MSB9008` counts are zero across a full solution rebuild. **This class was sequenced first**, because every subsequent dependency claim in this report depends on it. |

#### H-20 — Mail and MIME libraries carried published advisories

| Field | Value |
| --- | --- |
| **FINDING** | The mail plugin depended on a version of `MailKit` affected by a STARTTLS response-injection advisory, and transitively on a version of `MimeKit` affected by a CRLF-injection advisory. |
| **SEVERITY** | High. Both advisories are rated Moderate by their publisher, but they compound in this codebase: the plugin handles user-influenced recipient addresses *and* disables transport certificate validation at five sites (finding `H-11`, owned by a later class), so an injection defect meets an absent certificate check on the same path. |
| **CWE** | [CWE-74: Improper Neutralization of Special Elements in Output](https://cwe.mitre.org/data/definitions/74.html) for the transport advisory and [CWE-93: Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html) for the MIME advisory. |
| **LOCATION** | `WebVella.Erp.Plugins.Mail/WebVella.Erp.Plugins.Mail.csproj` — the `MailKit` package reference. `MimeKit` is not referenced directly; it resolves through `MailKit`. |
| **DESCRIPTION** | `MailKit` was referenced at `4.14.1`. Advisory [GHSA-9j88-vvj5-vhgr](https://github.com/advisories/GHSA-9j88-vvj5-vhgr) / CVE-2026-41319 describes STARTTLS response injection through an unflushed stream buffer, enabling an authentication-mechanism downgrade, and is first patched at `4.16.0`. The resolved `MimeKit` was `4.14.0`; advisory [GHSA-g7hc-96xr-gvvx](https://github.com/advisories/GHSA-g7hc-96xr-gvvx) / CVE-2026-30227 describes CRLF injection in a quoted local part, enabling SMTP command injection and message forgery, and is first patched at `4.15.1`. |
| **IMPACT** | Response injection during the STARTTLS handshake lets a network-positioned attacker influence which authentication mechanism is negotiated, which is a downgrade toward weaker or plaintext authentication of the mail credential. CRLF injection in an address lets a caller who can influence a recipient string inject additional SMTP commands, forging messages from the platform's own mail identity. |
| **EVIDENCE** | Reproduced with the toolchain's own dependency audit before the change: `dotnet list package --vulnerable --include-transitive` for the mail project reported both the `MailKit` and the `MimeKit` rows. |
| **REMEDIATION** | **One line closed both.** `MailKit` was raised to `4.17.0`, whose package metadata depends on `MimeKit 4.17.0`, so the transitive dependency is lifted past its own first-patched version without a second manifest entry. Verified after the change: `dotnet list package --include-transitive` reports `MailKit 4.17.0` and `MimeKit 4.17.0`, and the vulnerability listing reports neither. Adding an explicit `MimeKit` reference was deliberately avoided — it would have pinned a transitive dependency for no benefit, which is more change than the fix requires. |

### Medium severity findings

The first two findings below sit in the same file as `C-03` and were closed by the same edit. They are
recorded separately because they are distinct weaknesses with distinct identifiers, and because one of
them is closed on the live path today while the other is closed in the code as written — a difference
this report states rather than blurs. The third is documented only, per the severity matrix.

#### M-01 — No security response headers

| Field | Value |
| --- | --- |
| **FINDING** | The platform emitted none of the security response headers the engagement mandates. |
| **SEVERITY** | Medium — *missing security headers* sits in the Low tier of the severity matrix, but the absence of a content-security policy and of frame and content-type protections is what makes several other findings exploitable in a browser, so it is recorded here as the compensating control it is. |
| **CWE** | — (missing hardening control rather than a code weakness) |
| **LOCATION** | The seven host pipelines. The middleware introduced to close it is `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`. |
| **DESCRIPTION** | Only one project — the WebAssembly server — used any header middleware at all, and that was transport security alone. None of the seven site hosts emitted a content-security policy, frame options, content-type options, referrer policy or permissions policy. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | Without `X-Content-Type-Options: nosniff` an uploaded file served with a benign type can be re-interpreted as script; without `X-Frame-Options` the interface can be framed for clickjacking; without a content-security policy an injected script has no second line of defence. These headers are what bound the damage when another control fails. |
| **EVIDENCE** | A repository-wide search of the pre-audit revision finds header middleware in exactly one project, emitting transport security only. |
| **REMEDIATION** | A middleware emitting all seven mandated headers with the exact mandated values. **The content-security policy ships in report-only mode**, with the enforced value configurable: four components in the platform deliberately emit inline script or author-supplied markup, so enforcing the policy immediately would break working features and violate the requirement that existing functionality be preserved. The value is never weakened — only its delivery mode is staged, and the report-then-enforce path is documented. The middleware writes headers before the response starts and does not overwrite a header a host has already set, so a host with a stricter policy keeps it. **The middleware is now registered and ordered in all seven pipelines** - an earlier revision of this row said it "has no callers yet", which is retracted. It sits ahead of response compression and ahead of both static-file middlewares in every host, and all seven headers were verified **on the wire** against a published host on a dynamic response and on two static assets. The delivery switch binds from configuration — one key, `SecurityHeaders:ContentSecurityPolicyReportOnly` (environment variable `SecurityHeaders__ContentSecurityPolicyReportOnly`), which fails safe to report-only on an absent, blank or unparseable value — so advancing the rollout to enforcement requires no code change. It is the **only** member of the options type bound from configuration; the policy text itself is a `public const`, so no configuration source can weaken it. There is **no** violation-report endpoint: the collector and its `report-uri` directive were removed in full, which is why the emitted value stays byte-identical to the mandated policy and why `Invoke` has exactly one path through it — verified as zero `return` statements and exactly one `await next(context)`. |

#### M-03 — Sign-in call not awaited

| Field | Value |
| --- | --- |
| **FINDING** | The cookie sign-in call was invoked without being awaited, so the returned task was abandoned. |
| **SEVERITY** | Medium. |
| **CWE** | — (unobserved asynchronous operation) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs` — the sign-in call, and its single caller `WebVella.Erp.Web/Pages/login.cshtml.cs`. |
| **DESCRIPTION** | `httpContextAccesor.HttpContext.SignInAsync(...)` was called and its task discarded, so the sign-in could still be in flight when the response began, and any exception it raised was never observed. |
| **IMPACT** | A race between writing the authentication cookie and completing the response, which manifests as an intermittent failure to be logged in after a correct credential, and — the security-relevant half — swallows any error raised while establishing the session, so a failed sign-in can be indistinguishable from a successful one. |
| **EVIDENCE** | The un-awaited call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | The call is awaited, which necessarily makes the method asynchronous and propagates to its single caller — the login page handler, which becomes `async Task<IActionResult>`. That propagation is why the login page appears in this class's change set: it is compile-mandated, not opportunistic, and reverting it would break the build. **The sign-*out* counterpart was left in place at the time and has since been closed by review finding `F8`:** `Logout()` discarded the task returned by `SignOutAsync` in exactly the same way, which was recorded as observed and out of that finding's cited range. It is now `async Task LogoutAsync()`, awaited at both of its handlers, which additionally orders the server-side session revocation before the response is written rather than racing it. |

#### M-04 — Local time used for token timestamps

| Field | Value |
| --- | --- |
| **FINDING** | Token expiry was computed from local server time rather than UTC. |
| **SEVERITY** | Medium. |
| **CWE** | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/AuthService.cs` — the token construction. |
| **DESCRIPTION** | `expires: DateTime.Now.AddMinutes(...)`. Token expiry claims are defined in UTC, so on any host not set to UTC the effective lifetime was shifted by the offset. |
| **IMPACT** | West of UTC the token expires *later* than intended — silently extending session lifetime, which is the security-relevant direction; east of UTC it expires early, which is a functional defect. Either way the configured lifetime is not the actual one, and a daylight-saving transition changes it again. |
| **EVIDENCE** | The `DateTime.Now` call is present verbatim at the pre-audit revision. |
| **REMEDIATION** | Changed to `DateTime.UtcNow`, so the claim means what it says regardless of host timezone. |

#### M-05 — Password hash comparison was not constant time

| Field | Value |
| --- | --- |
| **FINDING** | The legacy hash comparison used an ordinal string comparer, which stops at the first differing character, so its duration revealed how many leading characters of the stored digest were already correct. |
| **SEVERITY** | Medium — *weak cryptography* under the engagement severity matrix. |
| **CWE** | [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs` — `VerifyMd5Hash`, at `L28-L29` of the pre-audit revision. |
| **DESCRIPTION** | `return (0 == StringComparer.OrdinalIgnoreCase.Compare(hashOfInput, hash));` short-circuits on the first mismatching character. The same member also returned **true** for an empty password against an empty stored digest, because both operands collapsed to `string.Empty`. |
| **IMPACT** | A timing oracle lets an attacker who can measure response latency reconstruct a stored digest one character at a time, reducing recovery from a search over the whole digest space to a linear walk. The empty-against-empty case is the more direct defect: an account with no stored credential would authenticate with no password. Scope is bounded, and the bound is stated plainly: at the pre-audit revision this member had **no callers**, so neither weakness was reachable — the live credential comparison happened inside the SQL predicate at `SecurityManager.cs:L85`. It becomes reachable, and therefore matters, exactly when credential resolution is switched onto `VerifyPassword`. |
| **EVIDENCE** | The pre-audit member body is the two lines quoted above; a search of that revision finds no caller of `VerifyMd5Hash` outside the file. |
| **REMEDIATION** | The comparison is now `CryptographicOperations.FixedTimeEquals` over equal-length byte spans, which inspects every byte regardless of where the values diverge. Casing is normalised before the comparison to preserve the case-insensitive tolerance the previous code had — normalising is not secret-dependent branching, so it does not reintroduce the oracle — and length is checked first on purpose, because fixed-time comparison is only fixed-time across equal-length spans and a length difference is not a secret that can be probed for. Absent input now fails closed on both sides, so the empty-against-empty case can no longer authenticate. **A second, distinct timing discrepancy at the *caller* level was subsequently identified as review finding `F28` and closed in a later pass.** Closing `M-05` inside the comparison did not close it: `SecurityManager.GetUser(email, password)` returned before any key derivation whenever the submitted password exceeded the 128-character bound, while an absent or legacy row still performed a 600,000-iteration dummy derivation — so latency alone answered *does this account exist*. The bound is now enforced **before** the lookup, and the dummy derivation is driven by an `out bool keyDerivationPerformed` fact reported by the verifier rather than predicted from the stored value's shape, so exactly one derivation happens on every credential path regardless of row or hash shape. Measured against a live database, the four failing paths are now indistinguishable: modern 123.0 ms, legacy 121.4 ms, corrupt 122.0 ms, absent 120.9 ms, and every over-long submission returns in 0.0 ms without touching the database. |

#### M-06 — Shared mutable hash instance used from concurrent requests

| Field | Value |
| --- | --- |
| **FINDING** | A single static, mutable MD5 instance was shared by every caller, and MD5 instances are not thread-safe. |
| **SEVERITY** | Medium. |
| **CWE** | [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html) |
| **LOCATION** | `WebVella.Erp/Utilities/PasswordUtil.cs:L9` of the pre-audit revision. |
| **DESCRIPTION** | `private static MD5 md5Hash = MD5.Create();` was held for the process lifetime and used from `GetMd5Hash` without any synchronisation. Two concurrent calls could interleave inside `ComputeHash` and corrupt each other's digest. |
| **IMPACT** | An interleaved computation yields a digest belonging to neither input. On a credential path that produces a spurious authentication failure at best, and a non-deterministic stored value at worst — a correctness and availability defect on a security-critical path, not merely a race in incidental code. Unlike `M-05`, this one was genuinely reachable: `GetMd5Hash` had, and still has, four live call sites across credential resolution and the two record write paths. |
| **EVIDENCE** | The single shared instance is the declaration quoted above; `GetMd5Hash` referenced it directly. Live callers at `SecurityManager.cs:L84`, `RecordManager.cs:L2017`, `DbRecordRepository.cs:L554` and `:L1856`. |
| **REMEDIATION** | The shared instance was removed and replaced with the static one-shot `MD5.HashData(...)`, which keeps no shared state, is correct under concurrency and needs no lock. **Closed on the live path**, because the replacement sits in the member those four callers already use. |

#### M-08 — Deterministic initialisation vector in the symmetric encryption helpers

| Field | Value |
| --- | --- |
| **FINDING** | The initialisation vector used by the symmetric encryption helpers is derived from the encryption key, so it is identical for every operation and the same plaintext always produces the same ciphertext. |
| **SEVERITY** | Medium — *weak cryptography* under the engagement severity matrix, which directs Medium findings to documentation with fix guidance rather than to remediation. |
| **CWE** | [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html) |
| **LOCATION** | `WebVella.Erp/Utilities/CryptoUtility.cs` — the key and initialisation-vector derivation helpers |
| **DESCRIPTION** | The vector is computed from the key rather than generated per operation, and the cipher mode is unauthenticated. A deterministic vector removes semantic security: an observer of two ciphertexts can tell whether the underlying plaintexts were equal. The mandated cryptographic standards name AES-256-GCM, an authenticated mode, which this construction is not. Maps to **OWASP A02:2021 — Cryptographic Failures**. |
| **IMPACT** | Equality between encrypted values leaks, which for low-entropy plaintexts is close to leaking the values themselves, and an unauthenticated mode gives no detection of ciphertext tampering. The impact is bounded, and the bound is stated plainly rather than used to dismiss the finding: **the symmetric encrypt and decrypt members have no callers anywhere in the repository**, so no data is protected by this construction today. It is latent, not live. |
| **EVIDENCE** | The derivation helpers compute the vector from the key material; a repository-wide search finds no caller of the symmetric encrypt or decrypt members. |
| **REMEDIATION** | **Documented, deliberately not changed** — the disposition is recorded as `RISK-006` in the [risk register](risk-register.md), which carries the reasoning and the recommended fix. In short: the finding is Medium and latent, and changing the derivation or moving to an authenticated mode would make every already-persisted ciphertext undecryptable, which the requirement that existing functionality remain operational forbids. Recommended fix when a caller is first introduced — generate a fresh cryptographically random vector per operation, store it alongside the ciphertext, and prefer AES-256-GCM. Doing this *before* the first caller exists costs nothing, because there is no persisted ciphertext to migrate; afterwards it requires a re-encryption migration. Any `CA5389`, `CA5390` or `CA5401` diagnostic on that region is expected and is left visible as a warning rather than suppressed. |

#### M-15 — Client library loaded from a content delivery network without an integrity attribute

| Field | Value |
| --- | --- |
| **FINDING** | A client-side library is loaded from a third-party content delivery network with no subresource-integrity attribute, and the repository's browser-side assets are unversioned. |
| **SEVERITY** | Medium — a compromise of the delivery network, or of the account that publishes to it, executes attacker-chosen script on the application's origin. Documented with fix guidance; not remediated. |
| **CWE** | [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) |
| **LOCATION** | Browser-side assets — the repository contains 188 `.js` and 5 `.css` files and no client-side package manifest. |
| **DESCRIPTION** | Without an integrity attribute the browser accepts whatever the network returns. Because there is no client-side package manifest, the assets also have no recorded versions, so a compromised file cannot be detected by comparison. Maps to **OWASP A08:2021 Software and Data Integrity Failures**. |
| **IMPACT** | Script from a compromised delivery network runs with the same authority as the application's own script, so it can read the session and act as the user. |
| **EVIDENCE** | The script reference carries no `integrity` or `crossorigin` attribute, and no client-side package manifest exists anywhere in the repository. |
| **REMEDIATION** | **Documented, not changed.** Recommended fix: add an `integrity` hash and a `crossorigin` attribute to every externally hosted reference, or vendor the library into the repository so its bytes are version-controlled; then introduce a client-side package manifest so the browser-side assets carry recorded versions. The content-security policy this remediation introduces is a partial compensating control once it is enforced rather than report-only, because `default-src 'self'` refuses third-party origins outright. |

#### M-17 — Exception details e-mailed off-box before they are persisted

| Field | Value |
| --- | --- |
| **FINDING** | The logging service sends an exception notification by e-mail before writing the record to the database, so internal detail leaves the host on a channel the platform does not control. |
| **SEVERITY** | Medium — information disclosure to an external mail relay. Documented with fix guidance; not remediated as such, although both of the conditions that made its exposure sharp have since been removed — see the remediation field. |
| **CWE** | [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) and [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |
| **LOCATION** | `WebVella.Erp.Web/Services/LogService.cs` — the notification path in both create overloads. |
| **DESCRIPTION** | The serialised log payload carries the message, the source, the exception detail and the request URL. It does **not** carry request headers, cookies or the request body, which bounds the exposure materially. Maps to **OWASP A05:2021**. |
| **IMPACT** | Exception text and the requested URL reach whatever mail infrastructure is configured, including any intermediate relay. Before the mail transport's certificate validation was restored, that path was also not authenticated, so the content was exposed to an active network attacker as well. |
| **EVIDENCE** | The notification call precedes the persistence call in both overloads, and the payload shape is fixed by the log record type, which serialises the URL but no header, cookie or body. |
| **REMEDIATION** | **Documented, not changed** — it is a Medium and does not meet the compensating-control test that brings a Medium into remediation scope. Its exposure is bounded by the payload shape above, and it has since been materially mitigated twice over. First, the mail transport's certificate validation was restored at all five callback sites while closing H-11, so outside Development posture the notification no longer travels over an unauthenticated connection. Second, and larger: while closing review finding `F26` the twenty-eight notifying `LogService` writes on the web API surface were replaced by a non-notifying audit sink, `WebVella.Erp.Web/Utils/SecurityAuditLog.cs`, which writes through `Log.Create` with `LogNotificationStatus.DoNotNotify` and therefore cannot reach the mail path at all. The only two `LogService` calls left in that controller are the authorization-refusal paths that already passed `DoNotNotify` before this engagement, so the platform's largest anonymous-reachable fault surface now has **no** notification-eligible path. The finding itself is unchanged, because `LogService` still notifies before it persists wherever it is still used. Recommended fix, in order of preference: persist first and notify second, so a notification failure cannot lose the record; then reduce the notified payload to an identifier and a severity, leaving the detail retrievable only from the database. This finding is directly relevant to the token-validation audit record added by this remediation, which suppresses notification for exactly this reason — a notifying log on a path an attacker can trigger becomes a mail flood rather than a control. |

#### M-18 — The codebase's only output encoder was trivially bypassable

| Field | Value |
| --- | --- |
| **FINDING** | The platform's single output-escaping helper defended against exactly one literal string, `</script>`, by rewriting it — so any other spelling passed through untouched. |
| **SEVERITY** | Medium. It is remediated rather than merely documented because the defective encoder stands directly at a cross-site-scripting sink, which makes it a compensating control for a confirmed High finding rather than an isolated quality issue. |
| **CWE** | [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) |
| **LOCATION** | `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs` |
| **DESCRIPTION** | The helper performed `.Replace("</script>", "</s\\cript>")` on its input before emitting it raw. The replacement is case-sensitive and whitespace-sensitive, so `</SCRIPT>`, `</script >` and `</script\n>` — all of which a browser accepts as a closing script tag — were not rewritten. A repository-wide search found no other encoder of any kind: no `HtmlEncoder`, no `HtmlEncode`, no anti-XSS library. Maps to **OWASP A03:2021 — Injection**. |
| **IMPACT** | Any value emitted through this helper into a script block could terminate that block and open an attacker-controlled one, which is stored cross-site scripting with the encoder's own blessing. Because it was the only escaping utility in the codebase, its weakness set the platform's effective escaping standard. |
| **EVIDENCE** | The single-string replacement is present verbatim at the pre-audit revision; searches for `HtmlEncoder`, `WebUtility.HtmlEncode` and `HttpUtility.HtmlEncode` return nothing anywhere in the repository. |
| **REMEDIATION** | Replaced with the framework's `JavaScriptEncoder`, applied to **every** `<` rather than to one spelling of one tag, so no casing or spacing variant survives. Behaviour is preserved for legitimate content: a browser parsing a JavaScript string literal converts the escape back to `<`, so rendered output is unchanged while breakout becomes impossible. The escape is computed once into a static field rather than per call, keeping the helper on its original hot path. |

### Low severity findings

#### L-02 — Fifteen package references exist only inside XML comments

| Field | Value |
| --- | --- |
| **FINDING** | Fifteen `PackageReference` entries are commented out in the project manifests. They are not restored, not compiled against and not shipped. |
| **SEVERITY** | Low — a repository-hygiene issue with no runtime exposure. Documented for a future sprint. |
| **CWE** | Not applicable — no weakness is present; the entry exists to record why these references were **excluded** from the findings. |
| **LOCATION** | Across the project manifests. |
| **DESCRIPTION** | Recorded because the alternative is worse than the clutter: several of the commented entries name versions that carry genuine published advisories, including an image-processing package with an out-of-bounds-write advisory and four end-of-life framework packages. Because they are not in the build graph, **none of those advisories applies to this build**, and reporting them would have put false High-severity findings into this report. Maps to **OWASP A06:2021** only in the sense of preventing a misclassification. |
| **IMPACT** | None at runtime. The risk is analytical: a future reader, or a scanner that parses manifests textually rather than resolving them, may mistake these for live references and either raise false findings or, worse, uncomment one. |
| **EVIDENCE** | All fifteen entries are inside XML comments; the dependency audit reports no advisory for any of them, and the full inventory with versions is recorded in the third-party inventory document. |
| **REMEDIATION** | **Documented, not changed.** Removing them is code hygiene rather than remediation, and the minimal-change boundary forbids refactoring beyond security fixes. Recommended fix for a future sprint: delete the commented entries, since version-control history already preserves them. Until then, treat the inventory document as the authority on which references are live. |

#### L-04 — Large binary committed to the repository

| Field | Value |
| --- | --- |
| **FINDING** | A large binary artefact is tracked in the repository. |
| **SEVERITY** | Low — no runtime exposure. Documented for a future sprint. |
| **CWE** | Not applicable — a supply-chain hygiene observation rather than a weakness. |
| **LOCATION** | Tracked binary content, recorded in the third-party inventory document. |
| **DESCRIPTION** | A committed binary cannot be reviewed, its provenance is not recorded, and it is not covered by the dependency audit, because that audit resolves package references rather than files. Maps loosely to **OWASP A08:2021**. |
| **IMPACT** | If the binary were ever replaced with a modified copy, nothing in the build or the audit would notice. The exposure is bounded by the fact that it is not executed as part of the application's request path. |
| **EVIDENCE** | The artefact is present and tracked; no checksum or provenance record accompanies it. |
| **REMEDIATION** | **Documented, not changed.** Deleting it is repository hygiene, not security remediation, and doing so could break whatever consumes it. Recommended fix for a future sprint: establish the artefact's provenance, record a checksum, and either move it to a package reference or to large-file storage so its integrity is verifiable. |

#### L-07 — No lock file and an unpinned SDK version

| Field | Value |
| --- | --- |
| **FINDING** | `global.json` pinned no SDK version — the version key was commented out — so the toolchain floated, and the repository has no package lock file. |
| **SEVERITY** | Low — *minor misconfiguration* under the severity matrix. Its consequence is not a vulnerability but a loss of reproducibility in the very gates that detect vulnerabilities. |
| **CWE** | — |
| **LOCATION** | `global.json` |
| **DESCRIPTION** | The dependency-audit default behaviour and the analyzer rule set both vary by SDK version, so an unpinned toolchain means two developers, or a developer and a pipeline, can legitimately obtain different scan results from the same source. Maps to **OWASP A05:2021 — Security Misconfiguration**. |
| **IMPACT** | A gate whose result depends on the machine is not a gate. Without the pin, a "clean scan" claim is unverifiable by anyone else. |
| **EVIDENCE** | The pre-audit file contained `//"version": "7.0.103"` — commented out — and no `rollForward` policy; no `packages.lock.json` exists anywhere in the repository. |
| **REMEDIATION** | The SDK is pinned to `10.0.302` with **`rollForward: latestPatch`**, which is the policy the file's frozen contract mandates. Both halves of the gate — the audit defaults and the analyzer rule set — are selected by the SDK **feature band**, and `latestPatch` holds the pin on the `10.0.3xx` band, so the reproducibility the finding asks for is delivered while a security patch of the SDK itself is still admitted. `disable` was tried and rejected on availability grounds: it renders the repository unbuildable the moment this exact patch is superseded, for every developer and for CI simultaneously, which breaks the *all existing functionality remains operational* preservation requirement in exchange for a guarantee the feature band already provides. The accepted cost of `latestPatch` is a patch-level difference that does not cross the band; the failure mode when no matching SDK exists at all remains loud and names the required version. **The lock-file half is deliberately not done**: adding one changes restore behaviour for every project and every contributor, which is materially more invasive than the finding warrants, and the exact-version pins already present on the two most security-relevant packages give the same guarantee where it matters most. Recorded as remaining guidance rather than silently dropped. |

## Part 2 — Post-remediation review inventory

Findings against the controls as delivered. Identifiers in this part use the single-digit form and
form their own namespace.

### A note on how these findings were confirmed

Every finding below was verified against the actual repository state rather than inherited from a
plan. That mattered: **five security helpers had been added to the codebase and none of them was
reachable.** The hashing utility, the SQL identifier validator, the deserialisation binder, the
response-headers middleware and the login throttle all existed, compiled, and had **zero callers**.
Code that is never invoked provides no protection, and a review that reads only the new files would
have recorded five fixes where there were none. Several findings below are therefore of the form
*"the control exists but nothing calls it"* — which is why they are severity-rated on the
vulnerability that remained open, not on the quality of the unused helper.

### Critical severity findings

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

### High severity findings

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
| **LOCATION** | `WebVella.Erp/Api/Models/ErpSerializationBinder.cs`; 20 sites across the relation and entity repositories, job profiles, code generation and the notification context. |
| **DESCRIPTION** | Polymorphic type handling was configured to resolve type names embedded in serialized payloads, with no restriction on which types could be constructed. The binder that would have constrained this was never wired in — including at one site the original enumeration omitted entirely. Maps to **OWASP A08:2021 — Software and Data Integrity Failures**. |
| **IMPACT** | Unrestricted type resolution during deserialisation is a well-established remote-code-execution primitive: an attacker who influences a persisted payload can name a type whose construction or property setters produce arbitrary effects. |
| **EVIDENCE** | No attachment site existed. After remediation a harness of 45 assertions confirms that allow-listed types round-trip and non-allow-listed ones are refused, and that already-persisted payloads still deserialise. |
| **REMEDIATION** | **Fixed.** The binder is attached at all 20 sites. Type handling was **constrained rather than removed**, because already-persisted entity, relation and job payloads carry type discriminators and would otherwise fail to deserialise, breaking existing installations. |

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
| **REMEDIATION** | **Fixed, with a documented residual.** A 7-day absolute session horizon is stamped at issue, carried verbatim across every refresh, and enforced by refusing refresh past it and capping the refreshed expiry at it. Worst-case exposure falls from **unbounded to at most 7 days with no operator action**. Rotating revocable refresh tokens were **not** implemented, because they require persisting token identifiers — a schema change the constraints forbid. Consequently sign-out does not invalidate an already-issued token. Recorded as `RISK-007`. **Partially improved since, by review finding `F8`:** the residual had a second half that needed no schema change at all — signing out deleted one browser cookie and revoked nothing, so a cookie copied beforehand kept authenticating for the rest of the ticket lifetime. Every ticket now carries a per-sign-in session identifier that sign-out records as revoked and that a cookie-validation hook checks on every request, so the **cookie** half of this residual is closed. An already-issued **bearer token** is still not revocable, which is what remains of it. |

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
| **REMEDIATION** | **Fixed.** `Directory.Build.props` created with dependency auditing across all dependencies at the lowest reporting level, the dependency diagnostics promoted to **errors**, and .NET analyzers enabled. Expressed in MSBuild rather than an editor-configuration file because the four existing `.editorconfig` files each declare themselves a configuration root, so a root editor file would not reach their subtrees. A CI workflow runs restore, analyzer build and vulnerable-package listing. **Negative-tested**: injecting a package with a known advisory failed the build. **Subsequently strengthened** (review finding `F2`): enabling the analyzers made findings *visible* but could not make the build *fail*, because every analyzer diagnostic was a warning. `AnalysisLevelSecurity=latest-all` in the same properties file raises the Security category alone to every rule the pinned SDK defines in it, and the auto-discovered repository-root `.globalconfig` now promotes **ten of those security rules to `Error`** and holds **five** more at warning against an enumerated baseline - each first measured at zero diagnostics across all 19 projects, so the promotion requires no refactor and the build stays green on the current tree while any newly introduced violation breaks it. Measured after the change: `3096 Warning(s), 0 Error(s)`, differing from the previous baseline by exactly the rules the Security-category upgrade newly *enables* and which fire — `CA2100`, `CA2326`, `CA2328`, `CA5351` and `CA5362`, **five** rules, not the four an earlier revision of this row listed — and by nothing else. **Negative-tested in both directions**: a probe with a hard-coded AES key and `new Random()` fails with real `error CA5390` and `error CA5394` lines, and with the `AnalysisLevelSecurity` property removed that same probe builds clean - so the control detects a disarmed gate rather than only a violating one. **The scenario the finding named is proven directly**: reintroducing the accept-all certificate callback that `H-11` removed now fails with `error CA5359`. One shape of that defect is not detected by the rule and is recorded as `RISK-054`. |

#### H-10 — Two projects outside the solution, invisible to every gate

| Field | Value |
| --- | --- |
| **FINDING** | Two projects were not solution members, so solution-wide restore, build, audit and analyzers silently skipped them. |
| **SEVERITY** | High. |
| **CWE** | CWE-1104 (use of unmaintained third-party components). |
| **LOCATION** | `WebVella.ERP3.sln`; the WebAssembly `Server` and `Shared` projects. |
| **DESCRIPTION** | The solution contained 17 of 19 projects. The two omitted were precisely the two still targeting an end-of-life framework, so the projects most in need of scrutiny were the ones excluded from it. |
| **IMPACT** | A gate that does not see a project cannot report on it. Any "clean" solution-wide result was clean only over the subset that happened to be enrolled — a false negative by construction. |
| **EVIDENCE** | `dotnet sln list` returned 17; `dotnet list package` enumerated 17. After remediation both return **19** and agree for the first time. |
| **REMEDIATION** | **Fixed — all three halves, membership included.** *The framework half:* both projects are retargeted to `net10.0`, so no project remains on an end-of-life framework and finding H-18 is closed. *The inheritance half was never actually broken:* `Directory.Build.props` is **directory-scoped, not solution-scoped**, so both projects inherited all six gate properties regardless of membership — verified by evaluating `NuGetAudit`, `NuGetAuditMode`, `NuGetAuditLevel`, `WarningsAsErrors`, `EnableNETAnalyzers` and `AnalysisLevel` on each directly. *The membership half is now fixed too.* An earlier revision of this entry recorded that a brief enrolment had been reverted, on the reasoning that solution membership was outside the authorised change to that file. **The cumulative security review superseded that scope judgement**, requiring that both projects be added to the solution or else explicitly restored, built and audited in every gate. Both are now enrolled: `dotnet sln WebVella.ERP3.sln list` returns **19**, and one `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` enumerates all 19 by name, each reporting no vulnerable package. Inheritance and membership now agree, and a new workflow step asserts that agreement on every push by comparing `dotnet sln list` against `git ls-files '*.csproj'`, so a project added later cannot silently escape the gate. The coverage obligation this entry used to disclose is therefore discharged rather than merely documented. |

#### H-11 — Patched object-mapping library conflicts with the declared product licence

| Field | Value |
| --- | --- |
| **FINDING** | The `AutoMapper` package was pinned to a version affected by a published High-severity advisory, and **every** patched version is licensed incompatibly with this product's declared licence — so closing the advisory and preserving the licence posture were mutually exclusive. |
| **SEVERITY** | High. |
| **CWE** | [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj` (the package pin and the `<PackageLicenseExpression>`); `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` (the single construction site an upgrade would change). |
| **DESCRIPTION** | Advisory [GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x) / CVE-2026-32933 affects every version below `15.1.1` and, separately, the `16.0.0` line below `16.1.1`. Because the pin uses exact-version notation, no transitive resolution can lift the platform onto a patched version. **The blocking fact is licensing:** `14.0.0` declares MIT, while `15.1.1`, `15.1.2`, `15.1.3`, `16.1.1` and `16.2.0` are **all** under the Reciprocal Public License 1.5. The product declares Apache-2.0 and publishes packages to nuget.org for third-party consumption. Maps to **OWASP A06:2021**. |
| **IMPACT** | Unbounded recursion in a mapping graph exhausts the stack and terminates the hosting process, so the exposure is availability loss rather than disclosure or code execution. Every host and the console application resolve mapping through this package. **Real-world exploitability in this codebase is low:** all 379 mappings are statically declared in source, and no user-controlled configuration or type graph reaches the single configuration-construction site, so the recursion path requires a self-referential mapping the project's own developers would have to author and ship. Against that, upgrading would impose a reciprocal source-disclosure obligation on every downstream consumer of the published packages — an irreversible change to the product's licensing posture. |
| **EVIDENCE** | Reproduced with the toolchain's own audit against the pre-remediation pin: `dotnet list package --vulnerable --include-transitive` reported `AutoMapper [14.0.0] 14.0.0 High https://github.com/advisories/GHSA-rvv3-g6hj-g44x` in **16 of 19 projects**. Licensing verified against the package registry rather than assumed: the `.nuspec` of all five patched releases was read, and all five declare a licence **file** resolving to the Reciprocal Public License 1.5, while `14.0.0` declares `<license type="expression">MIT</license>`. Separately, `15.1.3` declares **five** dependencies against `14.0.0`'s one, including a four-package `Microsoft.IdentityModel.*` chain at `8.14.0` — **behind** the `8.15.0` this solution already references directly. Re-measured at this commit, `dotnet list WebVella.Erp/WebVella.Erp.csproj package --include-transitive` shows that chain resolving at `8.14.0` alongside `Microsoft.IO.RecyclableMemoryStream 1.3.2`, `Microsoft.Win32.SystemEvents 10.0.1`, `NetBox 2.3.5` and `NodaTime 3.2.2`, and `--vulnerable` reports **no vulnerable package in any of the 19 solution projects**, both WebAssembly projects included, in a single solution-wide command. |
| **REMEDIATION** | **Decided: the advisory is closed by upgrade, and the licensing consequence is formally accepted as a recorded residual rather than left open.** The two halves of this finding are separable and have been separated. *The advisory:* the pin is raised to `[15.1.3]`, the newest release on the lowest patched major, and the one code change the upgrade requires — supplying `NullLoggerFactory.Instance` to the 15.x `MapperConfiguration` constructor at the repository's single construction site — is in place. `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` now reports **no vulnerable package in any of the 19 solution projects** — all 19 in a single command, since both WebAssembly projects are solution members. **No audit suppression is declared anywhere**: `Directory.Build.props` contains no `NuGetAuditSuppress` element, and the gate is green because the graph is clean rather than because a diagnostic is silenced. *The licence:* every patched release is under the Reciprocal Public License 1.5 while the product declares Apache-2.0 and publishes to nuget.org, so the reciprocal source-disclosure obligation is a real and irreversible change to the product's licensing posture. **The disposition is now settled and recorded once, in `RISK-001`, as *decided*: keep `[15.1.3]`, accept the reciprocal-licence obligation as a residual, and leave exactly one bounded item for owner ratification — the licence expression declared on the published packages.** Three verified facts drive it. *First, there is no permissive escape:* the advisory's affected ranges are `< 15.1.1` and `>= 16.0.0, < 16.1.1`, so the lowest patched version is `15.1.1`; `14.0.0` is the last `14.x` release, there is no `14.0.1`, and the `.nuspec` of `15.0.0`, `15.1.1` and `15.1.3` each declare a licence **file** resolving to the Reciprocal Public License 1.5. Every patched version is reciprocal-licensed. *Second, the reversal path is no longer compatible with the gate it would have to pass through.* Retaining `[14.0.0]` requires suppressing `NU1903`, and because `AutoMapper` is present transitively in 16 project graphs a project-scoped suppression is insufficient — measured at exactly 15 residual `NU1903` errors. A repository-wide suppression, the only placement that works, is inherited by the CI negative-control probe as well, because `Directory.Build.props` is directory-scoped: the probe deliberately pins `AutoMapper 14.0.0` and *requires* its restore to fail, so suppression would disable the one step that proves Gate 2 can fail at all. That was verified by evaluating the probe's inherited properties and confirming its restore still fails with `error NU1903`. *Third, the reciprocity obligation is already satisfied in substance for this repository,* whose source is public; what is not settled is narrowly the licence **declared** to third-party package consumers. **No audit suppression is declared anywhere**, so the gate remains green because the graph is clean. |

### Medium severity findings

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

### Low severity findings

#### L-1 — Mandated policy publicly replaceable; report-only with nowhere to report

| Field | Value |
| --- | --- |
| **FINDING** | The mandated Content-Security-Policy value was exposed through a writable property, so it could be replaced at runtime by a blank or weaker value with nothing to detect it, and the policy was emitted in report-only mode with no endpoint to receive reports. |
| **SEVERITY** | Low. |
| **CWE** | CWE-16 (configuration), CWE-778 (insufficient logging). |
| **LOCATION** | `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`. |
| **DESCRIPTION** | A settable property allows the mandated policy to be weakened or replaced at runtime with nothing to detect it. Report-only mode without a collection endpoint discards every violation, so the staged rollout produces no evidence and can never progress. |
| **IMPACT** | A policy that can be silently replaced provides no guarantee. A report-only policy with no collector is indistinguishable from no policy at all: it blocks nothing and records nothing. |
| **EVIDENCE** | The value is now a compile-time constant, so weakening it is a compilation error rather than a runtime possibility. `Invoke` was verified to contain **zero** `return` statements and exactly one `await next(context)`, so there is a single path through the middleware and it always attaches all seven headers. The emitted `Content-Security-Policy-Report-Only` value was captured from a running host and compared byte-for-byte against the mandated directives; `report-uri` is absent, and `POST /csp-violation-report` no longer resolves to an anonymous 204 but falls through to the ordinary pipeline carrying all seven headers. |
| **REMEDIATION** | **Fixed, then corrected.** The value was made immutable (`public const`, compiler-enforced). An intermediate revision also added a real collection endpoint at `/csp-violation-report`, handled inside the middleware ahead of routing and authentication, together with a 120-reports-per-minute logging cap to close a **CWE-779 log-flooding** vector it introduced. **That endpoint and its `report-uri` directive were subsequently removed in full**, on review, for two independent reasons: the `report-uri` directive meant the emitted header no longer matched the value the audit mandates, and the collector's early return gave the middleware a path that completed a request **without attaching the other six headers** (`CFG-02`, `CFG-04`). Removal was chosen over re-ordering the branch because re-ordering leaves a second path a future edit can reintroduce the defect into, whereas removal makes it structurally impossible. The half of this finding about *reporting* is therefore answered differently than first implemented: violations are read from the **browser console** for the duration of the report-only rollout, which carries the same blocked-URI and violated-directive information without adding an anonymous write-accepting route; a deployment wanting aggregation should terminate `report-to` at a reverse proxy or dedicated collector, outside this middleware. `RISK-005`, which existed only to record the logging-versus-acceptance trade-off, is **retired** — the vector was deleted along with the component that carried it. The staged rollout remains progressable: the report-only/enforcing switch is now bound from configuration, so advancing it requires no code change (`RISK-022`). |

### Additional observations

Confirmed during verification, outside this checkpoint's finding scope. Recorded so they are neither
lost nor mistaken for regressions. Each is tracked in [the risk register](risk-register.md).

* **A ninth location containing secret material.** A setup instructions text file in one host carries
  token configuration guidance referencing the signing key, in addition to the eight configuration
  files enumerated by the audit. Found by the secrets sweep; recorded under the secret-management
  finding so the enumeration is complete.
* **Stack-trace disclosure on the bearer-token route is live and unconditional.** A failed token
  request was confirmed to return exception text, including a method trace, to an **anonymous**
  caller. Because the path is not guarded by any environment check, setting the environment to
  Production does **not** suppress it — it requires a code change.
* **~~A permissive `Access-Control-Allow-Origin: *` is live on one host.~~ Closed — it is live on
  none.** Originally confirmed on the login response of two hosts across three independent verification
  runs, then narrowed to one. Both hosts now serve an explicit origin allow-list and retain
  `AllowAnyOrigin()` only inside explanatory comments. The two superseded counts are quoted rather than
  deleted because both were published as this finding's status.
* **Analyzer evidence for the cryptography work, stated precisely.** The broken-algorithm rule
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

* **The shipped configuration files were not scrubbed by the checkpoint this section reports on — they
  have been since.** As reported here, all eight contained development connection strings with
  passwords, a development-mode flag set true, and the published token signing
  key. **That scrub has since landed**, in a later pass: all eight files now carry empty secret values
  and `"DevelopmentMode": "false"`, `web.config` sets `Production`, and the seeded administrator
  password is no longer a literal. The *enabling* half had landed first and made it possible — the
  provider chain that lets operators supply secrets externally, and validation that **rejects the
  published defaults** so a historically published signing key disables the bearer routes rather than
  being trusted. `RISK-021` is closed for the tracked files; the residual is `RISK-026`.
* **Enforcing the Content-Security-Policy needs two directives the mandated policy omits entirely** —
  an image directive permitting `data:` URIs, because framework markup emits a 1×1 GIF spacer, and a
  worker directive permitting `blob:`, because the source editor loads a syntax worker. Both currently
  fall through to the default directive and would break images and the editor on first enforcement.
* **The inline-emitting surface is wider than the four components originally identified**, additionally
  implicating a rich-text editor, a lazy-loading web-component bundle (inline style *and* `eval`), and
  the source editor.
* **Three navigation anchors use a `javascript:` placeholder href** — framework dropdown toggles,
  byte-identical on every page. **These are not injection sinks**, and are named so a future scan hit
  is not misread.
* One page returns HTTP 500 because its page model does not derive from the type its layout requires;
  **proven pre-existing by counterfactual**. Two vendored source-map files answer 405 rather than 404.
  One page's document title disagrees with its visible heading. Four accessibility advisories were
  observed. None is a security finding.
* **A fifth live upload route exists that the finding inventory does not enumerate.**
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
  unconstrained stored type — **not** stored cross-site scripting. Tracked as `RISK-033` in
  [the risk register](risk-register.md).

## Part 3 — Remaining inventory: findings documented for completeness

Part 1 records the findings the audit wrote up in full, and Part 2 the post-remediation review. A census of the engagement's finding identifiers against this documentation set showed that fifteen identifiers had no eight-field record anywhere, so they are recorded here in the same mandated format. Nothing in this part is new analysis of the platform's *design* — each entry was re-measured against the tree at this commit, and where a measurement contradicts an earlier expectation the measurement is what is written down.

Only one of the fifteen is above Medium: **H-07**, and it is recorded first for that reason. It was open and unremediated when this part was written and is now **closed**; the record below has been regenerated against the tree rather than left describing the earlier state. The rest are Medium and Low findings whose disposition is *document with fix guidance* under the engagement's severity matrix, plus two informational records — L-09, which evidences a category that was investigated and found not to apply, and L-10, which is closed by the workflow this change adds.

### Identifiers documented elsewhere rather than here

For completeness in the other direction: nine identifiers carry no eight-field record because their full treatment lives in a companion document. They are not missing.

| Identifier | Subject | Where it is documented |
| --- | --- | --- |
| `C-01` | Hardcoded default administrator password in provisioning | [credential migration guide](credential-migration.md) |
| `C-02` | Credential hash readable by non-administrator roles | [credential migration guide](credential-migration.md) |
| `C-05` | Guest role granted create permission on user and role entities | [credential migration guide](credential-migration.md) |
| `H-08` | Unrestricted file upload chaining into inline execution | cited in source as `H-08` but resolving to Part 2 `H-8`; see the [identifier index](#identifier-index) |
| `H-13` | Unconditional stack-trace disclosure on anonymous endpoints — **now closed, and subsequently widened far past the two anonymous paths**. Both bearer-token paths return a generic message outside Development and retain their server-side log record. Review finding `F26` then established that the same disclosure persisted at thirty-six further response sinks in `WebVella.Erp.Web/Controllers/WebApiController.cs`, ten of them concatenating `ex.StackTrace` as well; every one now routes through a single `SafeErrorMessage` helper. A solution-wide sweep found thirteen more unguarded sinks outside that controller — two in `RecordManager`, one in `EqlBuilder`, seven in the SDK `AdminController` and three in the Project plugin's `ProjectController` — and closed every one, leaving no unguarded exception-text response sink anywhere in the tree | [risk register](risk-register.md), `RISK-014` |
| `H-14` | Permissive cross-origin policy at two hosts — **now closed**; both hosts serve an explicit origin allow-list | [secure configuration guide](secure-configuration.md) and the `RISK-013` entry in the [risk register](risk-register.md) |
| `H-17` | Regular-expression denial of service in the credential query | [remediation log](remediation-log.md) and the [credential migration guide](credential-migration.md) |
| `M-13` | Password length bounds of 6 to 24 characters — **raised to 12–128 and, in a later pass, actually enforced.** The bounds were metadata only: every `MinLength`/`MaxLength` consumer in `EntityManager.cs` is commented out, so nothing rejected a one-character password. Review finding `F25` established that, and a single validator — `PasswordUtil.ValidatePasswordPolicy` — is now applied at every boundary where a human *chooses* a credential: both `SecurityManager.SaveUser` branches, `ERPService.ResolveInitialAdministratorPassword`, and the generic record-write path `RecordManager.CreateRecord`/`UpdateRecord` reaches through `POST api/v3/{culture}/record/user`. Deliberately **not** applied inside the hashing primitive or on the legacy rehash path — see `RISK-046` | [credential migration guide](credential-migration.md) |
| `L-01` | Dead security code | cited in source as `L-01` but resolving to Part 2 `L-1`; the dead-code observation is carried in the [secure configuration guide](secure-configuration.md) |

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
| **REMEDIATION** | **Fixed.** Every value now sits in a context it cannot escape. The callback index is parsed with `int.TryParse(..., NumberStyles.Integer, CultureInfo.InvariantCulture, ...)` and the request is rejected outright when it does not parse; thereafter it is carried as an `int`, so the bare — and therefore unquotable — numeric position holds no attacker-controlled text at all, which is why integer validation is both sufficient and lossless for what is simply a numeric callback index. The URL and message are emitted inside JavaScript string literals through `JavaScriptEncoder.Default`, which escapes the double quote to `\u0022` and also the backslash, the apostrophe, CR, LF, U+2028, U+2029 and `<` to `\u003C`, so neither the string literal nor the enclosing `</script>` element can be terminated. The echoed `ex.Message` is replaced by a fixed internal-error string while the exception continues to be logged server-side. All three sinks are funnelled through one helper, `BuildCKEditorCallback(int, string, string)`, whose signature makes the fix structural: the index cannot be a string at that boundary. `grep -c 'JavaScriptEncoder'` on the controller returns **2**, both inside that helper, and the fixed string is `INTERNAL_ERROR_MESSAGE` at `:L46`. No new dependency was required — the same encoder already backs the replaced output helper in `WebVella.Erp.Web/Utils/HtmlHelperExtension.cs`. The markup, the content type and the CKEditor callback contract are unchanged, so the editor behaves exactly as before. Verify with `grep -n 'BuildCKEditorCallback' WebVella.Erp.Web/Controllers/WebApiController.cs` — the declaration at `:L4310` and four call sites (`:L5224`, `:L5239`, `:L5255`, `:L5268`), with the `int.TryParse` guard at `:L5203`. |

#### M-02 — No antiforgery validation on the MVC API surface

| Field | Value |
| --- | --- |
| **FINDING** | No antiforgery validation on the MVC API surface |
| **SEVERITY** | Medium |
| **CWE** | CWE-352 (OWASP A01:2021) |
| **LOCATION** | `WebVella.Erp.Web/Controllers/WebApiController.cs` (the whole controller); contrast `WebVella.Erp.Web/Pages/login.cshtml.cs` |
| **DESCRIPTION** | No antiforgery attribute or global filter exists anywhere in the solution: a repository-wide search for `ValidateAntiForgeryToken`, `AutoValidateAntiforgeryToken`, `IgnoreAntiforgeryToken` and `AddAntiforgery` in `*.cs` returns nothing. The state-changing MVC API endpoints therefore accept cookie-authenticated requests with no request-bound token. The finding is correctly narrowed to the MVC surface: Razor Pages validate antiforgery by convention, which is why the login page is not affected. |
| **IMPACT** | A cookie-authenticated user who visits a hostile page can be made to issue state-changing API calls. The residual risk is reduced but not removed by the `SameSite=Lax` cookie policy the remediation added, which blocks cross-site *form* posts of the session cookie for unsafe methods. |
| **EVIDENCE** | `grep -rn 'ValidateAntiForgeryToken\|AutoValidateAntiforgeryToken\|IgnoreAntiforgeryToken\|AddAntiforgery' --include=*.cs .` returns no match at this commit. |
| **REMEDIATION** | Documented, deliberately not enforced. Existing JavaScript clients post without a verification token, so switching on validation would break working functionality — which the preservation requirement forbids. The zero-breakage half of the control (the `SameSite` and `Secure` cookie attributes) has been applied. Enforcement should be staged: emit the token in the layout, attach it from the platform's own AJAX helper, then enable `AutoValidateAntiforgeryToken` once telemetry shows no untokened callers remain. |

#### M-07 — Unbounded script-evaluation cache holding compiled delegates

| Field | Value |
| --- | --- |
| **FINDING** | Unbounded script-evaluation cache holding compiled delegates |
| **SEVERITY** | Medium |
| **CWE** | CWE-770, CWE-94 |
| **LOCATION** | `WebVella.Erp.Web/Services/CodeEvalService.cs:L13` (the cache) and `:L46` (the unbounded insert) |
| **DESCRIPTION** | Compiled page-component scripts are memoised in a `private static readonly Dictionary<string, object>` keyed by a digest of the script text. Nothing removes an entry: the file contains no `Remove`, `Clear` or eviction call of any kind, and the dictionary is not a size-bounded cache. |
| **IMPACT** | Each distinct script text permanently retains a compiled object and its loaded assembly, so a workload that generates many script variants grows process memory without bound and cannot release it. Because the cache holds executable delegates keyed only by content digest, it also lengthens the lifetime of any code a privileged author has injected. |
| **EVIDENCE** | `private static readonly Dictionary<string, object> scriptObjects = new Dictionary<string, object>();` at `:L13`; `scriptObjects[md5Key] = scriptObject;` at `:L46`; `grep -c 'Remove\|Clear\|Evict\|MemoryCache'` over the 62-line file returns **0**. |
| **REMEDIATION** | Documented, deliberately not changed — it is a resource-exhaustion concern rather than a confirmed Critical or High, and the minimal-change rule keeps it out of the remediation. The recommended fix is to replace the dictionary with a size-bounded `MemoryCache` carrying a `SizeLimit` and a per-entry `Size`, exactly as `WebVella.Erp.Web/Services/LoginThrottleService.cs` now does, so eviction is automatic and the cardinality bound is explicit. |

#### M-09 — Anonymous access to a developer page

| Field | Value |
| --- | --- |
| **FINDING** | Anonymous access to a developer page |
| **SEVERITY** | Medium |
| **CWE** | CWE-306 |
| **LOCATION** | `WebVella.Erp.Site.Sdk/Startup.cs:L48` |
| **DESCRIPTION** | The SDK host's Razor Pages conventions exempt `/dev` from authorization alongside the legitimate `/login` exemption, so the developer page is reachable without credentials on that host. |
| **IMPACT** | An unauthenticated visitor reaches a developer-oriented page on the SDK host. The exposure is limited to that one host and to whatever that page renders, but it is an authentication bypass for the page in question and it widens the anonymous attack surface enumerated in this report. |
| **EVIDENCE** | `options.Conventions.AllowAnonymousToPage("/dev");` at `:L48`, immediately after the legitimate `AllowAnonymousToPage("/login")` at `:L47`. Measured at this commit — the exemption is still present. |
| **REMEDIATION** | Documented, deliberately not changed. It is a Medium that does not act as a compensating control for any confirmed Critical or High, so under the governing rule it is recorded rather than fixed. The recommended fix is a one-line deletion of the `/dev` exemption; if the page is needed for diagnostics, restrict it to the administrator role instead of exempting it. |

#### M-10 — Anonymous resource-read endpoint on the project plugin

| Field | Value |
| --- | --- |
| **FINDING** | Anonymous resource-read endpoint on the project plugin |
| **SEVERITY** | Medium |
| **CWE** | CWE-306, CWE-200 |
| **LOCATION** | `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs:L462` |
| **DESCRIPTION** | A single action carries `[AllowAnonymous]`, overriding the class-level authorization that otherwise protects the API surface, and serves a project resource read without authentication. |
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
| **DESCRIPTION** | The platform middleware sets `AllowSynchronousIO = true` on the request's synchronous-IO feature for every request, re-enabling blocking reads and writes that the server disables by default. |
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

#### M-14 — No multi-factor authentication

| Field | Value |
| --- | --- |
| **FINDING** | No multi-factor authentication |
| **SEVERITY** | Medium |
| **CWE** | CWE-308 (OWASP A07:2021) |
| **LOCATION** | Architectural — no location; a repository-wide search for two-factor, MFA, TOTP or authenticator terms in `*.cs` returns nothing |
| **DESCRIPTION** | The platform authenticates with a single factor: an e-mail address and a password, plus an optional persistent cookie. There is no second-factor enrolment, challenge or recovery mechanism anywhere in the codebase, and no external identity provider is integrated. |
| **IMPACT** | A single leaked or guessed credential is sufficient for full account takeover, including for the administrator account. The remediation reduces the likelihood of guessing (work-factored hashing, a five-attempt lockout, rate limiting) but cannot compensate for a credential compromised elsewhere. |
| **EVIDENCE** | `grep -rniE 'two.?factor\|mfa\|totp\|authenticator' --include=*.cs .` returns no match at this commit. |
| **REMEDIATION** | Documented, deliberately not built. Adding a second factor is feature work with schema, enrolment, recovery and user-interface consequences, which the no-feature-additions boundary excludes. The recommended path is to adopt the framework's own two-factor primitives behind an opt-in policy for administrator accounts first, and it is carried as a standing recommendation in the risk register rather than as remediation. |

#### M-16 — Legacy timestamp behaviour enabled on every host

| Field | Value |
| --- | --- |
| **FINDING** | Legacy timestamp behaviour enabled on every host |
| **SEVERITY** | Medium |
| **CWE** | CWE-1254-adjacent (correctness of a security-relevant value) |
| **LOCATION** | All seven hosts: `WebVella.Erp.Site/Startup.cs:L40`, `WebVella.Erp.Site.Crm/Startup.cs:L27`, `WebVella.Erp.Site.Mail/Startup.cs:L27`, `WebVella.Erp.Site.MicrosoftCDM/Startup.cs:L29`, `WebVella.Erp.Site.Next/Startup.cs:L30`, `WebVella.Erp.Site.Project/Startup.cs:L34`, `WebVella.Erp.Site.Sdk/Startup.cs:L27` |
| **DESCRIPTION** | Each host sets the data provider's legacy timestamp switch, which changes how timestamp values are mapped between the database and the application — in particular how offsets and kinds are interpreted. |
| **IMPACT** | Security-relevant timestamps such as token issue and expiry, lockout windows and audit times are only as trustworthy as their time-zone handling. Inconsistent interpretation can shift a comparison across a boundary, which is why the remediation moved token timestamps to UTC explicitly rather than relying on this switch. |
| **EVIDENCE** | `AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);` measured at all seven locations listed above. |
| **REMEDIATION** | Documented, deliberately not changed. Turning the switch off changes how *already stored* timestamps are read and risks data corruption across every existing deployment, which the preservation requirement forbids. The remediation instead removed the dependence on it where it mattered, by making token timestamps explicitly UTC in `WebVella.Erp.Web/Services/AuthService.cs`. The recommended fix is a migration that normalises stored values, after which the switch can be removed host by host. |

#### L-03 — Packaging script references manifests that do not exist

| Field | Value |
| --- | --- |
| **FINDING** | Packaging script references manifests that do not exist |
| **SEVERITY** | Low |
| **CWE** | CWE-1104-adjacent (unmaintained build tooling) |
| **LOCATION** | `create-nuget-pkgs.bat:L2-L5` |
| **DESCRIPTION** | The packaging script invokes `nuget pack` against four `.nuspec` manifests. No `.nuspec` file exists anywhere in the repository, so the script cannot succeed as written; it also spells one path `WebVella.Erp.Plugins.Sdk` where the folder on disk is `WebVella.Erp.Plugins.SDK`. |
| **IMPACT** | None directly — the script is already non-functional, so it cannot ship a mispackaged artifact. The concern is that a broken release path invites an ad-hoc manual one, which is how unreviewed content reaches a published package. |
| **EVIDENCE** | Four `nuspec` references at `:L2`, `:L3`, `:L4` and `:L5`; `find . -name '*.nuspec'` returns **0** files. |
| **REMEDIATION** | Documented, deliberately not changed. Repairing it is neither a security fix nor permitted under the minimal-change rule. The recommended fix is to delete the script and rely on `dotnet pack`, which the projects already support through their `PackageLicenseExpression` and related metadata. |

#### L-05 — No health endpoint and no rollback tooling

| Field | Value |
| --- | --- |
| **FINDING** | No health endpoint and no rollback tooling |
| **SEVERITY** | Low |
| **CWE** | CWE-1059-adjacent (operational observability) |
| **LOCATION** | Repository-wide — no `AddHealthChecks`, `MapHealthChecks` or health route exists in any of the 19 projects |
| **DESCRIPTION** | There is no liveness or readiness endpoint, no smoke-test script and no documented rollback procedure. Deployment verification therefore depends on a human loading a page. |
| **IMPACT** | A security change that fails closed — the deliberate fail-fast on a missing encryption key, for example — is indistinguishable from an unrelated outage without a health signal, which lengthens time to detect and time to roll back. |
| **EVIDENCE** | `grep -rn 'AddHealthChecks\|MapHealthChecks\|/health' --include=*.cs .` returns no match at this commit. |
| **REMEDIATION** | Documented, deliberately not built — it is feature work outside the remediation scope. The recommended fix is a single `AddHealthChecks()`/`MapHealthChecks("/health")` pair per host that reports database reachability and the presence of the required secrets, so that a fail-fast start is immediately distinguishable from a crash. The rollback procedure for the credential change specifically is documented in the credential migration guide. |

#### L-06 — Inert TypeScript build configuration in seven projects

| Field | Value |
| --- | --- |
| **FINDING** | Inert TypeScript build configuration in seven projects |
| **SEVERITY** | Low |
| **CWE** | CWE-1164 (irrelevant code) |
| **LOCATION** | `WebVella.Erp/WebVella.Erp.csproj`, `WebVella.Erp.Site/WebVella.Erp.Site.csproj`, `WebVella.Erp.Site.Crm/...csproj`, `WebVella.Erp.Site.Mail/...csproj`, `WebVella.Erp.Site.Next/...csproj`, `WebVella.Erp.Site.Project/...csproj`, `WebVella.Erp.Site.Sdk/...csproj` |
| **DESCRIPTION** | Seven manifests carry TypeScript build properties although the repository contains no TypeScript sources and no TypeScript compiler is invoked. The properties are evaluated and then have no effect. |
| **IMPACT** | None directly. Dead build configuration is a supply-chain hygiene concern: it misleads a reader about what the build does, and a future toolchain change could give an inert property a real effect nobody reviewed. |
| **EVIDENCE** | `grep -rln 'TypeScriptCompileBlocked\|TypeScriptToolsVersion' --include=*.csproj .` returns exactly the seven manifests listed above. |
| **REMEDIATION** | Documented, deliberately not changed, on the no-refactoring-beyond-security rule. The recommended fix is to delete the properties from all seven manifests in a single hygiene change, verifying afterwards that `dotnet build` output is byte-comparable. |

#### L-08 — Service-catalogue and documentation drift

| Field | Value |
| --- | --- |
| **FINDING** | Service-catalogue and documentation drift |
| **SEVERITY** | Low |
| **CWE** | CWE-1059-adjacent (documentation inconsistency) |
| **LOCATION** | `catalog-info.yaml` — the component description and the pull-request links |
| **DESCRIPTION** | The service catalogue descriptor advertises capabilities the repository does not contain: its description names cloud-native microservices and a serverless architecture alongside the security audit, and it links a pull request titled *Serverless Microservices Rewrite*. No container definition, orchestration manifest or serverless artifact exists anywhere in the tree. |
| **IMPACT** | Inaccurate catalogue metadata misdirects a reader about the platform's actual shape and attack surface, and an inventory that overstates what exists is a weak basis for risk decisions. |
| **EVIDENCE** | The `metadata.description` field and the `links` entries in `catalog-info.yaml`, read against a repository that contains no Dockerfile, no compose file and no infrastructure manifest. |
| **REMEDIATION** | Documented, deliberately not rewritten beyond what the audit required: the descriptor's security-audit claim is now true, because this report exists and is referenced from the documentation navigation. Correcting the microservices and serverless claims is the owner's editorial call on their own catalogue entry, not a security fix. |

#### L-09 — No server-side request forgery surface

| Field | Value |
| --- | --- |
| **FINDING** | No server-side request forgery surface |
| **SEVERITY** | Low (informational — investigated and found not applicable) |
| **CWE** | CWE-918 (OWASP A10:2021) — not present |
| **LOCATION** | Every `HttpClient` in the repository is under `WebVella.Erp.WebAssembly/Client/` |
| **DESCRIPTION** | A10:2021 was investigated deliberately rather than assumed absent. Every outbound HTTP client in the codebase is browser-side Blazor WebAssembly code, so its requests originate from the user's browser and not from the server. No server-side code constructs an outbound request from user-controlled input. |
| **IMPACT** | None. This record exists so that the absence is evidenced rather than silently omitted, and so a future change that introduces a server-side outbound call is recognised as entering new territory. |
| **EVIDENCE** | `grep -rln 'new HttpClient(' --include=*.cs .` returns nothing; every `HttpClient` reference resolves to `WebVella.Erp.WebAssembly/Client/ApiService/*` or `WebVella.Erp.WebAssembly/Client/Utilities/HttpExt.cs`. |
| **REMEDIATION** | No remediation required. If a server-side outbound call is ever introduced, it must validate the destination against an allow-list of hosts and schemes, refuse redirects to private address ranges, and be recorded as a new finding against this category. |

#### L-10 — No CI/CD pipeline existed

| Field | Value |
| --- | --- |
| **FINDING** | No CI/CD pipeline existed |
| **SEVERITY** | Low |
| **CWE** | CWE-1053-adjacent (missing build-time verification) |
| **LOCATION** | `.github/` contained only `FUNDING.yml`; there was no `.github/workflows` directory |
| **DESCRIPTION** | Before this change the repository had no continuous-integration pipeline of any kind, so nothing verified the build, the dependency audit or the analyzer set on a push. The validation objective had nowhere to live. |
| **IMPACT** | Without an automated gate, every security property asserted in this report would depend on a developer choosing to run the commands locally, and a regression — a reintroduced advisory or a reintroduced path-casing defect — could merge unnoticed. |
| **EVIDENCE** | The finding identifier is cited from `.github/workflows/security-scan.yml:L3`, the file created to close it. |
| **REMEDIATION** | **Closed, and since extended.** `.github/workflows/security-scan.yml` runs, in order: check out the repository; set up the pinned .NET SDK; assert the project graph is complete and correctly cased; assert every tracked project is a member of the solution; restore with dependency auditing; build with analyzers enabled and enforce the `.globalconfig` severities; list vulnerable packages including transitive dependencies; restore, build and list vulnerable packages for the two explicitly gated WebAssembly projects, whose build step also asserts each one's `TargetFramework` (finding H-18); Gate 1, failing on unreviewed security analyzer diagnostics; a positive control in which a deliberate security defect must be reported; the tracked-tree secret sweep with a repository-history audit; a Linux startup smoke test of the published artifacts; a negative control that must observe `error NU1903`; and the evidence publication. Counted from the parsed file, that is **16 named steps: 3 `uses:` actions, each pinned to a reviewed commit SHA, and 13 `run:` blocks.** Every `run:` block was extracted from the parsed YAML and `bash -n` checked, and each behaved as specified in both directions where a negative case exists. Three corrections to earlier revisions of this row, recorded rather than quietly overwritten because each was asserted as measured: it once claimed a *test-suite step*, which the workflow has never contained and could not usefully contain because no test project exists anywhere in the 19 projects (Gate 4 is vacuous, as recorded in the methodology section); it once reported "8 / 8" `run:` steps; and it then reported "10 steps — 7 `run:` and 3 `uses:`" and later "12 named steps … 9 `run:` blocks". Every one of those counts was stale by the time it was written; the current figures were re-counted from the parsed YAML at this commit. |


## Part 4 — Product vulnerabilities first discovered by reviewing the remediation

The findings in Parts 1 to 3 came from the audit of the product. The findings below came from a **code
review of the remediation itself**, and each one is a genuine product vulnerability that the original
audit had not reached. They are recorded in the same eight-field format and are **not** a separate class
of finding — a vulnerability found by reviewing a fix is still a vulnerability in the product.

They are presented separately for one reason only: so that a reader can see how much of the platform's
current protection exists because the audit's own output was independently reviewed rather than trusted.

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
| **REMEDIATION** | **Fixed** by replacing namespace reflection with an **exact enumerated** `Type` allow-list of the 33 persisted types actually required. `BindToName` output is byte-identical, so already-persisted payloads still round-trip; every wired site was re-verified against real persisted entity, relation and job payloads; and a gadget-shaped type outside the list is rejected, with a positive control proving the test can observe admission. Independently corroborated by the static-analysis gate: `CA2327` reports **zero** while `CA2326` reports twenty, which is machine-checked proof that a binder is attached at every polymorphic site. |

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
| **REMEDIATION** | **Fixed** with an explicit allow-list drawn from **this host's own** commented-out policy, which names four origins — it allows one more than the sibling host, so a copy of the sibling's list would have broken a working client. `AllowCredentials()` is deliberately not added, because the framework rejects it alongside any-origin and adding it now would widen behaviour rather than preserve it. Verified against a running host: all four listed origins are echoed back; four unlisted origins, including the literal `null` origin, receive no header at all; and the load-bearing ordering holds — a plaintext preflight is answered by CORS with `204` and no `Location`, while a non-preflight plaintext request to the same host still receives `307`. A repository-wide sweep confirms **zero** live any-origin registrations remain. |

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
