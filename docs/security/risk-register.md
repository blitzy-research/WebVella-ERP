# Risk Register

Accepted risks, open decisions and residual exposure arising from the security remediation.
Findings are described in the [security audit report](security-audit-report.md); the changes made
are recorded in the [remediation log](remediation-log.md).

Each entry states what the risk is, who owns the decision, and — where the risk is accepted — the
reasoning that justifies acceptance.

## Canonical risk index

This table is the register at a glance and is **authoritative for what each identifier means**. Where
an identifier carries more than one detailed entry below, those entries are complementary analyses of
the same risk written from different angles; the subject and status in this table govern.

| Ref | Subject | Status | Owner |
| --- | --- | --- | --- |
| `RISK-001` | `AutoMapper`: every version that patches `GHSA-rvv3-g6hj-g44x` is licensed under the Reciprocal Public License 1.5, which conflicts with the product's declared Apache-2.0 and its publication to nuget.org. The advisory is **closed** by pinning `[15.1.3]`; the licensing consequence is **not** resolved. | **Open** | Repository owner |
| `RISK-002` | Uncontrolled recursion in `AutoMapper` remains a weakness class that outlives any single version change; it is reachable only through a self-referential mapping the project's own developers would have to author. | Accepted | Platform team |
| `RISK-003` | Credential hashing uses PBKDF2-HMAC-SHA256 at 600,000 iterations rather than bcrypt, scrypt or Argon2, deviating from the literal wording of the mandated cryptographic standard while satisfying its intent and adding no dependency. | Accepted | Platform team |
| `RISK-004` | `CA5351` (broken cryptographic algorithm) is reported on the retained legacy MD5 verification path, which must stay until every stored credential has been upgraded on login. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-005` | The Content-Security-Policy report endpoint bounds *logging* rather than *acceptance*, so a flood of reports is capped in the log without corrupting the evidence. | Accepted | Platform team |
| `RISK-006` | Deterministic initialisation vector in the symmetric encryption helpers (finding `M-08`). Latent — no active caller — and changing it would make already-encrypted data undecryptable. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-007` | No token revocation list: sign-out does not invalidate an already-issued bearer token. Bounded by the 7-day absolute session horizon. | Accepted | Platform team |
| `RISK-008` | Login throttling is per-process, so its state neither spans instances nor survives a restart. | Accepted | Platform team |
| `RISK-009` | A throttle refusal and a credential rejection differ in response length, which is a weak oracle for whether an account is currently locked out. | Accepted | Platform team |
| `RISK-010` | Entity and relation names long enough to be truncated by PostgreSQL now **fail hard** rather than silently colliding on a truncated physical name. | Accepted | Platform team |
| `RISK-011` | A derived page model that re-declares `ReturnUrl` would bypass the sanitising setter on the base model. Guarded by convention and by comment, not by the compiler. | Accepted | Platform team |
| `RISK-012` | The generic record-update path can overwrite a password hash with a blank value; the user-facing save path is verified not to. | Named, not fixed | Platform team |
| `RISK-013` | Two hosts serve a permissive `Access-Control-Allow-Origin: *`. Outside this change's finding scope. | Named, not fixed | Platform team |
| `RISK-014` | Two bearer-token error paths return stack traces **unconditionally**, so setting `Production` does not suppress them (finding `H-13`). | Named, not fixed | Platform team |
| `RISK-015` | `/ckeditor/ImageFinder` returns HTTP 500; proven pre-existing by counterfactual. | Named, not fixed | Platform team |
| `RISK-016` | Three navigation anchors carry `href="javascript: void(0)"` — Bootstrap dropdown placeholders, **not** injection sinks. | Named, not a defect | Platform team |
| `RISK-017` | One host's `Startup.cs` lacks the UTF-8 byte-order mark the repository's own `.editorconfig` mandates. | Named, not fixed | Platform team |
| `RISK-018` – `RISK-020` | Further pre-existing issues named but deliberately not fixed; see the table under *risks arising from the integrated controls*. | Named, not fixed | Platform team |
| `RISK-021` | The shipped `Config.json` files contained a live connection string, encryption key, token signing key, storage connection string and mail password, with `DevelopmentMode: true`. **All eight files are now scrubbed**, `web.config` sets `Production`, and the seeded administrator credential is no longer a literal. | **Closed** for the tracked configuration files; see `RISK-026` for the residual | Platform team |
| `RISK-026` | One demo credential remains in the Blazor WebAssembly **client** page `Client/Pages/Index.razor.cs`, and every secret ever published in this repository's **history** stays public. | Named, not fixed — out of the authorised file set | Platform team |
| `RISK-027` | The generated initial administrator password has **no change-required-on-first-login marker**, because adding one requires a schema change the constraints forbid. | Accepted | Platform team |
| `RISK-028` | When the only configured package source is a **local folder mirror**, the dependency restore emits no `NU19xx` diagnostic at all, so promoting the audit codes to errors cannot close that fail-open path. It is closed instead by the workflow's advisory negative control. | Accepted — mitigated by a second, independent mechanism | Platform team |
| `RISK-029` | A `.csproj` that **assigns** rather than appends to `WarningsAsErrors` would silently discard the whole dependency gate for that project. No project does so today; the structural fix (a `Directory.Build.targets` re-appending the codes after every project body) is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-030` | A solution-level command reaches **17** of the repository's **19** projects; the two WebAssembly projects must be audited with explicit per-project commands. Solution membership was deliberately left unchanged, because altering it is not a security fix. | Accepted — disclosed in CI and in the guides | Platform team |
| `RISK-031` | Running an **unpublished** build directory under a non-Development environment leaves every `/_content/**` static asset unmapped, returning `405 Allow: DELETE` and an unstyled site. The obvious workaround — setting `ASPNETCORE_ENVIRONMENT=Development` — would undo the `H-12` and `H-15` remediations. Pre-existing; the host builder is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-022` | Content-Security-Policy ships in report-only mode, because four components emit inline script and enforcing it immediately would break them. | Accepted | Platform team |
| `RISK-023` | Four by-design raw-output channels are deliberately not encoded, because encoding them would disable the features they implement. | Accepted | Platform team |
| `RISK-024` | The static-analysis backlog is reported as warnings rather than enforced as errors, because promoting roughly 3,000 pre-existing diagnostics would force the mass refactor the constraints forbid. | Accepted | Platform team |
| `RISK-025` | Residual observations around the `H-10` deserialisation binder: the binder is measurably **inert at an `ExpandoObject` target**, the serialisation counterparts are deliberately unconstrained, and the `JobResultWrapper` fallback branch is effectively unreachable for well-formed payloads. **Cited from `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`.** | Accepted / named, not fixed | Platform team |

### Identifiers renumbered while consolidating this register

Several analyses were written independently and reused the same low identifiers for different
subjects. Where that happened the identifier cited from **source code** was treated as fixed and the
other subject was renumbered, so every citation in the codebase still resolves.

| Subject | Previously numbered | Now |
| --- | --- | --- |
| Static-analysis backlog kept as warnings | `RISK-003` | `RISK-024` |
| Content-Security-Policy ships report-only | `RISK-004` | `RISK-022` |
| Four by-design raw-output channels | `RISK-006` | `RISK-023` |
| Deterministic initialisation vector | `RISK-003` / `RISK-005` | `RISK-006` (cited from `CryptoUtility.cs`) |
| Credential hashing deviation | `RISK-005` | `RISK-003` |
| Login throttling is per-process | `RISK-006` | `RISK-008` |

## Open decisions


### RISK-001 — `AutoMapper` 15.1.3 licence conflicts with the declared project licence

| Field | Value |
| --- | --- |
| **Status** | **Open — repository-owner decision. Not resolved by the remediation.** |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021) |
| **Owner** | Repository owner / maintainers. This is a licensing and product-distribution decision, not an engineering one, so it is escalated rather than settled during remediation. |

**What the conflict is.** Closing H-01 requires moving `AutoMapper` off every version below
`15.1.1`, because that is where the advisory is first patched. Version `14.0.0` declares the MIT
licence (`automapper.nuspec`: `<license type="expression">MIT</license>`). From the patched line
onwards the package instead ships a licence file (`<license type="file">LICENSE.md</license>`) that
places the code under the **Reciprocal Public License 1.5**, with a separate commercial licence
agreement offered as the alternative. The core project declares
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, ships a matching licence file and
publishes packages for third-party consumption. A reciprocal licence's source-disclosure obligation
is not compatible with that distribution posture, and there is no patched permissive line to fall
back to — the fix begins at `15.1.1`, already under the new terms.

**Current state of the repository.** The pin has been raised to `[15.1.3]`, so the security
advisory is closed and the dependency gate is green. The declared licence expression was **not**
changed, no `PackageLicenseFile` was substituted for it, and the upgrade was **not** reverted. The
conflict is therefore visible and undecided rather than silently absorbed in either direction.

**Documented fallback, if the owner declines the upgrade.** Retain `14.0.0` behind a narrowly
scoped dependency-audit suppression carrying an inline justification, together with a formal
recorded risk acceptance. The acceptance rests on the following exploitability assessment: every
mapping is statically declared in source, and no user-controlled mapping configuration or type
graph reaches the configuration builder, so the recursion path is reachable only through a
self-referential mapping the developers themselves would have to author. Real-world exposure is
therefore low despite the High rating. The fallback keeps the build gate green without pretending
the advisory does not exist.

**Options, stated plainly.**

1. **Accept the upgrade** and reconcile the product's licensing position with the Reciprocal Public
   License 1.5 (or obtain the vendor's commercial licence).
2. **Decline the upgrade** and apply the documented fallback above — suppression plus formal,
   justified risk acceptance.
3. **Replace the dependency.** Not recommended on cost grounds: the platform declares hundreds of
   mappings across its profiles, so removing the library means hand-writing them, which is far
   beyond a security remediation.


### RISK-001, the two reversal analyses

Both analyses below argue the **alternative** disposition — retaining `[14.0.0]` behind a single,
negative-tested, per-advisory suppression. Neither is what shipped; the pin is `[15.1.3]` and no
suppression is declared. They are kept in full because they are the executable reversal path this
decision needs in order to remain reversible, and because their exploitability assessment and
negative-control evidence hold under either disposition.

### RISK-001, reversal path — accepting the advisory rather than the licence change

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* As argued below: **Option 2 applied: version held at `[14.0.0]`, advisory suppressed narrowly and explicitly, licensing posture unchanged. Reversible by the owner; steps below.** |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021) |
| **Decided by** | The remediation, on the conservative branch. The choice *between* the two options is a licensing and product-distribution decision reserved to the repository owner, and Option 2 is the branch that leaves that decision untaken: it preserves the declared `Apache-2.0` expression, the shipped `LICENSE.txt` and the published package terms exactly as the owner set them. Option 1 would have changed them, which an automated remediation must not do unilaterally. |
| **Owner action available** | Optional, not required. Adopting Option 1 is a positive decision to accept reciprocal licence terms (or to buy the vendor's commercial licence); until that decision is taken, Option 2 is the correct resting state. |

**What the conflict is.** Closing H-01 requires moving `AutoMapper` off every version below
`15.1.1`, because that is where the advisory is first patched. Version `14.0.0` declares the MIT
licence (`automapper.nuspec`: `<license type="expression">MIT</license>`). From the patched line
onwards the package instead ships a licence file (`<license type="file">LICENSE.md</license>`) that
places the code under the **Reciprocal Public License 1.5**, with a separate commercial licence
agreement offered as the alternative. The core project declares
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, ships a matching licence file and
publishes packages for third-party consumption. A reciprocal licence's source-disclosure obligation
is not compatible with that distribution posture, and there is no patched permissive line to fall
back to — the fix begins at `15.1.1`, already under the new terms.

**Current state of the repository.** The pin is held at `[14.0.0]`. The advisory is closed by an
explicit, narrowly scoped dependency-audit suppression naming exactly one advisory — declared once,
in `Directory.Build.props`, alongside an inline justification — paired with this formal acceptance.
No severity class is suppressed wholesale, nothing else in the repository is suppressed at all, the
declared licence expression is unchanged, and `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs`
is byte-identical to its pre-audit form. The dependency gate is therefore green **on the redefined
criterion that applies to this branch: no *unsuppressed* High or Critical advisory**, with the one
suppression accompanied by this record. The suppression is declared with the audit policy it
qualifies rather than in a project manifest, because `AutoMapper` reaches sixteen projects
transitively and the audit covers transitive packages; it therefore lands with the **Scan Gate
Enforcement** class in the [remediation log](remediation-log.md), which also carries the negative
control proving that removing this one suppression turns the advisory back into a build failure.

**Why the residual risk is acceptable.** Every mapping in this platform is declared statically in
source — 379 `CreateMap<...>` declarations across 32 `Profile` subclasses — and no user-controlled
mapping configuration or type graph ever reaches the configuration builder. The recursive path is
therefore reachable only through a self-referential mapping that the project's own developers would
have to author deliberately, in source, and then ship. It is not reachable by an external actor. The
impact class is availability (stack exhaustion terminating the host process), not disclosure and not
code execution. Real-world exposure is low despite the High rating.

**What this acceptance does not claim.** It does not claim the advisory is inapplicable, and it does
not claim the code is unaffected. The vulnerable version is present and the suppression is visible
in the build configuration precisely so that the acceptance cannot be mistaken for a clean scan.

**Options, stated plainly.**

1. **Accept the upgrade** and reconcile the product's licensing position with the Reciprocal Public
   License 1.5 (or obtain the vendor's commercial licence). Not taken — see *Decided by* above.
2. **Decline the upgrade** and apply the documented fallback — suppression plus formal, justified
   risk acceptance. ✅ **Taken.**
3. **Replace the dependency.** Not recommended on cost grounds: the platform declares hundreds of
   mappings across its profiles, so removing the library means hand-writing them, which is far
   beyond a security remediation.

**Reversal procedure, if the owner takes Option 1.** In order: (1) raise the pin in
`WebVella.Erp/WebVella.Erp.csproj` to `[15.1.3]` and replace the inline decision record with a note
that the reciprocal licence was accepted; (2) supply an `ILoggerFactory` to the
`MapperConfiguration` constructor at the repository's single construction site,
`WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs` — `NullLoggerFactory.Instance` from the
already-referenced ASP.NET Core shared framework is sufficient, because the platform performs no
mapping logging, and `Initialize`'s signature must stay unchanged so that both of its call sites
keep compiling; (3) remove the `AutoMapper` advisory suppression from `Directory.Build.props`,
leaving the repository with no suppression of any kind; (4) reconcile
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, the shipped `LICENSE.txt` and the
published package terms with the reciprocal obligation, and update this entry to record the
acceptance. Verify with `dotnet restore WebVella.ERP3.sln` followed by
`dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive`, both of which must then
report clean **with no suppression in place**.

**Review trigger.** Re-open this entry if any of the following becomes true: a patched AutoMapper
release appears under a permissive licence; user-controlled mapping configuration is introduced
anywhere in the platform, which would change the exploitability assessment above; or the project
stops publishing packages for third-party consumption, which would remove the licensing constraint
that drove this decision.

### RISK-001, reversal path — holding the pin at the permissively licensed version

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* As argued below: **decided, accepted, disclosed and gated** rather than open. |
| **Decision** | Hold the pin at `[14.0.0]` (MIT). Do **not** upgrade. Accept the advisory with a narrowly scoped audit suppression and this formal acceptance. |
| **Related finding** | H-01 / H-11 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, **High**, OWASP A06:2021) |
| **Owner** | Recorded by the remediation on the reasoning below. The *reversal* is a repository-owner and legal decision. |

**What the conflict is.** Closing this advisory requires moving `AutoMapper` off every version below
`15.1.1`. Version `14.0.0` declares the MIT licence
(`<license type="expression">MIT</license>`). From the patched line onwards the package ships a
licence file placing the code under the **Reciprocal Public License 1.5**, with a commercial licence
agreement offered as the alternative. The core project declares
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, ships a matching licence file and
publishes packages to nuget.org for third-party consumption. A reciprocal licence's
source-disclosure obligation is not compatible with that distribution posture.

**There is no patched permissive line to fall back to.** This was verified against the package
registry rather than assumed. AutoMapper has 235 published versions; the `.nuspec` of **every**
patched version was read, and `15.1.1`, `15.1.2`, `15.1.3`, `16.1.1` and `16.2.0` are **all** under
the Reciprocal Public License 1.5. Only `14.0.0` and earlier are MIT. The choice was therefore never
"patched versus unpatched at equal licensing cost" — it was "unpatched under MIT, or patched under a
reciprocal licence".

**Why the decision went this way.** An automated remediation must not change the effective licence of
someone else's published product in order to close an advisory. Upgrading would have traded a
low-exploitability denial-of-service advisory for a substantive, irreversible change to the product's
licensing posture affecting every downstream consumer of its published packages. Leaving the question
open was also untenable: the dependency gate promotes advisory diagnostics to build errors, so an
undecided licensing question means an indefinitely red build — and a red build is where genuinely new
advisories go unnoticed.

**Exploitability assessment supporting acceptance.** The High rating is not disputed; what is assessed
is reachability in *this* codebase:

* All 379 `CreateMap<...>` declarations across 32 `Profile` subclasses are **statically declared in
  source** and compiled into the assembly. None is built from configuration, user input, or reflection
  over an untrusted type graph.
* There is exactly **one** `new MapperConfiguration(...)` site in the repository, invoked from two
  fixed start-up call sites. No request path, stored record or plugin hook contributes to it.
* The recursion path therefore requires a **self-referential mapping that this project's own
  developers would have to author, compile and ship.** An external attacker has no mechanism to
  introduce one.
* If ever triggered, the consequence is a denial of service **at start-up** — not data disclosure,
  privilege escalation or code execution — and it would fail loudly on first initialisation, in
  development.

**Secondary benefit of holding the pin.** `14.0.0` declares **one** dependency; `15.1.3` declares
**five**, including a four-package `Microsoft.IdentityModel.*` chain at **8.14.0** — a version
*behind* the `8.15.0` this solution already references directly for its own token validation. An
object-mapping library pulling a JSON Web Token stack downward was an unwanted side effect. Reverting
removed all four packages, so the decision reduced the graph's attack surface rather than merely
preserving it.

**How it is gated, and why that is not concealment.**

* A single `NuGetAuditSuppress` entry in `Directory.Build.props` names
  `https://github.com/advisories/GHSA-rvv3-g6hj-g44x` **and nothing else**, with its justification
  recorded in place.
* Repository-wide placement is a **necessity, not a widening**: NuGet audit is evaluated per project,
  and AutoMapper reaches 16 project graphs through the core library. A project-scoped entry left the
  solution restore failing with exactly 15 `NU1903` errors.
* **Negative-tested.** Injecting an unrelated vulnerable package (`Newtonsoft.Json 9.0.1`) made the
  build fail with `NU1903` reporting a *different* advisory (`GHSA-5crp-9r3c-p9vr`). The suppression
  cannot mask a new advisory.
* `dotnet list package --vulnerable --include-transitive` **still reports the advisory in all 16
  affected projects**, because it does not honour audit suppressions. Anyone auditing this repository
  sees it. The asymmetry is intentional: the gate stays usable while the risk stays visible.

**Reversal, if the owner accepts RPL 1.5 or obtains the commercial licence.** Raise the pin; delete
the suppression from `Directory.Build.props`; restore the `ILoggerFactory` argument at the single
`new MapperConfiguration(...)` site, which 15.x requires. Then reconcile the Apache-2.0 expression in
all four packable manifests, `LICENSE.txt` and the published package metadata with the reciprocal
obligation — **that reconciliation is the part an automated agent must not perform unilaterally.**

**What would change this decision without owner involvement:** AutoMapper publishing a patched
release under a permissive licence, or the advisory being withdrawn or downgraded. Worth re-checking
at every dependency review.


## Accepted risks

### RISK-002 — Uncontrolled recursion in `AutoMapper` remains theoretically reachable by a developer

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual, informational. |
| **Related finding** | H-01 |

The advisory is closed by the upgrade, so this entry records only the residual shape of the
weakness class for future reference: a self-referential mapping authored in source could still
produce deep recursion. It is not reachable by an external actor, because mapping configuration is
statically declared and no user-controlled configuration or type graph reaches the configuration
builder. No control is added for it, consistent with fixing only what is confirmed and with the
prohibition on enhancement beyond remediation.


## Detailed entries — cryptographic standards, the legacy hashing path and the encryption helper

#### RISK-003 — Credential hashing deviates from the letter of the mandated cryptographic standard

| Field | Value |
| --- | --- |
| **Status** | Accepted — deviation disclosed, with an owner option to close it literally. |
| **Related finding** | C-03 (CWE-916 password hash with insufficient computational effort, CWE-759 one-way hash without a salt, OWASP A02:2021) |
| **Owner** | Repository owner, if literal compliance with the named algorithm families is required. Otherwise no action. |

The engagement's Cryptographic Standards block names **bcrypt, scrypt or Argon2 with a cost factor of
12 or above**. The primitive adopted in `WebVella.Erp/Utilities/PasswordUtil.cs` is none of those
three. **Two deviations exist, and both are recorded here rather than absorbed silently.**

**Deviation 1 — the algorithm family.** The implementation uses PBKDF2 through the ASP.NET Core
password hasher instead of bcrypt, scrypt or Argon2. Three reasons drive that choice, in order of
weight:

- The authoritative **OWASP Password Storage guidance sanctions PBKDF2 explicitly** at a high
  iteration count, so this is a sanctioned option rather than a downgrade improvised for convenience.
- It requires **no new package dependency.** The hasher ships inside the `Microsoft.AspNetCore.App`
  framework reference the core project already declares, and the minimal-change constraint in force
  for this remediation prefers the least invasive control that closes the finding.
- It supplies, in the same component, the two things the migration depends on: a **fixed-time
  verification** (which closes M-05, CWE-208, for free) and an explicit **rehash-needed signal** that
  makes the upgrade-on-next-authentication pattern implementable without guesswork.

The deviation satisfies the standard's unambiguous intent — slow, salted, work-factored, fixed-time
verification — while departing from its literal wording. **Owner option:** adding a dedicated bcrypt or
Argon2 package would achieve literal compliance, at the cost of a new dependency. That trade is a
repository-owner call and is not taken by the remediation.

**Deviation 2 — the pseudo-random function.** The mandated parameters name **HMAC-SHA-256** *and* the
versioned (V3) hasher format. In ASP.NET Core those two are mutually exclusive: the V3 format **is**
PBKDF2-HMAC-SHA512, and the hasher's options expose no pseudo-random-function selector — only a
compatibility mode and an iteration count. V3 is kept, because it is also the only route that supplies
the fixed-time verification and the rehash signal described above.

The outcome **exceeds** the named requirement rather than falling short of it: the OWASP iteration
floor for PBKDF2-HMAC-SHA512 is 210,000, and this implementation uses **600,000**. The measured cost
of that setting, and its acceptance against the engagement's performance boundary, are recorded in the
[remediation log](remediation-log.md).

#### RISK-004 — Broken-hash analyzer warnings are accepted on the retained legacy path

| Field | Value |
| --- | --- |
| **Status** | Accepted — expected diagnostics, deliberately left as warnings and deliberately not suppressed. |
| **Related finding** | C-03 (CWE-916, CWE-759, OWASP A02:2021); analyzer rule CA5351, "do not use broken cryptographic algorithms" |
| **Owner** | No action required. Revisit only when the legacy verification path can be deleted. |

The build gate introduced by `Directory.Build.props` enables the .NET analyzers repository-wide, which
means the broken-cryptographic-algorithm rule now reports on every remaining MD5 use. **Those
diagnostics are expected, and none of them is suppressed.** Suppression would hide the very signal the
gate exists to produce; recording the acceptance here keeps the signal visible and auditable instead.

Observed diagnostics, verified from a full solution build:

| Location | Why the MD5 use remains |
| --- | --- |
| `WebVella.Erp/Utilities/PasswordUtil.cs` — the legacy digest helper | **Retained deliberately** so that credentials written by earlier releases can still be verified and then upgraded. Deleting it would lock every existing user out, which the preservation requirement forbids. It can never produce a newly persisted value: new credentials go through the modern primitive. See the [credential migration guide](credential-migration.md) |
| `WebVella.Erp/Utilities/CryptoUtility.cs` — four **public** MD5 helper methods (`ComputeMD5Hash`, `ComputeMD5HashBytes`, `ComputeOddMD5Hash`, `ComputePhpLikeMD5Hash`) | General-purpose digest utilities on the published API surface of this library. They are **not** credential storage. Removing or changing them would be a breaking API change to a package published for third-party consumption, which is outside a security remediation whose scope excludes API contract changes |

**The correct reading of these warnings** is that the platform still contains MD5, which is true, and
that each remaining use has a recorded reason. The credential-storage use — the one that made C-03 a
Critical finding — is closed: MD5 no longer produces any newly stored password. The residual uses are
either a time-limited compatibility path or a public utility API.

**Exit criterion for this risk.** The `PasswordUtil` diagnostic disappears once every account has
authenticated at least once after the upgrade and the legacy verification path can be deleted. The
`CryptoUtility` diagnostics require a deliberate API-breaking decision and are therefore not tied to
this remediation at all.

#### RISK-006 — M-08: deterministic initialisation vector in the symmetric encryption helpers

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented only, deliberately not changed. |
| **Related finding** | M-08 (CWE-329, generation of predictable initialisation vector, OWASP A02:2021) |
| **Owner** | Repository owner, if the symmetric encryption API is ever put back into use. |

The key and initialisation-vector derivation helpers in `WebVella.Erp/Utilities/CryptoUtility.cs` are
**deterministic**: the vector is derived from the key itself, so the same plaintext always produces the
same ciphertext under the same key. That leaks equality — an observer can tell that two ciphertexts
encrypt the same value — and it rules out the semantic security an unpredictable per-message vector
provides.

**Three reasons this is accepted rather than fixed.**

1. **It is Medium severity under the engagement's own matrix** (weak cryptography), and the remediation
   scope fixes Critical and High findings and documents Medium and Low ones. It does not qualify for
   the compensating-control exception that brings some Medium findings into remediation scope, because
   no confirmed Critical or High depends on it.
2. **It is latent.** The symmetric encrypt and decrypt API in this class has **no in-repository
   callers**, so there is no data path on which the weakness is currently exercised.
3. **Changing it would destroy data.** Altering the derivation, or moving to an authenticated cipher
   mode, would make every already-persisted ciphertext undecryptable. The preservation requirement
   "all existing functionality remains operational" forbids that outright, and a fix that silently
   renders stored data unreadable would be worse than the weakness it removes.

**Recommended fix, for whenever this API is put back into use.** Generate a fresh initialisation
vector per message from a cryptographically secure random generator, store or prepend it alongside the
ciphertext, and move to an authenticated encryption mode — AES-256-GCM, as the engagement's
cryptographic standard names — so that tampering is detected rather than merely undetected. Because
that changes the ciphertext format, it needs a versioned envelope and a read path that still accepts
the old format, exactly as the credential migration does for password hashes.

**Analyzer diagnostics — the observed position, and why it is not reassuring.** The source comment on
this region names `CA5389`, `CA5390` and `CA5401` as diagnostics to expect. Measured against the
analyzer gate that `Directory.Build.props` enables, **none of those three is reported anywhere in the
repository** — but that is *not* because the code is clean. Those are dataflow/taint rules and they
are **not enabled** at the `latest-recommended` analysis level in use. This was confirmed directly: a
probe compiled against the same properties, deliberately hard-coding an AES key and passing a
caller-supplied initialisation vector, produced no `CA5390` and no `CA5401`, while `CA5350` and
`CA5351` fired on weak-hash calls in the same file.

**So the deterministic initialisation vector described above is a finding that this gate would not
catch.** It was identified by manual review, and it is recorded here precisely because no automated
check in the build will re-raise it. Anyone who later reactivates the symmetric encryption API should
not treat a clean build as clearance.

What the build does report in this file is `CA5351` at four sites — the four public MD5 helpers — and
that is RISK-004's subject, not this one. Should the dataflow rules later be enabled, or should a
future change surface a predictable-initialisation-vector diagnostic, it is **expected and to be left
as a warning** on the same reasoning as RISK-004. Nothing here is suppressed. The residual
static-analysis coverage gap is described in the
[secure configuration guide](secure-configuration.md).


## Detailed entries — dependency disposition, the analyzer backlog and the encryption helper

#### RISK-002 — Uncontrolled recursion in `AutoMapper` remains reachable only by a developer

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual. Subsumed by RISK-001, recorded separately because the weakness class outlives the version decision. |
| **Related finding** | H-01 |

Under RISK-001 the vulnerable version is retained, so the weakness itself is present rather than
removed: a self-referential mapping authored in source could produce unbounded recursion and exhaust
the stack. It is **not reachable by an external actor**, because mapping configuration is statically
declared and no user-controlled configuration or type graph reaches the configuration builder — the
same assessment that justifies RISK-001. No control is added for it, consistent with fixing only
what is confirmed and with the prohibition on enhancement beyond remediation. Note that this entry
would remain even under Option 1 of RISK-001, because a self-referential mapping is a developer
error rather than a library defect; the upgrade bounds the recursion, it does not make the mapping
correct.

#### RISK-024 — Static-analysis backlog reported as warnings rather than enforced as errors

| Field | Value |
| --- | --- |
| **Status** | Accepted — reported, measured and left visible. Not suppressed. |
| **Related control** | Gate 1, static analysis (`EnableNETAnalyzers`, `AnalysisLevel=latest-recommended` in `Directory.Build.props`) |
| **Scope** | Repository-wide, all 19 projects — `Directory.Build.props` is directory-scoped, so the analyzer gate reaches both non-solution-member projects too (see `RISK-030` for the separate question of which projects a *solution-level command* reaches) |

Enabling the .NET analyzer set across the platform surfaces **3,072 warnings** on a full rebuild.
None is newly introduced: no source file was modified by the class that enabled the gate, so every
one of them is pre-existing code that was previously simply never inspected. The largest groups are
`CA2201` (2,168), `CA1305` (682), `CA1310` (612) and `CA1862` (494) — culture-sensitivity, exception
typing and comparison-style rules, none of which is a security rule.

**Why they are not promoted to errors.** Promoting 3,072 diagnostics would require editing a large
proportion of roughly seven hundred source files, in a codebase with **no test suite of any kind** to
catch a mistake. That is both the repository-wide refactor this engagement's minimal-change
constraint forbids, and a materially riskier act than leaving the warnings reported. The gate's
security value is unaffected: the security rule families are running, and they report on every build.

**Why they are not suppressed either.** No rule is disabled and no baseline file is used, so the
count is honest and a regression is detectable. The non-analyzer diagnostic counts are recorded in
the [remediation log](remediation-log.md) as a comparison baseline (`CA2200`×52, `ASPDEPR008`×42,
`CS0618`×6, `CS0168`×4, `ASP0019`×2), which is what makes "no new diagnostic was introduced" a
measurement rather than a claim.

**Recommendation for a future sprint.** Reduce the backlog rule family by rule family, promoting
each family to an error only once it reaches zero, so the gate ratchets forward without a single
large change. Introducing a test suite first would make that materially safer.

#### RISK-004 — Legacy MD5 remains present and is reported by the analyzer gate

| Field | Value |
| --- | --- |
| **Status** | Accepted — required for one case, non-security use in the other. Reported on every build, not suppressed. |
| **Related findings** | C-03 (credential hashing), and the platform's content-hashing utilities |
| **Diagnostic** | `CA5351` — *Do not use broken cryptographic algorithms* — 10 reports across 2 files |

The analyzer gate reports MD5 use at five distinct call sites. Both groups are deliberate and neither
is a credential-verification weakness, but they are reported rather than silenced so that the
platform's remaining MD5 surface stays visible to every future reader.

**Group 1 — `WebVella.Erp/Utilities/PasswordUtil.cs` (`GetMd5Hash`, reported at line 261).** This is
the *legacy verification* path, and it is the mechanism that makes credential migration possible at
all. Stored MD5 digests cannot be reversed, so the only alternatives to retaining a
verify-legacy-then-rehash path are to force a password reset on every existing user or to lock them
all out — both of which would breach the requirement that existing functionality be preserved. The
path is verification-only: it is never used to *create* a stored credential, and it is guarded by a
fixed-time comparison so it leaks no timing signal.

**Stated precisely, because the difference matters:** `VerifyPassword` already *signals* that a
legacy value needs upgrading, through its `needsRehash` output. The credential-resolution path that
*acts* on that signal — verifying in application code and then persisting the modern hash — belongs
to a later vulnerability class and **is not yet wired**, so at the time of writing a legacy stored
value is still verified as legacy and is not yet upgraded on login. Confirmed by observation rather
than assumed: an interactive login against a provisioned database succeeded and left the stored value
at its original 32-character legacy length. Once that class lands, the exposure shrinks with every
login and becomes self-terminating; until then this entry covers the legacy shape as genuinely
present rather than as already retiring.
*Retirement condition:* once the credential-resolution path is switched over **and** operational
evidence shows no stored credential is still in the legacy shape, delete `GetMd5Hash` and
`VerifyMd5Hash`, at which point this group of reports disappears.

**Group 2 — `WebVella.Erp/Utilities/CryptoUtility.cs` (`ComputeMD5Hash`, `ComputeMD5HashBytes`,
`ComputeOddMD5Hash`, `ComputePhpLikeMD5Hash`, reported at lines 188, 200, 210 and 227).** These are
content-hashing helpers, not security primitives. Their live callers are
`WebVella.Erp/Api/Cache.cs` (entity and relation cache invalidation),
`WebVella.Erp/Api/EntityManager.cs` (entity change detection) and
`WebVella.Erp/Utilities/DatasetExtensions.cs` (dataset fingerprinting) — every one a
same-or-different comparison over server-generated data, with no authentication, authorisation,
integrity or signature decision resting on the result. MD5 collision resistance is irrelevant to a
cache key, and the values are never attacker-supplied. Changing them would alter stored hash values
and force cache and change-detection invalidation across existing installations, which is a
functional risk taken for no security gain — so under *fix only what is confirmed* they are left
alone.
*Recommendation for a future sprint:* if the reports are unwanted, replace the algorithm inside these
helpers with a non-cryptographic content hash and plan the resulting one-time invalidation. That is a
maintainability change, not a security fix.

#### RISK-003 — Credential hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2

| Field | Value |
| --- | --- |
| **Status** | Accepted — deviation from the letter of the mandated cryptographic standard, satisfying its intent. An owner option for literal compliance is stated below. |
| **Related findings** | `C-03` (unsalted MD5 password hashing) |
| **Owner of the decision** | The remediation scope's own escalation rules, which pre-authorise this deviation and require it to be recorded rather than absorbed. Reversible by the repository owner. |
| **Location** | `WebVella.Erp/Utilities/PasswordUtil.cs` — the `PasswordHasher<object>` configuration |

There are **two** deviations, and they are separate. Both are surfaced here because the code comments
that describe them promise a record in this register.

**Deviation 1 — the algorithm family.** The mandated Cryptographic Standards name bcrypt, scrypt or
Argon2 at a cost factor of 12 or above. The implementation uses PBKDF2. Three reasons, in the order
they carried weight:

- The authoritative OWASP Password Storage guidance sanctions PBKDF2 explicitly, provided the
  iteration count is high enough. This is not a downgrade to something the standards body rejects; it
  is one of the options that body lists.
- It requires **no new package**. The remediation scope forbids adding a dependency, and the
  framework the core library already references supplies this primitive. bcrypt and Argon2 would each
  require a new third-party package, which is the one thing the constraint rules out.
- The minimal-change constraint prefers the least invasive control that closes the finding, and the
  finding is *unsalted, unstretched, deterministic hashing*. PBKDF2 at 600,000 iterations with a
  128-bit random salt closes exactly that.

**Deviation 2 — the pseudo-random function, and why it is not a choice at all.** The mandated
parameters name HMAC-SHA-256 *and* the framework hasher's versioned (V3) format. In ASP.NET Core those
two are mutually exclusive: the V3 format **is** PBKDF2-HMAC-SHA512, and `PasswordHasherOptions`
exposes no pseudo-random-function selector — only `CompatibilityMode` and `IterationCount`. This was
verified empirically rather than inferred: a V3 payload hand-built with the HMAC-SHA-256 function
identifier at 600,000 iterations verifies as `SuccessRehashNeeded` rather than `Success`, which means
every single login would rewrite the stored credential. Choosing HMAC-SHA-256 would therefore have
forfeited both of the properties the scope explicitly requires of this component — the framework's own
fixed-time verification, and its `SuccessRehashNeeded` signal, which is the entire mechanism by which
legacy credentials are upgraded without a forced reset.

**The outcome exceeds the named requirement**, and the numbers are measured rather than asserted —
medians over 20 runs, single-threaded, .NET 10.0.10, on the audit host:

| Configuration | Cost per hash | Cost per verification |
| --- | --- | --- |
| PBKDF2-HMAC-SHA512 @ 600,000 — **as shipped** | 367.0 ms | 364.1 ms |
| PBKDF2-HMAC-SHA512 @ 210,000 — the OWASP floor for this function | 127.5 ms | 128.0 ms |
| PBKDF2-HMAC-SHA512 @ 100,000 — the framework default | 62.5 ms | 62.7 ms |
| PBKDF2-HMAC-SHA256 @ 600,000 — the literally named function, raw key derivation | 122.1 ms | — |

So the shipped configuration is **2.9× the OWASP iteration floor** and, at equal iteration counts,
costs **exactly 3.00×** what the literally named function would — measured, not estimated. The
iteration count is set explicitly because the framework default of 100,000 is well below what this
remediation requires.

**The accepted cost.** Authentication becomes measurably slower, by design: roughly 0.37 s of CPU per
login attempt. That is the control working, not a regression, and it is confined to the authentication
path — no other request path performs a key derivation. It is pre-declared here rather than discovered
later, because the scope caps performance regression at 10 % and this deliberately exceeds that on one
path. Practical consequence to be aware of: at four logical CPUs, sustained concurrent login attempts
are throughput-limited by this cost, which is also precisely what makes credential stuffing expensive.

**What this acceptance does not claim.** It does not claim PBKDF2 is preferable to Argon2 in the
abstract — for a greenfield system with a free choice of dependencies, a memory-hard function is the
stronger option. It claims only that PBKDF2 at this work factor is a sanctioned choice that closes the
confirmed finding within the constraints imposed on this remediation.

*Owner option for literal compliance:* add a dedicated bcrypt or Argon2 package, replace the two calls
in `HashPassword` and `VerifyPassword`, and extend the stored-shape discriminator to recognise a third
format. The legacy-upgrade mechanism already in place carries the migration, so existing credentials
would be re-hashed on next authentication exactly as they are now. The cost is a new third-party
dependency in the core library, which is why it is not taken here.

*Review trigger:* revisit when the OWASP iteration guidance for PBKDF2-HMAC-SHA512 next rises, or if a
memory-hard function becomes available in the framework without a third-party package.

#### RISK-006 — Deterministic initialisation vector in the symmetric encryption helpers

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented only, deliberately not changed. Latent, with no callers. |
| **Related findings** | `M-08` (deterministic initialisation vector) |
| **Owner of the decision** | The remediation scope, which fixes Critical and High findings and documents Medium and Low ones. |
| **Location** | `WebVella.Erp/Utilities/CryptoUtility.cs` — the key and initialisation-vector derivation helpers |
| **CWE** | [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html) |

The initialisation vector is derived from the encryption key itself, so it is the same for every
operation and the same plaintext always produces the same ciphertext. That leaks equality between
encrypted values and removes the semantic security a per-operation random vector provides.

**Why it is documented rather than fixed**, with each reason load-bearing on its own:

- It is **latent**: the symmetric encrypt and decrypt members have no callers anywhere in the
  repository, so no data is being protected by this construction today.
- It is a **Medium** finding under the engagement severity matrix, which directs Medium findings to
  documentation with fix guidance. This entry is that guidance.
- Changing the derivation, or moving to an authenticated cipher mode, would make **every
  already-persisted ciphertext undecryptable**. The requirement that all existing functionality remain
  operational forbids that, so a fix would have to ship with a re-encryption migration — which is
  materially larger than the weakness it closes while the weakness has no callers.

Any `CA5389`, `CA5390` or `CA5401` analyzer diagnostic on that region is expected and is left as a
warning rather than suppressed, so the surface stays visible. This is consistent with `RISK-024`.

*Recommended fix, when a caller is introduced:* generate a fresh cryptographically random
initialisation vector per operation and store it alongside the ciphertext, and prefer an authenticated
mode — AES-256-GCM, which the mandated cryptographic standards name — over unauthenticated CBC. Doing
this at the moment the first caller appears costs nothing, because there is no persisted ciphertext to
migrate; doing it afterwards requires the migration described above. **The cheapest moment to fix this
is before it is ever used.**

*Review trigger:* the moment any code calls the symmetric encryption members. This entry should be
re-assessed as an active finding at that point, not left accepted.


## Detailed entries — encryption helper, throttle scope and comment accuracy

#### RISK-006 — Deterministic initialisation vector in `CryptoUtility`

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented only, deliberately not changed. |
| **Related finding** | M-08 (CWE-329, OWASP A02:2021) |
| **Location** | `WebVella.Erp/Utilities/CryptoUtility.cs`, private key and initialisation-vector derivation helpers |

**What the weakness is.** The derivation helpers are deterministic: the initialisation vector is
derived from the key itself, so the same plaintext under the same key always produces the same
ciphertext. An observer can therefore tell that two encrypted values are equal, and identical values
across rows are distinguishable.

**Why it is accepted.** Three reasons, and all three have to hold for acceptance to be legitimate:

1. It is a Medium finding under the audit's severity matrix, and the remediation scope fixes Critical
   and High findings only; Mediums are documented with fix guidance.
2. It is **latent**. The symmetric encrypt/decrypt API has no in-repository callers, so no stored data
   is presently produced by this path.
3. Changing the derivation, or moving to an authenticated cipher mode such as AES-256-GCM, would make
   every already-persisted ciphertext undecryptable. That breaches the "all existing functionality
   remains operational" preservation requirement, so the fix is strictly larger than the finding.

**Recommended fix, for a future change with a data-migration budget.** Generate a per-encryption
random initialisation vector from a cryptographically secure source and store it alongside the
ciphertext, and move to an authenticated mode so tampering is detectable. This requires a versioned
ciphertext envelope plus a re-encryption pass over existing values, which is why it is not a
comment-level or drop-in change.

**Analyzer consequence.** `CA5390` (do not hard-code encryption key) and `CA5401` (do not use
`CreateEncryptor` with a non-default initialisation vector) diagnostics on this region are expected
and are intentionally left as warnings. They are not suppressed, globally or locally, so the weakness
stays visible in build output for as long as it remains unfixed.

#### RISK-004 — `CA5351` on the retained legacy MD5 verification path

| Field | Value |
| --- | --- |
| **Status** | Accepted — the warning is expected, and is not a defect. |
| **Related finding** | C-03 (CWE-916 / CWE-759, OWASP A02:2021) |
| **Location** | `WebVella.Erp/Utilities/PasswordUtil.cs`, `GetMd5Hash` and `VerifyMd5Hash`; and four further sites in `WebVella.Erp/Utilities/CryptoUtility.cs` |

**What the warning is.** `CA5351` ("do not use broken or risky cryptographic algorithms") reports on
the MD5 use in those two members. The report is correct: MD5 *is* broken for this purpose, which is
precisely what made C-03 Critical.

**The full observed set.** With the analyzers enabled by `Directory.Build.props`, a Debug build of the
solution reports `CA5351` at five distinct sites — one in `PasswordUtil.cs` (`GetMd5Hash`) and four in
`CryptoUtility.cs` (at lines 188, 200, 210 and 227), where MD5 derives the symmetric key material for
the platform's legacy symmetric encryption. The `CryptoUtility.cs` occurrences are pre-existing code
that predates this audit and are not credential storage; they belong to the same legacy symmetric
envelope that RISK-006 covers, and they are retained for the identical reason — changing the key
derivation would make every value already encrypted by an earlier release undecryptable. They are
recorded here so that the diagnostic count is fully accounted for and no occurrence is mistaken for a
regression introduced by this remediation. Their exit condition is RISK-006's versioned envelope plus
a re-encryption pass, not the credential migration.

**Why the code stays.** The legacy path is retained solely so that credentials already stored by
earlier releases can still be verified and then upgraded in place. Deleting it would lock out every
user whose credential has not yet been rehashed, which the requirement that existing credentials keep
working forbids. The migration design is in the
[credential migration guide](credential-migration.md).

**Why it is not suppressed.** No global suppression and no `NoWarn` entry is added, because
suppressing `CA5351` repository-wide would also hide any *new* broken-algorithm use introduced
anywhere else in ~700 source files. The warning is therefore left in place as a standing, visible
reminder that a legacy population still exists.

**Exit condition.** When no account carries a legacy hash any longer, the two legacy members in
`PasswordUtil.cs` can be removed and the `CA5351` occurrence there disappears on its own. The four
`CryptoUtility.cs` occurrences are not cleared by that step and are tracked under RISK-006 instead.

#### RISK-003 — Password hashing deviates from the literal wording of the cryptographic standard

| Field | Value |
| --- | --- |
| **Status** | Accepted — two deviations, both surfaced rather than absorbed. Substituting a dedicated package remains an open repository-owner option. |
| **Related finding** | C-03 (CWE-916 / CWE-759, OWASP A02:2021) |
| **Location** | `WebVella.Erp/Utilities/PasswordUtil.cs` |

**Deviation 1 — algorithm family.** The mandated Cryptographic Standards name bcrypt, scrypt or
Argon2 at a cost factor of 12 or above. The implementation uses PBKDF2 instead. The reasoning:
the authoritative OWASP Password Storage guidance sanctions PBKDF2 explicitly at a high iteration
count; PBKDF2 ships in the framework already referenced by this project
(`FrameworkReference Microsoft.AspNetCore.App`), so it adds no package dependency, which the
minimal-change constraint prefers; and the platform vendor's own guidance steers applications that
store password hashes toward this component rather than raw key-derivation calls. The deviation
satisfies the standard's unambiguous intent — slow, salted, work-factored, fixed-time verification.

**Deviation 2 — pseudo-random function.** The mandated parameters name HMAC-SHA-256 *and* the
versioned (V3) format. In ASP.NET Core those two are mutually exclusive: the V3 format **is**
PBKDF2-HMAC-SHA512, and `PasswordHasherOptions` exposes no pseudo-random-function selector — only
`CompatibilityMode` and `IterationCount`. V3 is kept, because it is the only route that also supplies
the framework's fixed-time verification and its rehash-needed upgrade signal, both of which the
migration requires. The outcome exceeds the named requirement rather than falling short of it: the
OWASP iteration floor for PBKDF2-HMAC-SHA512 is 210,000 and the implementation uses 600,000.

**Owner option, if literal compliance is required.** Add a dedicated bcrypt or Argon2 package and
substitute it behind the same `HashPassword` / `VerifyPassword` members. The migration design is
unaffected: the format discriminator keys on the stored value's shape, so a third format can be
introduced by the same upgrade-on-next-authentication mechanism. The cost is one new dependency,
which is the reason it was not taken by default.

#### RISK-008 — Login throttling is per-process, and its state does not survive a restart

| Field | Value |
| --- | --- |
| **Status** | Accepted — scope limitation documented rather than hidden. A distributed backing store is a standing recommendation, deliberately not built. |
| **Related finding** | H-16 (CWE-307, OWASP A07:2021) |
| **Location** | `WebVella.Erp.Web/Services/LoginThrottleService.cs` |

**What the limitation is.** The failure counters are held in the platform's existing in-process cache.
Two consequences follow:

* **Multi-instance deployments are not protected.** Each process counts failures independently, so a
  load-balanced deployment of *n* instances tolerates roughly *n* times the configured threshold
  before any single instance locks an account out.
* **State does not survive a process restart or recycle.** The service pins its cache entries against
  memory-pressure eviction and sizes each entry's lifetime to at least the remaining lockout, so
  neither eviction nor early expiry can release a lockout. A restart, however, discards the cache
  entirely, and absent state necessarily reads as "no failures recorded". An in-force lockout is
  therefore released by a restart.

**Why absent state must read as "no failures".** The alternative — treating missing state as locked —
would lock out every user after any restart or deployment. That is an availability failure far worse
than the exposure it would close, and it breaches the "all existing functionality remains operational"
preservation requirement.

**Why the in-process cache was chosen anyway.** It is the least invasive control that closes H-16: it
avoids both a database schema change and a new package dependency, which the minimal-change
constraint requires. A lockout that holds for the lifetime of a process is a large improvement over
the unlimited attempts that existed before.

**Recommended fix.** Move the counters to a distributed backing store shared by every instance — a
cache or table reachable by all processes — keyed exactly as today, by username and address together.
That converts both limitations at once. It is deliberately not built here, because it introduces
either infrastructure or a schema change, and neither is within a security remediation's scope.

**Complementary control.** Transport-level rate limiting is a separate layer that belongs in each
host pipeline and is not provided by this service. Adding it is recorded in the
[secure configuration guide](secure-configuration.md) as host wiring; a per-address fixed-window
limiter bounds attempt *rate* even where the lockout's state has been lost.


## Detailed entries — risks arising from the integrated controls

#### RISK-002 — Uncontrolled recursion in `AutoMapper` remains present in the graph

| Field | Value |
| --- | --- |
| **Status** | Accepted — see RISK-001. |
| **Related finding** | H-01 / H-11 |

A previous revision of this entry stated that "the advisory is closed by the upgrade". **That is no
longer true and has been corrected.** The advisory is *not* closed: the vulnerable package remains in
the dependency graph by the decision recorded in RISK-001. The weakness is not reachable by an
external actor for the reasons set out there. No control is added, consistent with fixing only what
is confirmed and with the prohibition on enhancement beyond remediation.

#### RISK-003 — Password hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2

| Field | Value |
| --- | --- |
| **Status** | Accepted — sanctioned deviation from the literal wording of the cryptographic standard. |
| **Related finding** | C-03 / CR-1, M-3 (CWE-916, OWASP A02:2021) |

The standard names bcrypt, scrypt or Argon2 at cost factor 12+. The implementation is
**PBKDF2-HMAC-SHA256 at 600,000 iterations** with a 128-bit random salt and constant-time
verification. OWASP's Password Storage guidance **explicitly sanctions** PBKDF2-HMAC-SHA256 at
600,000 iterations or more, so this is an approved primitive rather than a compromise; it satisfies
the standard's unambiguous intent (slow, salted, work-factored, fixed-time), and it requires **no new
package dependency**, which the least-invasive-control constraint prefers. Adding a dedicated bcrypt
or Argon2 package remains available to the owner if literal compliance is required.

**A withdrawn justification.** An intermediate revision of the source claimed that HMAC-SHA-256 and
the versioned payload format were mutually exclusive in ASP.NET Core. **That claim is false and has
been withdrawn** — the two are compatible and the implementation uses both. This deviation is now the
only one remaining in this area. See [the credential migration guide](credential-migration.md).

#### RISK-022 — Content-Security-Policy ships in report-only mode

| Field | Value |
| --- | --- |
| **Status** | Accepted — staged rollout. The mandated policy *value* is emitted verbatim; only the delivery mode is staged. |
| **Related finding** | M-01, L-1 (OWASP A05:2021) |

Enforcing `script-src 'self'; style-src 'self'` immediately would break the interface, violating the
requirement that existing functionality be preserved. Report-only was chosen so violations are
measured rather than guessed, and it has produced a concrete blocker inventory — including **two
directives the mandated policy does not account for at all**: `img-src 'self' data:` (a framework 1×1
GIF spacer) and `worker-src blob:` (the Ace editor's syntax worker). Both fall through to
`default-src 'self'` and would break images and the code editor on day one.

The inline-emitting surface is also **wider than the four components originally identified**: real
reports additionally implicate CKEditor 5, the `wv-lazyload`/Stencil bundle (inline style *and*
`eval`), and the Ace editor. Enforcement is a project, not a flag. The route to enforcement is in
[the secure configuration guide](secure-configuration.md).

**Scale of the backlog, measured rather than estimated.** A single authenticated browsing session
produced **at least 379** report-only violations. One isolated page context alone accounted for
**137**, broken down as **132 inline-style, 3 inline-script and 2 `eval`**. The distribution is the
useful part: inline *style* dominates by an order of magnitude, so the practical sequence is to address
`style-src` first, then the far smaller `script-src` and `eval` sets — and to add the two missing
directives above, which are prerequisites regardless of progress on the inline work.

#### RISK-005 — The CSP report endpoint bounds logging, not acceptance

| Field | Value |
| --- | --- |
| **Status** | Accepted — deliberate design trade-off. |
| **Related finding** | L-1, and a self-identified CWE-779 log-flooding vector closed during remediation |

`/csp-violation-report` is anonymous by necessity — a violation report cannot carry a session. An
unbounded anonymous logging sink is a log-flooding vector, so logging is capped at **120 reports per
minute**, checked before the request body is read.

The bound is applied to **logging** rather than to **acceptance** on purpose: a browser whose report
is refused does not resend it, so refusing reports would silently corrupt the very evidence the
report-only stage exists to gather. Every report is still accepted; only the log is bounded.

#### RISK-023 — Four by-design raw-output channels are not encoded

| Field | Value |
| --- | --- |
| **Status** | Accepted — remediated by compensating control. |
| **Related finding** | H-06 (CWE-79, OWASP A03:2021) |

The HTML-block page component (design and display views) and two generated-inline-script emitters
exist *in order to* emit markup and script. Encoding them would disable the features outright,
breaching the functionality-preservation requirement. The compensating controls are restricting
markup and script authoring to privileged roles, plus the Content-Security-Policy once enforced.
These four channels are the concrete reason RISK-022 exists.

### Accepted risks — residual and bounded

#### RISK-007 — No token revocation list; sign-out does not invalidate a bearer token

| Field | Value |
| --- | --- |
| **Status** | Accepted — bounded residual. Recommended future work. |
| **Related finding** | H-02 / H-4 (CWE-613, OWASP A07:2021) |

The audit's remediation guidance preferred rotating, revocable refresh tokens. That is **not**
implemented, because rotation with revocation requires persisting issued and revoked token
identifiers — a **database schema change, which the remediation constraints forbid outright.**

Honest consequences:

* There is no revocation list.
* **Signing out clears the cookie; it does not invalidate an already-issued bearer token.**
* A stolen token remains usable until the earlier of its own expiry and the absolute session horizon.

What *was* achieved: a **7-day absolute session horizon**, stamped at issue and carried verbatim
across every refresh, with refresh past the horizon refused and refreshed expiry capped at it. This
reduces worst-case exposure from **unbounded to at most 7 days with no operator action**. Previously
an anonymous refresh endpoint would renew a stolen token indefinitely, so one theft was permanent.

Recommended future work: a revocable refresh-token table with rotation and reuse detection, plus a
`jti` denylist.

#### RISK-008 — Login throttling is per-process

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented limitation. Recommended future work. |
| **Related finding** | H-16 / H-6, H-7 (CWE-307, OWASP A07:2021) |

The throttle is backed by an in-process store, chosen so the control required **no schema change and
no new dependency**. In a multi-instance or load-balanced deployment each instance counts
independently, so effective thresholds multiply by the instance count. A distributed backing store is
recommended and deliberately not built. Operators running more than one instance should also enforce
throttling at the load balancer.

Two further bounded trade-offs:

* **Account lockout is a denial-of-service primitive.** It lapses automatically after 15 minutes
  rather than requiring administrator action, so an attacker can lock a known account for 15 minutes.
  That is a deliberate trade against making credential stuffing cheap.
* **The store is size-bounded** to cap memory growth against an attacker varying the username.
  Displacing a specific account's partial count requires cycling the entire store, which buys at most
  a few extra guesses.
* The per-address threshold is deliberately **five times** the per-account threshold, because NAT and
  shared corporate egress mean many legitimate users share one address.

#### RISK-009 — A throttle refusal and a credential rejection differ in response length

| Field | Value |
| --- | --- |
| **Status** | Accepted — resolves itself when H-13 is fixed. |
| **Related finding** | H-16, H-13 |

On the bearer-token route a genuine credential rejection returns a longer body than a throttle
refusal, because the rejection currently includes exception text (finding H-13). Measured: a
credential rejection returns **518 characters** while a throttle refusal returns **25**. The two
become indistinguishable once H-13 removes the stack trace — so fixing H-13 closes this entry as a
side effect rather than requiring separate work. The login page itself preserves a single generic
message and was verified to render **pixel-for-pixel identically** on the fifth and sixth attempts, so
it is not an enumeration oracle.

#### RISK-010 — Long entity and relation names now fail hard rather than silently truncating

| Field | Value |
| --- | --- |
| **Status** | Accepted — fail-closed is the correct behaviour. |
| **Related finding** | H-09 / H-2, M-4 (CWE-89, OWASP A03:2021) |

PostgreSQL identifiers are limited to **63 bytes**, and the platform prefixes entity and relation
names when composing physical names. The platform's own name validation still admits names long
enough that the prefixed physical name exceeds that limit. The identifier helper now **rejects** such
names explicitly instead of allowing a silently truncated or malformed identifier to reach the
database. Tightening the platform's own name validation is out of scope for a security remediation.

#### RISK-011 — Derived page models must never re-declare `ReturnUrl`

| Field | Value |
| --- | --- |
| **Status** | Standing warning — a defect of this exact shape was found and fixed during remediation. |
| **Related finding** | H-1 (CWE-601, CWE-79, OWASP A01/A03:2021) |

The open-redirect fix is a **sanitizing setter on the base page model**, so every page inherits it
from one chokepoint. A derived model that re-declares the property with `new` **silently defeats it**:
model binding targets the most-derived declaration, so the raw value bypasses the sanitizer entirely.

Exactly that existed on the login page and was removed. Its effect was worse than an open redirect —
the unsanitized value reached a local-redirect sink, which threw, returning **HTTP 500 with a full
stack trace to an anonymous, pre-authentication caller**.

**Generalizable lesson: a chokepoint fix in a base class is only as strong as the guarantee that no
subclass shadows it.** Any future page model that needs a different bind name must route through the
sanitizer rather than re-declaring the property. A second, independent bypass was also found and
fixed in a page-header component that read the raw query string directly — a chokepoint does not help
where code declines to use it.

### Pre-existing issues named but deliberately not fixed

Named so they are not mistaken for regressions introduced by this remediation, and so a future scan
result is not misread.

| Ref | Issue | Why not fixed |
| --- | --- | --- |
| RISK-012 | **The generic record-update path can wipe a password hash.** The user-facing save path correctly ignores a blank incoming password, verified by a real UI save leaving the hash byte-identical. The *generic* record-update path guards only against `null`, not an empty string, which would be converted to `NULL` downstream. | Pre-existing and unchanged by the credential work. Named in [the credential migration guide](credential-migration.md) so it is not attributed to the migration. |
| RISK-013 | Two hosts serve a permissive `Access-Control-Allow-Origin: *`. Confirmed live on the login response across three independent verification runs. | Outside the finding scope of this checkpoint; recorded in the audit report. Compensate at the reverse proxy. |
| RISK-014 | Two bearer-token error paths return stack traces **unconditionally**, so setting `Production` does not suppress them. Confirmed live against an anonymous caller. | Recorded as H-13. Requires a code change, not configuration. |
| RISK-015 | `/ckeditor/ImageFinder` returns HTTP 500 — its page model does not derive from the type its layout requires. **Proven pre-existing by counterfactual**: reverting the view to its original content reproduced the identical exception. | A reliability defect, not a security one. |
| RISK-016 | Three navigation anchors carry `href="javascript: void(0)"` — Bootstrap dropdown toggle placeholders, byte-identical on every page. **These are not injection sinks.** | Named specifically so a future "the HTML contains `javascript:`" scan hit is not misread as a leak. |
| RISK-017 | One host's `Startup.cs` lacks the UTF-8 byte-order mark that the repository's own `.editorconfig` mandates and every sibling file carries. | Cosmetic encoding inconsistency, pre-existing. Deliberately not "fixed", to avoid an unrelated whole-file diff. |
| RISK-018 | Four accessibility advisories (label/form-field association, missing autocomplete attributes). | Not security findings; documentation only. |
| RISK-019 | Two vendored source-map files return HTTP 405. Requested only by browser developer tools, never by any page. | Cosmetic. |
| RISK-020 | On one management page `document.title` disagrees with the visible heading. | Cosmetic. |
| RISK-025 | Three residual observations around the `H-10` binder, all measured rather than assumed — see the detailed entry below. | Two are by design and one is a pre-existing functional quirk with no security consequence. |

#### RISK-025 — Residual observations around the H-10 deserialisation binder

| Field | Value |
| --- | --- |
| **Status** | Accepted for the first two; named-not-fixed for the third. |
| **Related finding** | `H-10` — unsafe polymorphic deserialisation (CWE-502, OWASP A08:2021). |
| **Cited from** | `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs` |

**1. The binder is inert at an `ExpandoObject` target — accepted, by design.** Newtonsoft dispatches
an `ExpandoObject` target to its own `ExpandoObjectConverter`, which treats `$type` as an ordinary
member and never resolves it. Measured: an identical gadget payload yields the same
`ExpandoObject` with keys `[$type]` with the binder attached and with it absent. The consequence is
benign in both directions — **no type is instantiated from the payload at those sites either way**, so
they were never the CWE-502 exposure, and the attachment is defence in depth that becomes
load-bearing the moment a target type changes. It is recorded because a reader who assumes all four
attachment sites are equally load-bearing would over-state the control, and because a future change
of target type from `ExpandoObject` to `object` would silently move the site from inert to critical.
The exposure lived at the POCO-targeted statements and inside any `dynamic` or `object`-typed member
of one, which is where the confirmed-then-closed exploit is recorded in the
[remediation log](remediation-log.md).

**2. The serialisation counterparts are deliberately unconstrained — accepted, by design.**
`WebVella.Erp/Jobs/JobDataService.cs` configures `TypeNameHandling.All` at four sites and is the
*write* counterpart that produces the exact JSON `JobProfile.cs` reads;
`WebVella.Erp/Notifications/NotificationContext.cs` configures `TypeNameHandling.Auto` at two.
Serialisation is **not** the CWE-502 attack surface: constraining what the platform is willing to
*write* protects nothing, because the attacker's leverage is over what is *read*, and it would break
writing. `BindToName` is correspondingly left unoverridden on the binder itself. Both files
nonetheless attach the binder at their read-adjacent settings, which is harmless and consistent; no
further change is warranted and none should be made on the strength of a scanner hit against
`TypeNameHandling` alone.

**3. The `JobResultWrapper` fallback branch is effectively unreachable — named, not fixed.** The job
`result` read path attempts `ExpandoObject` first, for backward compatibility, and falls back to
`JobResultWrapper` in a `catch`. Because `ExpandoObject` deserialisation **succeeds** on
wrapper-shaped JSON — again, `ExpandoObjectConverter` treats `$type` as an ordinary member — the first
attempt wins and the fallback is not reached for a well-formed wrapper payload; the caller receives an
`ExpandoObject` carrying `$type` and `result` keys rather than the unwrapped value. Measured
identically with and without the binder, so this is **pre-existing behaviour and not a regression**.
It is a functional quirk with no security consequence, and correcting the ordering would change the
shape of a value returned to every consumer of `Job.Result` — precisely the behavioural change the
minimal-change constraint forbids. Named so that a future reader does not attribute it to the binder
work, and so that anyone who does intend to reorder the attempts knows what depends on it.

#### RISK-021 — The shipped configuration files contained development secrets (now closed)

| Field | Value |
| --- | --- |
| **Status** | **Closed for the tracked configuration files.** The enabling half had landed earlier; the scrub itself has now landed too. The residual is tracked separately as `RISK-026`. |
| **Related finding** | The secret-management class (hardcoded credentials, weak shipped signing key, development mode enabled). Adjacent to M-2, which delivered the validation and provider chain. |

**The state this entry originally described.** All eight `Config.json` files, and one host's
`web.config`, carried development values in the tracked tree: connection strings including passwords,
`"DevelopmentMode": "true"`, and a token signing key **published in this public repository** — which
`WebVella.Erp.Site/JWT_README.txt` additionally republished as documentation. The seeded administrator
password was the literal `"erp"`. A demo credential also appeared in a WebAssembly client page.

**What was closed.** Every secret value in all eight `Config.json` files is now blank, every file sets
`"DevelopmentMode": "false"`, `WebVella.Erp.Site/web.config` sets `Production`, `JWT_README.txt` no
longer republishes the key, and `WebVella.Erp/ERPService.cs` resolves the initial administrator
password from an operator-supplied setting or generates a 20-character CSPRNG password surfaced once at
provisioning. The files were **scrubbed and retained, never deleted** — the JSON configuration source
is not optional, so deleting them breaks start-up outright. Ordering was load-bearing and was already
satisfied: the provider chain had to land *before* any scrub, or every host would fail to start with no
channel to supply a replacement.

**Verified rather than asserted.** The secrets gate now passes on the tracked tree, sweeping 13
configuration files with 15 checks and 0 failures. A host started with a required secret absent aborts
with a message naming only the missing key **names**. A host started with both secrets supplied *only*
through environment variables boots and serves a successful login. The details are in the
[remediation log](remediation-log.md).

**What is still true, and why it still matters:**

* Known published key material is refused by digest comparison, not merely absent — so a value
  recovered from this repository's history cannot be used even deliberately.
* Environment variables supply the secrets, touching no tracked file. See
  [the secure configuration guide](secure-configuration.md) and
  [`README.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/README.md).
* Absent or insufficient-entropy secrets fail closed outside Development.

**Operator obligation.** Every value that ever appeared in this repository's history must still be
treated as public knowledge and never reused. The application will not start until the required
secrets are supplied; that is the intended behaviour, not a defect.

#### RISK-026 — Residual secret exposure outside the scrubbed file set

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — outside the authorised file set. |
| **Related finding** | Residual of `RISK-021`. |

Two residuals survive the scrub and are recorded rather than implied.

* **A demo credential in the Blazor WebAssembly client.**
  `WebVella.Erp.WebAssembly/Client/Pages/Index.razor.cs` authenticates with a literal e-mail and
  password. The Blazor WebAssembly client project is explicitly outside this remediation's authorised
  file set, so it was not modified. The exposure is bounded: the credential is only useful against a
  deployment that still has the corresponding seeded account, and the seeded account no longer has a
  known password on a freshly provisioned installation. **Recommended fix:** replace the literal with
  an empty form binding, or delete the auto-login call, in a change scoped to the client project.
* **Repository history.** Blanking a tracked file does not remove the value from earlier commits. The
  two published defaults are additionally rejected by digest comparison, which is the durable control;
  the connection-string password and mail password are not, and must be rotated. **Recommended fix:**
  rotate every credential that ever appeared in a tracked file, and treat history rewriting as a
  separate, owner-approved operation.

#### RISK-027 — The generated initial administrator password is not forced to be rotated

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | C-01 (hardcoded default administrator password). |

The seeded credential is now strong and unique per installation: 20 characters drawn from a
65-character ambiguity-free alphabet by `RandomNumberGenerator.GetItems<char>`, roughly 120 bits of
entropy, surfaced exactly once on stderr at provisioning. What it does **not** have is a
change-required-on-first-login marker, because there is no field to carry one and adding a column is a
schema change the constraints forbid.

The compensating controls are that the password is unique per installation, is printed once rather
than stored anywhere retrievable, and is printed together with an instruction to change it
immediately. **Recommended fix, for a change permitted to alter the schema:** add a
`must_change_password` boolean to the user entity and gate the post-login redirect on it.

#### RISK-028 — A local package mirror makes the dependency audit silently inert

| Field | Value |
| --- | --- |
| **Status** | Accepted — mitigated by a second, independent mechanism. |
| **Related finding** | The dependency gate's fail-open behaviour. |

Promoting `NU1900` and `NU1905` to errors closes the case where the advisory database is
**unreachable**: the restore then fails with `error NU1900` instead of passing with a warning. It
cannot close the case where the only configured package source is a **local folder mirror**, because
that configuration emits **no `NU19xx` diagnostic at all** — there is nothing to promote. Both
configurations were reproduced; they behave differently, and that difference is the whole point of
this entry.

The mitigation is a different mechanism rather than a stronger version of the same one: the CI
workflow restores a throwaway project pinned to a package with a known High-severity advisory and
**requires** that restore to fail with `NU1903`. Against a local-mirror configuration that step fails
the job and states that every clean result in the run is unverified. **Neither mechanism is redundant
with the other**, which is why both are kept. The residual is that a developer running a local restore
outside CI has only the promotion, not the control.

#### RISK-029 — A project assigning `WarningsAsErrors` would discard the dependency gate

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — documented control only. |
| **Related finding** | The dependency gate's inheritance model. |

MSBuild imports `Directory.Build.props` **before** the body of each project file, so a `.csproj`
containing a bare `<WarningsAsErrors>CS0168</WarningsAsErrors>` overwrites the gate's promotion rather
than adding to it — and the build then stays green with a known High-severity advisory in that
project's graph. Measured: a probe declaring exactly that resolves the property to
`CS0168;SYSLIB0011` and restores a vulnerable package at exit 0 with only `warning NU1903`.

**No project in this repository does this today**, verified rather than assumed: `Directory.Build.props`
is the only MSBuild customisation file in the tree, and none of the 19 `.csproj` files mentions
`WarningsAsErrors`, `TreatWarningsAsErrors` or `NoWarn`. The in-scope control is documentation — the
contributor warning in [the secure configuration guide](secure-configuration.md) and the design note in
[the remediation log](remediation-log.md). **Recommended structural fix:** add a
`Directory.Build.targets` that re-appends the six codes after all project bodies are evaluated, making
the mistake impossible rather than merely documented. Not done here because it adds a second
build-customisation file outside the authorised file set.

#### RISK-030 — A solution-level command covers 17 of 19 projects

| Field | Value |
| --- | --- |
| **Status** | Accepted — disclosed in CI and in the guides. |
| **Related finding** | H-19 (build-graph integrity) and H-18 (end-of-life framework). |

`WebVella.ERP3.sln` enumerates 17 of the repository's 19 `.csproj` files;
`WebVella.Erp.WebAssembly/Server` and `.../Shared` are not members. A solution-wide restore, build,
audit or analyzer run therefore does not see them, and they must be covered by explicit per-project
commands. Both are clean when so covered.

The two projects were briefly enrolled in the solution and that enrolment was **reverted**: changing
the solution's project membership is not a security fix, and the only authorised change to that file
is the project-reference path casing repair. Two consequences are easy to get backwards and are stated
explicitly: the `net10.0` **retarget survived** the revert, so H-18 stays closed; and the build gate
**survived** it too, because `Directory.Build.props` is directory-scoped rather than solution-scoped —
verified by evaluating all six gate properties on both non-member projects. The residual is purely one
of command coverage, and it is disclosed in the workflow's own coverage note so that no green
solution-level run is mistaken for repository-wide coverage. **Recommended fix, for a change permitted
to alter the solution:** enrol both projects, or add their explicit per-project audit to every
pipeline.

#### RISK-031 — Unpublished output under a non-Development environment serves no static assets, and the obvious workaround undoes two remediations

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — documented control only. |
| **Related finding** | `H-12` (development mode disabled) and `H-15` (HSTS and HTTPS redirection), both of which the tempting workaround would undo. |

Observed during this checkpoint's cross-cutting regression verification, not reported by any finding.
Running `WebVella.Erp.Site` from `bin/Debug/net10.0` with `ASPNETCORE_ENVIRONMENT=Production` made
**every** `/_content/**` request return `405` with `Allow: DELETE`, so the application rendered with
browser-default styling and the browser console filled with resource and MIME-refusal errors.

The cause is a launch configuration, not a defect in anything this remediation touched, and it was
root-caused rather than assumed. These hosts ship **no `wwwroot`** — none is present in the source
tree, none in the build output, and `git ls-files` shows none was ever tracked — so all static content
is served from Razor Class Libraries through the `_content/**` convention. That convention depends on
the static-web-assets manifest, which ASP.NET Core's loader reads **only when the environment is
Development**, unless the host builder opts in explicitly; `WebVella.Erp.Site/Program.cs` uses
`WebHost.CreateDefaultBuilder(args)` and does not call `UseStaticWebAssets()`. Under Production the
manifest is therefore never read, `_content/**` is unmapped, and the request falls through to a
`DELETE`-only catch-all route — which is exactly where the `405` and its `Allow: DELETE` originate.
Confirmed by the controlled experiment: the *same binary* serving the *same URLs* returns `405
text/html` under Production and `200` with correct content types under Development.

The security-relevant part is not the `405`. It is that the seven security headers **are** still
emitted on that `405`, so a header verification still passes while the site looks broken — and the
quickest way to make the styling return is to set `ASPNETCORE_ENVIRONMENT=Development`, which
**re-enables the developer exception page (`H-12`) and disables both `UseHsts()` and
`UseHttpsRedirection()` (`H-15`), because those are deliberately guarded to non-Development
environments.** A cosmetic annoyance thus creates direct pressure toward a real security regression,
which is why it is recorded here rather than left as a note.

Attribution is explicit: `WebVella.Erp.Site/Program.cs` and any `wwwroot` are untouched by this
remediation — `git diff` against the checkpoint base returns nothing for either path, and there are no
uncommitted changes to them. The condition predates this work and is unrelated to it.

**Recommended fix, for a change permitted to alter the host builders:** call `UseStaticWebAssets()`
explicitly on the host builder, or verify only `dotnet publish` output, where the assets are
materialised physically and the manifest is not needed. Either closes the symptom without touching the
environment setting. Until then the operator guidance is stated in the
[secure configuration guide](secure-configuration.md).

### Documented-only findings

Every Medium and Low finding not remediated is documented with recommended fix guidance in
[the security audit report](security-audit-report.md), in the mandated eight-field format. They are
documented rather than fixed because the governing constraint is to remediate confirmed Critical and
High severity findings, remediate a Medium only where it is a compensating control for one of those,
and document the remainder. Adding controls for weakness classes with no confirmed finding would be
the enhancement-beyond-remediation that the constraints forbid.

### Ongoing recommendations

Recognised as valuable, all outside this remediation's scope, none started:

* **Make a non-published Production run behave like a published one.** Have the host builders call
  `UseStaticWebAssets()`, or standardise verification on `dotnet publish` output, so that no operator
  is ever tempted to restore styling by setting `ASPNETCORE_ENVIRONMENT=Development` and silently
  undoing the `H-12` and `H-15` remediations (`RISK-031`).
* **Add `autocomplete` attributes to the login form's e-mail and password inputs.** Chrome raises an
  informational advisory on `/login` for their absence. It is neither a console error nor a warning and
  carries no confirmed security finding, so it is noted for completeness only, as HTML hygiene rather
  than remediation.

* **A test suite.** The repository contains no test project, test file or test framework reference in
  any of its 19 projects, which made the "existing test suite passes" validation gate vacuous by
  construction. The substitute verification regime is recorded in the
  [remediation log](remediation-log.md). Creating a suite is feature work the constraints exclude,
  and it is the single highest-value investment available here.
* A distributed store for login throttling (RISK-008).
* A revocable refresh-token table with rotation and reuse detection (RISK-007).
* Completing the Content-Security-Policy rollout to enforcing mode (RISK-022).
* A `Directory.Build.targets` re-appending the promoted audit codes after every project body, so the
  dependency gate cannot be discarded by a single careless `.csproj` assignment (RISK-029).
* Either enrolling both WebAssembly projects in the solution, or making their explicit per-project
  audit a permanent pipeline step, so repository-wide coverage stops depending on remembering to run
  three commands instead of one (RISK-030).
* A `must_change_password` marker on the user entity, so the generated initial administrator password
  is *forced* to be rotated rather than merely advised (RISK-027).
* Replacing the two permissive CORS policies with explicit allow-lists (RISK-013).
* Integration with a dedicated secret manager, rather than environment variables alone.
* Centralised log aggregation, intrusion detection, and a web application firewall.
* Automated dependency-update tooling, so advisories surface without a manual review.
* Independent penetration testing. Nothing in this remediation substitutes for it.
* Multi-factor authentication, and password expiry and history policies — no confirmed Critical or
  High finding required them, so they are recommendations rather than remediation.
