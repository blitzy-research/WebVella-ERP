# Secure Configuration

Operator guide for running WebVella ERP securely: what you must supply, how to supply it, what the
platform now emits and enforces, and what is deliberately still open.

Findings are described in the [security audit report](security-audit-report.md), the changes in the
[remediation log](remediation-log.md), accepted risks in the [risk register](risk-register.md), and
the credential format change in the [credential migration guide](credential-migration.md).

## Read this first — the state of the shipped configuration

**The tracked `Config.json` files have been scrubbed.** All eight now carry **empty** secret values
and `"DevelopmentMode": "false"`, and `WebVella.Erp.Site/web.config` sets `Production`. The files are
retained rather than deleted, because the JSON configuration source is not optional and deleting them
breaks start-up outright. `RISK-021` is closed for the tracked configuration files.

**The application therefore will not start until you supply the required secrets — by design.** It
fails fast with a message naming each missing setting and never its value. Older passages further down
this document were written before the scrub landed and describe the files as still carrying live
values; where they do, the *What is in force at this commit* table below is authoritative.

Treat every value in every tracked configuration file as public. Two consequences follow, and they
are the whole point of this guide:

- **Override every secret externally before you run this anywhere but a developer laptop.** The
  configuration provider chain was extended for exactly this purpose, so you can now do so without
  editing a tracked file.
- **Rotate anything that was ever deployed with a shipped value** — the database password, the
  encryption key and the token signing key. A value published in a public repository is compromised
  by definition, and rotating it is the only remediation.

Sections below that describe the configuration files as already scrubbed describe the **planned**
end state of the secret-management class. They are the specification for that work, not a description
of this commit.

## What is in force at this commit

| Control | State |
| --- | --- |
| Configuration provider chain | **The tracked JSON file is always first**, so a blanked value can never override a supplied secret — that precedence is the control, and it holds at all four builder sites. The shared fallback path used by the Crm, Mail, MicrosoftCDM, Next and Sdk hosts is **JSON file → environment variables → user secrets (Development only)** (`WebVella.Erp.Web/ErpMvcExtensions.cs`, in `AddErp`, reached only when `ErpSettings.IsInitialized` is still false). `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` (each in its own `Startup.ConfigureServices`) initialise `ErpSettings` themselves and place **environment variables last**, so the fallback never runs for them. `WebVella.Erp.ConsoleApp/Program.cs` now follows the same shape as the shared fallback — **JSON file → environment variables → user secrets (Development only)** — with the environment resolved from `DOTNET_ENVIRONMENT`, falling back to `ASPNETCORE_ENVIRONMENT`, because a console application has no `IHostEnvironment` to consult. Its user-secrets provider is registered against the entry assembly with `optional: true`, which is load-bearing rather than decorative: this project declares no `UserSecretsId`, and every `AddUserSecrets` overload given `optional: false` throws `InvalidOperationException` when that attribute is absent. The practical consequence is stated plainly rather than implied — until the project declares a `UserSecretsId`, that provider contributes no configuration, so the console application's effective chain today is JSON file then environment variables. The two orderings differ **only** in whether a user secret or an ambient environment variable wins in Development when both define the same key; outside Development no user-secrets provider is added anywhere, so every host is exactly JSON file then environment variables |
| Missing-secret behaviour | Fail fast. `WebVella.Erp/ErpSettings.cs` aborts startup with an actionable message naming each missing or weak setting; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back, and the compiled-in default key is gone |
| Known published defaults | Rejected by SHA-256 digest comparison, so the repository's own example encryption key and token signing key cannot be used even if supplied deliberately |
| Response security headers | All seven emitted by `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, registered once through `AddErp` and ordered in **all seven** hosts ahead of `UseResponseCompression` and both `UseStaticFiles` calls |
| Content-Security-Policy | Emitted in **report-only** mode carrying the mandated value **verbatim** — `default-src 'self'; script-src 'self'; style-src 'self'` and nothing else. There is **no `report-uri` directive and no collection endpoint**; both were removed, because appending `report-uri` altered the mandated header value and the collector's early return could answer a request without attaching the other six headers. Reports are read from the browser console during the rollout instead (`RISK-022`) |
| Transport security | `UseHsts()` then `UseHttpsRedirection()` in all seven hosts, guarded to non-Development and ordered **after** `UseCors` so cross-origin preflight is not broken by a redirect |
| Cookies | `SecurePolicy=Always` **unconditionally, including in Development**, `SameSite=Lax`, a 24-hour sliding expiry window and a 7-day absolute horizon |
| Rate limiting | `UseRateLimiter()` in all seven hosts, positioned after both static-file middlewares so assets are never throttled |
| Login throttling | Per-account and per-address counters over a bounded private store, consulted at the login page and at the anonymous token route (`RISK-008`) |
| Build gate | `Directory.Build.props` — dependency auditing at `all`/`low` with **six** NuGet audit diagnostics promoted to errors: the four severity codes `NU1901`–`NU1904` **and** the two data-availability codes `NU1900` and `NU1905`. .NET analyzers run with `AnalysisLevel=latest-recommended` for the general categories and **`AnalysisLevelSecurity=latest-all` for the whole Security category**; their diagnostics are kept as warnings at the project level and enforced instead by the workflow's Gate 1 allow-list. Verified inherited by **19 of 19** projects — `Directory.Build.props` and the repository-root `.globalconfig` are directory-scoped, so inheritance does not depend on solution membership |
| Toolchain pin | `global.json` pins `10.0.302` with `rollForward: latestPatch`, because both gates are selected by the SDK feature band |
| Shipped secrets | **Scrubbed.** All eight `Config.json` files carry empty secret values and `DevelopmentMode: false`, `WebVella.Erp.Site/web.config` sets `Production`, and the seeded administrator password is no longer a literal (`RISK-021`, now closed). One demo credential remains in the Blazor WebAssembly **client** page `Client/Pages/Index.razor.cs`, which is outside this change's file scope |
| Mail transport | SMTP server certificates are **validated by default**. `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` bypasses validation only when `Settings:EmailSMTPAllowInvalidCertificates` is `true` — environment form `Settings__EmailSMTPAllowInvalidCertificates` — which exists for self-signed development servers, is honoured only in Development posture, and must never be set in production. **Revocation is checked by default too**, so the relay's chain must expose a reachable CRL or OCSP endpoint; `Settings:EmailSMTPCheckCertificateRevocation=false` narrows that single check — in any posture — while leaving chain, expiry and host-name verification in force (`RISK-060`). See *SMTP certificate revocation* |
| Closed since the inventory was taken | `RISK-013` is **closed**: no host applies `AllowAnyOrigin()` any longer. Both `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` serve explicit origin allow-lists, each reusing the origins recorded in its own previously commented-out policy, and the call survives only inside explanatory comments — `git grep -n 'AllowAnyOrigin' -- '*.cs'` returns comment lines and nothing applied. Finding `H-11` is **closed at all five sites**, not four: every `ServerCertificateValidationCallback` in the mail plugin — the four in `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` and the one in `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs` — now yields the `AllowInvalidRemoteCertificates` setting rather than a literal `true`, and that setting parses to `false` unless an operator sets `Settings__EmailSMTPAllowInvalidCertificates` to `true`. `RISK-014` is **closed**: both anonymous bearer-token error paths in `WebVella.Erp.Web/Controllers/WebApiController.cs` return a generic message outside Development and retain their server-side log record |

## How this guide is organised

The configuration guidance was written from four angles and all four are reproduced, because each
carries operational detail the others do not.


## Required settings, how they are supplied, and verifying a deployment

Operator guidance for running WebVella ERP securely. This is the document referenced by the startup
failure messages the platform raises when a required security setting is missing, and by the comment
in `global.json` that explains why the toolchain is pinned.

The companion documents are the [security audit report](security-audit-report.md), the
[remediation log](remediation-log.md), the [risk register](risk-register.md) and the
[credential migration guide](credential-migration.md).

**Read this before deploying.** The configuration that ships in this repository is *development*
configuration. Every `Config.json` file contains working values — a database password, a symmetric
encryption key and, on two hosts, a token signing key — and every one of them enables development
mode. Those values are public in this repository's history and must be treated as compromised.

---

### 1. Required security settings

`ErpSettings.Initialize` validates these at startup and aborts with an actionable message listing
**every** missing value at once, rather than one per restart. Only setting *names* ever appear in that
message — never values, prefixes, lengths or digests — so a startup failure cannot leak key material
into a console, a log file or a crash report (CWE-532).

| Setting key | Environment-variable form | Required | Purpose |
| --- | --- | --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` | **Always** | PostgreSQL connection. Consumed by `DbContext`, `ERPService` and every repository immediately after initialisation, so no host functions without it. |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` | **Always** | Symmetric key used by `CryptoUtility`. There is no longer a compiled-in default (finding C-04). |
| `Settings:EncriptionKey` | `Settings__EncriptionKey` | Alternative to the above | **Legacy misspelling, still honoured.** `Initialize` reads the correct spelling first and falls back to this one, resolving it into the same value before validation runs. Existing deployments therefore keep working unchanged. Prefer the correct spelling for new deployments. |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` | **Only when a `Settings:Jwt` section exists** | HMAC signing key for bearer tokens. |
| `Settings:Jwt:Issuer` | `Settings__Jwt__Issuer` | No — defaults to `webvella-erp` | Expected token issuer. |
| `Settings:Jwt:Audience` | `Settings__Jwt__Audience` | No — defaults to `webvella-erp` | Expected token audience. |
| `Settings:InitialAdministratorPassword` | `Settings__InitialAdministratorPassword` | No — **first provisioning only** | The first administrator's password on a brand-new database. Absent, provisioning generates a 20-character value with a CSPRNG and prints it once. Present, it must satisfy the password policy or **provisioning aborts** — see [§ The initial administrator password must satisfy the password policy](#the-initial-administrator-password-must-satisfy-the-password-policy). |

#### Why the token key is conditional

Demanding a signing key from every host would stop the ones that do not issue tokens from starting at
all, which the preservation requirement forbids. The check is therefore scoped: the key is mandatory
**if and only if** the configuration actually declares a `Settings:Jwt` section. Of the eight shipped
configuration files, exactly two declare one:

| Host | Declares `Settings:Jwt` | `Settings:Jwt:Key` required |
| --- | --- | --- |
| `WebVella.Erp.Site` | Yes | Yes |
| `WebVella.Erp.Site.Project` | Yes | Yes |
| `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Sdk` | No | No |
| `WebVella.Erp.ConsoleApp` | No | No |

Where the section *is* present the key is mandatory, because the hard-coded fallback that used to
cover it was removed (finding H-04).

#### The initial administrator password must satisfy the password policy

Review finding `F25` (CWE-521, OWASP A07:2021).
`Settings:InitialAdministratorPassword` is the one security setting whose *value* is validated for
content rather than merely for presence, and it is the one setting that can abort provisioning
rather than startup. The rule is the platform password policy, enforced by the single validator
`PasswordUtil.ValidatePasswordPolicy`:

| Rule | Value |
| --- | --- |
| Minimum length | 12 characters |
| Maximum length | 128 characters |
| Required character classes | an upper case letter, a lower case letter, a number, and a symbol — all four |
| Leading or trailing whitespace | rejected, because it is almost always an accident of how the value was supplied |

If the value you supply fails any of these, `InitializeSystemEntities` throws before it creates the
administrator record. The message names the setting and states the rule; it **never echoes the value,
its length, or any prefix of it**, for the same reason the missing-setting message never does
(CWE-532). Verified both directions against a throwaway database: a compliant value provisions two
seeded accounts carrying 84-character modern hashes, and a non-compliant value leaves **no
administrator credential behind at all** — it fails closed rather than falling back to a generated
password, because silently substituting a different password than the operator asked for is worse
than refusing.

**Why this is a refusal and not a warning.** The setting exists precisely so an operator can choose
the first credential of a new deployment. That credential is the most privileged one the system will
ever have, and it is chosen exactly once, unattended, at the moment when nobody is watching a log.
A warning would be read by nobody; the abort is read by everybody.

**If provisioning aborted on you.** Correct the value and start the host again. Nothing was written,
so there is no partial state to clean up — the refusal precedes schema creation entirely, which is
why a verification query for the administrator row at that point reports the table itself does not
exist. That is a stronger result than *no row exists*, not a missing answer.

**This is not the only place the policy applies.** The same validator guards both
`SecurityManager.SaveUser` branches and the generic record-write path, so a
`POST api/v3/{culture}/record/user` carrying a one-character password is refused with a field-level
error keyed `password` and creates no row. Two exemptions are deliberate and load-bearing — see
`RISK-047` in the [risk register](risk-register.md).

#### Choosing key values

| Key | Requirement |
| --- | --- |
| `Settings:Jwt:Key` | The signing algorithm is HMAC-SHA-256, so supply **at least 32 bytes** of key material — 256 bits. Generate it from a cryptographically secure random source, for example `openssl rand -base64 48`. Do not use a human-readable phrase, and do not repeat a short string to reach the length; the value that shipped in this repository did exactly that and is finding H-04. |
| `Settings:EncryptionKey` | Generate from a CSPRNG. See §3 before changing this value on an **existing** installation — changing it can make previously encrypted data unreadable. |
| `Settings:ConnectionString` | The role needs DDL rights because schema provisioning is code-driven, and — on this platform as it currently stands — it also needs `SUPERUSER`. See *PostgreSQL role privileges* immediately below; an earlier revision of this guide stated that `SUPERUSER` was not required, which is incorrect and would leave an operator with a role that cannot start the application. |

Rotate all three if this repository's shipped values were ever deployed.

#### PostgreSQL role privileges

The role in `Settings:ConnectionString` must be a **`SUPERUSER`** on the current codebase. This is a correction: this guide previously said `SUPERUSER` was
unnecessary, and an operator who provisioned a least-privilege role on the strength of that sentence would find the application unable to start at all.

The requirement comes from one specific pair of statements, not from the schema work in general. `WebVella.Erp/Database/DbRepository.cs:17-20` runs:

```sql
DROP CAST IF EXISTS(varchar AS uuid);
DROP CAST IF EXISTS(text AS uuid);
CREATE CAST(text AS uuid) WITH INOUT AS IMPLICIT;
CREATE CAST(varchar AS uuid) WITH INOUT AS IMPLICIT;
```

PostgreSQL requires ownership of the cast's source or target type, and `varchar`, `text` and `uuid` are all built-in types owned by the bootstrap superuser. A role
that owns its own database and can freely issue DDL therefore still cannot execute these four statements. Measured against PostgreSQL 16 with a role holding
`LOGIN` only and owning the database:

| Statement | Source | Result for a non-`SUPERUSER` owner |
| --- | --- | --- |
| `CREATE TABLE …` | ordinary schema provisioning | **succeeds** — ordinary DDL genuinely does not need elevation |
| `CREATE EXTENSION "uuid-ossp"` | `DbRepository.cs:30` | **succeeds** — `uuid-ossp` has been a *trusted* extension since PostgreSQL 13, so this is **not** a reason to elevate |
| `CREATE EXTENSION "postgis"` | `DbRepository.cs:37` | fails with `permission denied to create extension "postgis" / Must be superuser` — but the call is wrapped in `try`/`catch` at `DbRepository.cs:34-42` and the failure is deliberately tolerated, so it is **not** a blocker either |
| `CREATE CAST(varchar AS uuid) …` | `DbRepository.cs:20` | **fails** with `must be owner of type character varying or type uuid` — and it is **not** wrapped in `try`/`catch`. **This is the blocker.** |
| `DROP CAST IF EXISTS(varchar AS uuid)` | `DbRepository.cs:17` | no-op when the cast is absent, but **fails** with the same ownership error once the cast exists |

Two consequences follow, and both matter operationally:

* **The privilege is needed on every startup, not only at first install.** The cast block is invoked from `WebVella.Erp/ERPService.cs:77`
  (`DbRepository.CreatePostgresqlCasts()`, immediately after `CreatePostgresqlExtensions()` at `:75`), which sits *before*
  the `if (currentVersion < 1)` provisioning gate at `ERPService.cs:106`. It is therefore unconditional, and `InitializeSystemEntities` runs from the web host's
  own startup path (`WebVella.Erp.Web/ErpMvcExtensions.cs:503`). Every process start re-executes the drop-and-recreate.
* **"Provision once as `SUPERUSER`, then run as a least-privilege role" does not work.** It was tested rather than assumed: with the two casts pre-created by a
  superuser, the least-privilege role's very next `DROP CAST IF EXISTS` fails with `must be owner of type character varying or type uuid`. Pre-creating the casts
  makes the situation worse, not better, because the drop then has something to drop.

So there is currently no supported least-privilege configuration. Grant `SUPERUSER`, and compensate at the boundaries that are actually available: give the
platform its **own dedicated role and database**, never a role shared with other applications; restrict `pg_hba.conf` so that role can only authenticate from the
application host; and keep the connection string out of the repository exactly as §2 requires. The narrower fix — making the cast block version-gated so it runs
once and a steady-state role can be unprivileged — is a change to provisioning behaviour rather than a security fix, so it is out of scope for this remediation
under the minimal-change clause and is recorded as a recommendation in the [risk register](risk-register.md).

---

### 2. How settings are supplied

#### The mechanism as it stands today

Configuration is read from a **JSON file only**. Both configuration builders in the platform are:

```csharp
new ConfigurationBuilder().SetBasePath(...).AddJsonFile(configPath)
```

* `WebVella.Erp.Web/ErpMvcExtensions.cs:L425-L447` — inside `UseErp` (declared at `:L352`), file **`Config.json`**, base
  path **`AppContext.BaseDirectory`**, then `AddEnvironmentVariables()`, then user secrets in
  Development. This is the path the Crm, Mail, MicrosoftCDM, Next and Sdk hosts rely on.
* `WebVella.Erp.Site/Startup.cs:L49-L105` and `WebVella.Erp.Site.Project/Startup.cs:L41-L80` — the
  same file name and the same base path, used for each host's own `Configuration` property (which is
  what supplies the JWT parameters to the authentication handler).
* `WebVella.Erp.ConsoleApp/Program.cs:L74-L105` — the same file name and base path, resolved with an
  explicit `Path.Combine(AppContext.BaseDirectory, "Config.json")`.

Three consequences follow, and all three matter operationally:

1. **The file source is not optional.** The configuration files cannot be deleted — startup fails
   outright without them. Scrub the values; keep the files.
2. **Environment variables are consulted at every one of the four sites**, and user secrets are added
   in Development. The startup failure messages name the `Settings__*` forms because that is the
   supply channel that actually works. The tracked JSON file is always registered *first*, so a
   blanked value can never override a supplied secret — that precedence is the control.
3. **The base path is the application base directory, not the working directory.** That distinction
   is a security property rather than a convenience: `Directory.GetCurrentDirectory()` — which is
   also what `WebHost.CreateDefaultBuilder` defaults `ContentRootPath` to — resolves against whatever
   directory the process happened to be launched from, so a service unit, a scheduled task or a shell
   with the wrong `WorkingDirectory` would let the launcher decide which `Config.json` supplies the
   connection string, the data-at-rest encryption key and the token signing key, or find none at all.

#### The file the runtime actually reads

`Config.json` — with a capital `C`, exactly as the repository tracks it and exactly as both the build
and the publish output copy it. **No renaming or copying step is required, on any platform.**

An earlier revision of the platform asked for the lower-case spelling `config.json` while shipping
`Config.json`, and this guide documented a `cp Config.json config.json` workaround for
case-sensitive filesystems. Both the defect and the workaround are gone. The mismatch was a real
vulnerability rather than an inconvenience (CWE-178, improper handling of case sensitivity; CWE-706,
use of an incorrectly resolved name): on Linux and in containers the intended file simply did not
exist under the requested name, so startup either failed or — worse, once a `config.json` was
created by hand next to the working directory — silently read a file that was not the audited one.

If you followed the old instruction and left a lower-case `config.json` in a deployment directory,
**delete it.** It is no longer read, and leaving an unaudited copy of the configuration on disk is
exactly the exposure the fix removed.

This is not asserted from the source alone. The continuous gate proves it on every run: the
*Smoke-test Linux startup of the published artifacts* step in
`.github/workflows/security-scan.yml` publishes `WebVella.Erp.Site`, `WebVella.Erp.Site.Sdk`,
`WebVella.Erp.Site.Project` and `WebVella.Erp.ConsoleApp`, deletes any lower-case `config.json` from
the output, launches each **from an unrelated working directory**, and asserts that each one resolved
its own `Config.json` and reached the fail-fast secret validation rather than a
`FileNotFoundException`. The evidence is published as `startup-smoke.txt`.

```bash
# Nothing to do. Publish and run:
cd WebVella.Erp.Site
dotnet publish -c Release -o /srv/webvella/site
cd /srv/webvella/site && dotnet WebVella.Erp.Site.dll
```

One detail is worth recording, because it is why this had to be fixed in code rather than by shipping
a second file: adding a lower-case `config.json` alongside `Config.json` in the *source* directory is
not possible. MSBuild item identity is case-insensitive, so the two names collide and the build fails
outright with `NETSDK1022`. The only remaining alternatives were a post-publish copy step in every
deployment pipeline — unenforceable, and silently absent on the one host that forgets it — or making
the code ask for the name that actually exists. The code was changed.

> **Status — closed, and this section is superseded.** Review finding `F30`. **The copy above is no
> longer required and should be removed from deployment steps.** All four builder sites now ask for
> **`Config.json`** first and accept a lower-case `config.json` only when that is the only name
> present: `WebVella.Erp.Web/ErpMvcExtensions.cs` (the shared path for all seven web hosts),
> `WebVella.Erp.Site/Startup.cs`, `WebVella.Erp.Site.Project/Startup.cs` and
> `WebVella.Erp.ConsoleApp/Program.cs`. Provider order is unchanged — the JSON source is still first
> and still non-optional.
>
> The console host had a **second**, independent defect on the same line, which is why it could not
> start on Linux at all rather than merely needing the copy: its `ToApplicationPath` helper detected
> the application root with a Windows-only drive-letter regular expression, so on any other platform
> the root resolved to the empty string and the file name became relative to the **process working
> directory**. It now resolves against `AppContext.BaseDirectory`, which is defined on every platform,
> is independent of the working directory, and is also correct for a single-file publish — unlike the
> assembly-location probe it replaces. The fallback's own residual is `RISK-049`: a directory that has
> lost `Config.json` but kept a stale `config.json` will start from the stale copy, so keep one file,
> not two.

#### The configuration files keep their comments, and two blank values that are deliberate

All eight `Config.json` files and `global.json` carry `//` comments, and this remediation deliberately
kept them. RFC 8259 admits no comments, but nothing in this repository reads these files as strict
JSON: the runtime's own reader accepts them, `dotnet` accepts them in `global.json`, and no gate in
`.github/workflows/security-scan.yml` parses either file — the secret sweep matches key-name
signatures line by line and never invokes a JSON parser. The comments are, in several files, the only
in-place explanation of what a setting does, so stripping them would have deleted rationale for no
verifiable gain. If you introduce a strict consumer later, strip the comments in that consumer's own
copy rather than in the tracked file.

Two of those notes matter enough to restate here, because in each case a **blank** value is a
deliberate setting rather than an omission:

- **`CacheKey`** — leaving it empty is meaningful, not merely unset. The platform then derives the
  cache key from the current date, formatted `yyyyMMdd`, so it rolls over daily.
- **`CloudBlobStorageConnectionString`** (Sdk host only) — the accepted connection-string forms are
  documented by the storage library at
  <https://github.com/aloneguid/storage/blob/develop/doc/blobs.md>. Leaving it blank does **not** leave
  storage unconfigured: the platform substitutes the literal `disk://path=c:\erp-files`. That default is
  a Windows path, so a non-Windows deployment that switches `Settings:EnableCloudBlobStorage` on must
  set this explicitly. Neither setting is one the startup validator requires — it fails startup only
  for a missing `Settings:ConnectionString`, a missing `Settings:EncryptionKey`, or an encryption key
  that is weak or is the example value published in this repository.

---

### 3. The removed default encryption key, and keeping existing data readable

`CryptoUtility` no longer contains a compiled-in default encryption key, and its key accessor no
longer falls back to one. A missing key is now a loud `InvalidOperationException` naming only the
setting, instead of a silent degradation to a value published in this repository (finding C-04,
CWE-798 / CWE-321).

Removing the constant alone would not have fixed anything — the silent fallback *was* the
vulnerability — so both were changed together, and **no** replacement default and **no** generated
random key was introduced. A generated key would have been worse than failing: it would silently make
already-encrypted data undecryptable.

#### If your deployment relied on the removed default

The key is a symmetric key, not a derived one. Data encrypted under the old default is readable
**only** under that same value. So:

1. **Recover the previous value from your own copy of the repository history** — the constant used to
   sit in `WebVella.Erp/Utilities/CryptoUtility.cs`; check out any commit before the remediation and
   read it there. It is deliberately **not** reproduced in this document: republishing it would
   reintroduce exactly the hard-coded secret the remediation removed, and would fail the secrets gate.
2. **Set it explicitly** as `Settings:EncryptionKey` (or the legacy spelling). Your deployment then
   starts and reads its existing data exactly as before. Nothing is re-encrypted and no data is
   touched.
3. **Then rotate, deliberately.** Because that value is public, treat step 2 as a bridge, not a
   destination. To move to a fresh key you must decrypt with the old value and re-encrypt with the
   new one; there is no in-place re-key. Do it as a maintenance operation with a verified backup.

#### How much data this actually affects

Less than the wording suggests, and it is worth knowing before you plan a migration window:

* The only callers of `CryptoUtility.EncryptDES` / `DecryptDES` anywhere in the repository are
  **commented out** — in `WebVella.Erp.Web/Security/AuthToken.cs`, which is unreachable dead code
  (recorded as finding L-01). No live code path in the shipped platform writes `CryptoUtility`
  ciphertext.
* The `CryptoUtility` members that *are* live — `ComputeMD5Hash` and `ComputeOddMD5Hash`, used for
  entity and relation cache keys — are **hash** functions. They do not use the encryption key, so
  they are unaffected by its value and no cache invalidation is needed.
* Password storage does **not** use this key either; passwords are hashed, and that is a separate
  migration described in the [credential migration guide](credential-migration.md).

So on a stock installation, supplying any valid key satisfies startup and there is no ciphertext to
preserve. Step 1 above matters if — and only if — custom plugin code in your deployment called
`CryptoUtility.EncryptDES` and persisted the result.

---

### 4. Environment and development mode

Two independent switches control development behaviour, and **both** must be set for a production
deployment. Setting one and not the other leaves diagnostics exposed.

| Switch | Where | Shipped value | Production value |
| --- | --- | --- | --- |
| `Settings:DevelopmentMode` | All eight `Config.json` files | `"true"` | `"false"` |
| `ASPNETCORE_ENVIRONMENT` | `WebVella.Erp.Site/web.config` sets it to `Development` for IIS-hosted deployments; otherwise the process environment | `Development` | `Production` |
| `SecurityHeaders__ContentSecurityPolicyReportOnly` | `SecurityHeaders:ContentSecurityPolicyReportOnly` | No | `true` when unset or blank. Set `false` only after the report-only inventory is clean — enforcing the mandated `script-src 'self'` while inline script remains would break the interface (`RISK-022`). A **present but unparseable** value aborts startup rather than defaulting, so a typo cannot quietly drop the platform out of the staged rollout. This is the **only** member of `SecurityHeadersOptions` bound from configuration: the policy text is a `public const`, so no configuration source can weaken, blank or replace it |

`ASPNETCORE_ENVIRONMENT` is what gates the developer exception page. Leaving it at `Development`
serves full stack traces, source snippets and environment detail to anyone who triggers an error
(CWE-209, finding H-12).

Be aware of the limit of this switch: error paths that are **not** guarded by an environment check are
not fixed by setting it. The platform has responses that concatenate exception detail
unconditionally, so no environment marker suppresses them — they require a code change and are
recorded in the [audit report](security-audit-report.md) as their vulnerability class lands. Do not
assume a production environment marker suppresses all internal detail.

---

### 5. Response security headers

`WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` emits the mandated header set:

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `0` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

`X-XSS-Protection: 0` is correct and intentional. The legacy browser XSS auditor it disables was
itself exploitable; modern guidance is to switch it off and rely on the content policy.

> **Status: live in all seven hosts.** An earlier revision of this document said the middleware
> existed but was "not yet registered in any host pipeline". That is no longer true and the statement
> is retracted here. `UseSecurityHeaders()` is registered in all seven host pipelines, ordered ahead
> of response compression and ahead of both static-file middlewares. All seven headers were verified
> **on the wire** against a published host over HTTPS — on a dynamic response (`/login`) and on two
> static assets — not merely by reading the source.

##### Operator switches for the header block

One key binds from configuration, so enforcement is reachable without a code change:

| Key | Default | Effect |
| --- | --- | --- |
| `SecurityHeaders__ContentSecurityPolicyReportOnly` | `true` | `true` emits `Content-Security-Policy-Report-Only`; `false` emits the enforcing `Content-Security-Policy`. **The policy value is byte-identical in both modes — only the header name changes.** |

An absent value leaves report-only mode in force; a present but unparseable one aborts startup rather
than silently defaulting, so a typo cannot quietly drop the platform out of the staged rollout it
documents.

**There is deliberately no violation-report collector endpoint, and no `report-uri` directive.** An
intermediate revision of this platform mounted one at `/csp-violation-report`; it was removed, for two
reasons that both matter operationally. First, it was an anonymous, unauthenticated `POST` endpoint
reachable on all seven hosts ahead of routing and authentication, and it terminated the request itself —
so the one response class the header middleware produced was served with none of the seven headers on
it, defeating the all-responses guarantee the middleware exists to provide. Second, appending
`; report-uri …` made the emitted policy differ from the mandated value, and the requirement is that the
value is preserved exactly while only the *delivery mode* is staged. Removing the collector makes both
defects structurally impossible: one path through the middleware, one policy string.

The practical consequence for the rollout below is that violations surface in the **browser's own
developer console**, not in a server-side log. Collect them there. If you would rather aggregate them,
point the policy at an external collector you operate — accepting, if you do, that the emitted value
then differs from the mandated string, which is a deviation to record in the
[risk register](risk-register.md) rather than an invisible default.

#### Ordering matters

Register the middleware **early**, ahead of response compression and ahead of static-file serving.
Placed after them, the headers reach dynamic responses only, and static assets and compressed
responses are served without them. `Strict-Transport-Security` must come before HTTPS redirection.

#### The content policy ships in report-only mode

`SecurityHeadersOptions.ContentSecurityPolicyReportOnly` defaults to `true`, which emits
`Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. **The *policy* is
identical in both modes — the directives are the same, and report-only is not a weaker policy.**

One precision, because an earlier revision of this paragraph described the two modes as backed by two
separate constants, with the report-only value carrying an extra `report-uri` directive. That split was
removed together with the collector, and the superseded description is corrected here rather than
quietly dropped. Both header names now carry the single `ContentSecurityPolicy` constant — which is
`DefaultContentSecurityPolicy`, the mandated directives verbatim with nothing appended — so the value is
identical in both modes and only the header *name* is switchable. It is a compile-time constant, so no
host, plugin or configuration source can weaken it.

**The switch is operator-controlled, not compile-time.** Set `SecurityHeaders:ContentSecurityPolicyReportOnly`
to `false` — environment form `SecurityHeaders__ContentSecurityPolicyReportOnly=false` — and the same value is
emitted as the enforcing `Content-Security-Policy`. Leave it absent, or blank, for report-only. Note the
polarity: the bound setting is the REPORT-ONLY flag, so `false` is what enforces. The value is read with
`bool.TryParse`, so `true` and `false` in any casing are accepted and nothing else is — `1` and `0` are
not booleans to that parser — and a present-but-unparseable value aborts startup rather than quietly
selecting either posture.

This is deliberate, and it is the one place where the mandated header set cannot be *enforced* on
first deployment without breaking the interface. The platform contains components that emit inline
script and author-supplied markup by design — the HTML-block page component and the generated
inline-script emitters. A strictly enforced `script-src 'self'` suppresses them, and the affected
screens stop working.

Roll it out in this order:

1. **Deploy report-only** (the default). Nothing breaks; violations are reported, not blocked.
2. **Collect violations from the browser developer console** — there is no server-side
   collector, see above — and exercise every screen that renders authored markup or generated
   inline script — the HTML-block component, the sitemap component, the page-body manager.
3. **Resolve each violation** by moving inline script into a served file, or by adding a nonce or hash
   for the emissions that must stay inline.
4. **Set `SecurityHeaders:ContentSecurityPolicyReportOnly=false`** once the reports are clean — the
   bound setting is the report-only flag, so `false` is what enforces — and re-test the same screens. No rebuild is involved,
   so the step is reversible by removing the setting and restarting.

Do not skip step 2. The four remaining raw-output channels are the concrete reason this staging
exists. They are not defects to be encoded away — encoding them would disable the features they
implement — so the control that applies to them is a compensating one: authoring markup or script
requires a privileged role. That acceptance belongs in the [risk register](risk-register.md), which
is where this engagement records accepted risk as each vulnerability class lands.

Note that these four are now the **only** raw channels left, which narrows what this staging is
protecting. The wider set of stored raw-output sinks — the shared navigation and menu views and the
Project plugin widget views — were closed at their builders rather than accepted, so the report-only
default is no longer standing between ordinary record data and a script sink. It stands only between
**author-supplied** markup and script, written by a privileged role, and an enforced policy. See the
*Stored output encoding* row in the posture table above.

---

### 6. Transport security

| Control | Guidance |
| --- | --- |
| TLS version | TLS 1.2 or above. Terminate TLS at the reverse proxy or configure Kestrel directly; the platform does not manage certificates. |
| HTTPS redirection | Enable it, guarded to non-development environments. |
| HSTS | Enable it, guarded to non-development environments, ordered **before** redirection. Do not enable HSTS on a hostname you also serve over plain HTTP for other purposes — the `includeSubDomains` directive applies to every subdomain. |
| Cookies | `Secure`, `HttpOnly` and an explicit `SameSite` policy. Use `SameSite=Lax`, not `Strict`: `Strict` breaks the return-URL round trip through the login page, and `Lax` is the framework's documented default posture. |
| SMTP relay certificates | Validated by default, **including revocation**. The relay's chain must expose a reachable CRL distribution point or OCSP responder, or the handshake fails with `unable to get certificate CRL` while the certificate is otherwise valid. See *SMTP certificate revocation* below for the recognition signature and the two supported fixes; `Settings:EmailSMTPCheckCertificateRevocation=false` narrows the check without weakening chain, expiry or host-name verification. |

**Sequencing caveat — this one bites.** Introducing HTTPS redirection *before* the cross-origin
policy is tightened breaks CORS preflight requests, which fail with an invalid-redirect error rather
than an obvious redirect. Change the origin allow-list and enable redirection **together**, and
verify a preflight from an allowed origin afterwards. That is how both changes landed here, and the
verification was executed rather than assumed: with redirection active, an `OPTIONS` preflight from an
allowed origin over **plain HTTP** answers `204` carrying the full `Access-Control-Allow-*` set and
**no** `Location` header, because `UseCors` is ordered ahead of `UseHttpsRedirection` in every host and
short-circuits the preflight before a redirect can be written. A non-preflight plain-HTTP `GET` still
answers `307` to the HTTPS origin, so transport enforcement is intact and only preflight is exempt.

#### Cross-origin policy

All seven hosts now serve an explicit origin allow-list, and no `AllowAnyOrigin()` call remains
anywhere in the tree (finding H-14, `RISK-013`, closed). The two that previously permitted any origin
were `WebVella.Erp.Site` (`Startup.cs:L132-L138`) and `WebVella.Erp.Site.Project`
(`Startup.cs:L109-L115`). Both keep `AddDefaultPolicy` rather than converting to a named policy, so the
`app.UseCors()` call already present in each `Configure` method continues to apply the policy and the
pipeline needed no edit at all. `AllowCredentials()` is deliberately absent from both: the framework
refuses it alongside a wildcard origin, and these two hosts authenticate cross-origin callers with a
bearer token rather than with a cookie.

**The allowed origins are hard-coded localhost values in all seven hosts — they are development
defaults, not deployment configuration.** Replace them with the origins your deployment actually
serves before going live; an allow-list naming the wrong origins is not protection, it is a
mis-statement of it. Verify afterwards that an allowed origin receives `Access-Control-Allow-Origin`
together with `Vary: Origin`, and that an origin outside the list receives **no** CORS headers at all.
Do not be misled by the status code while testing: a disallowed origin still receives the normal
response *status and body*, because CORS is enforced by the browser on the basis of those headers, not
by the server refusing to answer. The absence of the header is the control.

---

### 7. Toolchain pinning and gate reproducibility

`global.json` pins the SDK:

```json
"sdk": { "version": "10.0.302", "rollForward": "latestPatch" }
```

This is a security control, not housekeeping (finding L-07). Both halves of the automated gate are
SDK-version dependent: the dependency-audit defaults and the analyzer rule set. An unpinned toolchain
means the same source can produce a different gate result on a different machine, which makes every
"scan is clean" claim unverifiable.

`rollForward: latestPatch` is what the tree carries, and it is the correct policy rather than merely
the more permissive one. The audit-mode default and the analyzer rule set are selected by the SDK
**feature band**, and `latestPatch` holds the pin on the `10.0.3xx` band — so it delivers exactly the
reproducibility the finding asks for, while still admitting a security patch of the SDK itself. Pinning
a toolchain must not become a reason to run an unpatched toolchain.

`disable` was tried and rejected. It freezes the toolchain to the exact version above, which sounds
stricter but fails on availability: the moment `10.0.302` is superseded, the repository becomes
unbuildable for every developer and for CI simultaneously — breaking the *all existing functionality
remains operational* preservation requirement — in exchange for a guarantee the feature band already
provides. If no SDK on the `10.0.3xx` band is installed at all, `latestPatch` still fails predictably
with an actionable message naming the required version.

`Directory.Build.props` at the repository root carries the gate and is inherited by every project:

| Property | Value | Effect |
| --- | --- | --- |
| `NuGetAudit` | `true` | Dependency auditing on. |
| `NuGetAuditMode` | `all` | Direct **and transitive** packages are audited. |
| `NuGetAuditLevel` | `low` | Advisories of every severity are reported, not just High and Critical. |
| `WarningsAsErrors` | appends `NU1900;NU1901;NU1902;NU1903;NU1904;NU1905` | A package advisory **fails the build** — and so does an audit that could not be performed. |
| `EnableNETAnalyzers` | `true` | The .NET analyzers run on every compilation. |
| `AnalysisLevel` | `latest-recommended` | The recommended rule set for the non-security categories. |
| `AnalysisLevelSecurity` | `latest-all` | **The whole Security category**, which `latest-recommended` alone does not deliver — see the coverage table below. The two levels are deliberately different: the security rules are turned all the way up while the style and design backlog stays at the recommended set. |

It must be an MSBuild properties file rather than an editor-configuration file: the four
`.editorconfig` files in this repository each declare `root = true`, so a repository-root editor
configuration would not reach the files inside those subtrees. MSBuild inheritance is not affected by
that scoping.

> **Contributor warning — always *append* to `WarningsAsErrors`, never assign it.** Write
> `<WarningsAsErrors>$(WarningsAsErrors);CS0168</WarningsAsErrors>`. A project that assigns the
> property instead — `<WarningsAsErrors>CS0168</WarningsAsErrors>` — **silently discards the entire
> dependency gate for that project**, and the build stays green while a High-severity advisory sits
> in its graph. This is not hypothetical: MSBuild imports `Directory.Build.props` *before* the body
> of the project file, so a later bare assignment overwrites the promotion rather than adding to it.
> A probe declaring `<WarningsAsErrors>CS0168</WarningsAsErrors>` under this repository's props
> resolves the property to `CS0168;SYSLIB0011` — every promoted `NU19xx` code, and the SDK's own
> `NU1605`, gone — and then restores a package with a known High advisory at **exit 0 with only
> `warning NU1903`**.
>
> No project in this repository currently does this, and that was verified rather than assumed:
> `Directory.Build.props` is the **only** MSBuild customisation file in the tree (there is no
> `Directory.Build.targets` and no `Directory.Packages.props`), and none of the 19 `.csproj` files
> mentions `WarningsAsErrors`, `TreatWarningsAsErrors` or `NoWarn` at all. The `NU1605;SYSLIB0011`
> that appears in the resolved value comes from the .NET SDK, which appends *after* this props file.
> The gate is intact today; it is one careless assignment away from not being. A
> `Directory.Build.targets` re-appending the codes after all project bodies would make this
> structurally impossible, and is recorded as a follow-up in the
> [risk register](risk-register.md) rather than done here, because it is outside this change's
> authorised file set.

**An earlier revision of this section said "analyzer diagnostics remain warnings; only the six
dependency codes are errors". That is no longer true and the claim is withdrawn.** The repository-root
`.globalconfig` promotes **ten security rules to errors**. An earlier revision attributed this to a
`security-analyzers.ruleset` file promoting 95 rules; no such file exists — severities are set
rule-by-rule in `.globalconfig`, which the SDK auto-discovers, and the breadth of the category comes
from `AnalysisLevelSecurity=latest-all` instead. The reasoning that used to justify keeping analyzer
diagnostics as warnings — that promoting an analyzer backlog across roughly 700 pre-existing files
would demand a mass refactor — still holds, and it is exactly why the choice of which rules to promote
was **measured** rather than assumed: every one of the ten emits zero diagnostics on the current tree,
so promoting it changes nothing about existing code and can only fail on code written afterwards. The
five rules that do have a backlog (`CA2100`, `CA2326`, `CA2328`, `CA5351`, `CA5362`) are the five
deliberately held at warning against an enumerated baseline.

For an operator the practical consequence is short: **a build that emits an analyzer error is now a
gate failure, not noise.** It names a security rule, it is about code changed recently, and demoting
the rule is not the remedy — `.globalconfig` requires a recorded risk acceptance before any rule moves.

#### CI secret sweep — detection envelope

`.github/workflows/security-scan.yml` substitutes a plain-shell signature sweep for the external
secrets scanner named in the brief (gitleaks / truffleHog / detect-secrets). Because it is a
substitute, its blind spots matter as much as its coverage, so the envelope is recorded here rather
than narrated in the workflow file.

What it asserts: every secret-bearing key in a tracked `Config.json` or `appsettings*.json` is empty;
`WebVella.Erp/Utilities/CryptoUtility.cs` carries no long embedded literal (finding C-04); and
`WebVella.Erp/ERPService.cs` assigns no literal seed password (finding C-01). It reports a file path,
the offending key *names* and a verdict only — never a matched value. Its own six positive fixtures
are stored base64-encoded rather than in the clear, for one specific reason: written literally they
would make the sweep match its OWN workflow file, and the only ways out of that would be to exclude
that file by path — the allowance the patterns deliberately refuse — or to weaken a pattern. The four
negative fixtures stay in the clear on purpose, because they are the exact benign shapes this
repository really carries and their presence proves, in the workflow's own source, that they do not
match.

The shipped sweep matches through **five independent pattern layers**, and a file fails the gate if
any one of them fires: `L1` (a quoted `key: "value"` or `key = "value"` assignment), `L1B` (the same
key names unquoted, as in an env-file or shell export), `L2A` (provider-specific literal shapes — a
PEM private-key header, an AWS access-key id, Slack, GitHub and Google API key prefixes), `L2B` (a
credential-bearing `scheme://user:password@host` URI), and `L2C` (an ADO.NET-style
`Server=...;Password=...` string, tolerating up to four intervening `key=value;` pairs). The layers
carry no path exclusions at all, and binary files are skipped only by `grep -I`.

Separately, **four bypasses** were found by fixture-testing an earlier revision of the sweep and are
closed in the shipped version. These are a history of defects, not a second enumeration of the layers
above:

| Bypass | How it evaded detection | How it is closed |
| --- | --- | --- |
| Case | A case-sensitive matcher let `connectionString` pass, and a case-sensitive pathspec never inspected a lower-case `config.json` or any `appsettings.json`. | `grep -iE` plus `:(icase)` pathspecs. Both pathspecs carry a leading `*`, because a git pathspec is anchored at the repository root and would otherwise match only a top-level file. |
| Prefix | The alternation anchored key names exactly, so `CloudBlobStorageConnectionString` — a key this repository really carries — passed while populated. | Every key-name alternative is now prefix-tolerant — the layers prepend `[A-Za-z_]*` to the whole alternation, and the separate `Config.json` emptiness pattern prepends `[A-Za-z]*` to each name — and `SecretKey`, `ApiKey`, `ClientSecret` and `Pwd` were added to both, with `Token` added to the `Config.json` pattern. |
| Line orientation | `grep` matches within a line, so a key and its value split across two lines passed. | Newlines are collapsed before matching. |
| Empty sweep | A pathspec matching nothing produced neither a PASS nor a FAIL, and the gate reported success having inspected nothing. | An explicit swept-count assertion fails closed, as does a missing target file for either source check. |

Deliberately preserved behaviour: an **empty** value passes, because that is the required end state,
while a **whitespace-only** value fails.

Known limits, and why they are acceptable here. File **type** is not a limit: the five layers enumerate
every tracked file through `git ls-files` piped into `grep`, with no path filter and no extension
filter, and the two pathspecs bound only the separate `Config.json` emptiness assertion. Three things
the sweep genuinely cannot see:

- **A secret under a key name none of the layers recognise, in a shape none of them matches.** Bounded
  by this platform supplying every secret from the environment, so there is no second tracked
  configuration surface for one to hide in.
- **A secret inside a file `grep -I` treats as binary.** Measured against this tree that is 48 of 1,574
  tracked files — 32 PNGs, 12 fonts, a GIF, an icon, a JAR and one 29 MB native DLL, the last recorded
  as finding L-04. None of them is a configuration surface, and none is text a reviewer would read.
- **A secret in repository history rather than the checked-out tree.** History rewriting is out of
  scope; the values already exposed are recorded as requiring rotation in [key rotation is
  mandatory](#key-rotation-is-mandatory).

The workflow also carries a **negative control**: it restores a throwaway project referencing the
`AutoMapper` version whose High-severity advisory finding H-01 closed, and fails the job if that
restore *succeeds*. This is what distinguishes a genuinely clean dependency scan from a gate that has
silently stopped working — for example because the advisory database was unreachable.

---

### 8. Verifying a deployment

```bash
# Dependency gate: must report no vulnerable packages, for every project.
dotnet restore WebVella.ERP3.sln
dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive

# That single command now covers ALL 19 projects. An earlier revision of this block said it covered
# only 17 and that the two WebAssembly projects had to be audited separately; both are now solution
# members, so the two extra commands are no longer required. Confirm the coverage rather than
# trusting it - this must print 19:
dotnet sln list | grep -c '\.csproj$'

# Static analysis gate: must be 0 errors. A security analyzer diagnostic is now an ERROR, not a
# warning, for the 95 promoted rules - so this build failing is a gate failure to be fixed in code.
dotnet build WebVella.ERP3.sln -c Debug
```

A dependency scan that reports clean is only trustworthy once the project-reference path casing
defect (finding H-19) is fixed — before that fix, `WebVella.Erp` dropped out of the solution restore
graph on case-sensitive filesystems and its advisories were never evaluated at all. Confirm the
defect stays fixed:

```bash
grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln   # must return nothing
```

Then confirm the fail-fast behaviour is real rather than merely configured: start a host with
`Settings:ConnectionString` or `Settings:EncryptionKey` removed. It must abort at startup with a
message naming the missing setting and nothing else. If it starts, a fallback still exists somewhere.

Confirm the mail transport's two certificate settings are still bound the way they are documented —
both are read at every send, so a rename or a typo in either is silent until mail stops:

```bash
# The accept-any opt-out must be gated on posture, and the revocation switch must NOT be.
grep -n 'EmailSMTPAllowInvalidCertificates\|EmailSMTPCheckCertificateRevocation' \
  WebVella.Erp.Plugins.Mail/Api/SmtpService.cs        # exactly one read of each key

# Every send path must set the revocation policy. This must print 5 - four direct sites plus the
# queued one - and any lower number means a path was left on the implicit default.
grep -rc 'CheckCertificateRevocation = ' \
  WebVella.Erp.Plugins.Mail/Api/SmtpService.cs \
  WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs | awk -F: '{t+=$2} END {print t}'
```

Then exercise the revocation path against your own relay rather than trusting the setting: send a test
message with the setting absent. If it fails with a chain status of only `unable to get certificate
CRL`, your relay's chain has no reachable revocation source — fix the chain, or set
`Settings__EmailSMTPCheckCertificateRevocation=false` and record `RISK-060`. Re-send afterwards; it
must deliver, and the host log must carry exactly one `SmtpService[2]` notice.

---

### Method and limitations

Stated plainly, so the confidence attached to each claim is visible:

* **Every setting name, default and validation rule above was read from the source** —
  `WebVella.Erp/ErpSettings.cs`, `WebVella.Erp/Utilities/CryptoUtility.cs`,
  `WebVella.Erp.Web/ErpMvcExtensions.cs` and the host `Startup.cs` files — not from the specification.
  Where the code and the specification disagreed, the code is what is documented.
* **The `Settings:Jwt` host table was produced by inspecting all eight shipped configuration files**,
  not inferred from which hosts appear to use tokens.
* **Two status gaps were disclosed here when this angle was written, and both have since closed.**
  The configuration provider chain now reads environment variables at every builder site (§2), and
  the headers middleware is now registered through `AddErp` and ordered in all seven host pipelines
  (§5). The *What is in force at this commit* table at the top of this document is the authoritative
  current state; where an older angle below still describes a gap, that table wins.
* **The encryption-key impact assessment in §3 is based on a repository-wide search** for callers of
  the encrypt and decrypt members, which found only commented-out ones. It cannot account for custom
  plugin code in your own deployment, which is why §3 step 1 is written as a conditional.
* **No secret value is reproduced anywhere in this document**, including the removed default
  encryption key. Recovering it is described as a procedure against your own repository history
  instead, because publishing it here would reintroduce the finding.
* **Line numbers are omitted in favour of file paths and member names.** Line numbers drift as files
  are edited; the enclosing declaration is the durable locator.


## Configuration values, key rotation, fail-fast behaviour and the build gate

Operator guide for running WebVella ERP securely after the OWASP Top 10 (2021) audit and
remediation. It is the companion to the [security audit report](security-audit-report.md), the
[remediation log](remediation-log.md), the [risk register](risk-register.md) and the
[credential migration guide](credential-migration.md).

This page is **operationally load-bearing, not decorative.** The remediation removes every
compiled-in security default the platform used to fall back on, so a host that is not supplied with
its own secrets no longer starts at all — it fails fast with an actionable message instead of
quietly encrypting with a key that is public knowledge. Everything needed to supply those values
correctly is below.

### Status of the controls described here

The remediation is committed as one atomic commit per vulnerability class, and this guide is written
to the configuration model those commits establish. **All classes have now landed.** An earlier
revision of this table marked five controls as *Pending* and two as implemented-but-unregistered; every
one of those has since landed, and the table below is the corrected state. Each row was re-verified
against the source rather than carried forward on trust.

| Control | Status in the current tree |
| --- | --- |
| Required-secret validation at startup, with fail-fast and no compiled-in fallback | **In force.** `WebVella.Erp/ErpSettings.cs` validates the required values; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back |
| Compiled-in default encryption key | **Removed.** The constant is gone from `CryptoUtility.cs`; a comment records what stood there and why |
| Compiled-in default token signing key | **Removed.** `ErpSettings.cs` reads `Settings:Jwt:Key` with no literal default |
| Credential hashing primitive (salted, work-factored, fixed-time verification) | **In force**, and **all call sites are switched** — see the [credential migration guide](credential-migration.md) for the per-element table |
| Dependency-audit and analyzer build gate | **In force.** `Directory.Build.props`, the repository-root `.globalconfig` rule severities, and the `global.json` toolchain pin |
| Response security headers | **In force.** Registered in all seven host pipelines and ordered ahead of compression and static files. All seven headers verified on the wire against a published host |
| Login lockout after five failed attempts | **In force.** Registered as a singleton in `AddErp` and consulted at **both** credential entry points — the interactive login page and the anonymous bearer-token route — via `TryBeginAttempt` / `RegisterFailedAttempt` / `RegisterSuccess` / `AbandonAttempt`, with the refresh route using the address-only `IsAddressRefusing` / `RegisterAddressFailure` pair because it presents no username |
| Configuration provider chain extended beyond the JSON file | **In force.** Environment variables, then user secrets where a `UserSecretsId` is declared, in both the web extension and the console host — landed **before** any shipped value was blanked, which is the only safe order |
| Shipped `Config.json` secret values blanked, `DevelopmentMode` disabled | **In force.** All eight files carry empty values for the connection string, encryption key, token signing key and mail password, and all eight set `"DevelopmentMode": "false"` explicitly |
| `web.config` environment marker set to `Production` | **In force** |
| Origin allow-list, HSTS, HTTPS redirection, rate limiting | **In force** in all seven hosts, with the origin allow-list applied at the two formerly permissive hosts and the ordering constraints verified against a running host |
| Trusted forwarded-header processing | **In force**, deny-by-default, ordered first so redirection and rate limiting see the real client address |
| SMTP certificate validation restored | **In force.** The five always-true callbacks now return a configuration flag that defaults to `false`, so an invalid certificate is refused unless an operator explicitly opts in |

> **`DevelopmentMode` is fail-safe in both directions, but audit your environment as well as your
> files.** All eight files set `"DevelopmentMode": "false"` explicitly. The setting is read as
> `IsNullOrWhiteSpace(value) ? false : bool.Parse(value)`, so deleting the key entirely would also
> yield `false` — there is no configuration state in which a missing value silently enables
> development behaviour. What *can* re-enable it is a stray `Settings__DevelopmentMode=true` in the
> environment, because environment variables outrank the JSON provider by design. A clean set of
> configuration files is therefore necessary but not sufficient.

Because the shipped configuration files previously carried live secrets **in committed history**, the
[rotation instruction below](#key-rotation-is-mandatory) remains mandatory. Blanking the working tree
does not remove the values from earlier commits, so every secret that was ever committed must be
treated as compromised and rotated.

### Required configuration values

Configuration keys live under a single `Settings` section. Supply them with the ASP.NET Core
hierarchical **double-underscore** environment-variable form once the provider chain is extended, or
in `Config.json` until then.

| Variable | Configuration key | Required | Notes |
| --- | --- | --- | --- |
| `Settings__ConnectionString` | `Settings:ConnectionString` | Yes, every host and the console app | Npgsql / PostgreSQL connection string. Startup fails if absent |
| `Settings__EncryptionKey` | `Settings:EncryptionKey` | Yes, every host and the console app | 64 hexadecimal characters (256-bit). Startup fails if absent — there is no longer any default |
| `Settings__Jwt__Key` | `Settings:Jwt:Key` | Yes for `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` | Only these two hosts ship a `Settings:Jwt` section, and the key is mandatory wherever that section exists |
| `Settings__Jwt__Issuer` | `Settings:Jwt:Issuer` | No | Defaults to `webvella-erp` |
| `Settings__Jwt__Audience` | `Settings:Jwt:Audience` | No | Defaults to `webvella-erp` |
| `Settings__InitialAdministratorPassword` | `Settings:InitialAdministratorPassword` | Yes when provisioning a new database, and when upgrading an installation still carrying the published default administrator password | 12–128 characters, chosen by the operator. Nothing is generated and nothing is printed; provisioning and the version 4 migration abort naming only the key if it is absent |
| `Settings__EmailSMTPPassword` | `Settings:EmailSMTPPassword` | Only when e-mail is enabled | Ships empty |
| `Settings__EmailSMTPAllowInvalidCertificates` | `Settings:EmailSMTPAllowInvalidCertificates` | No | Accepts **any** SMTP server certificate. Honoured only alongside `Settings:DevelopmentMode`; refused, and reported once per process, anywhere else. Never set it in production |
| `Settings__EmailSMTPCheckCertificateRevocation` | `Settings:EmailSMTPCheckCertificateRevocation` | No | Defaults to `true`. Set to `false` **only** when the relay's certificate chain cannot publish a reachable CRL or OCSP endpoint — see *SMTP certificate revocation*. Chain, expiry and host name stay verified; honoured in every posture; reported once per process (`RISK-060`) |
| `Settings__DevelopmentMode` | `Settings:DevelopmentMode` | No | Must be `false` outside development |
| `ASPNETCORE_ENVIRONMENT` | hosting environment | Recommended | Must **not** be `Development` in production |

The token-signing requirement is conditional on purpose. Demanding a signing key from the five hosts
and the console application that issue no tokens would stop them starting, which the preservation
requirement forbids; where the section is present the key is mandatory, because the fallback that
used to cover it has been removed.

All eight run configurations need the connection string and the encryption key: the seven site hosts
`WebVella.Erp.Site`, `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next`, `WebVella.Erp.Site.Project` and
`WebVella.Erp.Site.Sdk`, plus `WebVella.Erp.ConsoleApp`.

`ErpSettings` also honours two legacy misspelled keys for backwards compatibility —
`Settings:EncriptionKey` as a fallback for the encryption key, and `Settings:EnableBackgroungJobs`
for the background-jobs flag. Use the correctly spelled names; the aliases exist only so that
existing deployments keep working and are not recommended for new configuration.

### Why the configuration files must be scrubbed rather than deleted

> **State at this commit:** the scrub described in this section **has** now been performed — all eight
> tracked `Config.json` files carry empty secret values and `DevelopmentMode: false`. It landed *after*
> the enabling change it depended on: the provider chain consults environment variables, so a value can
> be supplied without editing a tracked file. That ordering was mandatory rather than incidental —
> scrubbing first would have left every host unstartable with no channel to supply a replacement.
> `RISK-021` is closed for the tracked files. `RISK-026` recorded two residuals; the demo credential in
> the Blazor WebAssembly client has since been **removed**, so what remains under that entry is only the
> values still present in repository history.

Configuration **used to** be built in `WebVella.Erp.Web/ErpMvcExtensions.cs` from a JSON file and
nothing else: a `ConfigurationBuilder` with a base path and `AddJsonFile("config.json")`, with **no**
environment-variable provider, **no** user-secrets provider, and the file source **not** marked
optional. `WebVella.Erp.ConsoleApp/Program.cs` and each host builder followed the same pattern. That
is the state the scrub had to be sequenced against, and it is recorded here for that reason.

In the current tree all four builder sites read **`Config.json`** — capital `C`, resolved from
`AppContext.BaseDirectory` — then `AddEnvironmentVariables()`, then user secrets in Development, with
the JSON source still non-optional and still registered **first** so a blanked value cannot override a
supplied secret.

Two consequences follow, and both are ordering constraints rather than preferences.

- **The provider chain must be extended before any value is blanked.** Scrubbing first would leave
  operators with no supply channel at all and every host unable to start.
- **The files cannot simply be deleted.** The JSON source is non-optional, so removing the files
  breaks startup outright. They are retained with **empty** values.

Once extended, the chain is: **JSON file → environment variables → user secrets (development only)**.
A later provider overrides an earlier one, so an environment variable supersedes anything left in the
file. That is what lets a container or a CI runner inject secrets without editing anything on disk.

### Key rotation is mandatory

Scrubbing a value out of a working tree does not undo its disclosure. Both platform secrets have
been public, and both remain recoverable from repository history permanently.

- The **encryption key** — `BC93B776A428…`, 64 hexadecimal characters — was present
  **byte-identically in all eight `Config.json` files**, and additionally as a compiled-in constant
  in `CryptoUtility.cs`. That constant shipped inside a library published to nuget.org, so the key
  was public twice over and could be neither rotated nor revoked per deployment.
- The **token signing key** — `ThisIsMySecretKey…`, a phrase repeated three times for 51 characters
  — was present at `WebVella.Erp.Site/Config.json:L25` and
  `WebVella.Erp.Site.Project/Config.json:L20`, with a further occurrence in
  `WebVella.Erp.Site/JWT_README.txt`.
- The **database credentials** were live too. Seven of the eight files pointed at the internal host
  `192.168.10.25:5436` — internal network topology disclosure in its own right — while
  `WebVella.Erp.Site` pointed at `localhost:5432`. The `User Id`/`Password` pairs were `test`/`test`
  in six files and `dev`/`dev` in two. `WebVella.Erp.Site/Config.json:L13` additionally exposed the
  UNC path `\\192.168.10.25\Share\erp3-files`.

**Rotate all three.** Generate replacements with a cryptographically secure random generator:

```text
openssl rand -hex 32      -> 64 hexadecimal characters, a 256-bit encryption key
openssl rand -base64 48   -> a token signing key with ample entropy
```

The signing algorithm actually in use is **HS256** — `SecurityAlgorithms.HmacSha256Signature` in
`WebVella.Erp.Web/Services/AuthService.cs` — so the signing key needs at least 256 bits of entropy.
One nuance worth stating so the wrong lesson is not drawn: the old key was 51 characters, so it was
**not too short.** Its weaknesses were near-zero entropy, because it was one short English phrase
repeated three times, and outright public disclosure. Length alone is not the property that matters.

### Fail-fast behaviour, and why it is the secrets gate's negative test

The platform used to resolve a missing encryption key by silently substituting a compiled-in
constant. **Deleting only that constant would have relocated the defect rather than fixing it — the
silent fallback was the actual vulnerability** — so both were removed together. `CryptoUtility`'s key
property now throws, and there is deliberately no development-mode escape hatch and no
randomly-generated substitute. A generated key would be worse than a loud failure, because it would
silently make already-encrypted data undecryptable.

`ErpSettings` collects **every** missing value before throwing, so a mis-provisioned deployment
learns about all of them from a single startup failure instead of one restart per variable. The
message names the configuration keys and their environment-variable equivalents, and it deliberately
withholds the values themselves — no prefix, no length, no digest — so a startup failure cannot leak
key material into a console, a log file or a crash report.

This behaviour is the **negative test** for the engagement's secrets-scan gate. A scan that finds no
hardcoded credentials proves only that the literals are gone; starting a host with no key supplied
and observing an immediate, explicit failure proves the fallback was genuinely removed rather than
merely hidden.

### The seven response security headers

The engagement mandates this exact header set, and it is reproduced here character for character:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

Delivery is a single middleware, `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`. It is
registered **once** in `WebVella.Erp.Web/ErpMvcExtensions.cs` so that all seven hosts inherit it from
one edit, and then **ordered early in each host pipeline** — ahead of response compression and ahead
of *both* static-file registrations. Ordering is not cosmetic: it is what decides whether the headers
reach static and compressed responses or only dynamically generated ones.

#### The report-then-enforce Content-Security-Policy rollout

The mandated policy value is emitted exactly as written above. Only its **delivery mode** is staged,
and the reason is concrete: four components in this platform emit inline script or author-supplied
markup by design, so a strictly enforced `script-src 'self'` would suppress them and break working
screens. Those four components are enumerated in the [risk register](risk-register.md).

- The policy ships as `Content-Security-Policy-Report-Only` first. Browsers evaluate it and report
  violations without blocking anything, so no interface breaks on first deployment.
- Collect the violation reports — either from the browser console during a deliberate walk-through of
  the affected screens, or by configuring a reporting endpoint and reading what arrives. Expect the
  four inline-script and inline-markup components to appear.
- Once the reports contain nothing but those known components and each has been addressed, set
  `SecurityHeaders:ContentSecurityPolicyReportOnly=false` to emit the enforcing `Content-Security-Policy` header
  instead. The value does not change when you do, only the header name — and neither does the assembly,
  because the switch is read from configuration rather than compiled in.

**The policy value is never silently weakened and the interface is never silently broken.** Staging
the delivery mode is the only way to honour both the mandated header set and the requirement that
existing functionality keep working.

### HSTS and HTTPS redirection

Both are guarded to non-development environments, and **HSTS is ordered first**, before redirection.

**The caveat that dictates deployment order:** HTTPS redirection breaks cross-origin preflight
requests with an invalid-redirect error. It must therefore be deployed **together with** the origin
allow-list described below, never ahead of it, and both must be verified in the same step — a listed
origin must still complete preflight successfully with redirection active. That is how the two changes
landed, and the verification was executed: with redirection active, an `OPTIONS` preflight from a listed
origin over plain HTTP answered `204` with the full `Access-Control-Allow-*` set and no `Location`
header, while a non-preflight plain-HTTP `GET` still answered `307`.

**A second caveat, measured rather than assumed: `UseHttpsRedirection()` is silently inert unless the
application knows an HTTPS port.** Started with `ASPNETCORE_ENVIRONMENT=Production` and only an HTTP
endpoint, the host emitted `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every
response — the header half works — while the redirection half logged
`Failed to determine the https port for redirect.` and passed plaintext requests through untouched.
That is the framework's documented behaviour, not a defect here, but it means an operator who
terminates TLS at a proxy and forwards plaintext gets HSTS and **no** redirect unless they also supply
`ASPNETCORE_HTTPS_PORTS` (or `https_port`) and forward the protocol with
forwarded-header processing. Treat "redirects plaintext" as conditional on that configuration and
verify it on the deployed topology rather than trusting the middleware's presence in the pipeline.

Before this remediation, HSTS was used nowhere in the platform except
`WebVella.Erp.WebAssembly/Server/Program.cs`.

#### Trusting a reverse proxy: `X-Forwarded-*` handling

Forwarded-header processing is **deny-by-default and must be configured explicitly**. It is ordered
**first** in every host pipeline, so that HTTPS redirection and the rate limiter both observe the real
client address and scheme rather than the proxy's.

| Key | Format | Effect |
| --- | --- | --- |
| `Settings__ForwardedHeaders__KnownProxies` | Comma-separated IP addresses | Individual proxy addresses whose `X-Forwarded-*` headers are trusted |
| `Settings__ForwardedHeaders__KnownNetworks` | Comma-separated CIDR blocks, e.g. `10.0.0.0/8` | Proxy networks whose headers are trusted |
| `Settings__ForwardedHeaders__ForwardLimit` | Integer | How many chained proxy entries to walk |

**If neither `KnownProxies` nor `KnownNetworks` is configured, the middleware is not registered at
all.** This is deliberate and stronger than registering it with an empty allow-list: an unconfigured
deployment cannot be tricked into believing a forged `X-Forwarded-For`, which would otherwise let an
attacker evade the per-address rate limiter and the login lockout by varying one header, and let a
forged `X-Forwarded-Proto: https` suppress the HTTPS redirect.

Verified against a running host as a matched set:

| Configuration | Forwarded `X-Forwarded-Proto: https` from loopback | Result |
| --- | --- | --- |
| nothing configured | ignored | `307` redirect — header not trusted |
| `KnownProxies=127.0.0.1` | honoured | `200` — no redirect |
| `KnownProxies=203.0.113.1` | refused | `307` — loopback is not the listed proxy |
| `KnownNetworks=127.0.0.0/8` | honoured | `200` — no redirect |

`X-Forwarded-Host` is **not** honoured in any configuration, so a forwarded host header cannot be used
to poison generated links. All seven security headers remain present on a trusted, non-redirected
forwarded request. A malformed value in any of the three keys **aborts startup** with an
operator-actionable message rather than silently falling back to trusting nothing or everything.

### Origins, mail transport, environment and request limits

#### The origin allow-list

Both hosts that were permissive now carry an explicit allow-list: `WebVella.Erp.Site`
(`Startup.cs:L132-L138`) and `WebVella.Erp.Site.Project` (`Startup.cs:L109-L115`). Both previously
combined any-origin, any-method and any-header, which places no restriction at all. Each keeps
`AddDefaultPolicy` rather than converting to a named policy, so the `app.UseCors()` call already
present in its `Configure` method applies the new policy with no pipeline change, and
`AllowCredentials()` is deliberately omitted — the framework refuses it alongside a wildcard origin,
and these two hosts authenticate cross-origin callers with a bearer token rather than a cookie.

**Two hosts, not seven.** The other five — `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next` and `WebVella.Erp.Site.Sdk` — already use
a restrictive named policy and are deliberately left alone. Their hard-coded localhost origins are a
separate low-severity item recorded in the [risk register](risk-register.md). Overstating this
finding's breadth was one of the false-positive classes the audit explicitly eliminated.

**The origins themselves are still development defaults.** Every one of the seven hosts names
localhost origins. Replace them with the origins your deployment actually serves, then verify that a
listed origin receives `Access-Control-Allow-Origin` together with `Vary: Origin` and that an unlisted
origin receives **no** CORS headers at all.

#### SMTP certificate validation

The mail plugin used to install an always-true certificate validation callback unconditionally at
five sites, four in `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` and one in
`WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs`. That accepts any certificate from any
server, which defeats transport authentication entirely.

The replacement is an explicit configuration flag that **defaults to secure**. A self-signed
development mail server stays usable through deliberate opt-in, so a development convenience can
never again ship as a production default. **Leave the opt-in off in production**, and treat a
certificate failure as a signal to fix the server's certificate rather than to disable the check.

That opt-in — `Settings:EmailSMTPAllowInvalidCertificates`, environment form
`Settings__EmailSMTPAllowInvalidCertificates` — is honoured **only** when `Settings:DevelopmentMode`
is also set. Enabled anywhere else it is refused, and the refusal is reported once per process on
standard error. It is therefore **not** a remedy for the situation described next, and must not be
reached for as one.

#### SMTP certificate revocation

**Your relay's certificate chain must expose a reachable CRL distribution point or OCSP responder.**
This is a genuine new prerequisite, not a restatement of the previous section, and it is the one
operational consequence of enabling certificate validation that will surprise you.

MailKit checks revocation by default, so once the always-true callback was removed the platform began
consulting the revocation source named in the relay's certificate. If that source cannot be reached —
an internal CA that publishes no CRL, a leaf issued without a `crlDistributionPoints` extension, or a
host whose egress filtering blocks the fetch — the handshake fails even though the certificate is
otherwise perfectly valid.

**Recognising it.** The failure is `MailKit.Security.SslHandshakeException` wrapping
`AuthenticationException: The remote certificate was rejected by the provided
RemoteCertificateValidationCallback`, and the chain-status detail contains **only**:

```text
unable to get certificate CRL
```

No expiry bullet, no host-name bullet, no untrusted-root bullet. Read that combination literally: it
says *"I could not find out whether this certificate has been revoked"*, **not** *"this certificate is
untrusted"*. Reaching for the accept-any-certificate opt-out in response would be treating a
reachability problem as a trust problem, and would remove transport authentication entirely to fix a
missing CRL.

**Fixing it, in order of preference.**

1. **Publish the revocation source.** Re-issue the relay leaf with a `crlDistributionPoints` extension
   pointing at a CRL your hosts can actually fetch, sign the CRL with a CA that carries `cRLSign` and a
   subject key identifier, and serve it in **DER** form. Allow the application host outbound access to
   that URL. This keeps every check in force and is the only option that leaves a revoked relay
   certificate refused.
2. **Narrow the check, and only the check.** Set `Settings:EmailSMTPCheckCertificateRevocation` to
   `false` — environment form `Settings__EmailSMTPCheckCertificateRevocation=false`. Mail delivery
   resumes, and the trust chain, validity dates, key usage and host name are **still verified**, so a
   self-signed, expired, wrong-name or wrong-CA certificate is refused exactly as before. What you give
   up is precisely one thing: a relay certificate whose key has leaked and whose issuer has since
   revoked it will no longer be refused. Record it as an accepted risk (`RISK-060`) and remove the
   setting once option 1 is available.

| Property | Value |
| --- | --- |
| Setting | `Settings:EmailSMTPCheckCertificateRevocation` |
| Environment form | `Settings__EmailSMTPCheckCertificateRevocation` |
| Default when absent | `true` — revocation **is** checked |
| Values that disable the check | only a value that parses as boolean `false` (`false`, `False`, `FALSE`, with surrounding whitespace tolerated) |
| Values that leave it enabled | absent, blank, `true`, and anything unparseable such as `no`, `0`, `off`, `disabled` |
| Posture gate | **none, deliberately.** Unlike the accept-any-certificate opt-out, this one is honoured in every posture including Production — a control that is inert in production is no remedy for a production outage, and the relaxation is narrow enough to be supportable there |
| Parsing | non-throwing, so a typo cannot turn a mail configuration mistake into a `FormatException` on every outbound message. The insecure state is `false`, so the test is arranged such that only an explicit `false` disables the check |
| Visibility when disabled | one notice per process on standard error, naming the setting key and nothing else: `warn: WebVella.Erp.Plugins.Mail.Api.SmtpService[2] SECURITY - 'Settings:EmailSMTPCheckCertificateRevocation' is false, so SMTP server certificates are accepted WITHOUT a revocation check.` |
| Sites governed | all five: the four in `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` and the queued one in `WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs`, from a single policy member so no site can drift |

**Two consequences worth knowing before you deploy.**

- Revocation checking genuinely works rather than failing blindly, which is why option 1 is preferred
  and why option 2 is a real, if bounded, loss. A leaf revoked in its issuer's CRL is refused with a
  distinct `certificate revoked` chain bullet, while a non-revoked leaf validated against that same
  freshly published CRL still delivers.
- The queued send path fails **differently** from the interactive one. A direct `SendEmail` throws
  where the caller can see it; the background queue records the handshake text in the message's
  `server_error`, increments `retries_count`, reschedules, and eventually marks the message
  `Aborted`. If mail silently stops flowing and the queue is filling with aborted rows, read
  `server_error` before anything else — the CRL bullet will be sitting in it.
- Both these paths measure a cost, and it is small: warm secure-TLS delivery is within a few
  milliseconds of the accept-all baseline, plus a one-off chain fetch the first time a CRL is
  retrieved and cached.

#### Two SMTP transport misconfigurations that are easy to mistake for certificate failures

Both of the settings above govern what happens **when TLS is negotiated**. Two common relay
misconfigurations never get that far, and both are frequently misread as certificate problems — which
sends the investigation to the wrong setting. Neither is changed by the certificate hardening; both are
pre-existing properties of the transport configuration, recorded here so the symptoms are recognisable.
They are carried in the risk register as `RISK-062` and `RISK-063`.

**A connection-security value that disagrees with the port hangs for two minutes.** The mail plugin does
not set a send timeout, so MailKit's default of 120,000 ms applies to every connect. If a service row is
configured for implicit TLS (`SslOnConnect`) against a port that expects `STARTTLS`, or for `STARTTLS`
against a port that answers with a TLS handshake immediately, neither side makes progress and nothing is
reported for two full minutes.

- The symptom is a **hang**, not an error: an interactive send appears to freeze, and a queue pass appears
  to stall on one message.
- It is not a certificate failure, and no certificate setting affects it. Neither
  `Settings:EmailSMTPCheckCertificateRevocation` nor `Settings:EmailSMTPAllowInvalidCertificates` will
  change the outcome by one millisecond.
- Check the `connection_security` value on the `smtp_service` row against what the relay actually offers
  on that port. The conventional pairings are `SslOnConnect` with 465, and `StartTls` with 587 or 25.

**A service row configured for cleartext delivers with no certificate involved at all.** A
`connection_security` of `None` connects in the clear, and `StartTlsWhenAvailable` silently degrades to
cleartext against a relay that does not advertise `STARTTLS`. On such a row the message body — and, when
the row carries a username, the **relay credential** — is transmitted unencrypted, and the send succeeds
while certificate revocation checking is at its secure default, because no certificate is presented,
requested or examined.

- Do not read that success as a bypass of the certificate controls. There is no certificate on this path
  for them to act on. Concluding otherwise sends the fix toward the certificate policy, which cannot
  help, and away from the transport configuration, which is the only thing that can.
- The platform applies no minimum-security floor to the column, so this is a deployment responsibility.
  On any row that carries a username, use `StartTls` or `SslOnConnect` — never `None`, and prefer
  `StartTls` over `StartTlsWhenAvailable` so a relay that stops advertising `STARTTLS` fails loudly
  instead of quietly downgrading.
- Verify it on the wire rather than from the configuration: a relay conversation that never issues
  `STARTTLS` and never establishes TLS is delivering in the clear regardless of what the row is
  intended to mean.

#### The environment marker

`WebVella.Erp.Site/web.config` sets `ASPNETCORE_ENVIRONMENT`, and it must be `Production` outside
development. What that actually changes is the error surface: it disables the developer exception
page, so the user-facing error page becomes the visible path — and that page must be verified to
render without leaking internal detail.

**One caveat matters more than the setting itself.** Flipping this marker does **not** fix the two
unconditional stack-trace responses in `WebVella.Erp.Web/Controllers/WebApiController.cs`, because
neither was guarded by any development-mode check. Those required a code change; see the
[security audit report](security-audit-report.md) for the finding.

Separately, all eight `Config.json` files set `"DevelopmentMode": "true"`, and all eight must be
`false`. That flag gates a distinct branch in `WebVella.Erp.Web/Controllers/ApiControllerBase.cs`
which returns richer error detail, so it is an information-disclosure switch and not merely a
convenience.

#### Rate limiting and the login lockout

- **Framework rate limiting** with a per-address fixed-window partition is registered in each host
  pipeline. It is a transport-level layer and it comes from the shared framework, so no package is
  added for it.
- **The login lockout threshold is five failed attempts**, taken literally from the engagement's
  authentication-hardening standard, and it is consulted at **both** of the platform's credential
  entry points — the interactive login page and the anonymous bearer-token route. Throttling only the
  login form would have left the token route as an unthrottled credential oracle.
- **State the limitation honestly:** the throttle is backed by the existing in-process cache
  (`WebVella.Erp.Web/Utils/Cache.cs`), so its protection is **per instance**. A multi-instance
  deployment behind a load balancer is not protected to the same degree, and a distributed backing
  store is recorded as a recommendation in the [risk register](risk-register.md) rather than a control
  in force. The throttle **fails closed** on cache eviction, so eviction cannot grant unlimited
  attempts.

### PostgreSQL is the only supported database

Data access is Npgsql-based throughout, so no in-memory or SQLite substitution is possible and any
verification that needs data must run against a real PostgreSQL instance.

No schema change was required by this remediation and **no schema definition statements were emitted
at any point.** The password column is already a 500-character variable-length string, which is why a
modern hash format fits without a migration. The only migration involved is a data-level one,
described in the [credential migration guide](credential-migration.md).

### The build gate

`Directory.Build.props` at the repository root turns an ordinary build into the combined
static-analysis and composition-analysis gate. It sets:

```text
NuGetAudit          true
NuGetAuditMode      all
NuGetAuditLevel     low
WarningsAsErrors    $(WarningsAsErrors);NU1900;NU1901;NU1902;NU1903;NU1904;NU1905
EnableNETAnalyzers  true
AnalysisLevel       latest-recommended
AnalysisLevelSecurity  latest-all
```

`NU1901`, `NU1902`, `NU1903` and `NU1904` are the dependency-audit diagnostics for low, moderate,
high and critical severity. **A dependency advisory therefore fails the build by design.** That is
the gate working, not a defect.

`NU1900` and `NU1905` are promoted alongside them for a different reason, and it matters: they are
not severities but *data-availability* diagnostics. `NU1900` is raised when the audit source cannot
be reached, `NU1905` when the configured source supplies no vulnerability data at all. Left as
warnings, either one produces the worst possible outcome for a gate — a build that exits `0` while
auditing nothing, with a known High advisory sitting in the graph unreported. Promoting them converts
"the audit could not run" into a failure instead of a silent pass. The disclosed trade-off is that a
transient outage of the advisory database now fails the build rather than passing it; that is the
correct direction for a security gate, and the failure text names the cause precisely.

One residual is stated plainly because the promotion does **not** close it: when the only configured
package source is a local folder mirror, the restore emits no `NU19xx` diagnostic whatsoever — there
is nothing to promote. That configuration is caught instead by the workflow's negative-control step,
which requires a project referencing a known-vulnerable package to *fail* the restore with `NU1903`
and fails the job when it does not. Neither mechanism is redundant with the other.

Several of these choices need their reasons recorded.

- **The audit mode covers transitive dependencies explicitly, not by default.** This graph really
  does contain a transitive advisory — MimeKit is reached only through MailKit — so a direct-only
  audit would never have reported `GHSA-g7hc-96xr-gvvx`. The default also varies by toolchain
  version, and a gate resting on a floating default is not reproducible.
- **The mechanism is MSBuild rather than a repository-root `.editorconfig`.** The four
  `.editorconfig` files in this repository each declare `root = true`, so a root editor-config would
  not reach any file inside the four subtrees that hold the code this remediation touches.
  `Directory.Build.props` is imported by every project regardless.
- **`global.json` pins the SDK** to `10.0.302` with `rollForward: latestPatch`, which is what the tree
  carries and what the file's frozen contract mandates. Both halves of this gate — the audit defaults
  and the analyzer rule set — are selected by the SDK **feature band**, and `latestPatch` holds the pin
  on the `10.0.3xx` band, so it delivers the reproducibility the finding asks for while still admitting
  a security patch of the SDK itself. A bare pin would accept a newer feature band and reintroduce
  non-reproducibility, so it is not a candidate. `disable` was considered and rejected on availability
  grounds: freezing to one exact patch makes the repository unbuildable for every developer and for CI
  the moment that patch is superseded, which breaks the *all existing functionality remains operational*
  preservation requirement in exchange for a guarantee the feature band already gives. When no SDK on
  the band is installed at all, `latestPatch` still fails with an actionable message naming the required
  version.
- **Bulk analyzer diagnostics remain warnings; an enumerated security subset does not.** Only the six
  dependency codes and the ten security rules listed below are errors. Promoting roughly 700 source
  files' worth of pre-existing analyzer warnings wholesale would demand exactly the mass refactor the
  change scope forbids, so the general `CA` backlog stays at warning severity.

#### What the static-analysis gate covers

An earlier revision of this document stated that the hard-coded-key, initialisation-vector, query-
construction, deserialisation, cookie-security and token-validation rule families **could not** be
activated, on the premise that per-rule severities had no way to reach the repository root past the
four `.editorconfig` files that declare `root = true`. **That premise was wrong, and the gap it
described is now closed.** The retraction is recorded here rather than quietly overwritten.

Per-rule severities are delivered by a repository-root **`.globalconfig`**. That file is discovered
automatically by the SDK — `Roslyn/Microsoft.Managed.Core.targets` includes `.globalconfig` from
`@(_AllDirectoriesAbove)` unless `DiscoverGlobalAnalyzerConfigFiles` is false — and global analyzer
configuration is **not** subject to `.editorconfig`'s `root = true` scoping. `Directory.Build.props`
sets `DiscoverGlobalAnalyzerConfigFiles` to `true` explicitly so the behaviour is stated rather than
inherited silently.

> **Do not also list the file in `<GlobalAnalyzerConfigFiles>`.** Adding an explicit include for a
> file the SDK already auto-discovers produces `MultipleGlobalAnalyzerKeys` and **silently unsets
> every key in it**, disabling the whole gate while the build still succeeds. This was reproduced
> during setup; it is the single most dangerous way to configure this file.

Ten rules are **errors**, each measured at zero occurrences in the tree, so each is a ratchet that
fails the build on the first new violation:

`CA2327` insecure `TypeNameHandling` · `CA5350` weak hashing · `CA5359` disabled certificate
validation · `CA5364` deprecated protocols · `CA5382`/`CA5383` cookie `Secure` attribute ·
`CA5390` hard-coded encryption key · `CA5401`/`CA5402` non-random initialisation vector ·
`CA5404` disabled token-validation check.

Five rules carry a **pre-existing population** and are therefore held at warning severity against an
enumerated baseline, which continuous integration asserts does not increase:

| Rule | Baseline | What it covers |
| --- | --- | --- |
| `CA2100` | 20 | Query construction from a non-constant string |
| `CA2326` | 20 | `TypeNameHandling` other than `None` |
| `CA2328` | 9 | Possibly-insecure `JsonSerializerSettings` |
| `CA5351` | 5 | Broken hashing algorithm — the retained legacy credential path |
| `CA5362` | 1 | Potential reference cycle in a deserialized object graph — the self-referential `SubQueries` collection at `WebVella.Erp/Api/Models/QueryObject.cs` |

**All 55 of those sites are pre-existing and none falls inside a remediation hunk.** They were made
*visible* by this change, not introduced by it, which is why the solution warning count rose from
3,047 to 3,096.

That total is the raw build figure. Deduplicated per unique file, line and diagnostic code — which is
how the CI ratchet counts, because a parallel build emits each diagnostic once per MSBuild node — the
same comparison against the pre-remediation baseline reads **2,937 to 2,968, a rise of 31**. The two
numbers agree: the 31 is the deliberate +49 above, less the 18 diagnostics that earlier classes
cleared. Deduplication is not cosmetic here; counting raw log lines double-counts every diagnostic and
would have made a clean tree appear to fail its own ratchet.

One measurement is worth stating on its own: **`CA2327` reports zero while `CA2326` reports twenty.**
`CA2326` flags every site that enables polymorphic type handling; `CA2327` flags only those that do so
*without* a serialization binder. Zero against twenty is machine-checked proof that the type
allow-list binder is attached at every polymorphic site in the repository.

##### The whole Security category is active, and the one measured limit inside it

The fifteen rules named above are the ones this repository sets a severity for. They are not the whole
gate. `AnalysisLevelSecurity=latest-all` in `Directory.Build.props` raises the **Security category alone**
to every rule the pinned SDK defines in it - **94** rules - while `AnalysisLevel` stays at
`latest-recommended` for every other category, so the security signal is not buried under the legacy
backlog. That is what brings the families `latest-recommended` omits into scope: hard-coded keys and
initialisation vectors, SQL and query construction, insecure deserialisation, cross-site scripting and
file canonicalisation, regular-expression injection, cookie security, and disabled token-validation
checks.

The gate derives that rule list from the SDK at run time rather than hard-coding it, and publishes it as
`security-rule-ids.txt`. A **positive control** runs alongside it: a throwaway project inside the
repository root, inheriting the real properties, hard-codes a symmetric key and concatenates a
`CommandText`. Both `CA5390` and `CA2100` must be reported and the job fails if either is absent.
`CA5390` is **not** enabled at `latest-recommended`, so its presence proves the category upgrade
specifically rather than merely that some analyzer ran. Two details of that control matter, because
getting either wrong turns it from a proof into a permanent false alarm. `CA5390` is promoted to
**error** in `.globalconfig`, so the probe build *fails on purpose*: the control reads the diagnostic
out of the build log and deliberately ignores the exit status. And it matches `error` as well as
`warning`, because the severity is set per rule — a control keyed to `warning` alone would fail to see
its own planted defect and would report the gate broken on every clean run.

**The one measured limit is inside the taint family, not around it.** `CA3001`-`CA3012` are enabled, but
with a per-rule `interprocedural_analysis_kind = None` option in `.globalconfig`. A tainted value that
enters one method and reaches a sink in **another** is not followed; a flow contained within a single
method is. This is a cost decision established by measurement, not an omission: with interprocedural
analysis left on, the whole-solution build exceeded 2,400 s without completing and the Roslyn compiler
server began failing under memory load, against 370-530 s tuned. The tuning sets an *option* only - never
a severity, never a suppression - so no rule is silenced and no file is excluded, and a probe confirmed
`CA3001`, `CA3003` and `CA3012` fire identically with and without it. The residual is recorded as
`RISK-035`.

An earlier revision of this guide stated that the dataflow families were *not* active and that the
absence of a `CA5390` or `CA3002` diagnostic therefore carried no assurance. That was true of
`AnalysisLevel=latest-recommended` alone, and it is exactly why the category level was added: a
static-analysis gate that does not run the rules corresponding to the audit's own findings is not a gate.

**What a clean run does and does not assert.** It asserts that no Security-category rule reported anything
outside a reviewed allow-list, across all 19 projects - a real and enforced claim. It does **not** assert
that no cross-method taint flow exists, because of the interprocedural limit above. And it does not
retrospectively validate the manual audit: the original findings were identified by review, and the
analyzers are a regression guard against their return rather than the instrument that found them.

**Diagnostics stay warnings at the project level; the security pass criterion is enforced in the workflow
instead.** Promoting roughly 3,100 pre-existing `CA*` diagnostics to errors would demand exactly the mass
refactor the change scope forbids, so at the project level only the NuGet audit codes are errors, plus the
ten security rules measured at zero which are promoted individually in `.globalconfig`. On top of that,
the workflow's Gate 1 step parses the analyzer log, extracts every Security-category diagnostic and fails
the job on any that is not in an inline, individually justified allow-list. That is a narrower and more
reviewable claim than "zero diagnostics repository-wide": **zero *unreviewed* Security-category
diagnostics.** The allow-list holds the `(rule, file)` pairs for `CA2100` on the fully parameterised data
layer, `CA2326`/`CA2328` on the polymorphic payload sites that already attach `ErpSerializationBinder`,
`CA5351` on the retained legacy verification path, and `CA5362` on the recursive query-tree model - each
with its justification recorded in the [risk register](risk-register.md).

Reproduce the gate locally with:

```bash
dotnet restore WebVella.ERP3.sln
dotnet build WebVella.ERP3.sln -c Debug
dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive
```

Two limits on that output must be understood rather than assumed away.

- **The project-reference path casing repair must be in place first.** Until it was, a solution-wide
  restore failed on a case-sensitive filesystem and the core project — the one that owned the graph's
  only High-severity advisory — was silently absent from the audit. A clean result obtained before
  that repair meant nothing at all.
- **A solution-level command used to reach 17 projects, not 19. That limit is now closed.**
  `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` were not solution members,
  so a solution-scoped audit silently skipped them. They are members now, and a single
  `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` enumerates all 19 —
  including both — each reporting no vulnerable packages. The per-project commands that this section
  previously described as **required** are no longer required; they still work, and are harmless.

  Two clarifications, because this history is easy to read backwards. First, membership never
  affected the gate itself: `Directory.Build.props` is inherited by directory location, so both
  projects always carried all six audit properties and, now, the ruleset. What membership affected
  was **command coverage** — which projects one invocation visits. Second, the enrolment was added,
  reverted on scope grounds, and then restored when the cumulative review superseded that judgement;
  the change is twelve added lines in the solution file and nothing removed. A workflow step now
  compares `dotnet sln list` against `git ls-files '*.csproj'` and fails if any tracked project is
  not a member, so the coverage cannot silently regress. Verify it yourself:

```bash
dotnet sln list | grep -c '\.csproj$'      # 19
git ls-files '*.csproj' | wc -l            # 19
```

  Both are clean, and both inherit the same gate properties through `Directory.Build.props`.

  **The continuous gate now runs these commands for you, and proves it covers everything.** A job that
  only restored the solution would never look at these two projects, and for a period this one did not —
  that was finding `CI-01`. Both are solution members now, so the solution-level restore, build and
  advisory listing reach all 19 on their own, and a dedicated step compares `dotnet sln list` against
  `git ls-files '*.csproj'` and fails the job if any tracked project ever stops being a member. Coverage
  is therefore a *checked property of each run* rather than a claim in a comment that can drift from the
  workflow beneath it.

  The workflow still builds those two projects individually, one project per `dotnet build` invocation
  (two project arguments fail `MSB1008`), for one reason solution membership does not supply: those steps
  assert each project's **`TargetFramework`**, which is the only continuous check on finding H-18. A
  green solution build cannot rule out an out-of-support target, so the assertion has to read the
  property itself. Two details keep those steps a real gate rather than a formality. Their build output
  is **appended to the same analyzer log the SAST gate parses**, so they sit inside Gate 1 rather than
  beside it. And their advisory listing is asserted on its *output* — any `High` or `Critical` row fails
  the job, and a listing command that itself fails is treated as a failure rather than as an absence of
  findings — because `dotnet list package --vulnerable` exits 0 even when it prints advisories.

  One distinction used to be worth keeping sharp here, and it is now obsolete — recorded rather than
  quietly deleted, because an operator who read the earlier revision needs to know it was superseded. That
  revision warned that **a green solution-level command covers only 17 of the repository's 19 projects, so
  any claim that one command covers all 19 is false.** That was true before the two WebAssembly projects
  were enrolled; it is false now. `dotnet restore WebVella.ERP3.sln` and
  `dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` cover **all 19**. The
  per-project commands above are still worth running to confirm each target framework by hand, but they
  are no longer required to reach full coverage.

  The residual that prompted `RISK-030` in the [risk register](risk-register.md) — that the two projects
  were gated only individually, so a defect appearing solely when all 19 resolved together in one graph
  would go uncaught — is closed by that enrolment: they now resolve inside the same solution graph as the
  other 17.

One open decision sits on top of this gate, and its two halves must not be confused. With the
dependency codes promoted to errors a build cannot be green while a vulnerable package remains, so
the object-mapping library **has** been moved to the lowest patched version, `[15.1.3]`. The advisory
is therefore **closed** and the dependency gate is green. The consequence of that move — every version
patching the advisory is licensed under the Reciprocal Public License 1.5, while the product declares
Apache-2.0 and publishes to nuget.org — is now **decided and recorded** rather than left hanging:
`RISK-001` keeps `[15.1.3]` and accepts the reciprocal obligation as a residual. There is no patched
permissive release to retreat to, and the reversal path would require a repository-wide `NU1903`
suppression that the CI negative-control probe also inherits, which would disable the only proof that
the dependency gate can fail. **Nothing here needs an operator decision.** One bounded item awaits owner ratification — the licence
expression declared on the published packages — and it does not affect how you configure or run the
platform. The full reasoning, and the reversal path, are in
`RISK-001` in the [risk register](risk-register.md).

### Login latency after the credential change

The credential hash uses a deliberately expensive key-derivation function. **Login becomes measurably
slower, by design** — the cost is the control. It is a pre-declared and accepted exception to the
engagement's ten-per-cent performance boundary, and it is **confined to the authentication path**; no
other request path is affected. Expect it and do not treat it as a regression. The measurement and
the acceptance are recorded in the [remediation log](remediation-log.md), and the migration itself in
the [credential migration guide](credential-migration.md).

### Related documents

- [Security audit report](security-audit-report.md) — the findings, in the mandated eight-field format.
- [Remediation log](remediation-log.md) — what changed, per vulnerability class, with verification.
- [Risk register](risk-register.md) — accepted risks, open decisions and residual exposure.
- [Credential migration guide](credential-migration.md) — how stored credentials are upgraded.
- [Third-party library inventory](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) — dependency versions and licences.
- [Security policy](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) — how to report a vulnerability.


## Headers, transport, cookies, tokens, rate limiting and open items

Operator guidance for running WebVella ERP securely. This document covers what you must supply, what the platform refuses to do without it, and what each hardening control actually does at runtime.

It is written for whoever deploys and operates the platform. Developer-facing detail about *why* each control was chosen is in [the remediation log](remediation-log.md); accepted risks and their reasoning are in [the risk register](risk-register.md).

Every behaviour described here is the behaviour of the code as it now stands, not an aspiration.

### 1. Required secrets

Three configuration values must be supplied by you.

**Read this before anything else in this section.** This passage was written while the shipped
`Config.json` files still contained development values, and it has since been overtaken: all eight
files now carry **empty** secret values and `"DevelopmentMode": "false"`, `web.config` sets
`Production`, and `RISK-021` is closed for the tracked files. Every value that ever appeared in those
files remains public in this repository's **history**, so it must still be treated as compromised —
that residual is `RISK-026` in [the risk register](risk-register.md).

What *is* already in force is the layer that makes those values unusable in a deployment:

* **The known published key material is rejected**, not trusted. Supplying the shipped signing key is
  equivalent to supplying none, so the bearer-token routes disable themselves rather than signing with
  a key an attacker also holds.
* **There is no fall-back to a compiled-in default** for the encryption key.
* **Environment variables override the file**, so you can supply real values without editing any
  tracked file.

Treat every value currently in those files as public knowledge, and override all three.

| Value | Environment variable | Consequence if missing or unacceptable |
|---|---|---|
| Database connection string | `Settings__ConnectionString` | The application cannot reach its database and fails at start-up with an actionable message |
| Encryption key | `Settings__EncryptionKey` | Rejected at start-up outside Development; a warning in Development |
| JWT signing key | `Settings__Jwt__Key` | **The bearer-token routes disable themselves.** Cookie login continues to work |

**The double underscore is configuration nesting, not a typo.** `Settings__Jwt__Key` maps to the `Settings:Jwt:Key` path, which in the JSON file is `{ "Settings": { "Jwt": { "Key": ... } } }`. This is the standard .NET environment-variable convention and is what makes it possible to override a nested JSON value without editing the file.

```bash
export Settings__ConnectionString='Host=...;Database=...;Username=...;Password=...'
export Settings__EncryptionKey='<32+ characters from your secret store>'
export Settings__Jwt__Key='<32+ bytes of high-entropy material>'
```

#### Where configuration comes from, and in what order

Configuration is assembled at **four** builder sites: the shared platform extension `WebVella.Erp.Web/ErpMvcExtensions.cs`, the console application `WebVella.Erp.ConsoleApp/Program.cs`, and two hosts that build their own - `WebVella.Erp.Site/Startup.cs` and `WebVella.Erp.Site.Project/Startup.cs`. The remaining five hosts inherit the shared extension's chain rather than declaring their own.

At every one of those four sites the order is:

1. The JSON configuration file — `Config.json`, that exact spelling, resolved from `AppContext.BaseDirectory`. There is no lower-case alternative and no fallback: the file is registered non-optional, so a mismatch is a startup failure rather than a silent empty configuration.
2. **Environment variables.**
3. User secrets, in Development only.

Environment variables come **after** the file deliberately, because later providers win. That is what lets you override a shipped placeholder without editing a tracked file, and it is why scrubbing the file of live secrets was safe: there is now a supply channel that does not involve committing anything.

The JSON file source is **not optional**. Deleting `Config.json` breaks start-up outright; it must be present, with its secret values blank, rather than removed.

#### Why a published key is treated as no key at all

Both the encryption key and the JWT signing key are checked for **shape and for known-published-default status**, not merely for being non-blank:

* A minimum length is enforced - 32 bytes for the signing key, 32 characters for the encryption key.
* A minimum number of distinct characters is required, so a long repetitive string such as `aaaaaaaa...` is rejected. Length alone is not entropy.
* The two values that have been published in this repository's history are rejected by **SHA-256 digest comparison**. The digests are stored rather than the literals, so this document and the source do not reintroduce the secrets they are trying to eliminate.

The check is **staged**: in Development it warns so that an existing developer checkout still starts, and outside Development it fails closed. Start-up is never aborted by a hard crash where a clean refusal at the point of use is possible - the intent is an actionable message, not an unexplained boot failure.

#### The bearer-token routes disable themselves - by design

If `Settings__Jwt__Key` is absent or unacceptable, the token issue and refresh routes **refuse cleanly** and the `AddJwtBearer` registration is screened so it can neither use nor throw on the bad key. The authentication *scheme* still exists, because the platform's policy selector forwards `Authorization: Bearer` headers to it; it is configured without a signing key while still validating signatures, so every presented token fails validation safely.

This is a deliberate, visible behaviour change and it is the correct outcome. The key previously shipped in `Config.json` is public. Anyone holding it could mint a token for any user, including an administrator. A token endpoint that signs with a public key is worse than no token endpoint. Supplying a real key re-enables both routes with no other change.

Cookie-based login is unaffected either way.

### 2. Response headers

`SecurityHeadersMiddleware` emits the mandated header set on **every** response - dynamic pages, static assets, and error responses alike:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

Six of the seven are emitted in **every** environment. `Strict-Transport-Security` is the exception: the middleware suppresses it when the environment is `Development`, so that a developer who loads the app once over `https://localhost` is not pinned to HTTPS for the entire `localhost` origin - which is shared with every other locally served project - for a full year. Outside `Development` all seven are present unconditionally, including behind a TLS-terminating reverse proxy that forwards plaintext, because the guard tests the environment rather than the request scheme. Expect to observe six headers on a development machine and seven on a deployed one; that difference is deliberate, not a gap.

`X-XSS-Protection: 0` is not an oversight. The legacy XSS auditor it disables has been removed from modern browsers and, while it existed, was itself exploitable; explicitly disabling it is current guidance.

The middleware is registered once in the shared platform extension and inserted **early** in each of the seven host pipelines - ahead of response compression and ahead of both static-file middlewares. Ordering is the whole point: registered late, the headers would be absent from exactly the responses most likely to carry attacker-controlled bytes. Verify on both a dynamic page and a static asset.

#### Content-Security-Policy ships in report-only mode

The policy value above is exactly what the audit requires, and it is emitted verbatim. What is staged is the **delivery mode**: it ships as `Content-Security-Policy-Report-Only` so violations are reported without being blocked.

This is not a weakening of the policy. Enforcing `script-src 'self'; style-src 'self'` today would break the interface, because the application and its vendored front-end libraries emit inline script and inline style. The report-only stage exists to enumerate exactly what must change first, and it has already produced that inventory.

**There is no `report-uri` directive and no collection endpoint.** An earlier revision added both; both were removed, for two independent reasons that each apply on their own.

First, the audit specifies the policy value exactly, and appending `; report-uri /csp-violation-report` meant the header no longer matched it. A header that has been extended is not the header that was mandated, and the mandated value is the acceptance criterion.

Second, and more seriously, the collector was handled inside the middleware ahead of routing, which meant the middleware acquired a request path that returned a response **without attaching the other six headers**. A control whose own instrumentation opens a hole through the control is worse than no instrumentation. Deleting the collector did not merely re-order that branch — it removed the branch, so there is now exactly one path through the middleware and it always attaches all seven headers.

Collect violations from the **browser console** during the rollout instead. Every modern browser logs a report-only violation there with the blocked URI and the violated directive, which is the same information the endpoint recorded, without adding an anonymous write-accepting route to the application. If a deployment later wants aggregation, terminate `report-to` at the reverse proxy or a dedicated collector service rather than inside this middleware — that keeps the header-attachment path single and unconditional.

#### What currently blocks enforcement

Measured from real violation reports, not predicted. Enforcing the policy as written would break all of the following:

| Violation class | Source | Directive needed |
|---|---|---|
| Inline `<style>` and `style=` attributes | Application pages, and the `wv-lazyload`/Stencil bundle | `style-src` allowance |
| Inline `<script>` blocks | Application pages; the by-design script-emitting components | `script-src` allowance |
| `eval` | CKEditor 5, and the Stencil loader | `script-src 'unsafe-eval'` |
| **A 1×1 GIF spacer as a `data:` URI** | ASP.NET Core framework markup | **`img-src 'self' data:`** |
| **A `blob:` worker** | The Ace source editor's syntax worker | **`worker-src blob:`** |

The last two matter disproportionately: **the mandated policy does not mention `img-src` or `worker-src` at all**, so both fall through to `default-src 'self'` and are blocked. Any enforcement plan that only reasons about `script-src` and `style-src` will break images and the code editor on the first deployment.

The inline-emitting surface is also **wider than the four components originally identified**. In addition to the HTML-block component and the two script-emitting components, real reports implicate CKEditor 5, the `wv-lazyload`/Stencil bundle (inline style *and* `eval`), and the Ace editor. Enforcement is a project of its own, not a configuration flip.

The route from here to enforcement:

1. Leave report-only on and collect from real usage across all hosts.
2. Work through the inventory above - move inline blocks to files, or adopt nonces or hashes.
3. Add the missing `img-src` and `worker-src` directives, which are required regardless.
4. Switch to enforcing mode **per host**, not globally, and watch the reports.

**Who owns the promotion, and when it is allowed to happen.** The four steps above describe the work;
they deliberately do not authorise it. Promotion to enforcement is governed, and the governance is
recorded once in [the risk register](risk-register.md) under `RISK-022` so that the criteria cannot
drift between documents. In summary:

- **Owner:** the **application security owner** for the platform, jointly with the **frontend
  maintainer** for the plugin and tag-helper surfaces. It is not an infrastructure flag flip, because
  clearing the backlog means editing components - which is why it is not owned by whoever last touched
  the middleware.
- **Quantitative threshold:** **zero** report-only violations attributable to first-party code, over a
  **14-consecutive-day** window, across **all seven hosts**. Zero rather than a percentage reduction,
  because one surviving inline script breaks the interface the moment the header name changes, so a
  99 %-clear backlog behaves identically to an untouched one. Violations from browser extensions or
  operator-injected third-party markup are excluded but must be individually listed and justified in
  the promotion record, never silently discounted.
- **Measured starting position:** a single authenticated session produced at least **379** violations;
  one page context alone accounted for **137**, split **132 inline-style, 3 inline-script, 2 `eval`**.
  Address `style-src` first - it dominates by an order of magnitude.
- **Stage exit conditions:** each of the five stages in `RISK-022` has an observable exit condition, and
  no stage may be skipped.
- **If enforcement is declined,** it is *formally deferred* and recorded with a date and rationale, not
  left quietly pending.

**And state this plainly to anyone reading a status summary: report-only is not the remediation for
`H-06`.** The stored cross-site-scripting finding is remediated in the view and builder layer - text
sinks encoded, and every retained by-design markup channel enumerated in `RISK-023` and `RISK-032`. A
report-only policy is **detective, not preventive**: the browser reports the violation and then runs
the script anyway. So it closes nothing on its own, and it must never be cited as evidence that `H-06`
is covered. Cite the encoding work and those two risk entries instead.

### 3. Transport security

`UseHsts` and `UseHttpsRedirection` are added to all seven hosts, **guarded to non-Development environments** and ordered HSTS first.

Two ordering constraints are load-bearing:

* They are placed **after** the CORS middleware. HTTPS redirection responds to a cross-origin preflight with a redirect, which browsers reject as an invalid preflight response; putting redirection ahead of CORS breaks every cross-origin client.
* The Development guard exists because HSTS is sticky. A browser that receives `Strict-Transport-Security` for `localhost` will refuse plaintext `http://localhost` afterwards, which is a genuinely painful state to clear on a developer machine.

Terminate TLS in front of the application. The platform issues HSTS unconditionally outside Development; it redirects plaintext **only when an HTTPS port is discoverable** (see the measured caveat under *HSTS and HTTPS redirection* above), and it does not manage certificates.

### 4. Cookies and session lifetime

Cookie authentication is configured identically across all seven hosts:

| Setting | Value | Reason |
|---|---|---|
| `SecurePolicy` | **`Always`, in every environment** — no Development carve-out | The cookie must never traverse plaintext. An earlier revision relaxed this to `SameAsRequest` in Development so that `http://localhost` kept working; that relaxation *was* the vulnerability (CWE-614), because `ASPNETCORE_ENVIRONMENT` is ambient — a deployment that inherits `Development` from a shell profile, a container image or a stale `web.config` silently stops marking the session cookie `Secure`, and the one signal that something is wrong is the same signal that is now suppressed. Local development uses the HTTPS profile, which the platform already ships with a development certificate |
| `SameSite` | `Lax` | `Strict` breaks the return-URL round trip through the login page. `Lax` is the framework's documented default posture |
| `ExpireTimeSpan` | **1440 minutes (24 hours)** | The **idle** window: a session that sees no activity for 24 hours ends |
| `SlidingExpiration` | **`true`** | Activity slides the idle window forward. Safe *only* because of the absolute horizon described below - see the warning |
| `AllowRefresh` | **`true`** | Required for sliding renewal to function at all |
| `HttpOnly` | `true` | Script cannot read the ticket |

All seven hosts obtain these values from a **single** shared configurator, `ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie`, so the seven hosts cannot drift apart.

> **Operators: `SecurePolicy` is `Always` even in Development.** Sign-in therefore works only over HTTPS. Running a host over plain `http://localhost` will appear to accept your credentials and then bounce you back to the login page, because the browser refuses to store the cookie. This is expected; use the HTTPS endpoint.

#### A configuration incoherence that was fixed

All seven hosts declared `ExpireTimeSpan = 8h`, but the authentication ticket was constructed with an **explicit `ExpiresUtc` of 24 hours**, and an explicit `ExpiresUtc` *overrides* `ExpireTimeSpan`. The real lifetime was therefore 24 hours - three times what every host declared - and seven hosts' configuration was inert.

Both halves are now aligned at **1440 minutes**: `ExpireTimeSpan` in the shared configurator and `AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES` on the ticket. The declared value and the effective value agree, and the agreed value is the *idle* window rather than an absolute one.

#### Sliding expiration, and why it is not an indefinite session

Sliding expiration alone would be a regression, not a fix: a stolen cookie that is used at least once every 24 hours would renew **forever**. It is safe here only because it is paired with a hard ceiling.

At authentication, the ticket is stamped with an absolute expiry in the item `wv_session_absolute_expiry`, set to **10080 minutes (7 days)** after issue. A `OnValidatePrincipal` handler, `AuthService.ValidateSessionHorizonAsync`, rejects any ticket presented past that stamp. Because the stamp lives inside the encrypted, signed ticket payload and the renewal path rewrites only `IssuedUtc` and `ExpiresUtc`, sliding renewal **cannot** push the horizon outward. Worst-case exposure from a stolen cookie is therefore 7 days, not unbounded.

Seven days deliberately matches the bearer-token horizon in section 5, so a cookie session and a bearer session expire on the same schedule.

Tickets issued *before* this change carried `AllowRefresh = false`, and the renewal path requires the ticket's own `AllowRefresh`. They therefore cannot slide at all and remain bounded by the `ExpiresUtc` they were issued with. They are deliberately **not** rejected outright, because that would sign out every currently active user on deployment.

**The idle bound is invisible at the HTTP layer, and that is expected.** Because the ticket is not persistent (`IsPersistent = false`), the cookie is a session cookie with no `expires` or `max-age` attribute; both the idle window and the horizon live inside the encrypted ticket payload. Do not try to verify them by reading response headers - decrypt the ticket instead. One related trap: the login redirect carries a top-level `expires: Thu, 01 Jan 1970 ...` header, which is a **cache** header and not a cookie attribute - it says nothing about session lifetime.

### 5. Tokens: the absolute session horizon

Bearer tokens carry a **7-day absolute session horizon**, stamped at issue and carried verbatim across every refresh. Refresh past the horizon is refused, and a refreshed token's expiry is capped at the horizon rather than extending beyond it.

Before this, an anonymous refresh endpoint would renew a stolen token indefinitely: the token never had to expire, so a single theft was permanent. The horizon reduces worst-case exposure from **unbounded to at most 7 days with no operator action required**.

**What is not implemented, stated plainly:** there is no revocation list and no refresh-token rotation. Both require persisting issued or revoked token identifiers - a database schema change, which the audit's own constraints forbid. The honest consequences:

* Signing out clears the cookie; it does **not** invalidate an already-issued bearer token.
* A stolen token stays usable until the earlier of its own expiry and the 7-day horizon.

Recommended future work, recorded in [the risk register](risk-register.md): a revocable refresh-token table with rotation and reuse detection, plus a `jti` denylist.

### 6. Rate limiting and login throttling

Two independent layers, both from the shared framework or in-process primitives - no new dependency and no schema change.

**Transport-level rate limiting** is a per-remote-address fixed window of **600 requests per minute**, positioned so static assets are not throttled. A single page load pulls many assets; a limit that counts them starves legitimate users long before it inconveniences an attacker.

**Login throttling** is enforced by `LoginThrottleService` with **two independent counters**:

| Counter | Threshold | Window |
|---|---|---|
| Per account | 5 failed attempts | 15 minutes |
| Per source address | 25 failed attempts | 15 minutes |

The counters are independent on purpose. A single composite key would let an attacker reset an account's failure count by rotating source address, and would let one noisy address exhaust an innocent account's budget. The address threshold is deliberately **five times** the account threshold, because NAT and shared corporate egress mean many legitimate users can share one address; a threshold equal to the account limit would lock out an entire office because of one user's typo.

Both credential-verification surfaces are throttled: the login page **and** the anonymous bearer-token route. The token route was a second entry point that an earlier analysis had missed - throttling only the login form would have left a fully unthrottled credential oracle exposed.

Failure registration is atomic - attempts are reserved before verification and finalised after - so concurrent requests cannot each pass the check before any of them records a failure.

Three limitations, stated rather than buried:

* **The store is in-process.** In a multi-instance or load-balanced deployment each instance counts independently, so effective thresholds multiply by the instance count. A distributed backing store is a recorded recommendation, deliberately not built. If you run more than one instance, enforce throttling at the load balancer as well.
* **Account lockout is a denial-of-service primitive**, which is why it lapses automatically after 15 minutes rather than requiring an administrator to clear it. An attacker can lock a known account for 15 minutes; that is a deliberate trade against making credential stuffing cheap.
* **The store is size-bounded** to cap memory against an attacker varying the username. Displacing a specific account's partial count requires cycling the entire store, which buys at most a few extra guesses.

Counters are held in memory, so **restarting the application clears all lockouts** - useful during testing.

### 7. Environment and error handling

Set the environment to **`Production`** for any installation reachable by untrusted users.

* `WebVella.Erp.Site/web.config` forces `ASPNETCORE_ENVIRONMENT=Development`, which enables the
  developer exception page - a full stack trace on any unhandled error. **Override it.**
* **The shipped `Config.json` files now set `"DevelopmentMode": "false"`**, and
  `WebVella.Erp.Site/web.config` now sets `Production`. Both were corrected in the tracked files
  (`RISK-021`, closed). Verify the effective values in your own deployment anyway, since either can be
  overridden by an environment variable that outranks the file.

Development mode still suppresses HSTS and HTTPS redirection, so leaving it on disables transport controls described in this document. It no longer affects the cookie `SecurePolicy`, which is now `Always` unconditionally.

### 8. Items formerly open, now closed

Both items previously recorded here have been remediated. They are kept, with their original text
retracted rather than deleted, because an operator who read the earlier revision may have deployed a
reverse-proxy compensation that is no longer required.

* **~~Two hosts still serve a permissive `Access-Control-Allow-Origin: *`.~~ Closed.** Both
  `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` now use an explicit origin allow-list. Each host
  reuses the origin list recorded in its **own** commented-out policy, so the two lists deliberately
  differ: `WebVella.Erp.Site` allows three origins, and `WebVella.Erp.Site.Project` allows four —
  it additionally allows `http://localhost:2202`. The other five hosts were already restrictive and
  were not touched.

  Verified against a running `WebVella.Erp.Site.Project` host: all four listed origins are echoed back
  in `Access-Control-Allow-Origin`, and four unlisted origins — including a wholly external one and the
  literal `null` origin — receive **no** `Access-Control-Allow-Origin` at all. `AllowCredentials()` is
  deliberately **not** added: the framework rejects it alongside `AllowAnyOrigin`, so credentialed
  cross-origin requests were never actually permitted, and adding it now would widen behaviour rather
  than preserve it.

  **The reverse-proxy compensation the earlier revision advised is no longer necessary**, though it
  remains harmless as defence in depth.

  One ordering property is load-bearing and was verified rather than assumed: the CORS middleware sits
  **before** HTTPS redirection. A cross-origin preflight over plaintext is therefore answered by CORS
  with `204` and **no** `Location` header, while a non-preflight plaintext request to the same host
  still receives `307`. Redirection is genuinely active *and* preflight is not broken by it. Moving
  `UseCors` after redirection reintroduces the documented invalid-preflight failure.

* **~~Two error paths return stack traces unconditionally.~~ Closed.** Both bearer-token routes now
  log the exception server-side through `LogService` and return a generic message to the caller. The
  failure message is deliberately identical whether the account exists or not, so it cannot be used as
  an account-existence oracle. Detailed exception text is emitted only when `DevelopmentMode` is
  explicitly enabled, and every shipped configuration file sets that key to
  `false`.

  Scope, stated precisely: ten *other* controller actions still concatenate `e.Message + e.StackTrace`
  into a response. Those are pre-existing, sit behind class-level authorization rather than on an
  anonymous route, and are outside the agreed change scope — which covers only the two
  **unconditional, anonymously reachable** token sites. They are recorded in
  [the risk register](risk-register.md). Setting `Production` does not suppress them, so continue to
  treat authenticated API error bodies as potentially verbose.

### 9. Verifying a deployment

**Read this before running anything below.** The checks split into two groups, and they must not be
run in the same way. An earlier revision of this section presented all of them as a single block of
"verify your deployment" commands, which was wrong: several of them *change state*. Running those
against production would lock out a real account, write real audit records, and — for the
authorization checks — require a real guest-role principal to exist. The split is therefore not
pedantry; it is the difference between a safe check and a self-inflicted outage.

#### 9a. Read-only checks — safe against any environment, including production

These issue `HEAD`/`GET` requests and change nothing.

```bash
# 1. All seven headers, on a dynamic response AND on a static asset.
curl -sI https://your-host/ | grep -iE 'content-security-policy|strict-transport|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy'
curl -sI https://your-host/_content/WebVella.TagHelpers/lib/toastr/toastr.min.css | grep -ic 'content-security-policy'

# 2. CSP must be report-only at this stage - and the enforcing header must be ABSENT.
curl -sI https://your-host/ | grep -i 'content-security-policy-report-only'
curl -sI https://your-host/ | grep -ic '^content-security-policy:'   # must print 0

# 2a. The enforcement switch must be reachable without a rebuild. Restart the host with
#     SecurityHeaders__ContentSecurityPolicyReportOnly=false and the header name must change to the
#     enforcing form, with the identical value. Note the polarity: the bound setting is the
#     REPORT-ONLY flag, so `false` enforces. Remove the setting and restart to go back to
#     report-only. A value that is present but not a boolean aborts startup by design.
curl -sI https://your-host/ | grep -iE '^content-security-policy(-report-only)?:'

# 2b. There is nothing to probe here, deliberately. An earlier revision of this block listed four
#     curl calls against a /csp-violation-report collector route, expecting 405/204/403/429. That
#     route was removed: the policy is delivered report-only for the browser console alone and the
#     application registers no report endpoint and no report-uri/report-to directive, so those four
#     checks would exercise a surface that does not exist. Assert its absence instead. Note that a
#     plain grep for the path string returns 1, not 0: the middleware keeps a comment recording why
#     the directive and the collector were removed. Assert on live code and on the wire instead.
grep -c 'HandleViolationReport' WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs  # 0, no collector
curl -sI https://your-host/ | grep -i '^content-security-policy' | grep -c report         # 0, no report directive

# 3. Plaintext must redirect, and HSTS must be present outside Development.
curl -sI http://your-host/ | head -1
```

#### 9b. State-changing checks — **staging only**

> **Run these only against a staging or pre-production instance that you can afford to disturb, and
> never against production.** Every check in this group mutates server-side state: the token route
> writes a `LogService` record and consumes a throttle slot, and the throttle check deliberately
> drives an account into lockout. There is no read-only equivalent, because what is being verified
> *is* the state change.

Preconditions, all four of which are required:

* **An isolated instance.** A staging deployment with its own database and its own process. The login
  throttle is backed by an in-process cache, so a shared instance would leak lockout state between
  testers, and clearing it requires a process restart you must be free to perform.
* **A dedicated throwaway account.** Create an account that exists only for this check — never a real
  user's, and never the administrator's. It will end the check locked out.
* **A recoverable database.** Take a backup, or run the instance against a database you can recreate
  from provisioning. The authorization checks below need a guest-role principal, and creating one is
  itself a state change.
* **A cleanup step you have planned in advance.** See the checklist after the commands.

```bash
# 4. The token route must refuse cleanly when no signing key is configured,
#    and must not return a stack trace. Supply the invalid value yourself rather
#    than copying a literal: this snippet deliberately embeds no credential-shaped
#    literal at all, so the Gate 3 secret sweep needs no allowance for this file.
read -r -s -p 'Type any value that is NOT a real password: ' WRONG_PASSWORD; echo
curl -s -X POST https://your-host/api/v3/en_US/auth/jwt/token \
     -H 'Content-Type: application/json' \
     --data-binary "{\"email\":\"x@y.z\",\"password\":\"${WRONG_PASSWORD}\"}"

# 5. Login throttling: a sixth consecutive failure must be refused.
#    STATE CHANGE: this LOCKS OUT the account it is run against.
#    Use the throwaway account from the preconditions - never a real one.
```

Then confirm the two authorization outcomes, both of which also require the staging instance: that the
seeded administrator credential no longer authenticates, and that a guest-role account cannot create
users or roles.

**Cleanup, after 9b:**

1. Restart the instance to clear the in-process throttle counters, or wait out the fifteen-minute
   lockout window.
2. Delete the throwaway account and any guest-role principal created for the authorization checks.
3. Restore the database backup if you took one, or re-provision.
4. Review the audit log and discard the records these checks generated, so a later reader does not
   mistake a deliberate lockout for a real attack.

> **Verify against published output, and never "fix" a missing-stylesheet symptom by setting
> `Development`.** Step 1 above fetches a `/_content/...` asset because the headers must reach static
> responses, not only dynamic ones. If you run an **unpublished** build directory — `bin/Debug/net10.0`
> — with `ASPNETCORE_ENVIRONMENT=Production`, every `/_content/**` URL returns **`405` with
> `Allow: DELETE`** instead of the asset, and the site renders unstyled. This is a launch-configuration
> artifact, not a header defect: these hosts ship no `wwwroot`, so all static content arrives from
> Razor Class Libraries, and ASP.NET Core's static-web-assets manifest is loaded only in the
> Development environment unless the host builder opts in explicitly. The unmapped request then falls
> through to a `DELETE`-only catch-all route, which is where the `405` and its `Allow: DELETE` come
> from. The seven headers *are* still present on that `405`, so the header check itself still passes —
> which is precisely why the symptom is easy to misread.
>
> Two correct responses: run `dotnet publish` and verify the published output, which materialises the
> assets physically; or, if a non-published Production run is genuinely needed, have the host builder
> call `UseStaticWebAssets()` explicitly. **The tempting third option — setting
> `ASPNETCORE_ENVIRONMENT=Development` to make the styling come back — silently undoes two
> remediations at once**, because it re-enables the developer exception page (finding H-12) and
> disables `UseHsts()` and `UseHttpsRedirection()`, both of which are deliberately guarded to
> non-Development environments (finding H-15). Recorded as `RISK-031` in the
> [risk register](risk-register.md); the host builder is outside this change's authorised file set, so
> it is documented rather than altered.

### Related documents

* [Security audit report](security-audit-report.md) - every finding, with evidence.
* [Remediation log](remediation-log.md) - what changed per vulnerability class.
* [Risk register](risk-register.md) - accepted risks and recommendations.
* [Credential migration guide](credential-migration.md) - the password-hash migration.
* [Security policy](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) - how to report a vulnerability.
* [Third-party libraries](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) - dependency inventory and licensing.


## Settings summary, keeping existing encrypted data readable, and the toolchain pin

Operator guidance for configuring and running the platform after the OWASP Top 10 (2021) security
remediation. Findings are described in the [security audit report](security-audit-report.md), the
changes made are recorded in the [remediation log](remediation-log.md), and accepted or open items
are in the [risk register](risk-register.md).

This document is the reference cited by the startup failures raised in `WebVella.Erp/ErpSettings.cs`
and `WebVella.Erp/Utilities/CryptoUtility.cs`, and by the SDK pin in `global.json`.

### Required settings

The remediation removed every compiled-in default secret. The values below therefore have no
fallback: when one is absent the platform refuses to start rather than degrading to a known-bad
value that ships in the public source tree.

| Configuration key | Required | Purpose |
| --- | --- | --- |
| `Settings:ConnectionString` | Always | PostgreSQL connection string. Consumed by `DbContext`, `ERPService` and every repository immediately after initialization, so no host functions without it (finding H-05). |
| `Settings:EncryptionKey` | Always | Symmetric key used by `CryptoUtility` for encrypted field values. The legacy misspelled `Settings:EncriptionKey` is still honoured for backward compatibility and satisfies the same check (finding C-04). |
| `Settings:Jwt:Key` | Only when a `Settings:Jwt` section exists | Bearer-token signing key. Required exclusively of the hosts that issue tokens; hosts and the console application that ship no `Settings:Jwt` section are not asked for one, because demanding it would stop them starting (finding H-04). |
| `Settings:Jwt:Issuer` | No | Token issuer. Defaults to `webvella-erp`. |
| `Settings:Jwt:Audience` | No | Token audience. Defaults to `webvella-erp`. |
| `Settings:DevelopmentMode` | No | Defaults to `false`. Must remain `false` in any deployment reachable by untrusted users (finding H-12). |
| `Settings:EmailSMTPCheckCertificateRevocation` | No | Defaults to `true`, so an SMTP relay certificate's revocation status **is** checked. Set it to `false` only when the relay's chain cannot publish a reachable CRL or OCSP responder; the trust chain, validity dates and host name remain verified either way. Unlike `Settings:EmailSMTPAllowInvalidCertificates` it is honoured in every posture, because a control that is inert in production is no remedy for a production outage. See *SMTP certificate revocation* and `RISK-060`. |

`ErpSettings.Initialize` validates the required values in one pass and reports **every** missing key
in a single startup failure, so a mis-provisioned deployment does not need one restart per variable.
Only configuration key *names* are reported — never values, prefixes, lengths or digests — so a
startup failure cannot leak key material into a console, a log file or a crash report (CWE-532).

### How values are supplied

#### The provider the hosts register today

`ErpMvcExtensions` builds configuration from **one non-optional JSON file**. Before this change the
builder read:

```csharp
new ConfigurationBuilder().SetBasePath(env.ContentRootPath).AddJsonFile(configPath)
```

That sample is the *pre-remediation* shape and is retained only to show what changed; no builder in the
tree calls `SetBasePath(env.ContentRootPath)` any more. All four sites — `ErpMvcExtensions`,
`WebVella.Erp.Site/Startup.cs`, `WebVella.Erp.Site.Project/Startup.cs` and the console app — now set
the base path to `AppContext.BaseDirectory`.

where `configPath` **was** the lower-case `config.json`, resolved from the host's content root, and no
environment-variable or user-secrets provider was registered by any host. Both of those are fixed:
every site now reads **`Config.json`** from `AppContext.BaseDirectory` and then consults environment
variables, with user secrets added in Development. Two consequences follow, and both matter
operationally:

* **Environment variables are a working supply channel**, at all four builder sites. The JSON file is
  still registered first, so it takes precedence where it defines a value — which is exactly why the
  tracked files must carry *empty* strings rather than sample values.
* **The file is not optional.** It cannot be deleted or renamed away; a host with no `Config.json`
  beside its entry assembly fails during initialization.

#### Ordering prerequisite before any value is scrubbed

*Retained because the constraint still governs any future change to these files, and because it is why
the scrub landed when it did rather than earlier.*

The shipped `Config.json` files **used to** carry live connection strings, a live encryption key and,
for the two token-issuing hosts, a live signing key; they are now blank. Replacing those values with
blanks was a **separate change with a hard prerequisite**: the configuration provider chain had to be
extended *first*. Scrubbing before the chain was extended would have left operators with no channel by
which to supply the secrets, and every host would then have failed to start. That order was followed,
which is why the scrub is safe today — and it must be followed again by anyone who adds a new required
setting to these files.

The required order is therefore:

1. Extend the `ConfigurationBuilder` in `WebVella.Erp.Web/ErpMvcExtensions.cs`, in
   `WebVella.Erp.ConsoleApp/Program.cs` and in each of the seven host builders so that, after the
   JSON file, it also reads environment variables (and user secrets in development).
2. Only then blank the secret values in the eight `Config.json` files and set
   `Settings:DevelopmentMode` to `false` in each.

Until step 1 lands, every value in a shipped `Config.json` **must** be replaced by the deployment with
its own value. None of the shipped values is safe to keep.

#### Environment-variable naming, once the provider is added

ASP.NET Core maps configuration section separators to a double underscore, so the keys above become:

| Configuration key | Environment variable |
| --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` |

Prefer environment variables, a mounted secret file or a platform secret store over checked-in
files. Never commit a real value to source control: the eight `Config.json` files are tracked, so a
value placed in one is published with the repository.

### Keeping existing encrypted data readable

`CryptoUtility` previously fell back to a 64-hex-character key compiled into the assembly whenever
none was configured. That constant has been deleted and the fallback now fails fast, with
deliberately **no** development-mode escape hatch and **no** generated random key — a generated key
would silently make already-encrypted data undecryptable, which is a worse outcome than failing
loudly.

A deployment that never supplied its own key was therefore encrypting with that former default. To
keep its existing data readable:

1. Recover the previous default value from source-control history, at the revision immediately
   before the constant was removed from `WebVella.Erp/Utilities/CryptoUtility.cs`.
2. Set `Settings:EncryptionKey` to exactly that value, so existing ciphertext continues to decrypt.
3. Treat the value as compromised, because it was public knowledge twice over — the assembly is
   published to nuget.org and the identical literal shipped in all eight `Config.json` files.
   Schedule a rotation: generate a fresh key from a cryptographically secure random source,
   re-encrypt the affected stored values under it, and only then retire the old key.

Do not skip step 1 on the assumption that a fresh key is harmless. Changing the key without
re-encrypting leaves previously encrypted values permanently unreadable.

### Response headers and the report-then-enforce policy rollout

`WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` emits the mandated header set when a host
adds it to its pipeline. Six headers carry fixed values:

| Header | Value |
| --- | --- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `0` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

`X-XSS-Protection: 0` is intentional and is not a disabled control: the legacy browser XSS auditor
it refers to was itself exploitable, and `0` is the value that switches it off rather than leaving it
in a partially enabled state.

The Content-Security-Policy value is
`default-src 'self'; script-src 'self'; style-src 'self'`, exposed as
`SecurityHeadersOptions.ContentSecurityPolicy`. It ships in **report-only** mode
(`SecurityHeadersOptions.ContentSecurityPolicyReportOnly` defaults to `true`), which emits
`Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. The enforcing header
carries that value verbatim; the report-only header carries the same directives plus a `report-uri`
pointing at the collection endpoint. Both are `public const`, derived from one shared constant, so
they cannot drift — see the mode table earlier in this document.

Report-only is not a weakened policy — the value is exactly the mandated one. It is a rollout mode,
required because four components deliberately emit inline script or author-supplied markup and a
strictly enforced `script-src 'self'` would suppress them, breaking working features. Move to
enforcement as follows:

1. Deploy with report-only left at its default and collect violation reports across the screens in
   real use, including the page-component designer and the sitemap form.
2. Eliminate or externalize the inline script the reports identify, or extend the policy value for
   exactly those cases.
3. Set `SecurityHeaders:ContentSecurityPolicyReportOnly` to `false` — environment form
   `SecurityHeaders__ContentSecurityPolicyReportOnly=false` — which switches the same value to the
   enforcing header name. This is a configuration change, not a code change, and removing the setting
   reverts it to report-only.

#### Wiring the middleware into a host

The middleware ships with its registration extension and is added to **all seven** site host
pipelines. The requirements each host satisfies, reproduced here because they govern any host you add
later:

* register the options and add `UseSecurityHeaders()` **early** in `Configure`, ahead of response
  compression and ahead of static-file serving, so the headers reach static and compressed responses
  and not only dynamically generated ones; and
* add the framework's own `UseHsts()` and `UseHttpsRedirection()`, guarded to non-development
  environments, with `UseHsts()` ordered first.

The middleware writes `Strict-Transport-Security` itself, so a host that also calls `UseHsts()` must
not end up emitting the header twice; follow the duplicate-avoidance note in the middleware source.
Introduce `UseHttpsRedirection()` in the same change as any cross-origin policy tightening: HTTPS
redirection makes cross-origin preflight requests fail with an invalid-redirect error if the two are
sequenced apart.

### Toolchain pin

`global.json` pins the SDK to `10.0.302` with `rollForward: latestPatch`, holding the pin on the
`10.0.3xx` feature band — which is the band that selects the audit defaults and the analyzer rule set,
so the gate stays reproducible while an SDK security patch is still admitted. Both the NuGet audit
defaults and the analyzer rule set are SDK-version dependent, so an unpinned toolchain makes the
dependency gate and the static-analysis gate non-reproducible — a scan result that varies with
whatever SDK happens to be installed is not evidence (finding L-07). `Directory.Build.props` at the
repository root carries the gate itself: dependency auditing across all dependencies at the lowest
reporting level, **six** NuGet audit diagnostics promoted to build errors — the four severity codes
`NU1901`–`NU1904` plus the data-availability codes `NU1900` and `NU1905`, so an audit that could not
run fails the build instead of passing it silently — and the .NET analyzers enabled at the recommended
level, raised to `latest-all` for the Security category alone by `AnalysisLevelSecurity`, with the
repository-root `.globalconfig` promoting ten of those security rules to build errors and holding five
more at warning against an enumerated baseline. The pin matters more once severities are set
rule-by-rule, not less: `.globalconfig` names rule identifiers, and which identifiers exist and what
each one flags is a property of the analyzer version shipped with the SDK. An unpinned toolchain could
therefore silently stop enforcing a rule the configuration still names.
