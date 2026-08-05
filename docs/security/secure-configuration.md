# Secure Configuration

Operator guide for running WebVella ERP securely after the OWASP Top 10 (2021) audit and remediation:
what you must supply, how to supply it, what the platform now emits and enforces, and what is
deliberately still open.

This page is **operationally load-bearing, not decorative.** The remediation removed every compiled-in
security default the platform used to fall back on, so a host that is not supplied with its own secrets
no longer starts at all — it fails fast with an actionable message instead of quietly encrypting with a
key that is public knowledge. It is the document cited by those startup failure messages, by the
comment in `global.json` that explains the toolchain pin, and by the mail plugin's certificate notices.

Findings are described in the [security audit report](security-audit-report.md), the changes in the
[remediation log](remediation-log.md), accepted risks and open decisions in the
[risk register](risk-register.md), and the credential format change in the
[credential migration guide](credential-migration.md).

## Read this first — the state of the shipped configuration

**The tracked `Config.json` files have been scrubbed.** All eight now carry **empty** secret values and
`"DevelopmentMode": "false"`, and `WebVella.Erp.Site/web.config` sets `Production`. The files are
retained rather than deleted, because the JSON configuration source is not optional and deleting them
breaks start-up outright. `RISK-021` is closed for the tracked configuration files.

**The application therefore will not start until you supply the required secrets — by design.** It
fails fast with a message naming each missing setting and never its value.

Treat every value that ever appeared in a tracked configuration file as public. Two consequences
follow, and they are the whole point of this guide:

- **Supply every secret externally before you run this anywhere but a developer laptop.** The
  configuration provider chain was extended for exactly this purpose, so you can do so without editing
  a tracked file.
- **Rotate anything that was ever deployed with a shipped value** — the database password, the
  encryption key and the token signing key. A value published in a public repository is compromised by
  definition, and rotating it is the only remediation. Blanking the working tree does not remove those
  values from earlier commits; that residual is `RISK-026`.

## What is in force at this commit

| Control | State |
| --- | --- |
| Configuration provider chain | **The tracked JSON file is always first**, so a blanked value can never override a supplied secret — that precedence is the control, and it holds at all four builder sites. `WebVella.Erp.Web/ErpMvcExtensions.cs` (in `AddErp`) supplies the chain the Crm, Mail, MicrosoftCDM, Next and Sdk hosts rely on; `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` each build their own in `Startup.ConfigureServices`; `WebVella.Erp.ConsoleApp/Program.cs` builds a fourth. Every one reads `Config.json`, then environment variables, then — in Development only — user secrets |
| Missing-secret behaviour | Fail fast. `WebVella.Erp/ErpSettings.cs` aborts startup with an actionable message naming **every** missing or weak setting at once; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back, and the compiled-in default key is gone |
| Known published defaults | Rejected by SHA-256 digest comparison, so this repository's own example encryption key and token signing key cannot be used even if supplied deliberately. The digests are stored rather than the literals, so neither the source nor this page reintroduces the secret it eliminates |
| Response security headers | All seven emitted by `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, registered once through `AddErp` and ordered in **all seven** hosts ahead of `UseResponseCompression` and both `UseStaticFiles` calls |
| Content-Security-Policy | Emitted in **report-only** mode carrying the mandated value **verbatim** and nothing else. There is **no `report-uri` directive and no collection endpoint**; both were removed, because appending `report-uri` altered the mandated value and the collector's early return could answer a request without attaching the other six headers. Reports are read from the browser console during the rollout instead (`RISK-022`) |
| Transport security | `UseHsts()` then `UseHttpsRedirection()` in all seven hosts, guarded to non-Development and ordered **after** `UseCors` so cross-origin preflight is not broken by a redirect. A startup guard refuses a non-Development host that can see no HTTPS request path at all |
| Cookies | Authentication: `SecurePolicy=Always` **unconditionally, including in Development**, `SameSite=Lax`, `HttpOnly`, a 24-hour sliding idle window and a 7-day absolute horizon. Antiforgery: `SecurePolicy=Always` outside Development and `SameAsRequest` in Development, retaining the framework's `SameSite=Strict` default |
| Data Protection | Per-application discriminator bound to the host's application name, so one host cannot decrypt another's authentication cookie; the key-ring directory is opt-in through `Settings:DataProtectionKeyDirectory` (`RISK-115`) |
| Rate limiting | `UseRateLimiter()` in all seven hosts — a per-address fixed window of 600 requests per minute — positioned after both static-file middlewares so assets are never throttled |
| Login throttling | Per-account and per-address counters over a bounded in-process store, consulted at **both** credential entry points: the login page and the anonymous bearer-token route (`RISK-008`) |
| Build gate | `Directory.Build.props` — dependency auditing at `all`/`low` with **six** NuGet audit diagnostics promoted to errors. .NET analyzers run with `AnalysisLevel=latest-recommended` and nothing further; no `AnalysisLevelSecurity` upgrade and **no** global analyzer configuration file is supplied, and the workflow fails if either appears. All analyzer diagnostics stay warnings at the project level and are enforced instead by the workflow's Gate 1 allow-list. Inherited by **19 of 19** projects, because the file is directory-scoped rather than solution-scoped |
| Toolchain pin | `global.json` pins `10.0.302` with `rollForward: disable`, so only that exact SDK builds the repository and the gate's recorded results are reproducible by construction (review findings `GATE-02` and `CR2-F-13`) |
| Shipped secrets | **Scrubbed.** All eight `Config.json` files carry empty secret values and `DevelopmentMode: false`, `web.config` sets `Production`, and the seeded administrator password is no longer a literal (`RISK-021`, closed) |
| Mail transport | SMTP server certificates are **validated by default, including revocation** (`RISK-060`) |
| Origins | No host applies `AllowAnyOrigin()` any longer (`RISK-013`, closed). Both formerly permissive hosts read `Settings:Cors:AllowedOrigins` and deny every origin when it is absent outside Development |
| Anonymous error paths | Both bearer-token routes return a generic message outside Development and retain their server-side log record (`RISK-014`, closed) |

## Required settings

`ErpSettings.Initialize` validates these at startup and aborts with an actionable message listing
**every** missing value at once, rather than one per restart. Only setting *names* ever appear in that
message — never values, prefixes, lengths or digests — so a startup failure cannot leak key material
into a console, a log file or a crash report (CWE-532).

### The settings the platform refuses to start without

| Setting key | Environment-variable form | Required | Purpose |
| --- | --- | --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` | **Always** | PostgreSQL connection. Consumed by `DbContext`, `ERPService` and every repository immediately after initialisation, so no host functions without it (finding H-05) |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` | **Always** | Symmetric key used by `CryptoUtility` for encrypted field values. There is no longer a compiled-in default (finding C-04) |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` | **Only when a `Settings:Jwt` section exists** | HMAC signing key for bearer tokens (finding H-04) |

The double underscore is configuration nesting, not a typo: `Settings__Jwt__Key` maps to the
`Settings:Jwt:Key` path, which in the JSON file is `{ "Settings": { "Jwt": { "Key": … } } }`. It is the
standard .NET convention and it is what makes it possible to override a nested value without editing
the file.

### Everything else an operator supplies

| Setting key | Environment-variable form | Required | Purpose |
| --- | --- | --- | --- |
| `Settings:Jwt:Issuer` | `Settings__Jwt__Issuer` | No — defaults to `webvella-erp` | Expected token issuer |
| `Settings:Jwt:Audience` | `Settings__Jwt__Audience` | No — defaults to `webvella-erp` | Expected token audience |
| `Settings:InitialAdministratorPassword` | `Settings__InitialAdministratorPassword` | **First provisioning only**, and when upgrading an installation still carrying the published default administrator password | The first administrator's password on a new database. Absent, provisioning generates a value with a CSPRNG and prints it once. Present, it must satisfy the password policy or **provisioning aborts** — see [the password policy below](#the-initial-administrator-password-must-satisfy-the-password-policy) |
| `Settings:EmailSMTPPassword` | `Settings__EmailSMTPPassword` | Only when e-mail is enabled | Relay credential. Ships empty |
| `Settings:EmailSMTPAllowInvalidCertificates` | `Settings__EmailSMTPAllowInvalidCertificates` | No | Accepts **any** SMTP server certificate. Honoured only alongside `Settings:DevelopmentMode`; refused, and reported once per process, anywhere else. Never set it in production |
| `Settings:EmailSMTPCheckCertificateRevocation` | `Settings__EmailSMTPCheckCertificateRevocation` | No | Defaults to `true`. Set `false` **only** when the relay's chain cannot publish a reachable CRL or OCSP endpoint. Chain, expiry and host name stay verified; honoured in every posture (`RISK-060`) |
| `Settings:DevelopmentMode` | `Settings__DevelopmentMode` | No — defaults to `false` | Must be `false` outside development. Gates a richer-error branch in `WebVella.Erp.Web/Controllers/ApiControllerBase.cs` (finding H-12) |
| `Settings:Cors:AllowedOrigins` | `Settings__Cors__AllowedOrigins` | `WebVella.Erp.Site` and `WebVella.Erp.Site.Project`, when a browser client calls either host cross-origin | Origin allow-list for those two hosts (finding H-14). Full resolution table under [*Cross-origin policy*](#cross-origin-policy) |
| `Settings:ForwardedHeaders:KnownProxies` and `:KnownNetworks` | `Settings__ForwardedHeaders__KnownProxies`, `Settings__ForwardedHeaders__KnownNetworks` | Only behind a TLS-terminating reverse proxy | Which proxies' `X-Forwarded-*` headers are trusted. Deny-by-default: unset means the middleware is not registered at all |
| `Settings:DataProtectionKeyDirectory` | `Settings__DataProtectionKeyDirectory` | No | Durable directory for the key ring that encrypts and signs every authentication cookie. Absent, keys are transient and a restart invalidates issued cookies (`RISK-115`, finding `CR2-F-11`) |
| `Settings:FileSystemStorageFolder` | `Settings__FileSystemStorageFolder` | Only when `Settings:EnableFileSystemStorage` is `true` | Root folder for file-system-backed storage. Blanked in all eight tracked files (finding `CR2-F-12`) |
| `Settings:CloudBlobStorageConnectionString` | `Settings__CloudBlobStorageConnectionString` | Only when `Settings:EnableCloudBlobStorage` is `true` | Credential-bearing, so it must never be committed. Blanked in all eight tracked files (finding `CR2-F-12`) |
| `Settings:TimeZoneName` | `Settings__TimeZoneName` | **In practice, on any non-Windows host** | Time-zone identifier. See [*Time zone identifier on non-Windows hosts*](#time-zone-identifier-on-non-windows-hosts) |
| `ASPNETCORE_ENVIRONMENT` | hosting environment | Recommended | Must **not** be `Development` in production (finding H-12). It also selects the Development-only cross-origin fallbacks |

All eight run configurations need the connection string and the encryption key: the seven site hosts
`WebVella.Erp.Site`, `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next`, `WebVella.Erp.Site.Project` and
`WebVella.Erp.Site.Sdk`, plus `WebVella.Erp.ConsoleApp`.

One nuance, recorded rather than recommended: `ErpSettings` still honours two **legacy misspelled**
keys for backwards compatibility — `Settings:EncriptionKey` as a fallback for the encryption key, and
`Settings:EnableBackgroungJobs` as a fallback for `Settings:EnableBackgroundJobs`, the misspelling that
seven of the eight shipped files actually used. Use the correctly spelled names; the aliases exist only
so that existing deployments keep working and are not recommended for new configuration.

### Why the token signing key is conditional

Demanding a signing key from every host would stop the ones that issue no tokens from starting at all,
which the preservation requirement forbids. The check is therefore scoped: the key is mandatory **if
and only if** the configuration actually declares a `Settings:Jwt` section. Of the eight shipped
configuration files, exactly two declare one.

| Host | Declares `Settings:Jwt` | `Settings:Jwt:Key` required |
| --- | --- | --- |
| `WebVella.Erp.Site` | Yes | Yes |
| `WebVella.Erp.Site.Project` | Yes | Yes |
| `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Sdk` | No | No |
| `WebVella.Erp.ConsoleApp` | No | No |

Where the section *is* present the key is mandatory, because the hard-coded fallback that used to cover
it was removed (finding H-04). If it is absent or unacceptable, the token issue and refresh routes
**refuse cleanly** and the bearer registration is screened so it can neither use nor throw on the bad
key. The authentication *scheme* still exists, because the platform's policy selector forwards
`Authorization: Bearer` headers to it, but it is configured without a signing key while still
validating signatures, so every presented token fails validation safely.

That is a deliberate, visible behaviour change and it is the correct outcome: the key that previously
shipped in `Config.json` is public, so anyone holding it could mint a token for any user, including an
administrator. A token endpoint that signs with a public key is worse than no token endpoint.
Supplying a real key re-enables both routes with no other change. **Cookie login is unaffected either
way.**

### The initial administrator password must satisfy the password policy

Review finding `F25` (CWE-521, OWASP A07:2021). `Settings:InitialAdministratorPassword` is the one
security setting whose *value* is validated for content rather than merely for presence, and the one
setting that can abort provisioning rather than startup. The rule is the platform password policy,
enforced by the single validator `PasswordUtil.ValidatePasswordPolicy`.

| Rule | Value |
| --- | --- |
| Minimum length | 12 characters |
| Maximum length | 128 characters |
| Required character classes | an upper-case letter, a lower-case letter, a digit and a symbol — all four |
| Leading or trailing whitespace | rejected, because it is almost always an accident of how the value was supplied |

If the value fails any of these, `InitializeSystemEntities` throws before it creates the administrator
record. The message names the setting and states the rule; it **never echoes the value, its length, or
any prefix of it**, for the same reason the missing-setting message never does (CWE-532).

**Why this is a refusal and not a warning.** The setting exists precisely so an operator can choose the
first credential of a new deployment. That credential is the most privileged one the system will ever
have, and it is chosen exactly once, unattended, at the moment nobody is watching a log. A warning
would be read by nobody; the abort is read by everybody. It also fails **closed** rather than falling
back to a generated password, because silently substituting a different password than the operator
asked for is worse than refusing.

**If provisioning aborted on you.** Correct the value and start the host again. Nothing was written, so
there is no partial state to clean up — the refusal precedes schema creation entirely.

The same validator guards both `SecurityManager.SaveUser` branches and the generic record-write path,
so a `POST api/v3/{culture}/record/user` carrying a one-character password is refused with a
field-level error keyed `password` and creates no row. Two exemptions are deliberate and load-bearing —
see `RISK-047`.

Whichever way the password is set, the account is flagged **change-required-on-first-login**: it can
sign in interactively to rotate the password, but cannot issue an API bearer token until it has been
rotated.

### Choosing key values

| Key | Requirement |
| --- | --- |
| `Settings:EncryptionKey` | At least 32 characters, at least 8 distinct characters, **US-ASCII only**, and not the value published in this repository. A 64-character hexadecimal string from a CSPRNG satisfies all four by construction and is the shape this guide recommends. Read *Keeping existing encrypted data readable* before changing this on an **existing** installation |
| `Settings:Jwt:Key` | The signing algorithm is HMAC-SHA-256 — `SecurityAlgorithms.HmacSha256Signature` in `WebVella.Erp.Web/Services/AuthService.cs` — so supply **at least 32 bytes**, that is 256 bits, of key material from a CSPRNG. Do not use a human-readable phrase, and do not repeat a short string to reach the length; the value that shipped in this repository did exactly that and is finding H-04 |
| `Settings:ConnectionString` | The role needs DDL rights because schema provisioning is code-driven, and — on this platform as it stands — it also needs `SUPERUSER`. See *PostgreSQL role privileges* |

Both keys are checked for **shape and for known-published-default status**, not merely for being
non-blank. A minimum length is enforced, a minimum number of distinct characters is required so that a
long repetitive string such as `aaaaaaaa…` is rejected, and the two values published in this
repository's history are rejected by SHA-256 digest comparison. The check is **staged**: in Development
it warns so an existing developer checkout still starts, and outside Development it fails closed.

Rotate all three if this repository's shipped values were ever deployed. See
[*Key rotation is mandatory*](#key-rotation-is-mandatory).

### Accepted character set for the encryption key

`Settings:EncryptionKey` must contain **US-ASCII characters only** — every character in the range
U+0000–U+007F. In practice, supply printable ASCII letters, digits and symbols. This is the character
set named by the startup failure raised in `WebVella.Erp/ErpSettings.cs` and by the derivation failure
raised in `WebVella.Erp/Utilities/CryptoUtility.cs`; both cite review finding `CR2-F-09`.

The restriction is not stylistic. `CryptoUtility` derives the AES key and the initialisation vector
from this text through an ASCII projection, and that projection used to **substitute** rather than
fail: every character above U+007F was silently replaced with `?` (0x3F). The consequence was measured
rather than presumed.

| Supplied key | Accepted by start-up validation? | Derived key bytes |
| --- | --- | --- |
| 32 ASCII characters | Yes | 32 distinct bytes, exactly the ASCII of the text |
| 32 **distinct non-ASCII** characters | Yes, before `CR2-F-09` | `3F` repeated 32 times — **one** distinct byte |
| A second, different 32-character non-ASCII key | Yes, before `CR2-F-09` | Byte-identical to the previous row |

The length floor and the variety floor both passed in those rows while the derived key carried a single
distinct byte, because the floors count **characters** and the derivation consumes **bytes**. The
initialisation vector, derived from the same text, collapsed and collided identically.

Requiring US-ASCII closes that gap by construction rather than by re-implementing the projection: for
US-ASCII input one character is exactly one byte, so the character-based floors are byte-exact and the
two layers cannot disagree. Two guards enforce it, and they are deliberately not the same guard:
start-up validation rejects a non-ASCII key before any data is touched, naming the setting and the rule
and never the value; and the derivation itself now refuses non-ASCII material rather than substituting
it, so key material reaching `CryptoUtility` from any future source is covered even if it never passed
through configuration validation.

Existing all-ASCII keys are entirely unaffected: ASCII and UTF-8 agree on ASCII input, so the derived
key bytes, the derived initialisation vector and the resulting ciphertext are byte-identical before and
after the change. The restriction is deliberately **not** applied to the connection string, whose
password may legitimately be non-ASCII. If a deployment has already encrypted data under a non-ASCII
key it will now be refused at start-up; the data is recoverable, and deterministically so — see
`RISK-114` for the procedure.

### Time zone identifier on non-Windows hosts

`Settings:TimeZoneName` defaults to the Windows-only identifier `FLE Standard Time`. On Linux and in
containers that identifier does not resolve, and the failure is not cosmetic: first provisioning aborts
with a `TimeZoneNotFoundException`, and two SDK list screens and the task detail view answer HTTP 500
afterwards. Set an IANA identifier instead, for example:

```bash
export Settings__TimeZoneName='Europe/Sofia'
```

The literal Windows identifier also lives inside the unmodified vendor tag-helper library, so the
application cannot fix it at source; this platform-level override is the supported route. Recorded in
the [risk register](risk-register.md), where the alternative tzdata remedy is described too.

### PostgreSQL role privileges

The role in `Settings:ConnectionString` must be a **`SUPERUSER`** on the current codebase. This is a
correction: an earlier revision of this guide said `SUPERUSER` was unnecessary, and an operator who
provisioned a least-privilege role on the strength of that sentence would find the application unable
to start at all.

The requirement comes from one specific pair of statements, not from the schema work in general.
`WebVella.Erp/Database/DbRepository.cs` runs:

```sql
DROP CAST IF EXISTS(varchar AS uuid);
DROP CAST IF EXISTS(text AS uuid);
CREATE CAST(text AS uuid) WITH INOUT AS IMPLICIT;
CREATE CAST(varchar AS uuid) WITH INOUT AS IMPLICIT;
```

PostgreSQL requires ownership of the cast's source or target type, and `varchar`, `text` and `uuid` are
all built-in types owned by the bootstrap superuser. A role that owns its own database and can freely
issue DDL therefore still cannot execute these four statements. Measured against PostgreSQL 16 with a
role holding `LOGIN` only and owning the database:

| Statement | Result for a non-`SUPERUSER` owner |
| --- | --- |
| `CREATE TABLE …` | **succeeds** — ordinary schema provisioning genuinely does not need elevation |
| `CREATE EXTENSION "uuid-ossp"` | **succeeds** — a *trusted* extension since PostgreSQL 13, so **not** a reason to elevate |
| `CREATE EXTENSION "postgis"` | fails, but the call is wrapped in `try`/`catch` and the failure is deliberately tolerated, so **not** a blocker either |
| `CREATE CAST(varchar AS uuid) …` | **fails** with `must be owner of type character varying or type uuid`, and is **not** wrapped. **This is the blocker** |
| `DROP CAST IF EXISTS(varchar AS uuid)` | no-op when the cast is absent, but **fails** with the same ownership error once the cast exists |

Two consequences follow, and both matter operationally:

- **The privilege is needed on every startup, not only at first install.** The cast block runs from
  `WebVella.Erp/ERPService.cs` *before* the version-gated provisioning block, so it is unconditional
  and every process start re-executes the drop-and-recreate.
- **"Provision once as `SUPERUSER`, then run as a least-privilege role" does not work.** It was tested
  rather than assumed: with the two casts pre-created by a superuser, the least-privilege role's very
  next `DROP CAST IF EXISTS` fails with the same ownership error. Pre-creating the casts makes the
  situation worse, not better, because the drop then has something to drop.

So there is currently no supported least-privilege configuration. Grant `SUPERUSER`, and compensate at
the boundaries that are actually available: give the platform its **own dedicated role and database**,
never one shared with other applications; restrict `pg_hba.conf` so that role can only authenticate
from the application host; and keep the connection string out of the repository. Making the cast block
version-gated would be a change to provisioning behaviour rather than a security fix, so it is out of
scope here and is recorded as a recommendation in the [risk register](risk-register.md).

## How settings are supplied

### The provider chain, and the order that makes it safe

Configuration is assembled at **four** builder sites: the shared platform extension
`WebVella.Erp.Web/ErpMvcExtensions.cs`, the console application
`WebVella.Erp.ConsoleApp/Program.cs`, and two hosts that build their own —
`WebVella.Erp.Site/Startup.cs` and `WebVella.Erp.Site.Project/Startup.cs`. The remaining five hosts
inherit the shared extension's chain rather than declaring their own.

At every one of those four sites the order is:

1. The JSON configuration file — **`Config.json`**, that exact spelling, resolved from
   `AppContext.BaseDirectory`. Registered **non-optional**.
2. **Environment variables.**
3. User secrets, in Development only.

**A later provider overrides an earlier one**, so an environment variable supersedes anything left in
the file. That is what lets a container or a CI runner inject secrets without editing anything on
disk, and it is why scrubbing the tracked files of live secrets was safe: there is now a supply
channel that does not involve committing anything.

The precedence direction is itself the control. Because the tracked JSON file is registered *first*, a
**blanked** value in it can never override a supplied secret — which is exactly why the tracked files
must carry empty strings rather than sample values.

Three further properties matter operationally:

- **The base path is the application base directory, not the working directory.** That distinction is
  a security property rather than a convenience: `Directory.GetCurrentDirectory()` resolves against
  whatever directory the process happened to be launched from, so a service unit, a scheduled task or
  a shell with the wrong `WorkingDirectory` would let the launcher decide which `Config.json` supplies
  the connection string, the data-at-rest encryption key and the token signing key — or find none at
  all.
- **User secrets contribute nothing to the console application today.** Its provider is registered
  against the entry assembly with `optional: true`, which is load-bearing rather than decorative: the
  project declares no `UserSecretsId`, and every `AddUserSecrets` overload given `optional: false`
  throws when that attribute is absent. Until the project declares one, the console application's
  effective chain is the JSON file then environment variables.
- **Outside Development no user-secrets provider is added anywhere**, so every host is exactly the
  JSON file followed by environment variables.

```bash
export Settings__ConnectionString='Host=db.internal;Port=5432;Database=erp;Username=erp_app;Password=<from your secret store>'
export Settings__EncryptionKey="$(openssl rand -hex 32)"
export Settings__Jwt__Key="$(openssl rand -base64 48)"
export ASPNETCORE_ENVIRONMENT='Production'
```

Prefer environment variables, a mounted secret file or a platform secret store over checked-in files.
Never commit a real value: the eight `Config.json` files are tracked, so a value placed in one is
published with the repository.

### The file the runtime actually reads

`Config.json` — with a capital `C`, exactly as the repository tracks it and exactly as both the build
and the publish output copy it. **No renaming or copying step is required, on any platform.**

An earlier revision of the platform asked for the lower-case spelling `config.json` while shipping
`Config.json`, and this guide documented a `cp Config.json config.json` workaround for case-sensitive
filesystems. **Both the defect and the workaround are gone; remove that copy from any deployment
steps that still carry it** (review finding `F30`). The mismatch was a real vulnerability rather than
an inconvenience — CWE-178, improper handling of case sensitivity, and CWE-706, use of an incorrectly
resolved name: on Linux and in containers the intended file simply did not exist under the requested
name, so startup either failed or, once a `config.json` was created by hand, silently read a file that
was not the audited one.

If you followed the old instruction and left a lower-case `config.json` in a deployment directory,
**delete it.** It is no longer read, and leaving an unaudited copy of the configuration on disk is
exactly the exposure the fix removed. The fallback's residual is `RISK-049`: a directory that has lost
`Config.json` but kept a stale `config.json` will start from the stale copy, so keep one file, not two.

The console host had a **second**, independent defect on the same line, which is why it could not
start on Linux at all rather than merely needing the copy: its path helper detected the application
root with a Windows-only drive-letter regular expression, so on any other platform the root resolved
to the empty string and the file name became relative to the process working directory. It now
resolves against `AppContext.BaseDirectory`, which is defined on every platform, is independent of the
working directory, and is also correct for a single-file publish.

This is not asserted from the source alone. The continuous gate proves it on every run: the
*Smoke-test Linux startup of the published artifacts* step in `.github/workflows/security-scan.yml`
publishes four hosts, deletes any lower-case `config.json` from the output, launches each **from an
unrelated working directory**, and asserts that each one resolved its own `Config.json` and reached
the fail-fast secret validation rather than a `FileNotFoundException`. The evidence is published as
`startup-smoke.txt`.

```bash
  # Nothing to do beyond publishing and running:
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

### Why the configuration files are scrubbed rather than deleted

Configuration **used to** be built from a JSON file and nothing else: a `ConfigurationBuilder` with a
base path and a single `AddJsonFile` call, with **no** environment-variable provider, **no**
user-secrets provider, and the file source **not** marked optional. Every builder site followed that
pattern. Two ordering constraints follow, and they are constraints rather than preferences:

- **The provider chain had to be extended *before* any value was blanked.** Scrubbing first would have
  left operators with no supply channel at all and every host unable to start. That order was
  followed, which is why the scrub is safe today — and **it must be followed again by anyone who adds
  a new required setting to these files.**
- **The files cannot simply be deleted.** The JSON source is non-optional, so removing them breaks
  startup outright. They are retained with **empty** values.

### Comments in the configuration files, and two deliberate blanks

All eight `Config.json` files and `global.json` carry `//` comments, and this remediation deliberately
kept them. RFC 8259 admits no comments, but nothing in this repository reads these files as strict
JSON: the runtime's own reader accepts them, `dotnet` accepts them in `global.json`, and no gate in
the workflow parses either file — the secret sweep matches key-name signatures line by line and never
invokes a JSON parser. The comments are, in several files, the only in-place explanation of what a
setting does, so stripping them would have deleted rationale for no verifiable gain. If you introduce
a strict consumer later, strip the comments in that consumer's own copy rather than in the tracked
file.

Two of those notes matter enough to restate, because in each case a **blank** value is a deliberate
setting rather than an omission:

- **`CacheKey`** — leaving it empty is meaningful. The platform then derives the cache key from the
  current date, formatted `yyyyMMdd`, so it rolls over daily.
- **`CloudBlobStorageConnectionString`** — leaving it blank does **not** leave storage unconfigured:
  the platform substitutes a literal Windows disk path, so a non-Windows deployment that switches
  `Settings:EnableCloudBlobStorage` on must set this explicitly. Neither setting is one the startup
  validator requires; it fails startup only for a missing connection string, a missing encryption key,
  or an encryption key that is weak, non-ASCII, or the example value published here.

## Key rotation is mandatory

Scrubbing a value out of a working tree does not undo its disclosure. Both platform secrets have been
public, and both remain recoverable from repository history permanently.

- The **encryption key** — `BC93B776A428…`, 64 hexadecimal characters — was present **byte-identically
  in all eight `Config.json` files**, and additionally as a compiled-in constant in
  `WebVella.Erp/Utilities/CryptoUtility.cs`. That constant shipped inside a library published to
  nuget.org, so the key was public twice over and could be neither rotated nor revoked per deployment.
- The **token signing key** — `ThisIsMySecretKey…`, a short phrase repeated three times for 51
  characters — was present at `WebVella.Erp.Site/Config.json:L25` and
  `WebVella.Erp.Site.Project/Config.json:L20`, with a third occurrence in
  `WebVella.Erp.Site/JWT_README.txt` and a fourth as a compiled-in 17-character default in
  `WebVella.Erp/ErpSettings.cs`, which also carried the same pattern for the issuer and the audience.
- The **database credentials** were live too. Seven of the eight files pointed at an internal RFC 1918
  host — `192.168.x.x:5436`, internal network topology disclosure in its own right — while
  `WebVella.Erp.Site` pointed at `localhost:5432`. The `User Id`/`Password` pairs were `test`/`test` in
  six files and `dev`/`dev` in two. `WebVella.Erp.Site/Config.json:L13` additionally exposed a UNC
  path naming the same internal host — raised independently as review finding `CR2-F-12`, which found
  that address still committed as a storage path in **all eight** files after the credentials
  themselves had been scrubbed.

The host address and both keys are **abbreviated here deliberately.** Enough to identify what was
exposed, not a copy of it. Abbreviating does not undo the original disclosure — the full values remain
in repository history, which is exactly why these instructions are not optional — but a tracked file
that reprints a secret or an internal address keeps it in every future clone and in every sweep of the
working tree, which would relocate the finding into the documentation rather than resolve it.

**Rotate all three.** Generate replacements with a cryptographically secure random generator:

```text
openssl rand -hex 32      # 64 hexadecimal characters, a 256-bit encryption key
openssl rand -base64 48   # a token signing key with ample entropy
```

The signing algorithm actually in use is **HS256**, so the signing key needs at least 256 bits of
entropy. One nuance is worth stating so the wrong lesson is not drawn: the old key was 51 characters,
so it was **not too short.** Its weaknesses were near-zero entropy — one short English phrase repeated
three times — and outright public disclosure. **Length alone is not the property that matters**, which
is why the platform now checks distinct-character variety and a published-default digest as well as
length.

Rotating the encryption key on an installation that already holds ciphertext is not a drop-in
substitution; read *Keeping existing encrypted data readable* first.

## Fail-fast behaviour, and why it is the secrets gate's negative test

The platform used to resolve a missing encryption key by silently substituting a compiled-in constant.
**Deleting only that constant would have relocated the defect rather than fixing it — the silent
fallback *was* the actual vulnerability** — so both were removed together. `CryptoUtility`'s key
accessor now throws, and there is deliberately no development-mode escape hatch and no
randomly-generated substitute. A generated key would be worse than a loud failure, because it would
silently make already-encrypted data undecryptable.

The same reasoning applies to the token signing key: the compiled-in 17-character default in
`ErpSettings.cs` is gone, so **a missing `Settings__Jwt__Key` no longer silently falls back to a
compiled-in value either.** It disables the token routes instead, which is a visible refusal rather
than a silent downgrade.

`ErpSettings` collects **every** missing value before throwing, so a mis-provisioned deployment learns
about all of them from a single startup failure instead of one restart per variable. The message names
the configuration keys and their environment-variable equivalents, and it deliberately withholds the
values themselves — no prefix, no length, no digest.

What the failure looks like, and how to resolve it: the host writes a message naming each unsatisfied
setting, aborts before serving a request, and exits non-zero. Supply the named settings through the
environment — or, in Development, through user secrets — and start it again. Nothing was written, so
there is nothing to undo.

This behaviour is the **negative test** for the engagement's secrets-scan gate. A scan that finds no
hardcoded credentials proves only that the literals are gone; starting a host with no key supplied and
observing an immediate, explicit failure proves the fallback was genuinely removed rather than merely
hidden. Run it deliberately, once, on any new deployment.

### Keeping existing encrypted data readable

The key is a symmetric key, not a derived one, so data encrypted under the old default is readable
**only** under that same value. A deployment that never supplied its own key was encrypting with the
former default. To keep its data readable:

1. **Recover the previous value from your own copy of the repository history** — the constant used to
   sit in `WebVella.Erp/Utilities/CryptoUtility.cs`; check out any commit before the remediation and
   read it there. It is deliberately **not** reproduced in this document: republishing it would
   reintroduce exactly the hard-coded secret the remediation removed, and would fail the secrets gate.
2. **Set it explicitly** as `Settings:EncryptionKey`. Your deployment then starts and reads its
   existing data exactly as before. Nothing is re-encrypted and no data is touched. Note that
   start-up validation rejects that value by digest outside Development, so this bridge is a
   Development-posture step or one taken alongside the migration in step 3 — it is a bridge, not a
   destination.
3. **Then rotate, deliberately.** To move to a fresh key you must decrypt with the old value and
   re-encrypt with the new one; there is no in-place re-key. Do it as a maintenance operation with a
   verified backup.

**Do not skip step 1 on the assumption that a fresh key is harmless.** Changing the key without
re-encrypting leaves previously encrypted values permanently unreadable.

How much data this actually affects is less than the wording suggests, and it is worth knowing before
planning a migration window:

- The only callers of `CryptoUtility`'s encrypt and decrypt members anywhere in the repository are
  **commented out**, in unreachable dead code recorded as finding L-01. No live code path in the
  shipped platform writes `CryptoUtility` ciphertext.
- The `CryptoUtility` members that *are* live are **hash** functions used for entity and relation
  cache keys. They do not use the encryption key, so they are unaffected by its value and no cache
  invalidation is needed.
- Password storage does **not** use this key. Passwords are hashed, and that is a separate migration
  described in the [credential migration guide](credential-migration.md).

So on a stock installation, supplying any valid key satisfies startup and there is no ciphertext to
preserve. Step 1 matters if — and only if — custom plugin code in your deployment called the encrypt
member and persisted the result.

## Response security headers

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
one edit, and then **ordered early in each host pipeline**. All seven were verified **on the wire**
against a published host over HTTPS — on a dynamic response and on two static assets — not merely by
reading the source.

`X-XSS-Protection` carries the value `0`, and that is correct and intentional rather than a disabled
control. The legacy browser XSS auditor it refers to has been removed from modern browsers and, while
it existed, was itself exploitable; `0` is the value that switches it off rather than leaving it in a
partially enabled state.

**Six of the seven are emitted in every environment. `Strict-Transport-Security` is the exception:**
the middleware suppresses it when the environment is `Development`, so that a developer who loads the
application once over `https://localhost` is not pinned to HTTPS for the whole `localhost` origin —
shared with every other locally served project — for a year. Outside Development all seven are present
unconditionally, including behind a TLS-terminating proxy that forwards plaintext, because the guard
tests the environment rather than the request scheme. **Expect six headers on a development machine and
seven on a deployed one; that difference is deliberate, not a gap.** The middleware also declines to
write a header a host has already set, so a host that additionally calls `UseHsts()` cannot emit a
duplicate.

### Ordering is what decides whether the headers apply

Register the middleware **early**: ahead of `UseResponseCompression` and ahead of **both**
`UseStaticFiles` registrations. Placed after them, the headers reach dynamically generated responses
only, and static assets and compressed responses are served without them — which is exactly the
response class most likely to carry attacker-influenced bytes. `Strict-Transport-Security` must also
precede HTTPS redirection. **Verify on both a dynamic page and a static asset**, not just on a page.

### The content policy ships in report-only mode

`SecurityHeadersOptions.ContentSecurityPolicyReportOnly` defaults to `true`, which emits
`Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. **The mandated policy value
is emitted exactly as written above in both modes — only the header *name* changes.** Report-only is
not a weaker policy; it is a rollout mode.

Both header names carry the single `ContentSecurityPolicy` constant, which is the mandated directives
verbatim with nothing appended. It is a compile-time constant, so no host, plugin or configuration
source can weaken, blank or replace it. An earlier revision of this section described the two modes as
backed by two separate constants with the report-only value carrying an extra `report-uri` directive;
that split was removed together with the collector, and the superseded description is corrected here
rather than quietly dropped.

**There is deliberately no violation-report collector endpoint and no `report-uri` directive.** An
intermediate revision mounted one at `/csp-violation-report`; it was removed for two reasons that each
apply on their own. First, appending a `report-uri` made the emitted policy differ from the mandated
value, and the mandated value is the acceptance criterion — a header that has been extended is not the
header that was mandated. Second, and more seriously, the collector was handled inside the middleware
ahead of routing, so the middleware acquired a request path that returned a response **without
attaching the other six headers**; a control whose own instrumentation opens a hole through the control
is worse than no instrumentation. Deleting the collector did not merely re-order that branch — it
removed the branch, so there is now exactly one path through the middleware and it always attaches
every applicable header.

**The switch is operator-controlled, not compile-time.**

| Key | Environment form | Default | Effect |
| --- | --- | --- | --- |
| `SecurityHeaders:ContentSecurityPolicyReportOnly` | `SecurityHeaders__ContentSecurityPolicyReportOnly` | `true` | `true` emits the report-only header name; `false` emits the enforcing one. The policy value is byte-identical either way |

Note the polarity: the bound setting is the **report-only** flag, so `false` is what enforces. The
value is read with `bool.TryParse`, so `true` and `false` in any casing are accepted and nothing else
is — `1` and `0` are not booleans to that parser — and a **present but unparseable** value aborts
startup rather than quietly selecting either posture, so a typo cannot drop the platform out of the
staged rollout. An absent or blank value leaves report-only in force. No rebuild is involved, so the
step is reversible by removing the setting and restarting. This is the **only** member of
`SecurityHeadersOptions` bound from configuration.

**How to collect violations.** There is no server-side collector, so read them from the **browser's own
developer console**. Every modern browser logs a report-only violation there with the blocked URI and
the violated directive — the same information the endpoint recorded — without adding an anonymous
write-accepting route to the application. If a deployment wants aggregation, terminate `report-to` at
the reverse proxy or a dedicated collector service rather than inside this middleware; that keeps the
header-attachment path single and unconditional, and it is a deviation from the mandated value to
record in the [risk register](risk-register.md) rather than an invisible default.

### What currently blocks enforcement

Measured from real violation reports, not predicted. Enforcing the policy as written would break all of
the following, so **do not skip the collection step**.

| Violation class | Source | Directive needed |
| --- | --- | --- |
| Inline `<style>` blocks and `style=` attributes | Application pages, and the lazy-load client bundle | a `style-src` allowance |
| Inline `<script>` blocks | Application pages; the by-design script-emitting components | a `script-src` allowance |
| String evaluation | The rich-text editor, and the client-bundle loader | `script-src 'unsafe-eval'` |
| **A 1×1 GIF spacer as a `data:` URI** | ASP.NET Core framework markup | **an `img-src` allowance for `data:`** |
| **A `blob:` worker** | The source editor's syntax worker | **a `worker-src` allowance for `blob:`** |

The last two matter disproportionately: **the mandated policy names neither `img-src` nor
`worker-src`**, so both fall through to the default directive and are blocked. Any enforcement plan
that reasons only about scripts and styles will break images and the code editor on the first
deployment.

The inline-emitting surface is also **wider than the four components originally identified**. In
addition to the HTML-block component and the two script-emitting components — enumerated in the
[risk register](risk-register.md) rather than duplicated here — real reports implicate the rich-text
editor, the lazy-load bundle and the source editor.

**The string-evaluation row is the one line the refactoring step cannot clear.** A nonce or a hash
authorises a *known script*; only an `unsafe-eval` allowance authorises string evaluation, so
refactoring first-party markup does nothing for an evaluation raised inside a dependency. That leaves
exactly two routes, and both are decisions rather than tasks: amend the mandated value — a real
weakening, owned by the application security owner — or rebuild or replace the vendored asset, which
this remediation's modification boundary excludes, because third-party code takes version updates only.

The route from here to enforcement:

1. **Deploy report-only** (the default). Nothing breaks; violations are reported, not blocked.
2. **Collect from real usage across all hosts**, exercising every screen that renders authored markup
   or generated inline script — the HTML-block component, the sitemap form, the page-body manager.
3. **Work through the inventory:** move inline blocks into served files, or adopt nonces or hashes.
4. **Add the missing image and worker directives**, which are required regardless.
5. **Set the report-only flag to `false`, per host rather than globally**, and re-test the same screens
   while watching the reports.

**The policy value is never silently weakened and the interface is never silently broken.** Only the
delivery mode is staged. That is the one place where the mandated header set cannot be *enforced* on
first deployment without breaking working features, and staging the delivery mode is the only way to
honour both the mandated set and the requirement that existing functionality keep working.

### Who owns the promotion to enforcement

The steps above describe the work; they deliberately do not authorise it. Promotion is governed, and
the governance is recorded once in the [risk register](risk-register.md) under `RISK-022` so the
criteria cannot drift between documents. In summary:

- **Owner:** the **application security owner**, jointly with the **frontend maintainer** for the
  plugin and tag-helper surfaces. It is not an infrastructure flag flip, because clearing the backlog
  means editing components.
- **Quantitative threshold:** **zero** report-only violations attributable to first-party code, over a
  **14-consecutive-day** window, across **all seven hosts**. Zero rather than a percentage reduction,
  because one surviving inline script breaks the interface the moment the header name changes, so a
  99 %-clear backlog behaves identically to an untouched one. Violations from browser extensions or
  operator-injected third-party markup are excluded but must be individually listed and justified in
  the promotion record, never silently discounted.
- **Measured starting position:** a single authenticated session produced at least **379** violations;
  one page context alone accounted for **137**, split **132 inline-style, 3 inline-script, 2
  evaluation**. Address styles first — they dominate by an order of magnitude.
- **If enforcement is declined,** it is *formally deferred* and recorded with a date and rationale, not
  left quietly pending.

**And state this plainly to anyone reading a status summary: report-only is not the remediation for
`H-06`.** The stored cross-site-scripting finding is remediated in the view and builder layer — text
sinks encoded, and every retained by-design markup channel enumerated in `RISK-023` and `RISK-032`. A
report-only policy is **detective, not preventive**: the browser reports the violation and then runs
the script anyway. It closes nothing on its own and must never be cited as evidence that `H-06` is
covered.

## Transport security

| Control | Guidance |
| --- | --- |
| TLS version | **TLS 1.2 or above.** Terminate TLS at the reverse proxy or configure Kestrel directly; the platform does not manage certificates |
| HSTS | Enabled, guarded to non-Development, ordered **before** redirection. Do not enable it on a hostname you also serve over plain HTTP for other purposes — the subdomain directive applies to every subdomain |
| HTTPS redirection | Enabled, guarded to non-Development, ordered **after** `UseCors` |
| Cookies | `Secure`, `HttpOnly` and an explicit `SameSite` policy — see *Cookies and session lifetime* |
| SMTP relay certificates | Validated by default, **including revocation** — see *Mail transport* |

### HSTS and HTTPS redirection

Both are guarded to non-Development environments, and **HSTS is ordered first**, before redirection.
The Development guard exists because HSTS is sticky: a browser that receives the header for `localhost`
will refuse plaintext `http://localhost` afterwards, which is a genuinely painful state to clear on a
developer machine. Before this remediation, HSTS was used nowhere in the platform except
`WebVella.Erp.WebAssembly/Server/Program.cs`.

**The caveat that dictates deployment order:** HTTPS redirection breaks cross-origin **preflight**
requests with an invalid-redirect error, because a browser rejects a redirect as a preflight response.
It must therefore be deployed **together with** the origin allow-list below, never ahead of it, and
both must be verified in the same step. That is how the two changes landed here, and the verification
was executed rather than assumed: with redirection active, an `OPTIONS` preflight from a listed origin
over plain HTTP answered `204` with the full `Access-Control-Allow-*` set and **no** `Location` header,
because `UseCors` is ordered ahead of `UseHttpsRedirection` in every host and short-circuits the
preflight before a redirect can be written. A non-preflight plain-HTTP `GET` still answered `307`, so
transport enforcement is intact and only preflight is exempt. **Moving `UseCors` after redirection
reintroduces the failure.**

**A second caveat, measured rather than assumed: `UseHttpsRedirection()` is silently inert unless the
application knows an HTTPS port.** Started in Production with only an HTTP endpoint, the host still
emitted the transport-security header on every response — the header half works — while the redirection
half logged `Failed to determine the https port for redirect.` and passed plaintext requests through
untouched. That is the framework's documented behaviour, not a defect here.

**Outside Development the consequence is worse than "no redirect".** A plaintext request that is not
redirected reaches MVC, and the antiforgery cookie is `Secure`-only by design (finding M-02).
`DefaultAntiforgery.CheckSSLConfig` therefore throws, and **every page carrying a form — `/login`
included — answers HTTP 500**, so nobody can sign in. Nothing else looks wrong while that is true: the
host starts healthy, `/` still answers `302`, and the security headers are still emitted, so a health
probe and a header audit both pass on an application that cannot be used. **Weakening the
non-Development antiforgery policy is not the remedy** — that reinstates the CWE-614 weakness M-02
closed.

**A startup guard now refuses that configuration** instead of letting it fail one request at a time.
`ValidateTransportSecurityPosture` in `WebVella.Erp.Web/ErpMvcExtensions.cs` runs inside `UseErp()`, so
all seven hosts inherit it, and it looks for any **one** of four ways a request can arrive over HTTPS:

1. a declared endpoint of this process whose scheme is `https` — `ASPNETCORE_URLS`, `UseUrls` or a host
   binding;
2. a `Kestrel:Endpoints:<name>:Url` whose scheme is `https`;
3. a public HTTPS port in configuration — `ASPNETCORE_HTTPS_PORT`, `HTTPS_PORT` or the configuration
   key `https_port` — which arms the redirect so a plaintext request never reaches a form;
4. a trusted reverse proxy — `Settings__ForwardedHeaders__KnownProxies` or
   `Settings__ForwardedHeaders__KnownNetworks` — which lets `X-Forwarded-Proto: https` establish the
   scheme.

Finding one ends the check silently. Finding none, the host **aborts at startup** with a message naming
every key above, before serving a single request. Two deliberate exceptions keep the guard from ever
refusing a deployment that would have worked: **Development is exempt** and gets the identical text as
a `warn:` line, because its antiforgery cookie uses `SameAsRequest` so local plaintext sign-in remains
supported; and **when no endpoint is declared at all** the endpoints come from Kestrel's defaults or
from host code the platform cannot inspect, so the same text is written as a warning rather than
enforced. Measured in Production for the record: with nothing declared this application binds
`http://localhost:5000` only, so that configuration does still fail on `/login` — the warning is the
notice, not a clean bill (`RISK-126`).

**`ASPNETCORE_HTTPS_PORTS` — plural — does not work, and an earlier revision of this guide wrongly
prescribed it.** It is a Kestrel default-binding key that this application's `WebHost` pipeline never
reads: measured with it set and a valid certificate but no `ASPNETCORE_URLS`, the host still bound
`http://localhost:5000` alone and `/login` still answered `500`. Use the singular
`ASPNETCORE_HTTPS_PORT`, or `HTTPS_PORT`, or the configuration key `https_port`.

The measured behaviour of each option, on a host whose only declared endpoint is plaintext:

| Configuration | `/login` over plaintext | Startup |
| --- | --- | --- |
| nothing further supplied | **HTTP 500** before the guard existed | **refused at startup** now, with the actionable message |
| `ASPNETCORE_HTTPS_PORT=<public https port>`, or `HTTPS_PORT` | `307` to `https://…/login` | starts |
| `Settings__ForwardedHeaders__KnownProxies=<proxy address>` **and** the proxy sends `X-Forwarded-Proto: https` | `200` | starts |
| `ASPNETCORE_HTTPS_PORTS` (plural) | still **500** — the key is not read | refused at startup |

Trusting a proxy that does not actually send `X-Forwarded-Proto` leaves the failure in place: the guard
can see that a proxy is trusted but cannot see what it sends, which is why option 4 has two halves.
Treat "redirects plaintext" as conditional on this configuration and verify it on the deployed topology
rather than trusting the middleware's presence in the pipeline.

### Trusting a reverse proxy: `X-Forwarded-*` handling

Forwarded-header processing is **deny-by-default and must be configured explicitly.** It is ordered
**first** in every host pipeline, so HTTPS redirection and the rate limiter both observe the real client
address and scheme rather than the proxy's.

| Key | Format | Effect |
| --- | --- | --- |
| `Settings__ForwardedHeaders__KnownProxies` | Comma-separated IP addresses | Individual proxy addresses whose `X-Forwarded-*` headers are trusted |
| `Settings__ForwardedHeaders__KnownNetworks` | Comma-separated CIDR blocks, e.g. `10.0.0.0/8` | Proxy networks whose headers are trusted |
| `Settings__ForwardedHeaders__ForwardLimit` | Integer | How many chained proxy entries to walk |

**If neither `KnownProxies` nor `KnownNetworks` is configured, the middleware is not registered at
all.** This is deliberate and stronger than registering it with an empty allow-list: an unconfigured
deployment cannot be tricked into believing a forged `X-Forwarded-For`, which would otherwise let an
attacker evade the per-address rate limiter and the login lockout by varying one header, and let a
forged `X-Forwarded-Proto` suppress the HTTPS redirect. Verified against a running host as a matched
set:

| Configuration | A forwarded HTTPS scheme from loopback | Result |
| --- | --- | --- |
| nothing configured | ignored | `307` redirect — header not trusted |
| `KnownProxies=127.0.0.1` | honoured | `200` — no redirect |
| `KnownProxies=203.0.113.1` | refused | `307` — loopback is not the listed proxy |
| `KnownNetworks=127.0.0.0/8` | honoured | `200` — no redirect |

`X-Forwarded-Host` is **not** honoured in any configuration, so a forwarded host header cannot be used
to poison generated links. All seven security headers remain present on a trusted, non-redirected
forwarded request. A malformed value in any of the three keys **aborts startup** with an
operator-actionable message rather than silently falling back to trusting nothing or everything.

## Cross-origin policy

All seven hosts now serve an explicit origin allow-list, and no `AllowAnyOrigin()` call remains applied
anywhere in the tree (finding H-14, `RISK-013`, closed — the old calls survive only inside explanatory
comments).

**Two hosts, not seven.** The two that previously permitted any origin were `WebVella.Erp.Site` and
`WebVella.Erp.Site.Project`; both combined any-origin, any-method and any-header, which places no
restriction at all. The other five — `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next` and `WebVella.Erp.Site.Sdk` — **already used
a restrictive named policy and were deliberately left alone.** Their hard-coded localhost origins are a
separate low-severity item in the [risk register](risk-register.md). Overstating this finding's breadth
was one of the false-positive classes the audit explicitly eliminated.

Both remediated hosts keep `AddDefaultPolicy` rather than converting to a named policy, so the
`app.UseCors()` call already present in each `Configure` method applies the new policy and the pipeline
needed no edit at all. `AllowCredentials()` is deliberately absent from both: the framework refuses it
alongside a wildcard origin, so credentialed cross-origin requests were never actually permitted, and
adding it now would widen behaviour rather than preserve it. These two hosts authenticate cross-origin
callers with a bearer token rather than with a cookie.

**Both are configuration-driven**, so changing the origins either deployment serves needs no rebuild.
Both read `Settings:Cors:AllowedOrigins`, environment form `Settings__Cors__AllowedOrigins`. The
resolution is layered:

| `Settings:Cors:AllowedOrigins` | `ASPNETCORE_ENVIRONMENT` | Resulting allow-list |
| --- | --- | --- |
| Supplied, one or more origins | any, including `Development` | Exactly the origins supplied — a supplied value always wins, and the Development defaults are **not** added as well |
| Supplied but empty | any, including `Development` | Empty. This is the explicit "allow nothing" |
| Absent | `Development` | Site: three localhost origins from its own previously commented-out policy. Project: those three plus `http://localhost:2202` |
| Absent | anything else, or unset | Empty — **deny by default** |

The value is one string delimited by `,` or `;`; entries are trimmed and empty entries dropped, so
`https://a.example.com ; https://b.example.com` supplies two origins. **Matching is exact** — scheme,
host and port must all correspond and there must be no trailing slash — which was verified rather than
assumed: a trailing-slash variant, a case-altered variant, the same host over `https` rather than
`http`, `127.0.0.1` in place of `localhost`, and the literal `null` origin were each refused, while the
exact listed origin was accepted. On Site, port `2202` is deliberately excluded because that client
belongs to Project.

**Supply the key for either host when a browser client calls it cross-origin.** An absent key outside
Development is a deny-all: correct as a default, but not a working configuration for such a client. The
key is deliberately **absent from the shipped `Config.json`**, so a configuration file left untouched
cannot silently authorise an origin and the Development fallbacks can never reach a production
deployment. **The five already-restrictive hosts name their origins in source**, so replace those with
the origins your deployment actually serves before going live; an allow-list naming the wrong origins
is not protection, it is a mis-statement of it.

Verify afterwards that a listed origin receives `Access-Control-Allow-Origin` together with
`Vary: Origin`, and that an unlisted origin receives **no** CORS headers at all. Do not be misled by
the status code while testing: a disallowed origin still receives the normal response *status and
body*, because CORS is enforced by the browser on the basis of those headers rather than by the server
refusing to answer. **The absence of the header is the control.**

## Cookies, sessions and bearer tokens

### Cookies and session lifetime

Cookie authentication is configured identically across all seven hosts, from a **single** shared
configurator, `ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie`, so the seven cannot drift
apart.

| Setting | Value | Reason |
| --- | --- | --- |
| `SecurePolicy` | **`Always`, in every environment** — no Development carve-out | The cookie must never traverse plaintext. An earlier revision relaxed this in Development so `http://localhost` kept working; that relaxation *was* the vulnerability (CWE-614), because `ASPNETCORE_ENVIRONMENT` is ambient — a deployment that inherits `Development` from a shell profile, a container image or a stale `web.config` silently stops marking the session cookie `Secure`, and the one signal that something is wrong is the signal that is suppressed. Local development uses the HTTPS profile instead |
| `SameSite` | `Lax` | `Strict` breaks the return-URL round trip through the login page. `Lax` is the framework's documented default posture, and it must not be "upgraded" |
| `HttpOnly` | `true` | Script cannot read the ticket |
| `ExpireTimeSpan` | **1440 minutes (24 hours)** | The **idle** window: a session that sees no activity for 24 hours ends |
| `SlidingExpiration` | `true` | Activity slides the idle window forward. Safe *only* because of the absolute horizon below |
| `AllowRefresh` | `true` | Required for sliding renewal to function at all |

The **antiforgery** cookie is posture-aware rather than unconditional: `Always` outside Development, and
`SameAsRequest` in Development so a plaintext `/login` renders and accepts a token-protected POST on a
developer machine. It retains the framework's `SameSite=Strict` default. The authentication cookie
remains `Secure` throughout. This is the pairing that makes a plaintext-only non-Development host
refuse to start rather than answer 500 on every form — see *HSTS and HTTPS redirection*.

**A configuration incoherence that was fixed.** All seven hosts declared an 8-hour `ExpireTimeSpan`,
but the authentication ticket was constructed with an explicit 24-hour `ExpiresUtc`, and an explicit
`ExpiresUtc` *overrides* `ExpireTimeSpan`. The real lifetime was therefore 24 hours — three times what
every host declared — and seven hosts' configuration was inert. Both halves are now aligned at 1440
minutes, so the declared value and the effective value agree, and the agreed value is the *idle* window
rather than an absolute one.

### Sliding expiration, and why it is not an indefinite session

Sliding expiration alone would be a regression, not a fix: a stolen cookie used at least once every 24
hours would renew **forever**. It is safe here only because it is paired with a hard ceiling.

At authentication the ticket is stamped with an absolute expiry in the item
`wv_session_absolute_expiry`, set to **10080 minutes (7 days)** after issue, and a validation handler
rejects any ticket presented past that stamp. Because the stamp lives inside the encrypted, signed
ticket payload and the renewal path rewrites only the issue and expiry timestamps, sliding renewal
**cannot** push the horizon outward. **Worst-case exposure from a stolen cookie is therefore 7 days,
not unbounded.**

Tickets issued *before* this change did not permit refresh, so they cannot slide at all and remain
bounded by the expiry they were issued with. They are deliberately **not** rejected outright, because
that would sign out every currently active user on deployment.

**The idle bound is invisible at the HTTP layer, and that is expected.** The ticket is not persistent,
so the cookie is a session cookie with no `expires` or `max-age` attribute; both the idle window and the
horizon live inside the encrypted payload. Do not try to verify them by reading response headers —
decrypt the ticket instead. One related trap: the login redirect carries a top-level `expires` header
dated 1970, which is a **cache** header and not a cookie attribute; it says nothing about session
lifetime.

### Bearer tokens: the absolute session horizon

Bearer tokens carry the same **7-day absolute session horizon**, stamped at issue and carried verbatim
across every refresh. Refresh past the horizon is refused, and a refreshed token's expiry is capped at
the horizon rather than extending beyond it. Before this, an anonymous refresh endpoint would renew a
stolen token indefinitely: the token never had to expire, so a single theft was permanent. Seven days
deliberately matches the cookie horizon, so a cookie session and a bearer session expire on the same
schedule.

**What is not implemented, stated plainly:** there is no revocation list and no refresh-token rotation.
Both require persisting issued or revoked token identifiers — a database schema change, which the
audit's own constraints forbid. The honest consequences: signing out clears the cookie and revokes the
cookie session identifier, but it does **not** invalidate an already-issued bearer token; and a stolen
token stays usable until the earlier of its own expiry and the 7-day horizon. A revocable refresh-token
table with rotation and reuse detection is recorded as future work in the
[risk register](risk-register.md).

### The Data Protection key ring, and why each host needs its own identity

Every authentication cookie this platform issues is an encrypted, signed payload produced by the
framework's Data Protection stack. Two properties of that stack decide whether a cookie minted by one
host can be read by another: the **key ring** that supplies the key, and the **application
discriminator** mixed into the derivation as additional authenticated data. Until review finding
`CR2-F-11` neither was configured anywhere in the repository, so both sat at defaults, and both
defaults are unsuitable here.

**Per-application isolation.** The discriminator is now set explicitly to the host's application name.
This matters because the seven hosts are designed to be co-hosted and two of them shipped the *same*
cookie name. A shared cookie name on a shared host name is not merely untidy: a cookie is scoped by
domain and path and **not** by port or by application, so both hosts see the same cookie on every
request. Whether that is harmless or a cross-application authentication flaw depends entirely on
whether the second host can *decrypt* the first host's ticket — and with an explicit per-application
discriminator it cannot; the payload fails authentication and the request is treated as anonymous. The
cookie-name collision was corrected in the same change, and all seven host cookie names are now
distinct.

Both halves were verified by running two hosts concurrently **against one shared key directory** —
deliberately the worst case, since a shared key ring removes the only accidental isolation a default
configuration would have provided:

| Test | Result |
| --- | --- |
| Host A's ticket presented to host A | `200` — accepted |
| Host A's ticket presented to host B | `302` to `/login` — refused |
| Host B's ticket presented to host A | `302` to `/login` — refused |
| Host A's ticket presented to the **same application** running from a **different directory** | `200` — accepted |

The last row is what isolates the value of the change. The framework's default discriminator is derived
from the content-root **path**, so the earlier rows would have looked the same without any change at
all. Only that row separates the two designs: with the discriminator bound to the application *name*,
republishing a host to a new directory keeps every existing session valid; with the path-derived
default, the same republish silently invalidates every ticket and logs every user out.

**Persisting the key ring.** By default the key ring is written to a per-user profile directory, or held
only in memory when no profile is available. Either way the keys are transient, so a container restart
or a scale-out replaces them and every issued cookie stops validating. Set
`Settings:DataProtectionKeyDirectory` — environment form `Settings__DataProtectionKeyDirectory` — to
durable, host-private storage to avoid that. The setting is **opt-in**: when absent the framework
default is left in place, deliberately, because a directory this code invented would be no more durable
than the default while being harder to reason about. When present the directory is created if necessary
and a path that cannot be created **fails at start-up** rather than being swallowed, because a silently
ignored key directory is exactly the misconfiguration that produces intermittent, unattributable
logouts weeks later. Give each host its own directory unless you specifically intend them to share one;
sharing is safe for isolation, as the table above shows, but it couples their key-rotation schedules.

**Keys are not encrypted at rest.** With a file-system key repository configured and no XML encryptor,
the framework logs that the key may be persisted in unencrypted form. That message is accurate and is
**not** remediated here: encrypting the key ring at rest requires platform-specific material this
repository does not have and cannot invent — an X.509 certificate, a DPAPI profile, or a hosted
key-management service — and choosing one on a deployment's behalf would either fail at start-up or
bind the platform to an environment it may not run in. The residual is carried as `RISK-115`, which
records the two supported ways to close it and the file-system controls that bound it meanwhile.

**One-time consequence: users are signed out once.** Two changes in this class each invalidate
previously issued cookies exactly once, at the deployment that adopts them — every host, because the
discriminator changed from the path-derived default; and the one host whose cookie name changed, whose
old cookie is no longer even read. Affected users simply sign in again. No stored data, credential or
permission is touched, and the effect does not repeat on subsequent deployments.

## Rate limiting and the login lockout

Two independent layers, both from the shared framework or from in-process primitives — **no new
dependency and no schema change.**

**Transport-level rate limiting** is a per-remote-address fixed window of **600 requests per minute**,
registered in every host pipeline and positioned after both static-file middlewares so assets are not
throttled. A single page load pulls many assets; a limit that counts them starves legitimate users long
before it inconveniences an attacker.

**Login throttling** is enforced by `WebVella.Erp.Web/Services/LoginThrottleService.cs` with **two
independent counters**:

| Counter | Threshold | Window |
| --- | --- | --- |
| Per account | **5 failed attempts** | 15 minutes |
| Per source address | 25 failed attempts | 15 minutes |

The **five-attempt account threshold is taken literally from the engagement's authentication-hardening
standard.** The counters are independent on purpose: a single composite key would let an attacker reset
an account's failure count by rotating source address, and would let one noisy address exhaust an
innocent account's budget. The address threshold is deliberately five times the account threshold,
because NAT and shared corporate egress mean many legitimate users can share one address; a threshold
equal to the account limit would lock out an entire office because of one user's typo.

**Both credential-verification surfaces are throttled: the login page and the anonymous bearer-token
route.** Throttling only the login form would have left a fully unthrottled credential oracle exposed.
The token refresh route uses the address-only counter because it presents no username. Failure
registration is atomic — attempts are reserved before verification and finalised after — so concurrent
requests cannot each pass the check before any of them records a failure.

Three limitations, stated rather than buried:

- **The store is in-process**, backed by the existing bounded cache primitive, so its protection is
  **per instance**. In a multi-instance or load-balanced deployment each instance counts independently
  and effective thresholds multiply by the instance count. A distributed backing store is a recorded
  **recommendation, deliberately not built**; if you run more than one instance, enforce throttling at
  the load balancer as well. The throttle **fails closed** on cache eviction, so eviction cannot grant
  unlimited attempts.
- **Account lockout is a denial-of-service primitive**, which is why it lapses automatically after 15
  minutes rather than requiring an administrator to clear it. An attacker can lock a known account for
  15 minutes; that is a deliberate trade against making credential stuffing cheap.
- **The store is size-bounded** to cap memory against an attacker varying the username. Displacing a
  specific account's partial count requires cycling the entire store, which buys at most a few extra
  guesses.

Counters are held in memory, so **restarting the application clears all lockouts** — useful during
testing, and the fastest way to undo a deliberate lockout you created while verifying a deployment.

## Mail transport

### SMTP certificate validation

The mail plugin used to install an always-true certificate validation callback **unconditionally at
five sites** — four in `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` and one in
`WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs`. That accepts any certificate from any
server, which defeats transport authentication entirely (finding H-11, closed at all five).

The replacement is an explicit configuration flag that **defaults to secure.** A self-signed
development mail server stays usable through deliberate opt-in, so a development convenience can never
again ship as a production default. Treat a certificate failure as a signal to fix the server's
certificate rather than to disable the check.

```bash
  # Development only. Never set this in production.
export Settings__DevelopmentMode='true'
export Settings__EmailSMTPAllowInvalidCertificates='true'
```

That opt-in is honoured **only** when `Settings:DevelopmentMode` is also set. Enabled anywhere else it
is refused, and the refusal is reported once per process on standard error. It is therefore **not** a
remedy for the situation described next, and must not be reached for as one.

### SMTP certificate revocation

**Your relay's certificate chain must expose a reachable CRL distribution point or OCSP responder.**
This is a genuine new prerequisite and the one operational consequence of enabling certificate
validation that will surprise you. The mail library checks revocation by default, so once the
always-true callback was removed the platform began consulting the revocation source named in the
relay's certificate. If that source cannot be reached — an internal CA that publishes no CRL, a leaf
issued without a distribution-point extension, or a host whose egress filtering blocks the fetch — the
handshake fails even though the certificate is otherwise perfectly valid.

**Recognising it.** The failure is an SSL handshake exception wrapping an authentication exception, and
the chain-status detail contains **only**:

```text
unable to get certificate CRL
```

No expiry bullet, no host-name bullet, no untrusted-root bullet. Read that combination literally: it
says *"I could not find out whether this certificate has been revoked"*, **not** *"this certificate is
untrusted"*. Reaching for the accept-any-certificate opt-out in response would be treating a
reachability problem as a trust problem, and would remove transport authentication entirely to fix a
missing CRL.

**Fixing it, in order of preference.**

1. **Publish the revocation source.** Re-issue the relay leaf with a distribution-point extension
   pointing at a CRL your hosts can actually fetch, sign the CRL with a CA that carries `cRLSign` and a
   subject key identifier, serve it in **DER** form, and allow the application host outbound access to
   that URL. This keeps every check in force and is the only option that leaves a revoked relay
   certificate refused.
2. **Narrow the check, and only the check.** Set `Settings__EmailSMTPCheckCertificateRevocation` to
   `false`. Mail delivery resumes, and the trust chain, validity dates, key usage and host name are
   **still verified**, so a self-signed, expired, wrong-name or wrong-CA certificate is refused exactly
   as before. What you give up is precisely one thing: a relay certificate whose key has leaked and
   whose issuer has since revoked it will no longer be refused. Record it as an accepted risk
   (`RISK-060`) and remove the setting once option 1 is available.

| Property | Value |
| --- | --- |
| Default when absent | `true` — revocation **is** checked |
| Values that disable the check | only a value parsing as boolean `false`, in any casing, with surrounding whitespace tolerated |
| Values that leave it enabled | absent, blank, `true`, and anything unparseable such as `no`, `0`, `off` |
| Posture gate | **none, deliberately.** Unlike the accept-any-certificate opt-out this one is honoured in every posture including Production — a control that is inert in production is no remedy for a production outage, and the relaxation is narrow enough to be supportable there |
| Parsing | non-throwing, so a typo cannot turn a mail configuration mistake into an exception on every outbound message. The insecure state is `false`, so only an explicit `false` disables the check |
| Visibility when disabled | one notice per process on standard error, naming the setting key and nothing else |
| Sites governed | all five, from a single policy member so no site can drift |

**Two consequences worth knowing before you deploy.** Revocation checking genuinely works rather than
failing blindly, which is why option 1 is preferred and option 2 is a real if bounded loss: a leaf
revoked in its issuer's CRL is refused with a distinct `certificate revoked` bullet, while a
non-revoked leaf validated against that same freshly published CRL still delivers. And **the queued
send path fails differently from the interactive one**: a direct send throws where the caller can see
it, while the background queue records the handshake text in the message's `server_error`, increments
the retry count, reschedules, and eventually marks the message aborted. If mail silently stops flowing
and the queue is filling with aborted rows, **read `server_error` before anything else** — the CRL
bullet will be sitting in it. The measured cost of secure delivery is small: warm TLS delivery is within
a few milliseconds of the accept-all baseline, plus a one-off chain fetch the first time a CRL is
retrieved and cached.

### Two SMTP misconfigurations easy to mistake for certificate failures

Both settings above govern what happens **when TLS is negotiated.** Two common relay
misconfigurations never get that far, and both are frequently misread as certificate problems — which
sends the investigation to the wrong setting. Neither is changed by the certificate hardening; both are
pre-existing properties of the transport configuration, carried as `RISK-062` and `RISK-063`.

**A connection-security value that disagrees with the port hangs for two minutes.** The mail plugin
sets no send timeout, so the library's 120-second default applies to every connect. If a service row is
configured for implicit TLS against a port that expects `STARTTLS`, or for `STARTTLS` against a port
that answers with a TLS handshake immediately, neither side makes progress and nothing is reported for
two full minutes. The symptom is a **hang**, not an error. **No certificate setting affects it by one
millisecond.** Check the `connection_security` value on the `smtp_service` row against what the relay
actually offers on that port; the conventional pairings are implicit TLS with 465, and `STARTTLS` with
587 or 25.

**A service row configured for cleartext delivers with no certificate involved at all.** A
`connection_security` of `None` connects in the clear, and the "when available" variant silently
degrades to cleartext against a relay that does not advertise `STARTTLS`. On such a row the message body
— and, when the row carries a username, the **relay credential** — is transmitted unencrypted, and the
send succeeds while revocation checking sits at its secure default, because no certificate is
presented, requested or examined. **Do not read that success as a bypass of the certificate controls:**
there is no certificate on this path for them to act on, and concluding otherwise sends the fix toward
the certificate policy, which cannot help, and away from the transport configuration, which is the only
thing that can. The platform applies no minimum-security floor to the column, so this is a deployment
responsibility: on any row that carries a username use `STARTTLS` or implicit TLS — never `None` — and
prefer strict `STARTTLS` over the "when available" variant so a relay that stops advertising it fails
loudly instead of quietly downgrading. Verify it on the wire rather than from the configuration.

## Environment and development mode

Two independent switches control development behaviour, and **both** must be set for a production
deployment. Setting one and not the other leaves diagnostics exposed.

| Switch | Where | Shipped value now | Production value |
| --- | --- | --- | --- |
| `ASPNETCORE_ENVIRONMENT` | `WebVella.Erp.Site/web.config` for IIS-hosted deployments; otherwise the process environment | `Production` | `Production` |
| `Settings:DevelopmentMode` | All eight `Config.json` files | `"false"` | `"false"` |

`ASPNETCORE_ENVIRONMENT` is what gates the **developer exception page.** Leaving it at `Development`
serves full stack traces, source snippets and environment detail to anyone who triggers an error
(CWE-209, finding H-12). Setting `Production` disables that page, so the user-facing error page
`WebVella.Erp.Web/Pages/error.cshtml` becomes the visible path — **and that page must be verified to
render without leaking internal detail.**

**One caveat matters more than the setting itself.** Flipping this marker did **not** by itself fix the
two unconditional stack-trace responses in `WebVella.Erp.Web/Controllers/WebApiController.cs`, because
neither was guarded by any development-mode check. Those required a code change; see finding H-13 in the
[security audit report](security-audit-report.md). Both now log server-side and return a generic
message, deliberately identical whether the account exists or not so it cannot be used as an
account-existence oracle (`RISK-014`, closed).

Scope, stated precisely: **ten other controller actions still concatenate exception detail into a
response.** Those are pre-existing, sit behind class-level authorization rather than on an anonymous
route, and are outside the agreed change scope — which covers only the two unconditional, anonymously
reachable token sites. They are recorded in the [risk register](risk-register.md). **Setting
`Production` does not suppress them**, so continue to treat authenticated API error bodies as
potentially verbose.

`Settings:DevelopmentMode` gates a distinct richer-error branch in
`WebVella.Erp.Web/Controllers/ApiControllerBase.cs`, so it is an information-disclosure switch and not
merely a convenience. It is also what gates the SMTP accept-any-certificate opt-out, and Development
mode is what suppresses HSTS and HTTPS redirection — so leaving it on disables transport controls
described above.

> **`DevelopmentMode` is fail-safe in both directions, but audit your environment as well as your
> files.** All eight files set it to `"false"` explicitly, and a *missing* value also yields `false`, so
> there is no configuration state in which an absent value silently enables development behaviour. What
> *can* re-enable it is a stray `Settings__DevelopmentMode=true` in the environment, because
> environment variables outrank the JSON provider by design. A clean set of configuration files is
> therefore necessary but not sufficient.

## File storage locations are supplied externally, not committed

Review finding `CR2-F-12` found that the secret scrub had cleared credentials from the eight tracked
`Config.json` files but left two **location** settings populated with real internal values — a UNC path
naming an internal host by address, and a local disk path. Neither is a credential, which is why the
credential-focused scrub passed over them; both are internal-topology disclosure, and both were
published in a public repository. They are now blank in every tracked file and are supplied externally
when the feature is used.

| Configuration key | Environment variable | Notes |
| --- | --- | --- |
| `Settings:FileSystemStorageFolder` | `Settings__FileSystemStorageFolder` | Consumed only when `Settings:EnableFileSystemStorage` is `true`. A placeholder is substituted when the value is blank, so a host whose file-system storage is disabled — the shipped state of all eight configurations — starts normally with the value empty |
| `Settings:CloudBlobStorageConnectionString` | `Settings__CloudBlobStorageConnectionString` | Consumed only when `Settings:EnableCloudBlobStorage` is `true`. Blank is likewise safe while the feature is off, and this value is credential-bearing, so it must never be committed |

Enabling either feature without supplying its location is a configuration error the operator will see
immediately, in the storage subsystem, rather than a silent write to whatever path happened to be
committed.

One consequence worth stating plainly: **abbreviating an address in this document, or blanking it in a
configuration file, does not undo the original disclosure.** Any internal host name or address that was
ever committed should be treated as public and reachability-restricted at the network layer, not merely
edited out of the current revision.

## PostgreSQL is the only supported database

Data access is Npgsql-based throughout, so **no in-memory or SQLite substitution is possible** and any
verification that needs data must run against a real PostgreSQL instance.

**No schema change was required by this remediation and no schema definition statements were emitted at
any point.** The password column is already a 500-character variable-length string, which is why a
modern hash format fits without a migration. The only migration involved is a data-level one, described
in the [credential migration guide](credential-migration.md). Role privileges are covered under
*PostgreSQL role privileges* above.

## The build gate

`Directory.Build.props` at the repository root turns an ordinary build into the combined
static-analysis and composition-analysis gate. It sets exactly these properties:

```text
NuGetAudit          true
NuGetAuditMode      all
NuGetAuditLevel     low
WarningsAsErrors    $(WarningsAsErrors);NU1900;NU1901;NU1902;NU1903;NU1904;NU1905
EnableNETAnalyzers  true
AnalysisLevel       latest-recommended
```

Those six properties are the **whole** of the gate. `AnalysisLevelSecurity` is deliberately not set and
**no global analyzer configuration file is supplied**; both evaluate empty, which the workflow asserts
on every run.

`NU1901`, `NU1902`, `NU1903` and `NU1904` are the dependency-audit diagnostics for low, moderate, high
and critical severity. **A dependency advisory therefore fails the build by design. That is the gate
working, not a defect**, and the advisory must be cleared by upgrading the package or consciously
accepted with a recorded risk acceptance — never by deleting the property.

`NU1900` and `NU1905` are promoted alongside them for a different reason, and it matters: they are not
severities but *data-availability* diagnostics. `NU1900` is raised when the audit source cannot be
reached, `NU1905` when the configured source supplies no vulnerability data at all. Left as warnings,
either one produces the worst possible outcome for a gate — a build that exits `0` while auditing
nothing, with a known High advisory sitting in the graph unreported. **Promoting them converts "the
audit could not run" into a failure instead of a silent pass.** The disclosed trade-off is accepted
deliberately: a transient outage of the advisory database now fails the build rather than passing it
quietly. That is the correct direction for a gate whose purpose is to be trustworthy — an
unavailable-data build is retried, whereas a falsely-green build is shipped. Never demote these two
codes to quieten a flaky network; re-run the job.

One residual is stated plainly because the promotion does **not** close it: when the only configured
package source is a local folder mirror, the restore emits no `NU19xx` diagnostic whatsoever — there is
nothing to promote. That configuration is caught instead by the workflow's negative control, which
restores a project referencing a known-vulnerable package and **fails the job when that restore
succeeds.** Neither mechanism is redundant with the other.

Two further choices need their reasons recorded:

- **The audit mode covers transitive dependencies explicitly rather than by default.** This graph really
  does contain a transitive advisory — MimeKit is reached only through MailKit — so a `direct`-only
  audit would never have reported `GHSA-g7hc-96xr-gvvx`. The default also varies by toolchain version,
  and a gate resting on a floating default is not reproducible.
- **The mechanism is MSBuild rather than a repository-root `.editorconfig`.** The four `.editorconfig`
  files in this repository each declare `root = true`, so a root editor-config would not reach any file
  inside the four subtrees that hold the code this remediation touches. `Directory.Build.props` is
  imported by every project regardless of that scoping — and by directory location rather than by
  solution membership, which is why it reaches all 19 projects while a solution-level command reaches
  17.

> **Contributor warning — always *append* to `WarningsAsErrors`, never assign it.** Write
> `<WarningsAsErrors>$(WarningsAsErrors);CS0168</WarningsAsErrors>`. A project that assigns the property
> instead **silently discards the entire dependency gate for that project**, and the build stays green
> while a High-severity advisory sits in its graph. MSBuild imports `Directory.Build.props` *before* the
> body of the project file, so a later bare assignment overwrites the promotion rather than adding to
> it. Measured: a probe declaring a bare assignment resolved the property with every promoted `NU19xx`
> code gone, then restored a package with a known High advisory at **exit 0 with only a warning**. No
> project in this repository currently does this — verified: none of the 19 manifests mentions
> `WarningsAsErrors`, `TreatWarningsAsErrors` or `NoWarn` at all — but the gate is one careless
> assignment away from not being intact.

### Toolchain pinning and gate reproducibility

`global.json` pins the SDK:

```json
"sdk": { "version": "10.0.302", "rollForward": "disable" }
```

This is a security control, not housekeeping (finding L-07). Both halves of the gate are SDK-version
dependent — the dependency-audit defaults and the analyzer rule set — so an unpinned toolchain means the
same source can produce a different gate result on a different machine, which makes every "the scan is
clean" claim unverifiable.

**`rollForward: disable` is what the tree carries**, and it is the pin: only SDK **10.0.302** builds
this repository, and every other version, patch or feature band, is refused.

**An earlier revision of this guide carried the opposite policy and defended it; the reversal is
recorded rather than quietly overwritten.** That revision set `rollForward: latestPatch`, reasoning that
the audit-mode default and the analyzer rule set are selected by the SDK *feature band*, so holding the
pin on the `10.0.3xx` band delivered the reproducibility the finding asks for while still admitting a
security patch. **That premise is not quite right.** A **patch** can add a rule, change a default
severity or alter an audit default, and every Gate 1 baseline was measured against one exact SDK. A
verdict that can change with no repository change is not a gate, and a *silent* change of verdict is
worse than a loud build failure, because nobody investigates what they cannot see.

**The residual is exactly the one the earlier revision named, and it is accepted as a deliberate
fail-closed.** If SDK 10.0.302 is not installed the build fails immediately with an actionable message
naming the required version. **The remedy is to install that SDK, not to loosen the pin** — loosening it
silently invalidates every Gate 1 baseline, which is why the workflow also asserts on every run that
`AnalysisLevel` still evaluates to `latest-recommended` and that no global analyzer configuration file
is being loaded.

Moving to a newer patch or band is therefore a deliberate, reviewed act — the "explicitly re-baseline
every accepted patch" half of `CR2-F-13`'s own resolution: update the version in `global.json`, re-run
the gate, and re-baseline the recorded per-rule figures in the [remediation log](remediation-log.md) in
the same commit, so the evidence continues to describe the toolchain that produced it.

### What the static-analysis gate actually covers

**A disclosed substitution:** the external SAST tooling named in the audit brief could not be installed
in this environment, so the .NET SDK's built-in Roslyn analyzers are the disclosed substitute. That
keeps the gate dependency-free, which the "no new package dependency" constraint requires, and the
substitution is recorded in the [security audit report](security-audit-report.md) too. **No external
scanner was run, and nothing here should be read as claiming one was.**

The ten security rule families bearing on this audit's findings are: weak hashing, disabled certificate
validation, deprecated transport protocols, SQL and query construction, insecure deserialisation and
unrestricted type-name handling, cross-site scripting and file canonicalisation through the taint
family, regular-expression injection, ASP.NET Core cookie security, disabled token-validation checks,
and hard-coded encryption key with non-random initialisation vector. **Only some of them execute, and
which ones was established by probe rather than by reading documentation.**

| Rule | Count | What it covers |
| --- | --- | --- |
| `CA5350` | 0 | Weak cryptographic algorithm |
| `CA5351` | **5** | Broken hashing algorithm — the retained legacy credential path in `WebVella.Erp/Utilities/CryptoUtility.cs` (4 sites) and `WebVella.Erp/Utilities/PasswordUtil.cs` (1 site) |
| `CA5359` | 0 | Disabled certificate validation |
| `CA5364` | 0 | Deprecated security protocols |

**Every other Security-category rule is inactive at this level**, including `CA2100` (query
construction), `CA2326`/`CA2327`/`CA2328` (type-name handling), `CA5382`/`CA5383` (cookie security),
`CA5390` (hard-coded key), `CA5401`/`CA5402` (non-random initialisation vector), `CA5404` (disabled
token-validation checks) and the whole `CA3001`–`CA3012` taint family. **A zero from an inactive rule is
not evidence** — it is the silence of a disabled rule, and it must not be read as clearance.

Activating them would need a per-rule severity entry, which needs a global analyzer configuration file
to reach past the four `root = true` `.editorconfig` files — and the taint family needs per-rule cost
tuning on top of that merely to terminate: enabled untuned, a whole-solution build exceeded 2,400
seconds without completing and the compiler server began failing under memory load, because one project
compiles 395 Razor views into a single compilation. Neither that file nor the widening is inside the
frozen scope of this gate, **so the weaknesses those rules would have flagged were established by
manual review instead**: every one of C-01 through C-05 and H-01 through H-20 is traceable to a
file-and-line locator in the [security audit report](security-audit-report.md), and the residual tooling
coverage gap is carried as an accepted risk under `RISK-051` and `RISK-052` rather than left as an
unstated assumption.

**All analyzer diagnostics remain warnings; only the six dependency codes are errors.** Promoting
roughly 700 source files' worth of pre-existing analyzer warnings wholesale would demand exactly the
mass refactor the change scope forbids, so no `CA` identifier is added to the promotion above and
build-time code-style enforcement is left off. A full rebuild reports around **3,044 warnings**; none is
newly introduced — every one is pre-existing code the gate made *visible*.

**Analyzer enforcement therefore lives in the workflow rather than in the compiler.** Gate 1 parses the
analyzer log, extracts every Security-category diagnostic and fails the job on any that is not in an
inline, individually justified allow-list — currently **two** `(rule, file)` pairs, both `CA5351` on the
retained legacy verification path. The pass criterion is consequently **zero *unreviewed*
Security-category diagnostics across the remediated files, and no increase over the recorded per-rule
baseline** — narrower and more reviewable than "zero repository-wide", and narrower still because only
four rules execute at all. Those baselines must not be "fixed" by weakening the gate: the `CA5351` sites
exist precisely so already-stored credentials keep working.

Two counting traps are worth knowing, because they made earlier revisions of this section quote every
figure at twice its true value. **MSBuild emits every diagnostic twice** in a solution build — once
inline with a node-number prefix such as `5>`, and once again in the end-of-build summary — so a raw
`grep -c` doubles every total, and the prefix defeats a naive `sort -u` as well. And an **incremental
build undercounts**, because it skips unchanged projects; use `-t:Rebuild` for any comparison.

```bash
sed -E 's/^[[:space:]]*[0-9]+>//' build.log \
  | grep -oE '[^ (]+\([0-9]+,[0-9]+\): warning (CA|CS|NU)[0-9]+' | sort -u | wc -l
```

### Coverage: 17 solution members, 2 explicitly gated non-members

**The decisive precondition first: the project-reference path casing repair must be in place before any
dependency-audit result is trusted.** Until it was, a solution-wide restore failed on a case-sensitive
filesystem and the core project — the one that owned the graph's only High-severity advisory — was
silently absent from the audit. **A clean result obtained before that repair meant nothing at all**
(finding H-19). The workflow asserts the repair on every push.

**A solution-level command reaches 17 projects, not 19, and that is by design.** Neither
`WebVella.Erp.WebAssembly/Server` nor `WebVella.Erp.WebAssembly/Shared` is a member of
`WebVella.ERP3.sln`, so a solution-scoped restore, build or audit does not visit them. **Do not imply
the gate's solution-level step covers all nineteen projects.** They must be covered by the explicit
per-project commands below, and those commands are **required, not optional**. The residual that
prompted `RISK-030` — that a defect appearing only when all 19 resolve together in one graph would go
uncaught — is therefore **not** closed, and is carried as an accepted risk instead; it is narrow,
because neither project is referenced by any of the other 17.

Membership never affected the **gate** itself: `Directory.Build.props` is inherited by directory
location, so both projects always carried all six audit properties and both analyzer properties. What
membership affects is **command coverage** — which projects one invocation visits. Coverage is complete
either way; it just takes three commands instead of one. The reconciliation is **17 members + 2
explicitly gated non-members = 19 manifests**, and the continuous gate proves the arithmetic in three
directions on every run, failing closed if any enumeration comes back empty so that an assertion which
inspected nothing cannot report success.

### The CI secret sweep, and its detection envelope

`.github/workflows/security-scan.yml` substitutes a plain-shell signature sweep for the external secrets
scanner named in the brief. Because it is a substitute, its blind spots matter as much as its coverage.

It asserts that every secret-bearing key in a tracked `Config.json` or `appsettings*.json` is empty,
that `WebVella.Erp/Utilities/CryptoUtility.cs` carries no long embedded literal (finding C-04), and that
`WebVella.Erp/ERPService.cs` assigns no literal seed password (finding C-01). It reports a file path, the
offending key *names* and a verdict only — never a matched value. It matches through five independent
pattern layers — a quoted assignment, the same key names unquoted as in an env-file, provider-specific
literal shapes, a credential-bearing URI, and an ADO.NET-style connection string — with **no path
exclusions at all**, and it collapses newlines first so a key and value split across two lines cannot
evade it. An **empty** value passes, because that is the required end state, while a **whitespace-only**
value fails. A pathspec matching nothing fails closed, so the gate cannot report success having
inspected nothing.

Three things it genuinely cannot see, recorded rather than glossed: a secret under a key name none of
the layers recognises, bounded by this platform supplying every secret from the environment so there is
no second tracked configuration surface for one to hide in; a secret inside a file `grep -I` treats as
binary, measured at 48 of 1,574 tracked files, none of which is a configuration surface; and **a secret
in repository history rather than the checked-out tree** — history rewriting is out of scope, which is
why [*Key rotation is mandatory*](#key-rotation-is-mandatory) is not optional.

### One open decision that does not reach an operator

With the dependency codes promoted to errors a build cannot be green while a vulnerable package remains,
so the object-mapping library **has** been moved to the lowest patched version. The advisory is
therefore **closed** and the dependency gate is green. The consequence of that move — every version
patching the advisory carries a reciprocal licence while the product declares a permissive one and
publishes to nuget.org — is **not** closed. It is recorded as **open, pending owner ratification**,
because what licence a product declares to third parties is an owner decision rather than an engineering
one, and **it is deliberately not resolved here.**

**Nothing about it needs an operator decision, and nothing about it changes how you configure or run the
platform.** The open half is enforced only on the one action that would make it irreversible: `dotnet
pack` fails until an owner records a decision, while `dotnet restore`, `dotnet build`, `dotnet publish`,
running a host and every CI gate step are unaffected. If you are deploying rather than publishing
packages, this does not reach you. The full reasoning, both options and the exact execution steps for
each are in `RISK-001` in the [risk register](risk-register.md).

## Login latency after the credential change

The credential hash uses a deliberately expensive key-derivation function, chosen in line with the OWASP
password-storage guidance. **Login becomes measurably slower, by design** — the cost *is* the control.
It is a **pre-declared and accepted exception** to the engagement's ten-per-cent performance boundary,
and it is **confined to the authentication path**; no other request path is affected. Expect it and do
not treat it as a regression. The measurement and the acceptance are recorded in the
[remediation log](remediation-log.md), and the migration itself — including the rehash-on-next-login
upgrade that keeps existing credentials working — in the
[credential migration guide](credential-migration.md).

## Verifying a deployment

**Read this before running anything below.** The checks split into two groups and must not be run the
same way. Several of the second group *change state*: run against production they would lock out a real
account and write real audit records. The split is the difference between a safe check and a
self-inflicted outage.

### Read-only checks — safe against any environment, including production

```bash
  # 1. Dependency gate: no vulnerable packages, for every project. Three commands, not one.
dotnet restore WebVella.ERP3.sln
dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive
for pj in WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj \
          WebVella.Erp.WebAssembly/Shared/WebVella.Erp.WebAssembly.Shared.csproj; do
  dotnet restore "$pj"
  dotnet list "$pj" package --vulnerable --include-transitive
done

  # 2. Confirm the coverage arithmetic rather than trusting it: 17 members + 2 non-members = 19.
dotnet sln list | grep -c '\.csproj$'      # must print 17
git ls-files '*.csproj' | wc -l            # must print 19

  # 3. The casing repair that makes any audit result trustworthy at all.
grep -rn 'WebVella\.ERP\\' --include=*.csproj . WebVella.ERP3.sln   # must return nothing

  # 4. Static-analysis gate: 0 errors. No analyzer rule is an error, so a security diagnostic
  #    appears here as a WARNING and is enforced by the workflow's Gate 1 instead.
dotnet build WebVella.ERP3.sln -c Debug -t:Rebuild -v n

  # 5. The gate's two deliberate absences.
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -nologo -getProperty:AnalysisLevelSecurity
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -nologo -getItem:EditorConfigFiles | grep -i globalconfig
```

Then the runtime posture, because a host that answers `/` cannot be assumed usable:

```bash
  # 6. All seven headers, on a dynamic response AND on a static asset. Six in Development.
curl -sI https://<host>/login | grep -iE 'content-security-policy|strict-transport|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy'
curl -sI https://<host>/_content/WebVella.Erp.Web/js/wv-lazyload/wv-lazyload.js | grep -ic 'content-security-policy'

  # 7. The content policy must be report-only at this stage, and the enforcing header ABSENT.
curl -sI https://<host>/login | grep -ic 'content-security-policy-report-only'
curl -sI https://<host>/login | grep -icE '^content-security-policy:'

  # 8. /login must NOT be 500. Over HTTPS expect 200; over plaintext expect 307 to https,
  #    or 200 when a trusted proxy forwards the HTTPS scheme.
curl -s -o /dev/null -w '%{http_code}\n' https://<host>/login

  # 9. A listed origin completes preflight; an unlisted one receives no CORS header at all.
curl -sI -X OPTIONS -H 'Origin: https://listed.example.com' \
     -H 'Access-Control-Request-Method: GET' https://<host>/api/v3/en_US/meta/entity/list
```

Two verification traps are worth stating, because both look like defects and neither is:

- **Verify against *published* output.** If you run an unpublished build directory with
  `ASPNETCORE_ENVIRONMENT=Production`, every static-web-asset URL returns **`405`** instead of the asset
  and the site renders unstyled — these hosts ship no `wwwroot`, so all static content arrives from
  Razor Class Libraries and the static-web-assets manifest is loaded only in Development unless the host
  builder opts in. The seven headers *are* still present on that `405`, which is precisely why the
  symptom is easy to misread. Two correct responses: publish and verify the published output, or have
  the host builder call `UseStaticWebAssets()` explicitly. **The tempting third option — setting
  `Development` to make the styling come back — silently undoes two remediations at once**, re-enabling
  the developer exception page (H-12) and disabling HSTS and HTTPS redirection (H-15). Recorded as
  `RISK-031`.
- **A `warn:` line about transport security means the condition was detected but only reported.** In
  Development that is expected. Outside Development it means no endpoint was declared, so verify the
  server defaults immediately: `/login` answers 500 if they resolve to plaintext only (`RISK-126`).

### State-changing checks — never against production

Use a throwaway account on a non-production instance, and take a database backup first.

```bash
  # 10. Fail-fast negative test: start a host with a required secret removed. It must ABORT
  #     naming the missing setting and nothing else. If it starts, a fallback still exists.
env -u Settings__EncryptionKey ASPNETCORE_ENVIRONMENT=Production dotnet <Host>.dll

  # 11. Transport negative test: with only a plaintext endpoint and none of ASPNETCORE_HTTPS_PORT /
  #     HTTPS_PORT / Settings__ForwardedHeaders__KnownProxies set, a non-Development host must ABORT
  #     and must never log "Now listening on".
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS='http://127.0.0.1:5199' dotnet <Host>.dll

  # 12. Login throttling: a sixth consecutive failure must be refused.
  #     STATE CHANGE - this LOCKS OUT the account it is run against. Throwaway accounts only.
```

Also confirm, by exercising the application rather than by reading source: that a legacy credential
still signs in and is transparently rehashed; that the previously seeded default administrator
credential no longer authenticates; that a guest-role account cannot create users or roles; that no API
response returns a password hash for any role; that the file move and delete actions are refused for a
non-owner; and that an uploaded markup or vector file downloads as an attachment rather than rendering
inline.

For the mail transport, exercise the revocation path against your own relay rather than trusting the
setting: send a test message with the revocation setting absent. If it fails with a chain status of
**only** the CRL bullet, your relay's chain has no reachable revocation source — fix the chain, or set
the narrowing switch and record `RISK-060`. Re-send afterwards; it must deliver, and the host log must
carry exactly one notice.

**Cleanup after the state-changing group:** restart the instance to clear the in-process throttle
counters, or wait out the fifteen-minute window; delete the throwaway account and any guest-role
principal created for the authorization checks; restore the database backup or re-provision; and review
the audit log and discard the records these checks generated, so a later reader does not mistake a
deliberate lockout for a real attack.

## Method and limitations

Stated plainly, so the confidence attached to each claim is visible.

- **Every setting name, default and validation rule above was read from the source** —
  `WebVella.Erp/ErpSettings.cs`, `WebVella.Erp/Utilities/CryptoUtility.cs`,
  `WebVella.Erp.Web/ErpMvcExtensions.cs`, `WebVella.Erp.Web/Services/AuthService.cs`,
  `WebVella.Erp.Web/Services/LoginThrottleService.cs`,
  `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs` and the host `Startup.cs` files — not from
  the specification. **Where the code and the specification disagreed, the code is what is documented.**
- **The gate values and the toolchain pin were read from `Directory.Build.props` and `global.json`
  themselves**, not from a plan describing them. Where an earlier plan described four promoted audit
  codes and a band-wide roll-forward policy, the tree carries six codes and an exact pin, and the tree
  is what this page documents.
- **The host table for the token signing key was produced by inspecting all eight shipped configuration
  files**, not inferred from which hosts appear to use tokens.
- **No external SAST, dependency or secrets scanner was installed or run.** Each is substituted by a
  mechanism described above, and each substitution is disclosed here and in the
  [security audit report](security-audit-report.md).
- **No secret value is reproduced anywhere in this document**, including the removed default encryption
  key. Recovering it is described as a procedure against your own repository history instead, because
  publishing it here would reintroduce the finding and fail the secrets gate.
- **The encryption-key impact assessment is based on a repository-wide search** for callers of the
  encrypt and decrypt members, which found only commented-out ones. It cannot account for custom plugin
  code in your own deployment, which is why that step is written as a conditional.
- **Line numbers are used only where a value was disclosed at a specific line.** Elsewhere the enclosing
  file and member name are the durable locator, because line numbers drift as files are edited.
- **This page was consolidated from four separately written angles.** Each was accurate when written and
  the overlap between them had begun to contradict itself — one passage described the configuration
  files as still carrying live values, another described the content policy as carrying a `report-uri`
  directive that had been removed. Both are corrected above rather than left standing beside the current
  text. Where this page records a reversal, the superseded position is stated with it, so an operator who
  followed an earlier revision can tell which way it finally landed.

## Related documents

- [Security audit report](security-audit-report.md) — every finding, in the mandated eight-field format.
- [Remediation log](remediation-log.md) — what changed, per vulnerability class, with verification.
- [Risk register](risk-register.md) — accepted risks, open decisions and residual exposure.
- [Credential migration guide](credential-migration.md) — how stored credentials are upgraded.
- [Security policy](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) — how to report a vulnerability.
- [Third-party library inventory](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) — dependency versions, licences and advisory state.
- [Project README](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/README.md) — the shorter required-secrets summary this page expands.
