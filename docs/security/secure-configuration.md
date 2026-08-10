# Secure Configuration

> **Authority split.** This guide **is** the single authority for **what an operator must configure** —
> the required-settings inventory below is normative. It is **not** the authority for gate or
> requirement *status*; that is the audit report's
> [Status at this revision, gate by gate](security-audit-report.md#status-at-this-revision-gate-by-gate) section, which governs wherever
> the two disagree. Recorded under code-review findings `MAJ-06` and `MAJ-12`.

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
| Missing-secret behaviour | Fail fast for the **two** secrets every host needs — `Settings:ConnectionString` and `Settings:EncryptionKey`. `WebVella.Erp/ErpSettings.cs` aborts startup with an actionable message naming **every** missing or weak one of those at once; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back, and the compiled-in default key is gone. The token signing key is **not** in this class — it degrades a capability instead of stopping startup, which is set out under [*Required settings*](#required-settings) |
| Known published defaults | Rejected by SHA-256 digest comparison, so this repository's own example encryption key and token signing key cannot be used even if supplied deliberately. The digests are stored rather than the literals, so neither the source nor this page reintroduces the secret it eliminates |
| Response security headers | All seven emitted by `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, registered once through `AddErp` and ordered in **all seven** hosts ahead of `UseResponseCompression` and both `UseStaticFiles` calls |
| Content-Security-Policy | Emitted in **report-only** mode carrying the mandated value **verbatim** and nothing else. There is **no `report-uri` directive and no collection endpoint**; both were removed, because appending `report-uri` altered the mandated value and the collector's early return could answer a request without attaching the other six headers. Reports are read from the browser console during the rollout instead (`RISK-022`) |
| Transport security | `UseHsts()` then `UseHttpsRedirection()` in all seven hosts, guarded to non-Development and ordered **after** `UseCors` so cross-origin preflight is not broken by a redirect. A startup guard refuses a non-Development host that can see no HTTPS request path at all |
| Cookies | Authentication: `SecurePolicy=Always` **unconditionally, including in Development**, `SameSite=Lax`, `HttpOnly`, a 24-hour sliding idle window and a 7-day absolute horizon. Antiforgery: `SecurePolicy=Always` outside Development and `SameAsRequest` in Development, retaining the framework's `SameSite=Strict` default |
| Data Protection | Per-application discriminator bound to the host's application name, so one host cannot decrypt another's authentication cookie; the key-ring directory is opt-in through `Settings:DataProtectionKeyDirectory` (`RISK-115`) |
| Rate limiting | `UseRateLimiter()` in all seven hosts — a per-address fixed window of 600 requests per minute — positioned after both static-file middlewares so assets are never throttled |
| Login throttling | Per-account and per-address counters in a **durable, shared** store — the existing `plugin_data` table under the reserved `wv_sec_` key prefix, mutated by atomic row-locked read-modify-write — consulted at **both** credential entry points: the login page and the anonymous bearer-token route. A lockout therefore survives a restart and spans instances, and the throttle fails closed when the store cannot be reached (`RISK-008`, review finding `H-OPEN-02`) |
| Build gate | `Directory.Build.props` — dependency auditing at `all`/`low` with **six** NuGet audit diagnostics promoted to errors. .NET analyzers run with `AnalysisLevel=latest-recommended` **and `AnalysisLevelSecurity=latest-all`**, which arms the whole Security category. **No** global analyzer configuration file is supplied, and the workflow fails if one appears — the category level is delivered through a property the SDK honours rather than through a `.globalconfig`. One family is excluded: `CA3001`–`CA3012` for `WebVella.Erp.Web` alone, on a measured termination bound, and the workflow asserts that exclusion in both directions so it can neither be lost nor widened (`RISK-051`, `RISK-138`). All analyzer diagnostics stay warnings at the project level and are enforced instead by the workflow's Gate 1 allow-list. Inherited by **19 of 19** projects, because the file is directory-scoped rather than solution-scoped |
| Toolchain pin | `global.json` pins `10.0.302` with `rollForward: disable`, so only that exact SDK builds the repository and the gate's recorded results are reproducible by construction (review findings `GATE-02` and `CR2-F-13`) |
| Shipped secrets | **Scrubbed.** All eight `Config.json` files carry empty secret values and `DevelopmentMode: false`, `web.config` sets `Production`, and the seeded administrator password is no longer a literal (`RISK-021`, closed) |
| Mail transport | **Encrypted on every path, and no path can opt out of encryption.** The five MailKit send paths validate the server certificate by default including revocation, and no setting can turn revocation off (`RISK-060`); since review finding `H-OPEN-03` they additionally **refuse** a cleartext connection outside Development — `None` is rejected and `Auto`/`StartTlsWhenAvailable` are raised to mandatory `StartTls`, so a relay that does not offer the extension is refused rather than downgraded. The separate diagnostic notification client in `WebVella.Erp.Web/Services/MailService.cs` used to negotiate no TLS at all; since review finding `M-OPEN-03` it sets `EnableSsl`, is disposed and carries a 15-second timeout, with no development escape hatch — see *Mail transport* |
| Origins | No host applies `AllowAnyOrigin()` any longer (`RISK-013`, closed). Both formerly permissive hosts read `Settings:Cors:AllowedOrigins` and deny every origin when it is absent outside Development |
| Anonymous error paths | Both bearer-token routes return a generic message outside Development and retain their server-side log record (`RISK-014`, closed) |

## Required settings

`ErpSettings.Initialize` validates these at startup and aborts with an actionable message listing
**every** missing value at once, rather than one per restart. Only setting *names* ever appear in that
message — never values, prefixes, lengths or digests — so a startup failure cannot leak key material
into a console, a log file or a crash report (CWE-532).

**Two categories, and the difference is not cosmetic.** A missing value in the first table stops the
process; a missing value in the second one lets the process start and takes a capability away. The token signing key does **not** belong in the *first* table: its absence is not startup-fatal. Reading the wrong category is
operationally expensive in both directions: an operator who believes a keyless host will refuse to
start will read a *successfully started* host as proof the key was supplied, when in fact bearer
authentication is silently off; and an operator who believes the connection string is merely degrading
will hunt for a runtime symptom that never arrives, because the process never came up. Reproduce the
distinction directly — `ValidateRequiredSecurityConfiguration` in `WebVella.Erp/ErpSettings.cs`
accumulates into `missingSecrets` only for `Settings:ConnectionString` and `Settings:EncryptionKey`
(and the weak, published and non-ASCII variants of the latter), and `Settings:Jwt:Key` is never added
to it:

```bash
# Every setting name that can appear in the startup-abort message:
grep -n 'missingSecrets +=' WebVella.Erp/ErpSettings.cs
# What happens instead when the signing key is unusable - a warning, not a throw:
grep -n 'ErpSettings\[2\]' WebVella.Erp/ErpSettings.cs
```

### Category 1 — the settings the platform refuses to start without

Absence, or an unacceptable value, throws `InvalidOperationException` out of
`ErpSettings.Initialize` before `IsInitialized` is set. The host does not start.

| Setting key | Environment-variable form | Required | Purpose |
| --- | --- | --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` | **Always** | PostgreSQL connection. Consumed by `DbContext`, `ERPService` and every repository immediately after initialisation, so no host functions without it (finding H-05) |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` | **Always** | Symmetric key used by `CryptoUtility` for encrypted field values. There is no longer a compiled-in default (finding C-04). Also refused as *unacceptable*: shorter than the length floor, too few distinct characters, equal to this repository's published example, or containing any character outside US-ASCII |

### Category 2 — the setting whose absence disables a capability instead

| Setting key | Environment-variable form | Consequence when absent or unacceptable | Purpose |
| --- | --- | --- | --- |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` | **Startup proceeds.** The bearer-token issue and refresh routes disable themselves and refuse every request, and every presented bearer token fails validation. Cookie login is unaffected. A `warn:` line is written to standard error **only if** a `Settings:Jwt` section exists — a host that declares no section is not warned about routes it never intended to serve | HMAC signing key for bearer tokens (finding H-04) |

The double underscore is configuration nesting, not a typo: `Settings__Jwt__Key` maps to the
`Settings:Jwt:Key` path, which in the JSON file is `{ "Settings": { "Jwt": { "Key": … } } }`. It is the
standard .NET convention and it is what makes it possible to override a nested value without editing
the file.

### Everything else an operator supplies

| Setting key | Environment-variable form | Required | Purpose |
| --- | --- | --- | --- |
| `Settings:Jwt:Issuer` | `Settings__Jwt__Issuer` | No — defaults to `webvella-erp` | Expected token issuer |
| `Settings:Jwt:Audience` | `Settings__Jwt__Audience` | No — defaults to `webvella-erp` | Expected token audience |
| `Settings:InitialAdministratorPassword` | `Settings__InitialAdministratorPassword` | **First provisioning only**, and when upgrading an installation still carrying the published default administrator password | The first administrator's password on a new database. **Required**: absent, provisioning is refused inside its own transaction and nothing is persisted — the platform never invents a value, because it would have to disclose it through a captured output stream. Present, it must satisfy the password policy or **provisioning aborts** — see [the password policy below](#the-initial-administrator-password-must-satisfy-the-password-policy) |
| `Settings:EmailSMTPPassword` | `Settings__EmailSMTPPassword` | Only when e-mail is enabled | Relay credential. Ships empty |
| `Settings:EmailSMTPAllowInvalidCertificates` | `Settings__EmailSMTPAllowInvalidCertificates` | No | Accepts **any** SMTP server certificate. Honoured only alongside `Settings:DevelopmentMode`; refused, and reported once per process, anywhere else. Never set it in production |
| `Settings:DevelopmentMode` | `Settings__DevelopmentMode` | No — defaults to `false` | Must be `false` outside development. Gates a richer-error branch in `WebVella.Erp.Web/Controllers/ApiControllerBase.cs` (finding H-12) |
| `Settings:Cors:AllowedOrigins` | `Settings__Cors__AllowedOrigins` | `WebVella.Erp.Site` and `WebVella.Erp.Site.Project`, when a browser client calls either host cross-origin | Origin allow-list for those two hosts (finding H-14). Full resolution table under [*Cross-origin policy*](#cross-origin-policy) |
| `Settings:ForwardedHeaders:KnownProxies` and `:KnownNetworks` | `Settings__ForwardedHeaders__KnownProxies`, `Settings__ForwardedHeaders__KnownNetworks` | Only behind a TLS-terminating reverse proxy | Which proxies' `X-Forwarded-*` headers are trusted. Deny-by-default: unset means the middleware is not registered at all |
| `Settings:DataProtectionKeyDirectory` | `Settings__DataProtectionKeyDirectory` | No | Durable directory for the key ring that encrypts and signs every authentication cookie. Absent, keys are transient and a restart invalidates issued cookies (`RISK-115`, finding `CR2-F-11`) |
| `Settings:FileSystemStorageFolder` | `Settings__FileSystemStorageFolder` | Only when `Settings:EnableFileSystemStorage` is `true` | Root folder for file-system-backed storage. Blanked in all eight tracked files (finding `CR2-F-12`) |
| `Settings:CloudBlobStorageConnectionString` | `Settings__CloudBlobStorageConnectionString` | Only when `Settings:EnableCloudBlobStorage` is `true` | Credential-bearing, so it must never be committed. Blanked in all eight tracked files (finding `CR2-F-12`) |
| `Settings:TimeZoneName` | `Settings__TimeZoneName` | **In practice, on any non-Windows host** | Time-zone identifier. See [*Time zone identifier on non-Windows hosts*](#time-zone-identifier-on-non-windows-hosts) |
| `ASPNETCORE_ENVIRONMENT` | hosting environment | Recommended | Must **not** be `Development` in production (finding H-12). It also selects the Development-only cross-origin fallbacks |
| `DOTNET_ENVIRONMENT` | hosting environment | Recommended **for `WebVella.Erp.ConsoleApp` only** | **Takes precedence over `ASPNETCORE_ENVIRONMENT` in the console host** (finding `MIN-02`). See [*The console host reads `DOTNET_ENVIRONMENT` first*](#the-console-host-reads-dotnet_environment-first) |

All eight run configurations need the connection string and the encryption key: the seven site hosts
`WebVella.Erp.Site`, `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next`, `WebVella.Erp.Site.Project` and
`WebVella.Erp.Site.Sdk`, plus `WebVella.Erp.ConsoleApp`.

One nuance, recorded rather than recommended: `ErpSettings` still honours two **legacy misspelled**
keys for backwards compatibility — `Settings:EncriptionKey` as a fallback for the encryption key, and
`Settings:EnableBackgroungJobs` as a fallback for `Settings:EnableBackgroundJobs`, the misspelling that
seven of the eight shipped files actually used. Use the correctly spelled names; the aliases exist only
so that existing deployments keep working and are not recommended for new configuration.

### The complete inventory of every configuration key the platform reads

The two tables above cover the settings an operator normally has a decision to make about. **This table is the exhaustive one.** A guide that claims to be an authoritative inventory while naming 23 of the 41 keys the source actually reads — omitting, among
others, every SMTP server, port, username, sender and recipient setting, which is precisely the group an
operator configuring mail delivery needs. Every row below was generated from the source tree, not from
memory, and the sweep is reproducible:

```bash
# Every configuration key read anywhere in the tree, deduplicated:
grep -rhoE '"(Settings|ApiUrlTemplates|SecurityHeaders|Development):[A-Za-z0-9_:]+"' \
  --include='*.cs' --include='*.cshtml' . | sort -u
#   39 lines, which is NOT the same as 39 keys - see the note below the block

# Bidirectional check - every key read from source appears in this guide, and
# every key this guide names is read from source:
grep -rhoE '"(Settings|ApiUrlTemplates|SecurityHeaders|Development):[A-Za-z0-9_:]+"' \
  --include='*.cs' --include='*.cshtml' . | tr -d '"' | sort -u > /tmp/from-source.txt
grep -ohE '`(Settings|ApiUrlTemplates|SecurityHeaders|Development):[A-Za-z0-9_:]+`' \
  docs/security/secure-configuration.md | tr -d '`' | sort -u > /tmp/from-docs.txt
comm -23 /tmp/from-source.txt /tmp/from-docs.txt   # read but undocumented - must be empty
```

**Read the sweep's output carefully: 39 lines, 41 keys, and the gap is a limitation of the pattern
rather than a missing row.** The pattern can only see a key read by its **full literal path**. **Three**
keys are read *section-relative* — `WebVella.Erp.Web/ErpMvcExtensions.cs` resolves
`GetSection("Settings:ForwardedHeaders")` once and then reads `section["KnownProxies"]`,
`section["KnownNetworks"]` and `section["ForwardLimit"]` — so the literal strings
`Settings:ForwardedHeaders:KnownProxies`, `Settings:ForwardedHeaders:KnownNetworks` and
`Settings:ForwardedHeaders:ForwardLimit` never appear in source and the sweep cannot match them. What it
matches instead is the section name `Settings:ForwardedHeaders`, which is one line but not a key. So: 39
lines, minus 1 section, plus **3** section-relative leaves, equals **41 keys**. *(This paragraph read
"two … equals 40" until code-review finding `MED-02`, which found `ForwardLimit` read at
`ErpMvcExtensions.cs` and documented nowhere in the inventory. Both the count and the arithmetic are
corrected, and the third leaf now has its own row in the table above.)* The reverse comparison therefore
reports **four** keys as "documented but not read", and all four are correct as documented: those three,
plus `Settings:EmailSMTPCheckCertificateRevocation`, which this guide names **precisely in order to
record that it does not exist** — see its row below. Anyone re-deriving the inventory should add a second
sweep for `GetSection` reads rather than trusting the single pattern; the single pattern is retained
because it is what the original inventory was built from and silently replacing it would hide this
qualification.

The reverse direction, `comm -13`, is **not** expected to be empty, and the reason is worth stating so
nobody reads it as invented keys. It reports exactly
`Settings:ForwardedHeaders:KnownProxies`, `Settings:ForwardedHeaders:KnownNetworks` and
`Settings:ForwardedHeaders:ForwardLimit`, which are read
by *relative* name — `BuildForwardedHeadersOptions` binds the section once and then indexes it as
`section["KnownProxies"]`, `section["KnownNetworks"]` and `section["ForwardLimit"]` — so their absolute
paths never appear as literals in the source and an absolute-path sweep cannot see them. They are
genuinely read; the sweep is what is partial. Confirm
directly:

```bash
grep -n 'section\["Known' WebVella.Erp.Web/ErpMvcExtensions.cs
```

Two conventions apply to the whole table. The environment-variable form of any key is the key with each
`:` replaced by `__`, so it is not repeated per row. And *"none"* in the **Default** column means the
value is genuinely `null` when unset — the platform does not substitute anything — whereas a stated
default is a literal the code supplies.

| Setting key | Default when unset | Applicability | Read at |
| --- | --- | --- | --- |
| `Settings:ConnectionString` | none — **startup aborts** | Every host and the console application | `ErpSettings.cs` |
| `Settings:EncryptionKey` | none — **startup aborts** | Every host and the console application | `ErpSettings.cs` |
| `Settings:EncriptionKey` | none | **Legacy misspelling**, consulted only when `Settings:EncryptionKey` is blank | `ErpSettings.cs` |
| `Settings:Jwt` | n/a — existence probe | Presence decides only whether an unusable key is reported on standard error | `ErpSettings.cs` |
| `Settings:Jwt:Key` | none — **capability degrades, startup proceeds** | The two token-issuing hosts; the routes exist on all seven | `ErpSettings.cs`, `WebVella.Erp.Site/Startup.cs`, `WebVella.Erp.Site.Project/Startup.cs` |
| `Settings:Jwt:Issuer` | `webvella-erp` | As above | same three files |
| `Settings:Jwt:Audience` | `webvella-erp` | As above | same three files |
| `Settings:InitialAdministratorPassword` | none — **provisioning aborts**; no value is ever generated | First provisioning, and when upgrading an installation still carrying the published default password | `ERPService.cs` |
| `Settings:DevelopmentMode` | `false` | Every host. Must stay `false` outside development (finding H-12) | `ErpSettings.cs` |
| `Settings:Cors:AllowedOrigins` | none — every origin denied outside Development | `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` only | both `Startup.cs` files |
| `Settings:ForwardedHeaders` | n/a — bound as a **section**, not read as a leaf | Only behind a TLS-terminating reverse proxy. `BuildForwardedHeadersOptions` takes `GetSection("Settings:ForwardedHeaders")` and then reads the two child keys below by relative name, which is why the section itself appears in a source sweep while the children do not | `ErpMvcExtensions.cs` |
| `Settings:ForwardedHeaders:KnownProxies` and `Settings:ForwardedHeaders:KnownNetworks` | none — with both empty the middleware is **not registered at all**, which is the deny-by-default position | Only behind a TLS-terminating reverse proxy. Entries are separated by `,` or `;` | `ErpMvcExtensions.cs` (`section["KnownProxies"]`, `section["KnownNetworks"]`) |
| `Settings:ForwardedHeaders:ForwardLimit` | `1` — the `DefaultForwardedHeadersForwardLimit` constant, i.e. exactly one trusted proxy entry is consumed | Only behind a TLS-terminating reverse proxy, and only when that middleware is registered at all. Set it to the number of trusted proxies chained in front of this application. **Validated, not guessed:** a value that is not a positive whole number — zero, negative, or unparseable — **aborts startup** with an `InvalidOperationException` naming the key; blank or absent falls back to the default. This row was missing from the inventory until code-review finding `MED-02` | `ErpMvcExtensions.cs` (`section["ForwardLimit"]` → `ParseForwardLimit`) |
| `Settings:DataProtectionKeyDirectory` | none — keys are transient, so a restart invalidates issued cookies | Every host that must survive a restart or run more than one instance | `ErpMvcExtensions.cs` |
| `SecurityHeaders:ContentSecurityPolicyReportOnly` | `true` — report-only | Every host. `false` emits the enforcing header; an uninterpretable value **aborts startup** rather than being guessed | `ErpMvcExtensions.cs` |
| `Settings:TimeZoneName` | `FLE Standard Time` | Every host. **A Windows-only identifier, so a non-Windows host must override it** — see [*Time zone identifier on non-Windows hosts*](#time-zone-identifier-on-non-windows-hosts) | `ErpSettings.cs` |
| `Settings:Lang` | `en` | Every host. Two-letter interface language | `ErpSettings.cs` |
| `Settings:Locale` | `en-US` | Every host. Also read directly by `WebVella.Erp.Site/Startup.cs` for request localisation and supported cultures | `ErpSettings.cs`, `WebVella.Erp.Site/Startup.cs` |
| `Settings:JsonDateTimeFormat` | `yyyy-MM-ddTHH:mm:ss.fff` | Every host. Serialisation format for date-time values | `ErpSettings.cs` |
| `Settings:CacheKey` | today's date as `yyyyMMdd` | Every host. Cache-busting suffix for static assets; the date default rotates it daily | `ErpSettings.cs` |
| `Settings:AppName` | none | Every host. Application name shown in the interface | `ErpSettings.cs` |
| `Settings:NavLogoUrl` | none | Every host. Navigation logo image | `ErpSettings.cs` |
| `Settings:SystemMasterBackgroundImageUrl` | none | Every host. Background image for the system master layout | `ErpSettings.cs` |
| `Settings:ShowAccounting` | `false` | Every host. Reveals accounting interface elements | `ErpSettings.cs` |
| `Settings:EnableBackgroundJobs` | **`true`** | Every host. Note the default is *on*: set it `false` explicitly on any instance that must not run jobs | `ErpSettings.cs` |
| `Settings:EnableBackgroungJobs` | `true` | **Legacy misspelling**, consulted only when `Settings:EnableBackgroundJobs` is blank. Seven of the eight shipped files used this spelling | `ErpSettings.cs` |
| `Settings:EnableFileSystemStorage` | `false` | Every host | `ErpSettings.cs` |
| `Settings:FileSystemStorageFolder` | `c:\erp-files` — **a Windows path, so a non-Windows host must override it** | Only when `Settings:EnableFileSystemStorage` is `true`. Blanked in all eight tracked files (finding `CR2-F-12`) | `ErpSettings.cs` |
| `Settings:EnableCloudBlobStorage` | `false` | Every host | `ErpSettings.cs` |
| `Settings:CloudBlobStorageConnectionString` | `disk://path=c:\erp-files` | Only when `Settings:EnableCloudBlobStorage` is `true`. **Credential-bearing** — never commit it. Blanked in all eight tracked files (finding `CR2-F-12`) | `ErpSettings.cs` |
| `Settings:EmailEnabled` | `false` | The mail plugin. Nothing is sent while this is false | `ErpSettings.cs` |
| `Settings:EmailSMTPServerName` | none | Only when e-mail is enabled | `ErpSettings.cs` |
| `Settings:EmailSMTPPort` | `25` | Only when e-mail is enabled. **A non-parsing value throws** rather than falling back | `ErpSettings.cs` |
| `Settings:EmailSMTPUsername` | none | Only when the relay requires authentication | `ErpSettings.cs` |
| `Settings:EmailSMTPPassword` | none | Only when the relay requires authentication. **Credential-bearing.** Ships empty | `ErpSettings.cs` |
| `Settings:EmailFrom` | none | Only when e-mail is enabled. Default sender address | `ErpSettings.cs` |
| `Settings:EmailTo` | none | Diagnostic and exception notification recipient (`RISK-030`) | `ErpSettings.cs` |
| `Settings:EmailSMTPAllowInvalidCertificates` | `false` | Accepts **any** relay certificate. Honoured **only** alongside `Settings:DevelopmentMode`; refused elsewhere and reported once per process. Never set it in production | `SmtpService.cs` |
| `Settings:EmailSMTPCheckCertificateRevocation` — **DOES NOT EXIST** | n/a | No code reads this key. Certificate revocation checking is **unconditional**: nothing assigns `client.CheckCertificateRevocation`, so MailKit's own default of `true` applies on every send path and no configuration turns it off. A relay whose chain names no reachable CRL distribution point or OCSP responder therefore **cannot be used from a Production deployment** — verified at runtime, where such a relay fails with *unable to get certificate CRL* even though the chain, dates and host name all verify. Use a relay whose chain publishes a reachable revocation endpoint (`RISK-060`) | `SmtpService.cs` |
| `ApiUrlTemplates:FieldInlineEdit` | `/api/v3/en_US/record/{entityName}/{recordId}` | Every host. Endpoint template the inline field editor posts to | `ErpSettings.cs` |
| `Development:TestEntityName` | `test` | Development scaffolding only. Not a `Settings:` key and not part of the security posture | `ErpSettings.cs` |
| `Development:TestRecordId` | a fixed GUID | Development scaffolding only; a non-parsing value is ignored rather than fatal | `ErpSettings.cs` |

Two keys named in this table are read by the Blazor WebAssembly client rather than by a host, and are
listed for completeness rather than as operator settings: the client reads `ServerUrl` from its own
configuration in `WebVella.Erp.WebAssembly/Client/Services/ConfigurationService.cs`. It is not a
`Settings:` key and carries no secret.

Hosting settings that are **not** platform configuration keys — `ASPNETCORE_ENVIRONMENT`,
`ASPNETCORE_URLS`, `HTTPS_PORT` and the `Kestrel:Endpoints` and
`Kestrel:Certificates:Default:*` family — are the runtime's own and are covered under
[*Transport security*](#transport-security).

### Why the token signing key degrades instead of aborting

Demanding a signing key from every host would stop the ones that issue no tokens from starting at all,
which the preservation requirement forbids. So the key is never demanded as a condition of startup on
any host. What the `Settings:Jwt` section controls is only whether the operator is **told**: a host
that declares a section plainly intends to serve tokens, so a silently disabled capability there is
itself a defect worth reporting, while a host that declares none is left alone. Of the eight shipped
configuration files, exactly two declare a section.

| Host | Declares `Settings:Jwt` | Needs a key to serve tokens | Startup blocked without one | Warned on standard error |
| --- | --- | --- | --- | --- |
| `WebVella.Erp.Site` | Yes | Yes | **No** | Yes |
| `WebVella.Erp.Site.Project` | Yes | Yes | **No** | Yes |
| `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Sdk` | No | Only if tokens are wanted | **No** | No |
| `WebVella.Erp.ConsoleApp` | No | No — it hosts no token routes | **No** | No |

The token routes are defined in `WebVella.Erp.Web`, so they exist on all seven hosts whether or not the
host declares a section; that is precisely why the key must be *screened* rather than *assumed*. Where
a key is absent or unacceptable, the token issue and refresh routes **refuse cleanly** and the bearer
registration is screened so it can neither use nor throw on the bad key — the hard-coded fallback that
used to cover this was removed (finding H-04). The authentication *scheme* still exists, because the platform's policy selector forwards
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
back to a generated password, because silently substituting a different password than the operator asked
for is worse than refusing — and because a generated value would have to be disclosed through an output
stream every hosting substrate captures and retains. There is no generated fallback anywhere in the
administrator path.

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

The role in `Settings:ConnectionString` must be a **`SUPERUSER`** on the current codebase. `SUPERUSER` is necessary, not optional: an operator who provisions a least-privilege role instead will find the application unable
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
- **User secrets now work for every executable, and this was corrected rather than left as a
  caveat.** That was accurate at the time and was true of **seven** of the eight executables, not
  one — only `WebVella.Erp.Site` declared an identifier, so for the console application and six of
  the seven hosts the documented developer channel resolved no store and silently loaded nothing.
  `AddUserSecrets` is called with `optional: true`, so it could not even fail loudly. **All eight
  now declare a stable `UserSecretsId`**, so the effective Development chain is the JSON file, then
  environment variables, then that executable's own store. `optional: true` is retained
  deliberately: it keeps a developer who has never created a store from hitting a hard failure, and
  outside Development the provider is not registered at all.

  A store is keyed by the identifier, so **a value set for one executable is invisible to the others** and
  `--project` is required:

  | Executable | `UserSecretsId` |
  | --- | --- |
  | `WebVella.Erp.Site` | `3d84b9b1-534b-473b-b0d8-f6b47f33297b` |
  | `WebVella.Erp.Site.Crm` | `7cdbf11d-ae56-5ee3-907d-2a50d47825c9` |
  | `WebVella.Erp.Site.Mail` | `433b5aa4-8f48-5924-b1c5-a2b91b06b85c` |
  | `WebVella.Erp.Site.MicrosoftCDM` | `1f2442e7-e410-5bd1-8ec1-b82f4388f95c` |
  | `WebVella.Erp.Site.Next` | `383b4579-6bb3-55f1-a998-47adfcf25dc6` |
  | `WebVella.Erp.Site.Project` | `921179fc-4177-5603-bbf9-9c8a43db8cc3` |
  | `WebVella.Erp.Site.Sdk` | `e902f2c3-b59e-5aef-b217-6501e03e6a44` |
  | `WebVella.Erp.ConsoleApp` | `9b3e4423-9b40-55c3-9abc-bcd7bcf79685` |

  ```bash
  # once per executable you intend to start, in Development only
  dotnet user-secrets set "Settings:ConnectionString" '<value>' --project WebVella.Erp.Site
  dotnet user-secrets set "Settings:EncryptionKey"    '<value>' --project WebVella.Erp.Site
  dotnet user-secrets list --project WebVella.Erp.Site
  ```

  **Do not run `dotnet user-secrets init`.** It generates a *new* identifier and writes it into the tracked
  project file, which orphans every store already created against the value above. The identifiers are
  derived deterministically from each project's name, are stable on purpose, and are **not secrets**: the
  store lives outside the repository, in the user profile, so naming one here adds nothing secret to the
  tree and has no effect in any non-Development posture.

  Verified end to end rather than assumed: with every `Settings__` environment variable unset and the
  environment set to Development, a connection string supplied **only** through the store reached
  configuration for both the console executable and the shared platform chain, each failing at the database
  with `3D000` for the deliberately non-existent database named in the store — and with the store cleared,
  startup aborted with `required security configuration is missing: - 'Settings:ConnectionString'`, so the
  fail-fast validation is unaffected.
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

**Both the defect and the workaround are gone; remove that copy from any deployment steps that still
carry it** (review finding `F30`). The mismatch was a real vulnerability rather than an
inconvenience — CWE-178, improper handling of case sensitivity, and CWE-706, use of an incorrectly
resolved name: on Linux and in containers the intended file simply did not exist under the requested
name, so startup either failed or, once a `config.json` was created by hand, silently read a file
that was not the audited one.

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
publishes and launches **eight artifacts — all seven site hosts and the console application**, not a
representative subset:

| # | Project | Published assembly |
| --- | --- | --- |
| 1 | `WebVella.Erp.Site` | `WebVella.Erp.Site.dll` |
| 2 | `WebVella.Erp.Site.Crm` | `WebVella.Erp.Site.Crm.dll` |
| 3 | `WebVella.Erp.Site.Mail` | `WebVella.Erp.Site.Mail.dll` |
| 4 | `WebVella.Erp.Site.MicrosoftCDM` | `WebVella.Erp.Site.MicrosoftCDM.dll` |
| 5 | `WebVella.Erp.Site.Next` | `WebVella.Erp.Site.Next.dll` |
| 6 | `WebVella.Erp.Site.Project` | `WebVella.Erp.Site.Project.dll` |
| 7 | `WebVella.Erp.Site.Sdk` | `WebVella.Erp.Site.Sdk.dll` |
| 8 | `WebVella.Erp.ConsoleApp` | `WebVella.Erp.ConsoleApp.dll` |

For each one the step asserts that the publish output contains `Config.json`, that it does **not** also
contain a lower-case `config.json` twin, and then launches the assembly **from an unrelated, empty
working directory** with every `Settings__` value blanked. Three outcomes are distinguished rather than
collapsed: a `FileNotFoundException` fails the step (the casing contract regressed), reaching
`Now listening on` also fails it (a tracked file must be carrying usable secrets), and only
`required security configuration is missing` passes — proving the artifact resolved its own audited
`Config.json` from its deployment directory and then stopped at the fail-fast secret validation.
Anything else fails closed. The step additionally asserts `smoke_count -eq 8`, so a matrix that quietly
collapsed to fewer artifacts cannot report clean.

**Why eight and not a sample.** That argument covers the chain, which is only half of what this
checks: the exact-casing contract, the presence of `Config.json` in the publish output and the
absence of a lower-case twin are properties of **each project's own publish**, which no sibling can
stand for, so `Crm`, `Mail`, `MicrosoftCDM` and `Next` were unverified on both counts. Eight
artifacts also give the eight audited `Config.json` files a **one-to-one** runtime counterpart,
which is what makes this half of Gate 4's substitute complete rather than sampled. The evidence is
published as `startup-smoke.txt`.

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

`//` comments do **not** appear in all eight `Config.json` files, and the distribution matters: an
operator told to expect in-place explanation would look for it in files that carry none. Measured on the
tracked tree, `//` comments appear in **three** of the eight configuration files plus `global.json`:

| File | Lines carrying `//` | What they say |
| --- | --- | --- |
| `WebVella.Erp.Site/Config.json` | 4 — 2 dedicated, 2 trailing | A two-line security note naming findings `H-05` (CWE-798), `H-04` (CWE-321) and `C-04` with OWASP A02/A05, the `Settings__ConnectionString` / `Settings__EncryptionKey` / `Settings__Jwt__Key` supply forms, and why the keys are retained with empty values; a trailing note on `DevelopmentMode` naming `H-12` (CWE-489, CWE-209, A05) and recording that the value is a **string** by design; and the original trailing `CacheKey` note |
| `WebVella.Erp.ConsoleApp/Config.json` | 3 — 2 dedicated, 1 trailing | A two-line security note naming `H-05`, `H-04` and `H-12` with their CWEs and OWASP categories, the `Settings__ConnectionString` and `Settings__EncryptionKey` supply forms, and why every key is retained with an empty value; plus the original trailing `CacheKey` note. It names no `Jwt` key, because this project has no `Jwt` section and none was added |
| `WebVella.Erp.Site.Sdk/Config.json` | 1 — trailing | A pointer to the storage library's own documentation on the `CloudBlobStorageConnectionString` line |
| `global.json` | 7 | Why the SDK version is pinned and `rollForward` disabled |
| `.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next`, `.Project` | **0** | Nothing — these five carry no comment of any kind, so this guide is their only explanation |

Reproduce the counts with `grep -c '//' <file>` for the total and `grep -cE '^[[:space:]]*//' <file>` for the
dedicated comment lines; the difference is the trailing comments that share a line with a setting.

This remediation deliberately **kept** every comment that was there and **added** only the two security
notes, which the engagement's own change discipline requires: a security change carries a comment naming
the threat it addresses. RFC 8259 admits no comments, but nothing in this repository reads these files as
strict JSON: the runtime's own reader accepts them, `dotnet` accepts them in `global.json`, and no gate in
the workflow parses either file — the secret sweep matches key-name signatures line by line and never
invokes a JSON parser. Where comments exist they are, in several files, the only in-place explanation of
what a setting does, so stripping them would have deleted rationale for no verifiable gain. If you
introduce a strict consumer later, strip the comments in that consumer's own copy rather than in the
tracked file. **For the five files that carry none, this guide's inventory table above is the only
explanation there is** — do not read their silence as "nothing to know about these settings."

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

- The **encryption key** — `[REDACTED — 64 characters, SHA-256 prefix 7810b2fe1ad52ed5]`, 64
  hexadecimal characters — was present **byte-identically in all eight `Config.json` files**, and
  additionally as a compiled-in constant in `WebVella.Erp/Utilities/CryptoUtility.cs`. That constant
  shipped inside a library published to nuget.org, so the key was public twice over and could be
  neither rotated nor revoked per deployment.
- The **token signing key** — `[REDACTED — 51 characters, SHA-256 prefix 87184b56659256b8]`, a short
  phrase padded to length rather than a random value — was present at
  `WebVella.Erp.Site/Config.json:L25` and `WebVella.Erp.Site.Project/Config.json:L20`, with a third
  occurrence published as documentation in `WebVella.Erp.Site/JWT_README.txt` and a fourth as a
  compiled-in 17-character default — `[REDACTED — 17 characters, SHA-256 prefix 82794e7c1030b896]` —
  in `WebVella.Erp/ErpSettings.cs`, which also carried a matching pattern for the issuer and the
  audience.
- The **database credentials** were live too. Seven of the eight files pointed at an internal RFC 1918
  host and port — `[REDACTED — host:port, SHA-256 prefix 72858cca8cb5df2d]`, internal network topology
  disclosure in its own right — while `WebVella.Erp.Site` pointed at `localhost:5432`. In every file
  the `User Id` and the `Password` were the same word as each other, and there were two such words
  across the eight: `[REDACTED — 4 characters, SHA-256 prefix 9f86d081884c7d65]` in six files and
  `[REDACTED — 3 characters, SHA-256 prefix ef260e9aa3c673af]` in two.
  `WebVella.Erp.Site/Config.json:L13` additionally exposed a UNC path naming the same internal host —
  raised independently as review finding `CR2-F-12`, which found that address still committed as a
  storage path in **all eight** files after the credentials themselves had been scrubbed.
- The **seeded administrator password** was the fourth published credential:
  `[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]`, assigned as a literal by provisioning.
  Its withdrawal is a data migration rather than a rotation an operator performs, and it is covered in
  the [credential migration guide](credential-migration.md).

**The values above are redacted, not abbreviated, and the shape is fixed:** `[REDACTED — <n>
characters, SHA-256 prefix <16 hexadecimal characters>]`. Abbreviating them is not an option — printing the first bytes of the encryption key, or naming the signing key's phrase and its repetition count, from which the whole 51-character key could be reconstructed.

The redaction keeps what an operator needs and discards what they do not. **To decide whether your own
deployment still carries a published value, fingerprint it rather than compare it:**

```bash
printf '%s' "$VALUE" | sha256sum | cut -c1-16
```

A match against a prefix above means that value is public and must be rotated now. The same digests are
compiled into `WebVella.Erp/ErpSettings.cs:L119-L120`, which refuses both published keys outright at
start-up, so the check is enforced as well as documented. Redacting does not undo the original
disclosure — the full values remain in repository history, which is exactly why these instructions are
not optional — but a tracked file that reprints a secret or an internal address keeps it in every future
clone and in every sweep of the working tree, which would relocate the finding into the documentation
rather than resolve it.

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

**A fourth response class was confirmed subsequently, and it is the one most easily assumed rather than
checked: a 3xx redirect.** The headers are present on redirect responses too, not only on responses that
carry a rendered body. That matters because a redirect is exactly where a header is most likely to be lost —
the pipeline short-circuits before any content is produced — and because two of the mandated headers,
`X-Frame-Options` and `Content-Security-Policy`, are only useful if they arrive on *every* response an
attacker can cause a browser to follow. Verified on the wire during the frontend and API seam pass, on the
post-save redirects of an SDK management form.

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

Both header names carry the single `ContentSecurityPolicy` constant, which is the mandated
directives verbatim with nothing appended. It is a compile-time constant, so no host, plugin or
configuration source can weaken, blank or replace it.

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
addition to the HTML-block component and the script-emitting components — enumerated in the
[risk register](risk-register.md) rather than duplicated here — real reports implicate the rich-text
editor, the lazy-load bundle and the source editor.

**The count of first-party emitters was wrong, and the corrected census is `RISK-170`.** Earlier
revisions of this guide and of the risk register said *four* components emit inline script or
author-supplied markup through a raw-output channel. There are **five**:
`PcJavaScriptBlock/Display.cshtml:11` wraps `@Html.Raw(options.Script)` in a literal `<script>` element
and was named in neither document until code-review finding `MAJ-09` raised it. `RISK-170` is now the
canonical inventory — all **109** raw-output sinks across **61** views, each with the code that writes
its value and the authorization contract governing that writer — and it quantifies the refactoring
target as **59** inline `<script>` elements and **27** inline `style` attributes. Use it, not this
table's prose, when scoping the work.

**Status of the mandated header requirement, and where that status lives.** Because the policy is
delivered report-only, the engagement's seven-header requirement is **`UNRESOLVED / PARTIAL`, not
compliant** — six of the seven mandated header names are emitted and enforced, and the seventh arrives
as `Content-Security-Policy-Report-Only`, which enforces nothing. This guide is **not** the authority for
that status: the single authoritative status surface is the
[audit report's status section](security-audit-report.md#status-at-this-revision-gate-by-gate), and if
anything here disagrees with it, that section governs. Promotion to enforcement is a repository-owner
decision, because it trades a security layer against the deliberate feature set of a page-designer
platform; the governance is `RISK-022`.

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
sinks encoded, and every retained by-design markup channel enumerated in `RISK-023` and `RISK-037`. A
report-only policy is **detective, not preventive**: the browser reports the violation and then runs
the script anyway. It closes nothing on its own and must never be cited as evidence that `H-06` is
covered.

**One correction to the sentence above, and it matters operationally.** *Remediated in the view and
builder layer* was accurate about the sinks then known, and it is exactly why one sink survived: the
census behind it counted **Razor** raw-output sites, and the Project plugin's comment, timelog and feed
bodies reach the browser through a **client-side `innerHTML` assignment inside a pre-built bundle** —
which no Razor census can see, because no Razor expression is involved. That chain was live until review
finding `SR-05` closed it with an allow-listed server-side sanitizer applied on write **and** again on
read, so already-stored payloads are neutralised without rewriting stored data.

Two operational consequences follow, and neither is inferable from the paragraph above:

- **Do not treat "the views are encoded" as coverage of the rendering surface.** Any component that
  assigns `innerHTML`, whether shipped here or added later, is a sink that server-side view encoding does
  not reach. The control that covers it is sanitization at the persistence and projection boundary.
- **The report-only measurement below is now corroborated independently.** A separate pass on a single
  page observed roughly **80** report-only violations, every one raised by the application's *own* inline
  styles, scripts and evaluation — consistent with the figures below and recorded as `RISK-155`. Enforcement
  is a backlog, not a switch.

## Transport security

| Control | Guidance |
| --- | --- |
| TLS version | **TLS 1.2 or above.** Terminate TLS at the reverse proxy or configure Kestrel directly; the platform does not manage certificates |
| HSTS | Enabled, guarded to non-Development, ordered **before** redirection. Do not enable it on a hostname you also serve over plain HTTP for other purposes — the subdomain directive applies to every subdomain |
| HTTPS redirection | Enabled, guarded to non-Development, ordered **after** `UseCors` |
| Cookies | `Secure`, `HttpOnly` and an explicit `SameSite` policy — see *Cookies and session lifetime* |
| SMTP relay certificates | Validated by default, **including revocation**, on the five MailKit send paths — see *Mail transport*. The diagnostic notification client is a different client and enables no TLS (`RISK-131`) |

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
all seven hosts inherit it, and it accepts **only evidence that a request can actually arrive over
HTTPS**:

1. a declared endpoint of this process whose scheme is `https` — `ASPNETCORE_URLS`, `UseUrls` or a host
   binding;
2. a `Kestrel:Endpoints:<name>:Url` whose scheme is `https`;
3. `ANCM_HTTPS_PORT` — supplied by the ASP.NET Core Module itself, and only when the IIS site in front
   of this process has an HTTPS binding. Nothing needs to be configured for this: in-process hosting
   also preserves the original request scheme, so `Request.IsHttps` is true and the `Secure` cookie
   policy is satisfied without any forwarded-header configuration;
4. a trusted reverse proxy — `Settings__ForwardedHeaders__KnownProxies` or
   `Settings__ForwardedHeaders__KnownNetworks` — **together with** the public HTTPS port
   (`ASPNETCORE_HTTPS_PORT` or `HTTPS_PORT`). The proxy trust is what lets `X-Forwarded-Proto: https`
   establish the scheme; the port is the operator asserting that the public endpoint is HTTPS.

Finding one ends the check silently. Finding none, the host **aborts at startup** with a message naming
every key above, before serving a single request.

**Two things that used to satisfy this guard no longer do, and one that used to be waved through is now
refused.** Both changes close ways in which the guard could pass — or merely warn — on exactly the
posture it exists to prevent:

- **The public HTTPS port on its own is no longer evidence.** `HTTPS_PORT` selects the *target* of a
  redirect; it neither binds an endpoint nor makes one exist. It now counts only alongside a trusted
  proxy (option 4). It is also **parsed and range-checked**: a value that is not a whole number between
  1 and 65535 aborts startup with a message naming the key and the value, because a mistyped port
  silently disarms the redirect and would otherwise be reported nowhere. `ANCM_HTTPS_PORT` is range-
  checked identically, and is accepted alone only because the module — not an operator — writes it.
- **A trusted proxy on its own is no longer evidence.** Trusting a proxy declares who may be believed,
  not that anything in front of this process terminates TLS.
- **"No endpoint declared" is now refused outside Development, not warned about.** It is not an unknown
  posture in practice: it means the server binds its own defaults, and those are plaintext. Measured in
  Production, with nothing declared this application binds `http://localhost:5000` only and `/login`
  answers `500` — so continuing produced an application that could not be signed in to. Refusing at
  startup surfaces the identical diagnosis at the identical moment, to the operator rather than to a
  user.

One deliberate exception remains: **Development is exempt** and gets the identical text as a `warn:`
line, because its antiforgery cookie uses `SameAsRequest`, so local plaintext sign-in keeps working.

### Three port-shaped settings that are not interchangeable

`ASPNETCORE_HTTPS_PORT`, `ASPNETCORE_HTTPS_PORTS` and a `Kestrel:Endpoints` entry look like variations
on one idea and are three different mechanisms. The plural key cannot do that job here, and calling it a key that is simply "not read" is wrong in the other direction — which is wrong in the other direction, because it *is* read, by a hosting model this
platform does not use. Both are corrected here (review finding **F4**).

| Setting | Configuration key | What it actually does | Binds a listener? |
| --- | --- | --- | --- |
| `ASPNETCORE_HTTPS_PORT`, `HTTPS_PORT` — **singular** | `HTTPS_PORT` | The **redirect target** `UseHttpsRedirection` sends a plaintext request to. Use it when TLS is terminated in front of this process. An ANCM-hosted site's `ASPNETCORE_ANCM_HTTPS_PORT` lands on the same setting | **No** |
| `ASPNETCORE_HTTPS_PORTS`, `ASPNETCORE_HTTP_PORTS` — **plural** | `https_ports`, `http_ports` (`WebHostDefaults.HttpsPortsKey`, `HttpPortsKey`) | A genuine **Kestrel listener binding** — but resolved by `GenericWebHostService`, which expands each listed port into an `https://*:<port>` or `http://*:<port>` address. That resolution belongs to the **generic host** | **Only under the generic host** — see below |
| `Kestrel__Endpoints__<name>__Url` | `Kestrel:Endpoints` | A declarative endpoint, read by Kestrel's own configuration loader independently of the host's address resolution | **Yes** |
| `ASPNETCORE_URLS` | `urls` | The address list the host resolves directly. **Highest precedence** of the three binding mechanisms | **Yes** |

**Why the plural keys do nothing on these seven hosts.** Every host here is built by
`WebHost.CreateDefaultBuilder(args).UseStartup<Startup>()`, and that legacy `IWebHost` resolves its
addresses from `urls` alone. The plural keys are consumed only by `GenericWebHostService`, which this
hosting model never instantiates. Measured with every competing endpoint variable cleared:

| Host builder | Variables set | Bound addresses |
| --- | --- | --- |
| `WebHost.CreateDefaultBuilder` — **what this platform uses** | `ASPNETCORE_HTTPS_PORTS=<port>` + a valid default certificate, no `ASPNETCORE_URLS` | `http://localhost:5000` — Kestrel's own default. Configuration reported `https_ports=<port>`, so the value arrived and nothing consumed it |
| `WebHost.CreateDefaultBuilder` | `ASPNETCORE_HTTP_PORTS=<port>` only | `http://localhost:5000` — **identical to setting nothing at all** |
| `WebHost.CreateDefaultBuilder` | `ASPNETCORE_URLS=https://localhost:<port>` | `https://localhost:<port>` |
| `Host.CreateDefaultBuilder().ConfigureWebHostDefaults(…)` | `ASPNETCORE_HTTPS_PORTS=<port>` + certificate | `https://[::]:<port>` — **the plural key works here** |
| `Host.CreateDefaultBuilder().ConfigureWebHostDefaults(…)` | `ASPNETCORE_URLS=http://…` **and** `ASPNETCORE_HTTPS_PORTS=<port>` | the `urls` value, and the framework logs `Overriding HTTP_PORTS '' and HTTPS_PORTS '<port>'. Binding to values defined by URLS instead` — the precedence rule, stated by the framework itself |

So on this platform: **use `ASPNETCORE_URLS` with an `https://` address, or a `Kestrel:Endpoints` entry,
to bind HTTPS; use the singular `ASPNETCORE_HTTPS_PORT` only to arm the redirect.** Setting the plural
key is not harmful, but it is inert, and the startup check now says so by name rather than leaving it to
look arbitrarily ignored — because the natural next move when a setting appears ignored is to weaken the
cookie policy, which reinstates the very findings these controls closed.

The measured behaviour of each option, on a host whose only declared endpoint is plaintext:

| Configuration | `/login` over plaintext | Startup |
| --- | --- | --- |
| nothing further supplied | **HTTP 500** | **refused at startup**, with the actionable message |
| `ASPNETCORE_HTTPS_PORT=<public https port>`, or `HTTPS_PORT`, **alone** | `307` to `https://…/login`, but nothing establishes that the target exists | **refused at startup** — a redirect target is not TLS |
| `Settings__ForwardedHeaders__KnownProxies=<proxy address>` **alone** | `200` only if the proxy really sends `X-Forwarded-Proto: https` | **refused at startup** — declare the public HTTPS port too |
| `Settings__ForwardedHeaders__KnownProxies=<proxy address>` **and** `HTTPS_PORT=<public https port>` | `200` when the proxy sends `X-Forwarded-Proto: https` | starts |
| `HTTPS_PORT=443abc`, or any value outside 1–65535 | n/a | **refused at startup**, naming the key and the value |
| `ANCM_HTTPS_PORT` (written by the ASP.NET Core Module) | n/a — IIS terminates TLS and the scheme is preserved | starts |
| `ASPNETCORE_HTTPS_PORTS` (plural) | still **500** — no listener follows from it on this hosting model | **refused at startup**, and the message now names the variable, explains that it supplies the hosting-layer key `https_ports` (`WebHostDefaults.HttpsPortsKey`), which `GenericWebHostService` resolves and these seven `WebHost.CreateDefaultBuilder` hosts do not, and gives the `ASPNETCORE_URLS=https://*:<that port>` translation |

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

### The five restrictive hosts allow credentialed cross-origin requests that the antiforgery control refuses

Read this before diagnosing a `403` on a cross-origin call. **Two configurations in this repository now
disagree, and the pipeline resolves the disagreement in favour of the stricter one.** Review finding `N9`
raised it; the residual is carried as `RISK-180`.

`WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next` and `.Sdk` each keep

```csharp
WithOrigins("http://localhost:3000", "http://localhost").AllowAnyMethod().AllowCredentials()
```

so CORS tells a browser at `http://localhost:3000` that it may send credentialed `POST`, `PUT` and
`DELETE`. The antiforgery remediation then added `RequireSameOriginRequestAttribute`, which reads the
browser-set `Sec-Fetch-Site` header and **refuses** a cookie-authenticated unsafe method arriving
`cross-site` or `same-site`, returning `403` with the fixed message:

```text
This request was not accepted because it was initiated by another site.
```

**The control wins, because it runs in the pipeline.** The CORS allowance is the stale half. A client
relying on it receives a `403` that reads like a permissions fault and is not one — it is the cross-site
request forgery control doing exactly its job.

**What to do about it, in order of preference.**

1. **Authenticate the cross-origin client with a bearer token rather than the cookie.** The attribute
   exempts a request that carries its own `Authorization: Bearer` header, precisely because such a request
   cannot be forged by another site — an attacker's page cannot read the token. This needs no change to
   either configuration and is the intended path; it is also what the two remediated hosts already do.
2. **Or drop `AllowCredentials()` from those five hosts.** That makes the two configurations agree by
   removing an allowance nothing can actually use. Cross-origin `GET` and preflight continue to work.

**Do not weaken the antiforgery control to make the CORS allowance work.** Trading a cross-site request
forgery protection for a stale development-time convenience is a net loss, and the exemption in point 1
exists so that trade is never necessary.

The attribute exempts four cases by design, which is what makes the diagnosis unambiguous: safe methods
(`GET`, `HEAD`, `OPTIONS`, `TRACE`), requests carrying `Authorization: Bearer`, unauthenticated requests,
and requests with **no** `Sec-Fetch-Site` header at all — the last because a non-browser client such as
`curl` or a server-to-server caller sends none, and refusing those would break every integration without
adding protection a browser-set header can supply.

**Probe it both ways rather than trusting either configuration.** From an origin other than the host, send
a credentialed `POST` to any `/api/**` route using cookie authentication and assert `403` with that exact
message; then repeat the identical request with `Authorization: Bearer <token>` and **no** cookie and assert
it is processed normally. Both outcomes are correct, and seeing both is what tells you the control and the
exemption are each working rather than one masking the other.

## Cookies, sessions and bearer tokens

### Cookies and session lifetime

Cookie authentication is configured identically across all seven hosts, from a **single** shared
configurator, `ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie`, so the seven cannot drift
apart.

| Setting | Value | Reason |
| --- | --- | --- |
| `SecurePolicy` | **`Always`, in every environment** — no Development carve-out | The cookie must never traverse plaintext. Relaxing this in Development so `http://localhost` keeps working *is* the vulnerability (CWE-614), because `ASPNETCORE_ENVIRONMENT` is ambient — a deployment that inherits `Development` from a shell profile, a container image or a stale `web.config` silently stops marking the session cookie `Secure`, and the one signal that something is wrong is the signal that is suppressed. Local development uses the HTTPS profile instead |
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

### Session revocation: durable, shared, and fail-closed

A revocation list **is** implemented, it **is** durable and shared, and it covers **both** credential
kinds — the cookie ticket and the bearer token alike. It introduces one operational behaviour, described
at the end of this section. Read from the source rather than from a sibling document, the control is as
follows.

**One identifier, one store, both credential kinds.** Every cookie ticket minted by `AuthService`
carries a random session-identifier claim, and `BuildTokenAsync` stamps the *same* claim into every
bearer token and carries it verbatim across refresh. Signing out records that one identifier as revoked
(`AuthService.RevokeCurrentSession`), and the cookie pipeline and both bearer validators consult the
store on **every** request before a principal is accepted. So logging out is server-validated session
termination: the first request made with a copied cookie **or** a previously issued bearer token after
logout is refused.

**The store is durable and shared, and it needs no schema change.**
`WebVella.Erp/Database/DbSecurityStateRepository` holds the state, which means it survives a restart,
recycle or crash, and every instance behind a load balancer that points at the same database observes
the same revocation. It writes under a reserved key namespace — `wv_sec_`, with revocations at
`wv_sec_revoked_<session-id>` — inside the pre-existing `public.plugin_data` table that every
installation already has, so no schema definition statement was needed. That table has no expiry column
and none may be added, so the expiry travels inside the row as a fixed-width sortable UTC stamp at the
front of the payload, and expired rows are reclaimed by an indexed predicate. **Reclamation is by expiry
only, never by capacity**, so no live revocation can be displaced by a newer one — which is exactly what
the earlier process-local, size-bounded cache could do.

**It fails closed.** When the durable store cannot be consulted at all,
`SessionRevocationService.IsSessionIdentifierRevoked` answers *revoked*. This is deliberate: answering
"not revoked" when the answer is unknown is how a database outage becomes an authorisation. It costs
nothing real, because every authenticated request in this platform already re-resolves its user from the
same database — a database this code cannot reach is one no request could have been served from anyway.
A fail-closed answer is deliberately **not** mirrored locally, so a transient outage cannot pin a
legitimate session as revoked once the store is reachable again.

**The local cache that remains is positive-only.** Only identifiers the durable store has already
confirmed revoked are mirrored in process, and only for as long as the durable entry itself has left to
live. A negative answer is never cached, because caching "not revoked" for any interval would recreate
the window this control exists to close. A cache hit can therefore only ever refuse a credential that is
already refused.

**Retention is clamped at both ends:** a one-minute floor, so a revocation written with a near-past
expiry is still observable by the requests it exists to reject, and a 25-hour ceiling, so no caller can
turn the store into an unbounded one. The ceiling is the smallest round value that leaves the longest
legitimate credential unclamped — 1440 minutes of lifetime plus the one-minute bearer clock skew.

**What this means for you as an operator, and it is the only operational consequence.** Every
authenticated request now performs one additional indexed point lookup against `plugin_data`. That cost
is accepted and recorded. Two deployment consequences follow from the fail-closed direction: **all
instances must point at the same database** for a logout on one to be honoured by the others, and while
the database is unreachable authenticated requests are refused rather than admitted — which is the
intended behaviour, not a fault to work around. There is no configuration key for any of this, and none
should be added.

**What genuinely remains not implemented, stated plainly:** **refresh-token rotation with reuse
detection**. Revocation ends a session; it does not give each refresh a fresh, single-use identifier, so
a stolen token that is refreshed before the theft is noticed still yields a successor until the session
is revoked or the 7-day horizon is reached. A revocable refresh-token table with rotation and reuse
detection is recorded as future work in the [risk register](risk-register.md).

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

Two independent layers, both from the shared framework or from primitives already in the tree — **no new
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

**The counters are durable and shared.**
They live in the platform's own `plugin_data` table through
`WebVella.Erp/Database/DbSecurityStateRepository.cs`, under the reserved key prefix `wv_sec_`, with keys
`wv_sec_lthr_acct_<username>` and `wv_sec_lthr_addr_<address>`. Every transition is a single atomic,
row-locked read-modify-write, so five failures means five in total rather than five per process. Nothing
about this is a schema change: the table already existed for plugin state, so no `CREATE TABLE` and no
column was added. **The one thing mirrored in memory is an in-force lockout, and only positively** — a
mirror hit can refuse a key that is already refused, but it can never authorise an attempt, because a
miss always consults the database and the mirror entry expires exactly when the lockout it mirrors does.
So the operational consequences that follow from a durable store are the ones to plan for:

- **A restart no longer clears a lockout, and a second instance sees it.** That is the fix for review
  finding `H-OPEN-02`; it also means an operator cannot release a locked-out account by bouncing the
  process. Deleting the account's `plugin_data` row is not sufficient on its own either, because a
  running process may still hold the lockout in its positive mirror — clearing an in-force lockout
  immediately takes **both** the row deletion and a restart of every instance holding it. In practice
  wait for the 15-minute window to lapse.
- **The throttle fails closed when the store cannot be consulted.** If the database is unreachable the
  attempt is refused rather than allowed, so a database outage cannot be used to switch the lockout off.
  The trade is explicit: during such an outage logins are refused, which is the same posture the rest of
  the platform already takes because every credential lookup needs the database anyway.
- **Account lockout is a denial-of-service primitive**, which is why it lapses automatically after 15
  minutes rather than requiring an administrator to clear it. An attacker can lock a known account for
  15 minutes; that is a deliberate trade against making credential stuffing cheap. The window is
  re-measured from the most recent attempt, so pacing attempts cannot age a counter out from under
  itself.
- **The mirror is size-bounded at 20,000 in-force lockouts** to cap memory against an attacker varying
  the username. Cycling it displaces only a cached copy of a refusal, never a partial count — the count
  itself is never cached — so unlike the previous in-process design, cache pressure cannot hand a
  budget back.

**Lockout state is durable, so restarting the application does NOT clear it.** Counters live in the
database, shared by every instance and surviving a restart; only the in-memory mirror of an in-force
refusal is lost, and a miss there re-reads the store. To clear a lockout deliberately, either wait for
the 15-minute window to lapse or delete the account's `plugin_data` row **and** restart every instance
still holding it in its mirror.

### Releasing an account lockout

This is the runbook for the one operational question the durable design creates: *a user is locked out and
cannot wait — what do I do?* It is written out because the behaviour was reproduced from the outside and the
obvious action alone does not work. In a verification pass all thirty rows the control had written were
deleted and confirmed gone, and login **still** failed with a verified-correct password; it succeeded only
after the host process was restarted. That is the positive-only mirror described above working as designed,
and it means the row deletion and the recycle are two halves of one action rather than alternatives.

**Route 1 — wait. This is the supported default and needs no operator action.** The window lapses
**15 minutes after the most recent failed attempt**, not 15 minutes after the first, so the user must stop
attempting for the window to age out. Tell them to stop trying and come back in fifteen minutes. Prefer this
route: it needs no database access and no downtime.

**Route 2 — clear deliberately.** Take all three steps, in order. Stopping after step 1 will appear to do
nothing.

1. Find the rows. Both counters are in `public.plugin_data` under the reserved `wv_sec_` prefix — the account
   counter is keyed by username and the address counter by remote address:

   ```sql
   SELECT key, left(value, 120) AS value
   FROM   public.plugin_data
   WHERE  key LIKE 'wv_sec_lthr_%'
   ORDER  BY key;
   ```

2. Delete only what you intend to release. Scope the delete to the one account, or to the one address, rather
   than to the prefix — deleting the whole prefix resets every counter in the installation, including the
   partial counts that are currently metering an attack in progress:

   ```sql
   -- release one account
   DELETE FROM public.plugin_data WHERE key = 'wv_sec_lthr_acct_' || lower('user@example.com');
   -- release one source address
   DELETE FROM public.plugin_data WHERE key = 'wv_sec_lthr_addr_' || '198.51.100.7';
   ```

3. Recycle every instance that may hold the lockout in its positive mirror. Until this happens the deletion
   has no visible effect on a process that has already learned the refusal, because a mirror hit never
   consults the database. In a single-instance deployment this is one restart; behind a load balancer it is
   all of them, since any instance can serve the next attempt.

**Then verify, rather than assuming.** Re-run the query from step 1 and confirm no matching row remains, then
have the user attempt a login and confirm it is accepted. If it is still refused, an instance was missed in
step 3 — or the account is locked on the **address** counter as well as its own, which the query in step 1
will show.

**What is deliberately absent.** There is no administrative unlock action in the application: no screen, no
endpoint and no command. Adding one would be a feature rather than a remediation, and it would itself need
authorisation, auditing and rate limiting — so the supported routes are the two above. Note also that a
first-login password rotation consumes the same account budget (`RISK-136`), so a user working through a
forced rotation can lock themselves out with five wrong attempts exactly as any other user can.

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

**Fixing it: there is one supported remedy, and it is not a setting.** Publish the revocation source.
Re-issue the relay leaf with a `crlDistributionPoints` extension pointing at a CRL your hosts can
actually fetch, sign that CRL with a CA carrying `cRLSign` and a subject key identifier, serve it in
**DER** form, and allow the application host outbound access to that URL. An OCSP responder named in
the leaf works equally well. Every check then stays in force and a revoked relay certificate stays
refused.

**There is deliberately no configuration key that disables the revocation check.** Such a key is deliberately absent: honoured in every posture, including Production, it weakened the production transport posture beyond the agreed remediation for
`H-11` and added an external-service accommodation the plan of record does not authorise. Do not
reintroduce it, and do not read a CRL-reachability failure as a reason to reach for the
accept-any-certificate opt-out instead — that removes transport authentication entirely to fix a
missing CRL, and it is refused outside Development anyway.

**If you cannot publish a revocation source**, the relay is not usable from a Production deployment of
this platform, and that is a deployment constraint rather than a bug to configure around. Your options
are to point the platform at a relay whose chain is complete, to place a relay you do control in front
of the one you do not, or to accept that this subsystem is unavailable until the chain is fixed. The
residual is recorded as `RISK-060` in the [risk register](risk-register.md) so it is an owner decision
on the record rather than a silent outage.

| Property | Value |
| --- | --- |
| Revocation checking | **Always on.** Left to the mail library's own default rather than assigned, so there is nothing to misconfigure and no code path that turns it off |
| Configuration | **None.** No setting governs it |
| Sites governed | All five send paths, because none of them touches the property |
| What a failure looks like | An SSL handshake exception whose chain-status detail is only `unable to get certificate CRL` |

**Two consequences worth knowing before you deploy.** Revocation checking genuinely works rather than
failing blindly: a leaf revoked in its issuer's CRL is refused with a distinct `certificate revoked`
bullet, while a non-revoked leaf validated against that same freshly published CRL delivers normally.
And **the queued send path fails differently from the interactive one**: a direct send throws where the
caller can see it, while the background queue records the handshake text in the message's
`server_error`, increments the retry count, reschedules, and eventually marks the message aborted. If
mail silently stops flowing and the queue is filling with aborted rows, **read `server_error` before
anything else** — the CRL bullet will be sitting in it. That column now carries the peer's own response
text through an HTML-encoding sink on the e-mail list screen (`INT-14`), so read it as data, not markup.
The measured cost of secure delivery is small: warm TLS delivery is within a few milliseconds of the
accept-all baseline, plus a one-off chain fetch the first time a CRL is retrieved and cached.

### Two SMTP misconfigurations easy to mistake for certificate failures

The certificate policy above governs what happens **when TLS is negotiated.** Two common relay
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

**A service row configured for cleartext is now refused rather than delivered, and that reverses what
this paragraph used to say.** Until review finding `H-OPEN-03` a `connection_security` of `None`
connected in the clear, and the "when available" variant silently degraded to cleartext against a relay
that did not advertise `STARTTLS` — so the message body and, when the row carried a username, the
**relay credential** went out unencrypted while revocation checking sat at its secure default, because
no certificate was ever presented, requested or examined. There is now a **minimum-security floor**, and
it is applied in two places:

- **At send time, in code.** Outside Development, `None` is refused before any socket is opened — the
  send is aborted with a diagnostic naming the mode and the `smtp_service` field, and the wire carries
  no session at all. `Auto` and `StartTlsWhenAvailable` are **raised** to mandatory `StartTls`, so a
  relay that does not offer the extension fails with `The SMTP server does not support the STARTTLS
  extension.` instead of downgrading. Development posture still permits a plaintext or self-signed
  development relay, which is the only escape hatch and is deliberate.
- **At record-validation time, in the entity metadata.** The `connection_security` field's default value
  is now `3` (`StartTls`), and the permitted option set on the create and edit screens is `SslOnConnect`
  and `StartTls` only — `None`, `Auto` and `StartTlsWhenAvailable` are rejected with *Connection
  security must be SslOnConnect or StartTls* and no row is written.

**One thing the migration deliberately does not do: it does not rewrite stored rows.** An installation
upgraded from an earlier version keeps whatever `connection_security` value it already had, so a row
sitting at `None` will start **failing** its sends after the upgrade rather than silently continuing to
leak. That is the intended direction, but it is a behaviour change to plan for: check every
`rec_smtp_service` row before upgrading and set it to `SslOnConnect` or `StartTls`. The conventional
pairings are implicit TLS with 465 and `STARTTLS` with 587 or 25. Verify it on the wire rather than from
the configuration.

### The diagnostic notification mailer is a different client, and it is now protected too — differently

Everything above this heading describes the **five MailKit send paths** in
`WebVella.Erp.Plugins.Mail`: the four in `Api/SmtpService.cs` and the queued one in
`Services/SmtpInternalService.cs`. Those are the paths `H-11` closed and `H-OPEN-03` made
encryption-mandatory.

The platform has a **second, entirely separate** outbound mail client, which is why this guide and the audit report generalised across the two as
though `H-11` covered both. It did not, and the distinction still matters — but the conclusion has
reversed. `WebVella.Erp.Web/Services/MailService.cs` builds a `System.Net.Mail.SmtpClient` and is called
by `WebVella.Erp.Web/Services/LogService.cs` when a log record is written. **Review finding `M-OPEN-03`
closed it.** Read its posture literally, as it now stands:

| Property | Actual behaviour |
| --- | --- |
| Transport | **STARTTLS, unconditionally.** `client.EnableSsl = true`, with no development escape hatch and no configuration key that could express an opt-out. A relay that cannot offer the extension makes the notification fail; switch diagnostic mail off with `Settings:EmailEnabled` rather than reaching for a downgrade |
| Certificate validation | The platform's **default chain policy** — chain, validity dates and host name. This type is never given a validation callback anywhere in the repository, and must not be. It does **not** check revocation, which is the one place it is weaker than the MailKit paths above; a chain-trusted certificate satisfies it even with no reachable CRL |
| Credential | `NetworkCredential` with the same `Settings:EmailSMTPUsername` / `Settings:EmailSMTPPassword` values — now sent inside the TLS session rather than in the clear |
| Payload | **Severity, source, host and the `system_log` identifier. Nothing else.** The exception message, the serialised detail and the request URL are no longer sent; the subject is fixed and content-free, because a subject is the part of a message intermediate relays log by default. The three interpolated values are HTML-encoded into the body |
| Ordering | The log record is **persisted first**, then the notification is attempted. A notification failure can therefore no longer lose the record it was announcing |
| Failure handling | Reported, not swallowed. The empty `catch` is gone; a fault goes to standard error — by exception **type** only, never the relay's response text — with the first always reported and one in 100 thereafter, and the record is marked `NotificationFailed` (`4`). Standard error rather than the platform log deliberately: this runs *inside* the platform log's own notification path, and recursing into it would be the defect being reported |
| Timeout | **15 seconds, explicit**, and the client is disposed. The framework default of 100 seconds — measured at 100.3 s against a socket that accepts and never answers — turned an unrelated fault into a request that appeared hung |

**What still bounds it.** The whole path remains gated on `Settings:EmailEnabled`, which is `false` in
all eight shipped configuration files and defaults to `false` when the value is absent — so on a default
deployment this client never runs. Separately, the twenty-eight notifying `LogService` writes on the web
API surface were replaced by a non-notifying audit sink while closing review finding `F26`, so the
platform's largest anonymous-reachable fault surface does not reach this path at all.

**What to do about it now.** Point it at a relay whose certificate this host can validate and which
offers STARTTLS, then confirm delivery. Until it validates, notifications fail silently to the operator
but loudly in the data: `system_log.notification_status` carries `4`. One residual is deliberately
**not** closed and is yours to bound — the notification is attempted once per notifying write with no
per-source ceiling, so a fault that recurs at volume still produces mail at volume. Rate-bound it at the
relay, or leave `Settings:EmailEnabled` off and read `system_log` directly. That residual, and the
history of this section, are recorded as `RISK-131` alongside `M-17`.

## Abandoned upload cleanup is an operator responsibility

`DbFileRepository.CleanupExpiredTempFiles(TimeSpan)` deletes staged uploads at `/tmp/<section>/<name>`
that are older than the age you pass. Until review finding `INT-13` it matched nothing at all, so
uploads that were never promoted to a permanent path accumulated for the lifetime of the installation —
up to the per-request upload ceiling each. The query and the age filter are now correct, and one
unreadable row no longer aborts the pass.

Two things are deliberately **not** shipped, and both are yours to arrange:

- **Nothing calls it.** No background job, schedule or configuration key was added, because scheduling
  is a deployment decision and a job would be feature work outside this remediation. Drive it from your
  own maintenance task — daily, with an age comfortably longer than your longest legitimate
  upload-then-save interaction; an hour is ample, a minute is not.
- **Call it in a system scope.** Wrap the call in `SecurityContext.OpenSystemScope()`, or run it as an
  administrator. Deletion resolves the path through the ownership-guarded lookup added for finding
  `F24`, so under an ordinary user's scope the pass silently skips every upload except that user's own
  and reports nothing. Failures are written to the platform log with the path and the backend error, so
  alert on those records rather than on the absence of an exception.

The residual is recorded as `RISK-134`.

## Environment and development mode

Two independent switches control development behaviour, and **both** must be set for a production
deployment. Setting one and not the other leaves diagnostics exposed.

| Switch | Where | Shipped value now | Production value |
| --- | --- | --- | --- |
| `ASPNETCORE_ENVIRONMENT` | `WebVella.Erp.Site/web.config` for IIS-hosted deployments; otherwise the process environment | `Production` | `Production` |
| `DOTNET_ENVIRONMENT` | The process environment, **`WebVella.Erp.ConsoleApp` only** | unset | unset, or `Production` |
| `Settings:DevelopmentMode` | All eight `Config.json` files | `"false"` | `"false"` |

### The console host reads `DOTNET_ENVIRONMENT` first

**Finding `MIN-02`.** For the seven site hosts the environment name comes from `IWebHostEnvironment`,
which ASP.NET Core resolves from `ASPNETCORE_ENVIRONMENT`. `WebVella.Erp.ConsoleApp` is a plain
`Microsoft.NET.Sdk` console application with no host builder and therefore no `IHostEnvironment` to
ask, so it reads the environment itself — and it reads **`DOTNET_ENVIRONMENT` first**, falling back to
`ASPNETCORE_ENVIRONMENT` only when that is unset or blank
(`WebVella.Erp.ConsoleApp/Program.cs`, the configuration-builder block).

**Why an operator has to know this.** The order is the opposite of the instinct that
`ASPNETCORE_ENVIRONMENT` is the one switch that matters, and it has a security consequence in each
direction:

- **`DOTNET_ENVIRONMENT=Development` silently wins.** A machine or container that carries it — the
  .NET SDK and several tool images set it — puts the console host into its development branch **even
  though `ASPNETCORE_ENVIRONMENT=Production` is also set**. The development branch adds the user-secrets
  provider, so an unencrypted on-disk store is consulted on a host the operator believes is in
  production.
- **Setting only `DOTNET_ENVIRONMENT=Production` does not harden the site hosts**, which never read it.

**What to do.** Treat them as one setting with a known precedence: on any host that runs the console
application, either leave `DOTNET_ENVIRONMENT` unset and rely on `ASPNETCORE_ENVIRONMENT`, or set
**both** to the same value. Verify with `printenv DOTNET_ENVIRONMENT ASPNETCORE_ENVIRONMENT` — an empty
first line is the state the site hosts and the console host agree on.

**The bound on the exposure.** Outside development the user-secrets provider is not added at all, so a
non-development chain is exactly *JSON file, then environment variables*. User secrets are also added
**last**, so a developer's own store outranks an ambient machine-wide variable — deliberate, so a
stale environment value cannot override a deliberate local one. Neither `DOTNET_ENVIRONMENT` nor
`ASPNETCORE_ENVIRONMENT` gates `Settings:DevelopmentMode`; that is the separate switch above.

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

Scope, stated precisely and **re-measured under review finding `OBS-08`: there are now zero
unguarded exception-detail sinks in that controller.** An earlier version of this paragraph said ten
other controller actions still concatenated exception detail into a response and that setting
`Production` would not suppress them. That was true when written and is no longer true, and the
correction matters because it inverts the operational advice: those bodies are no longer verbose in
Production posture.

What changed is that every one of those sites now takes its message from a single helper,
`SafeErrorMessage(Exception)` in `WebVella.Erp.Web/Controllers/WebApiController.cs:344`, which returns
`ex.ToString()` **only** when `Settings:DevelopmentMode` is true and the fixed
`INTERNAL_ERROR_MESSAGE` otherwise. Measured on the tree this commit publishes: **38** call sites route
through that helper, and the only two remaining assignments of raw exception text to a response body —
in the token issue and refresh routes — are each inside an explicit `if (ErpSettings.DevelopmentMode)`
branch. So in Production posture no exception message, type name or stack frame reaches any response
body from this controller.

Two qualifications that keep this honest rather than reassuring:

- **The guard is `Settings:DevelopmentMode`, not `ASPNETCORE_ENVIRONMENT`.** They are different
  switches, and this one is read from the configuration file. Setting the environment to `Production`
  while leaving `DevelopmentMode` true still returns full detail. Both must be correct; see the
  `Settings:DevelopmentMode` guidance immediately below.
- **Server-side detail is unchanged.** Every one of those paths still records the full exception
  through the non-notifying audit boundary, so this is a change of audience rather than a loss of
  diagnostic capability. The place to read a fault is the log table, not the client response.

`Settings:DevelopmentMode` gates a distinct richer-error branch in
`WebVella.Erp.Web/Controllers/ApiControllerBase.cs`, so it is an information-disclosure switch and not
merely a convenience. It is also what gates the SMTP accept-any-certificate opt-out, and Development
mode is what suppresses HSTS and HTTPS redirection — so leaving it on disables transport controls
described above.

**And it is the switch behind the one error-handling residual this remediation did not close, so it is
worth knowing exactly how much it governs.** Twenty-five statements in four core-library manager
classes — `WebVella.Erp/Api/EntityManager.cs` (13), `EntityRelationManager.cs` (5), `RecordManager.cs`
(5) and `ImportExportManager.cs` (2) — assign `e.Message + e.StackTrace` to a response body behind
`if (ErpSettings.DevelopmentMode)`. In the shipped Production posture none of them emits anything. With
this switch on, twenty-five authenticated manager paths return full stack traces. The web API
controller itself is clear — every sink there routes through one `SafeErrorMessage` helper and the file
contains no `StackTrace` reference at all — so this is the whole of the remaining surface, and it is
recorded as `RISK-129` in the [risk register](risk-register.md) with its guard status, its recommended
fix and the reason it was left. Treat it as a reason to audit for a stray
`Settings__DevelopmentMode=true`, not as a reason to relax about it.

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

**Supplying the location is necessary but NOT sufficient, and this guide previously implied otherwise.**
Review finding `INT-04` established that the alternative storage backends carry pre-existing lifecycle
defects, so read this as an enablement warning rather than an enablement instruction:

- **The object key is derived from the file's identifier, not from its path.** Create, read and delete
  address a blob at `<first two hex chars>/<next two>/<file id><extension>`, computed from the `files`
  row's identifier. **Move does not.** It reads and writes logical paths and deletes a third form again,
  so a move under cloud storage does not relocate the object the other three operations address. The
  practical consequence is narrow but real: because the identifier does not change on a move, a rename
  that keeps the extension still resolves afterwards, while one that **changes the extension** leaves the
  metadata pointing at a key that was never written.
- **External storage is not transactional with the database.** The blob or file-system write, move and
  delete happen before the database transaction commits and are not compensated if it rolls back, so a
  failure can leave an orphaned object, metadata that disagrees with the store, or — on a move — a
  deleted source with no committed destination (`INT-05`).
- **Neither defect is remediated here**, deliberately: this engagement documents external-service
  integration risks rather than modifying them, and correcting the lifecycle is a redesign well beyond
  the change constraints. Both are recorded as `RISK-132` and `RISK-133` with concrete fix guidance.
- **Both features ship disabled** — `Settings:EnableCloudBlobStorage` and
  `Settings:EnableFileSystemStorage` are `false` in all eight tracked configuration files — so a default
  deployment stores file content in PostgreSQL large objects and is unaffected. If you enable a backend,
  avoid extension-changing renames until `RISK-132` is closed, and reconcile the store against the `files`
  table after any failed save.

One consequence worth stating plainly: **abbreviating an address in this document, or blanking it in a
configuration file, does not undo the original disclosure.** Any internal host name or address that was
ever committed should be treated as public and reachability-restricted at the network layer, not merely
edited out of the current revision.

## The WebAssembly client — transport, API base address and origin

The Blazor WebAssembly client is a **browser-delivered** application, which changes what configuration can
safely mean for it. Everything in its `wwwroot/appsettings.json` is downloaded by, and readable by, every
visitor. **It cannot hold a secret of any kind**, and nothing should be added to it that an anonymous
visitor must not read.

### `serverUrl` — leave it empty unless the API is genuinely a separate host

| Value | Behaviour | When to use it |
| --- | --- | --- |
| **empty (shipped default)** | The client calls **the origin that served it**, inheriting that origin's scheme | Always, unless the API is on a different host. This is the safe default and it is safe *by construction* — a same-origin base can never be weaker than the page |
| a **relative** path | Resolved against the serving origin, so it is also scheme-safe by construction | A reverse proxy that mounts the API under a path prefix |
| an **absolute `https://` URL** | Used as given | A genuinely separate API host |
| an **absolute `http://` URL** | **Refused with a startup error** when the page itself is secure | Never. The two possible outcomes are a blocked request or a leaked bearer token |

That last row is a deliberate refusal rather than an attempt, and the reason is worth stating because the
failure it prevents is the *quiet* one. Under HTTPS, an `http://` API base makes every call active mixed
content and the browser blocks it — loud, obvious, and quickly diagnosed. Served over plain HTTP the very
same setting **works**, and transmits the bearer token in cleartext on every request. A working
misconfiguration is far more dangerous than a broken one, so the client fails fast with an actionable
message instead of leaving the outcome to the deployment's scheme. This is review finding `SR-03`; the
version shipped before it carried `http://localhost:5000/` as its default.

### Do not leave a cleartext listener bound

Removing the insecure default closed the client's half of that finding. **It does not stop an operator
binding a cleartext listener**, and during verification one was found live on the API port, answering
probes — which is what made the exposure reachable rather than theoretical (`RISK-159`).

- Bind **HTTPS only**, or terminate TLS at a proxy and let nothing else listen.
- If a plaintext listener must exist, it should do nothing but redirect. HTTPS redirection is enabled and
  guarded to non-Development, ordered **after** `UseCors` — see *Transport security*.
- HTTPS is **not optional** for this platform even in a development loop: the authentication and antiforgery
  cookies are `Secure`-only, so the login page cannot function over plain HTTP.

### Client origin and cross-origin policy

When the client is served from the same origin as the API — the shipped default — **no cross-origin
configuration is required at all**, and requests carry `sec-fetch-site: same-origin`. Only if you set an
absolute `serverUrl` does the client become a cross-origin caller, and in that case its origin must be added
to `Settings:Cors:AllowedOrigins` on the API host. An absent or empty list denies every origin outside
Development; see *Cross-origin policy*.

### Post-authentication redirects are restricted to local paths

The client's login component accepts a `returnUrl` only when it is a path on the same origin — a single
leading `/`, and neither `//` nor `/\`. Absolute, scheme-relative and backslash-relative values fall back
to `/`. Nothing needs configuring; it is noted so that a deep link which appears to be ignored after login
is understood as the policy working rather than as a defect (`SR-06`).

## File download serves the stored object at full size

`GET /fs/{path}` returns the stored object **exactly as uploaded**. There is no server-side resizing, and
there is no query parameter that will produce one.

This is stated explicitly because the endpoint previously *appeared* to offer it: it parsed `action`, `mode`,
`width` and `height` from the query string and then ignored them. The parsing was removed by review finding
`SR-09` — its only producer anywhere in the repository was a page retired by `SR-04`, and the third-party
field components were confirmed never to compose such a URL — so the behaviour is unchanged and the contract
is now honest. If you need thumbnails, generate them at upload time in your own pipeline, or resize in the
browser; do not expect a query parameter to do it.

Two related delivery behaviours belong with this, since operators meet all three together:

- **Inline versus attachment is an allow-list.** Only a small set of passive raster extensions is served
  inline; everything else is served with `Content-Disposition: attachment` alongside
  `X-Content-Type-Options: nosniff`. That is what stops an uploaded `.svg` or `.html` executing on this
  application's origin, and it is proven end to end rather than assumed — see `RISK-149`.
- **TIFF will render as a broken image**, inline or not, because no mainstream browser ships a TIFF decoder
  for `<img>`. That is a browser limitation, not a platform one, and the options are set out in `RISK-148`.

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
NuGetAudit                       true
NuGetAuditMode                   all
NuGetAuditLevel                  low
WarningsAsErrors                 $(WarningsAsErrors);NU1900;NU1901;NU1902;NU1903;NU1904;NU1905
EnableNETAnalyzers               true
AnalysisLevel                    latest-recommended
AnalysisLevelSecurity            latest-all
ErpTaintAnalysisFamily           CA3001;…;CA3012
ErpTaintAnalysisExcludedProject  WebVella.Erp.Web
```

**This block previously listed six properties and stated that `AnalysisLevelSecurity` was "deliberately
not set" and evaluated empty. That was true when written and is now false**; review finding `MAJ-07`
found it still standing, and it is corrected rather than quietly replaced because an operator
reproducing the gate from a stale property list gets a different gate. Reproduce the current values, do
not take them from prose:

```bash
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -nologo \
  -getProperty:EnableNETAnalyzers -getProperty:AnalysisLevel \
  -getProperty:AnalysisLevelSecurity -getProperty:NuGetAuditMode \
  -getProperty:ErpTaintAnalysisExcludedProject
```

`AnalysisLevelSecurity=latest-all` **arms the whole Security rule category**, which is what makes
`CA2100`, `CA2326`/`CA2327`/`CA2328`, `CA5390`, `CA5401`/`CA5402`, `CA5404` and the `CA3001`–`CA3012`
taint family execute at all. **No global analyzer configuration file is supplied**, and none may be
added: a `.globalconfig` anywhere in the tree is the one mechanism that could change any rule's
*severity* for all 19 projects at once, per-rule escalation is outside this gate's scope, and the
workflow fails the job on finding one — tracked or untracked.

The two `ErpTaintAnalysis*` properties are the taint family and the single compilation it is excluded
from, declared as readable properties so the workflow's Gate 1 reads the boundary out of this file
instead of carrying its own copy. **The exclusion is a build-time measure, not a coverage gap.**
`WebVella.Erp.Web` compiles 395 Razor views into one compilation and the family's dataflow analysis is
superlinear in compilation size: armed with no cost bound that project ran past **2,700 seconds** without
completing, so an ordinary build must not depend on it. Under review finding `MAJ-01` the scan is supplied
separately, by the workflow step *Gate 1 - terminating taint scan of the excluded compilation*, which arms
the family for that one project with the interprocedural chain bounded to one hop — **about 220 seconds,
exit 0, zero `CA3001`–`CA3012` diagnostics** — proves the bounded configuration still reports by requiring
`CA3001` and `CA3003` against deliberate taint flows in the same step, treats a timeout as a hard failure,
and publishes `taint-scan-web.txt` as evidence. Taint coverage is therefore **19 of 19** compilations. The
cost configuration is written **outside** the repository and handed to the build through the
`ErpTaintAnalysisOptions` property, which is inert unless set, so the `.globalconfig` prohibition above is
not weakened. What remains a residual is analysis *depth* for that one project — `RISK-051`.

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
{
  "sdk": { "version": "10.0.302", "rollForward": "disable" }
}
```

This is a security control, not housekeeping (finding L-07). Both halves of the gate are SDK-version
dependent — the dependency-audit defaults and the analyzer rule set — so an unpinned toolchain means the
same source can produce a different gate result on a different machine, which makes every "the scan is
clean" claim unverifiable.

**`rollForward: disable` is what the tree carries**, and it is the pin: only SDK **10.0.302** builds
this repository, and every other version, patch or feature band, is refused.

 That revision set `rollForward: latestPatch`, reasoning that
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

**THE WHOLE SECURITY CATEGORY IS ACTIVE, AND THREE PARAGRAPHS THAT STOOD HERE SAID THE OPPOSITE.** They
read *"every other Security-category rule is inactive at this level"*, listed `CA2100`,
`CA2326`/`CA2327`/`CA2328`, `CA5382`/`CA5383`, `CA5390`, `CA5401`/`CA5402`, `CA5404` and the whole
`CA3001`–`CA3012` taint family as disabled, and said activating them was outside the gate's frozen scope
so the weaknesses they cover *"were established by manual review instead"*. Every sentence of that was
accurate when written and **is now false**: `AnalysisLevelSecurity=latest-all` arms the category and the
taint family runs, so review finding `MAJ-07` correctly reported the passage as invalidating both operator
reproduction and gate interpretation. It is corrected here in place, and the withdrawal is recorded rather
than the text simply replaced, because a security guide that silently rewrites its own account of coverage
is the exact defect `MAJ-07` names. What remains true from the old passage, and only this: **a zero from an
inactive rule is not evidence.** Which is why the rules are armed and why the reporting capability of the
one bounded scan is proved against deliberate defects rather than assumed.

**Measured at this revision, and every figure here is a live measurement rather than an estimate.** A full
`-t:Rebuild` of the solution reports **0 errors and 3,055 warnings**. Of those, **641** are distinct
`(rule, file)` `CA` diagnostics across all categories, and **55** are Security-category diagnostics, from
exactly five rules — `CA2100` (20), `CA2326` (20), `CA2328` (9), `CA5351` (5) and `CA5362` (1) — which
collapse to **21** distinct `(rule, file)` pairs. Read any other total in this document set as dated and re-measure it, because the figure moves whenever the analyzer configuration does. None of the 3,055
is newly introduced by the remediation — they are pre-existing code the gate made *visible*.

**All analyzer diagnostics remain warnings; only the six dependency codes are errors.** Promoting roughly
700 source files' worth of pre-existing warnings wholesale would demand exactly the mass refactor the
change scope forbids, so no `CA` identifier is added to the promotion above and build-time code-style
enforcement is left off.

**Analyzer enforcement therefore lives in the workflow rather than in the compiler.** Gate 1 parses the
analyzer log, extracts every Security-category diagnostic and fails the job on any that is not on an
inline allow-list — **21** `(rule, file)` pairs at this revision. Each of the 21 carries a `RISK-` reference and a
one-line disposition, and the step fails on a missing, unresolvable or empty one, so a tolerated diagnostic
cannot exist without a traceable acceptance behind it; both forms of the list are published, the comparison
form as `security-allowlist.txt` and the justified form as `security-allowlist-justified.txt`. The pass
criterion is consequently **zero *unreviewed* Security-category diagnostics and no increase over the
recorded per-rule baseline** — measured at this revision as **0 unreviewed and 0 stale**. Read that
precisely: it means every diagnostic that fired is accounted for, **not** that none fired. Those baselines
must not be "fixed" by weakening the gate: the five `CA5351` sites are the legacy verification path that
exists so already-stored credentials keep working, and they are formally accepted with a measurable exit
condition in `RISK-171`.

Two counting traps are worth knowing, because either makes a figure come out at twice its true value. **MSBuild emits every diagnostic twice** in a solution build — once
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
binary, measured at 48 of 1,574 tracked files at the time of that measurement — the tracked total has
since moved to 1,576 while the 48 has not — none of which is a configuration surface; and **a secret
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

  # 5. The Security category is armed, and no config file from this tree carries a rule severity.
  #    Expect 'latest-all' from the first, and from the second only the SDK's own
  #    analysislevel_<n>_recommended and analysislevelsecurity_<n>_all - never a path in this tree.
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -nologo -getProperty:AnalysisLevelSecurity
dotnet msbuild WebVella.Erp/WebVella.Erp.csproj -nologo -t:CoreCompile -getItem:EditorConfigFiles | grep -i globalconfig
```

Then the runtime posture, because a host that answers `/` cannot be assumed usable:

```bash
  # Set the host once; every check below uses it. A VARIABLE, not an angle-bracketed word:
  # the shell reads < and > as redirection, so https://<host>/login would truncate a file
  # named "host" and then try to write to /login instead of contacting anything.
HOST=localhost:5001

  # 6. All seven headers, on a dynamic response AND on a static asset. Six in Development.
curl -sI "https://$HOST/login" | grep -iE 'content-security-policy|strict-transport|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy'
curl -sI "https://$HOST/_content/WebVella.Erp.Web/js/wv-lazyload/wv-lazyload.js" | grep -ic 'content-security-policy'

  # 7. The content policy must be report-only at this stage, and the enforcing header ABSENT.
curl -sI "https://$HOST/login" | grep -ic 'content-security-policy-report-only'
curl -sI "https://$HOST/login" | grep -icE '^content-security-policy:'

  # 8. /login must NOT be 500. Over HTTPS expect 200; over plaintext expect 307 to https,
  #    or 200 when a trusted proxy forwards the HTTPS scheme.
curl -s -o /dev/null -w '%{http_code}\n' "https://$HOST/login"

  # 9. A listed origin completes preflight; an unlisted one receives no CORS header at all.
curl -sI -X OPTIONS -H 'Origin: https://listed.example.com' \
     -H 'Access-Control-Request-Method: GET' "https://$HOST/api/v3/en_US/meta/entity/list"
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
- **A `warn:` line about transport security now only ever appears in Development.** It means the
  condition was detected and reported rather than enforced, which is expected there because the
  Development antiforgery cookie follows the request scheme. Outside Development the identical diagnosis
  is a startup refusal, including when no endpoint is declared at all — that case used to be a warning
  and is not any more, because the server defaults it leaves in force are plaintext.

### State-changing checks — never against production

Use a throwaway account on a non-production instance, and take a database backup first.

```bash
  # Set this to the published entry assembly you are testing, then run the two checks unchanged.
  # A variable again, for the same reason as above.
HOST_DLL=WebVella.Erp.Site.dll

  # 10. Fail-fast negative test: start a host with a required secret removed. It must ABORT
  #     naming the missing setting and nothing else. If it starts, a fallback still exists.
env -u Settings__EncryptionKey ASPNETCORE_ENVIRONMENT=Production dotnet "$HOST_DLL"

  # 11. Transport negative test: with only a plaintext endpoint and none of ASPNETCORE_HTTPS_PORT /
  #     HTTPS_PORT / Settings__ForwardedHeaders__KnownProxies set, a non-Development host must ABORT
  #     and must never log "Now listening on".
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS='http://127.0.0.1:5199' dotnet "$HOST_DLL"

  # 11b. Three further transport negative tests, all of which must ABORT outside Development:
  #      no endpoint declared at all; the public HTTPS port supplied with no trusted proxy; and a
  #      trusted proxy supplied with no public HTTPS port. A malformed port must abort naming the key.
ASPNETCORE_ENVIRONMENT=Production dotnet "$HOST_DLL"
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS='http://127.0.0.1:5199' HTTPS_PORT=443 dotnet "$HOST_DLL"
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS='http://127.0.0.1:5199' \
  Settings__ForwardedHeaders__KnownProxies='10.0.0.7' dotnet "$HOST_DLL"
  #      A malformed port aborts in EVERY environment, Development included, because
  #      ReadPublicHttpsPort throws before the Development exemption is consulted:
ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS='http://127.0.0.1:5199' \
  HTTPS_PORT='not-a-port' dotnet "$HOST_DLL"

  # 12. Login throttling: a sixth consecutive failure must be refused.
  #     STATE CHANGE - this LOCKS OUT the account it is run against. Throwaway accounts only.
```

Also confirm, by exercising the application rather than by reading source: that a legacy credential
still signs in and is transparently rehashed; that the previously seeded default administrator
credential no longer authenticates; that a guest-role account cannot create users or roles; that no API
response returns a password hash for any role; that the file move and delete actions are refused for a
non-owner; and that an uploaded markup or vector file downloads as an attachment rather than rendering
inline.

For the mail transport, exercise the revocation path against your own relay rather than reasoning about
it: send a test message. If it fails with a chain status of **only** the CRL bullet, your relay's chain
has no reachable revocation source, and because no setting disables that check the chain must be fixed —
or a different relay used — before this platform can send through it in Production. Record `RISK-060`
while it stands. Re-send after publishing the CRL or OCSP endpoint; it must then deliver.

The diagnostic notification client in `WebVella.Erp.Web/Services/MailService.cs` **is** now covered, and
this paragraph used to say the opposite. Review finding `M-OPEN-03` closed it: that client now requires
validated STARTTLS, is disposed, and carries an explicit 15-second timeout, so a relay that offers no
STARTTLS or presents a certificate this host cannot validate makes the *notification* fail while the log
record it was announcing is already persisted. One difference from the send relay above is worth knowing
before you test: this client is `System.Net.Mail.SmtpClient`, which validates the chain, the validity
dates and the host name but does **not** check revocation, whereas MailKit does — so a relay whose
certificate chains to a CA this host trusts will satisfy the diagnostic client even without a reachable
CRL. If `Settings:EmailEnabled` is `true`, verify that relay and expect `system_log` rows to carry
notification status `NotificationFailed` (`4`) until it validates (`RISK-131`).

**Cleanup after the state-changing group:** wait out the fifteen-minute throttle window — a restart no
longer clears the counters, because they are durable and shared; if you must clear a lockout sooner,
delete the account's `wv_sec_lthr_acct_*` row from `plugin_data` **and** restart every instance holding
it in its positive mirror. Then delete the throwaway account and any guest-role
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
- **This page was consolidated from four separately written angles.** Each was accurate when written
  and the overlap between them had begun to contradict itself — one passage described the
  configuration files as still carrying live values, another described the content policy as
  carrying a `report-uri` directive that had been removed. Both are corrected above rather than left
  standing beside the current text.

## Related documents

- [Security audit report](security-audit-report.md) — every finding, in the mandated eight-field format.
- [Remediation log](remediation-log.md) — what changed, per vulnerability class, with verification.
- [Risk register](risk-register.md) — accepted risks, open decisions and residual exposure.
- [Credential migration guide](credential-migration.md) — how stored credentials are upgraded.
- [Security policy](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md) — how to report a vulnerability.
- [Third-party library inventory](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) — dependency versions, licences and advisory state.
- [Project README](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/README.md) — the shorter required-secrets summary this page expands.
