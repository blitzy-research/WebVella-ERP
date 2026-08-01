# Secure Configuration

Operator guide for running WebVella ERP securely: what you must supply, how to supply it, what the
platform now emits and enforces, and what is deliberately still open.

Findings are described in the [security audit report](security-audit-report.md), the changes in the
[remediation log](remediation-log.md), accepted risks in the [risk register](risk-register.md), and
the credential format change in the [credential migration guide](credential-migration.md).

## Read this first — the state of the shipped configuration

**The tracked `Config.json` files still contain development values.** At this commit
`WebVella.Erp.Site/Config.json` carries a live `ConnectionString` including a password, a live
`EncryptionKey`, and `"DevelopmentMode": "true"`. Scrubbing those files belongs to the
secret-management class, which is **not** part of this change and is recorded as `RISK-021`.

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
| Configuration provider chain | **The tracked JSON file is always first**, so a blanked value can never override a supplied secret — that precedence is the control, and it holds at all four builder sites. The shared fallback path used by the Crm, Mail, MicrosoftCDM, Next and Sdk hosts is **JSON file → environment variables → user secrets (Development only)** (`WebVella.Erp.Web/ErpMvcExtensions.cs:L143-L165`, reached only when `ErpSettings.IsInitialized` is still false). `WebVella.Erp.Site` (`Startup.cs:L50-L61`) and `WebVella.Erp.Site.Project` (`Startup.cs:L42-L51`) initialise `ErpSettings` themselves and place **environment variables last**, so the fallback never runs for them. `WebVella.Erp.ConsoleApp/Program.cs:L50-L51` is JSON file then environment variables, with no user-secrets provider. The two orderings differ **only** in whether a user secret or an ambient environment variable wins in Development when both define the same key; outside Development no user-secrets provider is added anywhere, so every host is exactly JSON file then environment variables |
| Missing-secret behaviour | Fail fast. `WebVella.Erp/ErpSettings.cs` aborts startup with an actionable message naming each missing or weak setting; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back, and the compiled-in default key is gone |
| Known published defaults | Rejected by SHA-256 digest comparison, so the repository's own example encryption key and token signing key cannot be used even if supplied deliberately |
| Response security headers | All seven emitted by `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, registered once through `AddErp` and ordered in **all seven** hosts ahead of `UseResponseCompression` and both `UseStaticFiles` calls |
| Content-Security-Policy | Emitted in **report-only** mode with a real collection endpoint at `/csp-violation-report` (`RISK-022`) |
| Transport security | `UseHsts()` then `UseHttpsRedirection()` in all seven hosts, guarded to non-Development and ordered **after** `UseCors` so cross-origin preflight is not broken by a redirect |
| Cookies | `SecurePolicy` always outside Development, `SameSite=Lax`, explicit expiry window |
| Rate limiting | `UseRateLimiter()` in all seven hosts, positioned after both static-file middlewares so assets are never throttled |
| Login throttling | Per-account and per-address counters over a bounded private store, consulted at the login page and at the anonymous token route (`RISK-008`) |
| Build gate | `Directory.Build.props` — dependency auditing at `all`/`low` with `NU1901`–`NU1904` promoted to errors, and .NET analyzers at `latest-recommended` kept as warnings. Verified inherited by **19 of 19** projects |
| Toolchain pin | `global.json` pins `10.0.302` with `rollForward: disable`, because both gates are SDK-version dependent |
| Still open | `AllowAnyOrigin()` at `WebVella.Erp.Site/Startup.cs:L81` and `WebVella.Erp.Site.Project/Startup.cs:L69` (`RISK-013`); shipped secrets (`RISK-021`); SMTP certificate validation (finding `H-11`); two bearer-token error paths that return stack traces unconditionally (`RISK-014`) |

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

#### Choosing key values

| Key | Requirement |
| --- | --- |
| `Settings:Jwt:Key` | The signing algorithm is HMAC-SHA-256, so supply **at least 32 bytes** of key material — 256 bits. Generate it from a cryptographically secure random source, for example `openssl rand -base64 48`. Do not use a human-readable phrase, and do not repeat a short string to reach the length; the value that shipped in this repository did exactly that and is finding H-04. |
| `Settings:EncryptionKey` | Generate from a CSPRNG. See §3 before changing this value on an **existing** installation — changing it can make previously encrypted data unreadable. |
| `Settings:ConnectionString` | Use a least-privilege PostgreSQL role. The role needs DDL rights because schema provisioning is code-driven, but it does not need `SUPERUSER`. |

Rotate all three if this repository's shipped values were ever deployed.

---

### 2. How settings are supplied

#### The mechanism as it stands today

Configuration is read from a **JSON file only**. Both configuration builders in the platform are:

```csharp
new ConfigurationBuilder().SetBasePath(...).AddJsonFile(configPath)
```

* `WebVella.Erp.Web/ErpMvcExtensions.cs` — inside `UseErp`, base path `env.ContentRootPath`, file
  `config.json`, used to build the configuration passed to `ErpSettings.Initialize`.
* `WebVella.Erp.Site*/Startup.cs` — base path `Directory.GetCurrentDirectory()`, used for the host's
  own `Configuration` property (which is what supplies the JWT parameters to the authentication
  handler).

Two consequences follow, and both matter operationally:

1. **The file source is not optional.** The configuration files cannot be deleted — startup fails
   outright without them. Scrub the values; keep the files.
2. **Environment variables and user secrets are not yet consulted by these builders.** The startup
   failure messages name the `Settings__*` environment-variable forms because that is the intended
   supply channel, and the naming convention above is the one those variables will use — but the
   provider chain has not yet been extended, so **today the values must be present in the JSON file.**

> **Status — open gap.** Extending the chain with `AddEnvironmentVariables()` (and user secrets in
> development) at the two sites named above is the remaining part of the secret-management
> remediation. It is recorded here rather than implied, so that an operator following this guide is
> not misled into believing an environment variable alone is sufficient at this commit. Until it
> lands, treat the JSON file as the only supply channel and protect it accordingly: restrict its
> filesystem permissions to the service account, and keep it out of source control in your
> deployment pipeline.

#### The file the runtime actually reads

`UseErp` looks for **`config.json`** — lower-case — relative to the content root. The repository
ships **`Config.json`** with a capital `C`, which is what the build copies to the output directory.
On a case-sensitive filesystem such as Linux these are different names, so after publishing you must
provide the lower-case name in the output directory:

```bash
cd WebVella.Erp.Site/bin/Debug/net10.0
cp Config.json config.json
```

Do **not** solve this by adding a lower-case `config.json` next to `Config.json` in the *source*
directory. MSBuild item identity is case-insensitive, so the two names collide and the build fails
with `NETSDK1022`. Copy it in the output directory, or in your deployment step.

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

> **Status.** The middleware and its options type exist. It is **not yet registered in any host
> pipeline** at this commit, so the headers are not being emitted yet. Registration and — critically
> — *ordering* are the remaining step; see below.

#### Ordering matters

Register the middleware **early**, ahead of response compression and ahead of static-file serving.
Placed after them, the headers reach dynamic responses only, and static assets and compressed
responses are served without them. `Strict-Transport-Security` must come before HTTPS redirection.

#### The content policy ships in report-only mode

`SecurityHeadersOptions.ContentSecurityPolicyReportOnly` defaults to `true`, which emits
`Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. **Only the header name
changes; the policy value is identical in both modes.**

This is deliberate, and it is the one place where the mandated header set cannot be *enforced* on
first deployment without breaking the interface. The platform contains components that emit inline
script and author-supplied markup by design — the HTML-block page component and the generated
inline-script emitters. A strictly enforced `script-src 'self'` suppresses them, and the affected
screens stop working.

Roll it out in this order:

1. **Deploy report-only** (the default). Nothing breaks; violations are reported, not blocked.
2. **Collect violation reports** and exercise every screen that renders authored markup or generated
   inline script — the HTML-block component, the sitemap component, the page-body manager.
3. **Resolve each violation** by moving inline script into a served file, or by adding a nonce or hash
   for the emissions that must stay inline.
4. **Flip `ContentSecurityPolicyReportOnly` to `false`** once the reports are clean, and re-test the
   same screens.

Do not skip step 2. The four raw-output channels are the concrete reason this staging exists. They
are not defects to be encoded away — encoding them would disable the features they implement — so the
control that applies to them is a compensating one: authoring markup or script requires a privileged
role. That acceptance belongs in the [risk register](risk-register.md), which is where this
engagement records accepted risk as each vulnerability class lands.

---

### 6. Transport security

| Control | Guidance |
| --- | --- |
| TLS version | TLS 1.2 or above. Terminate TLS at the reverse proxy or configure Kestrel directly; the platform does not manage certificates. |
| HTTPS redirection | Enable it, guarded to non-development environments. |
| HSTS | Enable it, guarded to non-development environments, ordered **before** redirection. Do not enable HSTS on a hostname you also serve over plain HTTP for other purposes — the `includeSubDomains` directive applies to every subdomain. |
| Cookies | `Secure`, `HttpOnly` and an explicit `SameSite` policy. Use `SameSite=Lax`, not `Strict`: `Strict` breaks the return-URL round trip through the login page, and `Lax` is the framework's documented default posture. |

**Sequencing caveat — this one bites.** Introducing HTTPS redirection *before* the cross-origin
policy is tightened breaks CORS preflight requests, which fail with an invalid-redirect error rather
than an obvious redirect. Change the origin allow-list and enable redirection **together**, and
verify a preflight from an allowed origin afterwards.

#### Cross-origin policy

Two hosts ship a permissive any-origin policy — `WebVella.Erp.Site` and `WebVella.Erp.Site.Project`
(finding H-14). Replace it with an explicit allow-list of the origins your deployment actually
serves. Each of those two files contains a restrictive named policy in commented-out form directly
above the permissive one; use its shape.

The other five hosts already use a restrictive named policy and need no change — though note that
their allowed origins are hard-coded to localhost values, which you will want to replace with your
own for a real deployment.

---

### 7. Toolchain pinning and gate reproducibility

`global.json` pins the SDK:

```json
"sdk": { "version": "10.0.302", "rollForward": "disable" }
```

This is a security control, not housekeeping (finding L-07). Both halves of the automated gate are
SDK-version dependent: the dependency-audit defaults and the analyzer rule set. An unpinned toolchain
means the same source can produce a different gate result on a different machine, which makes every
"scan is clean" claim unverifiable. `rollForward: disable` is what the tree now carries, and it is the stricter of the two candidates: it
freezes the toolchain to the exact version above and fails predictably, with an actionable message
naming the required version, when it is not installed. The weaker `latestPatch` accepts security
patches to the SDK
itself while holding the feature band.

`Directory.Build.props` at the repository root carries the gate and is inherited by every project:

| Property | Value | Effect |
| --- | --- | --- |
| `NuGetAudit` | `true` | Dependency auditing on. |
| `NuGetAuditMode` | `all` | Direct **and transitive** packages are audited. |
| `NuGetAuditLevel` | `low` | Advisories of every severity are reported, not just High and Critical. |
| `WarningsAsErrors` | appends `NU1901;NU1902;NU1903;NU1904` | A package advisory **fails the build**. |
| `EnableNETAnalyzers` | `true` | The .NET analyzers run on every compilation. |
| `AnalysisLevel` | `latest-recommended` | The recommended rule set, including the security rules. |

It must be an MSBuild properties file rather than an editor-configuration file: the four
`.editorconfig` files in this repository each declare `root = true`, so a repository-root editor
configuration would not reach the files inside those subtrees. MSBuild inheritance is not affected by
that scoping.

Analyzer diagnostics remain **warnings**. Only the four dependency codes are errors. Promoting the
analyzer backlog on roughly 700 pre-existing files would demand a mass refactor, which is out of
scope; the dependency codes are errors because they are actionable by a version change.

---

### 8. Verifying a deployment

```bash
# Dependency gate: must report no vulnerable packages, for every project.
dotnet restore WebVella.ERP3.sln
dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive

# All 19 projects are solution members, so the command above covers every one of them.
# (Both WebAssembly projects were outside the solution when this guide was first written;
#  they were added, and retargeted from net7.0 to net10.0, in the same change.)

# Static analysis gate: must be 0 errors. Analyzer diagnostics appear as warnings.
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

---

### Method and limitations

Stated plainly, so the confidence attached to each claim is visible:

* **Every setting name, default and validation rule above was read from the source** —
  `WebVella.Erp/ErpSettings.cs`, `WebVella.Erp/Utilities/CryptoUtility.cs`,
  `WebVella.Erp.Web/ErpMvcExtensions.cs` and the host `Startup.cs` files — not from the specification.
  Where the code and the specification disagreed, the code is what is documented.
* **The `Settings:Jwt` host table was produced by inspecting all eight shipped configuration files**,
  not inferred from which hosts appear to use tokens.
* **Two status gaps are disclosed rather than smoothed over**: the configuration provider chain does
  not yet read environment variables (§2), and the headers middleware is not yet registered in any
  host pipeline (§5). Both are stated at the point where an operator would otherwise be misled.
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
to the configuration model those commits establish. Not every class has landed yet, so the table
below states plainly what is enforced in the current tree and what arrives with a later commit.
Nothing here is asserted as already true when it is not.

| Control | Status in the current tree |
| --- | --- |
| Required-secret validation at startup, with fail-fast and no compiled-in fallback | **In force.** `WebVella.Erp/ErpSettings.cs` validates the required values; `WebVella.Erp/Utilities/CryptoUtility.cs` throws rather than falling back |
| Compiled-in default encryption key | **Removed.** The constant is gone from `CryptoUtility.cs`; a comment records what stood there and why |
| Compiled-in default token signing key | **Removed.** `ErpSettings.cs` reads `Settings:Jwt:Key` with no literal default |
| Credential hashing primitive (salted, work-factored, fixed-time verification) | **In force** in `WebVella.Erp/Utilities/PasswordUtil.cs`. Its call sites are switched by the credential-integrity class — see the [credential migration guide](credential-migration.md) |
| Dependency-audit and analyzer build gate | **In force.** `Directory.Build.props` and the `global.json` toolchain pin |
| Response security headers | Middleware **implemented** (`WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`); **registration and per-host ordering land with the transport class** |
| Login lockout after five failed attempts | Service **implemented** (`WebVella.Erp.Web/Services/LoginThrottleService.cs`); **consultation at the login entry point lands with the brute-force class** |
| Configuration provider chain extended beyond the JSON file | **Pending** — lands with the secret-management class, and it must land **before** any shipped value is blanked |
| Shipped `Config.json` secret values blanked, `DevelopmentMode` disabled | **Pending** — the eight files still carry live values in the current tree |
| `web.config` environment marker set to `Production` | **Pending** |
| Origin allow-list, HSTS, HTTPS redirection, rate limiting | **Pending** — transport and rate-limiting classes |
| SMTP certificate validation restored | **Pending** — the five bypass sites are still present |

Because the shipped configuration files still carry live secrets in the current tree, the
[rotation instruction below](#key-rotation-is-mandatory) is **more** urgent than it will be after the
scrub, not less.

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
| `Settings__EmailSMTPPassword` | `Settings:EmailSMTPPassword` | Only when e-mail is enabled | Ships empty |
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

> **State at this commit:** the scrub described in this section has **not** been performed — the
> tracked `Config.json` files still carry a live connection string, encryption key and
> `DevelopmentMode: true`. What *has* landed is the enabling change: the provider chain now consults
> environment variables, so a value can be supplied without editing a tracked file. Read this section
> as the ordering constraint the secret-management class must respect (`RISK-021`).

Configuration is built in `WebVella.Erp.Web/ErpMvcExtensions.cs` from a JSON file and, in the
current tree, nothing else: a `ConfigurationBuilder` with a base path and `AddJsonFile("config.json")`,
with **no** environment-variable provider, **no** user-secrets provider, and the file source **not**
marked optional. `WebVella.Erp.ConsoleApp/Program.cs` and each host builder follow the same pattern.

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
- Once the reports contain nothing but those known components and each has been addressed, flip the
  report-only switch on the middleware options to emit the enforcing `Content-Security-Policy` header
  instead. The value does not change when you do.

**The policy value is never silently weakened and the interface is never silently broken.** Staging
the delivery mode is the only way to honour both the mandated header set and the requirement that
existing functionality keep working.

### HSTS and HTTPS redirection

Both are guarded to non-development environments, and **HSTS is ordered first**, before redirection.

**The caveat that dictates deployment order:** HTTPS redirection breaks cross-origin preflight
requests with an invalid-redirect error. It must therefore be deployed **together with** the origin
allow-list described below, never ahead of it, and both must be verified in the same step — a listed
origin must still complete preflight successfully with redirection active.

**A second caveat, measured rather than assumed: `UseHttpsRedirection()` is silently inert unless the
application knows an HTTPS port.** Started with `ASPNETCORE_ENVIRONMENT=Production` and only an HTTP
endpoint, the host emitted `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every
response — the header half works — while the redirection half logged
`Failed to determine the https port for redirect.` and passed plaintext requests through untouched.
That is the framework's documented behaviour, not a defect here, but it means an operator who
terminates TLS at a proxy and forwards plaintext gets HSTS and **no** redirect unless they also supply
`ASPNETCORE_HTTPS_PORTS` (or `https_port`) and forward the protocol with
`UseForwardedHeaders`. Treat "redirects plaintext" as conditional on that configuration and verify it
on the deployed topology rather than trusting the middleware's presence in the pipeline.

Before this remediation, HSTS was used nowhere in the platform except
`WebVella.Erp.WebAssembly/Server/Program.cs`.

### Origins, mail transport, environment and request limits

#### The origin allow-list

Configure an explicit allow-list at the **two** hosts that were permissive: `WebVella.Erp.Site` and
`WebVella.Erp.Site.Project`. Both previously combined any-origin, any-method and any-header, which
places no restriction at all.

**Two hosts, not seven.** The other five — `WebVella.Erp.Site.Crm`, `WebVella.Erp.Site.Mail`,
`WebVella.Erp.Site.MicrosoftCDM`, `WebVella.Erp.Site.Next` and `WebVella.Erp.Site.Sdk` — already use
a restrictive named policy and are deliberately left alone. Their hard-coded localhost origins are a
separate low-severity item recorded in the [risk register](risk-register.md). Overstating this
finding's breadth was one of the false-positive classes the audit explicitly eliminated.

#### SMTP certificate validation

The mail plugin used to install an always-true certificate validation callback unconditionally at
five sites, four in `WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` and one in
`WebVella.Erp.Plugins.Mail/Services/SmtpInternalService.cs`. That accepts any certificate from any
server, which defeats transport authentication entirely.

The replacement is an explicit configuration flag that **defaults to secure**. A self-signed
development mail server stays usable through deliberate opt-in, so a development convenience can
never again ship as a production default. **Leave the opt-in off in production**, and treat a
certificate failure as a signal to fix the server's certificate rather than to disable the check.

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
  authentication-hardening standard, and it is consulted at the platform's single login entry point.
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
WarningsAsErrors    $(WarningsAsErrors);NU1901;NU1902;NU1903;NU1904
EnableNETAnalyzers  true
AnalysisLevel       latest-recommended
```

`NU1901`, `NU1902`, `NU1903` and `NU1904` are the dependency-audit diagnostics for low, moderate,
high and critical severity. **A dependency advisory therefore fails the build by design.** That is
the gate working, not a defect.

Several of these choices need their reasons recorded.

- **The audit mode covers transitive dependencies explicitly, not by default.** This graph really
  does contain a transitive advisory — MimeKit is reached only through MailKit — so a direct-only
  audit would never have reported `GHSA-g7hc-96xr-gvvx`. The default also varies by toolchain
  version, and a gate resting on a floating default is not reproducible.
- **The mechanism is MSBuild rather than a repository-root `.editorconfig`.** The four
  `.editorconfig` files in this repository each declare `root = true`, so a root editor-config would
  not reach any file inside the four subtrees that hold the code this remediation touches.
  `Directory.Build.props` is imported by every project regardless.
- **`global.json` pins the SDK** to `10.0.302` with `rollForward: latestPatch`. That keeps the pin
  deterministic on one feature band while still accepting an SDK security patch. A bare pin would
  accept a newer feature band and reintroduce non-reproducibility; disabling roll-forward entirely
  would make the repository unbuildable on a machine carrying only a patched SDK.
- **Analyzer diagnostics remain warnings.** Only the four dependency codes are errors. Promoting
  roughly 700 source files' worth of pre-existing analyzer warnings would demand exactly the mass
  refactor the change scope forbids. The static-analysis gate passes when there are zero diagnostics
  in the **active** security rule families across the remediated files, not repository-wide.

#### What the static-analysis gate does and does not cover

This boundary was measured rather than assumed, because an operator who over-trusts the gate is worse
off than one who knows its limits.

| | Rule families | Evidence |
| --- | --- | --- |
| **Active** | Weak and broken hashing algorithms; disabled transport certificate validation | `CA5351` reports on the retained legacy credential path and `CA5359` at the five mail-transport sites. A probe compiled against these properties also raised `CA5350`. |
| **Not active** | Hard-coded encryption keys; non-random initialisation vectors; and by extension the dataflow families - SQL and query construction, insecure deserialisation, cross-site scripting and file canonicalisation, regular-expression injection, cookie security, disabled token-validation checks | The same probe deliberately hard-coded an AES key and passed a caller-supplied initialisation vector. Neither `CA5390` nor `CA5401` reported. These are dataflow/taint rules and are not enabled at `latest-recommended`. |

**The consequence is the important part: a clean build is not evidence that the inactive families
are clean.** Do not read the absence of a `CA5390` or `CA3002` diagnostic as an assurance that no
hard-coded key or cross-site-scripting sink exists. Those findings were identified by manual review
during the audit, not by this gate.

Enabling the dataflow families requires an explicit opt-in beyond the properties above. It is
deliberately not done here, because it would surface a large volume of findings across roughly 700
pre-existing source files — the mass refactor the change scope forbids. The residual coverage gap is
recorded in the [risk register](risk-register.md) rather than left implied, and closing it is a
reasonable follow-up once the pre-existing warning backlog is addressed.

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
- **A solution-level command now reaches all 19 projects.** When this guide was first written
  `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` were not solution members
  and had to be audited explicitly. Both were added to `WebVella.ERP3.sln` and retargeted to
  `net10.0` in the same change, so the per-project commands below are no longer necessary — they are
  kept only as the way to audit a project that is ever added to the repository without being added to
  the solution:

```bash
dotnet list WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj package --vulnerable --include-transitive
dotnet list WebVella.Erp.WebAssembly/Shared/WebVella.Erp.WebAssembly.Shared.csproj package --vulnerable --include-transitive
```

  Both are clean, and both inherit the same gate properties through `Directory.Build.props`, but a
  continuous-integration job that only restores the solution will never look at them. That residual
  coverage gap is recorded in the [risk register](risk-register.md); it is stated here so that nobody
  reads a green solution build as covering all nineteen projects.

One open decision currently sits on top of this gate: with the dependency codes promoted to errors, a
build cannot be green while a vulnerable package remains, and the object-mapping library's advisory
can only be cleared by moving to a version whose licence terms are a repository-owner question. That
decision is recorded in the [risk register](risk-register.md) and is deliberately not settled here.

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

**Read this before anything else in this section.** The shipped `Config.json` files **still contain
development values** — connection strings with passwords, a development-mode flag set to `true`, and a
token signing key that is published in this public repository. Scrubbing them belongs to a separate
vulnerability class that has not landed yet; it is tracked as `RISK-021` in
[the risk register](risk-register.md).

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

1. The JSON configuration file (`Config.json` / `config.json`).
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

A report-collection endpoint at **`/csp-violation-report`** is handled inside the middleware, ahead of routing and authentication, so reports arrive without requiring a session. It accepts reports and logs them.

**Its logging is rate-limited to 120 reports per minute, deliberately at the logging step rather than the acceptance step.** A browser that has its report rejected does not resend it, so refusing reports would silently corrupt the evidence the report-only stage exists to gather. Bounding the log instead protects the log from flooding by an anonymous caller while keeping every accepted report's effect on behaviour identical.

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
| `SecurePolicy` | `Always` outside Development, `SameAsRequest` in Development | The cookie must not traverse plaintext; the Development relaxation keeps `http://localhost` working |
| `SameSite` | `Lax` | `Strict` breaks the return-URL round trip through the login page. `Lax` is the framework's documented default posture |
| `ExpireTimeSpan` | 8 hours | A bounded working session |
| `SlidingExpiration` | `false` | A sliding window renews indefinitely while a session is merely *open*, which is precisely what an attacker with a stolen cookie wants |
| `HttpOnly` | `true` | Script cannot read the ticket |

#### A configuration incoherence that was fixed

All seven hosts declared `ExpireTimeSpan = 8h`, but the authentication ticket was constructed with an **explicit `ExpiresUtc` of 24 hours**, and an explicit `ExpiresUtc` *overrides* `ExpireTimeSpan`. The real lifetime was therefore 24 hours - three times what every host declared - and seven hosts' configuration was inert.

The ticket expiry is now aligned to **480 minutes**, so the declared value and the effective value agree.

**This reduction is invisible at the HTTP layer, and that is expected.** Because the ticket is not persistent, the cookie is a session cookie with no `expires` or `max-age` attribute; the bound lives inside the encrypted ticket payload. Do not try to verify it by reading response headers. One related trap: the login redirect carries a top-level `expires: Thu, 01 Jan 1970 ...` header, which is a **cache** header and not a cookie attribute - it says nothing about session lifetime.

Ticket refresh is disabled (`AllowRefresh = false`), so a ticket cannot extend itself.

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
* **The shipped `Config.json` files still set `"DevelopmentMode": "true"`.** Correcting that in the
  tracked files belongs to the secret-management class and has not landed (`RISK-021`), so you must set
  it to `false` — or override it by environment variable — as part of deployment.

Development mode also relaxes the cookie `SecurePolicy` and suppresses HSTS and HTTPS redirection, so leaving it on disables several controls in this document at once.

### 8. Open items that affect configuration

Recorded here because they change what an operator must compensate for. Both are tracked in [the security audit report](security-audit-report.md).

* **Two hosts still serve a permissive `Access-Control-Allow-Origin: *`.** `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` use an any-origin CORS policy; this was confirmed live on the login response across three independent verification runs. The other five hosts already use a restrictive named policy. Until the two permissive policies are replaced with an explicit allow-list, restrict cross-origin access at your reverse proxy.
* **Two error paths return stack traces unconditionally.** On the bearer-token routes, error text is returned to the caller regardless of environment, so setting `Production` does **not** suppress it. It was confirmed live that a failed token request returns exception text to an anonymous caller.

### 9. Verifying a deployment

```bash
# 1. All seven headers, on a dynamic response AND on a static asset.
curl -sI https://your-host/ | grep -iE 'content-security-policy|strict-transport|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy'
curl -sI https://your-host/_content/WebVella.TagHelpers/lib/toastr/toastr.min.css | grep -ic 'content-security-policy'

# 2. CSP must be report-only at this stage.
curl -sI https://your-host/ | grep -i 'content-security-policy-report-only'

# 3. Plaintext must redirect, and HSTS must be present outside Development.
curl -sI http://your-host/ | head -1

# 4. The token route must refuse cleanly when no signing key is configured,
#    and must not return a stack trace.
curl -s -X POST https://your-host/api/v3/en_US/auth/jwt/token \
     -H 'Content-Type: application/json' -d '{"email":"x@y.z","password":"wrong"}'

# 5. Login throttling: a sixth consecutive failure must be refused.
#    Run against a test account you own, then restart to clear the counter.
```

Confirm as well that the seeded administrator credential no longer authenticates, and that a guest-role account cannot create users or roles.

### Related documents

* [Security audit report](security-audit-report.md) - every finding, with evidence.
* [Remediation log](remediation-log.md) - what changed per vulnerability class.
* [Risk register](risk-register.md) - accepted risks and recommendations.
* [Credential migration guide](credential-migration.md) - the password-hash migration.
* [Security policy](https://github.com/WebVella/WebVella-ERP/blob/master/SECURITY.md) - how to report a vulnerability.
* [Third-party libraries](https://github.com/WebVella/WebVella-ERP/blob/master/LIBRARIES.md) - dependency inventory and licensing.


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

`ErpSettings.Initialize` validates the required values in one pass and reports **every** missing key
in a single startup failure, so a mis-provisioned deployment does not need one restart per variable.
Only configuration key *names* are reported — never values, prefixes, lengths or digests — so a
startup failure cannot leak key material into a console, a log file or a crash report (CWE-532).

### How values are supplied

#### The provider the hosts register today

`ErpMvcExtensions` builds configuration from **one non-optional JSON file**:

```csharp
new ConfigurationBuilder().SetBasePath(env.ContentRootPath).AddJsonFile(configPath)
```

where `configPath` is `config.json`, resolved from the host's content root. No environment-variable
provider and no user-secrets provider is registered by any host at present. Two consequences follow,
and both matter operationally:

* **`config.json` is the only supply channel that works today.** Each required value must be present
  in that file for the host to start.
* **The file is not optional.** It cannot be deleted or renamed away; a host with no `config.json`
  fails during initialization.

#### Ordering prerequisite before any value is scrubbed

The shipped `Config.json` files still carry live connection strings, a live encryption key and, for
the two token-issuing hosts, a live signing key. Replacing those values with blanks is a **separate
change with a hard prerequisite**: the configuration provider chain must be extended *first*.
Scrubbing before the chain is extended leaves operators with no channel by which to supply the
secrets, and every host then fails to start.

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
`Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`.

Report-only is not a weakened policy — the value is exactly the mandated one. It is a rollout mode,
required because four components deliberately emit inline script or author-supplied markup and a
strictly enforced `script-src 'self'` would suppress them, breaking working features. Move to
enforcement as follows:

1. Deploy with report-only left at its default and collect violation reports across the screens in
   real use, including the page-component designer and the sitemap form.
2. Eliminate or externalize the inline script the reports identify, or extend the policy value for
   exactly those cases.
3. Set `ContentSecurityPolicyReportOnly` to `false` to switch the same value to enforcement.

#### Wiring the middleware into a host

The middleware ships with its registration extension but is not yet added to any of the seven site
host pipelines. Each host must:

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

`global.json` pins the SDK to `10.0.302` with `rollForward: latestPatch`. Both the NuGet audit
defaults and the analyzer rule set are SDK-version dependent, so an unpinned toolchain makes the
dependency gate and the static-analysis gate non-reproducible — a scan result that varies with
whatever SDK happens to be installed is not evidence (finding L-07). `Directory.Build.props` at the
repository root carries the gate itself: dependency auditing across all dependencies at the lowest
reporting level, the four NuGet audit diagnostics promoted to build errors, and the .NET analyzers
enabled at the recommended level.
