[NEW PROJECT ALERT] Check out our new project for [Data collaboration - Tefter.bg](https://github.com/WebVella/WebVella.Tefter).

[NEW PROJECT ALERT] Check out our new project for [Document template generation](https://github.com/WebVella/WebVella.DocumentTemplates).

---

[![Project Homepage](https://img.shields.io/badge/Homepage-blue?style=for-the-badge)](https://webvella.com)
[![Dotnet](https://img.shields.io/badge/platform-.NET-blue?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![GitHub Repo stars](https://img.shields.io/github/stars/WebVella/WebVella-ERP?style=for-the-badge)](https://github.com/WebVella/WebVella-ERP/stargazers)
[![Nuget version](https://img.shields.io/nuget/v/WebVella.ERP?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![Nuget download](https://img.shields.io/nuget/dt/WebVella.ERP?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![License](https://img.shields.io/badge/Apache--2.0-green?style=for-the-badge)](https://github.com/WebVella/WebVella-ERP/blob/master/LICENSE.txt)

---

# WebVella ERP

**WebVella ERP** is a free and open-source web software, that targets extreme customization and plugability in service of any business data management needs. It is build upon our experience, best practices and the newest available technologies. Currently it targets ASP.NET Core on **.NET 10** — all nineteen projects declare `net10.0`, so the previous claim of ASP.NET Core 9 was stale. Our database of choice is PostgreSQL 16. Targets Linux or Windows as host OS. Currently tested only on Windows.

If you want this project to continue or just like it, we will greatly appreciate your support of the project by:

- giving it a "star"
- contributing to the source
- Become a Sponsor: Click on the Sponsor button and Thank you in advance

Related repositories

[WebVella-ERP-StencilJs](https://github.com/WebVella/WebVella-ERP-StencilJs)

[WebVella-ERP-Seed](https://github.com/WebVella/WebVella-ERP-Seed)

[WebVella-TagHelpers](https://github.com/WebVella/TagHelpers)

## Configuration: required secrets

**Read this before the first run.** The tracked `Config.json` files ship with every secret-bearing value
**empty**, and the application deliberately refuses to start until the connection string and the encryption
key are supplied. This is the remediation for security findings H-05, H-04 and C-04 (CWE-798 hard-coded
credentials, CWE-321 hard-coded cryptographic key): the connection string, the data-at-rest encryption key
and the bearer-token signing key used to be committed to this public repository, which made them identical
across every deployment and impossible to rotate. The signing key is handled differently from the other
two — its absence disables the bearer-token routes rather than stopping the host; see the table below.

The eight `Config.json` files are **retained, never deleted** — only emptied. Every key stays in place with
an empty value for two reasons: the JSON configuration source is **non-optional** in every host builder, so
deleting the file breaks startup outright rather than falling back to the environment; and the keys
themselves are the record of what a deployment has to provide.

Two settings are mandatory for every host and for the console application:

| Setting | Environment variable | Notes |
| --- | --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` | The PostgreSQL connection string. |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` | At least 32 US-ASCII characters, unique per deployment; 64 hex characters — 256 bits — is the recommended shape. The key published in this repository's history is rejected. |

Three more are conditional:

| Setting | Environment variable | When it is needed |
| --- | --- | --- |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` | Only for the hosts that issue tokens — `WebVella.Erp.Site` and `WebVella.Erp.Site.Project`. At least 32 bytes. While it is absent the token issue and refresh routes disable themselves rather than sign forgeable tokens; cookie login is unaffected. |
| `Settings:InitialAdministratorPassword` | `Settings__InitialAdministratorPassword` | **Required** on a brand-new database, and on an upgrade of an installation still holding the old shipped default. Sets the first administrator's password; the shipped default `erp` no longer exists (finding C-01). There is **no generated fallback** — if it is absent, blank, or does not satisfy the policy, provisioning **fails fast** rather than seeding a weak administrator or inventing a credential it would then have to print somewhere durable. It must be 12–128 characters and contain a lower-case letter, an upper-case letter, a digit and a symbol. Every message about it names the **setting**, never the value, its length or a digest. The account is flagged **change-required-on-first-login**: it can sign in interactively to rotate the password, but cannot issue an API bearer token until it has been rotated. |
| `Settings:EmailSMTPPassword` | `Settings__EmailSMTPPassword` | Only when outgoing mail is enabled. |

`Settings:InitialAdministratorPassword` is the one entry above that is deliberately **not** declared in any
`Config.json`, because a first-run credential has no business being written into a tracked file at all: it is
read from configuration like every other setting, but it is expected to arrive as an environment variable or a
user secret and to be withdrawn once provisioning has run. Every other `Settings:` entry in the tables above
is a key you can see in `WebVella.Erp.Site/Config.json`; the optional `Settings:ForwardedHeaders` proxy lists
mentioned further down are the only other configuration path named here that the shipped file does not declare.

Two overrides and one hosting variable complete the set:

| Setting | Environment variable | When it is needed |
| --- | --- | --- |
| `Settings:Jwt:Issuer` | `Settings__Jwt__Issuer` | Only to override the shipped value; blank falls back to `webvella-erp`. |
| `Settings:Jwt:Audience` | `Settings__Jwt__Audience` | Only to override the shipped value; blank falls back to `webvella-erp`. |
| *(hosting environment)* | `ASPNETCORE_ENVIRONMENT` | Recommended everywhere, and it must **not** be `Development` in production: that setting engages the developer exception page and its stack traces (finding H-12, CWE-489/CWE-209). `WebVella.Erp.Site/web.config` now ships `Production`; override it on the host, never in source. |

Configuration is read from **`Config.json`** first — note the capital `C`, and note that it is resolved from
the directory the application was loaded from rather than from the working directory — then from environment
variables, then, in the Development environment only, from user secrets, so a later provider always wins.
Startup aborts with a message naming every missing setting; the message never prints a value.

```bash
export Settings__ConnectionString='Server=localhost;Port=5432;User Id=...;Password=...;Database=...;'
export Settings__EncryptionKey="$(openssl rand -hex 32)"
```

```powershell
$env:Settings__ConnectionString = 'Server=localhost;Port=5432;User Id=...;Password=...;Database=...;'
$env:Settings__EncryptionKey = '<64-hex-characters>'
```

**Environment variables are the supply channel that works everywhere** — all seven site hosts and the
console application. Use them unless you have a specific reason not to.

In Development, and **for one project only**, the same values can be kept out of the shell and out of the
process environment with user secrets, which take the single-colon key path rather than the double
underscore — the two spellings name the same setting. The command must name that project, because the
repository root contains no project file of its own:

```bash
dotnet user-secrets set "Settings:EncryptionKey" "<64-hex-characters>" --project WebVella.Erp.Site
```

**`--project` is not optional here, and the reason is worth knowing.** A user-secrets store is keyed by the
project's `UserSecretsId`, and each executable in this repository declares **its own**, so a value set for
one host is invisible to another. Run the command once per executable you intend to start:

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

**Do not run `dotnet user-secrets init`.** It would generate a *new* identifier and write it into the
tracked project file, orphaning every store already created against the value above. The identifiers are
already declared and are stable on purpose; the store itself lives outside the repository, in the user
profile, so naming one here adds nothing secret to the tree.

**Generating secrets.** Use a cryptographically secure generator; never a passphrase, a dictionary word, or a
literal reused across deployments:

```bash
openssl rand -hex 32     # Settings__EncryptionKey - 64 hex characters
openssl rand -base64 48  # Settings__Jwt__Key - 48 random bytes
```

**Absent means refuse to start, by design.** A missing or weak required secret aborts startup with a message
that names the setting and its environment variable and never prints a value. That replaced a silent fallback
to an encryption key compiled into the source and published in this repository (finding C-04, CWE-798
hard-coded credentials / CWE-321 hard-coded cryptographic key), so the refusal is the remediation rather than
a rough edge: Validation Gate 3 asserts it with a negative test — start a host with a required secret absent
and it must fail fast, not run on a key everyone can read. Bearer-token setup is walked through step by step
in [WebVella.Erp.Site/JWT_README.txt](WebVella.Erp.Site/JWT_README.txt).

**One more thing is required to sign in outside Development: the application must be able to see an
HTTPS request.** In that posture the authentication and antiforgery cookies are `Secure`-only by design
(finding M-02, CWE-614), so on a host reachable only over plaintext `/login` answers **HTTP 500** and no
sign-in is possible. Development keeps the authentication cookie `Secure` but lets the antiforgery cookie
follow the request scheme so local plaintext sign-in remains usable. Bind an HTTPS endpoint, or tell the
application about the HTTPS port your proxy terminates on:

```bash
export ASPNETCORE_URLS='https://localhost:5001;http://localhost:5000'
export Kestrel__Certificates__Default__Path=/path/to/certificate.pfx
export Kestrel__Certificates__Default__Password='...'
# Behind a TLS-terminating proxy instead, either:
#   export ASPNETCORE_HTTPS_PORT=443                      # singular; redirects plaintext to HTTPS
#   export Settings__ForwardedHeaders__KnownProxies=<ip>  # and have the proxy send X-Forwarded-Proto
```

Outside Development the startup check reports this in **two different ways**, and the difference matters
because only one of them stops a deployment:

| What configuration declares | Outside Development | Why |
| --- | --- | --- |
| Endpoints **are** declared — through `ASPNETCORE_URLS`, `UseUrls` or a host binding — and **every one** is plaintext | **Startup is refused**, naming every setting that would satisfy the check | The posture is known to be wrong, so failing once is better than failing every form-bearing page |
| **Nothing** is declared | A `warn:` line with the identical diagnosis, and **the host starts** | The addresses will come from the server's defaults or from host code the check cannot inspect, and refusing a deployment that would have worked is worse than the failure it prevents |

The second row carries real risk, so it is stated rather than implied: with nothing declared, this
application was measured binding `http://localhost:5000` alone, and `/login` answered **HTTP 500**. The
warning is the notice, not a clean bill — verify the deployed topology.

Note the difference between two similarly named variables, because it is not a spelling detail:

- **`ASPNETCORE_HTTPS_PORT`** — singular — sets the **redirect target** for `UseHttpsRedirection`. It
  binds no listener, and it is one of the four things the check accepts as evidence.
- **`ASPNETCORE_HTTPS_PORTS`** — plural — supplies the hosting-layer key `https_ports`
  (`WebHostDefaults.HttpsPortsKey`). It **is** a real Kestrel listener-binding input, but only under the
  **generic host**, where `GenericWebHostService` expands each listed port into an address — and only
  when `urls` is empty; declaring `ASPNETCORE_URLS` overrides it. All seven of these hosts are built by
  `WebHost.CreateDefaultBuilder`, whose legacy `IWebHost` resolves addresses from `urls` alone, so here
  the value is visible in configuration and consumed by nothing. Set it and the host still binds
  `http://localhost:5000`. If you have set it, the startup message says so explicitly and tells you to
  translate it to `ASPNETCORE_URLS=https://*:<that port>`.

**The first administrator credential.** The historic default administrator password that provisioning used to
seed is gone (finding C-01, CWE-798/CWE-1392): a new database uses `Settings__InitialAdministratorPassword`
if you supply one and otherwise a cryptographically random password surfaced **once** on standard error, and
either way the account is flagged change-required-on-first-login. Installations provisioned by an earlier
release are not left behind — the schema version 4 migration withdraws the credential that was shipped, and
stored password hashes are upgraded to the current format on each user's next successful login, so nobody is
locked out and no reset is forced. What operators must do about the previously seeded credential, and how
that migration behaves, is in
[docs/security/credential-migration.md](docs/security/credential-migration.md).

The complete list, key-rotation guidance and the deployment checklist are in
[docs/security/secure-configuration.md](docs/security/secure-configuration.md).

### Third party libraries

- see [LIBRARIES](https://github.com/WebVella/WebVella-ERP/blob/master/LIBRARIES.md) files

## License

- see [LICENSE](https://github.com/WebVella/WebVella-ERP/blob/master/LICENSE.txt) file

## Security

To report a vulnerability, and for the supported versions and the operator hardening checklist, see
[SECURITY.md](SECURITY.md). The platform has been audited against the OWASP Top 10 (2021); the findings
and everything that followed from them are recorded here:

- [Security audit report](docs/security/security-audit-report.md) — every finding, with CWE, location, impact and evidence
- [Remediation log](docs/security/remediation-log.md) — what changed per vulnerability class, and how each was verified
- [Risk register](docs/security/risk-register.md) — accepted risks, standing warnings and ongoing recommendations
- [Secure configuration guide](docs/security/secure-configuration.md) — the operator guide behind the section above
- [Credential migration guide](docs/security/credential-migration.md) — the password-hash migration and rollback

The posture is enforced at build time, not merely documented: [`Directory.Build.props`](Directory.Build.props)
turns on NuGet dependency auditing and the .NET security analyzers for all nineteen projects, and
[`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs restore, that analyzer
build and a vulnerable-package listing in CI. **A dependency advisory fails the build by design** — that is
the gate working, not a broken build. Clear it by upgrading the package, or by recording an audited
suppression in the risk register.

## Contact

### Developer/Company

- Homepage: [webvella.com](https://webvella.com)
- Twitter: [@webvella](https://twitter.com/webvella "webvella on twitter")
