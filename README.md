[NEW PROJECT ALERT] Check out our new project for [Data collaboration - Tefter.bg](https://github.com/WebVella/WebVella.Tefter).

[NEW PROJECT ALERT] Check out our new project for [Document template generation](https://github.com/WebVella/WebVella.DocumentTemplates).

---

[![Project Homepage](https://img.shields.io/badge/Homepage-blue?style=for-the-badge)](https://webvella.com)
[![Dotnet](https://img.shields.io/badge/platform-.NET-blue?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![GitHub Repo stars](https://img.shields.io/github/stars/WebVella/WebVella-ERP?style=for-the-badge)](https://github.com/WebVella/WebVella-ERP/stargazers)
[![Nuget version](https://img.shields.io/nuget/v/WebVella.ERP?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![Nuget download](https://img.shields.io/nuget/dt/WebVella.ERP?style=for-the-badge)](https://www.nuget.org/packages/WebVella.ERP)
[![WebVella Document Templates License](https://img.shields.io/badge/MIT-green?style=for-the-badge)](https://github.com/WebVella/WebVella-ERP/blob/master/LICENSE.txt)

---

WebVella ERP 
======
**WebVella ERP** is a free and open-source web software, that targets extreme customization and plugability in service of any business data management needs. It is build upon our experience, best practices and the newest available technologies. Currently it targets ASP.NET Core 9. Our database of choice is PostgreSQL 16. Targets Linux or Windows as host OS. Currently tested only on Windows.

If you want this project to continue or just like it, we will greatly appreciate your support of the project by: 
* giving it a "star" 
* contributing to the source
* Become a Sponsor: Click on the Sponsor button and Thank you in advance

Related repositories

[WebVella-ERP-StencilJs](https://github.com/WebVella/WebVella-ERP-StencilJs)

[WebVella-ERP-Seed](https://github.com/WebVella/WebVella-ERP-Seed)

[WebVella-TagHelpers](https://github.com/WebVella/TagHelpers)


### Third party libraries
* see [LIBRARIES](https://github.com/WebVella/WebVella-ERP/blob/master/LIBRARIES.md) files

## Configuration: required secrets

**Read this before the first run.** The tracked `Config.json` files ship with every secret-bearing value
**empty**, and the application deliberately refuses to start until the missing values are supplied. This is
the remediation for security findings H-05, H-04 and C-04 (CWE-798 hard-coded credentials, CWE-321
hard-coded cryptographic key): the connection string, the data-at-rest encryption key and the bearer-token
signing key used to be committed to this public repository, which made them identical across every
deployment and impossible to rotate.

Two settings are mandatory for every host and for the console application:

| Setting | Environment variable | Notes |
| --- | --- | --- |
| `Settings:ConnectionString` | `Settings__ConnectionString` | The PostgreSQL connection string. |
| `Settings:EncryptionKey` | `Settings__EncryptionKey` | At least 32 characters, unique per deployment. The key published in this repository's history is rejected. |

Three more are conditional:

| Setting | Environment variable | When it is needed |
| --- | --- | --- |
| `Settings:Jwt:Key` | `Settings__Jwt__Key` | Only to serve bearer tokens. At least 32 bytes. While it is absent the token issue and refresh routes disable themselves rather than sign forgeable tokens; cookie login is unaffected. |
| `Settings:InitialAdministratorPassword` | `Settings__InitialAdministratorPassword` | Only on a **brand-new** database. Sets the first administrator's password. If it is absent, provisioning generates a random one and prints it **once** on standard error — the shipped default password `erp` no longer exists (finding C-01). |
| `Settings:EmailSMTPPassword` | `Settings__EmailSMTPPassword` | Only when outgoing mail is enabled. |

Configuration is read from `config.json` first, then from environment variables, then — in the Development
environment only — from user secrets, so a later provider always wins. Startup aborts with a message naming
every missing setting; the message never prints a value.

```bash
export Settings__ConnectionString='Server=localhost;Port=5432;User Id=...;Password=...;Database=...;'
export Settings__EncryptionKey="$(openssl rand -hex 32)"
```

The complete list, key-rotation guidance and the deployment checklist are in
[docs/security/secure-configuration.md](docs/security/secure-configuration.md).

## Security

* Report a vulnerability: see [SECURITY.md](SECURITY.md)
* Audit findings, remediation record and accepted risks: [docs/security](docs/security/security-audit-report.md)

## License 
* see [LICENSE](https://github.com/WebVella/WebVella-ERP/blob/master/LICENSE.txt) file

## Contact
#### Developer/Company
* Homepage: [webvella.com](http://webvella.com)
* Twitter: [@webvella](https://twitter.com/webvella "webvella on twitter")



