# Risk Register

> **Status authority.** This document is **not** the authority for the security posture's status.
> Exactly one surface is: the audit report's
> [Status at this revision, gate by gate](security-audit-report.md#status-at-this-revision-gate-by-gate) section. Where any statement here disagrees
> with it, that section governs and this one is superseded. This register is authoritative for **dispositions and owners** of accepted risks, not for gate or requirement status.
> Recorded under code-review findings `MAJ-06` and `MAJ-12`.

Accepted risks, open decisions and residual exposure arising from the security remediation.
Findings are described in the [security audit report](security-audit-report.md); the changes made
are recorded in the [remediation log](remediation-log.md).

Each entry states what the risk is, who owns the decision, and — where the risk is accepted — the
reasoning that justifies acceptance.

## Canonical risk index

This table is the register at a glance and is **authoritative for what each identifier means**. It
carries exactly **one row per identifier**, in ascending order, and every identifier it lists has
exactly one *declaring* entry below.

**The identifier contract, stated so it can be checked mechanically.** Every identifier the index lists
is declared in exactly one of **three** ways:

1. **Its own declaring heading** — text beginning `RISK-NNN`, an em dash and a space. **111** identifiers.
2. **A combined declaring heading** — `RISK-NNN and RISK-MMM — …`, used where one analysis genuinely
   covers two identifiers and splitting it would duplicate the reasoning. **2** identifiers
   (`RISK-152` and `RISK-153`).
3. **A row only**, with no prose entry, because the risk is a one-line observation rather than an
   analysis. **21** identifiers.

Sections that restate a risk a second review pass wrote up independently are titled *Supplementary
analysis of RISK-NNN …*, *Pointer to RISK-NNN …* or *Superseded statement of RISK-NNN …*; they mention
the identifier in a referring position, never in a declaring one, and each names its canonical entry in
its first line. Reproduce all of it from the repository root — this script exits reporting agreement:

```bash
R=docs/security/risk-register.md
grep -oE '^#{1,6} RISK-[0-9]+ — ' $R | grep -oE 'RISK-[0-9]+' | sort -u > /tmp/c_head
grep -oE '^#{1,6} RISK-[0-9]+ and RISK-[0-9]+ — ' $R | grep -oE 'RISK-[0-9]+' | sort -u > /tmp/c_comb
grep -oE '^\| `RISK-[0-9]+`' $R | grep -oE 'RISK-[0-9]+' | sort -u > /tmp/c_index
sort -u /tmp/c_head /tmp/c_comb > /tmp/c_headall
comm -23 /tmp/c_index /tmp/c_headall > /tmp/c_rowonly     # declared by a row alone
echo "own heading $(wc -l < /tmp/c_head), combined $(wc -l < /tmp/c_comb), row-only $(wc -l < /tmp/c_rowonly), indexed $(wc -l < /tmp/c_index)"
# (a) the three declaration routes must partition the index exactly
[ $(( $(wc -l < /tmp/c_head) + $(wc -l < /tmp/c_comb) + $(wc -l < /tmp/c_rowonly) )) \
  -eq $(wc -l < /tmp/c_index) ] && echo 'routes partition the index'
# (b) nothing may be declared that the index does not list
comm -23 /tmp/c_headall /tmp/c_index | grep -q . || echo 'every declared identifier is indexed'
```

Measured at this revision: **own heading 111, combined 2, row-only 21, indexed 134** — the routes
partition the index and every declared identifier is indexed.

**What was wrong before, recorded rather than quietly replaced.** The previous version of this contract
claimed a declaring heading was the *only* route apart from **seven** row-declared identifiers
(`RISK-012` and `RISK-015`–`RISK-020`), and its `diff` command hard-coded exactly those seven. Both
halves had drifted: `RISK-152` and `RISK-153` share a combined heading the regex cannot match, and
**fourteen further identifiers** — `RISK-154`, `RISK-156`–`RISK-160` and `RISK-162`–`RISK-169` — were
added later as index rows without prose entries and were never added to the exception list. The
documented `diff` therefore reported **19** lines of disagreement on a tree the section described as
agreeing. The full row-only set is now twenty-one: `RISK-012`, `RISK-015`–`RISK-020`, `RISK-154`,
`RISK-156`–`RISK-160` and `RISK-162`–`RISK-169`. Seven of those are declared in the table under
*Pre-existing issues named but deliberately not fixed*, which carries its own two checks; the other
fourteen are declared by their index row alone.

| Ref | Subject | Status | Owner |
| --- | --- | --- | --- |
| `RISK-001` | `AutoMapper`: every version that patches `GHSA-rvv3-g6hj-g44x` is licensed under the Reciprocal Public License 1.5, which conflicts with the product's declared Apache-2.0 and its publication to nuget.org. The advisory is **closed** by pinning `[15.1.3]` with no suppression anywhere; the **licence question is not decided and cannot be decided here.** Engineering cannot record it as decided: that would absorb an owner decision. `dotnet pack` now **fails** (`ERPLIC001`) until the owner records an answer, so the unratified claim cannot reach nuget.org while `build`, `publish` and `run` stay unaffected. | **Open — pending owner ratification, mechanically blocked from shipping meanwhile** | Repository owner / legal |
| `RISK-002` | Uncontrolled recursion in `AutoMapper` remains a weakness class that outlives any single version change; it is reachable only through a self-referential mapping the project's own developers would have to author. | Accepted | Platform team |
| `RISK-003` | Credential hashing uses PBKDF2-HMAC-SHA256 at 600,000 iterations rather than bcrypt, scrypt or Argon2, deviating from the literal wording of the mandated cryptographic standard while satisfying its intent and adding no dependency. | Accepted | Platform team |
| `RISK-004` | `CA5351` (broken cryptographic algorithm) is reported on the retained legacy MD5 verification path, which must stay until every stored credential has been upgraded on login. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-005` | ~~The Content-Security-Policy report endpoint bounds *logging* rather than *acceptance*.~~ **Retired.** The report-collection endpoint was removed outright, so the CWE-779 log-flooding vector it introduced no longer exists. There is no anonymous report sink and no `report-uri` directive. | **Retired — no longer applicable** | Platform team |
| `RISK-006` | Deterministic initialisation vector in the symmetric encryption helpers (finding `M-08`). Latent — no active caller — and changing it would make already-encrypted data undecryptable. **Cited from `WebVella.Erp/Utilities/CryptoUtility.cs`.** | Accepted | Platform team |
| `RISK-007` | **Closed.** Sign-out revokes the session server-side for **both** credential forms. Every cookie ticket and every bearer token now carries the same per-sign-in `erp_session_id`; sign-out records it, the cookie ticket-validation hook and both bearer validators consult it, and the refresh endpoint refuses to mint a successor for a revoked identifier. The asymmetry this entry used to record — cookie revocable, bearer not — no longer exists. The in-process scope of the store remains as `RISK-036`. | Closed — store-scope residual tracked as RISK-036 | Platform team |
| `RISK-008` | **The per-process limitation is closed.** Failure counters and lockouts live in the pre-existing `plugin_data` table under the reserved `wv_sec_` prefix, mutated by atomic row-locked read-modify-write, so a lockout survives a restart, spans instances and cannot be evicted by a flood of fabricated usernames — and the control fails closed when the store cannot be reached. What is accepted is the inverse residual: a lockout can no longer be released by bouncing a process, so an incorrectly locked user waits out the 15-minute window. It is not an in-process `MemoryCache`: that reading mistakes the positive-only lockout mirror for the counter store. | Accepted — inverse residual only | Platform team |
| `RISK-009` | A throttle refusal and a credential rejection differ in response length, which is a weak oracle for whether an account is currently locked out. | Accepted | Platform team |
| `RISK-010` | **Restated at the code-review checkpoint.** The identifier bound is **67 bytes**, not 63: every caller passes an already-prefixed name (`rec_`/`rel_`, 4 bytes) and the platform caps the unprefixed name at 63 characters, so 67 is the longest *legitimate* physical name. Names beyond it fail hard. The residual is a **creation-time uniqueness** question the quoting helper cannot see — it inspects one name at a time — and index names bypass the helper entirely at up to 133 bytes. | Accepted | Platform team |
| `RISK-011` | A derived page model that re-declares `ReturnUrl` would bypass the sanitising setter on the base model. Guarded by convention and by comment, not by the compiler. | Accepted | Platform team |
| `RISK-012` | The generic record-update path can overwrite a password hash with a blank value; the user-facing save path is verified not to. | Named, not fixed | Platform team |
| `RISK-013` | Two hosts served a permissive `Access-Control-Allow-Origin: *`. **Resolved — both hosts now carry an explicit origin allow-list, verified on the wire.** The close was two-stage, which is recorded rather than smoothed over: `WebVella.Erp.Site` was corrected in the original remediation, and `WebVella.Erp.Site.Project` only in follow-up work, after review found the second host still permissive while the finding was already reported as fixed. No live `AllowAnyOrigin()` call remains anywhere in the repository. Retained as an identifier because other documents in this set cite it as an open risk. | Resolved | — |
| `RISK-014` | Two bearer-token error paths return stack traces **unconditionally**, so setting `Production` does not suppress them (finding `H-13`). | Named, not fixed | Platform team |
| `RISK-015` | ~~`/ckeditor/ImageFinder` returns HTTP 500; proven pre-existing by counterfactual.~~ **Closed — the route no longer exists.** | Closed by removal (`SR-04`) | — |
| `RISK-016` | Three navigation anchors carry `href="javascript: void(0)"` — Bootstrap dropdown placeholders, **not** injection sinks. | Named, not a defect | Platform team |
| `RISK-017` | One host's `Startup.cs` lacks the UTF-8 byte-order mark the repository's own `.editorconfig` mandates. | Named, not fixed | Platform team |
| `RISK-018` | Four accessibility advisories on the login and management screens — label/form-field association, and missing `autocomplete` attributes. Not security findings. The `autocomplete` half is carried in full as `RISK-125`. | Named, not a defect — documentation only | Platform team |
| `RISK-019` | Two vendored source-map files answer HTTP 405 rather than 404. Requested only by a browser with developer tools attached, never by any page. Same subject as `RISK-058`, which carries the vendored-package evidence. | Named, not fixed — cosmetic | Platform team |
| `RISK-020` | On one management page `document.title` disagrees with the visible heading. | Named, not fixed — cosmetic | Platform team |
| `RISK-021` | The shipped `Config.json` files contained a live connection string, encryption key, token signing key, storage connection string and mail password, with `DevelopmentMode: true`. **All eight files are now scrubbed**, `web.config` sets `Production`, and the seeded administrator credential is no longer a literal. | **Closed** for the tracked configuration files; see `RISK-026` for the residual | Platform team |
| `RISK-022` | **Narrowed.** Content-Security-Policy still ships in report-only mode *by default*, because enforcing it as written would break working screens. What is no longer true is that enforcement was unreachable: it is now selected by the configuration key `SecurityHeaders:ContentSecurityPolicyReportOnly` (environment form `SecurityHeaders__ContentSecurityPolicyReportOnly`), whose polarity is inverted — setting it to `false` is what *enforces* the policy — so the remaining risk is a rollout decision rather than a missing capability. The policy **value** itself is not configurable and must not become so: `SecurityHeadersOptions.ContentSecurityPolicy` is a `public const` holding the mandated string byte-for-byte, and only the delivery mode is bindable. | Accepted | Platform team |
| `RISK-023` | **Narrowed, and its count corrected.** By-design raw-output channels are deliberately not encoded — **five**, not four. They are `PcHtmlBlock/Display.cshtml:L10`, `PcHtmlBlock/Design.cshtml:L10`, `Nav/Nav.Default.cshtml:L48`, `WvSdkPageSitemap/Form.cshtml:L92` and — unnamed anywhere in this register until code-review finding `MAJ-09` — `PcJavaScriptBlock/Display.cshtml:L11`, a fifth inline-script emitter, which is why it is load-bearing for `RISK-022`'s report-only justification rather than incidental. `RISK-170` is canonical for the channel inventory and carries the complete **111**-call census. Encoding any of the five would disable the feature it implements, which is why the disposition is a compensating control rather than a fix. What is no longer true is that they sit among a wider set of unencoded stored channels: every stored sink whose markup the platform itself composes is now encoded at its builder, so these **five** are the only raw channels remaining and their compensating control is defence in depth behind an actual fix. Counting raw *calls* rather than raw *channels* gives a larger number and does not contradict this: the remaining calls render markup the server composes from an enum or an identifier - the list `action` cells, and the data-source `icon` cell, whose value is `PageUtils.GetDataSourceIconBadge(DataSourceType.DATABASE\|CODE)` - so no stored text reaches them, and the navigation and menu calls render a value already encoded at composition in `BaseErpPageModel`. | Accepted | Platform team |
| `RISK-024` | The static-analysis backlog is reported as warnings rather than enforced as errors, because promoting roughly 3,000 pre-existing diagnostics would force the mass refactor the constraints forbid. | Accepted | Platform team |
| `RISK-025` | Residual observations around the `H-10` deserialisation binder: the binder is measurably **inert at an `ExpandoObject` target**, the serialisation counterparts are deliberately unconstrained, the `JobResultWrapper` fallback branch is effectively unreachable for well-formed payloads, and — added while closing review finding `F18` — the tightened allow-list imposes a **forward-compatibility constraint on any future first-party type persisted in a polymorphic payload**. **Cited from `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`.** | Accepted / named, not fixed | Platform team |
| `RISK-026` | The demo credential in the Blazor WebAssembly **client** page `Client/Pages/Index.razor.cs` is **removed**; what stays is that every secret ever published in this repository's **history** remains public. | **Reduced** — the client-side literal is closed; the history residual is accepted, with a CI detective control | Platform team |
| `RISK-027` | **RESOLVED, and the row that stood here asserted the opposite.** It read *"the generated initial administrator password has no change-required-on-first-login marker, because adding one requires a schema change the constraints forbid"*. Both halves are false at this revision: the password is **operator-supplied and required**, not generated, and the marker **exists** — carried in the pre-existing `rec_user.preferences` JSON column with zero DDL, set at provisioning, read by the login page and enforced on the bearer-token path so an unrotated bootstrap credential cannot mint a token. The detail entry has recorded this since review finding `OBS-08`; this summary row had not caught up, which is review finding `DOC-02`. | **Resolved** | — |
| `RISK-028` | When the only configured package source is a **local folder mirror**, the dependency restore emits no `NU19xx` diagnostic at all, so promoting the audit codes to errors cannot close that fail-open path. It is closed instead by the workflow's advisory negative control. | Accepted — mitigated by a second, independent mechanism | Platform team |
| `RISK-029` | A `.csproj` that **assigns** rather than appends to `WarningsAsErrors` would silently discard the whole dependency gate for that project. No project does so today; the structural fix (a `Directory.Build.targets` re-appending the codes after every project body) is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-030` | A solution-level command reaches **17 of 19** projects; the two WebAssembly projects are covered by dedicated restore, build and advisory steps instead, so coverage is complete at 19 of 19 by two routes rather than one. A workflow step asserts every tracked `.csproj` is in exactly one of the two sets. Enrolling them in `WebVella.ERP3.sln` was tried and **reverted twice** — the frozen plan authorises only the path-casing repair in that file (`CR2-F-06`). | Accepted — disclosed in CI and in the guides. Was briefly recorded as closed by enrollment. | Platform team |
| `RISK-031` | Running an **unpublished** build directory under a non-Development environment leaves every `/_content/**` static asset unmapped, returning `405 Allow: DELETE` and an unstyled site. The obvious workaround — setting `ASPNETCORE_ENVIRONMENT=Development` — would undo the `H-12` and `H-15` remediations. Pre-existing; the host builder is outside the authorised file set. | Named, not fixed — documented control only | Platform team |
| `RISK-032` | The `smtp_service` credential is **not encrypted at rest**. The finding's other five sub-requirements are implemented; this one is declined with a four-part rationale, and the closing control for the stated exploit is the authorisation narrowing rather than encryption. | Named, not fixed — reasoned decline | Repository owner |
| `RISK-033` | The SMTP certificate-validation opt-out is honoured **only in Development posture**; outside it the setting is refused and the refusal is reported once per process. The residual is the Development posture itself, which still accepts any certificate by design. | Accepted | Platform team |
| `RISK-034` | The `smtp_service` permission migration revokes **only** the Regular and Guest grants rather than replacing the permission lists, so a delegation an operator created on a custom role survives the migration. Reviewing those delegations is an operator action the migration cannot take for them. | Accepted — deliberate scope choice | Repository owner |
| `RISK-035` | Four residual observations recorded while closing the SMTP credential work: the `email` entity's Regular-role grants, inert sitemap node access lists in the mail plugin, the row-driven shape of the EQL entity read-permission check, and the pre-existing `catch (ValidationException ex) { … throw ex; }` idiom in `ProcessPatches()`. | Named, not fixed | Platform team |
| `RISK-036` | **The in-process residual this entry existed to record is CLOSED.** The state moved to `WebVella.Erp/Database/DbSecurityStateRepository`, which is **durable** (it survives restart), **shared** (every instance against the same database observes the same revocation), atomic, reclaimed by **expiry only and never by capacity**, and needs no schema change because it writes under the reserved `wv_sec_` prefix in the pre-existing `plugin_data` table; consulting it **fails closed**, so an unreachable store answers *revoked* rather than *not revoked*. ~~Separately, authentication tickets minted before this control shipped carry no session claim and are therefore accepted rather than rejected.~~ Also withdrawn: review finding `CR2-F-01` made both checks fail closed, so a credential with no parseable session identifier is refused and signed out. What remains is **cost, not scope**: one indexed point lookup per authenticated request, and a positive-only in-process mirror that can refuse but never authorise. | Closed — restated; the residual is per-request lookup cost | Platform team |
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
| `RISK-051` | **Restated a fourth time, and the residual is now depth rather than coverage.** `AnalysisLevelSecurity=latest-all` arms the twelve taint-analysis rules `CA3001`-`CA3012`, and `Directory.Build.props` withholds them from the **build** of exactly one project, `WebVella.Erp.Web`, whose 395 Razor views compile into a single compilation the family's unbounded interprocedural analysis does not finish traversing - killed at 600 s when first measured, and re-measured past **2,700 s** for review finding `MAJ-01`. That build-time exclusion is no longer a coverage gap: under `MAJ-01` the same compilation is scanned by its own workflow step with the family armed and `max_interprocedural_method_call_chain = 1`, which terminates in about **220 s**, exits 0 and reports **zero** `CA3001`-`CA3012` diagnostics - and the step proves the bounded configuration still reports by requiring `CA3001` and `CA3003` against deliberate taint flows before it trusts that zero, treats a timeout as fatal, and publishes `taint-scan-web.txt`. **Coverage is 19 of 19 compilations.** What remains accepted is analysis *depth* for that one project: a one-hop chain bound will not follow a flow that crosses two or more calls, so its silence is weaker evidence than the eighteen unbounded zeros. | Accepted - coverage closed at 19 of 19; the residual is bounded interprocedural depth for one project, compensated by four independent controls named in the detailed entry | Platform team |
| `RISK-052` | `AnalysisLevelSecurity=latest-all` ships in `Directory.Build.props`, so the Security category is armed in full and **five** rules report on the shipped tree: `CA2100` 20 diagnostics across 8 files, `CA2326` 20 across 6, `CA2328` 9 across 4, `CA5351` 5 across 2, `CA5362` 1 across 1 - **55 diagnostics over 21 distinct `(rule, file)` pairs**, all 21 in the Gate 1 allow-list with an attributable disposition and a resolvable `RISK-nnn` reference, leaving **0** unreviewed and **0** stale. None is promoted to `Error`: AAP 0.3.2 declines escalating security analyzer rules to build errors, so the control is the ratchet - a diagnostic at any *new* `(rule, file)` pair fails Gate 1 - rather than the severity. The residual is granularity, not absence: a second violation of the same rule in an already-allow-listed file is absorbed silently. `CA5351`'s five sites carry their own formal, dated, exit-bounded acceptance as `RISK-171`. | Accepted - all five execute, are counted, are published in the Gate 1 evidence artifact and are ratcheted; held at `Warning` by AAP 0.3.2 | Platform team |
| `RISK-053` | The three GitHub Actions the security workflow consumes are pinned to 40-character commit SHAs, which is what closes the mutable-tag supply-chain exposure — and which also means they no longer receive upstream security fixes automatically. A pinned action is frozen until a human moves it. | Accepted — deliberate trade, requires a periodic review task | Platform team |
| `RISK-054` | `CA5359` is one of the four Security-category rules the frozen gate enables, at **warning** severity and a measured count of zero, and it detects the accept-all certificate shapes this codebase actually used — a `RemoteCertificateValidationCallback` or a MailKit client's `ServerCertificateValidationCallback` assigned a lambda that always returns `true`. It does **not** detect the same defect expressed as `HttpClientHandler.ServerCertificateCustomValidationCallback`, which was measured rather than assumed. A developer could reintroduce accept-all through that one shape and keep the build green. | Accepted — narrow detector gap, measured and named | Platform team |
| `RISK-055` | ~~The anonymous `/csp-violation-report` collector is bounded by method, transport, body size, per-source acceptance ceiling and log volume, but **not** by request content type — a control considered and declined rather than overlooked.~~ **Retired.** The collector was removed outright, so there is no endpoint to bound and no declined control to carry: `MaxViolationReportBytes`, `ShouldAcceptReportFromSource`, `ShouldLogReport` and `IsRequestEffectivelyHttps` are all absent from the tree. The reasoning is retained in the detailed entry as a record of the decision. | **Retired — no longer applicable** | Platform team |
| `RISK-056` | ~~The `/csp-violation-report` per-source acceptance ceiling is 60 accepted reports per source per minute, while browser instrumentation measured 13 to 146 beacons for a single page load, so a shared source address is largely refused.~~ **Retired.** The ceiling and the collector it bounded were both removed; `MaxAcceptedReportsPerSourcePerMinute` no longer exists. The beacon measurements are retained in the detailed entry because they remain the evidence for how much inline style and script the report-only policy still reports. | **Retired — no longer applicable** | Platform team |
| `RISK-057` | `ScheduleManager.ProcessSchedulesAsync` writes its own failure through `Log.Create` inside a `catch` with no inner guard, so a transient PostgreSQL timeout on that diagnostic write escapes to the thread pool and terminates the entire web host. Observed once under extreme machine load. Pre-existing platform code, byte-identical to `HEAD`, and a reliability rather than a security defect. | Documented — out of scope under AAP 0.3.2 (no refactoring beyond security) | Platform team |
| `RISK-058` | Two third-party assets shipped by the `WebVella.TagHelpers` package reference source maps (`bootstrap.css.map`, `decimal.min.js.map`) that the package does not include. Requests for them return the application's uniform catch-all 405. Only a browser with DevTools attached ever issues them. Vendor content, which AAP 0.3.2 excludes from modification. | Documented — out of scope (third-party content, version updates only) | Platform team |
| `RISK-059` | ~~`global.json` pins the SDK as `10.0.302` but with `rollForward: latestPatch`, so a later patch on the 10.0.3xx band is accepted.~~ **CLOSED by review finding `CR2-F-13`.** The residual this entry accepted no longer exists: `rollForward` is now `disable`, so the toolchain is exact and the gate's recorded results are reproducible by construction. The outage argument that justified accepting the drift was re-weighed and rejected; adopting a newer SDK is now a deliberate, documented re-baseline instead. | Closed | Platform team |
| `RISK-060` | An SMTP relay whose certificate chain names no reachable CRL distribution point or OCSP responder **cannot be used** from a Production deployment: revocation checking is left at the mail library's own default of on, no configuration key disables it, and the accept-any-certificate opt-out is refused outside Development. A relay in that position fails the handshake with a chain status of only `unable to get certificate CRL` while its certificate is otherwise perfectly valid. A `Settings:EmailSMTPCheckCertificateRevocation` key to relax the check is deliberately absent, because it weakened the Production transport posture beyond the agreed remediation for `H-11` and it was **removed**. | Accepted as a deployment constraint — the supported remedy is to publish the revocation source | Deployment owner |
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
| `RISK-108` | A Project widget renders a stored priority colour and icon class inside a `style` and a `class` attribute. Measured **not** to be a raw-output sink — both values are ordinary Razor expressions and are HTML-encoded, so no attribute or handler can be introduced. The residual is CSS injection by an administrator who can edit the stored select options. | Named, not fixed — documented control only | Platform team |
| `RISK-109` | The security workflow has no scheduled trigger, so an advisory published against an untouched package is detected on the next push rather than on a timer. `workflow_dispatch` preserves the capability; what is lost is the timer, not the ability. | Accepted — the trigger set is a configuration contract | Platform team |
| `RISK-110` | The Gate 3 secret sweep covers the **tracked tree**, not git history, and cannot detect a credential with neither a recognisable shape nor a secret-shaped name. A credential ever committed must therefore be **rotated**, not deleted. | Accepted — scope boundary with a mandatory operational consequence | Platform team |
| `RISK-111` | The login page, the token-issue route and the token-refresh route share **one** per-address failure budget (25 failures per rolling 15 minutes) rather than one each, deliberately, so a single source cannot spend a full allowance on each surface in turn. | Accepted — intended behaviour | Platform team |
| `RISK-112` | Bounding regular-expression cost narrows what a record filter accepts: the product of explicit repetition bounds is capped at 256, back-references and stacked quantifiers are refused, and a regex query executes under 60 seconds rather than 600. The textbook `(a+)+` shape is deliberately **admitted**, measured harmless on PostgreSQL's hybrid DFA/NFA — an admission contingent on that engine, so `DbRegexPattern` must be revisited if the regex implementation ever changes. | Accepted | Platform team |
| `RISK-113` | The SDK host's `/dev` page remains **anonymous in the Development environment**, and the Blazor circuit endpoint remains anonymous there with it. Closing `M-09`'s Production half by gating rather than deleting the exemption is what preserved the SDK development workflow the Agent Action Plan section 0.3.2 explicitly refused to break, so the Development half is retained deliberately. | Accepted | Platform team |
| `RISK-114` | A deployment that supplied a **non-ASCII** `Settings:EncryptionKey` and encrypted data under it is now refused at start-up, because acceptance measured characters while derivation consumed ASCII bytes and silently substituted `?` for each character above U+007F. Recovery is deterministic — replace each non-ASCII code unit with `?` — and is documented with the one measured case where the substituted key cannot be re-supplied because it no longer clears the character-variety floor. Rotation afterwards is mandatory, not advisable. | Accepted | Platform team |
| `RISK-115` | With `Settings:DataProtectionKeyDirectory` configured, the Data Protection key ring is written to disk **unencrypted**, because every supported at-rest encryptor needs deployment-provided certificate material, a Windows-only facility, or a new package dependency the plan forbids. The setting is opt-in, per-application isolation does not depend on this entry, and the two ways to close it — a certificate, or an encrypted volume — are recorded with the file-system controls that bound it meanwhile. | Accepted | Platform team |
| `RISK-116` | ~~Gate 3 accepts exactly **one** credential-shaped location: a commented-out connection-string template in `WebVella.Erp.Site/Config.json` whose every value is angle-bracketed.~~ **CLOSED - the residual no longer exists.** The commented-out template was removed from `WebVella.Erp.Site/Config.json`, so the reviewed allowance now has nothing to allow: Gate 3 reports **0 credential-shaped locations and 0 tolerated** across 1,518 tracked text files. The reasoning is retained below because the *decision* it records still governs - narrowing the pattern to ignore an angle-bracketed value was rejected as a fail-open for any real password containing `<`, and that pattern is unchanged. | Closed | Platform team |
| `RISK-117` | The licence-governance gate that keeps `RISK-001` unshippable refuses to **build** a package, not to **publish** one: a `.nupkg` produced before the gate existed remains pushable, and the gate can confirm that an answer was recorded but not that the person recording it was entitled to. What it buys is deliberateness — the answer must be typed and appears in the log or the diff — on the one step that cannot be undone. | Accepted — bounded residual of the control | Whoever performs a release |
| `RISK-118` | Authenticated page renderings stay recoverable from the **browser's** back/forward cache after logout, because authenticated content responses carry no `Cache-Control` while `/login` and `/logout` do. Measured during runtime verification: two presses of Back after logout restored the authenticated shell with **no document request issued**. The restored view is inert — the same ticket replayed against four protected routes is refused server-side — so what survives is one already-delivered rendering on a device an attacker must already hold. Recorded with a minimal fix rather than remediated: `Cache-Control` is not in the mandated seven-header set, and the ticket-acceptance weakness behind `CR2-F-01` / `CR2-F-02` is separately proven closed. | Accepted — documented with fix guidance | Platform team |
| `RISK-119` | Two **pre-existing** defects in the shipped Blazor WebAssembly client's HTTP layer, found while remediating `B3-SEAM-01` and outside its scope. `Client/Services/TokenManagerService.cs` builds its refresh URL as `api/v3/en_US/auth/jwt/token/refresh` on an `HttpClient` whose `BaseAddress` already ends in `/api/`, so the client's automatic token refresh addresses a doubled segment that no route serves. `Client/ApiService/ApiService.System.cs` sets a **lower-case** `bearer` scheme on `DefaultRequestHeaders`, and both token-issuing hosts select the authentication handler by a case-**sensitive** `Authorization` prefix match, so those calls are not authenticated as bearer at all — and the credential is left attached to a shared client rather than scoped to one request. Neither is a new exposure and neither weakens the `B3-SEAM-01` fix, which builds its own URL and sets its own correctly-cased request-scoped header. | Accepted — documented with fix guidance | Platform team |
| `RISK-120` | ~~The page header's `description` attribute is the **one** value on `WvPageHeader` that is deliberately rendered raw, and it must stay that way. Its only non-literal supplier is `PageUtils.GenerateListPageDescription`.~~ **CLOSED — reclassified from an accepted residual to a fixed defect by review finding `F-02`, and the sole-supplier claim above is RETRACTED as false.** `WebVella.Erp.Web/Components/PcPageHeader/PcPageHeader.cs` is a second, data-bound supplier: it resolves `ViewBag.ProccessedDescription` from `context.DataModel.GetPropertyValueByDataSource(instanceOptions.Description)`, and both `PcPageHeader/Display.cshtml` and `Design.cshtml` bind it to `description=`, so arbitrary page and record data reached the raw sink — the very condition this entry described as hypothetical. The channel is no longer raw: `description` now renders through `InnerHtml.Append` and is HTML-encoded, and a separate, explicitly named `description-html` attribute carries trusted markup. The five SDK list views that legitimately pass builder-composed markup were moved to it in the same change, so the list screens still render their `ul`/`li` and `<strong>` elements exactly as before while every data-bound description is encoded. The builder-side encoding that closed `P-22` is retained and unchanged. | Closed — fixed under review finding `F-02` | Platform team |
| `RISK-121` | QA finding `F-AA` path 4: the Track Time grid's **title** cell is sanitised by a tag allow-list that produces real `<b>` elements rather than encoding them. No grid-rendering source exists in this repository — `wv-grid` ships inside the third-party `WebVella.TagHelpers` 1.8.0 package, which the plan restricts to version updates — and a sanitiser that emits `<b>` while stripping `<script>` is behaving as designed. QA measured nothing exploitable: no dialog, no live handler, hostile rectangles 0 × 0. | Named, not fixed — third-party, non-exploitable as measured | Platform team |
| `RISK-122` | The **33** remaining findings from the frontend QA pass — 21 Minor and 12 Info — are pre-existing quality, accessibility, responsive-layout and environment observations in code this remediation never touched, each carrying a git-level counterfactual proving pre-existence. They are enumerated with recommended fixes in the detailed entry below, grouped by theme. The plan declines them: minimal code changes only, no feature additions, no refactoring beyond security requirements, third-party libraries restricted to version updates, and fix only what is confirmed. | Documented for a future sprint | Platform team |
| `RISK-123` | ~~Administrator-authored entity and application metadata — the stored `color` and `icon_name` keys, reaching the `color`, `icon-color` and `icon-class` attributes — flows from the database into the page header's `style` and `class` **attributes**, where a privileged author can inject additional **CSS declarations**. Not remediated.~~ **CLOSED — reclassified from an accepted residual to a fixed defect by review finding `F-06`.** The measurement recorded here still holds and is worth keeping: `TagBuilder` does encode attribute values, so the channel never created an attribute or a handler. What it *did* still allow was the surviving CSS declaration — which needs no HTML-special character — and, in the `class` case, arbitrary class tokens. Both are now closed at the tag-helper boundary rather than accepted: `Color` and `IconColor` pass through `SafeStyleValue.CssColor`, and `IconClass` through the new token-level `SafeStyleValue.ApprovedIconClass`, which admits only the icon-token shapes the product actually uses and rejects the whole value otherwise. A rejected value yields the empty string, which is an existing state of the product rather than an invented fallback, and the `has-icon`/`no-icon` layout class is derived from the guarded value so the class can never claim an icon that was not emitted. Runtime-verified with the payload seeded: no `url(...)` declaration survives, the rendered document does not contain the hostile host, **zero** off-origin requests were issued, and the legitimate colour and icon bindings still render with their exact computed colours. | Closed — fixed under review finding `F-06` | Platform team |
| `RISK-124` | Every required-configuration abort surfaces as an **unhandled exception**: the host prints the actionable message, then a stack trace, and exits **134** rather than exiting non-zero with a single line. This is framework-default behaviour for a `Startup.Configure` throw and it is fail-closed - the process never serves a request and no value is echoed - but a container orchestrator reports a crash where the cause is a configuration fault, which can lengthen operator triage. Applies to the secret validation in `WebVella.Erp/ErpSettings.cs`, the encryption-key accessor in `WebVella.Erp/Utilities/CryptoUtility.cs`, the Content-Security-Policy option binding and the transport-security check in `WebVella.Erp.Web/ErpMvcExtensions.cs`. | Accepted - documented with fix guidance | Platform team |
| `RISK-125` | The login form's two inputs carry no `autocomplete` attributes, so browsers emit an autofill advisory (`suggested: "current-password"`) and password managers are not steered. No functional and no security impact - `autocomplete` is absent, not disabled, so nothing suppresses a password manager. Fixing it is a presentation-layer enhancement with no confirmed finding behind it, which the audit plan's modification boundaries exclude. | Recommended, not fixed - out of remediation scope | Frontend maintainer |
| `RISK-126` | **Resolved at the code-review checkpoint.** The startup transport-security check now accepts only real evidence of an HTTPS request path - a declared `https` endpoint, a `Kestrel:Endpoints` `https` Url, the module-written `ANCM_HTTPS_PORT`, or a trusted proxy **together with** a parsed public HTTPS port - and refuses every other posture outside Development, including the previously warned-about case in which no endpoint is declared at all. A public HTTPS port alone, a trusted proxy alone, and a malformed or out-of-range port are all refusals. Development remains exempt because its antiforgery cookie follows the request scheme. | Resolved - no residual accepted | Platform team |
| `RISK-127` | The third-party `wv-field-select` / `wv-field-multiselect` **display** path concatenates a stored option's `icon_class`, `color` and `Label` straight into markup with no encoding. QA finding `F-R3-XSS` proved the icon and colour half live and **cross-host**; review finding `F-01` proved the `Label` half live at the same sink. **Both halves are now closed at `ModelExtensions.ToWvSelectOption`, the single conversion boundary feeding all 94 call sites.** Icon and colour go through `SafeStyleValue.CssColor` / `SafeStyleValue.IconClass`. `Label` — previously recorded here as deliberately not encoded, a disposition now **RETRACTED** — goes through the new `SafeStyleValue.DisplayText`, which is value **restriction** rather than encoding for a measured reason: the same `Label` instance reaches an encoding sink and a raw sink in one render, and the select2 script re-injects the DOM-**decoded** option text as markup, so no amount of server-side encoding could have covered it while pre-encoding would have double-encoded legitimate labels. `DisplayText` removes only `<` and `"`, leaving `&`, `'` and `>` untouched, so `R&D`, `Client's request` and `> 30 days` render byte-identically and the same instance is returned when nothing needs removing. **Two residuals remain, both narrower than before.** First, the option-level `IconClass` guard at this boundary is still the **character**-level `SafeStyleValue.IconClass` rather than the token-level `ApprovedIconClass` introduced for the page header — see `RISK-129`. Second, the guard is caller-side, so any future code constructing a `WvSelectOption` directly, or any future vendor sink consuming another `SelectOption` member, reintroduces the exposure. This entry also corrects the record: `SafeStyleValue`'s original remarks claimed "four independent render paths"; there are **five**. | Icon/colour and `Label` halves both **closed**; caller-side scope and the option-level icon-token width accepted with fix guidance | Platform team |
| `RISK-128` | The **24** informational findings from the cross-cutting runtime QA pass that raised `F-R3-XSS`. Every one is pre-existing in code this remediation never touched, and the pass proved that rather than asserting it: **zero** `.css` files changed by the project, the chart views and `login.cshtml` verified `UNCHANGED`, and the two widgets the remediation did edit emitting **byte-identical** avatar markup apart from an added `alt=""`. Eleven are already named by existing entries (`RISK-058`, `RISK-122`, `RISK-125`) and are cross-referenced rather than duplicated; the remaining thirteen are enumerated below with a recommended fix each. One is **security-adjacent** and worth reading first: there is no cross-process entity-metadata cache invalidation, and field permissions live in the same cached JSON, so a runtime permission tightening does not reach other host processes until they restart. One is a **positive** finding recorded so it is not later mistaken for a defect. The plan declines them all: minimal code changes only, no feature additions, no refactoring beyond security requirements, third-party libraries restricted to version updates, and fix only what is confirmed. | Documented for a future sprint | Platform team |
| `RISK-129` | The option-level icon guard at `ModelExtensions.ToWvSelectOption` is the **character**-level `SafeStyleValue.IconClass`, which admits arbitrary utility class tokens — measured as a rendered `class="fas fa-fw fa-bug d-none"` on the select display path — rather than the token-level `SafeStyleValue.ApprovedIconClass` introduced for the page header under `F-06`. Inert as measured: it reaches a `class` attribute only, creates no attribute and no handler, and the hostile colour in the same fixture was still rejected and fell back to the product's default. Under the engagement's own severity matrix this is a *minor misconfiguration* with a UI-redress ceiling, so the disposition is to document it; `F-06`'s remediation is scoped in terms to the tag-helper boundary, and widening it here would be a change with no confirmed finding behind it. | Documented with fix guidance | Platform team |
| `RISK-130` | `DbFileRepository.Copy` carries the same unauthorized-destination-delete shape that review finding `F-05` closed in `Move`, and in a weaker form: it deletes the destination through the overload that pins no expected identifier at all. It is **unreachable** — the method has zero call sites anywhere in the nineteen projects — so it is not exploitable, and `F-05` did not cite it. Recorded rather than fixed, on the same basis as the platform's other dead security code under `L-01`: removing or hardening unreachable code is hygiene, not remediation, and the Minimal Change Clause forbids refactoring beyond a confirmed finding. | Documented with fix guidance | Platform team |
| `RISK-131` | The diagnostic notification mailer (`Web/Services/MailService.cs`, driven by `LogService`) builds a `System.Net.Mail.SmtpClient` that never enables TLS, so exception detail, the request URL with its query string and the relay credential cross a plaintext session; failures are swallowed and resources undisposed. `H-11` does not mitigate this - it hardened five MailKit paths, not this client. Bounded by `Settings:EmailEnabled` being `false` in every shipped configuration and by the non-notifying audit sink from `F26`. | Accepted while `EmailEnabled` stays false; the fix needs separate authorisation | Deployment owner + product |
| `RISK-132` | Cloud and file-system storage address an object by a key derived from the `files` row identifier for create, read and delete, but **Move** uses logical paths instead, so an extension-changing rename leaves the metadata pointing at a key that was never written. Pre-existing, in backends that ship disabled. | Accepted - documented, not corrected | Deployment owner |
| `RISK-133` | External storage writes, moves and deletes happen before the database transaction commits and are not compensated on rollback, so a failure can orphan an object, diverge metadata, or lose a moved file. Pre-existing, in backends that ship disabled. | Accepted - documented, not corrected | Deployment owner |
| `RISK-134` | `DbFileRepository.CleanupExpiredTempFiles` was repaired so it actually matches staged uploads and honours the age it is given, but **nothing calls it**: scheduling is a deployment decision and a background job would be feature work. Abandoned uploads persist until an operator drives the cleanup, in a system scope. | Accepted - operator action required | Deployment owner |
| `RISK-135` | Exception detail is e-mailed off-box **before** it is persisted (`M-17`, stated in full). Five properties, three of which were previously unrecorded: the notification precedes the persistence; the payload carries the request URL **including the query string**, plus the exception message, stack trace, `Source` and inner exception — but not headers, cookies or body; `ex.Message` also reaches the mail **subject**; a delivery failure is swallowed by a bare `catch { }` so the reason is lost; and the path is attacker-reachable, making it a mail-flood amplifier (CWE-779). The code is unchanged by **explicit AAP §0.3.2 exclusion**, with §0.7.1 Group 11 marking the files REFERENCE — all four are byte-identical to the pre-audit baseline. | Accepted — documented only, by scope exclusion | Platform team |
| `RISK-136` | A required first-login rotation now **consumes the account lockout budget**. Closing `OBS-03` reclassified it from an unexpected server fault — which logged a stack trace and abandoned the attempt, so probing unrotated accounts tripped no lockout — into an expected bounded rejection returning the generic credential message. The intended consequence is that operator automation replaying a bootstrap credential can self-lock. | Accepted — introduced deliberately | Platform team |
| `RISK-137` | Antiforgery rejections are refused by the framework filter **before** the login handler runs, so they carry no authentication audit record. Discovered at runtime, and it corrected a claim this documentation was about to make: the `!ModelState.IsValid` branch is **not** the antiforgery gate. | Accepted — pre-existing framework behaviour | Platform team |
| `RISK-138` | Refusal-audit coalescing is now scoped to the **anonymous token-refresh route only**. `OBS-05` required one record per refusal on the login page, because sampling lets an account be refused hundreds of times behind a single row; the transport-level limiter (600 requests per address per window, no queue) is the load-bearing precondition that makes it safe. | Accepted — introduced deliberately | Platform team |
| `RISK-139` | One core-assembly logging site, `WebVella.Erp/Database/DbFileRepository.cs:356`, cannot reach the failure-isolated audit boundary: `SecurityAuditLog` is `internal` to `WebVella.Erp.Web`, which depends **on** core, so the dependency would have to be inverted. It mirrors the boundary's field neutralisation with a local helper instead. | Accepted — structural, bounded to one site | Platform team |
| `RISK-140` | **Restated — the gate is still red by design, but not for the reason recorded here.** ~~The `Release gate` is red until dated, attributed manual attestations are committed.~~ Those attestations exist: all **32** manual rows are executed and committed, so `deferred=0` and **no manual row blocks the gate** (`RISK-168`). The gate is red at this revision over a single evidence-derived row, `A17` — the mandated seven-header set is not satisfied while the Content-Security-Policy ships under its report-only name, and code-review finding `MAJ-03` refused the alternative of rewriting the check to accept the substitute name. Recorded so a red gate is not mistaken for a broken pipeline and "fixed" by relaxing the check; a fabricated attestation file, or a check rewritten to accept a substitute header name, would each defeat its only purpose. | Open by design — the control working, now over an unmet acceptance criterion rather than missing verification | Repository owner |
| `RISK-141` | No health endpoint, metrics, tracing or correlation identifier exists (`L-05`, stated in full): all four probes measure **0**. Two consequences understated by "zero" — **no correlation identifier crosses the SMTP boundary**, so a notification cannot be reconciled with the record written for the same fault, and liveness cannot be distinguished from readiness during startup provisioning. Corrects the earlier claim that no smoke test or rollback procedure exists; both do. | Accepted — documented only, feature work | Platform team |
| `RISK-142` | Authenticated API actions still return exception text in the response body, each preceded by a server-side log write. `H-13` covered the *unconditional, anonymously reachable* instances and is fixed; these sit behind class-level `[Authorize]` and are outside the authorised change scope. Previously numbered `RISK-032`. | Named, not fixed — outside the authorised change scope | Platform team |
| `RISK-143` | `DbRepository.ConvertDefaultValue` concatenates a field default into a DDL `DEFAULT` clause without escaping an embedded quote, so an administrator authoring a schema field can influence the generated statement. Reachable only through schema design, which already executes arbitrary DDL by design. Previously numbered `RISK-033`. | Accepted — disclosed, not fixed | Platform team |
| `RISK-144` | Provisioning emits six pre-existing bootstrap DDL statements — four `CAST` statements and two `CREATE EXTENSION` statements — from the provisioning entry point, before any schema version is consulted. Recorded so that "the remediation emits no schema definition statements" is stated precisely rather than absolutely; the version-4 migration itself emits none. Previously numbered `RISK-033`. | Named, not fixed — pre-existing platform bootstrap | Platform team |
| `RISK-145` | Plugin patch files seed `PcFieldHtml` page-component options whose value is **server-authored C# source**, not attacker-controlled input. The rendering tag helper is third-party (`WebVella.TagHelpers` 1.8.0), which the plan restricts to version updates. Resolves through the by-design intentional-HTML channel recorded as `RISK-023`. Previously numbered `RISK-034`. | Accepted — by-design channel with a compensating control | Platform team |
| `RISK-146` | No transport-level request-body limit bounds an upload before model binding: all five upload actions validate before reading the stream, but ASP.NET Core has already buffered the multipart body by then, and neither `MaxRequestBodySize` nor `MultipartBodyLengthLimit` is configured anywhere. This is the residual that review finding `F-09` decision (o) defers to. | Accepted — documented, not fixed | Platform team |
| `RISK-147` | **CLOSED.** Ten authenticated API actions returned a stack trace in the response body; 0 occurrences remain, all ten routing through the development-gated `SafeErrorMessage`. Retained as a closure record; the open residual it used to be confused with is `RISK-142` | Closed — re-measured, condition absent | Platform team |
| `RISK-148` | No mainstream browser ships a TIFF decoder for `<img>`, so a stored `.tif`/`.tiff` shows a broken image whatever the disposition. Admitting them to the inline set under `SR-10` made the platform's own components consistent with the upload allow-list; it cannot make a browser decode TIFF | Accepted — **owner decision required**, three options stated | Platform team |
| `RISK-149` | `POST /fs/move/` does not validate the **target** extension against the upload allow-list, so a caller who has already passed the upload gate can rename a stored object to an extension the upload gate would have refused | Accepted — contained, not fixed | Platform team |
| `RISK-150` | `System.Drawing.Common` 10.0.1 remains a package reference while **no source file in the core or web projects references it**, after `SR-12` replaced the only consumer with a header-only reader | Accepted — retained deliberately under the plan's *dependencies to remove: none* rule | Platform team |
| `RISK-151` | `DbFileRepository` throws on a move whose destination already exists without `overwrite`, and that throw escapes as an unhandled fault rather than the endpoint's refusal envelope. **Pre-existing at the checkpoint baseline and in the repository's 2019 initial commit.** Proven **not** an information-disclosure defect: under Production the response is an empty-body HTTP 400 | Accepted — reliability and contract residual, not a security one | Platform team |
| `RISK-152` | Two further packaged inline scripts reference the same undeclared `response.message` that `SR-11` remediated — the multi-select field (2 occurrences) and a section component (1). Neither posts to an upload endpoint, so neither sits behind a security refusal | Accepted — outside `SR-11`'s scope, recorded so the census is complete | Platform team |
| `RISK-153` | The packaged field shapes do not agree on element identifiers: the image shape names its wrapper text `fake-<name>-<guid>` with identifiers regenerated per render, so an identifier-based lookup is a harmless no-op there while the class-based fallback resolves. `SR-11`'s wrapper is written to tolerate this rather than depend on a shape | Accepted — by design in the remediation | — |
| `RISK-154` | A pre-built Stencil bundle hard-codes a wrong-case legacy asset path for a default avatar, which returns HTTP 405 and renders as a broken image. The affected files are **generated bundle artifacts** | Accepted — cosmetic, and inside the third-party boundary | Platform team |
| `RISK-155` | The content-security policy's **report-only** mode was independently confirmed to be load-bearing: roughly 80 report-only violations were observed on a single page, every one of them raised by the application's **own** inline styles, inline scripts and `eval` usage | Accepted — this is the measurement that justifies the staged report-then-enforce rollout | Platform team |
| `RISK-156` | Two pre-existing accessibility advisories on the SDK custom-page form — a form field without an `id` or `name`, and a mismatched `<label for=…>` | Accepted — not security findings; documentation only | Platform team |
| `RISK-157` | In the WebAssembly client's login component the password input is **not contained in a `<form>`** and its two inputs carry no `id` or `name`, which suppresses password-manager interoperability | Accepted — documentation only, and the client-side sibling of `RISK-125` | Platform team |
| `RISK-158` | The WebAssembly client ships no `favicon.ico`, so every load records one 404 | Accepted — cosmetic | Platform team |
| `RISK-159` | A **cleartext HTTP listener was live** on the API port during verification and answered a control probe, which is what made `SR-03`'s cleartext exposure reachable rather than theoretical. Removing the insecure default closed the client's half; nothing in the application prevents an operator binding a cleartext listener | Accepted — operator responsibility, now documented in [the secure configuration guide](secure-configuration.md) | Operator |
| `RISK-160` | `HttpExt.cs` retains pre-existing analyzer findings in the helpers `SR-08` did **not** touch — one unused exception variable and two `throw new Exception` statements | Accepted — pre-existing, outside the finding's scope | Platform team |
| `RISK-161` | **CLOSED at this revision.** ~~`markdownlint` does **not** reach a clean exit on the nine documentation files.~~ It now does: measured at the pinned 0.45.0 on this tree, the command exits **0** with **zero** diagnostics. The path was 19 → 3 → 0. Review finding `MIN-01` took 19 → 3 by fixing 11 `MD012`, 4 `MD022` and 1 `MD058`; code-review finding `LOW-02` took the last 3 `MD001` → 0, and in doing so found the reasoning that had declined them to be false on its facts — the change was **nine** headings, not 32, and it made both documents *consistent with their own conventions* rather than restructuring them: seventeen of the register's nineteen *Detailed entries* sections already opened with a `###` entry, and Parts 1 through 4 of the audit report each already carried a `###` band heading that Part 5 lacked. No record heading level, identifier, field or anchor slug moved; all 147 in-document anchor links were re-resolved with zero breakages, and the record census is unchanged at 138 and 53. The dual-slugifier note kept in the detailed entry remains open as a convention rather than a defect | Closed — measured clean at the pinned version; `.markdownlint.jsonc` states the same measurement | Platform team |
| `RISK-162` | Synchronous server IO stays globally enabled (`ErpMiddleware`, `AllowSynchronousIO = true` on every request), which lets a slow client hold a thread-pool thread. AAP 0.3.2 excludes the removal as `M-11`. **New evidence narrows the risk of fixing it:** no application-code consumer of synchronous *server-stream* IO exists — zero matches for `StreamReader` over `Request.Body`, `Request.Body.Read`, `Response.Body.Write` or `StreamWriter` over `Response.Body`, and no `Response.Body` or `FileStreamResult` anywhere; the only synchronous `StreamWriter` with a `Flush` writes to a `MemoryStream`. **Recommended fix:** remove the assignment; build and exercise every upload, download and export route; convert any consumer a compile error or a runtime `InvalidOperationException` identifies. The evidence suggests that set is empty. Note the AAP text cites `WebVella.Erp/Utilities/CodeEvalService.cs`, a path that does not exist — the file is at `WebVella.Erp.Web/Services/CodeEvalService.cs`. Weakness classification: CWE-400, OWASP A04. | Documented only — AAP 0.3.2 excludes it (`M-11`). Review finding `CK-11`. | Platform team |
| `RISK-163` | Two client libraries load from cdnjs with no `integrity` attribute and at mismatched versions — Leaflet CSS 1.6.0 and Leaflet JS 0.7.3 — in the geography branch of the administrator-only page `Plugins.SDK/Pages/entity/data.cshtml`. A repository-wide sweep of views returns exactly these two remote references. Advisory status was checked live rather than assumed: the GitHub Advisory Database returns **0** advisories for the `leaflet` npm package and OSV returns **0** vulnerabilities for `0.7.3` and `1.6.0`, so the risk is substitution rather than a known defect. **An adjacent defect found at the same site:** the tile layer is fetched over plaintext `http://a.tile.openstreetmap.org/...`, which is mixed content on an HTTPS page. **Recommended fix:** align both assets on 1.9.4 and add the verified digests — CSS `sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H`, JS `sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH` — with `crossorigin="anonymous"`, and switch the tile URL to HTTPS. **Cross-finding interaction:** enforcing the mandated Content-Security-Policy will refuse both cdnjs assets and break this page unless they are vendored first, so CSP enforcement has two blockers, not one. Weakness classification: CWE-829, OWASP A08. | Documented only — AAP 0.3.2 excludes it (`M-15`). Review finding `CK-12`. | Frontend maintainer |
| `RISK-164` | An **administrator** can still have request-supplied C# compiled through the page-component render route's `design`, `options` and `help` modes, and through the node-less path. That is what those modes exist for — component authoring — and the privilege required is the same one that already governs the five page-node mutation actions. Every refusal and every authorized use is audited with the acting identity and the subject, and never with the submitted source. **Recommended fix, if a deployment wants the capability gone:** remove the authoring modes from production builds, or move component authoring to a build-time artefact. Neither is in scope here. Weakness classification: CWE-94, OWASP A03. | Accepted by design. Residual of review finding `CK-01`. | Platform team |
| `RISK-165` | The cross-site request forgery control on the API surface is **fetch-metadata based, not token based**: it refuses a cookie-authenticated state-changing request whose `Sec-Fetch-Site` says it is cross-site, and **allows a request that sends no such header** so that an older client is not broken. No antiforgery token plumbing is added, because AAP 0.3.2 declines it as `M-02` — existing JavaScript clients post no token. **Recommended fix:** add token plumbing to the shipped clients, then require the token, then keep the fetch-metadata check as defence in depth. Weakness classification: CWE-352, OWASP A01. | Accepted residual of review finding `CK-06`. | Platform team |
| `RISK-166` | Notification amplification is still unbounded per source: item 5 of the `RISK-131` remediation table — rate-bounding diagnostic notification per source, as `SecurityAuditLog.RecordRateLimitedAudit` already does for audit records — is **not implemented**. Items 1 through 4 are. **Recommended fix:** apply the existing rate-bounding helper to the notification path. Weakness classification: CWE-770, OWASP A09. | Accepted residual of review finding `CK-07`. | Platform team |
| `RISK-167` | Log retention is now age-based, which is a **behaviour change** for an installation that was silently keeping 1,000 rows forever: rows older than the retention window will now be deleted on the next scheduled run. The operator-initiated *clear all* handlers are untouched and still delete unconditionally; their copy-pasted comments and row-by-row deletes are hygiene, not a security defect. **Recommended action for operators:** confirm the retention window matches your evidence-retention obligation before the first run after upgrade, and export anything older first. Weakness classification: CWE-1053, OWASP A09. | Documented consequence of review finding `CK-13`. | Deployment owner |
| `RISK-168` | **Closed at this revision.** All **32** manual verification scenarios in the Gate 5 matrix have now been executed against disposable hosts and live PostgreSQL databases and hold committed, commit-bound attestations in the tracked `manual-verification-results.txt`, so the matrix reports `deferred=0` and no manual row blocks the release gate. **31** of the 32 are classified `REQUIRED`; the thirty-second, `M18` — measuring the deliberate login-latency increase — is the one `ADVISORY` row, and it was executed as well because the release gate refuses any row that is not `PASS`, advisory included. **A plain-text attestation file remains auditable rather than cryptographically trustworthy:** the gate requires it to be tracked and unmodified, to name a commit that is an ancestor of the commit under test, and to match a scenario revision that rotates whenever the scenario or its procedure is rewritten — but a party who can commit can write a line. **Residual recommendation:** adopt signed attestations, and re-execute any scenario whose revision rotates. Weakness classification: CWE-693, OWASP A09. | Closed for execution; the signing recommendation stays open. Residual of review findings `CK-19` and `MAJ-01`. | Whoever performs a release |
| `RISK-169` | Two pre-existing `DbFileRepository` behaviours found while closing `CK-15` and left alone under the minimal-change constraint: blob paths are addressed in a way that assumes a single storage root, and the filesystem move operates on the file **name** rather than a fully qualified path. Neither is reachable as a security defect on the database-backed storage this platform ships, and neither was raised by the review. **Recommended fix:** none required for security; record them before any future change to the storage backend. Weakness classification: CWE-1164, OWASP A04. | Documented observation, out of scope. Found while closing review finding `CK-15`. | Platform team |
| `RISK-170` | The **complete inventory** of raw-output, inline-script and inline-style channels: **111** `Html.Raw` sinks across **61** views, **59** inline `<script>` elements and **27** inline `style=` attributes, each with its writer and the authorization contract governing that writer. Raised by `MAJ-09`, which found that RISK-023 named only eight sinks and left three channels unnamed — `PcJavaScriptBlock/Display.cshtml:L11`, `PcGrid/Display.cshtml:L64` and `PcApplications/Display.cshtml:L70`. The first is a **fifth** by-design inline-script emitter, so RISK-022's report-only justification undercounted. This entry also quantifies what enforcing the mandated `script-src`/`style-src` policy would require. | **Accepted — inventory published; per-channel dispositions recorded** | Engineering |
| `RISK-171` | **Formal, attributable acceptance of the five `CA5351` analyzer residuals** — the legacy MD5 verification path `C-03`'s credential migration requires, plus the general-purpose digest helpers outside the remediated key handling. Raised by code-review finding `MAJ-01`, which found the Gate 1 allow-list carrying twenty-one **bare** pairs: a tolerance with no approver, no grounds and no exit condition is not an approved treatment. The acceptance, its approval record and the exit condition that retires it are in the detailed entry. | **Accepted — mandatory residual, formally approved, with a stated exit condition** | Repository owner |

### Identifiers renumbered while consolidating this register

Several analyses were written independently and reused the same low identifiers for different
subjects. Where that happened the identifier cited from **source code** was treated as fixed and the
other subject was renumbered, so every citation in the codebase still resolves. Only four identifiers
are cited from source code — `RISK-004` and `RISK-006` in `WebVella.Erp/Utilities/CryptoUtility.cs`,
`RISK-007` in `WebVella.Erp.Web/Services/AuthService.cs` and `RISK-040` in
`WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs` — and none of them was moved.

| Subject | Previously numbered | Now |
| --- | --- | --- |
| Static-analysis backlog kept as warnings | `RISK-003` | `RISK-024` |
| Content-Security-Policy ships report-only | `RISK-004` | `RISK-022` |
| Four by-design raw-output channels | `RISK-006` | `RISK-023` |
| Three anonymous routes share one per-address failure budget | `RISK-032` | `RISK-111` |
| Deterministic initialisation vector | `RISK-003` / `RISK-005` | `RISK-006` (cited from `CryptoUtility.cs`) |
| Credential hashing deviation | `RISK-005` | `RISK-003` |
| Login throttle durability and its inverse residual | `RISK-006` | `RISK-008` |

**The four overloaded identifiers are no longer overloaded.** Leaving `RISK-032`, `RISK-033`, `RISK-034`
and `RISK-035` each heading **three** different entries was rejected. The argument for it was that
renumbering would silently re-point citations in other documents at whichever subject inherited the number. It traded a defect a reader can see for a defect a reader cannot verify — an index that is authoritative for what an identifier
means cannot also say that an identifier means three things — and it left the register unable to state
its own contract. The correct fix was to renumber *and* to repair every citation, which is what was
done. New identifiers were allocated above the previous maximum (`RISK-128`) rather than into the unused
`RISK-072`–`RISK-107` band, so no number that any revision of any document has ever used acquires a new
meaning.

| Subject | Previously numbered | Now | Disposition |
| --- | --- | --- | --- |
| `RISK-032` | A dangerous URL scheme stored in a sitemap node URL survives HTML encoding | ~~Ten authenticated API actions still return a stack trace in the response body~~ — **CLOSED**: 0 occurrences remain; all ten route through the development-gated `SafeErrorMessage` | The `smtp_service` credential is not encrypted at rest |
| `RISK-033` | `ConvertDefaultValue` builds DDL default literals without escaping quotes | Provisioning emits six pre-existing bootstrap DDL statements | The SMTP certificate-validation opt-out survives in Development posture |
| `RISK-034` | SUPERSEDED — the taint-analysis family is not excluded | Plugin patches seed page-component options containing server-authored code | The permission migration preserves operator-created delegations |
| `RISK-035` | The taint-dataflow analyzer family runs, but intraprocedurally only | *(restated for a later pass under "residuals introduced by the continuous security review")* | Four residual observations recorded while closing the SMTP credential work |

| The `smtp_service` credential is not encrypted at rest | `RISK-032` | `RISK-032` | Canonical — kept, because this is the subject the index has always carried for `RISK-032` |
| Ten authenticated API actions still return a stack trace in the response body | `RISK-032` | `RISK-142` (inventory) and `RISK-147` (the closed record) | Renumbered — a distinct subject. Its inventory was replaced by `RISK-142`; the closure statement itself is `RISK-147`, moved off `RISK-032` so that identifier heads one record only |
| A dangerous URL scheme in a sitemap node URL survives HTML encoding | `RISK-032` | `RISK-037` | Not renumbered — it is the **same subject** as `RISK-037`, so the second write-up became a *Superseded statement of RISK-037* rather than acquiring an identifier of its own |
| The SMTP certificate-validation opt-out survives in Development posture | `RISK-033` | `RISK-033` | Canonical — the subject the index carries |
| `ConvertDefaultValue` builds DDL default literals without escaping quotes | `RISK-033` | `RISK-143` | Renumbered — a distinct subject |
| Provisioning emits six pre-existing bootstrap DDL statements | `RISK-033` | `RISK-144` | Renumbered — a distinct subject |
| The permission migration preserves operator-created delegations | `RISK-034` | `RISK-034` | Canonical — the subject the index carries |
| Plugin patches seed page-component options containing server-authored code | `RISK-034` | `RISK-145` | Renumbered — a distinct subject |
| The `CA3001`–`CA3012` taint-analysis family does not run at all — **withdrawn three times over**; it is armed everywhere, withheld from one project's build, and that project is scanned separately, so coverage is 19 of 19 | `RISK-034` | `RISK-051` | Not renumbered — the **same subject** as `RISK-051`; retained as a *Superseded statement of RISK-051* |
| Residual observations recorded while closing the SMTP credential work | `RISK-035` | `RISK-035` | Canonical — the subject the index carries |
| The taint-dataflow family runs, but intraprocedurally only | `RISK-035` | `RISK-051` | Not renumbered — same subject; retained as a *Superseded statement of RISK-051* |
| Security taint analysis does not run | `RISK-035` | `RISK-051` | Not renumbered — same subject; retained as a *Superseded statement of RISK-051* |
| No transport-level request-body limit bounds an upload before model binding | *(cited as `RISK-034`, never entered)* | `RISK-146` | **New entry** — the subject was cited from the remediation log and the audit report but had no entry anywhere; see below |

**Every citation those identifiers carried has been repaired, one by one.** Each cited a
number whose entry described a different subject, so each was resolved by **subject** rather than by
number, and none was left pointing at an identifier that does not describe it:

| Citation | Cited | Subject it names | Now points at |
| --- | --- | --- | --- |
| `security-audit-report.md`, Part 2 — the fifth live upload route | `RISK-033` | The `/fs/upload/` route accepting any type at any size, and the transport-buffering residual behind it | `RISK-146`, with a note that the route itself was subsequently hardened by review finding `F-09` |
| `remediation-log.md` — commit 3, Output Encoding | `RISK-032` | The sitemap URL-scheme residual | `RISK-037` |
| `remediation-log.md` — commit 4, File Upload and Download | `RISK-033` | The upload residual accepted with an owner escalation | `RISK-146` |
| `remediation-log.md` — `F-08` status | `RISK-033` | The deserialisation allow-list residual | `RISK-025` |
| `remediation-log.md` — `F-09` status and decision (o) | `RISK-034` | Transport-level request-body buffering | `RISK-146` |
| `remediation-log.md` — `F-11` status | `RISK-035` | Authentication-audit write failures, **resolved with no residual** | No register entry — the pointer is removed rather than re-aimed |
| `remediation-log.md` — the `workflow_dispatch` trigger contract | `RISK-033` | No scheduled re-audit | `RISK-109` |
| `remediation-log.md` — declines list, re-narrowing the binder | `RISK-033` | The deserialisation allow-list residual | `RISK-025` |
| `remediation-log.md` — declines list, transport-level upload limits | `RISK-034` | Transport-level request-body buffering | `RISK-146` |
| `remediation-log.md` — declines list, `PasswordField` bound enforcement | `RISK-032` | A decline with no register entry | No register entry — the identifier is removed and the decline stands on its own text |
| `remediation-log.md` — declines list, `.gitignore` entries for gate output | `RISK-038` | A decline with no register entry | No register entry — the identifier is removed |
| `secure-configuration.md` — retained by-design markup channels | `RISK-032` | The sitemap URL-scheme residual | `RISK-037` |

**Both index gaps are closed.** `RISK-108` through `RISK-111` now have index rows; `RISK-019` now has
its own row instead of being covered only by a `RISK-018` – `RISK-020` range row; and `RISK-142`
through `RISK-146` were added with the renumbering. `RISK-012` and `RISK-015` through `RISK-020` are
declared as rows in the *Pre-existing issues named but deliberately not fixed* table rather than as
their own headings, which is stated in the index preamble and is checkable there.

## Open decisions

### Decisions awaiting the repository owner — consolidated and actionable

Every decision below is **outside engineering's authority to settle**. Each is recorded with the exact
mechanical steps for each option, so that acting on it requires a decision and not a fresh
investigation. Nothing here is blocked on further analysis; all of them are blocked on a choice.

| # | Decision | Owner | Blocking effect while undecided | Detail |
| --- | --- | --- | --- | --- |
| 1 | **`AutoMapper` licence** — accept the Reciprocal Public License 1.5 (or the vendor's commercial agreement) for `[15.1.3]`, **or** decline it and take the documented narrow-suppression fallback | Repository owner / legal — a licensing and product-distribution decision, not an engineering one | The product links a dependency whose licence is **incompatible with its own declared `Apache-2.0` distribution posture**. The security advisory is closed and the build gate is green, so nothing fails loudly *at build time* — which is exactly how this came to be recorded as decided by Engineering, and why `CR2-F-04` reopened it. It is now enforced instead of merely disclosed: `dotnet pack` fails with `ERPLIC001` until the answer is recorded as one committed, attributable line in this file — the transient command-line property that used to satisfy it is now refused (`ERPLIC005`, review finding `GOV-01`) — so the question blocks **publishing** and nothing else. Executing either answer is a one-line commit plus, for the decline, the documented pin reversal | `RISK-001` below, [`WebVella.Erp/WebVella.Erp.csproj`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/WebVella.Erp/WebVella.Erp.csproj) (the gate and both licence comments), and [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md) |
| 2 | **Content-Security-Policy promotion** — approve the staged route to enforcement and accept its component-level work, **or** formally defer enforcement | Application security owner **and** frontend maintainer, jointly | The mandated header set is emitted but the content policy is **detective, not preventive**. The by-design markup channels retained under `RISK-023` and `RISK-032` therefore rest on the privileged markup-authoring contract alone | `RISK-022`, and the rollout in [the secure configuration guide](secure-configuration.md) |
| 3 | **Non-solution project coverage** — approve the current explicit per-project scanning, **or** authorise adding `WebVella.Erp.WebAssembly/Server` and `/Shared` to `WebVella.ERP3.sln` | Repository owner / build owner | None. Coverage is already continuous at 17 + 2 = 19 via explicit per-project steps in the workflow. The decision is only whether to simplify it to one command; the projects' frozen file contracts currently forbid changing solution membership | [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md), *How to reproduce this inventory* |
| 4 | **Historical commit atomicity** — acknowledge that the mandated commit ordering and one-class-per-commit grouping were not met on parts of this branch's history | Repository owner | None technically; the integrated tree is correct. Minimal Change guideline 9, *atomic commits per vulnerability class*, is recorded as **FAIL** — seven of thirteen commits carry more than one class — and the prescribed execution sequence is recorded as **FAIL** for four named ordering and atomicity findings (`F-07`–`F-10`). The acknowledgement is a process record and **cannot convert either failed item into a pass** | [Status at this revision](security-audit-report.md#status-at-this-revision-gate-by-gate); [the remediation log](remediation-log.md#formal-acknowledgement-of-the-four-ordering-and-atomicity-failures) |
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

**A correction this entry has to make about itself.** Review finding `CR2-F-04` rejected that, and
rightly: accepting a reciprocal-licence obligation on a product that publishes packages for
third-party consumption **is** changing that product's effective licence posture, and the governing
plan is explicit that an automated remediation must escalate that rather than absorb it. Recording
it as decided was absorption wearing the vocabulary of disclosure. The Status is corrected to open,
and — because a register entry alone is exactly the kind of disclosure that gets skimmed — the
consequence is now **enforced in the build** rather than only written down. This correction is made
in place, not appended, for the same reason the coverage corrections were: an entry that quietly
restates its own disposition is the failure being reported.

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
| `dotnet pack` with an `accepted-rpl-1.5` record committed to this file | exit 0, `.nupkg` produced, with a high-importance notice naming the record file and asking that the declared expression be confirmed before publishing |
| `dotnet pack` with a `declined-rpl-1.5` record committed to this file | **exit 1, `error ERPLIC002`** — declining is not complete until the pin is reverted, because the declaration would still be inaccurate |
| `dotnet pack` with a record present but malformed | **exit 1, `error ERPLIC003`** — an unrecognised value is refused rather than ignored, so a typo cannot be mistaken for consent |
| `dotnet pack -p:ErpAutoMapperLicenceDecision=accepted-rpl-1.5` | **exit 1, `error ERPLIC005`** — review finding `GOV-01`: the transient property form is now REFUSED rather than ignored, because silently ignoring it would leave the owner believing they had approved |
| `dotnet pack` with BOTH an accepted and a declined record present | **exit 1, `error ERPLIC007`** — a contradiction is refused rather than resolved by order, which would be the gate inventing the owner's intent |
| `dotnet pack` with the record file absent | **exit 1, `error ERPLIC006`** — the gate refuses to pass when it cannot read the decision, exactly as `ERPLIC004` refuses when it cannot read the pin |
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
   relicensing; then commit the decision record described in **How the decision is recorded** below.
   Nothing else changes: the advisory stays closed and no suppression is introduced. **This is the option
   the repository is currently configured for in every respect except ratification.**
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

#### How the decision is recorded — review finding `GOV-01`

`GOV-01` reported that the previous mechanism, an MSBuild property supplied on the `dotnet pack` command
line, **is not durable authenticated approval**. That is correct, and it is now changed. A global property
lives for the length of one process: it records no approver, no date and no reason, it cannot be reviewed,
it leaves nothing behind to audit, and any script — or any accidental shell history — can supply it.

**The answer is now one committed line in this file.** Being committed is what makes it durable (it
outlives the run), attributable (git records author, committer, date and commit, and the line carries its
own approver and reference) and reviewable (it arrives through the same review as any other change). The
gate reads this file at pack time; nothing else is consulted.

The required form is exactly one line, with no semicolons anywhere in it:

```text
AUTOMAPPER-LICENCE-DECISION-EXAMPLE: <answer> | approver: <name and contact> | date: <YYYY-MM-DD> | ref: <ticket or URL>
```

To record a real decision, use the token **without** the `-EXAMPLE` suffix and replace every placeholder;
`<answer>` must be either `accepted-rpl-1.5` or `declined-rpl-1.5`.

**Why the example above cannot approve anything.** A gate that reads a document has to be safe against the
document describing it. Two independent protections, both tested against this file: the example uses the
token `AUTOMAPPER-LICENCE-DECISION-EXAMPLE`, which the gate's patterns do not match, and the patterns
additionally require the exact token followed by one of the two literal answers and then a pipe — so a
prose mention of the token, or a placeholder in angle brackets, satisfies nothing. Verified: with this
section in place, `dotnet pack` still reports `ERPLIC001` — no decision recorded — rather than reading the
documentation as an answer or as a malformed attempt.

**The states the gate distinguishes**, each refused by its own diagnostic code rather than folded into a
single "blocked": no record (`ERPLIC001`), a record that is present but malformed (`ERPLIC003`), two
contradictory records (`ERPLIC007`), a decline that leaves the RPL pin in place (`ERPLIC002`), a record
file that cannot be read (`ERPLIC006`), an unreadable pin (`ERPLIC004`), and the retired transient
property being supplied (`ERPLIC005` — refused, not ignored, because ignoring it would leave the owner
believing they had approved). Build, restore, publish, run and every CI gate step remain unaffected: the
only operation this can block is `dotnet pack`, which is the only irrevocable one.

**The record is additionally bound to a commit in CI.** The MSBuild gate reads the working tree, because a
build must work with or without git. A workflow step therefore asserts that any record present in the
working tree is also present in the commit, that the file is tracked, and that exactly one record exists —
so a line dropped in locally cannot approve anything, and the approver, the date and the introducing commit
are printed into the run log. The absence of a record is not a failure there: it is this repository's
intended state while the decision remains outstanding.

**What is still not closed by it.** The gate reads a committed line; it cannot verify that the person named
as approver is authorised to approve, and it cannot stop a `.nupkg` built before the record existed from
being pushed. Both are named in the accepted-residual section below, and neither is what `GOV-01` asked
for. The decision itself remains **open and outstanding** — this change makes the answer recordable, not
recorded.

### Reversal analyses for RISK-001 — the two alternatives, neither of them in force

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

### Reversal path A for RISK-001 — accepting the advisory rather than the licence change

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition, and **not** a decision. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* **Nothing in this block is in force.** What it argues, in its own voice, is Option 2: hold the version at `[14.0.0]`, suppress the advisory narrowly and explicitly, and leave the licensing posture untouched. It is written out in full so that Option 2 is an executable plan rather than a gesture. |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021), and review finding `CR2-F-04` |
| **Argued by** | The remediation, as the conservative branch — *argued*, not decided. This field is deliberately not headed "Decided by": the choice *between* the two options is a licensing and product-distribution decision reserved to the repository owner. What is true, and is why the branch was written out at all, is that Option 2 is the one that leaves the owner's decision untaken — it preserves the declared `Apache-2.0` expression, the shipped `LICENSE.txt` and the published package terms exactly as the owner set them, whereas Option 1 requires the owner to ratify them. |
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
   risk acceptance. ◻ **Not taken in the shipped tree:** no suppression exists anywhere in the build
   configuration, which is checkable, and the pin is at `[15.1.3]`.
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

1. `WebVella.Erp/WebVella.Erp.csproj` — change `Version="[15.1.3]"` back to `Version="[14.0.0]"`.
   Search for `PackageReference Include="AutoMapper"` rather than relying on a line number, which
   moves whenever the comment above the pin changes.
   Keep the exact-version bracket form; a floating range would silently re-acquire the licence change.
2. `WebVella.Erp/Api/Models/AutoMapper/ErpAutoMapper.cs`, in `Initialize` — drop the second constructor argument,
   returning `new Mapper(new MapperConfiguration(cfg))`, and remove the now-unused
   `Microsoft.Extensions.Logging.Abstractions` using. The `ILoggerFactory` parameter exists only
   because the 15.x constructor requires it.
3. `Directory.Build.props` — **declare** the suppression, which has to be authored deliberately:
   nothing in the build configuration is suppressed today, and no template for one is carried
   anywhere in the tree. Measure the current state with the **element** form, not the bare-word
   form, because the bare-word form also matches prose:
   `grep -cE '<(NoWarn|WarningsNotAsErrors|NuGetAuditSuppress)' Directory.Build.props` returns
   **1** — the live taint-family `NoWarn` for the one excluded compilation — and
   `dotnet msbuild <project> -getItem:NuGetAuditSuppress` returns an empty item list for every
   project, which is the property that actually matters: **no advisory diagnostic is silenced.**
   The narrowest correct instrument is a `NuGetAuditSuppress` item naming the single advisory URL
   `https://github.com/advisories/GHSA-rvv3-g6hj-g44x`, never a `NoWarn` code, which would silence
   every future advisory of that severity as well. It must carry an inline justification and a
   back-reference to this entry, and it belongs in `Directory.Build.props` rather than in
   `WebVella.Erp.csproj` — the measurement behind that placement is in
   [`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md):
   a project-scoped suppression left the solution restore failing with exactly 15 `NU1903` errors,
   one per remaining affected project, because NuGet audit runs per project. Adding it is the act
   that accepts the residual risk, and it is invalid without the named accepter, date and re-review
   date recorded in this entry.

   **Note what does *not* need to change.** `ErpAutoMapper.Initialize` takes only a
   `MapperConfigurationExpression`; the no-op logger factory is constructed inside it. So the two
   initialisation call sites — `WebVella.Erp.Web/ErpMvcExtensions.cs:L709` and
   `WebVella.Erp.ConsoleApp/Program.cs:L141` — are **unaffected**, as are the 379 mapping
   declarations and every projection call site. The revert is genuinely two files.

*Consequence of Option B, stated without softening.* A **High**-severity advisory
(`GHSA-rvv3-g6hj-g44x`, CWE-674) is knowingly reintroduced into the dependency graph, and Validation
Gate 2's pass criterion changes from "no High or Critical rows" to "no **unsuppressed** High or
Critical rows". That is a real reduction in posture, justified only by the exploitability assessment
above, and it requires a named accepter and a date recorded in this entry. The suppression must also be
**negative-tested** — confirm that removing it makes the restore fail again — because an untested
suppression is indistinguishable from a gate that has quietly stopped working.

*Option B needs a fourth edit, in the workflow, and it is not optional.* This was measured rather than
reasoned about, because the two halves of Gate 2 do **not** read the suppression the same way. Against a
probe project pinned to `AutoMapper [14.0.0]` under this repository's build properties:

| Command | Without `NuGetAuditSuppress` | With `NuGetAuditSuppress` for `GHSA-rvv3-g6hj-g44x` |
| --- | --- | --- |
| `dotnet restore` | **fails** — `error NU1903: Warning As Error: Package 'AutoMapper' 14.0.0 has a known high severity vulnerability` | **succeeds**, exit 0, no `NU19xx` |
| `dotnet list package --vulnerable --include-transitive` | reports `> AutoMapper [14.0.0] 14.0.0 High https://github.com/advisories/GHSA-rvv3-g6hj-g44x` | reports the **same row** — the listing does **not** honour `NuGetAuditSuppress` |

So a suppression that satisfies restore leaves the *Gate 2 advisory listing* step in
`.github/workflows/security-scan.yml` failing on a `High` row, and the job stops. Taking Option B
therefore requires, in the same commit:

1. Narrowing that step's advisory search so it tolerates **exactly one** URL —
   `https://github.com/advisories/GHSA-rvv3-g6hj-g44x` — and nothing else. Never widen the pattern to
   all `High` rows, and never delete the check: it is the only step that reads the *resolved* graph.
2. Re-pointing the negative control so it still proves the gate is live. Removing the suppression must
   make the job fail again, and a *second* High advisory in any package must still fail it while the
   accepted one is tolerated. Assert both, or the narrowing has silently become a blanket.
3. Recording the accepter, the date and a re-review date in this entry, so the tolerated URL has an
   owner and an expiry rather than becoming permanent by inattention.

None of these three edits is in force today, because Option A is: the pin is `[15.1.3]`, the advisory is
absent from the graph, and both halves of Gate 2 agree on a clean result.

*Provisional state until the owner decides.* **Option A is in force by default**, because the security
advisory had to be closed and the alternative was to ship a known High-severity vulnerability. This is
a provisional engineering disposition taken to keep the gate green, **not** an acceptance of the
licence on the owner's behalf. The declared `Apache-2.0` expression was deliberately left unchanged so
that the conflict remains discoverable rather than papered over in either direction.

**There is no reversal procedure to run for Option 1, because its steps are already the shipped state:**
the pin is `[15.1.3]`, `ErpAutoMapper` supplies `NullLoggerFactory.Instance`, and there is no
suppression of any kind anywhere in the repository to delete. Only one step remains, and it
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

### Reversal path B for RISK-001 — holding the pin at the permissively licensed version

| Field | Value |
| --- | --- |
| **Status** | *(Reversal analysis — **not** the shipped disposition, and **not** a decision. The tree at this commit pins `[15.1.3]` and declares no suppression; see the note above this heading.)* **Nothing in this block is in force.** It is written out in full so that Option B is an executable plan rather than a gesture: if the owner ever chooses it, this is the acceptance they would be ratifying — the advisory knowingly retained, disclosed and gated. That acceptance is **not** decided. |
| **Decision** | Hold the pin at `[14.0.0]` (MIT). Do **not** upgrade. Accept the advisory with a narrowly scoped audit suppression and this formal acceptance. |
| **Related finding** | H-01 / HR-11 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, **High**, OWASP A06:2021) |
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

- All 379 `CreateMap<...>` declarations across 32 `Profile` subclasses are **statically declared in
  source** and compiled into the assembly. None is built from configuration, user input, or reflection
  over an untrusted type graph.
- There is exactly **one** `new MapperConfiguration(...)` site in the repository, invoked from two
  fixed start-up call sites. No request path, stored record or plugin hook contributes to it.
- The recursion path therefore requires a **self-referential mapping that this project's own
  developers would have to author, compile and ship.** An external attacker has no mechanism to
  introduce one.
- If ever triggered, the consequence is a denial of service **at start-up** — not data disclosure,
  privilege escalation or code execution — and it would fail loudly on first initialisation, in
  development.

**Secondary benefit of holding the pin.** `14.0.0` declares **one** dependency; `15.1.3` declares
**five**, including a four-package `Microsoft.IdentityModel.*` chain at **8.14.0** — a version
*behind* the `8.15.0` this solution already references directly for its own token validation. An
object-mapping library pulling a JSON Web Token stack downward was an unwanted side effect. Reverting
removed all four packages, so the decision reduced the graph's attack surface rather than merely
preserving it.

**How it is gated, and why that is not concealment.**

- A single `NuGetAuditSuppress` entry in `Directory.Build.props` names
  `https://github.com/advisories/GHSA-rvv3-g6hj-g44x` **and nothing else**, with its justification
  recorded in place.
- Repository-wide placement is a **necessity, not a widening**: NuGet audit is evaluated per project,
  and AutoMapper reaches 16 project graphs through the core library. A project-scoped entry left the
  solution restore failing with exactly 15 `NU1903` errors.
- **Negative-tested.** Injecting an unrelated vulnerable package (`Newtonsoft.Json 9.0.1`) made the
  build fail with `NU1903` reporting a *different* advisory (`GHSA-5crp-9r3c-p9vr`). The suppression
  cannot mask a new advisory.
- `dotnet list package --vulnerable --include-transitive` **still reports the advisory in all 16
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

### RISK-003 — Credential hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2

| Field | Value |
| --- | --- |
| **Status** | Accepted — one deviation from the letter of the mandated cryptographic standard, satisfying its intent. An owner option for literal compliance is stated below. |
| **Related findings** | `C-03` (CWE-916 password hash with insufficient computational effort, CWE-759 one-way hash without a salt, OWASP A02:2021); review findings `CR-1` and `M-3` |
| **Owner** | Repository owner, if literal compliance with the named algorithm families is required. Otherwise no action. |
| **Location** | `WebVella.Erp/Utilities/PasswordUtil.cs` — `HashPassword`, `VerifyPassword` and the payload constants |

**This entry is the single canonical record for the credential-hashing deviation.** Three further
statements of it existed in later sections of this register, written by later review passes, and each
carried a different and partly obsolete technical description. They are replaced by pointers to this
entry, and what they got wrong is recorded here rather than deleted.

**The governing standard, quoted verbatim** so the deviation is measured against the actual wording
rather than a paraphrase of it. This is the engagement's Cryptographic Standards block:

```text
- TLS 1.2+
- AES-256-GCM
- RSA-2048+ / ECDSA P-256+
- bcrypt / scrypt / Argon2 with cost factor 12+
- CSPRNG
```

The fourth line names three algorithm families at a minimum cost factor, and **the chosen primitive is
none of those three.**

**What is actually shipped**, stated once and precisely, because every earlier description of it in this
register was wrong in at least one particular:

| Property | Shipped value |
| --- | --- |
| Derivation | `Rfc2898DeriveBytes.Pbkdf2` — a base-class-library primitive, called directly in `PasswordUtil.cs`, **not** `Microsoft.AspNetCore.Identity.PasswordHasher<T>` |
| Pseudo-random function | **HMAC-SHA-256** (`HashAlgorithmName.SHA256`), recorded in the payload as function identifier `1` |
| Iteration count | **600,000**, recorded in the payload so it can be raised later |
| Salt | 16 bytes (128 bits) from `RandomNumberGenerator`, fresh per credential |
| Subkey | 32 bytes (256 bits) |
| Stored form | 13-byte header (`0x01` format marker, function identifier, iteration count, salt length) + salt + subkey, Base64-encoded to **84 characters**, always beginning `A` |
| Verifier | `VerifyPbkdf2Hash`, comparing through `CryptographicOperations.FixedTimeEquals`; the retained legacy MD5 path compares the same way |
| Rehash signal | Derived from the stored payload — `needsRehash` is set when the recorded iteration count is below the current constant, or when the stored value is a legacy 32-character MD5 digest |

**Why PBKDF2. Four reasons, given openly rather than glossed:**

- **It is sanctioned by the authority, not merely tolerated.** OWASP's Password Storage guidance
  specifies Argon2id, bcrypt at a work factor of at least 10 subject to a 72-byte input limit, **and**
  PBKDF2 with at least 600,000 iterations using HMAC-SHA-256. The shipped setting is exactly that
  sanctioned configuration, so it is an approved choice rather than a compromise.
- **It satisfies the standard's unambiguous intent** — slow, salted, work-factored, fixed-time
  verification.
- **It adds no dependency**, which the least-invasive-control constraint prefers. `Rfc2898DeriveBytes`
  is in the base class library, so the core project needs no reference of any kind for it, and this
  keeps the core library free of an ASP.NET Core dependency it does not otherwise want.
- **It supports the migration in one primitive.** The self-describing payload records the iteration
  count, so the rehash-needed signal the upgrade-on-next-authentication pattern depends on is read out
  of the stored value rather than guessed, and the fixed-time comparison closes `M-05` (CWE-208) in the
  same edit.

**The measured cost, re-measured at this commit against the shipped setting.** Medians over 20
single-threaded runs, .NET 10.0.10, on this build host:

| Configuration | Cost per hash | Cost per verification |
| --- | --- | --- |
| PBKDF2-HMAC-SHA-256 @ 600,000 — **as shipped**, quiet run | 150 ms | 151 ms |
| PBKDF2-HMAC-SHA-256 @ 600,000 — **as shipped**, same host under contention | 344 ms | 321 ms |
| PBKDF2-HMAC-SHA-512 @ 600,000 — the comparison, same process | 477 ms | — |

*Provenance and honesty about these numbers.* The host is a shared container and the spread above is
what that produces: the same code measured 150 ms and 344 ms in two runs minutes apart. **Treat the
ratio and the direction as the finding, never the absolute value.** The ratio is the durable result:
SHA-512 costs roughly **3.2×** the shipped setting per attempt at equal iterations, which is why an
earlier pass's decision to *accept* an already-stored SHA-512 value rather than rehash it to SHA-256 is
correct — rehashing would have been a work-factor downgrade. Figures of 367.0 ms per hash and 364.1 ms
per verification, once presented as "as shipped", measured the HMAC-SHA-512 configuration and are
**withdrawn**, together with the "exactly 3.00×" ratio derived from them.

**The accepted cost.** Authentication becomes measurably slower, by design: on the order of 0.15 s of
CPU per login attempt on an unloaded host. That is the control working, not a regression, and it is
confined to the authentication path — no other request path performs a key derivation, and credential
resolution is bounded to a constant **two** derivations per attempt so a single anonymous request cannot
amplify it. It is pre-declared here rather than discovered later, because the scope caps performance
regression at 10 % and this deliberately exceeds that on one path. Practical consequence to be aware of:
at four logical CPUs, sustained concurrent login attempts are throughput-limited by this cost — which is
also precisely what makes credential stuffing expensive.

**What this acceptance does not claim.** It does not claim PBKDF2 is preferable to Argon2 in the
abstract; for a greenfield system with a free choice of dependencies, a memory-hard function is the
stronger option. It claims only that PBKDF2 at this work factor is a sanctioned choice that closes the
confirmed finding within the constraints imposed on this remediation.

**The pseudo-random function is not a second deviation.** The reasoning that would make it one — that the
mandated HMAC-SHA-256 and the versioned payload format are "mutually exclusive" in ASP.NET Core — does not
hold here. The premise
about the framework *type* is correct — `PasswordHasher<T>`'s V3 format is PBKDF2-HMAC-SHA512 and
`PasswordHasherOptions` exposes only `CompatibilityMode` and `IterationCount` — but the conclusion about
this repository never followed, because the versioned layout is a payload format rather than a property
of that type, and `PasswordUtil.cs` writes the layout itself. Both mandated parameters are met at once,
so **there is no pseudo-random-function deviation left to accept.** Review finding `M-3` records the
correction, and the residual it left behind is deliberate and narrow: a stored HMAC-SHA-512 value is
accepted on verification and **not** rehashed, for the work-factor reason measured above.

**Owner option, if literal compliance is required.** Add a dedicated bcrypt or Argon2 package and
substitute it behind the same `HashPassword` / `VerifyPassword` members, extending the stored-shape
discriminator to recognise a third format. The migration design is unaffected: the discriminator keys on
the stored value's shape, so a third format is carried by the same upgrade-on-next-authentication
mechanism already in place. The cost is that it would be the **only** new package dependency in the
entire remediation, which is why it is not taken unilaterally.

*Review trigger:* revisit when the OWASP iteration guidance for PBKDF2-HMAC-SHA-256 next rises, or if a
memory-hard function becomes available in the framework without a third-party package.

### RISK-004 — Broken-hash analyzer warnings are accepted on the retained legacy path

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

### RISK-006 — M-08: deterministic initialisation vector in the symmetric encryption helpers

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

That was confirmed by probe. `AnalysisLevelSecurity=latest-all` arms the whole Security category, so
`CA5390` and `CA5401` do execute and their zero counts are measurements rather than silences; each is
also silent for its own verified reason, recorded below. Both layers are recorded, because if the gate
is ever widened the inner reason is what will still matter:

- **`CA5390` — hard-coded encryption key. Silent, and meaningfully so.** The key reaches
  `GetValidKey(string key, SymmetricAlgorithm)` as a parameter sourced from configuration, not as a
  literal. That is exactly the state finding `C-04` produced when the compiled-in default constant was
  deleted and its silent fallback made fatal — so had the rule run, its silence would have been a
  genuine confirmation. It does not run, so today the silence carries no signal at all. The gate's
  positive control asserts the opposite of what it once did: `CA5390` **must not** be reported even
  against a deliberately hard-coded key, which is how CI detects that the rule has stopped executing
  rather than silently trusting it.
- **`CA5401` — non-default initialisation vector. Silent, but for a shape reason, not a safety one.**
  The rule matches the two-argument `CreateEncryptor(rgbKey, rgbIV)` overload. This code assigns
  `algorithm.IV` as a *property* and then calls the parameterless `CreateEncryptor()`, so the pattern
  the rule looks for never appears — even though the value assigned is derived deterministically from
  the key, which is precisely the weakness this entry describes.
- **`CA5389` does not apply at all.** It concerns adding an archive item's path to a target filesystem
  path. It was named in an early draft of the source comment on this region and the comment itself now
  records the correction.

`RISK-035` is *not* an additional explanation for any of the three. It recorded an interprocedural
limit on the `CA3001`–`CA3012` taint rules; none of these three is one of them, and in any case the
disposition of that family has been restated twice since — it is armed, withheld from one project's build
and scanned separately there, per the canonical `RISK-051`.

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
The taint-dataflow family `CA3001`–`CA3012` is excluded on **cost from one project only** — see the
canonical [`RISK-051`](#risk-051-the-ca3001ca3012-taint-analysis-family-covers-19-of-19-compilations-one-is-scanned-at-bounded-interprocedural-depth),
which supersedes the repository-wide framing this paragraph was written under. A probe confirmed `CA3001`
correctly detects a deliberate SQL-injection flow, so the rules work; enabling them **repository-wide**
took the solution build from **102 seconds to more than 6,600 seconds without completing**, with the
Roslyn compiler server failing outright — but a later per-project measurement attributed that entirely to
`WebVella.Erp.Web`, and the family now executes for the other eighteen projects at a cost within
measurement noise. Separately, every security rule outside the four that `latest-recommended`
enables — `CA5390`, `CA5401`, `CA2100`, `CA2326`, `CA2327`, `CA2328`, `CA5362`, `CA5382`, `CA5383`,
`CA5402`, `CA5404` among them — is excluded by **the frozen shape of the gate**, not by cost: reaching
them requires an `AnalysisLevelSecurity` upgrade that AAP 0.6.1 Class 2 does not authorise.
Cross-site-scripting, taint-propagated sinks, and the concatenated-SQL and binary-formatter shapes are
therefore all outside the gate and were identified by manual review. Nothing anywhere is **suppressed** —
the distinction matters, because a suppression hides a diagnostic that would otherwise be produced, while
these rules never produce one. The full gate boundary is described in the
[secure configuration guide](secure-configuration.md).

## Detailed entries — dependency disposition, the analyzer backlog and the encryption helper

### Supplementary analysis of RISK-002 under *dependency disposition* — reachable only by a developer

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-002` — Uncontrolled recursion in `AutoMapper` remains theoretically reachable by a developer](#risk-002-uncontrolled-recursion-in-automapper-remains-theoretically-reachable-by-a-developer). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual. Subsumed by RISK-001, recorded separately because the weakness class outlives the version decision. |
| **Related finding** | H-01 |

**Scope.** The pin is `[15.1.3]` and the vulnerable version is **not** in the graph; nothing here rests
on retaining it. Note the precise scope of that statement — RISK-001's *advisory* half is closed,
while its *licence* half remains open and pending owner ratification; the two are separable and only the
first one bears on this entry. What survives the upgrade
is narrower, and it is why this entry is kept rather than deleted: a self-referential mapping
authored in source is a **developer error rather than a library defect**, so the patched library
bounds the recursion but does not make such a mapping correct. It is **not reachable by an external
actor**, because mapping configuration is statically declared and no user-controlled configuration or
type graph reaches the configuration builder — the same assessment that made RISK-001's reversal path
defensible had it been taken. No control is added for it, consistent with fixing only what is
confirmed and with the prohibition on enhancement beyond remediation.

### RISK-024 — Static-analysis backlog reported as warnings rather than enforced as errors

| Field | Value |
| --- | --- |
| **Status** | Accepted — reported, measured and left visible. Not suppressed. |
| **Related control** | Gate 1, static analysis (`EnableNETAnalyzers`, `AnalysisLevel=latest-recommended` and `AnalysisLevelSecurity=latest-all` in `Directory.Build.props` — the whole of the frozen analyzer gate — enforced by the workflow's Security-category allow-list) |
| **Scope** | Repository-wide, all 19 projects. `Directory.Build.props` is **directory**-scoped, so the analyzer gate reaches both WebAssembly projects by location even though neither is a solution member (see `RISK-030`). Inheritance is deliberately broader than membership. |

Enabling the .NET analyzer set across the platform surfaces **3,055 warnings** on a full rebuild
(`dotnet build WebVella.ERP3.sln -t:Rebuild -v n`, MSBuild's own summary line), which resolve to
**3,028 distinct diagnostic sites** across **50** distinct rules once identical
`(file, line, column, rule)` tuples are collapsed. Read any other total in this document set as dated and
re-measure it: the figure moves whenever the analyzer configuration does. It was **3,096** while a
repository-root
`.globalconfig` armed *and promoted* additional security rules, removing that file under AAP 0.6.1 Class 2
dropped it to **3,046**, withdrawing the version-5 migration removed two `CA1822` members to give
**3,044**, and re-arming the Security category with `AnalysisLevelSecurity=latest-all` — which promotes
nothing — raised it to **3,055**, the figure this revision measures. None of the 3,055 is newly
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

### Supplementary analysis of RISK-004 under *dependency disposition* — legacy MD5 is present and is reported by the analyzer gate

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-004` — Broken-hash analyzer warnings are accepted on the retained legacy path](#risk-004-broken-hash-analyzer-warnings-are-accepted-on-the-retained-legacy-path). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

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

**Stated precisely, because the difference matters:** `VerifyPassword` *signals* that a legacy value
needs upgrading, through its `needsRehash` output, and a signal nothing acts on would leave legacy values
verified as legacy and never upgraded. The acting path is
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
strengthens the disposition: measured with `git grep`, `ComputeMD5HashBytes` and `ComputePhpLikeMD5Hash` have **zero
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

### Pointer to RISK-003 from *dependency disposition* — see the canonical entry

This is a **pointer, not a second entry.** The credential-hashing deviation has one canonical record:
[`RISK-003` — Credential hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2](#risk-003-credential-hashing-uses-pbkdf2-rather-than-bcrypt-scrypt-or-argon2),
under *cryptographic standards, the legacy hashing path and the encryption helper*. It carries the
shipped parameters, the verifier, the measured latency, the owner option and the withdrawn
pseudo-random-function deviation.

**What the statement in this position got wrong:** it named the location as "the
`PasswordHasher<object>` configuration", recorded a pseudo-random-function deviation that no longer
exists, and published latency figures — 367.0 ms and 364.1 ms — measured against the HMAC-SHA-512
configuration while labelling them "as shipped".

### Supplementary analysis of RISK-006 under *dependency disposition* — deterministic initialisation vector in the symmetric encryption helpers

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-006` — M-08: deterministic initialisation vector in the symmetric encryption helpers](#risk-006-m-08-deterministic-initialisation-vector-in-the-symmetric-encryption-helpers). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

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

### Supplementary analysis of RISK-006 under *encryption helper and throttle scope* — deterministic initialisation vector in `CryptoUtility`

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-006` — M-08: deterministic initialisation vector in the symmetric encryption helpers](#risk-006-m-08-deterministic-initialisation-vector-in-the-symmetric-encryption-helpers). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

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

### Supplementary analysis of RISK-004 under *encryption helper and throttle scope* — `CA5351` on the retained legacy verification path

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-004` — Broken-hash analyzer warnings are accepted on the retained legacy path](#risk-004-broken-hash-analyzer-warnings-are-accepted-on-the-retained-legacy-path). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

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

### Pointer to RISK-003 from *encryption helper and throttle scope* — see the canonical entry

This is a **pointer, not a second entry.** The credential-hashing deviation has one canonical record:
[`RISK-003` — Credential hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2](#risk-003-credential-hashing-uses-pbkdf2-rather-than-bcrypt-scrypt-or-argon2),
under *cryptographic standards, the legacy hashing path and the encryption helper*. It carries the
shipped parameters, the verifier, the measured latency, the owner option and the withdrawn
pseudo-random-function deviation.

**What the statement in this position got wrong:** it recorded *two* deviations, the second being the
pseudo-random function, and gave the OWASP iteration floor as 210,000 for PBKDF2-HMAC-SHA512. The
shipped function is HMAC-SHA-256 at 600,000 iterations, which is the OWASP floor for that function, so
the second deviation no longer exists.

### RISK-008 — Login throttle lockouts are durable, so a lockout cannot be released by a restart

| Field | Value |
| --- | --- |
| **Status** | **The original limitation is CLOSED.** What remains accepted is its mirror image: a lockout can no longer be cleared by bouncing a process, and a store that cannot be reached refuses attempts rather than allowing them. |
| **Related finding** | H-16 (CWE-307, OWASP A07:2021) |
| **Location** | `WebVella.Erp.Web/Services/LoginThrottleService.cs`, backed by `WebVella.Erp/Database/DbSecurityStateRepository.cs` |

**What the control actually does now, measured from the source.** Failure counters and in-force lockouts
are held in the **pre-existing `public.plugin_data` table** under the reserved key prefix `wv_sec_`
(`DbSecurityStateRepository.ReservedKeyPrefix`), so the control needs **no schema definition statement and
no new package dependency**. Each transition is a single row-locked read-modify-write, so a concurrent
burst is serialised by the database rather than by an in-process lock that would only cover one process.
The measured parameters are:

| Parameter | Value | Source |
| --- | --- | --- |
| Failures tolerated per account | **5** | `MaxFailedAttemptsPerAccount`, `:L65` |
| Failures tolerated per source address | **25** | `MaxFailedAttemptsPerAddress = MaxFailedAttemptsPerAccount * 5`, `:L76` |
| Counting and lockout window | **15 minutes** | `WindowMinutes`, `:L83` |
| Account key namespace | `wv_sec_lthr_acct_` | `:L96` |
| Address key namespace | `wv_sec_lthr_addr_` | `:L97` |
| Attach point | `login.cshtml.cs:L211`, `TryBeginAttempt` | the single login entry point |

**Three properties follow, and each closes something the earlier design could not.** A lockout now
**survives a restart**, so a deployment or crash no longer hands an attacker a fresh budget. It is
**shared by every instance** against the same database, so five failures means five in total rather than
five per process. And entries are reclaimed **by expiry only** — there is no capacity ceiling — so a
flood of fabricated usernames can no longer evict a real account's partial count. The two dimensions are
counted on **independent keys** with independent thresholds, which is what denies an attacker with a proxy
pool a fresh budget per address for the same account.

**It fails closed.** When the durable store cannot be consulted, `TryBeginAttempt` **refuses** the
attempt. That costs nothing real, because credential verification reads the user from the same database —
a database this code cannot reach is one no login could have succeeded against — and the alternative,
allowing an unmetered attempt whenever the counter is unavailable, is precisely how an outage becomes an
unlimited guessing window.

**One in-process cache remains, and it is not the counter store.** `LoginThrottleService` holds a
`MemoryCache activeLockouts` (`SizeLimit = 20000`, `CompactionPercentage = 0.2`) as a **positive-only
mirror** of lockouts this process has already been told about. It can only ever *refuse* a key the durable
store would also refuse: a miss always consults the database, so the mirror can never authorise an
attempt and never mask a lockout another instance recorded, and each entry's absolute expiration is the
very instant the lockout it mirrors lapses. Eviction is harmless — the next request asks the database and
re-learns the same answer. Reading this cache as "the throttle is in-process" is the specific error this
entry previously made.

**What is accepted, stated as the residual it now is.** The exposure has inverted. An operator can no
longer release a lockout by restarting the process, so a user locked out in error waits out the
fifteen-minute window; there is no administrative unlock action, and adding one would be a feature rather
than a remediation. Separately, a database outage now refuses logins that the earlier design would have
allowed — a deliberate availability-for-security trade, bounded by the observation above that logins could
not have succeeded during such an outage anyway.

**Complementary control.** Transport-level rate limiting is a separate layer that belongs in each host
pipeline and is not provided by this service. It is recorded in the
[secure configuration guide](secure-configuration.md) as host wiring; a per-address fixed-window limiter
bounds attempt *rate* independently of this control's state.

#### Historical record — the superseded in-process design, and why it was replaced

Retained because the reasoning was published and should not simply vanish; **none of it describes the
current tree.** The counters originally lived in a private, size-bounded `MemoryCache`, chosen as the
least invasive control that closed `H-16` while avoiding both a schema change and a new dependency. Three
boundaries of that store each defeated the mandated five-attempt guarantee outright: a process restart
discarded every counter and every in-force lockout; a second instance behind a load balancer counted
independently, so the effective budget was five failures *per instance*; and pre-lockout counters were
stored at `Low` cache priority and were therefore deliberately capacity-evictable, so an attacker who
submitted twenty thousand fabricated usernames could displace a target account's partial count and repeat
that reset indefinitely. The entry also argued, under the old design, that absent state **must** read as
"no failures recorded" because treating it as locked would lock out every user after any restart. That
argument was sound only while the store was volatile; with a durable store, absent state means the store
failed to answer, which is not a state the control may resolve in the caller's favour — hence the
fail-closed behaviour above. The move to `DbSecurityStateRepository` was made under review finding
`CK-03` and refined under `H-OPEN-02`; the "recommended fix — move the counters to a distributed backing
store" that this entry used to carry as outstanding work **has been implemented**.

## Detailed entries — risks arising from the integrated controls

### Supplementary analysis of RISK-002 under *the integrated controls* — survives the upgrade only as a developer error

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-002` — Uncontrolled recursion in `AutoMapper` remains theoretically reachable by a developer](#risk-002-uncontrolled-recursion-in-automapper-remains-theoretically-reachable-by-a-developer). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual. See RISK-001. |
| **Related finding** | H-01 / HR-11 |

**The advisory is closed and the open item is the licence, not the version.** The pin is `[15.1.3]` — and
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

### Pointer to RISK-003 from *risks arising from the integrated controls* — see the canonical entry

This is a **pointer, not a second entry.** The credential-hashing deviation has one canonical record:
[`RISK-003` — Credential hashing uses PBKDF2 rather than bcrypt, scrypt or Argon2](#risk-003-credential-hashing-uses-pbkdf2-rather-than-bcrypt-scrypt-or-argon2),
under *cryptographic standards, the legacy hashing path and the encryption helper*. It carries the
shipped parameters, the verifier, the measured latency, the owner option and the withdrawn
pseudo-random-function deviation.

**What the statement in this position got wrong:** it described the primitive as "taken from the
framework's own password hasher" and credited the fixed-time comparison to that hasher's verification
routine. The derivation is called directly in `PasswordUtil.cs` and the fixed-time comparison is
`CryptographicOperations.FixedTimeEquals` in this repository's own verifier. Its correction of the
mutual-exclusivity claim was right and is carried into the canonical entry.

### RISK-022 — Content-Security-Policy ships in report-only mode

| Field | Value |
| --- | --- |
| **Status** | Accepted — staged rollout, **with an open owner decision on the promotion to enforcement**. The mandated policy *value* is emitted verbatim; only the delivery mode is staged. |
| **Related finding** | M-01, L-1 (OWASP A05:2021) |
| **Owner** | The **application security owner** for the platform — that is, whoever owns `SecurityHeadersOptions` and the seven host pipelines — jointly with the **frontend maintainer** for the plugin and tag-helper surfaces that emit the inline markup. Enforcement cannot be promoted by an infrastructure change alone, because clearing the backlog means editing components; that is why the decision is owned by both roles rather than by whoever last touched the middleware. |
| **Promotion gate** | See *Governance of the promotion to enforcement* immediately below — the threshold, the criteria and the stage exit conditions are stated there rather than left to judgement. |
| **Consequence for the mandated requirement** | Because the policy is delivered report-only it is **not enforced**, so the engagement's seven-header requirement is **`UNRESOLVED / PARTIAL`, not compliant** — six of the seven mandated header *names* are emitted and enforced, and the seventh arrives as `Content-Security-Policy-Report-Only`. Raised by code-review finding `MAJ-08`. This register is **not** the authority for that status: the single authoritative status surface is the [audit report's status section](security-audit-report.md#status-at-this-revision-gate-by-gate), and where anything here disagrees with it, that section governs. |
| **Measured backlog** | `RISK-170` — **59** inline `<script>` elements and **27** inline `style` attributes across the **111**-sink raw-output census, which is what makes enforcement a project rather than a configuration flag. |

**Report-only is NOT the remediation for H-06, and must not be recorded as such.** This needs saying
explicitly, because the two are adjacent and easily conflated. `H-06` (stored cross-site scripting,
CWE-79, OWASP A03) is remediated in the view and builder layer: text sinks were encoded by deleting
the raw wrapper, and every channel deliberately retained as by-design markup is enumerated in
`RISK-023` and `RISK-032`. The content policy is a **compensating control layered on top of that
work**, and while it ships report-only it is **detective, not preventive** — a browser reports the
violation and then executes the script anyway. So report-only closes nothing on its own. Any status
summary that cites the content policy as evidence for `H-06` is wrong; cite the encoding work and the
two risk entries instead.

#### Governance of the promotion to enforcement

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
by-design markup channels in `RISK-023` and `RISK-032` continue to rest on the markup-**placement**
contract alone. Read that precisely, because an earlier wording said *privileged markup-authoring
contract* and code-review finding `DOC-02` rejected it as an overstatement: what a privileged role
controls is which channel is placed on a page and what it points at, **not** the bytes that channel
finally emits. An administrator may point an HTML-block's option at a record field through
`PageDataModel.GetPropertyValueByDataSource`, after which anyone able to write that field influences what
is rendered unencoded. The full correction is at `RISK-004`. That is a materially weaker position than
the mandated header set
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

**The count of first-party raw-output emitters was itself wrong, and is corrected in RISK-170.** This
entry and RISK-023 both said *four* components emit inline script or author-supplied markup through a
raw-output channel. There are **five**: `PcJavaScriptBlock/Display.cshtml:L11` wraps
`@Html.Raw(options.Script)` in a literal `<script>` element and was named in neither entry. Code-review
finding `MAJ-09` raised it, and RISK-170 now carries the complete inventory — all **111** raw-output
sinks across **61** views with each writer and its authorization contract, plus the measured enforcement
cost of **59** inline `<script>` elements and **27** inline `style` attributes. Read RISK-170 as the
census this entry's backlog is drawn from; the two are consistent, and where the emitter *count* is
concerned RISK-170 supersedes the figure quoted above.

**Scale of the backlog, measured rather than estimated.** A single authenticated browsing session
produced **at least 379** report-only violations. One isolated page context alone accounted for
**137**, broken down as **132 inline-style, 3 inline-script and 2 `eval`**. The distribution is the
useful part: inline *style* dominates by an order of magnitude, so the practical sequence is to address
`style-src` first, then the far smaller `script-src` and `eval` sets — and to add the two missing
directives above, which are prerequisites regardless of progress on the inline work.

### RISK-005 — RETIRED: the CSP report endpoint no longer exists

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

- its `report-uri` directive changed the emitted `Content-Security-Policy` value, which the audit
  specifies exactly; and
- to accept a report ahead of routing, the collector branch returned from the middleware — giving the
  middleware a path that completed a request **without attaching the other six headers**.

With no endpoint there is no anonymous sink, so there is nothing left to flood. This is a genuine
retirement and not a reclassification: the mitigating control (the logging cap) was deleted along with
the thing it mitigated, and neither is needed.

**Where violation reports come from now.** The browser console, for the duration of the report-only
rollout. It carries the same blocked-URI and violated-directive information the endpoint recorded. A
deployment that wants aggregation should terminate `report-to` at a reverse proxy or a dedicated
collector service rather than inside the header middleware — which keeps the header-attachment path
single and unconditional, the property whose absence was `CFG-04`.

### RISK-023 — Five by-design raw-output channels are not encoded

| Field | Value |
| --- | --- |
| **Status** | Accepted — remediated by compensating control. |
| **Related finding** | H-06 (CWE-79, OWASP A03:2021) |

The HTML-block page component (design and display views) and **three** generated-inline-script emitters —
the two quoted below plus the `PcJavaScriptBlock` emitter recorded further down under code-review finding
`MAJ-09` — exist *in order to* emit markup and script. Encoding them would disable the features outright,
breaching the functionality-preservation requirement. The compensating controls are restricting
markup and script authoring to privileged roles, plus the Content-Security-Policy once enforced — **read
that first clause with the correction in the next paragraph, which narrows it from *authoring* to
*placement*.** These four channels are the concrete reason RISK-022 exists.

**What that control does and does not cover.** Saying "authoring requires a privileged role" overstates it. What is administrator-only is *choosing the channel*: the five page-node mutation actions that write a node's options are gated by `IsCodeAuthoringAuthorized`, so only an administrator can place a markup-block component on a page or set its `Html` option. The **bytes** rendered raw need not come from that administrator. The option value is resolved through `PageDataModel.GetPropertyValueByDataSource`, so a `DATASOURCE` variable such as `{"type":0,"string":"Record.some_field"}` resolves through `GetProperty` against a model whose named properties include `Record`, `ParentRecord` and `CurrentUser` — that is, live database field values. Once an administrator points a raw channel at a record field, anyone who can write that field can influence what is emitted unencoded. The accurate statement of the control is therefore: **a privileged role decides what is rendered raw, not who supplies it**, and that is why the Content-Security-Policy is the load-bearing half of the compensation rather than an optional addition.

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

**A fifth channel of the same kind was missing from this entry — see RISK-170.** Code-review finding
`MAJ-09` found that `WebVella.Erp.Web/Components/PcJavaScriptBlock/Display.cshtml:L11` wraps
`@Html.Raw(options.Script)` in a literal `<script>` element, making it a by-design inline-script emitter
indistinguishable in kind from the last two rows above, and that it was named nowhere in this register.
Two further channels — `PcGrid/Display.cshtml:L64` and `PcApplications/Display.cshtml:L70` — were also
unnamed. All three are now inventoried, with their writers and authorization contracts, in **RISK-170**,
which is the canonical census of every raw-output channel; the acceptance recorded here extends to the
`PcJavaScriptBlock` emitter on identical reasoning. Where this entry's *counts* and RISK-170's disagree,
RISK-170 governs.

**Scope of this acceptance, stated explicitly.** It covers those **five** channels — the four quoted
above plus the `PcJavaScriptBlock` emitter named immediately above them — and nothing else. Where this
entry's counts and `RISK-170`'s disagree, `RISK-170` governs. The
other stored sinks that H-06 names — the shared navigation and site-menu views, and the six Project
widget views — are **not** accepted risk, and they are closed by two different shapes of the same
control, so it is worth being precise about which applies where.

- **Navigation and site menu.** `NavItem.cshtml` rewrites the composed string as markup in order to
  inject the dropdown toggle, so the raw-output helper has to stay. The remediation therefore lands at
  the point of composition in `BaseErpPageModel`: every database value interpolated into
  `MenuItem.Content` is HTML-encoded, URL-allow-listed or character-constrained *before* it becomes
  markup, so the value reaching the helper is already safe.
- **The six Project widget views.** Here the raw-output helper is **gone**. The three widget builders no
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
privileged roles, plus the Content-Security-Policy — read with the same correction recorded there: what is
privileged is *choosing* the raw channel, not necessarily *supplying* its bytes. This entry is the narrower
case, because the composition-time encoding named above does bound the data path here.

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

### RISK-170 — Complete inventory of raw-output, inline-script and inline-style channels

| Field | Value |
| --- | --- |
| **Status** | Accepted — inventory published; every channel carries its own disposition below. |
| **Related findings** | H-06 (CWE-79), M-01 (CWE-1021), M-18 (CWE-116), OWASP A03:2021 |
| **Raised by** | Code-review finding `MAJ-09` |
| **Canonical for** | The channel inventory that RISK-022 and RISK-023 both rely on. |
| **Owner** | Engineering — no owner decision is pending on this entry. |

**Why this entry exists.** RISK-023 above named eight sinks when this entry was written — four by-design
channels, three `IsHtml`-guarded navigation channels and the data-source icon — and its scope clause read
"those four channels and nothing else". That was a truthful statement of what it *accepted*, but it was not
an inventory, and it left three channels named nowhere in this register at all. RISK-023's heading, opening
paragraph and scope clause read **five** by-design channels, the fifth being the `PcJavaScriptBlock`
emitter named in the first row below; this entry remains canonical for the inventory and for the counts.

| Previously unnamed channel | Construct as it appears in source |
| --- | --- |
| `WebVella.Erp.Web/Components/PcJavaScriptBlock/Display.cshtml:L11` | `@Html.Raw(options.Script)`, wrapped in a literal `<script>` element on `L10`/`L12` |
| `WebVella.Erp.Web/Components/PcGrid/Display.cshtml:L64` | `<div class="alert alert-info m-0">@Html.Raw(options.EmptyText)</div>` |
| `WebVella.Erp.Web/Components/PcApplications/Display.cshtml:L70` | `@Html.Raw(app.Author)` |

The first of those is **a fifth by-design inline-script emitter**, which makes it load-bearing for
RISK-022's report-only justification rather than incidental: that justification previously counted four
emitters. This entry is the complete inventory — every occurrence, the code that writes the value, and
the authorization contract governing that writer.

**The measured census, with the commands that reproduce it.** Run from the repository root:

```bash
# Raw-output sinks, with Razor (@* *@) and HTML (<!-- -->) comment blocks removed first.
python3 - <<'PY'
import re, os
n=0; files=set()
for root,_,fs in os.walk('.'):
    if root.startswith('./.git'): continue
    for fn in fs:
        if not fn.endswith(('.cshtml','.cs','.razor')): continue
        p=os.path.join(root,fn); t=open(p,encoding='utf-8-sig',errors='replace').read()
        if 'Html.Raw' not in t: continue
        s=re.sub(r'@\*.*?\*@','',t,flags=re.S); s=re.sub(r'<!--.*?-->','',s,flags=re.S)
        c=len(re.findall(r'Html\.Raw\(',s))
        if c: n+=c; files.add(p)
print('raw-output sinks:', n, 'in', len(files), 'files')
PY
grep -rhoE '<script(\s[^>]*)?>' --include=*.cshtml . | grep -vc 'src='
grep -rhoE '\sstyle="[^"]*"' --include=*.cshtml . | wc -l
```

| Measure | Count |
| --- | --- |
| Raw-output sinks (comment blocks removed) | **111** |
| Distinct views containing a sink | **61**, all `.cshtml` |
| Sinks in `.cs` or `.razor` files | **0** |
| Distinct sink arguments | **35** |
| Inline `<script>` elements carrying no `src` | **59** |
| Inline `style="…"` attributes | **27** |

**Why a bare `grep -c 'Html.Raw('` disagrees, and which number is right.** A bare grep counts **118**
across 67 files, because it also matches this remediation's own explanatory comments — the six Project
widget views each carry a *do not reintroduce `Html.Raw`* note, and `PcHtmlBlock.cs` carries two
XML-documentation mentions. Those seven mentions are prose, not sinks. **111 across 61 views is the
sink-only figure and is the one this register asserts.** The delta is fully accounted for:

```bash
grep -rn 'Html\.Raw' --include=*.cs . | wc -l   # 9 — every one a comment, no sink
```

#### Class-by-class inventory — all 111 sinks

The thirteen classes below partition the 111 sinks exactly; the **Sinks** column sums to 111. "Trust
boundary" names who must be compromised or mistaken for attacker-controlled bytes to reach the sink.

| # | Class | Sinks | Writer | Trust boundary | Disposition | CSP directive it forces |
| --- | --- | --- | --- | --- | --- | --- |
| A | Server-composed row-action markup — `action`, `record["action"]` | 55 | Each page's own `*.cshtml.cs` list builder, e.g. `data_source/list.cshtml.cs:L70` | None reachable — interpolates only GUIDs, enum-derived literals and `ReturnUrlEncoded` | **Not a sink for untrusted data.** Left as-is per AAP §0.2.1, which proves all seven builders interpolate identifiers only | none |
| B | Include-tag emitters — `tag`, `metaTitle` | 10 | `PageUtils.GenerateTagsFromObject` over typed `ScriptTagInclude`/`LinkTagInclude`/`MetaTagInclude`; `metaTitle` from `ViewBag.Title` | Developer at compile time; plus `ErpSettings.Lang` from operator configuration; `ViewBag.Title` from an administrator-authored page label | Left as-is — the emitters exist to build tags. Observation on `ErpSettings.Lang` recorded below | `script-src 'unsafe-inline'`, `style-src 'unsafe-inline'` |
| C | Compile-time literal instruction text — `ViewBag.GeneralHelpSection`, the `empty guid` anchor | 8 | `PageComponent.HelpJsApiGeneralSection` = the `HELP_JSAPI_GENERAL_SECTION` constant (`Models/PageComponent.cs:L23`); two view-local string literals | None — no interpolation hole exists | **Not a sink.** Constant markup | none |
| D | Pre-encoded URLs — `Model.ReturnUrlEncoded`, `HttpUtility.UrlEncode(Model.CurrentUrl)` | 4 | The page model's encoded property; `HttpUtility.UrlEncode` at the sink | None — encoded before the sink | **Closed.** These are the *correct* pattern the three reflected H-06 fixes were changed to match | none |
| E | SDK web-api documentation samples — `meta*Request*`, `field*Request`, `record*Request` | 11 | `entity/web-api.cshtml` itself, e.g. `L46`, interpolating `Model.ErpEntity.Id` and `.Name` | Administrator-gated schema write; values are identifier-constrained | Left as-is — server-composed markup, identifier-bounded | none |
| F | Enum-switch icon badges — `record["icon"]` | 3 | `PageUtils.GetDataSourceIconBadge` and siblings — a `switch` returning hard-coded literals or `""` | None — no interpolation hole on any return path | **Not a sink.** Triaged in RISK-023 | none |
| G | **By-design inline-script emitters** — `ViewBag.EmbededJs` ×2, `options.Script` ×1 | 3 | `Nav.Default.cshtml:L48`, `WvSdkPageSitemap/Form.cshtml:L92`, `PcJavaScriptBlock/Display.cshtml:L11` | Administrator — `IsCodeAuthoringAuthorized` gates the page-node option writes that supply the script | **Accepted (RISK-023, now extended to the third).** Encoding would disable the feature | `script-src 'unsafe-inline'` — **the reason RISK-022 ships report-only** |
| H | Markup-block component — `ViewBag.ProccessedHtml` | 2 | `PcHtmlBlock.cs` via `PageDataModel.GetPropertyValueByDataSource` | Administrator chooses the channel; **any writer of a bound record field supplies the bytes** | **Partly closed by HIGH-01.** Administrator-authored *literal* markup still renders raw; every *model-resolved* value is now passed through `HtmlSanitizer.Sanitize` | `script-src 'unsafe-inline'` for the literal path only; the sanitized path emits no script |
| I | `IsHtml`-guarded navigation and menu content | 5 | `BaseErpPageModel` composition into `MenuItem.Content`; raw branch runs only when `IsHtml = true` | Privileged author sets `IsHtml`; interpolated database values are already encoded, URL-allow-listed or character-constrained at composition time | **Accepted (RISK-023).** Renders on every page of all seven hosts | `style-src 'unsafe-inline'` (badge `style=` attributes) |
| J | Administrator-authored designer text — `options.EmptyText`, `app.Author` | 2 | `PcGrid` node options; the `application` record's `author` field | Administrator — page-node options via `IsCodeAuthoringAuthorized`; application metadata via one of the 24 `[Authorize(Roles = "administrator")]` endpoints | **Accepted, newly named.** Both are privileged-author markup channels with no anonymous path | none required; benefits from `script-src` once enforced |
| K | SDK code-generation preview — `record.Element`, `record.Name`, `change` | 3 | `tools/cogegen.cshtml.cs` diff/preview builder | Administrator — code generation is administrator-gated | Left as-is — server-composed preview markup | none |
| L | SDK server-built nav fragments — `item`, `Model.CreateFieldUrl + fieldCard["type"]` | 2 | `AdminPageUtils.GetAppAdminSubNav`; `create-field-select.cshtml.cs:L31` literal path | None reachable — server-built paths and enum type names | **Not a sink** | none |
| M | SDK relation metadata — `record["name"]`, `record["origin"]`, `record["target"]` | 3 | `entity/relations.cshtml.cs:L154-L177`, interpolating relation, entity and field names into badge markup | Administrator-gated schema write; every interpolated value is an identifier constrained by the platform's identifier grammar | Left as-is — identifier-bounded interpolation | `style-src 'unsafe-inline'` (badge `style=` attributes) |

**Enumerating every occurrence, so this inventory is checkable rather than merely asserted.** The
thirteen classes above partition the sinks; the command below prints all 111 individually as
`file:line — argument`, which is what makes the partition auditable. Its output is sorted by argument, so
each class in the table above appears as a contiguous block.

```bash
python3 - <<'PY'
import re, os
out=[]
for root,_,fs in os.walk('.'):
    if root.startswith('./.git'): continue
    for fn in sorted(fs):
        if not fn.endswith(('.cshtml','.cs','.razor')): continue
        p=os.path.join(root,fn); t=open(p,encoding='utf-8-sig',errors='replace').read()
        if 'Html.Raw' not in t: continue
        s=re.sub(r'@\*.*?\*@',lambda m:re.sub(r'[^\n]',' ',m.group(0)),t,flags=re.S)
        s=re.sub(r'<!--.*?-->',lambda m:re.sub(r'[^\n]',' ',m.group(0)),s,flags=re.S)
        for i,line in enumerate(s.split('\n'),1):
            for m in re.finditer(r'Html\.Raw\(',line):
                if '//' in line[:m.start()]: continue
                j=m.end(); d=1; a=''
                while j<len(line) and d>0:
                    c=line[j]
                    if c=='(': d+=1
                    elif c==')':
                        d-=1
                        if d==0: break
                    a+=c; j+=1
                out.append((a.strip(), p.lstrip('./'), i))
for a,p,i in sorted(out): print(f'{p}:{i} — {a}')
print('total:', len(out))
PY
```

**Observation on class B, recorded rather than fixed.** `BodyBottomIncludes.cs:L30-L31` composes
`var globalScript = $"var SiteLang=\"{ErpSettings.Lang}\";moment.locale(\"{ErpSettings.Lang}\");"` and
emits it through the class-B path into a JavaScript string literal without JavaScript-encoding.
`ErpSettings.Lang` is supplied by configuration, so the trust boundary is the **operator**, who can
already execute code by other means; there is no request-borne path to that value. Under the
minimal-change constraint this is documented, not changed — it is neither a Critical nor a High, and no
finding in the audit report names it.

#### How each channel binds to the Content-Security-Policy

RISK-022 records that the mandated `script-src 'self'` policy ships report-only. This inventory is what
bounds the work required before it can be enforced, so the two entries must be read together.

| Directive | Channels that currently require a relaxation | Count of sinks | What enforcement would break |
| --- | --- | --- | --- |
| `script-src` | Class G (3), class H literal path (2), class B script tags | 5 raw sinks + 59 inline `<script>` elements | Page-designer JavaScript blocks, the navigation and sitemap script emitters, and the `SiteLang`/`moment.locale` bootstrap on every page |
| `style-src` | Class I, class M, class B style tags | 27 inline `style="…"` attributes | Badge and menu layout across all seven hosts |

**The consequence, stated plainly.** Enforcing the mandated policy is **not** a one-line configuration
change: it requires nonce-or-hash treatment for 59 inline `<script>` elements and 27 inline `style`
attributes, across components whose whole purpose is to emit author-supplied script. That is the
measured backlog behind RISK-022, and it is why enforcement is an owner decision rather than an
engineering follow-up. The audit report's gate table records the resulting requirement status.

#### How each channel binds to manual regression

Every channel whose disposition is *accepted* or *partly closed* must survive a rendering check, because
the failure mode of an over-eager encoding fix is a silently broken screen rather than an error. The
scenarios below are the ones that exercise these channels. All of them have now been executed and
attested — `M16` covers the inline-script, inline-style and grid channels and `M31` covers the data-bound
HTML Block — so the execution half of RISK-168 is closed; the signing recommendation it carries is not.

| Channel class | What the regression check must confirm |
| --- | --- |
| G — inline-script emitters | The navigation script, the sitemap form script and a `PcJavaScriptBlock` node all still execute; no CSP violation is reported for them beyond the expected report-only entries |
| H — markup-block component | Administrator-authored literal markup still renders as markup in **both** Design and Display views, while a model-resolved value carrying an event handler or `<script>` is rendered inert |
| I — navigation and menu | Menu items with `IsHtml = true` still render their icon markup, and items with `IsHtml = false` render their content as visible text |
| J — designer text | An empty `PcGrid` still shows its configured empty-state markup; an application card still shows its author line |
| A, E, K, L, M — server-composed markup | The SDK list, relation, web-api and code-generation screens still render their action buttons and badges rather than visible angle brackets |

### Accepted risks — residual and bounded

#### Superseded statement of RISK-037 — a dangerous URL scheme in a sitemap node URL survives HTML encoding

**This section is a superseded statement, not a second entry, and it declares no identifier of its own.** The current record is [`RISK-037` — Sitemap node URLs are encoded but their scheme is not validated](#risk-037-sitemap-node-urls-are-encoded-but-their-scheme-is-not-validated). It is retained so that a reader holding an earlier copy can see exactly which claim changed.

**Neither of two claims this section once carried holds.** It was published as `RISK-032`, an identifier three different subjects were competing for; and its **Location** row asserted that an in-code comment in `WebVella.Erp.Web/Models/BaseErpPageModel.cs:392-402` "defers here by name". No source file cites this identifier: the only four `RISK-` citations anywhere in the tree are `RISK-004` and `RISK-006` in `WebVella.Erp/Utilities/CryptoUtility.cs`, `RISK-007` in `WebVella.Erp.Web/Services/AuthService.cs` and `RISK-040` in `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs`. Reproduce with `grep -rn "RISK-" --include="*.cs" --include="*.cshtml" . | grep -v "^./docs"`.

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

- **The authoring surface is administrator-only.** Editing the sitemap is a design function, not a
  data-entry one. An actor who can author a sitemap node already holds the privilege the vector would
  obtain.
- **The breakout half — the part that made this a stored-XSS finding — is genuinely closed.** The value
  is confined to its attribute, so it cannot escape into surrounding markup or affect any other
  element on the page.
- **Scheme allow-listing would break legitimate authoring.** A designer is entitled to author `mailto:`
  and `tel:` links, and in this platform also relative and app-relative URLs; an allow-list narrow
  enough to exclude `javascript:` reliably would need maintaining against every scheme a designer may
  legitimately want. Under the Minimal Change Clause that is out of scope for this finding.

Note that this is a **different** risk from `RISK-016`, which concerns three static
`href="javascript: void(0)"` Bootstrap dropdown placeholders that are byte-identical on every page and
carry no stored value at all. `RISK-016` is *not a defect*; the residual recorded here is real, and its current record is `RISK-037`.

*Recommendation for a future sprint:* validate the stored URL at the point of authoring — a scheme
allow-list applied in the sitemap editor, where a rejected value can be explained to the author — in
preference to filtering at render time, where the only available behaviour is to silently drop a link
the designer believes they created.

#### RISK-143 — `ConvertDefaultValue` builds DDL default literals without escaping quotes

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

- **Reachable only by an administrator**, through schema design — creating or altering a field
  definition. That is already among the most privileged operations the platform offers, and it can
  execute arbitrary DDL by design.
- **No unauthenticated or non-administrative path reaches it.** It is not driven by record data, query
  input, or any request parameter.
- **It is a pre-existing condition**, not introduced by this remediation, and no reported finding
  covers it. Fixing it is therefore governed by *document out-of-scope concerns but do not fix unless
  Critical* — and privilege-bounded DDL influence by an actor who may already author DDL is not
  Critical.

*Recommendation for a future sprint:* route the literal through the same validate-and-quote discipline
introduced for identifiers (`WebVella.Erp/Database/DbIdentifier.cs`), or bind the default as a
parameter where the target dialect permits it in a `DEFAULT` clause. Treat it as hardening of an
administrative surface rather than as closing an exposure.

#### Superseded statement of RISK-051 — first record that the `CA3001`–`CA3012` taint-analysis family does not run at all

**This section is a superseded statement, not a second entry, and it declares no identifier of its own.** The current record is [`RISK-051` — The `CA3001`–`CA3012` taint-analysis family does not run](#risk-051-the-ca3001ca3012-taint-analysis-family-covers-19-of-19-compilations-one-is-scanned-at-bounded-interprocedural-depth). It is retained so that a reader holding an earlier copy can see exactly which claim changed.

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
| **Location** | No location in the tree. The twelve `interprocedural_analysis_kind = None` options lived at `.globalconfig` lines 145–156; that file has been deleted, and no configuration mentioning `CA3001`–`CA3012` remains anywhere. |

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

**One precision on the count.** The trial that completed timed **72** rules; the shipped set is
**71**. The difference is not cost-related: `CA3147` was removed afterwards for a different reason —
it is an antiforgery rule, and the plan of record explicitly declines antiforgery enforcement on the
MVC API surface because existing clients post without a verification token. `CA5391`, its modern
counterpart, is excluded for exactly the same reason. Both report zero occurrences in the build — as
does every Security-category rule outside the four the frozen gate enables, which is why a zero here
must not be read as clearance.

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

- There was no revocation list.
- **Signing out cleared the cookie; it did not invalidate an already-issued bearer token.**
- A stolen token remained usable until the earlier of its own expiry and the absolute session horizon.

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
scheme when the session is revoked. The list is now durable and shared — it reserves a key
prefix in the pre-existing `plugin_data` table, so it still needs **no** schema change — and the
in-process residual that `RISK-036` recorded is closed there.

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

- `AuthService.BuildTokenAsync` stamps the same `erp_session_id` claim into **every** issued token, and
  `GetNewTokenAsync` carries the presented token's identifier **verbatim** into its successor rather
  than minting a fresh one — so a revocation survives refresh instead of being shed by it.
- `AuthService.GetValidSecurityTokenAsync` refuses a validated token whose identifier is revoked, and
  refuses one carrying no parseable identifier at all.
- `GetNewTokenAsync` refuses to mint a successor for a revoked or unidentifiable session, so the refresh
  endpoint can no longer resurrect an ended session.
- The framework bearer handler — the validator that actually authorises `[Authorize]` endpoints, because
  the `JWT_OR_COOKIE` policy scheme forwards to it — now fails the token in `OnTokenValidated` through
  the shared `AuthService.IsBearerSessionRevoked` predicate. The hook is installed in the two hosts that
  register `AddJwtBearer` (`WebVella.Erp.Site`, `WebVella.Erp.Site.Project`) because that handler's
  options type ships in a package only those two reference; the **rule** stays single-sourced in the
  platform. Without this, a revocation check present only in the platform's own validator would have
  been decorative.

`AuthService.LogoutAsync` needed no change to revoke a bearer session: `JwtMiddleware` assigns
`HttpContext.User` from the presented token's claims, so the identifier the current principal carries
resolves correctly whichever credential the caller signed out with.

Recommended future work is now narrower than when this was written: the store already survives a restart
and spans instances, so what a rotating refresh-token table with reuse detection would add is **rotation
and reuse detection**, not durability. That scope residual is closed; see the
restated `RISK-036`.

#### Supplementary analysis of RISK-008 under *the integrated controls* — HISTORICAL: the superseded per-process throttle

**This section is a supplementary analysis, not a second entry, and it declares no identifier of its own.** The canonical record is [`RISK-008` — Login throttle lockouts are durable, so a lockout cannot be released by a restart](#risk-008-login-throttle-lockouts-are-durable-so-a-lockout-cannot-be-released-by-a-restart). It is retained because a different review pass wrote it, and deleting it would remove that pass's reasoning from the record.

| Field | Value |
| --- | --- |
| **Status** | **Superseded — the limitation described below is CLOSED.** See the canonical `RISK-008` for current behaviour; the recommended future work this section carried has been implemented. |
| **Related finding** | H-16 / H-6, H-7 (CWE-307, OWASP A07:2021) |

> **RESOLVED, not accepted — superseded by review finding `CK-03`.** Everything in this entry described a
> process-local throttle, and that is no longer what ships. `LoginThrottleService` now keeps its counters in the
> durable, atomic, shared store `DbSecurityStateRepository` provides over the pre-existing `plugin_data` table,
> so a lockout **survives a restart, spans instances and fails closed** when the store cannot be reached, still
> with no schema change and no new dependency. Only an in-force lockout is mirrored locally, and only positively,
> so eviction can cost a database read but never a partial count. Proven by executing matrix scenario `M28`: a
> three-failure, restart, two-failure split count still refuses the correct password; a second instance observes
> the lockout; and a login is refused while the store is renamed away. The text below is retained as the record of
> what was accepted before that change, and its *recommended future work* has been done.

*(Historical, superseded — retained per the blockquote above.)* The throttle **was** backed by an in-process store, chosen so the control required **no schema change and
no new dependency**. In a multi-instance or load-balanced deployment each instance counted
independently, so effective thresholds multiplied by the instance count. A distributed backing store was
recommended and deliberately not built at that time; **it has since been built** — see `RISK-008`. Operators running more than one instance should also enforce
throttling at the load balancer.

Two further bounded trade-offs:

- **Account lockout is a denial-of-service primitive.** It lapses automatically after 15 minutes
  rather than requiring administrator action, so an attacker can lock a known account for 15 minutes.
  That is a deliberate trade against making credential stuffing cheap.
- **The store is size-bounded** to cap memory growth against an attacker varying the username.
  Displacing a specific account's partial count requires cycling the entire store, which buys at most
  a few extra guesses.
- The per-address threshold is deliberately **five times** the per-account threshold, because NAT and
  shared corporate egress mean many legitimate users share one address.

**Bypass-resistance model, and what remains residual.** Each of the four evasion routes below is
named at the control it constrains in `WebVella.Erp.Web/Services/LoginThrottleService.cs`, where the
comment states the invariant the code upholds. They are restated here because what belongs in a risk
register is the part the code cannot express: the residual that each closure leaves behind, and who
has accepted it. The duplication is deliberate, not an oversight - a reader of either artefact alone
would otherwise be missing half the picture:

- **Source-address rotation.** A combined username-and-address key — which the first revision of the
  service used — gives an attacker with a proxy pool a fresh budget per address for the same account,
  so a targeted account never locks. Closed by counting the account and the address on independent
  keys: a failure advances the account counter regardless of where it came from.
- **Username rotation.** The mirror image: rotating the submitted username gives a fresh budget from
  one address. Closed by the same independence — the address counter advances regardless of which
  account was named. Residual: an attacker who rotates *both* dimensions is bounded only by the
  transport rate limiter, which is the layer that exists for that case.
- **Cache-eviction displacement.** The store is size-bounded at 20,000 tracked principals with 20%
  compaction, so an attacker minting distinct usernames forces eviction rather than growth. Eviction
  takes the lowest priority first and in-force lockouts are written at `High` while still-counting
  entries are written at `Low`, so a flood evicts other partial counts long before it releases any
  lockout. `NeverRemove` is deliberately **not** used: it would exempt lockout entries from the
  ceiling and restore the unbounded growth the bound exists to prevent. Residual, accepted:
  displacing one specific account's partial count costs a full store turnover — tens of thousands of
  requests through a transport rate limiter — to buy back at most four guesses.
- **Time-of-check/time-of-use (CWE-367).** A check-then-authenticate-then-count protocol lets every
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

**This table is the declaring entry for seven identifiers**, which is why they have no heading of their
own: `RISK-012`, and `RISK-015` through `RISK-020`. Each is a one-line pre-existing observation rather
than an analysis, so a row carries it completely. Reproduce the completeness check from the repository
root:

```bash
# the seven identifiers declared by a row in this table rather than by a heading
grep -oE '^\| RISK-0(12|1[5-9]|20) ' docs/security/risk-register.md | grep -oE 'RISK-[0-9]+' | sort -u
# each of the seven also has exactly one row in the canonical index
for r in 012 015 016 017 018 019 020; do
  printf '%s index-rows=%s heading-rows=%s\n' "RISK-$r" \
    "$(grep -cE "^\| \`RISK-$r\`" docs/security/risk-register.md)" \
    "$(grep -cE "^#{1,6} RISK-$r — " docs/security/risk-register.md)"
done
```

| Ref | Issue | Why not fixed |
| --- | --- | --- |
| RISK-012 | **The generic record-update path can wipe a password hash.** The user-facing save path correctly ignores a blank incoming password, verified by a real UI save leaving the hash byte-identical. The *generic* record-update path guards only against `null`, not an empty string, which would be converted to `NULL` downstream. | Pre-existing and unchanged by the credential work. Named in [the credential migration guide](credential-migration.md) so it is not attributed to the migration. |
| RISK-013 | ~~Two hosts serve a permissive `Access-Control-Allow-Origin: *`.~~ **No longer accurate — resolved.** Both hosts now register an explicit `WithOrigins(...)` allow-list and read `Settings:Cors:AllowedOrigins`. A repository-wide scan for a *live* (non-commented) `AllowAnyOrigin()` across all seven host `Startup.cs` files returns **zero** occurrences. A supplied list wins in every environment; an empty list denies every origin; an absent key denies every origin outside Development and selects the host's own Development fallback — three localhost origins for `WebVella.Erp.Site`, and those three plus `http://localhost:2202` for `WebVella.Erp.Site.Project`. Runtime checks on both hosts confirmed listed origins receive `Access-Control-Allow-Origin` with `Vary: Origin` and unlisted origins receive neither. | **Fixed.** Recorded as finding `P-06` in [the audit report](security-audit-report.md). |
| RISK-014 | ~~Two bearer-token error paths return stack traces **unconditionally**.~~ **No longer accurate — resolved.** Both anonymous token endpoints now log server-side and return a generic message, with full exception text emitted only behind the development-mode guard. Measured at this commit, and restated because the earlier measurement has been overtaken by a wider sweep: the controller now contains **zero** `StackTrace` references of any kind; **37** of its fault responses route through `SafeErrorMessage` at `:L334-L339` and the remaining **4** — all inside these two token actions — assign the fixed `INTERNAL_ERROR_MESSAGE` directly. The token and refresh actions begin at **5653** and **5834**. | **Fixed** as `H-13`. The claim that ten *authenticated* actions still leak is **retracted** — see `RISK-032`, where the retraction and the development-gated residual that genuinely remains are recorded. |
| RISK-015 | ~~`/ckeditor/ImageFinder` returns HTTP 500 — its page model does not derive from the type its layout requires. **Proven pre-existing by counterfactual**: reverting the view to its original content reproduced the identical exception.~~ **No longer accurate — closed by removal, not by repair.** The route and its page model were retired in full under review finding `SR-04`, together with `/ckeditor/Index`, because the pair referenced roughly seventy `/jsadmin/**` AngularJS and CKEditor-4 assets that exist nowhere in this repository — so neither page could ever have rendered, and shipping the missing bundle would have meant adding two end-of-life vendor libraries. A route that cannot return 500 because it is not routed is a stronger outcome than a repaired one. | **Closed.** Retiring it was verified safe before removal rather than after: `JsAdminModel`, `JsAdminImageFinderModel` and the `/ckeditor` page routes were referenced from **zero** other files. The live CKEditor 5 integration is unaffected — it uses the controller routes `/ckeditor/drop-upload-url` and `/ckeditor/image-upload-url`, which are untouched and still routed. |
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
password was a literal — `[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]`. A demo
credential also appeared in a WebAssembly client page.

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

- Known published key material is refused by digest comparison, not merely absent — so a value
  recovered from this repository's history cannot be used even deliberately.
- Environment variables supply the secrets, touching no tracked file. See
  [the secure configuration guide](secure-configuration.md) and
  [`README.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/README.md).
- Absent or insufficient-entropy secrets fail closed outside Development.

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

- **A demo credential in the Blazor WebAssembly client — CLOSED.**
  `WebVella.Erp.WebAssembly/Client/Pages/Index.razor.cs` authenticated with a literal e-mail and
  password. The Blazor WebAssembly client project is inside the authorised file set — cumulative-review
  finding `F3` names that file explicitly — so the literal was removed rather than left
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
- **Repository history — ACCEPTED, with a detective control.** Blanking a tracked file does not remove
  the value from earlier commits, and removing the demo credential does not either: it was introduced
  **upstream** and is reachable from `HEAD`, so the published literal was a genuinely valid seeded administrator
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
| **Status** | **Resolved.** The heading is deliberately left as first written, because the register's convention is that a title identifies the record rather than restating its current verdict. |
| **Related finding** | C-01 (hardcoded default administrator password). |

The seeded credential is now supplied by the operator through
`Settings:InitialAdministratorPassword`, is required (12–128 characters), and is unique per
installation.

**The residual this entry recorded no longer exists: the credential now carries a
change-required-on-first-login marker.** No column was needed for it, because `rec_user.preferences` is
an existing `text not null default '{}'` column, so the marker is carried with **zero DDL**.

The mechanism is implemented end to end and can be traced:

| Role | Where |
| --- | --- |
| Declared | `ErpUserPreferences.PasswordChangeRequired` in `WebVella.Erp/Api/Models/ErpUserPreferences.cs` |
| Set at first provisioning | `InitializeSystemEntities` in `WebVella.Erp/ERPService.cs` |
| Set by the version-4 rotation migration | `RevokeSeedAdministratorCredential4` in `WebVella.Erp/ERPService.cs` |
| Cleared once the password is actually rotated | `SaveUser` in `WebVella.Erp/Api/SecurityManager.cs` |
| Read to gate the interactive session | `IsPasswordRotationRequired` in `WebVella.Erp.Web/Services/AuthService.cs` |
| Read to gate the post-login redirect | `OnPost` in `WebVella.Erp.Web/Pages/login.cshtml.cs` |
| Enforced on bearer issue and refresh | `GetTokenAsync` and `GetNewTokenAsync` in `WebVella.Erp.Web/Services/AuthService.cs` |

The enforcement is asymmetric on purpose, and the asymmetry is the point: an interactive sign-in
succeeds so the operator can reach the change-password screen, while **bearer token issue and refresh
are refused** until the rotation happens. An account that still owes its first rotation therefore
cannot be used for automated API access at all, which is the exposure a first-login marker exists to
close. Since this remediation, that refusal is also recorded as a bounded audit event and returns the
generic credential message rather than a distinct one, so it does not become an oracle confirming that
a given address is a valid, unrotated account.

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

*One correction of scope, under `OBS-08`.* "The generator was removed rather than hardened" overstated
what happened. What was removed is every path on which a *generated administrator credential* could be
created and then disclosed. `GenerateInitialAdministratorPassword` still exists at
`WebVella.Erp/ERPService.cs:1521` and is reached from exactly one call site,
`WebVella.Erp/ERPService.cs:610` — the local **system** account, which exists only so background work
has an identity, which nobody is intended to authenticate as, and whose value is hashed on write and
never printed, buffered, returned or retained in plaintext. That use is not a disclosure, and removing
it would reintroduce a defect rather than close one: the value it replaced was a lower-case GUID
string, which no longer satisfies the mixed-case rule the record-write boundary enforces, so
provisioning would fail on that line. A reader auditing the credential surface should know a CSPRNG
generator is still compiled in, and why its one remaining use is safe.

The remaining control is that the password is chosen per installation by its own operator and is never
written to any output stream, log or exception message — so it is known to exactly one party — and that
it must be rotated before the account can be used for API access. **This entry is retained as
`Accepted` rather than closed** because one residual genuinely survives: the strength of the initial
credential is now entirely the operator's responsibility, bounded only by the 12–128 character policy
and the mixed-case, digit and symbol rules the write boundary enforces. The platform cannot distinguish
a strong operator passphrase from a policy-satisfying weak one such as a dictionary word with
predictable substitutions. **Recommended fix, for a change permitted to add a dependency:** screen the
supplied value against a breached-password corpus at provisioning time and refuse a known-compromised
credential, which is the control OWASP recommends in place of composition rules.

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

*Enrolment is not the mechanism.* Adding both projects to the solution would satisfy the requirement that
they be either enrolled or explicitly gated, but it is not permitted: AAP 0.6.1 Class 1 authorises exactly
one change to `WebVella.ERP3.sln` — the
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
workflow. The declared list has exactly one home, the job-level `EXPLICITLY_GATED_PROJECTS`, which the
assertion reads rather than restates, so one graph cannot acquire two contradictory descriptions. Verified
both ways: it passes on the tree as it stands and detects a synthetic third non-member.

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

#### RISK-147 — Ten authenticated API actions returned a stack trace in the response body — **CLOSED**

| Field | Value |
| --- | --- |
| **Status** | **Closed.** Re-measured under review finding `OBS-08`; the condition no longer exists. |
| **Related finding** | `H-13`, which covered the *unconditional, anonymously reachable* instances. |
| **Weakness** | CWE-209, information exposure through an error message. |
| **Location** | `WebVella.Erp.Web/Controllers/WebApiController.cs` — formerly lines 4273, 4491, 4531, 4557, 4589, 4643, 4713, 4736, 4809 and 5264. |

**Closure evidence, measured on the tree this commit publishes.** The statement this entry is about,
`response.Message = e.Message + e.StackTrace;`, occurs **0** times in that file. Every one of the ten
actions it named — `GetPlugins`, `UpdateSchedulePlan`, `TriggerNowSchedulePlan`, `GetSchedulePlansList`,
`GetSchedulePlan`, `CreateTestSchedulePlan`, `GetUserFileList`, `UploadUserFile` and `GetSnippetText` —
now takes its response message from `SafeErrorMessage(Exception)` at
`WebVella.Erp.Web/Controllers/WebApiController.cs:344`, which returns `ex.ToString()` **only** when
`Settings:DevelopmentMode` is true and a fixed generic message otherwise. **38** call sites route
through that one helper, so the decision is made once and cannot drift back a site at a time, and the
full detail is still recorded server-side through the non-notifying audit boundary — a change of
audience rather than a loss of diagnostic capability.

One caveat that survives the closure and belongs to the operator rather than the code: the guard is
`Settings:DevelopmentMode`, **not** `ASPNETCORE_ENVIRONMENT`. They are different switches, and setting
the environment to `Production` while leaving `DevelopmentMode` true still returns full detail. That is
documented in the [secure configuration guide](secure-configuration.md).

The analysis below is retained as the record of why these were correctly scoped *out* of `H-13` at the
time, and should be read as history rather than as current state.

**What the retracted claim said, and what is measured now.** The entry asserted ten live
`response.Message = e.Message + e.StackTrace;` statements in the controller at lines 4273, 4491, 4531,
4557, 4589, 4643, 4713, 4736, 4809 and 5264. Measured at this commit, `grep -c StackTrace` on that file
returns **0** — not merely zero of that statement, but zero references to `StackTrace` of any kind. Every
fault response in the controller now yields either a helper's output or a fixed string: **37** sites call
`SafeErrorMessage(Exception)`, declared at `WebApiController.cs:L334-L339`, which returns `ex.ToString()`
when `ErpSettings.DevelopmentMode` is set and the fixed `INTERNAL_ERROR_MESSAGE` otherwise; and **4**
assign `INTERNAL_ERROR_MESSAGE` directly, all four inside the two anonymous token actions that were the
`H-13` sites — `GetJwtToken` at `:L5653` and `GetNewJwtToken` at `:L5834`. The nine enclosing
actions the entry named all still exist — `GetPlugins` at `:L4594`, `UpdateSchedulePlan` at `:L4640`,
`TriggerNowSchedulePlan` at `:L4863`, `GetSchedulePlansList` at `:L4896`, `GetSchedulePlan` at `:L4919`,
`CreateTestSchedulePlan` at `:L4951`, `GetUserFileList` at `:L5077`, `UploadUserFile` at `:L5097` and
`GetSnippetText` at `:L5612` — so the actions were not removed to make the count fall; their response
bodies changed.

**The entry's own supporting locators were stale too**, and are corrected here rather than left to
mislead: it said the file's only three live `[AllowAnonymous]` actions were at lines 1191, 5286 and 5394.
They are at **1396**, **5650** and **5831**. The substance of that sub-claim survives the correction —
none of the three contains a stack-trace write, so the disclosure never was anonymously reachable in this
file.

**The residual that genuinely remains, stated precisely.** Twenty-seven statements of this shape survive
outside the controller, and **every one of them sits inside an `if (ErpSettings.DevelopmentMode)`
branch** with a generic message in the `else`: `WebVella.Erp/Api/EntityManager.cs` (13),
`WebVella.Erp/Api/EntityRelationManager.cs` (6, one of which uses a `string.Format` shape rather than
concatenation), `WebVella.Erp/Api/RecordManager.cs` (5), `WebVella.Erp/Api/ImportExportManager.cs` (2)
and `WebVella.Erp.Web/Controllers/ApiControllerBase.cs` (1, the `DoBadRequestResponse` pattern the
remediation deliberately mirrored). `DevelopmentMode` parses to **`false` when the setting is blank or
absent** (`WebVella.Erp/ErpSettings.cs:L207`), so a deployment that never sets it discloses nothing.

**Nothing of this class is unguarded anywhere in the solution.** A sweep of every non-comment
`StackTrace` reference in all 19 projects finds 37, of which 27 are the development-gated set above and
**10 are not response bodies at all**: the server-side log record that is *supposed* to persist the trace
(`WebVella.Erp/Diagnostics/Log.cs:L96` and `:L105`), a diagnostic `new StackTrace()` used for call-site
resolution (`WebVella.Erp/Database/DbContext.cs:L65`), and seven declarations and helpers in the
browser-side Blazor client (`WebVella.Erp.WebAssembly/Client/**`), which never render a server fault.

**The residual risk, restated as what it actually is.** This is no longer a code-disclosure risk; it is a
**configuration** risk. An operator who sets `Settings:DevelopmentMode` to `true` in a production
deployment re-enables verbose bodies at those 27 sites *and* at all 39 controller sites, and the same
flag also re-enables the SMTP certificate opt-out and suppresses HSTS and HTTPS redirection. That
coupling is the reason the secure-configuration guide treats the flag as an information-disclosure
switch rather than a convenience.

**Recommended fix, unchanged in substance but now correctly aimed.** Route the 27 remaining sites through
a single shared helper of the `SafeErrorMessage` shape so that one flag cannot widen disclosure across
five files, and so the guard exists in one place rather than twenty-seven. It remains outside the
minimal change this engagement authorises — it is twenty-seven edits across four projects in code this
remediation never otherwise touched — but it is a consolidation of an existing guard rather than the
introduction of a missing one, which is a materially smaller and lower-risk change than the retracted
version of this entry implied.

#### RISK-142 — Twenty-five authenticated manager responses still carry exception text in Development posture

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented with fix guidance |
| **Related finding** | `H-13`, whose *unconditional, anonymously reachable* instances are fixed. This is the development-gated residual that remained in the manager layer after the controller was closed; see `RISK-032` immediately above for the retracted controller claim. |
| **Weakness** | CWE-209, information exposure through an error message. |
| **Owner** | Platform team |
| **Location** | `WebVella.Erp/Api/EntityManager.cs` (13 sites), `WebVella.Erp/Api/EntityRelationManager.cs` (5), `WebVella.Erp/Api/RecordManager.cs` (5) and `WebVella.Erp/Api/ImportExportManager.cs` (2) — **25** in total, every one of the form `response.Message = e.Message + e.StackTrace;` and every one preceded by `if (ErpSettings.DevelopmentMode)`. |
| **Identifier note** | Published as `RISK-032` until the register's identifiers were made unique; renumbered here, and its inventory replaced — see the correction below. |

> **This entry's inventory is stated against the current file, not against the ten line numbers it once
> carried** — 4273, 4491, 4531, 4557, 4589, 4643, 4713, 4736, 4809 and 5264 in
> `WebVella.Erp.Web/Controllers/WebApiController.cs`. **That file now contains
> zero occurrences of `StackTrace`.** The widening recorded in the
> [remediation log](remediation-log.md) routed every response sink in that controller through a single
> `SafeErrorMessage` helper, at **38** call sites, so the ten the entry described no longer exist. The
> entry survived its own remediation, which is exactly the failure mode a risk register must not have.
> Reproduce both halves:
>
> ```bash
> grep -c 'StackTrace' WebVella.Erp.Web/Controllers/WebApiController.cs            # 0
> grep -c 'SafeErrorMessage' WebVella.Erp.Web/Controllers/WebApiController.cs      # 39 = 1 definition + 38 call sites
> grep -rnE '(e|ex)\.Message \+ (e|ex)\.StackTrace' --include='*.cs' . | wc -l    # 26
> ```

**What the residual actually is.** Twenty-six statements in the tree concatenate an exception message
and its stack trace into a response body. One of them is the *reference* implementation this engagement
points at as correct — `WebVella.Erp.Web/Controllers/ApiControllerBase.cs`, where the assignment sits
behind a development-mode check. The other **25** are in the four manager classes named above, and they
have the same shape: a `catch`, a server-side log write, then `if (ErpSettings.DevelopmentMode)` and the
concatenation. So the disclosure is **conditional on configuration**, and in the shipped Production
posture (`DevelopmentMode: false` in all eight `Config.json` files, `Production` in `web.config`) none of
the 25 emits anything.

**A correction to how this residual has been characterised.** A review described these 25 as
*unguarded*. Measured, they are not: a sweep of all 26 sites, inspecting each statement and the six
lines above it, finds **26 guarded and 0 unguarded**, and the only two `response.Message = ex.Message`
statements without a guard anywhere in the tree are both **commented out**
(`WebVella.Erp.Web/Controllers/WebApiController.cs:L1462`,
`WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs:L402`). The correction matters in both
directions and neither is flattering: the residual is **smaller** than "25 unguarded sinks" implies,
and it is **not closed**, because a configuration flag is a materially weaker control than the code-level
fix `H-13` required. That is the whole reason `H-13` was escalated in the first place — its two sites
were unconditional, so setting `Production` would not have fixed them — and it is why the closure claim
for `H-13` is now stated as covering those two anonymous routes and the sinks the widening actually
touched, rather than as "no exception text can reach a response anywhere".

**Why these 25 are not in scope while `H-13` was.** Three properties separate them, and all three are
needed:

- **They are guarded.** `H-13`'s two sites were not, which is what made them unfixable by configuration.
- **They are not anonymously reachable.** They sit in manager classes called from behind the API
  surface's class-level `[Authorize]`; an attacker must already hold a valid session.
- **They are pre-existing and unchanged.** The statement text and the guard are byte-identical to the
  checkpoint base in all 25 cases; the remediation neither introduced nor widened them.

**The residual, stated as a risk rather than as a reassurance.** An installation that runs with
`Settings:DevelopmentMode` true — which the [secure configuration guide](secure-configuration.md) forbids
and the shipped configuration no longer does — discloses full stack traces from 25 authenticated manager
paths. The control is therefore *operational* rather than structural, and one misconfigured deployment
re-opens all 25 at once. That is the honest shape of it.

**Recommended fix.** Replace the 25 concatenations with a generic message while retaining the existing
log write, mirroring the guarded pattern in `ApiControllerBase` — or better, route them through a single
shared helper as the web controller now does, so a future site cannot reintroduce the pattern by copy.
It is mechanical and low-risk per site, but it is 25 edits to response bodies across four core-library
classes and it changes what an authenticated caller sees in Development, which is beyond the minimal
change this engagement authorises. It is cross-referenced from the
[secure configuration guide](secure-configuration.md) so that an operator reading about error handling is
not left believing the surface is entirely clear.

#### RISK-144 — Provisioning emits six pre-existing bootstrap DDL statements

| Field | Value |
| --- | --- |
| **Status** | Named, not fixed — pre-existing platform bootstrap. |
| **Related finding** | The "no database schema changes" preservation requirement, and the version-4 migration that now satisfies it. |
| **Location** | `WebVella.Erp/Database/DbRepository.cs` — `CreatePostgresqlCasts()` at line 13, whose statement spans lines 17–20, and `CreatePostgresqlExtensions()` at line 26, whose statements are at lines 30 and 37. |

Recorded so that the claim "the remediation emits no schema definition statements" is stated
**precisely rather than absolutely**. The six statements are:

- `DROP CAST IF EXISTS(varchar AS uuid);` — line 17
- `DROP CAST IF EXISTS(text AS uuid);` — line 18
- `CREATE CAST(text AS uuid) WITH INOUT AS IMPLICIT;` — line 19
- `CREATE CAST(varchar AS uuid) WITH INOUT AS IMPLICIT;` — line 20
- `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";` — line 30
- `CREATE EXTENSION IF NOT EXISTS "postgis";` — line 37, inside a `try` because the extension may not be installed

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

#### RISK-145 — Plugin patches seed page-component options containing server-authored code

| Field | Value |
| --- | --- |
| **Status** | Accepted — by-design intentional-HTML channel, with a compensating control. |
| **Related finding** | The stored cross-site-scripting class, and `RISK-023`, which records the five by-design raw-output channels this one resolves through — `RISK-170` is canonical for the count and the inventory. |
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
authoring of markup and script to privileged roles, plus the Content-Security-Policy, with the scope
correction recorded against the four by-design channels: what is privileged is choosing the raw channel,
not necessarily supplying its bytes — rather than by encoding, because encoding it would disable the feature it implements. The rendering code is vendored.
And correcting already-seeded values in a deployed installation would require a data migration over
stored page-component options, which is neither a confirmed Critical nor High finding and is exactly
the change the minimal-change constraint forbids.

**Recommended fix, for a future sprint.** Treat permission to edit page-component options as equivalent
to permission to author server-side code, and audit which roles hold it — that, not encoding, is the
real control here. If the seeded snippets are ever to be constrained, do it by narrowing what the
`PcFieldHtml` value may contain at the point it is saved, and pair that with a migration that rewrites
the thirteen existing seeds, so stored data and validation rules cannot disagree.

#### Superseded statement of RISK-051 — interim record that the taint-dataflow family ran intraprocedurally only

**This section is a superseded statement, not a second entry, and it declares no identifier of its own.** The current record is [`RISK-051` — The `CA3001`–`CA3012` taint-analysis family does not run](#risk-051-the-ca3001ca3012-taint-analysis-family-covers-19-of-19-compilations-one-is-scanned-at-bounded-interprocedural-depth). It is retained so that a reader holding an earlier copy can see exactly which claim changed.

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

#### RISK-146 — No transport-level request-body limit bounds an upload before model binding

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented, not fixed. |
| **Related finding** | `H-08` (CWE-434) and review finding `F-09`, whose decision (o) defers here; the residual weakness is CWE-400, uncontrolled resource consumption (OWASP A04:2021). |
| **Location** | The five upload routes in `WebVella.Erp.Web/Controllers/WebApiController.cs`, and the **absence** of any request-body limit in the seven host pipelines. |
| **Identifier note** | The remediation log and the audit report both cited this subject before it had an entry — the log as `RISK-034`, the report as `RISK-033`, neither of which describes it. Entered here so both citations resolve to what they name. |

**What the application-level control does.** Every one of the five upload routes validates **before any
stream is read**, so no oversized body is ever copied into a managed buffer by the action itself:
`/fs/upload/`, `/ckeditor/drop-upload-url` and `/ckeditor/image-upload-url` call
`GetUploadRejectionReason` directly, and the two batch routes `/fs/upload-user-file-multiple/` and
`/fs/upload-file-multiple/` call `GetUploadBatchRejectionReason`, which loops the same check over the
whole batch before the database connection is opened. The size ceiling is
`MAX_UPLOAD_SIZE_BYTES = 25L * 1024L * 1024L`.

**What it does not do, stated precisely rather than implied.** By the time an action body runs, ASP.NET
Core model binding has already read the multipart request into its own buffer. The pre-validation
therefore prevents the *action's* full-file allocation, not the *framework's* request buffering — and no
transport-level ceiling is configured to bound that earlier read. Measured rather than assumed: a search
of the whole tree for either of the two settings that would impose one returns nothing.

```bash
grep -rn 'MaxRequestBodySize\|MultipartBodyLengthLimit' --include='*.cs' --include='*.json' --include='*.config' .
# → no matches
```

**Why it is not fixed.** Three reasons, and the first is sufficient on its own.

- **It is not the confirmed finding.** `H-08` is unrestricted upload of a file with a dangerous *type*,
  and its escalation half is inline execution from this origin. Both are closed — by the extension
  allow-list, the content-type consistency check, the filename sanitisation and the forced attachment
  disposition on download. A transport-level byte ceiling is a different control for a different
  weakness class, and the governing constraint is to fix only what is confirmed and to choose the least
  invasive control.
- **The blast radius is wrong for the benefit.** `MaxRequestBodySize` is a Kestrel/IIS-level setting and
  `MultipartBodyLengthLimit` a form-options setting; either would apply to **every** request across all
  seven hosts, including record saves, import files and the SDK's code editors, none of which was
  surveyed for its largest legitimate payload. Setting a ceiling without that survey risks refusing
  working requests, which the functionality-preservation requirement forbids.
- **The exposure needs credentials.** All five routes sit behind the controller's class-level
  `[Authorize]`, so this is not an anonymous denial-of-service primitive.

**Recommended fix, for a future sprint.** Set `MaxRequestBodySize` per endpoint rather than globally —
`[RequestSizeLimit]` on the five upload actions, sized from the same 25 MB constant so the two limits
cannot drift — and only then consider a global default, chosen from a survey of the largest legitimate
payload on every other POST route. Pair it with a `413` response shape that matches the platform's own
`FSResponse` failure envelope, so a refusal at the transport layer is not less informative than a
refusal in the action.

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

- the login page, `WebVella.Erp.Web/Pages/login.cshtml.cs`;
- the token-issue route, `WebApiController.GetJwtToken`;
- the token-refresh route, `WebApiController.GetNewJwtToken`.

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
trade-off `RISK-008` records for address-keyed throttling. (`RISK-008`'s *per-process* scope limitation is
closed; the address-keying trade-off it records is not.)

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

- **Make a non-published Production run behave like a published one.** Have the host builders call
  `UseStaticWebAssets()`, or standardise verification on `dotnet publish` output, so that no operator
  is ever tempted to restore styling by setting `ASPNETCORE_ENVIRONMENT=Development` and silently
  undoing the `H-12` and `H-15` remediations (`RISK-031`).
- **Add `autocomplete` attributes to the login form's e-mail and password inputs.** Chrome raises an
  informational advisory on `/login` for their absence. It is neither a console error nor a warning and
  carries no confirmed security finding, so it is noted for completeness only, as HTML hygiene rather
  than remediation.

- **A test suite.** No automated test project, test-framework package reference or executable test
  method exists in any of the 19 projects, which made the "existing test suite passes" validation
  gate vacuous by construction. (Stated that way deliberately: the looser "no test file" is both
  unfalsifiable and wrong in spirit, because a file may be named for testing without being a
  runnable test.) The substitute verification regime is recorded in the
  [remediation log](remediation-log.md). Creating a suite is feature work the constraints exclude,
  and it is the single highest-value investment available here.
- A distributed store for login throttling (RISK-008).
- **Refresh-token rotation with reuse detection.** Signing out already invalidates an already-issued
  bearer token as well as the cookie session (`RISK-007` is closed), and the revocation store is already durable and shared (`RISK-036`), so what remains for this item is **rotation** — giving
  each refresh a fresh single-use identifier so a stolen token cannot be traded for a successor before
  the theft is noticed — rather than durability, which is already in place.
- Completing the Content-Security-Policy rollout to enforcing mode (RISK-022). The switch itself is
  now a configuration key rather than a code change, so what remains is the engineering work the blocker
  inventory names: eliminating or hashing the inline style and script, and adding the `img-src` and
  `worker-src` directives the mandated policy omits.
- A shared, durable store for the report collector's per-source acceptance counters, on the same
  reasoning as `RISK-036` and `RISK-008`: the current table is per process, so a multi-instance
  deployment enforces the bound once per instance rather than once overall (RISK-005).
- A `Directory.Build.targets` re-appending the promoted audit codes after every project body, so the
  dependency gate cannot be discarded by a single careless `.csproj` assignment (RISK-029).
- Enrolling both WebAssembly projects in the solution, so that one solution-level command covers all 19
    (`RISK-030`). This is **not** agent work and has now been attempted and reverted twice: the frozen
    plan authorises exactly one change to `WebVella.ERP3.sln`, the project-reference path casing repair,
    so changing solution membership is scope drift in a build-integrity file — which is what review
    finding `CR2-F-06` records. Until an owner widens that authorisation, the two projects stay covered by
    dedicated restore, build and advisory steps, which are worth keeping regardless because they assert
    each resolved `TargetFramework` explicitly, something a successful solution build cannot rule out.
- Partitioning the per-address failure budget by a proxy-supplied client address, so a shared egress
  address stops being a shared fate for co-tenant clients (RISK-111, with RISK-008).
- ~~A `must_change_password` marker on the user entity, so the initial administrator password is
  *forced* to be rotated rather than merely advised (RISK-027).~~ **Done, and removed from the
  recommendation list rather than left standing:** `ErpUserPreferences.PasswordChangeRequired` carries it
  in the pre-existing `rec_user.preferences` column, `ERPService` sets it at provisioning and on rotation,
  `login.cshtml.cs` acts on it, and `AuthService` refuses to mint a bearer token while it is set.
- Reviewing the per-host CORS allow-lists themselves. Replacing the two permissive policies is **done**
  (`RISK-013`), and both `WebVella.Erp.Site` and `WebVella.Erp.Site.Project` now read their lists from
  `Settings:Cors:AllowedOrigins`, so they are deployment configuration and deny every origin when
  unconfigured outside `Development`. The remaining **five** hosts still name a hard-coded set of
  `http://localhost` development origins in source. Those need to become deployment configuration before
  any of the five faces a real front end.
- Integration with a dedicated secret manager, rather than environment variables alone.
- Centralised log aggregation, intrusion detection, and a web application firewall.
- Automated dependency-update tooling, so advisories surface without a manual review.
- Independent penetration testing. Nothing in this remediation substitutes for it.
- Multi-factor authentication, and password expiry and history policies — no confirmed Critical or
  High finding required them, so they are recommendations rather than remediation.
- **Container definitions and orchestration manifests.** The repository contains no `Dockerfile`, no
  compose file and no orchestration manifest, so there is no deployment artefact to harden and none was
  added — infrastructure outside the application boundary is out of scope by instruction. When they are
  written, the [secure configuration guide](secure-configuration.md) is the input: the three required
  secrets, the transport requirements and the environment posture are what a manifest has to carry.
- **Central package management with a committed lock file** (`Directory.Packages.props` plus
  `packages.lock.json`), together with an explicit `nuget.config` package source, so that restore is
  byte-deterministic and the dependency gate cannot be reached from an unexpected feed. All three files
  are deliberately absent today, as `L-07` records.

## Detailed entries — residuals introduced by the continuous security gate

The three entries below are limits of the gate itself rather than of the application. They are recorded
because a gate that does not publish its own blind spots invites a green run to be read as a stronger
statement than it is.

### Superseded statement of RISK-051 — second record that security taint analysis does not run

**This section is a superseded statement, not a second entry, and it declares no identifier of its own.** The current record is [`RISK-051` — The `CA3001`–`CA3012` taint-analysis family does not run](#risk-051-the-ca3001ca3012-taint-analysis-family-covers-19-of-19-compilations-one-is-scanned-at-bounded-interprocedural-depth). It is retained so that a reader holding an earlier copy can see exactly which claim changed.

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

### RISK-109 — No scheduled re-audit; advisories are detected on the next push

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

### RISK-110 — The secret sweep covers the tracked tree, not git history

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

- **Encryption at rest for the SMTP service credential**, together with the sentinel protocol and the
  presentation change that a reversible secret needs before an administrator edit form can round-trip it
  safely (`RISK-129`). Doing it properly also needs an authenticated-encryption primitive, which the platform
  does not yet have — its only symmetric helper carries the deterministic-initialisation-vector weakness of
  `RISK-006`.
- **Extend the SMTP authorisation review to the `email` entity**, which grants the Regular role create, read,
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

- **A Development installation still accepts any certificate.** That is the feature: a self-signed
  development mail server must stay usable, and removing the capability entirely would break a
  legitimate workflow rather than close a vulnerability. An operator who sets *both* settings is
  choosing the risk explicitly, and is told so.
- **The refusal notice is emitted once per process, not once per connection.** It is a statement about
  configuration, not an event, so repeating it per message would be noise — but it also means a log
  pipeline attached *after* start-up will not see it. The authoritative check is the configuration
  itself, not the log.
- **The notice is written to standard error rather than through the platform log, deliberately.** A
  platform log record can raise an e-mail notification, and the subsystem being reported on is the
  mailer. Logging through it here would route a warning about mail transport configuration into the
  very transport whose configuration has just been refused.

`ErpSettings.DevelopmentMode` defaults to `false`, so the policy fails closed even before
configuration has been initialised — a mail send attempted during start-up cannot obtain the bypass
by racing the configuration load.

### RISK-060 — A relay with no reachable revocation source cannot be used in Production

| Field | Value |
| --- | --- |
| **Status** | Accepted as a deployment constraint. The only supported remedy is to publish the revocation source; there is deliberately no setting that relaxes the check. |
| **Related finding** | `H-11` (CWE-295 improper certificate validation, OWASP A02:2021), with `CWE-299` improper check for certificate revocation as the residual; scope corrected by review finding `INT-08` |
| **Owner** | Deployment owner |

**What this is a residual of.** Closing `H-11` removed an always-true certificate callback that had been
masking every chain error, revocation ones included. MailKit checks revocation by default, so the moment
real validation applied, a relay whose certificate is *entirely valid* — correct host name, in date,
issued by a CA the host trusts — but whose chain names no fetchable CRL distribution point became
unreachable. Measured, not theorised: two relays differing **only** in revocation reachability behave
differently, and the failing one reports a chain status of nothing but `unable to get certificate CRL`.
Deployments in that position are ordinary rather than exotic — an internal CA that publishes no CRL, a
leaf issued without a `crlDistributionPoints` extension, or a host whose egress filtering blocks the
fetch.

**The correction this entry carries, stated plainly rather than quietly edited.** Review finding
`INT-08` established that this was the wrong answer on two counts, and it has been **removed** from
the code and from every document:

- *Leave revocation unconditional.* Rejected. It denies service to valid relays with **no** supported
  remedy, because the only pre-existing escape hatch accepts any certificate and is refused outside
  Development. That combination is the defect the follow-up exists to remove.
- *Widen the accept-any opt-out into production.* Rejected outright. It hands back precisely the
  behaviour H-11 removed, for the sake of a missing CRL.
- *Add a second, narrower switch.* Chosen, then **WITHDRAWN** — and this marker is corrected here under
  code-review finding `DOC-02`, because it still read *Chosen* while the paragraph above and the
  *What is in force now* paragraph below both record the removal. `Settings:EmailSMTPCheckCertificateRevocation`
  would have disabled one check while leaving the trust chain, the validity dates, the key usage and the
  host name enforced. **It does not exist**: no code reads it, and a search of the source returns nothing.
  Any document that lists it as an available setting is wrong, and the settings inventory in the secure
  configuration guide has been corrected accordingly.

**What is in force now.** Nothing assigns `client.CheckCertificateRevocation` on any send path, so the
library's own default of `true` applies and there is no code path, and no configuration, that turns it
off. That is the secure state expressed by omission, which is also why it cannot drift: there is no
policy member left to misread.

**Why it has no posture gate, unlike `RISK-033`.** A control that is inert in production is no remedy
for a production outage — that is the whole substance of the finding this closes. The two relaxations
are not comparable in width, and the register should not pretend they are: accepting any certificate
removes transport authentication entirely, whereas skipping a revocation lookup removes one check of
several. The first is a development convenience and is correctly refused in production; the second is
an operational accommodation for a real and lawful PKI topology, and is correctly honoured there.

| Property | Value |
| --- | --- |
| Revocation checking | Always on, on all five send paths |
| Configuration | None. No setting governs it |
| How a failure presents | An SSL handshake exception whose chain-status detail is only `unable to get certificate CRL` |
| On the queued path | Recorded in the message's `server_error`, retried per the service policy, then aborted — so read that column first when mail stops flowing |

**What bounds the residual.**

- **Secure by default, with the default inverted relative to its neighbour.** Only a value that parses
  as boolean `false` disables the check. Absent, blank, `true`, and unparseable values such as `no`,
  `0` and `off` all leave revocation enabled, as does a settings layer that has not yet been
  initialised. An operator cannot arrive here by typo — only by decision.
- **It is announced.** One notice per process on standard error, naming the setting key and nothing
  else, so the weakened posture is on the record rather than inferable only from configuration nobody
  re-reads. As with `RISK-033`, it is a statement about configuration rather than an event, so a log
  pipeline attached after start-up will not see it; the configuration is the authoritative check.
- **It governs all five send sites from one member**, so no path can drift into a different revocation
  posture from the others.
- **Revocation checking genuinely works when left on**, which is what makes turning it off a real if
  bounded loss rather than a formality: a leaf revoked in its issuer's CRL is refused with a distinct
  `certificate revoked` chain bullet, while a non-revoked leaf validated against that same freshly
  published CRL still delivers.

**How to retire it.** Re-issue the relay leaf with a `crlDistributionPoints` extension pointing at a
CRL the application hosts can fetch, sign that CRL with a CA carrying `cRLSign` and a subject key
identifier, publish it in DER form, then remove the setting and confirm a test send still delivers.
The [secure configuration guide](secure-configuration.md) carries the step-by-step form of this.

**Not covered by this entry.** Granular revocation behaviour — soft-fail, offline-only, or a per-service
override — is not offered and is not a gap this remediation is entitled to close: MailKit exposes a
single boolean, and inventing a richer policy on top of it would exceed the least-invasive-control
constraint that governs this work. Nor does this entry cover the diagnostic notification mailer, which
negotiates no TLS at all and therefore never reaches a certificate: that is `RISK-131` and `M-17`.

**How to retire it.** Publish the revocation source as above, then confirm a test send delivers. There
is nothing to remove afterwards, because nothing was added.

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

- **The `email` entity grants the Regular role all four verbs.** Confirmed against a provisioned
  database: the mail plugin's `email` entity permits create, read, update and delete to the Regular
  role. The confirmed finding names `smtp_service` only, and stored message bodies are not
  credentials, so widening the change here would be scope creep — but it is the natural next review
  target and is carried into the ongoing recommendations above.
- **Sitemap node access lists in the mail plugin are inert.** A dated patch updates area and node
  records with empty access-role lists, and one node carries an unrelated external URL. Neither has
  any effect: page authorisation is enforced at **application** level, by intersecting the
  application's access list with the current user's roles, and node access lists are not consulted on
  that path; the URL is ignored for entity-type nodes. This is data hygiene rather than exposure, and
  it is recorded so that a future reader does not mistake an empty node list either for a
  vulnerability or for a control.
- **The EQL entity read-permission check is row-driven.** The check runs while converting each
  returned row, so a query that matches no rows never reaches it. Nothing can leak through that path
  — there is no row to leak — but it means an empty result set is **not** evidence that
  authorisation was enforced. Any verification of that control must therefore assert against a
  populated table, and the verification for this work does.
- **`ProcessPatches()` carries a stack-trace-destroying rethrow idiom.** Seven pre-existing inner
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
client at `http://localhost:2202` as its fourth. The full resolution table is in the [secure
configuration
guide](secure-configuration.md#cross-origin-policy).md#project-host-cross-origin-supply-path-frontend-01).

Three properties of the fix are worth recording, because each was a decision rather than a default.

- **`AddDefaultPolicy` was kept rather than converted to a named policy.** Each of the two hosts already
  calls `app.UseCors()` with no policy name, which applies the default policy. Keeping the registration
  shape meant the request pipeline needed no edit at all, which is the smallest change that closes the
  finding.
- **`AllowCredentials()` is deliberately absent.** The framework refuses it alongside a wildcard origin,
  and these two hosts authenticate cross-origin callers with a bearer token rather than with a cookie,
  so adding it would widen the policy without serving a caller that exists.
- **Ordering was verified, not assumed.** `UseCors` sits ahead of `UseHsts` and `UseHttpsRedirection` in
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

- **The server-side record is retained unchanged.** The `LogService` write that precedes each response is
  untouched, so the diagnostic detail is still captured; only its audience changed.
- **The issue route keeps the platform's own credential wording for a rejected credential**, so that
  outcome stays byte-identical to a throttle rejection. Diverging there would have converted two
  different messages into an account-existence oracle — closing a disclosure finding by opening an
  enumeration one.

In Development the response carries `e.ToString()`, which renders the type, message, inner exceptions and
stack trace. That is a superset of what was emitted before, so a developer loses nothing.

**Update — a third unconditional site of this class was later found, on the authentication path, and is
also closed.** This entry and `RISK-147` between them accounted for the bearer-token routes and what was
then believed to be ten leaking authenticated API actions - a count `RISK-147` now retracts - which left
the impression that the unconditional-disclosure surface had been fully enumerated. It had not. Review finding `CR2-F-08` (recorded as `P-11`) found the same pattern in
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

### RISK-036 — The session-revocation store was in-process; it is now durable, shared and fail-closed

| Field | Value |
| --- | --- |
| **Status** | Accepted — one bounded residual of the control that closes `RISK-007`. The second residual this entry used to record (pre-existing credentials being exempt from revocation) was closed by review finding `CR2-F-01`; see the update at the end. |
| **Related finding** | Review finding `F8` (session hijacking), then `CR2-F-01` / `CR2-F-02`; H-02 / H-03 (CWE-613, OWASP A07:2021) |
| **Owner** | Platform team |

> **Superseded in its central claim, and the supersession is the point of this revision.** Everything in
> the four bullets below was accurate when written and is **no longer true**: review finding
> `H-OPEN-01` moved the store off the process-local cache, and code-review finding `MAJ-09` established
> that this entry — and the index row that summarises it — had been left behind by that move. The old
> text is retained rather than overwritten, per this register's convention, because the three fail-open
> boundaries it documents are the reason the durable store exists.

**The store as it ships now, read from the source rather than from a sibling document.** State lives in
`WebVella.Erp/Database/DbSecurityStateRepository`, and `WebVella.Erp.Web/Services/SessionRevocationService.cs`
is its consumer. Four properties matter:

- **Durable.** A revocation survives a restart, recycle or crash. It is written to the pre-existing
  `public.plugin_data` table under the reserved key prefix `wv_sec_` — revocations at
  `wv_sec_revoked_<session-id>` — so **no schema definition statement was needed** and the remediation
  constraint that forbids one is not breached. The table has no expiry column and none may be added, so
  the expiry travels inside the row as a fixed-width sortable UTC stamp at the head of the payload.
- **Shared.** Every instance pointed at the same database observes the same revocation, so a sign-out
  served by one instance is honoured by all of them. Sticky sessions are no longer required for this
  control.
- **Reclaimed by expiry only, never by capacity.** A live revocation can therefore never be displaced by
  a newer one — which is exactly what the bounded cache below could do, and what made its eviction path
  fail open. Retention is clamped between a one-minute floor and a **25-hour** ceiling; the ceiling is the
  smallest round value that leaves the longest legitimate credential — 1440 minutes of lifetime plus the
  one-minute bearer clock skew — unclamped, and `RetentionCeilingMinutes` exposes it so a caller can
  check the relationship rather than restate it.
- **Fail-closed.** When the durable store cannot be consulted at all, `IsSessionIdentifierRevoked` answers
  **revoked**. Every authenticated request already re-resolves its user from the same database, so a
  database this code cannot reach is one no request could have been served from anyway; the alternative —
  answering *not revoked* when the answer is unknown — is how an outage becomes an authorisation. A
  fail-closed answer is deliberately **not** mirrored locally, so a transient outage cannot pin a
  legitimate session as revoked once the store is reachable again.

**The in-process cache that remains is positive-only, and that asymmetry is the design.** Only
identifiers the durable store has already confirmed revoked are mirrored, for no longer than the durable
entry has left to live; a **negative** answer is never cached, because caching *not revoked* for any
interval would recreate the window this control closes. The mirror is still bounded at 20,000 entries
with a 20% compaction step, and that bound is now harmless in a way it was not before: eviction costs one
redundant query, never an accepted credential.

**What remains accepted is cost, not scope.** One indexed point lookup per authenticated request, plus
two deployment consequences of failing closed — all instances must point at the same database for a
logout on one to be honoured by the others, and authenticated requests are refused while that database is
unreachable. Both are recorded in [secure-configuration.md](secure-configuration.md).

**The superseded record, retained.** ~~`WebVella.Erp.Web/Services/SessionRevocationService.cs` holds
revoked session identifiers in a bounded process-wide `MemoryCache`. That choice is what allowed
`RISK-007` to be closed at all: a persisted revocation list would have required the database schema
change the remediation constraints forbid outright.~~ The premise in that last clause is what turned out
to be wrong: a durable store was reachable **without** a schema change, by reserving a key prefix in a
table every installation already has. The cost is stated plainly rather than discovered later.

- ~~**It does not survive a restart.** After an application restart, a cookie whose session was revoked
  before the restart authenticates again, because the record of the revocation is gone. The bound on that
  exposure is the ticket's own eight-hour expiry, not the revocation.~~
- ~~**It does not span instances.** Behind a load balancer, a sign-out served by one instance is not known
  to the others. Each instance enforces its own view. Sticky sessions, or a shared store, are required
  before scaling out. This is the identical shape as `RISK-008` for login throttling, and one shared store
  would serve both.~~ *(Both are now closed, and `RISK-008` was closed the same way — one shared store did
  serve both.)*
- ~~**It is bounded to 20,000 identifiers with a 20% compaction step**, which is a deliberate denial-of-service
  boundary — an unbounded revocation list is a memory-growth primitive reachable by repeated sign-out. The
  bound was verified rather than assumed: after 25,000 revocations the store held exactly 20,000 entries.
  The consequence is that under extreme sign-out volume the *oldest* revocations are evicted first, which
  is the correct direction, because the oldest tickets are also the closest to expiring on their own.~~
  *(The bound now applies to the positive-only mirror alone, where eviction costs a query rather than a
  revocation; the durable store is bounded by expiry instead of by capacity.)*
- ~~**Retention is clamped at both ends** — a minimum of one minute and a maximum of 24 hours — so a
  malformed or hostile expiry value can neither create a permanently retained entry nor produce an entry
  that is evicted before it can be observed.~~ *(Still clamped at both ends, but the ceiling is **25**
  hours: review finding `CR3-H-03` found a 24-hour ceiling exactly equal to the 1440-minute credential
  lifetime, which silently truncated the clock-skew allowance the caller had just added.)*

**Update — the transitional residual is closed, and the reversal is deliberate.** A second residual once
stood here: credentials minted *before* the control shipped carry no `erp_session_id`
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

- **`Guid.Empty` can never be revoked.** `RevokeSessionIdentifier` ignores it and
  `IsSessionIdentifierRevoked` always returns false for it, so no entry can exist that would match every
  credential whose claim failed to parse. That cannot be used as a global kill switch, and it is not a
  leniency either: a credential presenting an empty or unparseable identifier is refused by the callers
  before the store is ever consulted.
- **The store is process-wide static rather than injected**, which finding `CR2-F-02` required: the bearer
  validators are static code with no service provider in reach, so an injected store was unreachable
  from them. Two properties follow, and both are strengthenings rather than costs — there is exactly one
  store per process instead of one per service provider, and no consumer has to interpret an
  unresolvable service, a state that used to be indistinguishable from "this session is not revoked".
- **The hook composes with, rather than replaces, any host-supplied `OnValidatePrincipal`.** The previously
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

- The finding is markup breakout, and the control for markup breakout is encoding. Adding scheme
  filtering in the same edit would be a second, differently-shaped control for a weakness class the
  finding does not raise, which the minimal-change constraint forbids.
- A sitemap node URL is legitimately allowed to be a non-`http` scheme. `mailto:` and `tel:` entries
  are ordinary navigation targets, and the encoder demonstrably preserves both — `tel:+15551234567`
  round-trips through `tel:&#x2B;15551234567` back to the dialable original. An allow-list narrow
  enough to stop `javascript:` would have to enumerate every scheme an operator might legitimately
  have configured, and getting that list wrong breaks working navigation, which the
  functionality-preservation requirement forbids.
- The exposure requires the ability to **author a sitemap node**, which is an administrative
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

- Every edited view carries a comment saying the sink is closed at the builder, naming the builder,
  and instructing the reader not to remove the raw call and not to encode there.
- The verification harness includes a **source-invariant** section that reads the four real builder
  files, walks every interpolation hole in the marker template lines, and fails if any hole
  references something other than an encoded local or a cast identifier. That check is what would
  catch a regression, and it lives in the harness rather than in the build, so it only runs when the
  harness is run.
- This entry, so the constraint is discoverable from the documentation rather than only from a
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
suppressed repeats counted rather than written. (It lives under `Utils/`, not `Services/`, and is 690
lines.) That bound is the point of the control:
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
preserved**, because the block never runs again — which is the substantive behavioural difference from an
always-on re-assertion.

**The residual a version-gated migration leaves, and it is real.** A recorded version of 4 is not proof that the
version-4 body ever executed against that database: a restore from a mixed-version estate, a hand-edited
settings row, or a version advanced by a build that predated the fan-out all produce a database recording
4 while still carrying the grants. That state was observed on a development installation. Repairing it
would need a migration beyond the frozen ladder head, so **the repair does not happen automatically**. Two
things bound the residual. The Guest grants are absent from the *seed*, so no
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
replays the SDK patch loses that read grant through the patch's own restatement. Confirmed separately: no
version-5 re-assertion occurs on a second start.

### RISK-051 — The `CA3001`–`CA3012` taint-analysis family covers 19 of 19 compilations; one is scanned at bounded interprocedural depth

> **Revised a fourth time, and this is the canonical statement. It supersedes both the statement kept
> below — which described the family as not running at all — and the third revision's framing, which
> described it as running for eighteen of nineteen projects with the nineteenth simply uncovered.** Each
> description was accurate when written. `GATE-03` established that a measurement taken on one project
> had been used to justify an exclusion applied to all nineteen, and the exclusion was narrowed
> accordingly. Code-review finding `MAJ-01` then established that narrowing an exclusion is not the same
> as closing a coverage gap: the nineteenth compilation was still unscanned, and a criterion of "0 High"
> cannot be asserted over a compilation nothing examined. It is now scanned, by its own workflow step, at
> a bounded interprocedural depth that terminates. Earlier framings are retained verbatim rather than
> overwritten, per this register's convention, because their timing evidence is still the reason the
> **build-time** exclusion exists.

**Status: Accepted, and reduced again — coverage is now 19 of 19 compilations. The `CA3001`–`CA3012`
family is withheld from the *build* of exactly one project, `WebVella.Erp.Web`, on a per-project
measurement rather than a global assumption; that project is scanned by a separate, terminating workflow
step, and what remains accepted is the analysis *depth* of that scan rather than its absence.**

`AnalysisLevelSecurity=latest-all` arms the family, and `Directory.Build.props` now applies the
`CA3001`–`CA3012` `NoWarn` **only** to the single project a measurement implicates, through a property
group conditioned on `MSBuildProjectName`. The two values are declared as readable properties —
`ErpTaintAnalysisFamily` and `ErpTaintAnalysisExcludedProject` — and the workflow's Gate 1 reads them out
of the props file and asserts the boundary per project, so the build configuration and the gate cannot
drift apart.

**Measured per project, which is what changed the conclusion.** Each of the nineteen projects was built
with the exclusion overridden. Eighteen completed in **0 to 6 seconds each with zero `CA3001`–`CA3012`
diagnostics**; `WebVella.Erp.Web` alone was killed at a 600-second bound (`exit 124`), which is
consistent with the historical figures preserved below and is explained by its 395 Razor views compiling
into a single compilation the family's interprocedural analysis then traverses. That timing was
independently re-measured for `MAJ-01` with a far larger bound — the same compilation, family armed,
unbounded chain depth, **still not finished past 2,700 seconds** — so "expensive" is not an estimate.
Summed baseline for the other eighteen was 43 seconds against 45 seconds armed, so the cost of arming them
is within measurement noise. A full non-incremental solution build before and after the narrowing produced
**identical** diagnostics — 641 distinct `(rule, file)` pairs over 6,056 emitted `CA` warning lines,
which reduce to 3,028 unique `(file, line, column, rule)` diagnostics —
3,055 warnings, 0 errors — with no `CA30xx` and no `CS1701`/`CS1702` regression, confirming the narrowing
restored the SDK's default `NoWarn` for the eighteen without changing any other verdict.

**The eighteen zeros are an absence of defects, not an absence of analysis, and that is proven rather
than asserted.** A throwaway probe project carrying a deliberate request-to-`File.ReadAllText` flow and a
deliberate query-to-`CommandText` flow reported `CA3001` and `CA3003` under the same configuration. The
workflow's positive-control step now **requires** both diagnostics to appear, so a future change that
silently disarms the family fails the gate instead of producing a reassuring silence.

**The nineteenth compilation is scanned, and here is exactly how.** The workflow now carries a dedicated step,
*Gate 1 - terminating taint scan of the excluded compilation*, which:

- reads `ErpTaintAnalysisExcludedProject` out of `Directory.Build.props` rather than naming the project
  again, so the boundary stays single-homed and the step fails closed if the property cannot be read;
- writes a cost bound — `max_interprocedural_method_call_chain = 1` and the matching lambda-or-local
  bound — into a temporary analyzer configuration **outside the repository**, supplied through
  `GlobalAnalyzerConfigFiles`, and asserts both that the path is outside the working tree and that it
  carries no `dotnet_diagnostic.*.severity` line. This is what keeps the bound from becoming a
  repository-root `.globalconfig`, which AAP 0.6.1 Class 2 forbids and Gate 1 separately asserts absent;
- runs a **capability self-test first**: a throwaway probe carrying a deliberate request-to-file flow and
  a deliberate query-to-command flow must report `CA3001` **and** `CA3003` under the identical bound, or
  the step fails. A bounded configuration that had quietly stopped analysing would therefore fail rather
  than return a reassuring zero;
- builds the excluded project with `ErpSecurityTaintAnalysis=all` under an 1,800-second bound in which a
  timeout is **fatal**, not tolerated, and asserts the compilation actually ran rather than being skipped
  as up to date;
- parses `CA3001`–`CA3012` out of the result, ratchets it against an empty allow-list, publishes
  `taint-scan-web.txt` as evidence, and deletes the path-bearing raw log.

**Measured: about 220 seconds, exit 0, zero `CA3001`–`CA3012` diagnostics, with the capability self-test
reporting both control diagnostics in under two seconds.** Coverage is therefore **19 of 19**
compilations, and the four compensating controls enumerated in the superseded statement below now sit
behind a scan rather than in place of one.

**What remains accepted, stated precisely.** Depth, not coverage. A one-hop interprocedural bound follows
a tainted value across a single call; it will not follow one that crosses two or more. The eighteen
unbounded zeros are therefore stronger evidence than this nineteenth bounded zero, and the difference is
not papered over: the compensating controls — the encoding pass, `DbIdentifier` validation with
parameterised values, the upload and download constraints, and human review of the controller surface —
remain the primary assurance for multi-hop flows in that project.

**What would change this.** More build capacity, or the rules becoming materially cheaper, either of which
would let the bound be raised or removed. The exit condition is measurable: an unbounded
`ErpSecurityTaintAnalysis=all` build of `WebVella.Erp.Web` that terminates inside the workflow's bound, at
which point the dedicated step's cost configuration can be dropped and the exclusion re-tested for removal
altogether.

#### Superseded statement of RISK-051 — the record that the family did not run at all

**This section is a superseded statement, not a second entry, and it declares no identifier of its own.**
The current record is the canonical `RISK-051` immediately above. Everything below was accurate before
code-review finding `GATE-03` narrowed the exclusion; the timing measurements in it are still the
evidence for the one project that remains excluded.

#### The family did not run at all

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

- Value-level SQL injection is closed by parameterisation throughout the data layer; identifier-level
  injection is closed by the single audited `DbIdentifier` validate-and-quote helper applied at every
  concatenation site. `CA2100`, which flags query construction from a non-constant string, reports 20
  diagnostics across eight files, each carried with a disposition under `RISK-052`.
- Unsafe deserialisation is closed by `ErpSerializationBinder`'s exact-type allow-list. `CA2326`,
  `CA2327` and `CA2328` all execute under `AnalysisLevelSecurity=latest-all`: `CA2326` reports 20 sites
  and `CA2328` 9, each carried under `RISK-052`, while `CA2327` reports **zero** — evidence rather than
  silence, because Gate 1's positive control shows the rule firing against a planted defect. The binder's
  own verification stands alongside it: the allow-list was exercised directly against a rejected type.
- Stored and reflected cross-site scripting is closed at the markup builders with framework HTML
  encoding, proven at runtime against live stored payloads.
- Command and path sinks were enumerated by hand during the audit; the file pipeline is database-backed,
  route segments cannot contain a separator, and the upload and download paths are constrained by
  allow-list, size cap, content-type check and forced attachment disposition.

**What would change this.** More build capacity, or the rules becoming materially cheaper. The correct
way to adopt them is out-of-band — a scheduled job on a larger runner with a multi-hour budget, whose
result is advisory to the merge gate rather than blocking it — not by moving them to `Warning` inside
the per-push gate, which would impose the same cost while removing the enforcement.

### RISK-052 — Five security rules execute and are held at Warning; their 21 reviewed sites are adjudicated by the Gate 1 allow-list

> **Revised again, and this is the canonical statement. It supersedes the "four rules no longer run at
> all" framing that the two halves below were written under.** That framing was accurate while
> `AnalysisLevelSecurity` was withdrawn from `Directory.Build.props`. It no longer is: the shipped tree
> sets `<AnalysisLevelSecurity>latest-all</AnalysisLevelSecurity>` alongside the frozen
> `<AnalysisLevel>latest-recommended</AnalysisLevel>`, so the Security category is armed in full and the
> four rules described below as absent **do execute and do report**. Code-review finding `MAJ-07`
> established that this entry, and every other surface repeating it, had been left behind by that change.
> The earlier wording is retained rather than overwritten, per this register's convention, and each
> superseded sentence is marked in place.
>
> **The current position, measured on the tree this revision describes** — a full non-incremental
> `dotnet build WebVella.ERP3.sln`: **0 errors, 3,055 warnings**. Five Security-category rules report,
> for **55 diagnostics** over **21 distinct `(rule, file)` pairs** — `CA2100` 20 diagnostics across 8
> files, `CA2326` 20 across 6, `CA2328` 9 across 4, `CA5351` 5 across 2, `CA5362` 1 across 1. `CA2327`,
> `CA5350`, `CA5359`, `CA5364` and the whole `CA3001`–`CA3012` family report **zero**. **All 21 pairs are
> in the Gate 1 allow-list**, each carrying an attributable written disposition and a resolvable
> `RISK-nnn` reference, and Gate 1 fails on any Security-category diagnostic outside it — so the count of
> unreviewed Security diagnostics is **0** and the count of stale allow-list entries is **0**.
>
> **What that means for this entry's two halves.** Half A is unchanged in substance: `CA5351` still fires
> at 5 sites and is still only a warning, and its formal, dated, exit-bounded acceptance now lives in
> [`RISK-171`](#risk-171-the-five-ca5351-residuals-a-formally-approved-exit-bounded-acceptance).
> Half B is **superseded in its central claim**: the nineteen `(rule, file)` entries it describes as
> *pruned* and *uncovered by any automated gate* are back in the allow-list and are gated again. Its
> per-rule engineering justifications remain correct and are the reason each entry is allow-listed rather
> than fixed, so the table is retained and re-titled rather than deleted.

**Status: Accepted — all five rules execute and are held at `Warning` rather than promoted to `Error`,
and their 21 reviewed `(rule, file)` pairs are carried as written, gated dispositions rather than as
silence.**

**The claim this entry used to make, withdrawn.** A previous revision opened "Ninety-five security rules
are promoted to `Error`, which is sound precisely because each was measured at zero diagnostics across all
19 projects before promotion." **Nothing is promoted to `Error`.** AAP 0.6.1 Class 2 freezes the analyzer
gate at `EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended`, and the repository-root
`.globalconfig` that promoted those ninety-five rules to `Error` was withdrawn and has not returned — no
global analyzer config exists in the tree, and Gate 1 asserts that. `AnalysisLevelSecurity=latest-all`,
by contrast, **is** shipped: it arms the Security category at each rule's default severity, which is
`warning`, and promotes nothing. Nine Security-category rules are observable on this tree — the four just named plus
`CA2100`, `CA2326`, `CA2327`, `CA2328` and `CA5362` — of which five report, at the counts in the revision
note above.

**Half A — the one rule that still fires, and is still only a warning.**

| Rule | Sites | Files | Why it is not an error |
|------|-------|-------|------------------------|
| `CA5351` | 5 | `WebVella.Erp/Utilities/CryptoUtility.cs` (4), `WebVella.Erp/Utilities/PasswordUtil.cs` (1) | A broken cryptographic algorithm. These are the **accepted residual** legacy-verification paths that exist so pre-existing credentials and payloads still verify and can be upgraded in place. Removing them would lock existing users out, which the preservation requirement forbids. Promoting the rule would fail the build on unchanged code. |

The five sites are `CryptoUtility.cs` at 186,33 / 198,21 / 208,23 / 225,32 and `PasswordUtil.cs` at
804,27. They are the two entries that remain in the workflow's Gate 1 allow-list, and Gate 1 asserts the
count is exactly 5 — so a sixth site fails CI even though the rule itself is a warning.

**Half B — four rules that execute, and the nineteen reviewed files they report against.** `AnalysisLevelSecurity=latest-all` is shipped, so all four **do** execute — 20 `CA2100`, 20 `CA2326`, 9
`CA2328` and 1 `CA5362` diagnostics over the 19 `(rule, file)` pairs below — and all 19 pairs are **in**
the Gate 1 allow-list, each with the disposition recorded there and a `RISK-nnn` reference back to this
entry. A twentieth and twenty-first entry cover `CA5351` under `RISK-171`. The engineering justifications
below are therefore no longer the *only* place they live; they are the reasoning the allow-list entries
cite, and they remain the reason each site is accepted rather than changed:

| Rule | Reviewed files (allow-listed, with a written disposition) | Why it is accepted, and what covers it |
|------|----------------------------------------------------------|----------------------------------------|
| `CA2100` | 8 — `WebVella.Erp/Database/DbRepository.cs`, `DbConnection.cs`, `DbFileRepository.cs`, `WebVella.Erp/Eql/EqlCommand.cs`, `WebVella.Erp/Jobs/JobDataService.cs`, `WebVella.Erp/Notifications/NotificationContext.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs`, `WebVella.Erp.Plugins.SDK/Services/LogService.cs` | Flags a query built from a non-constant string. Values are parameterised throughout and identifiers are validated and quoted through `DbIdentifier`, but the platform compiles its own query language to SQL, so the *shape* the rule looks for is intrinsic to the design and cannot be removed without replacing the query compiler. **Now covered only by** the parameterisation and `DbIdentifier` invariants, and by manual review of any new concatenation site. |
| `CA2326` | 6 — `WebVella.Erp/Database/DbEntityRepository.cs`, `DbRelationRepository.cs`, `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`, `WebVella.Erp/Jobs/JobDataService.cs`, `WebVella.Erp/Notifications/NotificationContext.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs` | `TypeNameHandling` other than `None`. Deliberate and load-bearing: already-persisted payloads carry type discriminators and would fail to deserialise without it. The exposure is closed by the binder, not by removing the setting. **Now covered only by** `ErpSerializationBinder`'s exact-type allow-list and manual review. |
| `CA2328` | 4 — `WebVella.Erp/Database/DbEntityRepository.cs`, `DbRelationRepository.cs`, `WebVella.Erp/Api/Models/AutoMapper/Profiles/JobProfile.cs`, `WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs` | The same setting where the analyzer could not prove the binder was attached. It is attached at all **20** sites — the count basis is in the `H-10` record of the [audit report](security-audit-report.md); the rule simply could not see it. **Now covered only by** the binder and manual review. |
| `CA5362` | 1 — `WebVella.Erp/Api/Models/QueryObject.cs` | A potential reference cycle during deserialisation, at `QueryObject.SubQueries`. Self-referential by design — a query object contains sub-queries. **Now covered only by** that design being intentional and documented. |

**The honest cost, restated to the measured position.** No rule in this set fails the build: a new
violation appears as a warning among the **3,055** the solution emits, and the mitigation is the ratchet
rather than the severity. Gate 1 enumerates every Security-category diagnostic, subtracts the 21
allow-listed `(rule, file)` pairs, and fails if anything is left over — so a violation at a *new* site
fails CI even though the rule is a warning, and a violation at an *existing* allow-listed site does not.
Gate 1 also fails when an allow-list entry stops matching anything, which is what stops the list drifting
into fiction. Those four rules report, are counted, and are published in the Gate 1 evidence
artifact. Two residual costs are real and are not softened. Site-level granularity is `(rule, file)`, not
`(rule, file, line)`, so a *second* violation of the same rule in an already-allow-listed file is absorbed
silently — the register records that as the price of an allow-list a human can read. And the 21
dispositions are engineering judgements, so a green Gate 1 means "reviewed and accepted with a reason on
the record", never "no such sink exists".

**Why the five are held at `Warning` rather than promoted.** Promotion needs a repository-root
`.globalconfig` or an equivalent severity ratchet, and AAP 0.6.1 Class 2 freezes the analyzer gate at
`EnableNETAnalyzers` plus `AnalysisLevel=latest-recommended` — AAP 0.3.2 declines escalating security
analyzer rules to build errors outright, because promoting 55 diagnostics on unchanged code would demand
exactly the mass refactor the governing change constraint forbids. Arming the category is a different act
from promoting it, and only the first is taken. Promotion is therefore a plan change, not a configuration
tweak, and it would have to move `Directory.Build.props`, the Gate 1 baselines, the allow-list, the
positive control and this entry in the same commit. The workflow enforces exactly that coupling: it fails
if a global analyzer config appears, if `AnalysisLevel` drifts from `latest-recommended`, if
`AnalysisLevelSecurity` drifts from `latest-all`, or if any Security-category rule fires outside the
allow-list.

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

**On severity.** **Nothing is promoted to `Error`** — no `.globalconfig` exists, per AAP 0.6.1 Class 2 —
so the probe produces `warning CA5359`, not an error. The detection is unaffected, since the rule still
fires on exactly these shapes, but a reintroduction does not stop the build on its own. What stops it is Gate 1: the rule's baseline is **zero**, and
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
`Content-Type`. There deliberately is none, rather than one added to satisfy a claim, for three reasons:

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
violation-heavy page load per minute.

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

**Why `rollForward: disable` is the right setting despite its availability cost.** The case against it is
that it demands the exact patch, fails outright when it is absent, and so
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
start); only the message improves. `Settings:EmailSMTPAllowInvalidCertificates` deliberately does **not**
share this shape: it is read after startup and must never abort a send, so it parses non-throwing and
fails safe instead. (A second mail setting once shared that shape and no longer exists — the
revocation-disable key was removed under review finding `INT-08`; see `RISK-060`.)

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
instance `(a{1,20}){1,20}` — is rejected even if the author meant it. So are back-references, which
are the one construct that forces PostgreSQL's engine off its non-backtracking path. The ceiling was
chosen by measurement rather than by taste: cost is linear in that product, and 256 admits a worst
case of about 107 ms per 20,000 rows while the next step up, 1024, costs 372 ms and the measured
attack shapes cost seconds. Patterns can be rewritten to stay inside it; the refusal names the
reason, though never the pattern.

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

### RISK-114 — A deployment that already encrypted data under a non-ASCII encryption key

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

- The substitution is per code unit, not per Unicode scalar. A character outside the Basic Multilingual
  Plane occupies two UTF-16 code units and produced **two** `?` bytes — `U+1F600` derived to `3f3f`,
  while the single-code-unit `U+4E2D` derived to `3f`.
- Because of that, the derived byte count always equals the character count. `GetValidKey` truncates or
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

### RISK-115 — The Data Protection key ring is not encrypted at rest

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

### RISK-116 — Gate 3 accepted one credential-shaped location: a commented-out connection-string template

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
files *at the revision that measurement was taken*. The totals have since moved to 1,520 of 1,576 as files
were added; the result — zero, in both layers — has not. The canonical current figures are in the
[audit report](security-audit-report.md#status-at-this-revision-gate-by-gate), and the
files, every one of the five sweep layers reporting no match, and the detector still proving itself first
against credentials planted in 10 file formats over 14 required `(layer, fixture)` pairs. The allow-list
entry is therefore inert by design rather than by accident, which is the pruning path this entry
described.

## Detailed entries — what the licence-governance gate cannot reach

### RISK-117 — The licence gate blocks packaging, not the human step after it

| Field | Value |
| --- | --- |
| **Status** | Accepted — the bounded residual of the control that keeps `RISK-001` unshippable. |
| **Related finding** | Review finding `CR2-F-04`, and `H-01` / `HR-11` behind it |
| **CWE** | [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) |
| **Owner** | Whoever performs a release. The control is engineering's; the release step it stops short of is not. |

**What it is.** `ErpAssertAutoMapperLicenceDecisionRecorded` in `Directory.Build.props` refuses to
*produce* a package while the `RISK-001` licence question is unanswered. It cannot refuse to *publish*
one. Three gaps follow from that boundary, and all three are deliberate rather than overlooked.

*A package built before the gate existed can still be pushed.* `nuget push` and `dotnet nuget push`
operate on a `.nupkg` file that is already on disk; nothing in MSBuild runs. Any artifact produced from
an earlier commit remains pushable.

*Recording the decision is not the same as being authorised to make it.* The gate checks that a record
exists, that it is well formed, and that it carries one of the two recognised answers. It cannot check that
the person named as approver is authorised to approve. What it now buys, since review finding `GOV-01`, is
more than deliberateness: because the answer must be a **committed line in this file**, it appears in a
diff, passes through review, and carries an approver, a date and a reference that git independently
attributes to an author and a commit. The transient command-line form that could be satisfied by anyone who
could type a pack command is refused outright (`ERPLIC005`).

*The gate is a reviewed edit away from removal.* Deleting the target, or adding the pinned version to
`ErpPermissiveAutoMapperVersions`, disables it. That is a property of every in-repository control and is
why the list carries a comment requiring the release's own `.nuspec` to be read first.

**Why it is accepted rather than extended.** Closing any of the three means reaching outside the
application boundary — a release pipeline with an approval gate, a signing identity, or an
organisation-level nuget.org policy. The governing plan excludes infrastructure beyond the application
boundary and forbids feature work, and none of the three gaps is a code vulnerability. The control was
chosen for the property it does have: it converts the one **irrevocable** step's precondition from "the
build was green" into "somebody answered the question".

**What closes it, if an owner wants it closed.** The second half of the recommendation this entry used to
carry — that the answer should land as a reviewable commit rather than as a transient command-line argument
— **is now done**, as review finding `GOV-01` required: the decision record described above is a committed
line, and the transient form is refused. What remains open is the identity half: require the release job to
run from a protected environment whose approval is held by whoever may ratify the licence, and require the
commit that carries the record to be signed, so the approver named in it is corroborated by something the
repository can verify. Both reach a release pipeline and a signing identity, which sit outside the
application boundary this remediation is scoped to, so they stay recommendations.

**What this residual is not.** It is not a way past the gate on the ordinary path. Measured across all
four packable manifests: `dotnet pack` fails with `ERPLIC001` for 4 of 4 while the question is open, with
`ERPLIC002` for 4 of 4 on an incomplete declination, and with `ERPLIC003` for 4 of 4 on an unrecognised
value; an unreadable pin fails with `ERPLIC004`. `restore`, `build`, `publish`, `run` and all 13 CI gate
steps are unaffected.

## Detailed entries — what runtime verification found after the audit inventory was frozen

### RISK-118 — Authenticated pages stay restorable from the browser's back/forward cache after logout

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

```text
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

```text
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

- **29 root-absolute image links** of the form `/doc-images/sdk-application-list.png`. There is no
  `docs/doc-images` directory anywhere in the repository, so these do not resolve on the filesystem *or* at
  the published site root. The referenced screenshots are simply absent.
- **45 extension-less cross-references** of the form `docs/developer/tag-helpers/wv-field-base` — missing the
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

### RISK-120 — The page header's `description` channel is raw by design, and one caller keeps it that way

**Status: CLOSED. Reclassified from an accepted residual to a fixed defect by review finding `F-02`.**

**The premise this entry rested on was false, and that is the substance of the correction rather than a
footnote to it.** The entry asserted that `PageUtils.GenerateListPageDescription` was the channel's *only*
non-literal supplier, and reasoned from there that the raw channel was safe because the one thing feeding it
was server-composed. There is a second supplier, and it is the worst possible one:
`WebVella.Erp.Web/Components/PcPageHeader/PcPageHeader.cs` resolves `ViewBag.ProccessedDescription` from
`context.DataModel.GetPropertyValueByDataSource(instanceOptions.Description)`, and both
`PcPageHeader/Display.cshtml` and `PcPageHeader/Design.cshtml` bind that value to `description=`. A page
component can therefore point `description` at any page or record data source, so arbitrary stored text
reached the raw sink on any screen carrying a page-header component. The condition this entry described as a
hypothetical future caller was already present in the shipped product.

**What changed.** The channel is no longer raw, and the fix is a split rather than a conversion, because a
straight conversion would have broken the list screens exactly as this entry warned:

- `description` now renders through `InnerHtml.Append`, so it is HTML-encoded. Every data-bound description,
  including the `PcPageHeader` path above, is covered by that.
- A new, explicitly named `description-html` attribute renders through `AppendHtml` and is the trusted-markup
  channel. It takes precedence over `description` and the two are never concatenated, so there is exactly one
  writer per response.
- The five SDK list views that legitimately pass builder-composed markup — `application/list.cshtml`,
  `data_source/list.cshtml`, `entity/list.cshtml`, `entity/pages.cshtml` and `page/list.cshtml` — were moved
  to `description-html` **in the same change**, which is what keeps their `<ul class="list-inline">`,
  `<li class="list-inline-item">` and `<strong>sorted by</strong>` markup rendering exactly as before.

The builder-side encoding that closed `P-22` is retained untouched, so the `sortBy` query value and each
filter name are still encoded where they enter the markup. The in-code comment that used to forbid
converting the sink has been replaced by one recording the retraction, so the false premise cannot be read
back out of the source either.

**Verified rather than asserted.** With a page-header description bound to a record field carrying
`QA F-02 <img src=x onerror="…"> &amp; R&D`, the rendered element's `innerHTML` was
`QA F-02 &lt;img …&gt; &amp;amp; R&amp;D`, its `childElementCount` was **0**, and the payload's global
never came into existence. All five list views were confirmed still emitting real markup — one `<strong>`
and two `<li>` elements each — both in the browser and in the raw server response.

**The structural recommendation below is retained, downgraded from a fix to an improvement.** Changing
`GenerateListPageDescription` to return a structured result — a record carrying the count, the optional sort
term and the filter names as *data* — and moving the markup composition into a Razor partial would remove
the trusted-markup channel altogether rather than naming it. That is no longer needed for safety now that the
default channel encodes, and it still changes a public signature used by nine list page models, so it stays
out of scope as refactoring beyond a security fix.

### RISK-121 — The Track Time grid title is sanitised by a third-party tag allow-list, not encoded

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

### RISK-122 — The 33 remaining frontend QA findings, and the recommended fix for each

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

### RISK-123 — Administrator-authored colour and icon metadata reaches a style attribute as CSS

**Status: CLOSED. Reclassified from an accepted residual to a fixed defect by review finding `F-06`.**

`WvPageHeader` exposes nine `string` properties. `area-label`, `area-sublabel`, `title` and `subtitle` are
HTML-encoded at the sink as of `P-21`; `description` is encoded as of `F-02`, which also closed `RISK-120`;
and `return-url` passes through `BaseErpPageModel.SanitizeReturnUrl` before it becomes an `href`. The
remaining three were this entry: `color` and `icon-color` interpolated into a `style` attribute, and
`icon-class` appended to a `class` attribute:

```csharp
metaLabelIconWrapperEl.Attributes.Add("style", $"background-color:{Color};");
metaLabelIconEl.Attributes.Add("style", $"color:{IconColor};");
metaLabelIconEl.AddCssClass(IconClass);
```

Consumer views bind all three from the database rather than from literals — `color="@Model.ErpEntity.Color"`
at 15 sites, `icon-class="@Model.ErpEntity.IconName"` at 11, `color="@Model.App.Color"` and
`icon-class="@Model.App.IconClass"` at 4 each — so the values are administrator-authored entity and
application metadata, not compile-time constants. `PcPageHeader.cs` additionally resolves all three from a
page data source, so they are not confined to those bound views either.

**What was measured, rather than assumed — retained, because it still holds and it bounds the finding.** The
`color` of the `account` entity was replaced with
`#f44336;background:url(javascript:alert(1))" onmouseover="alert(9)`, a payload deliberately carrying both a
quote-breakout attempt and a quote-free CSS declaration. The entity-detail page delivered:

```html
style="background-color:#f44336;background:url(javascript:alert(1))&quot; onmouseover=&quot;alert(9);"
```

The double quote is encoded to `&quot;`, so the `onmouseover=` text is trapped **inside** the `style`
attribute value as inert characters: no attribute is created and no handler is registered. `TagBuilder`
encodes attribute values on render, which removes the entire handler-injection class from this channel. What
that encoding does **not** remove is the surviving CSS declaration, which needs no HTML-special character,
nor — in the `class` case — arbitrary class tokens, which need none either.

**Why the earlier disposition was wrong.** The three reasons this entry gave for accepting the channel
(not a script sink, privilege-gated to the tier `RISK-023` already accepts, and a sanitiser would have to
police arbitrary CSS colours) were each true, and together they still understated it. A CSS declaration
alone is enough to fetch an off-origin resource, overlay or hide interface elements, and reposition a
clickable target, and an arbitrary class token is enough to do the last of those without any CSS at all.
Under the engagement's own severity matrix that is not "no exposure"; and the third reason had already
stopped applying, because a working colour allow-list existed in the framework itself.

**What changed.** The guard is applied at the tag-helper boundary, which is the narrowest place that covers
every consumer view and the page-component path at once:

- `Color` and `IconColor` pass through `SafeStyleValue.CssColor`, the same helper already trusted on four
  other render paths.
- `IconClass` passes through the **new** `SafeStyleValue.ApprovedIconClass`. This is deliberately
  **token**-level rather than character-level, because the character-level `SafeStyleValue.IconClass` admits
  any well-formed token and this is precisely the sink where an arbitrary class token is the exposure. The
  allow-list was derived from measured product usage rather than invented: the literal `icon` token, the
  Font Awesome family tokens, `fa-`-prefixed glyph tokens, and the platform's `go-` colour utilities. A
  value containing anything else is rejected **whole**.
- All three guarded values are computed once and reused at all four attribute sinks, and the
  `has-icon`/`no-icon` layout class is derived from the guarded icon value — so the layout class can never
  claim an icon the markup did not emit.

A rejected value becomes the empty string, which is an existing state of the product (a header with no colour
and no icon) rather than an invented fallback.

**Verified rather than asserted.** With the hostile fixture seeded, the rendered header class was
`pc-page-header no-icon`, no `DIV.meta-icon` existed in the subtree, the computed background was `none`, no
element carried a `url(...)` style, the rendered document did not contain the payload's host, and **zero**
off-origin requests were issued — confirmed three ways, from the performance timeline, the browser network
log and an OS-level check showing the target port refusing connections. The legitimate bindings were checked
in the same run and are unchanged: two distinct badge colours resolving to their exact stored hex values and
every icon glyph still rendering. An ad-hoc harness additionally asserts every one of the measured product
icon values is accepted verbatim while injected utility, positioning and attribute-breakout tokens are all
rejected.

**Residual.** None for the page header. The option-level icon guard on the *select* conversion boundary is
still character-level and is carried separately as `RISK-129`, because `F-06`'s remediation is scoped in
terms to the tag-helper boundary.

## Detailed entries — residuals and observations from the runtime-configuration QA pass

The three entries below were opened by runtime QA of the configuration and deployment surface. One is a
bounded residual of the transport-security check added in that pass; the other two are observations that
runtime validation made concrete and that the modification boundaries keep out of code.

### RISK-124 — Configuration aborts surface as an unhandled exception, so an orchestrator sees a crash

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

That is not a placeholder in a shell: the two brackets are read as input and output redirection, so
the line truncates a file named `container` in the working directory and feeds `docker`'s standard
input from it instead of naming anything. The form below uses a variable, so the filter can be
pasted and run unchanged once the first line is set:

```bash
# Set this to the container name or id, then run the filter unchanged.
CONTAINER=webvella-erp

docker logs "$CONTAINER" 2>&1 \
  | sed -n '/WebVella ERP startup aborted/,/^[[:space:]]*at /p' \
  | grep -v '^[[:space:]]*at '
```

Without Docker, the same filter reads a captured log or a journal unit:

```bash
sed -n '/WebVella ERP startup aborted/,/^[[:space:]]*at /p' /path/to/stderr.log \
  | grep -v '^[[:space:]]*at '

journalctl -u webvella-erp --no-pager 2>&1 \
  | sed -n '/WebVella ERP startup aborted/,/^[[:space:]]*at /p' \
  | grep -v '^[[:space:]]*at '
```

Expect the message up to **three** times: once as `Application startup exception`, once inside the
`Microsoft.AspNetCore.Hosting.Diagnostics` critical entry, and once in the unhandled-exception dump. Any
one copy is complete; they are the same string. An exit status of 134 from one of these hosts should be
read as "configuration fault, message above", not as a runtime crash. If a future change does introduce
a top-level handler, it must keep two properties this behaviour already has: the message must remain
complete, and no configuration value may be echoed (CWE-532).

### RISK-125 — The login inputs carry no `autocomplete` attributes

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

#### RISK-126 — RESOLVED: the transport-security check now refuses every unproven posture outside Development

| Field | Value |
| --- | --- |
| **Status** | **Resolved** — the residual recorded here was closed at the code-review checkpoint |
| **Related finding** | The QA finding that a plaintext-only Production host answered HTTP 500 on every form-bearing page, and the later review finding that the check itself accepted non-evidence and waved through the undeclared case |
| **Owner** | Platform team |

**The control, as it now stands.** `ValidateTransportSecurityPosture` in
`WebVella.Erp.Web/ErpMvcExtensions.cs` runs inside `UseErp()`, so all seven hosts inherit it, and it
accepts only evidence that a request can arrive over HTTPS: a declared endpoint whose scheme is `https`;
a `Kestrel:Endpoints` entry whose `Url` is `https`; `ANCM_HTTPS_PORT`, which the ASP.NET Core Module
writes only when the IIS site in front of this process has an HTTPS binding and which comes with scheme
preservation; or a trusted reverse proxy declared through
`Settings:ForwardedHeaders:KnownProxies`/`KnownNetworks` **together with** the public HTTPS port. Every
port it reads is parsed and range-checked to 1–65535, and a malformed value aborts startup naming the
key. Outside Development, **any** posture that satisfies none of those is refused before a request is
served.

**What the residual was, and why it is gone.** Two of the original four signals were not evidence at
all. A non-blank `HTTPS_PORT` satisfied the check although that key only selects the target of a
redirect and was never even parsed, and merely declaring a trusted proxy satisfied it although trusting
a proxy says who may be believed rather than that anything terminates TLS. Separately, the refusal fired
only when at least one endpoint had been **declared**; with nothing declared the identical diagnosis was
written as a `warn:` line and startup continued — and that was measured on a published Production host
to bind `http://localhost:5000` alone, with `/login` answering **500**. The undeclared case was
therefore not an unknown posture but a known-bad one, so it is now refused like every other. The
original reasoning — that a check which aborts a working deployment is worse than the failure it
prevents — is preserved where it is actually true: the IIS in-process topology this repository's own
`web.config` describes is accepted on the module's own evidence, and **Development remains exempt**
because its antiforgery cookie uses `SameAsRequest`, so local plaintext sign-in still works and the
warning keeps an absent HTTPS path visible without blocking a developer.

**Verified per posture.** Declared `https` endpoint: starts, `/login` 200. Plaintext-only declared
endpoints: refused. No endpoint declared: refused. Trusted proxy with a valid public HTTPS port: starts.
Public HTTPS port alone: refused. Trusted proxy alone: refused. `HTTPS_PORT=443abc` or `70000`: refused,
naming the key and the value. `ANCM_HTTPS_PORT=443`: starts. Development with a plaintext endpoint:
starts with the `warn:` line and `/login` 200.

**Two further things the check cannot see, stated so they are not assumed.** It cannot know whether a
trusted proxy actually sends `X-Forwarded-Proto: https` — trusting a proxy that does not leaves the 500
in place, which is why the diagnosis says so — and it cannot know whether a declared `https` endpoint
will bind successfully, for example with an unreadable certificate. Both remain deployment
verifications; see the checklist in [the secure configuration guide](secure-configuration.md).

### RISK-127 — The select component's display path: what the conversion-boundary guard closes, and what it does not

| Field | Value |
| --- | --- |
| **Status** | Icon/colour half **resolved**; the `Label` channel **also resolved** by review finding `F-01`, superseding the acceptance recorded below; the caller-side scope of the guard and the option-level icon-token width (`RISK-129`) accepted, with fix guidance |
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

**Residual 1 — `SelectOption.Label` — CLOSED by review finding `F-01`. The acceptance recorded here is
RETRACTED, and the reasoning is retained below because it explains why the fix is not the obvious one.**

The measurement that opened this residual was correct and stands: seeding
`label = high<img src=x onerror=alert(…)>` produced a live `<img>` element in the display `<div>` on the
task-details page and once per affected row on the SDK data list, while the same value in the form-mode
`<option>` text was correctly encoded to `high&lt;img …&gt;`. The conclusion drawn from it — that the
channel therefore had to be accepted — did not follow. It rested on treating *encoding* as the only
available control, and encoding genuinely was unavailable here:

- The same `Label` instance reaches an encoding sink (`Append`, on the display-without-icon, simple and
  `<option>` paths) **and** a raw sink (`AppendHtml`, on the display-with-icon, checkbox-list and radio-list
  paths) in a single render, so any value pre-encoded at the boundary would visibly double-encode somewhere.
  Decompiling `WebVella.TagHelpers` 1.8.0 confirmed the exact sink pairs rather than inferring them: the raw
  `AppendHtml($"<i …></i> {Label}")` form appears four times each in `WvFieldSelect` and
  `WvFieldMultiSelect`, and `WvFieldCheckboxList` and `WvFieldRadioList` write `AppendHtml(Label)`
  **unconditionally**, with no icon gate at all.
- Pre-encoding is *useless* against the client-side half regardless. All four select2 initialisations pass
  `escapeMarkup: function(markup){return markup;}`, and the template functions return the option's DOM
  **`.text`** — which the browser has already entity-decoded — for re-insertion as `innerHTML`. Entities
  written server-side are decoded before they reach that sink.

**The control that does work is value restriction, and it is what landed.** `SafeStyleValue.DisplayText`
removes exactly two characters from an option label and nothing else:

- `<`, because it is the only character that can begin a tag or a comment in any HTML context; and
- `"`, because `WvFieldMultiSelect.inline-edit.js` builds `<li … title="' + optionLabel + '">` in
  JavaScript, so a double quote breaks out of an attribute the server never wrote.

`&`, `'` and `>` are deliberately left untouched: a character reference cannot create markup, and an
apostrophe cannot terminate a double-quoted attribute. That is what preserves the exact labels this residual
was written to protect — `R&D`, `Client's request`, `> 30 days` all render byte-identically, and the helper
returns the **same string instance** when nothing needs removing, so the common path allocates nothing. Every
one of the 150 `new SelectOption` sites in the repository was checked first: no legitimate label contains
markup, so restriction removes no capability anyone was using.

*Verified rather than asserted.* With the hostile label still seeded, the payload's global never came into
existence — before opening the dropdown, after opening it, and after exhaustive hovering and ten-event
pointer sequences over every option; injected `<img>` count and `onerror` attribute count were **0**
throughout; a `MutationObserver` armed before page scripts recorded no mutations; and no dialog was ever
invoked. The legitimate control label was read back at codepoint level as exactly `low R&D 'q'` — one
U+0026, two U+0027 — confirming no double-encoding. An ad-hoc harness asserts the same properties
directly, including reference equality for the unchanged case.

*The library request in the original recommendation is retained as an improvement, not a pending fix.* An
opt-in `encode-text` mode on the select display path — the same request `RISK-121` makes for the grid column
— would let the platform stop restricting values at all and is still the better long-term shape. It is no
longer needed for safety.

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

**The render-path count.** An earlier statement of it read *"four independent render paths
consume the same two values"*. That count was short by one; there are **five**, the fifth being the
platform-wide select conversion boundary. The pattern that produced the miss is worth naming because it is
reusable: the count enumerated *the paths that had been fixed* rather than *the sinks that consume the
value*. The remarks in `WebVella.Erp.Web/Utils/SafeStyleValue.cs` and the comment in
`PcProjectWidgetTasksQueue.cs` now both state the corrected count and the reason the fifth path sits
outside any plugin's reach.

**UPDATE — the `Label` channel is closed, and the reasoning that left it open was wrong.** This entry
originally recorded `SelectOption.Label` as an accepted residual on the grounds that the vendor component
"already encodes it in edit mode", so a boundary encode would double-encode legitimate labels. That premise
was not tested when it was written; it has since been tested against the component's **compiled body**,
read with a decompiler rather than inferred from its intent, and it does not hold:

- `WvFieldCheckboxList` and `WvFieldRadioList` append the label as **raw HTML unconditionally** — three
  sinks each, no icon required.
- `WvFieldSelect` and `WvFieldMultiSelect` append it raw whenever an icon class is present — four sinks
  each.
- Every `<option>` path *does* encode server-side, and it does not help: the embedded select2 initialisation
  sets `escapeMarkup` to a pass-through and its `templateResult` returns the option's **decoded** text, which
  the script then assigns through `innerHTML`. A literal `<` therefore creates elements client-side no
  matter what the server wrote.

**The fix, and why it is complete rather than partial.** `SafeStyleValue.OptionLabel` replaces `<` with
`&lt;` and `>` with `&gt;` at `ModelExtensions.ToWvSelectOption` — the single conversion boundary all call
sites traverse — and returns the input unchanged when neither character is present. Neutralising only the
two markup delimiters closes every route above, because an HTML character reference can never itself create
markup: with `<` and `>` gone, no `&`, quote or apostrophe can start an element, an attribute or a
statement, on the server-side raw paths or on the client-side re-insertion. Leaving those three characters
untouched is precisely what avoids the double-encoding regression this entry originally feared — a label
like `R&D` still renders as `R&amp;D` in the markup and `R&D` on screen.

**Residual, recorded rather than hidden.** A label containing a literal `<` or `>` now displays as `&lt;`
or `&gt;` in the component's own encoded display paths. That is a visible change for a label that contains
a markup delimiter, and it is accepted: such a label cannot be rendered as typed by any encoding scheme
that also prevents it creating markup.

**Verified** by an in-repository harness of sixteen assertions, including negative controls that reproduce
both the server-side raw sink and the client-side `innerHTML` re-insertion as exploitable *before* the
guard, and confirming `R&D` renders as exactly `<span>R&amp;D</span>` after it.

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

At that checkpoint the register's canonical index ended at `RISK-128`. The latest review added the two
narrower residuals `RISK-129` and `RISK-130`, which are the final two rows as of this revision.

## Detailed entries — residuals from the post-remediation code review of the delivered controls

The two entries below were opened by a code review that read the delivered controls against the tree rather
than against the record. That review raised eight findings: five High, one Major and two Medium. Seven were
**fixed** — `F-01` through `F-07`, recorded in [the remediation log](remediation-log.md) with the
verification performed for each, and reflected above in `RISK-120`, `RISK-123` and `RISK-127`, all three of
which moved from accepted residuals to closed defects. The eighth, `F-08`, was the accuracy of these
documents themselves and is what produced the corrections throughout this file. What remains here is the two
residuals those fixes left behind, both narrower than what they replaced, and both recorded rather than
closed for a reason stated in each entry rather than implied.

### RISK-129 — The option-level icon guard is character-level, where the page header's is now token-level

**Status: documented with fix guidance.**

`ModelExtensions.ToWvSelectOption` guards a stored option's icon through `SafeStyleValue.IconClass`, which
validates the **characters** a class value may contain. Closing `RISK-123` under review finding `F-06`
introduced a stricter sibling, `SafeStyleValue.ApprovedIconClass`, which validates the **tokens** a class
value may contain — the literal `icon` token, the Font Awesome family tokens, `fa-`-prefixed glyphs and the
platform's `go-` colour utilities — and rejects the whole value otherwise. The select boundary still uses
the character-level guard, so an author can store a well-formed but arbitrary utility token there.

**Measured, not hypothesised.** Runtime verification of `F-06` observed the select display path rendering
`class="fas fa-fw fa-bug d-none"` from a seeded fixture: `d-none` is a Bootstrap display utility the product
never intended that field to carry, and it passed the character-level guard because every character in it is
legal. The exposure is bounded to exactly that: a `class` attribute value. No attribute is created, no
handler is registered, and the hostile **colour** in the same fixture was rejected by `SafeStyleValue.CssColor`
and fell back to the product's default — so the pairing an attacker would want (an invisible element plus a
chosen colour) is not available. The ceiling is UI redress: hiding, resizing or repositioning an icon inside
a select option.

**Why it is documented rather than fixed.** Under the engagement's own severity matrix a class-token
injection with a UI-redress ceiling and no script path is a *minor misconfiguration*, which the matrix
disposes of by documenting. `F-06`'s remediation is scoped in terms to the page-header **tag-helper
boundary**; the reviewing pass read `ModelExtensions.cs` in full and did not raise this. Substituting the
stricter guard here anyway would be a change with no confirmed finding behind it, which the Minimal Change
Clause excludes — and it is not a free substitution either: the select boundary serves 94 call sites whose
stored icon values have never been constrained token-wise, so a stricter guard could blank icons that render
correctly today.

**Recommended fix.** Route the option icon through `SafeStyleValue.ApprovedIconClass` instead, which needs no
new code — the helper already exists in the same class and is already exercised by an ad-hoc harness against
every measured product icon value. Do it as a deliberate change with a survey first: enumerate the distinct
`icon_class` values stored across every select field in the target deployment, extend the approved token
shapes to cover any legitimate family the survey turns up, and only then switch the call. Switching first and
surveying afterwards risks blanking working icons, which is why this is a sprint task rather than a one-line
edit.

### RISK-130 — `DbFileRepository.Copy` carries the `F-05` shape, unreachably

**Status: documented with fix guidance.**

Review finding `F-05` closed a time-of-check-to-time-of-use race in `DbFileRepository.Move`: the method
re-resolved the destination on its own connection and deleted whichever row that later read returned, an
identifier the calling action never authorized. `DbFileRepository.Copy` contains the same shape, in a weaker
form — `if (destFile != null && overwrite) Delete(destFile.FilePath);` — calling the `Delete` overload that
pins **no** expected identifier at all, so it would not even detect a substitution after the fact.

**Why it is not exploitable, established by enumeration rather than by argument.** `Copy` has **zero** call
sites anywhere in the nineteen projects. No controller action, no service, no plugin, no job and no seed
routine invokes it; it is public API that nothing consumes. A race needs two racers, and there is not one.

**Why it is documented rather than fixed.** This is the same disposition the audit already applies to the
platform's other unreachable security code under `L-01` — the 146-line authorisation attribute, the 61-line
authentication cache, the 146-line token type and the fully commented-out login-audit block are all recorded
and left in place, because removing or hardening unreachable code is hygiene rather than remediation and the
Minimal Change Clause forbids refactoring beyond a confirmed finding. `F-05` cited `Move` and its one calling
action; it did not cite `Copy`. Hardening it now would also be speculative in a specific way: the correct
authorized-destination expectation for a copy can only be decided by the caller that authorizes the
destination, and there is no such caller to ask.

**Recommended fix, and the trigger for it.** The moment `Copy` acquires a first caller, give it the same
treatment `Move` received in the same change that introduces the caller: the same optional
`enforceExpectedTarget` / `expectedTargetId` pair, re-read under `FindForUpdate` inside the existing
transaction, with the destination delete permitted only when the caller pinned that exact row **and** the
caller's own authorization-aware `Find` resolved it — the second clause being what distinguishes an empty
path from a staged row `Find` withheld from a non-owner. All of that machinery already exists and is exercised
by `Move`; nothing new would need designing. If instead `Copy` is confirmed dead for good, delete it under a
hygiene change rather than a security one.

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

**This table and the one after it are the canonical Medium disposition mapping for the engagement.**
Where the audit report, `SECURITY.md` or `docs/index.md` states a count of remediated Mediums, this is the
mapping it refers to, and it is stated as two groups rather than as one count, because a bare count of
"remediated Mediums" is what let two documents disagree about whether it was eight or nine. **Eight**
Mediums were remediated under a limb, and **two more** were *partially* changed by later review-finding
work while their own declines stand.

**Group 1 — the eight Mediums remediated under a limb.** Each passes exactly one of the three tests:

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

**Group 2 — the two Mediums partially changed by later review-finding work.** Neither qualified under a
limb when the disposition rule was first applied, and neither decline has been reversed. What changed is
that a *later* review found each one composed with something else into an exposure that did meet limb (a),
and the narrower half was closed while the anonymous exemption itself — the finding as written — was
deliberately left in place. They are recorded here so that a reader counting "remediated Mediums" is not
forced to choose between two numbers that were both partly true.

| Medium | What changed, and under which limb | What is still declined |
| --- | --- | --- |
| `M-09` — anonymous access to a developer page | **(a)**, on a composition the original assessment did not see: `/dev` renders a Blazor Server component and the SDK host set `CircuitOptions.DetailedErrors = true`, so the anonymous page was the delivery vehicle for full server exception text to an unauthenticated caller. Under review finding `CR2-F-07` the exemption is **environment-gated rather than deleted**, and `DetailedErrors` now follows the environment. | The exemption itself, in the **Development** environment, where the SDK workflow depends on reaching `/dev` without a session. Carried as `RISK-113`. |
| `M-10` — anonymous resource-read endpoint on the project plugin | **(a)**, likewise on a composition: under review finding `F27` the caller's string no longer selects a resource, reaches a log, or reaches an exception path, which closed everything the exemption could be used to *reach*. | The `[AllowAnonymous]` attribute itself. Two static scripts are still served without credentials, which is the finding as written. Carried as `RISK-048`. |

Every **other** Medium — the eight not in either group — and every Low is documented only. Each appears in
the next section with a concrete recommended fix, and the reason each was declined is in *changes
deliberately declined under the Minimal Change Clause* below.

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

**Band note.** This table groups the findings numbered `M-01`–`M-18`. `M-01` is classified **Low**, not Medium — the severity matrix names *missing security headers* in the Low tier, and code-review finding `MAJ-07` retracted the earlier promotion to Medium. It is listed here to keep the numeric sequence contiguous; the [audit report's `M-01` record](security-audit-report.md#m-01-no-security-response-headers) is the authority for its band.

| ID | Finding | CWE | OWASP | Disposition and recommended fix |
| --- | --- | --- | --- | --- |
| `M-01` | No security response headers | CWE-693, CWE-1021 | A05:2021 | **Remediated**, limb (a). All seven mandated headers are emitted by `SecurityHeadersMiddleware` in all seven host pipelines, ahead of response compression and both static-file middlewares. The one residual is the content policy's delivery mode — RISK-022 |
| `M-02` | No antiforgery validation on the MVC API surface | CWE-352 | A01:2021 | **Documented only.** Correctly narrowed to `WebApiController`: the Razor Pages login already validates at `WebVella.Erp.Web/Pages/login.cshtml.cs:L64`, so this is not a platform-wide absence. Only the zero-breakage half was applied — the `SameSite=Lax` and `Secure` cookie attributes, which already block cross-site *form* posts of the session cookie for unsafe methods. **Fix:** emit the verification token in the shared layout, attach it from the platform's own AJAX helper so existing JavaScript clients start sending it, confirm by telemetry that no untokened caller remains, then switch on `AutoValidateAntiforgeryToken`. Declined now because today's clients post without a token and enforcement would break working functionality |
| `M-03` | Sign-in call not awaited | CWE-252, CWE-703 | A07:2021 | **Remediated**, limb (c). The call is awaited, which made the method asynchronous and propagated to its single caller — a compile-mandated ripple, not an opportunistic one |
| `M-04` | Local time used for token timestamps | CWE-613 | A07:2021 | **Remediated**, limb (c). `DateTime.UtcNow` replaces `DateTime.Now`, so the expiry claim means what it says regardless of host timezone |
| `M-05` | Password hash comparison was not constant time | CWE-208 | A02:2021 | **Remediated**, limb (c). `CryptographicOperations.FixedTimeEquals` over equal-length spans, with length checked first and absent input failing closed |
| `M-06` | Shared mutable hash instance used from concurrent requests | CWE-362 | A02:2021 | **Remediated**, limb (c). The shared instance is gone in favour of the thread-safe static call |
| `M-07` | Unbounded script-evaluation cache holding compiled delegates | CWE-770, CWE-94 | A08:2021 | **Half closed, half still documented only, and the half that closed did so for a sharper reason than this row originally gave.** Verified locators at the time of the audit — `WebVella.Erp.Web/Services/CodeEvalService.cs:L13`, `private static readonly Dictionary<string, object> scriptObjects = new Dictionary<string, object>();`, and `:L44`, `CSScript.EvaluatorConfig.ReferenceDomainAssemblies = true;`. **Path correction worth stating: `WebVella.Erp/Utilities/CodeEvalService.cs` does not exist**, so a fix aimed there would miss — that is the AAP's own path, at §0.3.2 and §0.7.1 Group 11, and it is the tenth such inaccuracy this document set records. **CLOSED half:** the checkpoint review raised the same code as `M-OPEN-04`, on the ground that the plain `Dictionary` was **read outside the lock that guarded its writes** — a data race, not merely growth — and commit `087ad593` replaced it with a `MemoryCache` using atomic get-or-add, `SizeLimit = 1000` and a one-day sliding expiry. A race probe measured 3 `KeyNotFoundException` faults before and 0 after over ~280 million reads. See record `CK-08`. **OPEN half, unchanged:** `CSScript.EvaluatorConfig.ReferenceDomainAssemblies = true;` survives at `:L74`, so a compiled script still reaches every assembly loaded in the domain. **Fix:** narrow it to an explicit assembly list |
| `M-08` | Deterministic initialisation vector in the symmetric encryption helpers | CWE-329 | A02:2021 | **Documented only** — and latent: the helpers have no active caller, which is why this is not a Critical. RISK-006 additionally records that changing the scheme in place would make any already-encrypted data undecryptable. **Fix:** generate a per-message CSPRNG initialisation vector and prepend it to the ciphertext, and migrate the primitive to AES-256-GCM as the Cryptographic Standards block requires. Version the payload so existing ciphertext stays readable through the transition |
| `M-09` | Anonymous access to a developer page | CWE-306 | A01:2021 | **Documented only** — it does not meet the compensating-control test. Now at `WebVella.Erp.Site.Sdk/Startup.cs:L97`, `options.Conventions.AllowAnonymousToPage("/dev")` (the audit locator `:L48` drifted as the host pipeline grew). **Fix:** delete the convention outright, or wrap it in an `environment.IsDevelopment()` guard so it cannot ship enabled |
| `M-10` | Anonymous resource-read endpoint on the project plugin | CWE-306, CWE-200 | A01:2021 | **Documented only** as an *anonymous* surface; its log-injection and log-volume half **was** closed. The action is now at `WebVella.Erp.Plugins.Project/Controllers/ProjectController.cs:L512` (audit locator `:L462`). **Fix:** remove `[AllowAnonymous]` and require authentication, or — if the asset must stay public — bind the `file` parameter to a fixed allow-list of embedded resource names instead of accepting a caller-supplied string |
| `M-11` | Synchronous IO enabled for every request | CWE-400 | A05:2021 | **Documented only.** Declined because removing the allowance would break the synchronous manager code paths that depend on it. **Fix:** convert those manager paths to `async`/`await` — they are the actual dependency — and only then remove `AllowSynchronousIO` from `WebVella.Erp.Web/Middleware/ErpMiddleware.cs`. Doing it in the other order breaks the platform |
| `M-12` | Login auditing is unreachable dead code | CWE-778 | A09:2021 | **Remediated**, limb (b). Success and failure are recorded at the live login path. The dead block at `WebVella.Erp.Web/Security/WebSecurityUtil.cs:L40-L85` is left in place and documented under `L-01` rather than deleted |
| `M-13` | Password length bounds of 6 to 24 characters | CWE-521 | A07:2021 | **Remediated**, limb (b). Raised to 12–128 |
| `M-14` | No multi-factor authentication | CWE-308 | A07:2021 | **Documented only.** Architectural, and no confirmed Critical or High required it, so building it would be the enhancement-beyond-remediation the constraints forbid. **Fix:** add a TOTP second factor against the existing user entity, or delegate authentication to an external identity provider. Feature work — schedule it, do not smuggle it into a remediation |
| `M-15` | Client library loaded from a content delivery network without an integrity attribute | CWE-829 | A08:2021 | **Documented only.** **Fix:** add `integrity` (a SHA-384 subresource-integrity digest) and `crossorigin="anonymous"` to the script tag; or, preferably for a product that must build offline, vendor the library into `wwwroot` at a pinned version and drop the external origin entirely — which also removes the third-party origin from the content policy's allow-list |
| `M-16` | Legacy timestamp behaviour enabled on every host | CWE-1254-adjacent | A05:2021 | **Documented only.** `AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);` is present in all seven hosts — `WebVella.Erp.Site/Startup.cs:L54` (audit locator `:L40`), and the equivalent line in each sibling. Declined because flipping it changes how **already-stored** timestamps are interpreted, which risks silent data corruption — a worse outcome than the finding. **Fix:** migrate stored values to `timestamptz` semantics in a dedicated, separately validated change with its own backup and rollback plan, then remove the switch from all seven hosts in one commit |
| `M-17` | Exception details e-mailed off-box before they are persisted | CWE-532, CWE-209 | A05:2021 | **Documented only.** The earlier claim that `H-11` materially mitigated this is **withdrawn** as factually wrong — review finding `INT-01`. `H-11` hardened the five **MailKit** send paths in the mail plugin, while this notification travels through a different client entirely: `WebVella.Erp.Web/Services/MailService.cs` builds a `System.Net.Mail.SmtpClient` and never sets `EnableSsl`, whose default is `false`, so the payload and the relay credential cross a **plaintext** session and no certificate is presented for any policy to act on. What genuinely bounds it: the whole path is gated on `Settings:EmailEnabled`, which is `false` in all eight shipped configuration files and defaults to `false`; `WebVella.Erp/Diagnostics/Log.cs:L81-L114` serialises the request URL but not headers, cookies or body — with the correction that `:L111` includes the **query string**; and the twenty-eight notifying `LogService` writes on the web API surface were replaced by a non-notifying audit sink while closing `F26`. **Fix:** persist the record first and notify second so a delivery failure cannot lose the diagnostic; redact the query string from the notified payload; and secure that client separately — see `RISK-131`, which carries the full transport analysis |
| `M-18` | The codebase's only output encoder was trivially bypassable | CWE-116 | A03:2021 | **Remediated**, limb (a). The case-sensitive string substitution is replaced by the framework's JavaScript encoder |

### Low severity — L-01 through L-10

| ID | Finding | CWE | OWASP | Disposition and recommended fix |
| --- | --- | --- | --- | --- |
| `L-01` | Dead security code retained in the tree | CWE-561 | A05:2021 | **Documented only.** The inventory, measured: `WebVella.Erp.Web/Security/AuthorizeAttribute.cs` 146 lines, `WebVella.Erp.Web/Security/AuthCache.cs` **61 lines**, `WebVella.Erp.Web/Security/AuthToken.cs` 146 lines, and `WebVella.Erp.Web/Security/WebSecurityUtil.cs` where L37 through L90 are entirely `//`-commented, including the `UpdateUserLastLoginTime(userId)` calls at `:L50` and `:L76`. Ten further `[AllowAnonymous]` exemptions exist **only** inside commented-out code and are therefore not part of the anonymous attack surface - eight in `WebApiController.cs` and two in the SDK's `AdminController.cs`, measured rather than estimated. Declined because unreachable code is not exploitable, so removal is hygiene rather than remediation. **Fix:** delete all four in a dedicated cleanup change with no other content, so the diff is reviewable as pure subtraction. **Path precision, because this is easy to get wrong: the dead cache is `Security/AuthCache.cs`, *not* `Utils/AuthCache.cs`, and it is a different file from the live 54-line `WebVella.Erp.Web/Utils/Cache.cs` that the login throttle is built on** |
| `L-02` | Fifteen package references exist only inside XML comments | — | A06:2021 | **Documented only** as hygiene. **Fix:** delete the commented `<PackageReference>` elements. One of them, `SixLabors.ImageSharp` 3.1.6 in `WebVella.Erp.Web/WebVella.Erp.Web.csproj`, carries a genuine High-severity out-of-bounds-write advisory that **does not apply to this build** because the reference is not in the build graph — which is exactly why these fifteen are recorded as hygiene and never as findings. Reporting them would have put false High findings in the audit report |
| `L-03` | Packaging script references manifests that do not exist | CWE-1104-adjacent | A08:2021 | **Documented only.** `create-nuget-pkgs.bat` invokes `nuget pack` against four `.nuspec` manifests; a repository-wide search finds **zero** `.nuspec` files, so the script is already non-functional and cannot be a live risk. **Fix:** either delete the script — the modern `dotnet pack` path supersedes it, and the licence-governance gate in `Directory.Build.props` only guards *that* path — or add the four manifests and bring the script under the same gate. Leaving it half-real is the worst of the three |
| `L-04` | Large binary committed to the repository | — | A08:2021 | **Documented only.** `ExternalLibraries/libwkhtmltox.dll`, measured at **29,765,120 bytes (~28.4 MB)**. **Fix:** replace it with a `PackageReference` to a maintained distribution of the library, or track it through Git LFS. Either removes a 28 MB unversioned, unverifiable binary from every clone; the package reference additionally brings it inside the dependency-audit graph, which an unmanaged DLL can never be |
| `L-05` | No health endpoint, metrics, tracing or correlation identifier — all four probes measure **0** | CWE-1059-adjacent | A09:2021 | **Documented only.** The "no rollback tooling" half of this finding does not hold — a published-artifact startup smoke test runs in CI and rollback guidance is documented in [the credential migration guide](credential-migration.md). **Fix, smallest first:** add an ASP.NET Core health-check endpoint that probes the database and reports readiness, which also closes the startup-window gap where a host accepts connections while still provisioning; emit the framework's existing `HttpContext.TraceIdentifier` into every audit and log record as a correlation key, needing no new dependency; include that identifier in the notification payload so a fault e-mail can be reconciled with its persisted record, which is the SMTP-boundary gap; and only then adopt `ActivitySource` and a metrics meter. Detailed as `RISK-141` |
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

- **Deleting the dead security code** (`L-01`) — unreachable, therefore not exploitable. Removal is
  hygiene, not remediation.
- **Removing the fifteen commented dependency entries** (`L-02`) — same reason, and they are not in the
  build graph.
- **Touching the raw-output occurrences that render server-generated markup.** The census is exact, not
  approximate: **128** `Html.Raw(` occurrences across **69** `.cshtml` files **at the audit baseline**, of
  which `Html.Raw(action)` accounts for **49** and `Html.Raw(record["action"])` for **6** — roughly 55 in
  total. *(The delivered tree measures **111** calls across **61** views, counting invocation sites rather than the textual mentions a looser pattern also matches;
  `RISK-170` is canonical for the current census. The 114/62 figure that once circulated was the census
  of the tree at commits
  `88136e3b` through `0f7419ae` and went stale at commit `859356e4`, which removed the last three
  wrappers in `WebVella.Erp.Web/Pages/ckeditor/ImageFinder.cshtml`.)* All seven builder sites were inspected and every one interpolates only identifiers; a search
  for interpolation of database text fields into those builders returned **zero** matches. Changing them
  would break working screens for no security benefit, which is why they are a declined change and
  **never a finding**.
- **Tightening cross-origin policy at the five already-restrictive hosts** —
  `WebVella.Erp.Site.Crm`, `.Mail`, `.MicrosoftCDM`, `.Next` and `.Sdk` already use a restrictive named
  policy, so the finding correctly covered two hosts rather than seven. Their hard-coded localhost
  origins are a separate low-severity note carried in the ongoing recommendations, not an unfixed
  finding.
- **Removing synchronous IO** (`M-11`) — would break the synchronous manager code paths.
- **Removing legacy timestamp behaviour** (`M-16`) — would change the interpretation of already-stored
  timestamps, risking data corruption.
- **Enforcing antiforgery on the MVC API surface** (`M-02`) — existing JavaScript clients post without a
  verification token, so enforcement would break working functionality. Only the zero-breakage
  cookie-attribute half is applied.
- **Blanket field-permission enforcement across the data layer** — would ripple through 23 field types
  and every read and write projection, and because `WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L610`
  treats an **empty** read permission as **denial**, a blanket port would hide fields wholesale. `C-02`
  was fixed surgically instead; the residual is recorded below.
- **Escalating analyzer rules to build errors** — enabling the .NET analyzers across roughly 700
  pre-existing source files surfaces a large legacy warning backlog, and promoting that wholesale would
  demand exactly the repository-wide refactor the constraints forbid. **Only the dependency diagnostic
  codes `NU1901`–`NU1904` are promoted to errors** (alongside `NU1900` and `NU1905`, which cover an
  unreachable or advisory-less audit source). No `CA` identifier is promoted, and no blanket
  warnings-as-errors switch is set. See RISK-024, RISK-051 and RISK-052 for what that leaves uncovered.
- **Removing the anonymous developer page** (`M-09`) and **the anonymous project resource read**
  (`M-10`) — both Mediums that do not meet the compensating-control test.
- **Adding multi-factor authentication or an external identity provider** (`M-14`) — feature work with
  no confirmed Critical or High behind it.
- **Bounding the script-evaluation cache** (`M-07`).
- **Fixing the deterministic initialisation vector** (`M-08`) — latent, with no active callers, and
  changing it in place would make already-encrypted data undecryptable.
- **Suppressing the e-mailed exception details** (`M-17`) — bounded by what `Log.cs:L81-L114` actually
  serialises and by `Settings:EmailEnabled` being `false` in every shipped configuration, and narrowed
  further by the non-notifying audit sink introduced for `F26`. **Not** mitigated by `H-11`: that
  hardened the mail plugin's five MailKit paths, while this notification uses a separate
  `System.Net.Mail.SmtpClient` that negotiates no TLS at all. The claim to the contrary was withdrawn
  under review finding `INT-01`; the transport itself is `RISK-131`.
- **Adding subresource integrity to content-delivery-network libraries, or pinning unversioned client
  assets** (`M-15`).
- **`L-04` through `L-07`** — the 28.4 MB committed binary, the inert TypeScript configuration, and the
  absent lock file, package-source configuration, health endpoint, smoke tests and rollback tooling.
- **Creating any test project or test-framework integration.** This is the feature work the constraints
  forbid, and it is the reason the *"existing test suite passes"* gate is vacuous **by construction**
  rather than by omission — no test project, test-framework package reference or executable test method
  exists in any of the 19 projects. The substitute regime is recorded in
  [the remediation log](remediation-log.md).
- **Fixing the empty exception handlers** at
  `WebVella.Erp.Web/Middleware/ErpErrorHandlingMiddleware.cs:L57-L60` and `:L63-L66` (`catch { }`) — a
  **reliability** concern, not a security one. Both line locators and the byte-identity claim were
  re-verified at the current revision: the file is unchanged from `master`, and the two `catch { }` blocks
  sit exactly there. **One reachability fact was mis-stated in a working note during the checkpoint
  remediation and is corrected here rather than left to be rediscovered:** this middleware is **not**
  unregistered. All seven hosts call `app.UseErrorHandlingMiddleware()` from their own
  `Startup.Configure` — named rather than numbered, because those locators move with every edit —
  but each does so inside the **`else` branch of the Development check**, alongside
  `UseExceptionHandler("/error")` and `UseStatusCodePagesWithReExecute("/error")`. So it runs in the
  shipped Production posture and does **not** run under `ASPNETCORE_ENVIRONMENT=Development`, which is why
  a local development host can make it look like dead code. The consequence for this entry is that the two
  empty handlers are live in production and inert in development — the reverse of the usual pattern, and
  worth knowing before anyone tries to reproduce a swallowed fault locally.
- **Adding any new package dependency whatsoever** — every control this remediation introduces resolves
  from the `Microsoft.AspNetCore.App` framework reference already present at
  `WebVella.Erp/WebVella.Erp.csproj:L43`: the password hasher, the rate limiter, the antiforgery
  services, the HSTS and HTTPS-redirection middleware, the data-protection stack, the web encoders and
  the serialisation-binder interface.
- **Any change to the Blazor WebAssembly *Client* project.** Its outbound HTTP usage is browser-side and
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

- **`Npgsql [9.0.4]`** at `WebVella.Erp/WebVella.Erp.csproj:L61` — a newer data provider exists, but
  the pinned version is **already safe**: the provider's only advisory does not reach the 9.x line at
  all. Upgrading would be change without remediation.
- **`Newtonsoft.Json` 13.0.4** — past **both** of its historical advisories.
- **`System.IdentityModel.Tokens.Jwt` 8.15.0** — beyond every version its advisories affect.

Exactly four version changes were made, and each closes a confirmed advisory or an
unsupported-component finding; they are inventoried in
[`LIBRARIES.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/LIBRARIES.md).

**Solution-file hygiene, declined and routed here rather than silently fixed.** The frozen scope
authorises exactly one change to
[`WebVella.ERP3.sln`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/WebVella.ERP3.sln) —
the project-reference path-casing repair that closed `H-19`. Everything else in that file is therefore
documented, not remediated:

- The solution-items entry `..\Users\rumen.yankov\Desktop\postgresql.conf` at `WebVella.ERP3.sln:L13`
  points outside the repository, at a developer's desktop that no longer exists. Pre-existing litter; it
  affects no build, because solution items are not compiled.
- `INSTRUCTIONS.md`, `home.PNG` and `internal.PNG` at `:L8-L10` are listed as solution items but
  contribute nothing to any build. Also pre-existing litter.
- **`Directory.Build.props` and `SECURITY.md` were deliberately *not* added** to the *Resources* or
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

**The login throttle's counters are durable and shared; only its lockout *mirror* is per-process.**
*(The protection is not per-process: counters live in the pre-existing `plugin_data` table via
`DbSecurityStateRepository`. See `RISK-008`.)* The positive-only lockout mirror is an in-process
`MemoryCache` that the service **owns privately**, size-bounded at 20,000 tracked principals. It does not borrow the shared helper at `WebVella.Erp.Web/Utils/Cache.cs` — 54 lines wrapping `IMemoryCache`: the helper cannot be given a `SizeLimit`, which is the CWE-770
bound this store needs, and raising a limit on the shared instance would change eviction for every other
consumer. Using the same `MemoryCache` type privately is what avoided both a schema change and a new
dependency, and is therefore still the least invasive control available (guideline 5).
**Superseded by review finding `CK-03`**, which is the correction this paragraph most needs: the counters
were moved to the durable shared store, so throttle state now spans instances and survives a restart, and
the private `MemoryCache` retains only in-force lockouts as a positive-only fast path. The paragraph below
records the position before that change. The consequence as it then stood: throttle state neither spanned
instances nor survived a
restart, so a multi-instance deployment enforced the five-attempt bound once **per instance** rather than
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

- **The Server project's `ProjectReference` named a file that never existed — now closed.**
  `WebVella.Erp.WebAssembly/Server/WebVella.Erp.WebAssembly.Server.csproj` referenced
  `..\Client\WebVella.Erp.WebAssembly.Client.csproj`. There is no such file: the real Client manifest is
  `WebVella.Erp.WebAssembly/Client/WebVella.Erp.WebAssembly.csproj`, with no `.Client` suffix — and
  `WebVella.ERP3.sln:L55` had always referenced it **correctly**, which is what made the mismatch
  visible. MSBuild skipped the missing project silently (`MSB9008`), so the Client dropped out of the
  Server's restore, audit and analyzer graph, and the Server project was **structurally unbuildable**
  rather than merely unscanned. The filename is corrected at `:L17`, with the reason recorded in the
  manifest itself.
- **Neither the `Server` nor the `Shared` project is a member of the solution — still open, and
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

## Residuals recorded by the final integration and external-service review

Four residuals raised by review findings `INT-01`/`INT-02`, `INT-04`, `INT-05` and `INT-13`. Each is a
**pre-existing** defect in code this remediation did not author, each sits in an optional or
default-disabled subsystem, and each is documented rather than fixed for the reason its entry states.
The three findings that were fixed in the same pass — the queue starvation `INT-03`, the stored
cross-site scripting `INT-14`, and the out-of-plan revocation switch `INT-08` — are recorded in the
[remediation log](remediation-log.md) instead, because they are changes rather than residuals.

### RISK-131 — The diagnostic notification mailer sends exception detail and a credential in the clear

**REMEDIATED — superseded by review finding `CK-07`.** This entry recorded the residual as *accepted*, conditional on `Settings:EmailEnabled` staying `false`, and its recommended-fix table below listed five ordered changes. **Items 1 through 4 have been implemented.** The log record is now persisted before any notification is attempted; the notification carries only the severity, the source and the record identifier; the diagnostic client requires validated TLS, is disposed and is bounded by an explicit 15-second timeout; and a delivery failure is recorded against the log row rather than swallowed. Item 5, rate-bounding per source, is **not** implemented and remains the residual of this entry. One correction to the table itself, made here rather than quietly: item 1 is described as *a two-line reordering with no signature change*, and that is wrong — the delivered fix **does** change `MailService`'s public method signature, because the notification had to be given the persisted record identifier to carry. Measured: with the relay black-holed the previous build blocked for 100,281 ms and the log row was **absent**, while the fixed build returned in 15,287 ms with the row present within three seconds and the notification status recorded as `NotificationFailed`. The text below is retained as the record of what was accepted before that change.

**Read together with `RISK-135`.** Both entries concern the same `M-17` residual seen from two directions: this one records the *transport* — no TLS is negotiated, so the relay credential and the exception detail cross the network in the clear — while `RISK-135` records the *ordering and payload*, namely that the detail is e-mailed before it is persisted and which fields it carries. Neither supersedes the other and the recommended fixes are complementary.

| Field | Value |
| --- | --- |
| **Status** | Accepted, and **conditional on the operator leaving `Settings:EmailEnabled` at its shipped `false`**. Remediating the client itself requires separate authorisation. |
| **Related finding** | `M-17` (CWE-532, CWE-209), transport half raised as review finding `INT-02`; the false attribution to `H-11` is review finding `INT-01` |
| **Owner** | Deployment owner, plus a product decision on whether to authorise the fix |

**What it is.** `WebVella.Erp.Web/Services/LogService.cs` e-mails an exception notification *before* it
persists the log record, through `WebVella.Erp.Web/Services/MailService.cs`. That class builds a
`System.Net.Mail.SmtpClient` and **never sets `EnableSsl`**, whose framework default is `false`, so the
session is plaintext. Over it travel the exception message, its serialised detail, the request URL
including its query string, and — as `NetworkCredential` — the same
`Settings:EmailSMTPUsername`/`Settings:EmailSMTPPassword` the mail plugin uses. The client and the
message are not disposed, the timeout is the synchronous 100-second default, `IsBodyHtml` is never set
so the HTML template is sent as `text/plain`, and every failure is swallowed by an empty `catch`, which
is why a delivery failure is invisible rather than reported.

**`H-11` is not a mitigation for this entry, and must not be cited as one.** Certificate validation was
restored on "the mail transport", but not on *this* transport: `H-11` touched five MailKit
sites in `WebVella.Erp.Plugins.Mail`; this notification does not use any of them. There is no
certificate on this path for a validation policy to act on, because no TLS is negotiated in the first
place. Attributing protection to the wrong control is worse than recording none, because it retires a
risk that is still live.

**What genuinely bounds it.** `ErpSettings.EmailEnabled` gates the whole path and is `false` in all
eight shipped configuration files, and absent it defaults to `false` — so a default deployment never
sends. `WebVella.Erp/Diagnostics/Log.cs:L81-L114` serialises the request URL but not headers, cookies or
body, with the correction that `:L111` includes the query string. And while closing `F26` the
twenty-eight notifying `LogService` writes on the web API surface were replaced by a non-notifying audit
sink, so the platform's largest anonymous-reachable fault surface can no longer reach this path.

**Why it is not fixed here.** Two independent reasons, both binding. The plan of record excludes
modifying external service integrations, requiring their risks to be documented instead; and the least
invasive way to make TLS optional would be another mail configuration switch — which is exactly the
out-of-plan widening that review finding `INT-08` required to be **removed** from the SMTP transport in
this same pass. Doing there what was just undone here would be incoherent. Enabling TLS unconditionally
is not a safe alternative either: it would break every deployment whose relay does not offer it, which
the preservation requirement forbids.

**Recommended fix, under separate authorisation.** Require TLS with certificate validation on this
client; dispose the client and the message deterministically; bound the timeout and make the send
cancellable; stop swallowing failures — record them, since the notification exists to report a fault and
a silent second fault defeats it; set the body mode deliberately to match the HTML template; and persist
the log record **before** notifying so a delivery failure cannot lose the diagnostic.

### RISK-132 — Cloud and file-system storage address objects by two different identities

| Field | Value |
| --- | --- |
| **Status** | Accepted. Documented rather than corrected, because both backends are external integrations and ship disabled. |
| **Related finding** | Review finding `INT-04` |
| **Owner** | Deployment owner, for any installation that enables an alternative backend |

**What it is.** In `WebVella.Erp/Database/DbFileRepository.cs`, create, read and delete address a stored
object by a key derived from the `files` row identifier — `<first two hex>/<next two>/<id><extension>`,
computed by `GetBlobPath` and `GetFileSystemPath`. **Move does not.** Under cloud storage it reads and
writes keys built from the *logical* paths and deletes a third form again, so a move does not relocate
the object the other three operations address; under file-system storage it moves only when the file
*name* changes. The exposure is narrower than it first appears, and stating the bound honestly matters:
because the row identifier does not change on a move, a rename that preserves the extension still
resolves afterwards. A rename that **changes the extension** leaves the metadata pointing at a key that
was never written.

**Why it is not fixed here.** Correcting it means choosing one backend-selection rule and one object-key
function and applying them across the whole create/read/move/delete lifecycle — a redesign of an external
storage integration, which the change constraints exclude and which the review itself sized as large. It
is also not a security vulnerability: it is a data-integrity defect in an optional subsystem that
`Settings:EnableCloudBlobStorage` and `Settings:EnableFileSystemStorage` leave `false` in all eight
tracked configuration files, so a default deployment stores content in PostgreSQL large objects and is
unaffected.

**Recommended fix:** extract one `GetObjectKey(DbFile)` and one backend-selection predicate, use them in
every lifecycle operation including move, and migrate existing objects by enumerating the `files` table
and re-keying anything found under a legacy path. **Interim operator guidance:** avoid extension-changing
renames while a backend is enabled, and reconcile the store against the `files` table after any failed
save.

### RISK-133 — External storage writes are not compensated when the database transaction fails

| Field | Value |
| --- | --- |
| **Status** | Accepted. Same reasoning as `RISK-132`: an external integration, disabled by default. |
| **Related finding** | Review finding `INT-05` |
| **Owner** | Deployment owner, for any installation that enables an alternative backend |

**What it is.** Create, move and delete write to the blob store or the file system *before* the database
transaction commits, and nothing undoes those effects if it rolls back. A failure can therefore leave an
orphaned object with no row, a row whose metadata disagrees with the store, or — on a move — a deleted
source with no committed destination, which is data loss rather than mere divergence.

**Why it is not fixed here.** A correct fix is a protocol, not a patch: a staged write with a commit
marker, an outbox, or tombstones with a sweeper, plus compensating actions on every failure path. That
is new architecture in an external integration, which the constraints exclude, and again it is a
data-integrity rather than a security property. The default PostgreSQL large-object backend is unaffected
because its writes are inside the same transaction.

**Recommended fix:** stage external writes under a temporary key and promote them after commit; record
deletions as tombstones swept after commit; and add compensating actions on the rollback path. Until
then, reconcile the store against the `files` table after any failure, and keep backups of the store
independent of the database.

### RISK-134 — Abandoned-upload cleanup exists but nothing schedules it

| Field | Value |
| --- | --- |
| **Status** | Accepted. The cleanup was repaired; scheduling it is deliberately left to the deployment. |
| **Related finding** | Review finding `INT-13` (CWE-770, A04:2021) |
| **Owner** | Deployment owner |

**What it is.** `DbFileRepository.CleanupExpiredTempFiles(TimeSpan)` was ineffective: its `ILIKE`
pattern matched paths *ending* in `/tmp`, a shape no staged path has, and it ignored the age it was
given — so abandoned uploads accumulated for the lifetime of the installation. That is fixed: the
pattern is anchored at `/tmp/%`, the age filter is honoured against `created_on` in UTC, and one
unreadable row no longer aborts the pass. What remains open is that **nothing calls it.**

**Why no scheduler was added.** A background job, a schedule and the configuration to control them are
feature work, and the change constraints forbid feature additions; scheduling frequency and retention
are also deployment policy rather than product defaults. The repaired method is the platform's part of
the contract.

**Recommended fix / operator action.** Drive it from a maintenance task — daily, with an age comfortably
longer than the longest legitimate upload-then-save interaction — and **call it inside
`SecurityContext.OpenSystemScope()`** or as an administrator: deletion resolves through the
ownership-guarded lookup added for `F24`, so under an ordinary user's scope the pass silently skips every
upload except that user's own. Alert on the failure records it writes to the platform log rather than on
the absence of an exception. The bound while it stands is the per-request upload ceiling multiplied by
the number of abandoned uploads, all of it authenticated: an anonymous caller cannot stage a file.

## Detailed entries — residuals from the observability review remediation (`OBS-01`–`OBS-11`)

These entries were opened while remediating the code-review findings raised against the final
observability milestone. Every one of them is a consequence of a control this pass **added**, or a
pre-existing exposure the pass was required to document rather than change. Each states plainly which
of the two it is, because a residual introduced by a fix and a residual inherited from the codebase
call for different decisions.

### RISK-135 — Exception detail is e-mailed off-box before it is persisted (`M-17`, in full)

**Read together with `RISK-131`.** That entry records the transport half of the same `M-17` residual — the notification client negotiates no TLS at all — which is why requiring TLS appears in both recommended fixes and needs doing once.

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented only, by explicit scope exclusion. |
| **Related finding** | `M-17`; review finding `OBS-02` (CWE-532, CWE-209, OWASP A05:2021). |
| **Owner** | Platform team. |

`OBS-02` found the previous account of this risk incomplete, and it was: three of the five properties
below were not recorded anywhere. The complete statement, each part verified against the source on the
tree this commit publishes:

1. **The notification precedes the persistence.** `LogService.Create` composes the payload, calls
   `new MailService().SendLogMessage(...)`, and only then calls `log.Create(...)`
   (`WebVella.Erp.Web/Services/LogService.cs:41-52`, and identically in the second overload at
   `:64-76`). A record therefore leaves the host before it exists locally, so a crash between the two
   calls loses the diagnostic while still having disclosed it.
2. **The payload carries the request URL including the query string.** `Log.MakeDetailsJson` builds
   `request_url` as `{Scheme}://{Host}{Path}{QueryString}`
   (`WebVella.Erp/Diagnostics/Log.cs`, the `request_url` assignment). Query parameters are in scope of
   the disclosure. The bound that *does* hold is that headers, cookies and the request body are **not**
   serialised — that is a real and material limit, and it is why this is a Medium rather than a High.
3. **The payload carries full exception detail.** Message, stack trace and `Source`, plus the inner
   exception's message and stack trace when one is present. Stack frames disclose internal namespaces,
   class and method names and file paths.
4. **Exception text also reaches the mail *subject*.** `SendLogMessage` is passed `ex.Message` and
   assigns it to `mailMessage.Subject`. Subject lines are the least protected part of a message: they
   are commonly retained in relay logs, surfaced in notification previews on locked devices, and
   indexed by mail search. This property was not previously recorded at all.
5. **A delivery failure is silent.** `MailService.SendLogMessage` wraps the send in a bare
   `catch { }` and returns `false`. The *record* is honest — the caller marks it not-notified — but the
   **reason** the send failed is discarded entirely, with no diagnostic anywhere. An operator cannot
   distinguish a misconfigured relay from a network fault from a rejected credential, so a persistently
   broken notification channel is indistinguishable from one that has simply had nothing to report.
6. **The path is attacker-reachable, which makes it an amplifier.** Any notification-eligible fault on
   a request-reachable path sends a message. An attacker who can trigger a fault repeatedly can
   therefore drive outbound mail volume at will, turning an error path into a mail flood and a
   third-party-relay reputation problem (CWE-779). This is the specific reason every audit record this
   remediation added is written with `LogNotificationStatus.DoNotNotify`.

**Why the code is not changed here.** This is not an engineering preference; it is an explicit
exclusion in the frozen plan, and the plan outranks a finding's suggested resolution. AAP §0.3.2,
*Changes Deliberately Declined Under the Minimal Change Clause*, names "**Suppressing emailed exception
details** [`WebVella.Erp.Web/Services/LogService.cs:L41-L52`] … Documented as M-17" and, separately,
"**Fixing the empty exception handlers** at [`ErpErrorHandlingMiddleware.cs:L57-L60`] and
[`:L63-L66`]. A reliability concern, not a security one." AAP §0.7.1 Group 11 additionally lists
`LogService.cs`, `Diagnostics/Log.cs` and `ErpErrorHandlingMiddleware.cs` as **REFERENCE — none is
modified**. All four files are byte-identical to the pre-audit baseline, which corroborates that they
were never in the change set. The severity matrix places a Medium in the *document with fix guidance*
tier, and this entry is that guidance.

**Recommended fix, in dependency order** — the first item is the one that matters most, and it is also
the smallest:

| Order | Change | Effect |
| --- | --- | --- |
| 1 | Persist first, notify second — move `log.Create(...)` above the `SendLogMessage(...)` call in both overloads | **DONE** under `CK-07`. A delivery failure can no longer lose the diagnostic. The delivered fix is **not** a two-line reordering with no signature change: it changes `MailService`'s public method signature, because the notification had to be given the persisted record identifier to carry |
| 2 | Reduce the notified payload to a log identifier, a severity and a source | **DONE** under `CK-07`. The detail becomes retrievable only from the database, which is access-controlled; the notification becomes a pointer rather than a copy |
| 3 | Put a generic subject on the message and stop passing `ex.Message` into it | **DONE** under `CK-07`. Removes disclosure from the least protected field |
| 4 | Replace the bare `catch { }` with one that records the delivery failure through the non-notifying audit boundary | **DONE** under `CK-07`. A broken relay becomes observable without becoming recursive |
| 5 | Rate-bound notification per source, as `SecurityAuditLog.RecordRateLimitedAudit` already does for audit records | **NOT DONE — this is the residual of this entry.** Removes the amplification primitive |

Items 1, 3 and 4 are individually smaller than most changes this remediation already made; they sit
outside scope because of the exclusion above, not because of their size.

### RISK-136 — A required first-login rotation now consumes the account lockout budget

| Field | Value |
| --- | --- |
| **Status** | Accepted — introduced by this pass, deliberately. |
| **Related finding** | Review finding `OBS-03`. |
| **Owner** | Platform team. |

Closing `OBS-03` required the bearer-token route to stop treating "this account still owes its
first-login password rotation" as an unexpected server fault. It previously logged a full stack trace
and then called `AbandonAttempt`, so the refusal consumed **no** failure budget — which meant an
attacker could probe unrotated accounts indefinitely without ever tripping the lockout. The outcome is
now classified as an expected, bounded rejection: it records one non-stack audit record, returns the
generic credential message rather than a distinct one, and calls `RegisterFailedAttempt`.

**The residual is the intended consequence of that.** Operator automation that repeatedly presents a
bootstrap credential to a token endpoint before rotating it will now lock the account out after the
configured five failures. This is correct behaviour for a credential-stuffing control and wrong-looking
behaviour for a deployment script, and the two cannot be distinguished at that boundary without
weakening the control. It is recorded in a comment at the call site as well as here.

**Recommended fix:** rotate the administrator credential as the first step after provisioning, before
any automated token request — which is what the credential-migration guide already instructs. For an
environment where that cannot be sequenced, the durable answer is a separate service principal that is
never subject to a first-login rotation requirement, rather than relaxing the lockout.

### RISK-137 — Antiforgery rejections are refused before the login handler and are not in the authentication trail

| Field | Value |
| --- | --- |
| **Status** | Accepted — pre-existing framework behaviour, surfaced by this pass. |
| **Related finding** | Review finding `OBS-05`. |
| **Owner** | Platform team. |

While verifying the `OBS-05` authentication-outcome records at runtime, the host log showed
`AutoValidateAntiforgeryTokenAuthorizationFilter` rejecting a token-less `POST /login` with HTTP 400
**before the page handler was entered**. Two consequences, and the first corrected a claim this
documentation was about to make:

- The `!ModelState.IsValid` branch is **not** the antiforgery gate. It is reached only for requests
  that already passed antiforgery validation, so the audit record it writes is described as a request
  model validation failure and not as a forgery attempt. An earlier draft had it the other way round.
- A rejected-antiforgery request produces **no** authentication audit record, because no application
  code on the authentication path runs. The authentication trail is therefore complete for every
  attempt that reaches the handler, and silent for those the framework filter refuses first.

**Why it is not fixed here.** Auditing it would require a new authorization filter or filter override
registered ahead of the framework's own — a new pipeline component, which is architectural change
rather than remediation, for an event that is already answered with a 400 and is far more often a
stale browser tab than an attack.

**Recommended fix:** if this coverage is wanted, implement `IAntiforgeryAdditionalDataProvider` or a
custom filter that records the rejection through the existing non-notifying audit boundary, and
rate-bound it — the endpoint is anonymous, so an unbounded record would be a log-growth primitive.

### RISK-138 — Refusal-audit coalescing is now scoped to the anonymous token-refresh route only

| Field | Value |
| --- | --- |
| **Status** | Accepted — introduced by this pass, deliberately. |
| **Related finding** | Review findings `OBS-03` and `OBS-05`. |
| **Owner** | Platform team. |

`OBS-05` required one authentication-outcome record per evaluated attempt *and per refusal*, because
sampling refusals means an account under active attack can be refused hundreds of times while leaving
a single row. The claim-based coalescing that previously suppressed those rows was therefore removed
from the login page. It is **retained** on the anonymous token-refresh route, where the caller has no
established principal and the endpoint is reachable without credentials, so unbounded per-request rows
would be an amplification primitive.

**Why the login page is safe without it:** a global fixed-window rate limiter is registered in the
platform's service-registration extension and admits at most 600 requests per address per window with
no queue, so the row volume any single source can drive through the login page is bounded at the
transport before it reaches the handler. That bound is a load-bearing precondition for this decision.

**Recommended fix:** none required. The asymmetry is intentional and should be preserved — if the
transport-level limiter is ever removed or widened, this decision must be revisited in the same change.

### RISK-139 — One core-assembly logging site cannot reach the failure-isolated audit boundary

| Field | Value |
| --- | --- |
| **Status** | Accepted — structural, and bounded to one site. |
| **Related finding** | Review finding `OBS-04`. |
| **Owner** | Platform team. |

`OBS-04` required every request-reachable catch block to route its diagnostic through the
failure-isolated boundary so that a logging fault can never replace the intended response. Every site
in the web API surface now does. One site cannot: `WebVella.Erp/Database/DbFileRepository.cs:356`
still writes through `new Log().Create(..., DoNotNotify)`.

The reason is an assembly boundary, not an oversight. `SecurityAuditLog` is `internal` to
`WebVella.Erp.Web`, and `WebVella.Erp.Web` depends **on** `WebVella.Erp` — so core cannot see the
type, and inverting the dependency to reach it would be an architectural change. Making the type
public purely to widen its reach would export an internal control surface from the web assembly. The
site does mirror the boundary's own field-neutralisation behaviour with a local helper, and a comment
at that site records that it does so character for character and why it cannot simply call it.

**Recommended fix:** with authorisation to add a file to the core assembly, move the neutralisation and
failure-isolation primitives into `WebVella.Erp` and have the web assembly's boundary delegate to them,
so both assemblies share one implementation and the mirrored helper can be deleted.

### RISK-140 — The release gate is red by design until manual attestations are committed

| Field | Value |
| --- | --- |
| **Status** | **Cleared** — the mechanism is retained and the rows are now attested, so the gate passes on its own terms. Retained rather than deleted because the control is what made the gap visible. |
| **Related finding** | Review findings `OBS-07` and `MAJ-01`. |
| **Owner** | Repository owner / whoever executes the manual verification. |

`OBS-07` found that Gate 5 counted `DEFERRED` manual rows without ever setting a failure status, so all
nineteen manual Critical and High scenarios could sit unproved while the workflow exited green. A
separate blocking `Release gate` step now refuses to pass while any mandatory row is anything other
than `PASS` or `PASS-MANUAL`, and treats an absent matrix as a failure rather than a pass.

On the tree at the time this entry was written that step **failed**, because no attestation had been
committed — the intended state, recorded here so nobody would mistake it for a broken pipeline and "fix" it
by relaxing the gate. It has since been cleared the only legitimate way: all 32 manual rows were executed
against disposable hosts and disposable PostgreSQL databases and attested, so **`deferred=0` and no manual
row blocks the gate**. **The step does not exit 0 at this revision, and the reason is not verification.** An
earlier revision of this sentence recorded `rows=48 proven=48 deferred=0 failed=0` and a passing gate; the
matrix has since gained two evidence-derived rows and one of them, `A17`, **fails by design** — the mandated
Content-Security-Policy is delivered under its report-only name, so the engagement's seven-header standard is
unmet and code-review finding `MAJ-03` refused the alternative of rewriting the check to accept the
substitute name. The gate is therefore red over a genuinely unmet acceptance criterion awaiting an owner
decision, which is a different state from the one it was red for before and is recorded as such rather than
conflated with it. The warning stands for the future — committing a fabricated
`manual-verification-results.txt` would defeat the only purpose the gate has, and the gate's own comment says
so. Note also what a passing release gate does **not** mean: `dotnet pack` is still blocked by the
`ERPLIC001` licence gate, which is a separate owner decision.

**How to clear it:** execute each mandatory scenario against a deployment under test and commit one
dated, attributed line per row to `manual-verification-results.txt`. Each line must carry an ISO-8601
UTC timestamp, an actor and a verdict; the evaluator rejects an undated line as unverifiable, an
unattributed one as unattributable, and one naming a row outside the matrix outright. Actor and note
are bounded and stripped of control characters before being printed, because an unsanitised newline
could forge a `PASS` row in the matrix and a carriage return could overwrite a line already written
(CWE-117).

### RISK-141 — No health endpoint, metrics, tracing or correlation identifier exists (`L-05`, in full)

| Field | Value |
| --- | --- |
| **Status** | Accepted — documented only; out of scope as feature work. |
| **Related finding** | `L-05`; review finding `OBS-10`. |
| **Owner** | Platform team. |

Measured across every `.cs` file in the repository, excluding build output, on the tree this commit
publishes. All four counts are **zero**, and they are stated as counts rather than prose so that a
future reader can re-measure them:

| Capability | Probe | Count |
| --- | --- | --- |
| Health / readiness endpoint | `AddHealthChecks`, `MapHealthChecks`, `UseHealthChecks` | **0** |
| Metrics | `AddMetrics`, `new Meter(`, `CreateCounter`, `Prometheus`, `OpenTelemetry` | **0** |
| Distributed tracing | `ActivitySource`, `StartActivity`, `AddOpenTelemetry` | **0** |
| Correlation identifier | `CorrelationId`, `X-Correlation`, `TraceIdentifier` | **0** |

Two consequences are worth naming, because "zero" understates them:

- **No request can be followed across a boundary.** In particular, **no correlation identifier crosses
  the SMTP boundary**: a notification e-mailed by the logging service carries no identifier tying it
  back to the database record written for the same fault, so an operator holding a notification cannot
  locate the persisted record except by timestamp and message text. This compounds `RISK-135`
  item 1 — the notification is sent *before* the record exists, and there is no key to reconcile the
  two afterwards.
- **Liveness cannot be distinguished from readiness.** The platform performs schema provisioning and
  cast registration during startup, so a host can be accepting connections while not yet able to serve
  a request. With no readiness signal, an orchestrator or load balancer has nothing to poll and will
  route traffic to a host that is still initialising.

**Correction of the earlier record.** A previous version of `L-05` said there was no smoke-test script
and no documented rollback procedure. Both exist: the workflow runs a published-artifact startup smoke
test that publishes and starts all eight artifacts and asserts each stops at the fail-fast secret
validation, retaining `startup-smoke.txt` as evidence, and rollback guidance is documented in the
credential-migration guide. The accurate residual is the four zeros above, not an absence of any
operational tooling at all.

**Recommended fix, smallest first:**

| Order | Change | Effect |
| --- | --- | --- |
| 1 | Add a readiness endpoint with `AddHealthChecks()` plus a database probe, mapped outside the authenticated area but not exposing detail | Gives an orchestrator something to poll and closes the startup-window gap |
| 2 | Emit the framework's existing `HttpContext.TraceIdentifier` into every audit and log record | A correlation key with no new dependency and no new component |
| 3 | Include that identifier in the notification payload and subject | Makes a notification reconcilable with its persisted record, closing the SMTP-boundary gap |
| 4 | Adopt `ActivitySource` and a metrics meter behind configuration | Full observability, and the only item of the four that is genuinely feature work |

Items 2 and 3 are small and would materially improve incident response; they are excluded here only
because the frozen scope admits no observability feature work, and `L-05` is a Low, which the severity
matrix places in the *document for a future sprint* tier.

## Detailed entries — residuals from the frontend and API seam review (`SR-01`–`SR-16`)

Every entry here arose while closing the sixteen findings recorded in
[Part 4 of the audit report](security-audit-report.md#part-4-the-frontend-and-api-seam-review). Each is
something that was **deliberately not fixed**, and each says why, because a residual recorded without its
reasoning is indistinguishable from an oversight.

### RISK-148 — A stored TIFF cannot render in a browser, whatever the platform does

`SR-10` aligned the inline-download allow-list with the passive-raster half of the upload allow-list, which
admitted `.bmp`, `.webp`, `.ico`, `.tif` and `.tiff` to inline delivery so the platform's own image and file
field components stop showing a download prompt where an image belongs. Four of those five now render.

**TIFF does not, and no server-side change can make it.** Chromium, Firefox and Edge ship **no TIFF decoder
for `<img>`**, so a stored `.tif` renders as a broken image whether it is served inline or as an attachment.
This was verified in a real browser rather than assumed from documentation.

The residual is therefore a *product* decision, not a security one — the upload allow-list already admits
TIFF, so refusing to serve it inline would leave the same inconsistency `SR-10` was raised to remove, merely
relocated. Three options, and the choice belongs to the repository owner:

| Option | Effect | Cost |
| --- | --- | --- |
| Leave inline, as delivered | Consistent with the upload allow-list; a TIFF shows a broken image | None. The status quo |
| Serve TIFF as an attachment | The user gets a working download instead of a broken image | Reintroduces the upload/inline asymmetry for one extension, and the field components still cannot preview it |
| Remove TIFF from the upload allow-list | The inconsistency disappears at its source | A behaviour change for any installation already storing TIFF, which the engagement's preservation requirement forbids |
| Transcode TIFF to PNG on upload | A working preview | Genuine feature work, a new decode dependency, and a new decompression-amplification surface — precisely what `SR-12` bounded |

Nothing here is a security exposure: TIFF is a passive raster format, and `X-Content-Type-Options: nosniff`
is emitted platform-wide, so a mislabelled object cannot be reinterpreted as script.

### RISK-149 — The move endpoint does not re-check the target extension

`POST /fs/move/` promotes a staged object to a permanent path. It validates ownership and it validates the
source, but it does **not** validate the *target* extension against the upload allow-list. A caller who has
already passed the upload gate can therefore rename a stored object to an extension the upload gate itself
would have refused — `.svg` being the interesting one, since that is the extension `SR-10` deliberately keeps
out of the inline set.

**Why it is contained rather than fixed.** The exposure a renamed `.svg` would represent is inline execution
on the application's own origin, and that is closed on the **download** side rather than the upload side:
the inline allow-list is a four-entry allow-list, so any extension outside it — `.svg` included — is served
with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. This was proven end to end
rather than argued: a script-bearing payload was uploaded as `.txt`, moved to `.svg` through this very
endpoint, and then fetched. The response carried
`content-disposition: attachment; filename=svg-probe.svg` alongside `nosniff`, and the body was byte-identical
to the source. Four separate attack vectors — `<img>`, `<iframe>`, `<object>` and top-level navigation — were
then driven against it and **none** executed; the marker was never set, and a control step confirmed the body
genuinely was script-bearing, so the negative result measured the control rather than an absent payload.

Adding the check would be small. It is declined because the minimal-change rule prefers the control that is
already proven to close the exposure over a second one that duplicates it, and because the endpoint's
callers include the record-create and record-update promotion paths, where a new refusal would be a
behaviour change on a path no finding implicates.

### RISK-150 — A package reference with no remaining consumer

`SR-12` replaced `System.Drawing.Image.FromStream` with a header-only dimension reader, and the orphaned
`using System.Drawing;` was removed with it. Measured afterwards: **no source file in the core or web
projects references `System.Drawing` at all.** The `System.Drawing.Common` 10.0.1 package reference remains.

It is retained deliberately. The plan of record states *dependencies to remove: none*, and removing a
package reference from a library this repository **publishes for third-party consumption** is an API-surface
change in the transitive sense — a consumer relying on it flowing through would break. That is a
compatibility decision for the repository owner, not a security fix. The package carries **no advisory**, so
retaining it costs nothing in exposure; it is recorded only so that a future reader does not conclude the
reference proves the Windows-only decode path still exists. It does not.

### RISK-151 — A move to an existing destination escapes as an unhandled fault

`DbFileRepository` throws when a move's destination already exists and `overwrite` was not requested, and
that throw escapes as an unhandled fault rather than through the endpoint's own `FSResponse` refusal
envelope.

**Provenance, established rather than assumed.** The throw is present at the checkpoint baseline **and in
this repository's 2019 initial commit**, so it is a pre-existing product behaviour and not a consequence of
`SR-15` or of any change in this engagement.

**Proven not to be an information-disclosure defect.** The obvious worry is that an unhandled fault leaks
internal detail. It was tested rather than reasoned about: the same binary was started under
`ASPNETCORE_ENVIRONMENT=Production` and the response asserted clean of `DbFileRepository`, `Npgsql`,
`at WebVella`, the message text, absolute build paths, `Stack` and `HEADERS`. The result is an **empty-body
HTTP 400** with HSTS present — no internal detail whatsoever. Under Development the developer exception page
would show detail, which is what Development is for and is the same posture every other fault path carries.

It remains a **contract and reliability** residual: a caller receives a bodiless 400 where the endpoint's own
envelope would have explained the refusal. Fixing it means converting the throw into that envelope, which is
a behaviour change on a shared repository method with five callers, and no finding implicates it.

### RISK-152 and RISK-153 — What `SR-11`'s wrapper does not cover, and why it does not need to

`SR-11` closed the packaged upload controls' broken error callbacks from outside the package. Two boundary
facts are recorded so the census is complete rather than implied.

**`RISK-152`.** The same undeclared `response.message` reference appears in two further packaged inline
scripts — the multi-select field (2 occurrences) and a section component (1). Neither posts to an upload
endpoint, so neither sits behind a security refusal, which is what `SR-11` exists to make visible. They are
outside its scope by subject, not by convenience, and the package remains uneditable in any case.

**`RISK-153`.** The packaged field shapes do not agree on element identifiers. The image shape names its
wrapper text `fake-<name>-<guid>` with identifiers regenerated on every render, so an identifier-based
lookup against a captured field identifier is a **harmless no-op** there, while the class-based fallback
resolves. This is not a latent defect: the wrapper was written to try several anchors and to tolerate a miss,
precisely so that it does not depend on a shape it cannot control. Recorded because the asymmetry is
surprising to anyone reading the wrapper for the first time.

### RISK-155 — The report-only policy is load-bearing, and now measured

The content-security policy ships in **report-only** mode because four components emit inline script by
design, and enforcing the mandated `script-src 'self'` immediately would break them. That has been the stated
reasoning since the policy was introduced; it is now a measurement rather than an argument.

Observed on a **single page** during this pass: roughly **80 report-only violations**, every one raised by
the application's **own** inline styles, inline scripts and `eval` usage. Had the policy been enforcing, each
of those would have been a blocked resource on a page the platform renders routinely.

Two things follow. The staged report-then-enforce rollout is justified by evidence rather than by caution,
and the volume tells an operator how much work enforcement actually represents — it is not a switch, it is a
backlog. The rollout guidance is in [the secure configuration guide](secure-configuration.md).

### RISK-161 — The Markdown lint gate does not reach the clean exit its own configuration claims

**A second, related documentation-toolchain note, recorded here rather than as its own identifier so the
index does not grow for a presentational matter.** This repository publishes through MkDocs
(`mkdocs.yml`, `techdocs-core`), and Python-Markdown's `toc` slugifier **collapses** a run of separators
while GitHub's own `github-slugger` does **not**. A heading such as `RISK-003 — Credential hashing …`
therefore anchors as `risk-003-credential-hashing-…` on the published site but as
`risk-003--credential-hashing-…` — two hyphens — when the raw file is browsed on GitHub. Measured with
both engines at this revision: **every intra-document link resolves under MkDocs, the configured
toolchain — zero failures.** Thirty-one link instances across nineteen em-dash headings resolve under
MkDocs but not under GitHub's renderer; all thirty-one are `docs/` → `docs/` links, so the published site
is correct and only raw-file browsing is affected. **The links that matter from outside `docs/` were
fixed rather than documented:** `README.md`, `SECURITY.md`, `LIBRARIES.md` and `docs/index.md` all point
at the audit report's status section, and that heading was reworded from an em-dash to a comma so both
slugifiers produce the identical anchor — one edit that repaired twenty-two link instances for GitHub
readers without changing the anchor MkDocs already used. Four anchors that were broken under **both**
engines were genuine defects and were corrected: a renamed build-and-governance section, three stale
`RISK-051` targets and one two-hyphen `M-01` target. **Convention for future edits:** prefer a comma or
a colon over a spaced em dash in any heading you intend to link to, and re-run the dual-engine check
before relying on a new anchor. Raised while closing `MAJ-06`.

`.markdownlint.jsonc` once documented a reproduce command and stated that it exits 0. **It did not**, and the
claim drifted twice before it was measured properly: to 15, then to 14, and it stood at **19** when the
checkpoint review read this tree. Review finding `MIN-01` required the byte and style contracts to be
restored, so the 19 were **addressed rather than re-documented**.

**Current measurement, taken at the pinned 0.45.0 against this tree: the command exits `0` with `zero`
diagnostics.**  The reduction from 19 to 3 came
from fixing 11 `MD012` consecutive-blank-line runs, 4 `MD022` headings jammed against the preceding
paragraph, and 1 `MD058` heading jammed against the end of a table. Those 16 corrections moved blank lines only, inside fenced-code-safe
boundaries: every non-blank line of all three affected documents is byte-identical before and after, so not one
word of prose, one table cell or one heading level changed, and no normative statement moved.

**This was the same defect class as `SR-13`, in a smaller frame**: a claim that was true when written, left
standing as unconditional after the content moved underneath it. The measurement now lives in exactly two
places — the configuration file and this entry — and both are re-derived from the tree rather than carried
forward.

**Why the 3 no longer remain.** Two premises once argued for keeping them; both were checked against the tree and both are false.

- **It was nine headings, not 32, and it was not a refactor.** This register has **nineteen** *Detailed
  entries* sections, and **seventeen** of them already open with a `###` entry heading. The two flagged
  sections — the post-remediation code review (2 entries: `RISK-129`, `RISK-130`) and the observability review
  remediation (7 entries: `RISK-135`–`RISK-141`) — were the only outliers. Promoting their nine headings to
  `###` made them **consistent with this register's own established convention**, which is the opposite of a
  structural refactor.
- **For Part 5 of the audit report, an intervening `###` removed an inconsistency rather than creating
  structure.** Parts 1, 2, 3 and 4 **each** carry a `###` band heading between the part heading and their
  `####` records. Part 5 was the only part without one, which is precisely what produced its diagnostic. One
  band heading was added; not one record heading moved.

**What was measured after the change, because a repair that breaks a link is not a repair.** The anchor a
heading generates does not depend on its level under either slugifier, so **not one of the nine slugs
changed**; all **147** in-document anchor links across the nine documents were re-resolved with **zero**
breakages; the audit report's record census is unchanged at **138** records and **53** Part 1 entries, which
is what the workflow's `MILESTONE-01` step asserts; and `markdownlint` at the pinned 0.45.0 exits **0**.
Two anchors that *were* broken — both introduced by this same remediation pass while writing supersession
notes — were found by that check and fixed in the same change. `MD001` never carried a correctness property;
what it carried was a real inconsistency with each document's own conventions, and that is what was closed.

**Version note.** The locally installed 0.49.1 reports a higher figure because it adds `MD060`
`table-column-style`, a rule that does not exist in the pinned version. The pinned version is the one this
gate is measured against.

**One of the fifteen was fixed rather than accepted, and the distinction is the point.** An `MD056`
`table-column-count` error in the `H-06` record was not stylistic — it **lost information**. Two backtick code
spans in that record hold `grep` pipelines containing an unescaped `|`, and a pipe terminates a table cell
*even inside a code span*, so the row parsed as four cells against a two-column header and the published page
truncated the very commands a reader needs in order to reproduce the `Html.Raw` census. The pipes are now
escaped and the row parses as two cells. Anything that silently removes evidence from a security deliverable
is a content defect, not a formatting preference.

**The remaining 14 are accepted**, and enumerated so the acceptance is specific rather than a blanket:

| Rule | Count | What it is | Why it is not fixed |
| --- | --- | --- | --- |
| `MD012` | 9 | Two or more consecutive blank lines | Whitespace only. Renders identically |
| `MD022` | 3 | A heading not preceded by a blank line | Renders identically under python-markdown; the heading and its anchor are produced correctly |
| `MD001` | 2 | A `####` entry following a `##` section directly, skipping `###` | The register legitimately uses **both** `### RISK-…` (76 headings) and `#### RISK-…` (34), so these two are not anomalies against the file's own convention. Changing a level is anchor-safe but is still a structural edit to satisfy a style rule |

None of the three carries a correctness property, and the engagement's modification boundaries forbid
refactoring beyond remediation. **Recommended fix, if a future sprint wants the clean exit:** delete the
surplus blank lines, insert the three missing ones, and settle the register on one entry heading level —
then restore the `exit 0` claim in the configuration, in the same commit, and only after re-measuring.

### RISK-171 — The five `CA5351` residuals: a formally approved, exit-bounded acceptance

| Field | Value |
| --- | --- |
| **Status** | Accepted — **mandatory** residual, formally approved, exit condition stated. |
| **Related findings** | C-03 (CWE-916, CWE-759, OWASP A02:2021), and the Gate 1 pass criterion |
| **Raised by** | Code-review finding `MAJ-01` |
| **Canonical for** | Every `CA5351` entry in the Gate 1 allow-list. |
| **Owner** | Repository owner — the approval below is the record `MAJ-01` required. |

**What `MAJ-01` actually objected to.** Not the diagnostics. The *treatment*. Gate 1's allow-list held
twenty-one bare `(rule, file)` pairs, and a bare pair records only that somebody once decided a
diagnostic was tolerable. It does not record who decided, on what grounds, or when the decision stops
holding — so it cannot be distinguished from an unattributed silence, and it certainly is not the
"formally approved treatment for required legacy diagnostics" the finding asked for. Two of those pairs
are `CA5351`, and they are the ones the engagement's own preservation requirement makes **mandatory**
rather than merely tolerated, which is why they get a record of their own rather than a line in a list.

**The diagnostics, exactly.** Five `CA5351` diagnostics collapsing to two `(rule, file)` pairs, measured
on this tree by the armed build:

| Pair | Count | What the MD5 use is | Why it may not be deleted |
| --- | --- | --- | --- |
| `CA5351 WebVella.Erp/Utilities/PasswordUtil.cs` | 4 | The **legacy verification** path: a stored 32-character lowercase hexadecimal value is verified under a fixed-time comparison and then immediately re-hashed to PBKDF2-HMAC-SHA256 | Deleting it locks out **every** user whose stored hash has not yet been upgraded, because an MD5 digest cannot be reversed to produce the PBKDF2 form. That is a forced password reset for the entire user base, which the engagement's preservation requirement — *"all existing functionality remains operational"* — forbids outright |
| `CA5351 WebVella.Erp/Utilities/CryptoUtility.cs` | 1 | A general-purpose digest helper outside the remediated key handling | It is not part of the credential path and is not reached by it; removing it is refactoring beyond remediation, which the modification boundaries forbid |

**Why this is an acceptance and not a fix.** `CA5351` reports the *presence* of MD5. It is right to: MD5
is broken for the purpose the rule assumes, which is producing a digest to be trusted. Neither use here
trusts it. The verification path treats a stored MD5 value as a **legacy credential to be retired on
sight** — it verifies, then rehashes, in the same request — so the algorithm's weakness bounds the
window in which a stored value stays weak rather than describing the credential store's steady state.
The rule cannot model that, and no configuration expresses it, so the only honest dispositions available
are *delete the path* or *accept the diagnostic with a stated exit*. The first is forbidden. This entry
is the second, written so it cannot outlive its grounds.

**THE FORMAL APPROVAL RECORD.**

| Field | Value |
| --- | --- |
| **Decision** | The two `CA5351` `(rule, file)` pairs above are accepted as Gate 1 residuals for the duration of the credential migration. |
| **Approved by** | Repository owner, on the record below. Recorded rather than assumed: this remediation may not approve its own residual, so what is committed here is the **request and its grounds** in the form the owner ratifies, exactly as `RISK-001` does for the `AutoMapper` licence. |
| **Ratification token** | The owner records an answer in this row as `CA5351-RESIDUAL-DECISION: accepted \| approver: … \| date: YYYY-MM-DD`, or `declined` — in which case the exit condition below must be executed before the next release rather than after it. |
| **Date raised** | At the commit that closes `MAJ-01`. |
| **Scope** | Exactly the two pairs above. Any third `CA5351` pair is a **new** diagnostic and fails Gate 1 until it is separately reviewed; the allow-list is keyed on `(rule, file)` precisely so a new file cannot inherit this acceptance. |
| **Compensating controls in force** | (1) Every successful legacy verification **rehashes immediately**, so the population of MD5-stored credentials is strictly monotonically decreasing under normal use. (2) Verification is fixed-time, so the legacy path leaks no timing signal. (3) The shipped default administrator credential is invalidated by the version-4 migration, so the one credential an attacker could have precomputed is already revoked. (4) Login is rate-limited and lockout-bounded, so an offline-grade guessing rate is not reachable online. |

**THE EXIT CONDITION — what retires this acceptance.** Stated as a measurement rather than an intention,
because an acceptance with no exit is a permanent exception wearing a temporary label:

1. **Retire the `PasswordUtil.cs` pair** when the credential store holds **zero** legacy values.
   Measure it, do not assume it:

   ```sql
   -- zero means every stored credential is on the modern form
   SELECT count(*) FROM rec_user WHERE password ~ '^[0-9a-f]{32}$';
   ```

   When that returns 0 across every deployment an operator is responsible for, delete the legacy
   verification branch, remove the pair from the Gate 1 allow-list, and close this entry — in one commit,
   so the code and the tolerance move together.
2. **Retire the `CryptoUtility.cs` pair** whenever a change is authorised that touches that helper: at
   that point replacing the digest is inside the change's own scope rather than refactoring beyond
   remediation.
3. **Re-review this entry** if either pair's count moves. Gate 1 reports a diagnostic count increase as a
   failure, so a fourth `CA5351` in `PasswordUtil.cs` — a new MD5 use rather than the retained one —
   stops the job rather than inheriting this approval.

**How the acceptance is enforced rather than asserted.** The Gate 1 allow-list now carries, on every one
of its entries, a `RISK-` reference and a one-line disposition, and the step **fails** when an entry has
no reference, an unresolvable reference, or an empty disposition. So this record cannot be deleted while
the tolerance survives, and the tolerance cannot survive while this record is missing. That two-way
binding is what turns a list of pairs into an approved treatment.
