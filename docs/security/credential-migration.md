# Credential Migration

> **Status authority.** This document is **not** the authority for the security posture's status.
> Exactly one surface is: the audit report's
> [Status at this revision, gate by gate](security-audit-report.md#status-at-this-revision-gate-by-gate) section. Where any statement here disagrees
> with it, that section governs and this one is superseded. This guide is authoritative for the **migration procedure** only.
> Recorded under code-review findings `MAJ-06` and `MAJ-12`.

This guide covers the password-hash migration, the operator actions it requires, and rollback.

WebVella ERP stored user passwords as unsalted, single-pass MD5 digests. That is finding `C-03`
([CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html),
[CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html),
OWASP A02:2021), and it is filed as Critical rather than as a "weak cryptography" Medium because the
consequence is a data breach: a leaked password column is recoverable wholesale from precomputed
tables at effectively no cost, and identical passwords produce identical digests, so one cracked
value exposes every account that shares it.

Credentials are now stored as salted, work-factored PBKDF2 values. **The change is backward
compatible by design.** Verification accepts either format, and a legacy value is replaced silently
the next time its owner authenticates successfully. No user is locked out, no password reset is
forced for ordinary users, and there is no downtime. The single credential that *is* forcibly
retired is the administrator password the platform used to ship — see
[the credential the platform used to ship](#the-credential-the-platform-used-to-ship).

The companion documents are the [security audit report](security-audit-report.md), which records
every finding in the mandated eight-field format; the [remediation log](remediation-log.md), which
records what changed and the verification performed for each vulnerability class; the
[risk register](risk-register.md), which records the accepted deviations and standing warnings; and
the [secure configuration guide](secure-configuration.md), which records the secrets an installation
must be supplied before it will start at all.

Line references to `WebVella.Erp/...` describe the code **as audited**, before remediation. They are
the evidence locators for the findings, not pointers into the current tree.

## What changes

| | Before | After |
| --- | --- | --- |
| Algorithm | MD5, a single pass | PBKDF2-HMAC-SHA-256 |
| Salt | **None** | 128 bits, from the operating system CSPRNG, fresh for every credential |
| Iterations | 1 | **600,000** |
| Stored form | 32 lower-case hexadecimal characters | 84 Base64 characters in the ASP.NET Core versioned (V3) payload layout |
| Comparison | string equality, **inside a SQL predicate** | fixed-time comparison, in application code |
| Concurrency | one shared, mutable `MD5` instance | no shared mutable state |

Two secondary findings close as a by-product of the same edit, because they lived in the same file:

- `M-05` ([CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)) —
  the comparison at `WebVella.Erp/Utilities/PasswordUtil.cs:L28-L29` used
  `StringComparer.OrdinalIgnoreCase`, which short-circuits at the first differing character, so its
  duration revealed how many leading characters were already correct.
- `M-06` ([CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)) —
  the single shared `MD5` instance at `WebVella.Erp/Utilities/PasswordUtil.cs:L9`. `MD5` instances
  are not thread-safe, so two simultaneous authentications could interleave inside `ComputeHash` and
  corrupt each other's digest.

### No schema change was required, and none was made

**No schema definition statement was emitted at any point in this migration.** No column was added,
altered or dropped. Two facts make that possible.

The password column was already wide enough. The platform's type converter provisions a password
field as `varchar(500)` — `WebVella.Erp/Database/DBTypeConverter.cs:L57` selects the
`FieldType.PasswordField` case and `:L58` sets `pgType = "varchar(500)"`. The new stored value is
**84 characters**: a 13-byte header, a 16-byte salt and a 32-byte derived subkey make a 61-byte
payload, and Base64 encodes 61 bytes as 84 characters. It fits with a wide margin.

No discriminator column was needed either, because the format of a stored value is inferable from
its shape. That is the subject of the next section.

The declared bounds on the field are metadata, carried by
`WebVella.Erp/Database/FieldTypes/DbPasswordField.cs` alongside the `encrypted` flag; changing them
rewrites a metadata row, not a column definition.

## How a legacy stored value is recognised

**A legacy value is exactly 32 hexadecimal characters.** The old primitive produced a 16-byte MD5
digest at `WebVella.Erp/Utilities/PasswordUtil.cs:L16` and rendered it at `:L18-L20` with
`sBuilder.Append(data[i].ToString("x2"))` — the `x2` format emits exactly two lower-case hexadecimal
characters per byte, so sixteen bytes render as thirty-two characters and never anything else.

A modern value cannot collide with that shape: it is 84 Base64 characters and always begins with
`A`, the encoding of the `0x01` format marker. The test is therefore a length check plus a
hexadecimal-digit scan, and it needs no stored discriminator.

Two deliberate properties of that test are worth stating, because both are load-bearing:

- **Hexadecimal is accepted in either case.** The old primitive only ever emitted lower case, but the
  comparison this remediation replaced was case-insensitive, so a value persisted in upper or mixed
  case by any other route must still be recognised. Failing to recognise one would lock that account
  out, which the requirement that existing credentials keep working forbids. The tolerance costs
  nothing, because a 32-character hexadecimal string cannot collide with the modern format at any
  casing.
- **A malformed stored value fails verification rather than throwing.** A value that is neither a
  well-formed legacy digest nor a well-formed modern payload — truncated, corrupted, or written by
  some third party — returns *false*. It does not raise. This matters because the login path is
  reachable anonymously: a single damaged row must never become a denial of service, or a
  server-error response that discloses internals.

## The primitive now in use

| Parameter | Value |
| --- | --- |
| Key derivation function | PBKDF2 |
| Pseudo-random function | HMAC-SHA-256 |
| Iterations | 600,000 |
| Salt | 16 bytes (128 bits), from the operating system CSPRNG, fresh per credential |
| Derived subkey | 32 bytes (256 bits) |
| Encoding | ASP.NET Core versioned (V3) payload layout, Base64, 84 characters |
| Comparison | fixed-time |

The [OWASP Password Storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
is the authority for these choices, not convenience. It sanctions PBKDF2 explicitly at a high
iteration count, and **600,000 is exactly its floor for PBKDF2-HMAC-SHA-256** — so the configured
work factor meets the named standard rather than approximating it.

The payload is self-describing: it records its own pseudo-random function identifier, its own
iteration count and its own salt length alongside the salt and subkey. That is what allows the work
factor to be raised later without invalidating anything already written, and it is why HMAC-SHA-256
and the V3 layout are not in tension — the format carries the function it used.

**The iteration count is the control, not a tuning knob.** Do not lower it to chase a latency target;
see [login latency is deliberate](#login-latency-is-deliberate) for why the cost is the point.

### One disclosed deviation, and where it is recorded

The engagement's Cryptographic Standards name bcrypt, scrypt or Argon2 at a cost factor of 12 or
above. PBKDF2 is none of those three. **That deviation is disclosed and justified as `RISK-003` in
the [risk register](risk-register.md)**, together with the repository-owner option of substituting a
dedicated bcrypt or Argon2 package if literal compliance with the named algorithms is required. It is
not re-argued here.

Retaining the legacy MD5 code path is likewise a recorded, accepted decision — it is what makes this
migration backward compatible, and it is why a broken-hash analyzer warning is still reported on that
path. It is recorded as `RISK-004` in the [risk register](risk-register.md). Do not delete the legacy
path and do not add a blanket suppression to silence the warning.

Members of the credential utility remain **assembly-internal**, exactly as they were. Every consumer
is in the same assembly, so **no public API contract changed** and no route, verb or response shape
was altered by this migration.

## The upgrade: rehash on next authentication

**This is the work-factor upgrade pattern the OWASP Password Storage guidance prescribes**: rather
than converting stored values in bulk — which is impossible, because a hash cannot be reversed to
recover the plaintext it needs — wait until the user next authenticates, and re-hash at that moment.

The mechanism is three steps:

1. Verification is handed the plaintext the user just supplied and the value currently stored, and
   accepts **either** format.
2. When verification succeeds **and** the stored value is out of date, it reports that fact to its
   caller. A failed attempt never reports it, so a failed attempt can never trigger a write.
3. The caller still holds the plaintext at exactly that moment — and nowhere else — so it re-hashes
   with the modern primitive and persists the result.

The upgrade write is conditional on the same account row and the same stored value that the
verification actually matched; the identifier and the previously stored value are passed to the
upgrade rather than looked up again, so a concurrent change cannot be overwritten by a stale one.

Four properties follow, and together they are what satisfies the engagement's requirement that all
existing functionality be preserved despite a cryptographic format change:

- **Backward compatible.** A credential written by any earlier release still authenticates.
- **No forced reset.** Ordinary users are never asked to choose a new password.
- **No downtime.** There is nothing to run, nothing to schedule and no maintenance window. The
  upgrade happens per user, on that user's next successful login.
- **No lockout.** No account becomes unusable as a result of the format change.

"Out of date" is deliberately broader than "legacy MD5". It also covers a value written at a lower
iteration count or in an older payload version, so **a future increase to the work factor is carried
by this same mechanism with no further code change.**

There is nothing for an operator to do to start this. It is not a batch job and it has no progress to
monitor. An installation simply converges: every account that logs in after the upgrade is stored in
the modern format from that point on, and accounts that never log in keep working whenever they
eventually do.

## Why the credential lookup had to be restructured

This was the enabling change for everything above, so it is worth explaining rather than glossing.

The old lookup computed the digest in application code at
`WebVella.Erp/Api/SecurityManager.cs:L84` — `var encryptedPassword = PasswordUtil.GetMd5Hash(password);`
— and then compared it **inside the SQL predicate** at `:L85`:

```text
SELECT *, $user_role.* FROM user WHERE email ~* @email AND password = @password
```

**A salted hash cannot be compared by SQL equality.** Every stored value carries its own random salt,
so the same password produces a different value in every row; `password = @password` can never match.
The lookup therefore had to be restructured so that the **password comparison happens in application
code** rather than in the query. Adding a salt without moving that comparison would simply have
prevented every login.

**What the shipped query actually is**, stated exactly, because an earlier revision of this section
said the regular-expression predicate had been removed and that is **not** what the code does:

```text
SELECT *, $user_role.* FROM user WHERE email ~* @email PAGE 1 PAGESIZE 2
```

The `AND password = @password` term is gone — that is the change the salted format required, and it is
the whole of it. The `~*` operator is **retained**, and three properties bound it. All three are read
from `WebVella.Erp/Api/SecurityManager.cs` at this commit:

- **The pattern is anchored and fully escaped.** The parameter is not the submitted address; it is
  `BuildExactEmailPattern(email)` (`:L408-L435`), which returns `"^" + Regex.Escape(email) + "$"`. Every
  metacharacter that could open a construct — `\ * + ? | { [ ( ) ^ $ . #` and whitespace — is
  neutralised, and the anchors make the match exact. A caller therefore cannot supply a *pattern* at
  all, only a literal, so the pattern's cost is fixed by its length rather than by its structure.
- **The row count is bounded.** `PAGE 1 PAGESIZE 2` applies `MaxCredentialCandidates` (`:L75`), so the
  server evaluates the match against at most two candidate rows and at most two key derivations follow.
  The bound exists so that a single anonymous request cannot amplify either cost.
- **The authoritative match is still the exact one in application code**, and it always was. The loop
  at `:L294-L299` collects candidates with
  `string.Equals(recordEmail, email, StringComparison.OrdinalIgnoreCase)`, so the database predicate is
  a filter and the ordinal comparison decides. Collecting first, rather than verifying inside the same
  pass, is what lets a case-fold duplicate be counted and reported rather than silently authenticated
  against whichever row the database happened to return.

**Why the operator was kept rather than replaced.** An exact SQL comparison would be case-*sensitive*
against a column that has always matched addresses case-insensitively, so replacing `~*` with `=` would
have locked out every account whose stored address differs in case from what its owner types. Anchoring
and escaping the operand closes the weakness without changing which accounts can sign in, which is the
smaller change and the one the preservation requirement demands.

That single restructure closed two further findings at no additional cost:

- **`H-17`** ([CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html),
  [CWE-625: Permissive Regular Expression](https://cwe.mitre.org/data/definitions/625.html)) — `~*` is
  PostgreSQL's case-insensitive **regular expression** match operator, not a string comparison, and at
  the audit baseline an anonymous caller controlled the pattern by controlling the submitted e-mail
  address, with the server evaluating it once per row over an unbounded row set. Both halves of that are
  closed: the operand is escaped and anchored so no caller-supplied pattern exists, and the row set is
  capped at two. The operator itself remains, deliberately, for the case-folding reason above.
- **`M-05`** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)) — verification in
  application code uses `CryptographicOperations.FixedTimeEquals`, so the timing oracle in the old
  character-by-character comparison is gone. An address that matches no row still costs one key
  derivation, through `PasswordUtil.PerformDummyVerification`, so moving the comparison out of the query
  did not open an account-enumeration channel in its place (CWE-203).

One detail records the same defect from the other side: the utility's own legacy verification helper
at `WebVella.Erp/Utilities/PasswordUtil.cs:L25` had **zero external callers**, precisely *because*
comparison had been pushed into the SQL predicate. A verification routine nobody calls is the
structural symptom of verification happening in the wrong place.

Three write paths were switched to the modern primitive in the same class of change:
`WebVella.Erp/Api/RecordManager.cs:L2017`, inside the encrypted-password branch spanning
`:L2008-L2018`; and `WebVella.Erp/Database/DbRecordRepository.cs:L554` and `:L1856`.

## What the version 4 migration does to existing installations

**The core schema version head was 3.** The provisioning ladder in `WebVella.Erp/ERPService.cs` ran
`if (currentVersion < 1)` at `:L51`, `< 2` at `:L865` and `< 3` at `:L871`, and nothing higher.
Remediation adds an **`if (currentVersion < 4)`** block, so the head is now 4.

### Why this block is indispensable

Every provisioning correction described in this guide — the removed guest grants, the password field's
permissions, the raised length bounds, the retired administrator credential — is written inside the
`currentVersion < 1` gate. **That gate runs exactly once, at first provisioning, and never again.**

A source-only fix therefore protects new installations and nothing else. Without the migration block,
every already-deployed installation keeps the published default administrator password, keeps the
anonymous create and read grants, and keeps an unprotected credential column — **while the source
reads as though all of it had been remediated.** That gap between apparent and actual state is the
whole reason the block exists, and it is the single highest-leverage element of the remediation.

### What the block does

It runs three steps, each individually idempotent, in a deliberately fixed order:

| Step | What it does | Findings |
| --- | --- | --- |
| 1 | Raises the password field's declared length bounds from 6–24 to **12–128**, and assigns the field **administrator-only** read and update permissions where it previously had none at all | `M-13`, `C-02` |
| 2 | **Conditionally** retires the administrator credential earlier releases shipped, and marks the account as requiring a password change at first login | `C-01` |
| 3 | Revokes the over-permissive Guest record grants on the user and role entities | `C-05`, `C-02` |

The order is not incidental. Step 1 raises the bounds *before* step 2 writes a password, so the
replacement credential is written against the bounds this release declares rather than the ones it is
in the middle of replacing.

The whole block runs inside the existing provisioning transaction and **before** the version number is
saved. Any failure rolls the entire migration back without advancing the version, so it is retried on
the next startup rather than leaving an installation half-migrated.

**It writes rows and metadata only — never column or table definitions.** That is a property of *how*
it writes, not merely an intention: the metadata step deliberately bypasses the ordinary field-update
API, because that API issues `ALTER TABLE ... ALTER COLUMN` and `CREATE`/`DROP INDEX` before storing
metadata. Anything added to this block in future must go through the repositories directly for the
same reason.

### The findings it carries, with their locators

| Finding | CWE | Audited location | What was wrong |
| --- | --- | --- | --- |
| `C-01` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | `ERPService.cs:L467` | A literal assigned to `user["password"]` — `[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]`, a hardcoded default administrator password |
| `C-02` | [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | `ERPService.cs:L204-L218` | The `InputPasswordField` block assigned **no field permissions at all**, so the credential hash was readable by any role that could read the user entity |
| `C-05` | [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | `ERPService.cs:L77`, `:L363` | Guest granted **create** on the user entity and on the role entity |
| `C-02` | as above | `ERPService.cs:L79`, `:L366` | Guest granted **read** on the user entity and on the role entity |
| `M-13` | [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | `ERPService.cs:L216-L217` | `password.MinLength = 6;` and `password.MaxLength = 24;` |

### Three of the four guest grants are revoked on existing installations, not four

This distinction is stated precisely because overclaiming it would mislead an operator about their own
exposure:

- The two Guest **create** grants (user entity, `:L77`; role entity, `:L363`) and the Guest **read**
  grant on the **user** entity (`:L79`) are removed from the seed **and** revoked on already-provisioned
  installations by the version 4 migration.
- The Guest **read** grant on the **role** entity (`:L366`) is removed from **the seed only**. A fresh
  installation does not have it; an existing installation keeps it.

The migration that would have carried that fourth revocation to existing installations was withdrawn
as outside the frozen remediation scope — it is a Medium that did not meet the compensating-control
test, and advancing the ladder to version 5 for it would have exceeded the plan. **The migration
ladder head therefore stops at 4.** The residual grant remains an open, documented Medium, recorded
as `RISK-050` in the [risk register](risk-register.md), where the operator remedy is given.

#### Plugin interference on fresh installations — **FIXED at the code-review checkpoint**

This behaviour was originally recorded as out of scope, with the operator left to clean up after it. The
code review escalated it to a **Critical** finding and it is now fixed. It is documented because it
explains why a *freshly provisioned* installation could still carry the grants the migration had just
removed.

**The defect.** On a fresh installation the SDK and Project plugin patches run *after* the core system
entities are initialised, and each rebuilt the `user` and `role` entities' record permissions from
source — re-adding the Guest role to `CanCreate` and `CanRead`. Those patches are gated on the plugin's
own version counter, which defaults to an early value when no plugin-data row exists, which is exactly
the situation on a new database. So the version 4 revocation ran correctly and was then silently
undone. The migration was never at fault; the replay after it was.

Upgraded installations whose plugin-data row already recorded a later version were unaffected, because
the patches did not re-run.

**The fix.** The stale Guest grants were deleted from both plugin patches, so a replay no longer has a
grant to restore. Neither patch now references the Guest role at all. This has a useful side effect for
existing installations: an installation that replays the SDK patch loses the residual role-entity read
grant described above anyway, because the patch restates the entity's full permission set from source
and that source no longer contains it.

The underlying weakness — that the entity-update path **replaces** an entity's whole record-permission
set rather than merging into it — is why the defect was invisible until a fresh provisioning was
observed end to end. It is recorded in the [security audit report](security-audit-report.md).

### The administrator credential is retired conditionally, never unconditionally

Step 2 rewrites the administrator password **if and only if** the stored value is still the one earlier
releases shipped: it must have the legacy 32-character shape *and* verify against the historic literal,
which the migration predicate at `WebVella.Erp/ERPService.cs:L2291` supplies to
`PasswordUtil.VerifyMd5Hash`.

That condition is the point. Retiring the credential unconditionally would overwrite a password an
operator had already chosen and changed — turning a security fix into an outage. Anything else in the
column, including a password the operator set themselves, an already-modern value, or an empty column,
is left exactly as it is.

When the condition does match, the migration rewrites the password to the value supplied in
`Settings:InitialAdministratorPassword` — validated against the policy *before* the write — and sets a
change-required-at-first-login marker on the account. It does not generate a replacement; if the
setting is absent the migration aborts and the schema version stays at 3, so the upgrade is retried on
the next start rather than completing with a credential nobody knows. The marker is carried in the account's existing
preferences value, read-modify-write so that any real preferences the account has accumulated survive
— which is why it needs no schema change either.

### Credential hashes are redacted on read — and the write path must respect the marker

Alongside the field permissions, values of any field carrying the `encrypted` flag are now **redacted
from read projections**, so a stored credential hash never leaves the server regardless of the caller's
role. Redaction is applied at the projection seams rather than at a single choke point, so the
protection survives one layer later being bypassed.

**This is the highest-risk ripple in the whole remediation, and it needs stating explicitly.** A client
that reads a user record, edits one unrelated field and posts the whole record back sends the
*redaction marker* where the hash used to be — it never saw the real hash. The write path must
recognise that marker and **leave the stored credential untouched.** Accepting it as a password would
replace every affected user's credential with a literal marker string: a data-destroying outcome from a
change intended to prevent disclosure.

The write path does recognise it, at four separate guard sites, and a blank value is treated the same
way — both already mean *leave the stored value alone*. Refusing either would break ordinary record
updates. This is recorded as `RISK-047` in the [risk register](risk-register.md), and the round-trip was
verified explicitly after a real interface save — see the manual verification checklist in the
[remediation log](remediation-log.md).

If you maintain a client that posts full user records back to the platform, this is the one behaviour
to re-test after upgrading.

### What operators will see in the interface

Because the password field's permissions become administrator-only, any screen that previously
rendered that field for a non-administrator now hides it. The behaviour is consistent rather than
surprising: the presentation layer already treats an **empty** read permission as denial, at
`WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs:L610`, where a role only gains read access by
appearing in the field's permission list.

**Administrative user-management screens should nevertheless be verified manually after upgrading**,
because they are the screens where the password field is *expected* to remain visible.

## The credential the platform used to ship

Provisioning seeded a first administrator account at `WebVella.Erp/ERPService.cs:L462-L475` with a
literal assigned to `user["password"]` at `:L467`, `user["email"] = "erp@webvella.com";` at `:L468` and
`user["username"] = "administrator";` at `:L469`. **The e-mail address is the account identifier and is
not redacted anywhere in this document set** — it is what an operator types at the sign-in form, and it
is still the shipped address. The password is:

```text
[REDACTED — 3 characters, SHA-256 prefix d24f1f612642b77b]
```

That is finding `C-01` ([CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html),
[CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)). A
three-character dictionary word, published in the source of an open repository, on a known e-mail
address, for an account holding the administrator role, is an authentication bypass in practice.

**It no longer authenticates.** An earlier revision of this section quoted the literal, on the argument
that an operator cannot check their exposure without knowing what to check for. That argument does not
survive scrutiny, and it is withdrawn: an operator does not need the value, because **nothing about the
check requires them to type it.** Two routes settle the question without it:

- **Fingerprint a candidate** rather than compare it: `printf '%s' "$CANDIDATE" | sha256sum | cut -c1-16`
  and compare with the prefix above.
- **Read the stored column**, which is the direct test. A password column still holding a 32-character
  lower-case hexadecimal value has never been used to sign in since the upgrade; whether that value is
  the published one is decided by the migration, not by the operator.

> **The historic value remains in this repository's git history and must be assumed known to anyone who
> has ever seen this repository.** It must never be reinstated as a password on any account, on any
> installation, for any reason — including temporarily during testing. The one place the literal is
> still retained in source is the migration predicate at `WebVella.Erp/ERPService.cs:L2291`, which must
> recognise the value in order to withdraw it; that site is a named, justified exception in the secrets
> gate and is the only one.

### On a fresh installation

Provisioning resolves the initial administrator password in exactly **one** way: from the setting
`Settings:InitialAdministratorPassword`, supplied as the environment variable
`Settings__InitialAdministratorPassword`. The value must satisfy the password policy below, and if it
is absent, blank or non-compliant, **provisioning fails fast** with a message naming only the setting
key — never the value, its length or a digest of it. The account is then marked as requiring a password
change at first login.

**There is no generated fallback, and this changed.** An earlier revision generated a 20-character
password when the setting was absent and printed it once to standard error so an operator could read it
back. That emission was itself a vulnerability (CWE-532, OWASP A09:2021) and was removed under review
finding `OBS-01`: standard error is captured and retained wholesale by every substrate this platform
runs on — systemd's journal, the Docker log driver, IIS stdout redirection, Kubernetes container logs,
CI transcripts — so a notice described as "one-time" was in fact durable plaintext readable by anyone
holding log or host access, and routinely forwarded off-box to aggregation. Requiring your own value is
the only shape of the code that never holds a credential it has to disclose.

If you are looking for the one-time notice because older instructions mentioned it: it no longer
exists, and its absence is not a fault. Supply the setting instead. Every remaining reference to a
generated value in this repository's documentation has been removed for the same reason — the code has
one credential route, and it is yours.

**There is no notice to deliver, because there is no generated value.** `ERPService.ResolveInitialAdministratorPassword` reads `Settings:InitialAdministratorPassword` and throws when it is blank, so provisioning is refused **inside its own transaction**: nothing is persisted, no account is created, the schema version does not advance, and the message names the setting as the remedy without echoing any value. An earlier revision of this document described an additional provisioning route in which it generated a value, probed standard error and standard output to confirm a stream would accept it, and recorded undeliverable notices under a `system_log` source. **None of that exists in the code**, and its removal is the remediation rather than a regression: a notice described as one-time was durable plaintext in every substrate that captures those streams, and a credential the platform invents is one it must disclose. Requiring your own value is the only shape of the code that never holds a credential it has to reveal.

> The one CSPRNG generator still compiled in serves the local `system@webvella.com` account, which exists > only so background work has an identity and which nobody authenticates as. Its value is hashed on write > and is never printed, stored in plaintext or returned. Anyone auditing the credential surface will find > that generator in the source, so it is named here rather than left to look like an oversight.

The steps are:

1. Supply the required secrets before first start. An installation will not start without
   `Settings__ConnectionString` and `Settings__EncryptionKey`. Supply `Settings__Jwt__Key` to the two
   token-issuing hosts as well — but note that it is **not** startup-fatal, so its absence will not
   stop you: those hosts start normally and their bearer-token issue and refresh routes stay disabled
   until a usable key is supplied, while cookie login works throughout. The
   [secure configuration guide](secure-configuration.md#required-settings) sets out the two categories
   and the full key inventory.
2. Supply `Settings__InitialAdministratorPassword` as well. It is **not optional**: there is no
   generated fallback, and provisioning refuses to run without it.
3. Start the application. Provisioning either completes using the password you supplied, or is refused
   with a message naming the setting — there is no third outcome and nothing to capture from any output
   stream. If it was refused, nothing was written, so correct the value and start again.
4. Sign in as **`erp@webvella.com`** and change the password immediately. **The sign-in identifier is
   the e-mail address, not the user name.** The account's `username` is `administrator`, and that value
   authenticates nothing: the login form's field is labelled *Email*
   (`WebVella.Erp.Web/Pages/login.cshtml:L18-L20`) and `SecurityManager` resolves the credential by
   e-mail only. Submitting `administrator` is refused with *Invalid username or password* and consumes
   one of the five attempts the lockout permits — measured, not assumed: against a published Production
   host, `administrator` returned HTTP 200 with that message and wrote an `Authentication failed` audit
   row, while `erp@webvella.com` with the same password returned **302** to `/`. An earlier revision of
   this step said "Sign in as `administrator`", which would have stranded an operator at the one screen
   they cannot afford to be stranded at. The change-required marker is enforced, not advisory:
   interactive login works precisely so the password *can* be changed, but bearer tokens are refused for
   the account until it has been rotated.

### On an upgraded installation

On the first start after upgrading, the version 4 migration detects whether the account still carries
the shipped credential and, if it does, rotates it to the value you supply in
`Settings__InitialAdministratorPassword` and marks the account for rotation. If the password was
already changed, it is left untouched and the setting is not consulted at all.

**That distinction decides whether you need to do anything.** The migration checks the stored value
before it looks at any configuration, so an installation whose administrator password was already
rotated upgrades with nothing supplied. Only an installation still holding the published default needs
the setting — and for that installation the migration will **abort**, rolling back and leaving the
schema version at 3, if the setting is absent. The abort message says so explicitly and names the
setting; the upgrade is retried on the next start once you supply it. This is deliberate: the
alternative is a migration that invents a replacement credential and then has to publish it somewhere
durable, which is the exposure `OBS-01` removed.

Verify afterwards that `"erp"` no longer authenticates and that the schema version reads 4, then sign
in with the value you supplied and rotate it as above.

The value itself is unrecoverable, because the stored form is a one-way hash and the platform keeps no
copy anywhere — there is no notice, no log row and no output stream holding it. What follows are the
**two supported routes back in**, in order of preference. Both have been executed; neither destroys data.

**Route 1 — reset it from another administrator. No database access required.** Sign in with any other
account holding the administrator role and reset the locked-out account's password through the ordinary
user-management screen. This is the route to use whenever such an account exists.

**Route 2 — the emergency reset, when no other administrator account exists.** This needs direct
database access and nothing else. It uses the platform's own legacy-credential compatibility path, so it
adds no mechanism and relies on nothing that is not already exercised by every upgraded installation:

1. Choose a temporary password that satisfies the policy below, and compute its **MD5 hex digest** —
   the legacy stored format this platform still accepts on verification:

    ```bash
    printf '%s' 'YOUR-TEMPORARY-PASSWORD' | md5sum | cut -d' ' -f1
    ```

2. Write that digest into the account's password column, addressing the account by **e-mail**:

    ```sql
    UPDATE rec_user SET password = '<the 32-character digest>'
     WHERE email = 'erp@webvella.com';
    ```

3. Sign in at `/login` as `erp@webvella.com` with the temporary password. Verification accepts the
   legacy shape, authenticates, and **transparently rewrites the column in the modern format** — the
   same upgrade-on-next-authentication mechanism every pre-existing user gets.
4. Change the password immediately through the user-management screen. Step 3 leaves a working
   credential, not a finished job.

*Why this is safe rather than a hack.* It writes a **row**, never a schema object. It cannot be undone
by the version-4 migration, which is version-gated and runs once, and which in any case rewrites the
password only when the stored value verifies against the historic published literal — a digest of your
own temporary password does not. And it leaves the account in exactly the state a legacy installation is
in the moment before its owner next signs in.

*Executed, not asserted.* Against a published Release host in Production posture on a live PostgreSQL
instance: the column was replaced with a 32-character MD5 digest, `POST /login` with the temporary
password returned **302** to `/`, the column was re-read as **84 characters beginning `A`** — the modern
PBKDF2 form — and a second sign-in with the same password returned **302** again with the value
unchanged. The original stored hash was restored afterwards and verified byte-identical.

> **Two things this section used to say, and both are withdrawn.** It said the situation was
> "recoverable and does not require a database edit", and it offered, when no other administrator
> exists, to "set `Settings__InitialAdministratorPassword` and re-provision against an empty database,
> restoring your data afterwards". Re-provisioning seeds a *new* administrator only into an **empty**
> database; restoring your backup over it reinstates the very rows — including the inaccessible account
> — that made you unable to sign in, and there is no supported selective merge that would keep the new
> account and the old data. Following it would have cost a restore and returned an operator to exactly
> where they started. Route 2 above is offered in its place because it was tested.

## The password policy now in force

**Minimum 12 characters, maximum 128.** The 12-character minimum is taken literally from the
engagement's Authentication Hardening standard — *"Minimum password complexity: 12+ characters, mixed
case, numbers, symbols"* — and it replaces the audited minimum of 6 at
`WebVella.Erp/ERPService.cs:L216`.

**The ceiling was raised as part of the same fix, not as an unrelated improvement.** The audited
maximum of 24 at `WebVella.Erp/ERPService.cs:L217` was *itself* an obstacle to strong credentials: a
24-character cap rules out ordinary passphrases and pushes users toward short, complex, memorised
strings — the weaker choice. Raising it to 128 removes that obstacle. Together these are finding
`M-13` ([CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)).

One correction is worth recording, because it changes what the old bounds actually meant: they were
**declarative metadata only.** Every consumer of the field's length bounds was commented out, so
nothing rejected a short password — a one-character password was accepted. The bounds are now
*enforced* by a single validator applied at every boundary where a human chooses a credential: both
user-save paths, the initial-administrator resolution, and the generic record-write path reached
through the user record endpoint.

The validator is deliberately **not** applied inside the hashing primitive, and **not** on the legacy
rehash path. Applying it to the rehash path would lock out every existing user whose current password
predates the policy — the exact forced reset this migration exists to avoid. That decision is recorded
as `RISK-046` in the [risk register](risk-register.md).

Verification tolerates an over-long submitted password by rejecting it before any derivation is
attempted, so an oversized input cannot be used to force expensive work.

**Account lockout complements this policy: five failed attempts trigger a lockout**, and it is consulted
at **both** surfaces that verify a password, not one. An earlier revision of this paragraph called the
Razor page the *single login entry point*; it is the single **interactive** login page, which is a
different statement. The two surfaces are:

| Surface | Route | Consulted at |
| --- | --- | --- |
| The interactive login page | `GET`/`POST /login`, antiforgery-validated | `WebVella.Erp.Web/Pages/login.cshtml.cs:L152` (`TryBeginAttempt`), with the failed-attempt and success registrations at `:L205` and `:L210` |
| The anonymous bearer-token **issue** route | `POST api/v3/en_US/auth/jwt/token`, `[AllowAnonymous]` | `WebVella.Erp.Web/Controllers/WebApiController.cs:L5692`, in the `GetJwtToken` action declared at `:L5653`, with its failed-attempt registration at `:L5734` |

Both verify the same e-mail and password through the same `AuthService` credential path, so both reach
the migration described in this guide - a legacy hash is rehashed on a successful sign-in through
*either* one. Sharing a single throttle instance is what stops the anonymous route from being used as an
unmetered oracle against the account the login page protects. The token **refresh** route is a third
anonymous entry point but is not a third password surface: it exchanges an existing token and never sees
a password, so it plays no part in the rehash path. **The throttle's scope is no longer per-instance** —
review finding `H-OPEN-02` moved its counters into the platform's existing `plugin_data` table, so a
lockout survives a restart and spans instances, and one shared bound covers both credential surfaces
rather than one bound per process per surface. That, and its fail-closed behaviour when the store cannot
be consulted, are documented in the [secure configuration guide](secure-configuration.md) and the
[risk register](risk-register.md) rather than repeated here.

## Login latency is deliberate

A high-iteration key-derivation function is **deliberately slow.** That is the entire point of a work
factor: it multiplies the cost of every offline guess an attacker makes against a stolen password
column, and it raises the cost of online guessing too, which complements the lockout above.

Login is therefore measurably slower than before, **by design**:

- It is the **pre-declared, accepted exception** to the engagement's 10% performance boundary. It was
  declared in advance as a trade-off, not discovered afterwards as a regression. **Re-measured at this
  commit against the shipped setting** — PBKDF2-HMAC-SHA-256 at 600,000 iterations, medians over 20
  single-threaded runs — a hash costs **150 ms** and a verification **151 ms** on a quiet run, rising to
  around 340 ms on the same host under contention. Some figures in the
  [remediation log](remediation-log.md) are labelled against an earlier HMAC-SHA-512 configuration of
  the same 600,000-iteration work factor and are marked superseded there; the shipped pseudo-random
  function is **HMAC-SHA-256**, as the parameter table above states and as every stored payload records
  for itself. Because the measurement host is shared, the order of magnitude — not the exact
  millisecond — is what it establishes.
- It is **confined to the authentication path.** No other request path performs a key derivation, so no
  other request path is affected.
- It is bounded per attempt and serialised per request, so plan capacity for it if you authenticate at
  high volume.

**One additional effect appears on the first login per user after the upgrade**, and only that one: a
successful legacy verification is followed immediately by a rehash and a database write, so that single
request does slightly more work than the same user's subsequent logins. It is a one-time cost per
account, not a steady-state one.

A failed login also spends a derivation even when no account matches the submitted address. That is
intentional: without it, the response time would reveal whether an address is registered, turning the
login endpoint into an account-enumeration oracle.

Do not attempt to tune the latency down by lowering the iteration count. If authentication throughput
is genuinely a constraint, treat it as a capacity question.

## What deploying this looks like

### Expect one sign-out at deployment — every in-flight session ends once

This is a **session** consequence rather than a password one, and it is recorded here because it lands at
the same moment and is the only user-visible effect of deploying the change.

Session revocation and the absolute session horizon are both keyed on markers the platform stamps into a
credential when it mints it: a session-identifier claim, and a horizon stamp inside the authentication
ticket. Both controls previously **accepted** a credential carrying no marker, on the reasoning that such
a credential could only predate the control. That reasoning left a permanent bypass rather than a
temporary allowance: nothing expired the exemption, so any future source of an unmarked credential would
inherit a session neither control could bound or end. **Both now fail closed.**

The consequence, stated plainly so it is not mistaken for a fault:

- Anyone holding a session issued **before** this deployment is signed out on their next request and
  signs in again. **Once.** There is nothing to configure and nothing to migrate.
- Any bearer token issued before this deployment is refused, and the refresh endpoint will not renew it.
  Clients re-authenticate to obtain a token carrying the new marker. The WebAssembly client already
  handles a refused refresh by discarding its stored token, so it recovers without operator action.

Plan the deployment accordingly if you have long-running interactive sessions, and expect a single burst
of re-authentication rather than a sustained one.

## Rollback

**MD5 hashes cannot be reversed.** This is the constraint that shapes every option below, and it is
stated plainly rather than softened.

**Rollback cannot restore legacy values for accounts that have already been rehashed.** Once a user has
authenticated after the upgrade, their stored value is a modern hash. There is no computation that
turns it back into the MD5 digest that was there before, because the plaintext it would need was never
retained. Reverting the code would leave every such account unable to authenticate, since the old
verification path understands only the old format.

The practical guidance follows directly:

1. **Take a database backup before deploying.** This is the only thing that makes rollback possible at
   all, and it must be taken *before* the first post-upgrade login rather than after.
2. **If rollback is required, restore that backup** rather than attempting to downgrade in place.
   Restoring is a supported operation; converting modern hashes back is not a supported operation and
   is not possible.
3. **If a partial rollback has already happened** — the code reverted while some accounts had already
   been rehashed — the remedy for the affected accounts is an **administrative password reset**, not a
   hash conversion. Reset them from an account that can still authenticate.

Three further properties of the migration bear on rollback:

- **It is forward-only.** There is no down-migration. Nothing lowers the recorded version number, and
  nothing restores the guest grants, the old field permissions or the old length bounds.
- **The schema is unchanged**, so a rollback is a code-and-data restore, never a schema operation.
  There is no column to drop and no index to rebuild.
- **The retired administrator credential is not recoverable either.** If the version 4 migration
  replaced it, restoring the backup restores the historic published value — which is exactly the exposure the
  migration existed to close. Treat that installation as compromised and rotate the credential
  immediately.

**PostgreSQL is the only supported database.** Any rehearsal of this procedure must run against a real
PostgreSQL instance; there is no in-memory or SQLite substitute, so a dry run cannot be shortcut.

## Verifying the outcome

These checks confirm the migration behaved as described. They are drawn from the manual verification
checklist in the [remediation log](remediation-log.md), which records the results.

| Check | Expected result |
| --- | --- |
| Sign in with a credential created before the upgrade | Succeeds, and the stored value is transparently rewritten in the modern format |
| Sign in again with the same credential | Succeeds against the rewritten value, with no further rewrite |
| Sign in as `erp@webvella.com` with the historic published password | Refused — on a fresh installation and on an upgraded one |
| Read a user record through any API or query route, as any role | No password hash is returned; the redaction marker appears instead |
| Read a user record, edit one unrelated field, post the whole record back | The stored credential is unchanged — **not** replaced by the marker |
| Sign in as a Guest-role account and attempt to create a user or a role | Refused |
| Set a password shorter than 12 characters or longer than 128 | Refused with an actionable message |
| Fail six consecutive logins, then succeed | Lockout engages on the sixth; a successful login resets the counter |

## Related documents

| Document | What it covers |
| --- | --- |
| [Security audit report](security-audit-report.md) | **The authoritative record.** Every one of the 53 findings carries its own eight-field record there, including `C-01`, `C-02`, `C-05`, `H-17` and `M-13`. This page **supplements** those records with the operator-facing detail they do not carry — the migration mechanism, the runbook and the rollback guidance — and does not replace them. An earlier revision of this row said those five findings were documented here "rather than there", which was wrong in both directions: it understated the report and it invited a reader to treat a guide as the finding inventory |
| [Remediation log](remediation-log.md) | What changed per vulnerability class, the verification performed, and the recorded latency measurement |
| [Risk register](risk-register.md) | `RISK-003` the algorithm deviation, `RISK-004` the retained legacy path, `RISK-046` the policy floor, `RISK-047` the redaction marker exemptions, `RISK-050` the residual guest grant |
| [Secure configuration guide](secure-configuration.md) | The secrets an installation must be supplied before it will start, and the lockout's scope |

The vulnerability disclosure policy is in
[`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md).
