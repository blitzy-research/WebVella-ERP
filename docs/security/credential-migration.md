# Credential Migration

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
The lookup therefore had to be restructured to **fetch by e-mail only and verify in application
code.** Adding a salt without moving the comparison would simply have prevented every login.

**The restructure is semantically safe**, because an exact, case-insensitive e-mail comparison
*already existed* in application code immediately afterwards — inside the loop opened at `:L88`,
`WebVella.Erp/Api/SecurityManager.cs:L90` reads
`if (((string)rec["email"]).ToLowerInvariant() == email.ToLowerInvariant())`, returning the mapped
user at `:L91` and `null` at `:L94`. The exact comparison was always the operative one; the SQL
predicate was only ever a coarse pre-filter. Removing it changed which rows were fetched, not which
row authenticated.

That single restructure closed two further findings at no additional cost:

- **`H-17`** ([CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html),
  [CWE-625: Permissive Regular Expression](https://cwe.mitre.org/data/definitions/625.html)) — `~*` is
  PostgreSQL's case-insensitive **regular expression** match operator, not a string comparison. An
  anonymous caller controls the pattern by controlling the submitted e-mail address, and the server
  evaluates it once per row. Replacing it with the exact comparison already present removes the
  exposure entirely rather than trying to bound it.
- **`M-05`** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)) — verification in
  application code uses a fixed-time comparison, so the timing oracle in the old character-by-character
  comparison is gone.

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
| `C-01` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | `ERPService.cs:L467` | `user["password"] = "erp";` — a hardcoded default administrator password |
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
releases shipped: it must have the legacy 32-character shape *and* verify against the literal `"erp"`.

That condition is the point. Retiring the credential unconditionally would overwrite a password an
operator had already chosen and changed — turning a security fix into an outage. Anything else in the
column, including a password the operator set themselves, an already-modern value, or an empty column,
is left exactly as it is.

When the condition does match, the migration writes a fresh generated password and sets a
change-required-at-first-login marker on the account. The marker is carried in the account's existing
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

Provisioning seeded a first administrator account at `WebVella.Erp/ERPService.cs:L462-L475` with
`user["password"] = "erp";` at `:L467`, `user["email"] = "erp@webvella.com";` at `:L468` and
`user["username"] = "administrator";` at `:L469`.

That is finding `C-01` ([CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html),
[CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)). A
three-character dictionary word, published in the source of an open repository, on a known e-mail
address, for an account holding the administrator role, is an authentication bypass in practice.

**It no longer authenticates.** The literal is quoted here deliberately, because an operator cannot
check whether their installation is exposed without knowing what to check for.

> **`"erp"` remains in the repository's git history and must be assumed known to anyone who has ever
> seen this repository.** It must never be reinstated as a password on any account, on any
> installation, for any reason — including temporarily during testing.

### On a fresh installation

Provisioning resolves the initial administrator password in one of two ways, in this order:

1. **From configuration, if you supply it** — the setting `Settings:InitialAdministratorPassword`,
   supplied as the environment variable `Settings__InitialAdministratorPassword`. **This is the
   preferred route**, because you already know the value and nothing has to be captured from output.
   The value must satisfy the password policy below or startup fails fast with an actionable message.
2. **Generated, if you do not** — a 20-character password from a cryptographically secure random
   source, printed **exactly once** to standard error during provisioning.

Either way the account is marked as requiring a password change at first login.

The steps are:

1. Supply the required secrets before first start. An installation will not start without
   `Settings__ConnectionString` and `Settings__EncryptionKey`, and the two token-issuing hosts also
   require `Settings__Jwt__Key`. The [secure configuration guide](secure-configuration.md) is the
   reference for the full set and for how to supply them.
2. Supply `Settings__InitialAdministratorPassword` as well, unless you intend to capture the generated
   value from the provisioning output.
3. Start the application and, if you did not supply a password, **capture the one-time notice from
   standard error.** It is written after the provisioning transaction commits — so that a notice only
   ever appears for an account that really exists — and it is not written to the platform's log table,
   because a credential in the log table would be readable by every account holding log access.
4. Sign in as `administrator` and change the password immediately. The change-required marker is
   enforced, not advisory: interactive login works precisely so the password *can* be changed, but
   bearer tokens are refused for the account until it has been rotated.

### On an upgraded installation

There is nothing to run. On the first start after upgrading, the version 4 migration detects whether
the account still carries the shipped credential and, if it does, replaces it and marks it for
rotation. If the password was already changed, it is left untouched and no notice is printed.

Verify afterwards that `"erp"` no longer authenticates, and — if a replacement was generated — capture
the one-time notice and rotate it as above.

### If the one-time value was not captured

This is recoverable and does not require a database edit. Sign in with any other account holding the
administrator role and reset the administrator account's password through the ordinary user-management
screen. If no such account exists, set `Settings__InitialAdministratorPassword` and re-provision
against an empty database, restoring your data afterwards; because the stored form is a one-way hash,
there is no way to recover the value that was printed.

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

**Account lockout complements this policy: five failed attempts trigger a lockout**, consulted at the
single login entry point `WebVella.Erp.Web/Pages/login.cshtml.cs:L92`. Its per-instance scope and its
fail-closed behaviour are documented in the [secure configuration guide](secure-configuration.md) and
the [risk register](risk-register.md) rather than repeated here.

## Login latency is deliberate

A high-iteration key-derivation function is **deliberately slow.** That is the entire point of a work
factor: it multiplies the cost of every offline guess an attacker makes against a stolen password
column, and it raises the cost of online guessing too, which complements the lockout above.

Login is therefore measurably slower than before, **by design**:

- It is the **pre-declared, accepted exception** to the engagement's 10% performance boundary. It was
  declared in advance as a trade-off, not discovered afterwards as a regression, and the measurement is
  recorded in the [remediation log](remediation-log.md). Some figures there are labelled against an
  earlier HMAC-SHA-512 configuration of the same 600,000-iteration work factor; the shipped
  pseudo-random function is **HMAC-SHA-256**, as the parameter table above states and as every stored
  payload records for itself. The order of magnitude is what the measurement establishes.
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
  replaced it, restoring the backup restores the old `"erp"` value — which is exactly the exposure the
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
| Sign in as `administrator` with `"erp"` | Refused — on a fresh installation and on an upgraded one |
| Read a user record through any API or query route, as any role | No password hash is returned; the redaction marker appears instead |
| Read a user record, edit one unrelated field, post the whole record back | The stored credential is unchanged — **not** replaced by the marker |
| Sign in as a Guest-role account and attempt to create a user or a role | Refused |
| Set a password shorter than 12 characters or longer than 128 | Refused with an actionable message |
| Fail six consecutive logins, then succeed | Lockout engages on the sixth; a successful login resets the counter |

## Related documents

| Document | What it covers |
| --- | --- |
| [Security audit report](security-audit-report.md) | Every finding in the eight-field format. `C-01`, `C-02`, `C-05`, `H-17` and `M-13` are documented in full on this page rather than there |
| [Remediation log](remediation-log.md) | What changed per vulnerability class, the verification performed, and the recorded latency measurement |
| [Risk register](risk-register.md) | `RISK-003` the algorithm deviation, `RISK-004` the retained legacy path, `RISK-046` the policy floor, `RISK-047` the redaction marker exemptions, `RISK-050` the residual guest grant |
| [Secure configuration guide](secure-configuration.md) | The secrets an installation must be supplied before it will start, and the lockout's scope |

The vulnerability disclosure policy is in
[`SECURITY.md`](https://github.com/Blitzy-Sandbox/blitzy-WebVella-ERP/blob/master/SECURITY.md).
