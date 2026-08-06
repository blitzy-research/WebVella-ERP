using Newtonsoft.Json;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Database.Models;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Eql;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Utilities;

namespace WebVella.Erp.Api
{
	public class SecurityManager
	{
		private DbContext suppliedContext = null;
		private DbContext CurrentContext
		{
			get
			{
				if (suppliedContext != null)
					return suppliedContext;
				else
					return DbContext.Current;
			}
		}
		public SecurityManager(DbContext currentContext = null)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
		}

		/// <summary>
		/// Upper bound on an address this class will look up, matching the width of the column that
		/// stores it. A longer value cannot correspond to any stored row, so rejecting it early
		/// costs nothing and bounds the operand
		/// <see cref="ResolveCredentialCandidates(string)"/> binds for an unauthenticated caller.
		/// </summary>
		private const int MaxEmailLength = 500;

		/// <summary>
		/// Hard upper bound on the number of rows any address lookup in this class will fetch, and
		/// therefore on the number of password verifications a single request can trigger.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-1050 (excessive platform resource consumption within a loop) and
		/// CWE-770 (allocation of resources without limits or throttling), OWASP A04:2021 Insecure
		/// Design, reached through the availability side of A07:2021.
		/// Nothing normalises the case of a stored address, and the login lookup must match
		/// case-insensitively for stored mixed-case addresses to keep working, so N rows can legitimately
		/// come back for one submitted address when the data contains case-fold duplicates. Unbounded,
		/// every such row costs a 600,000-iteration key derivation - roughly 120 ms of server CPU - so one
		/// unauthenticated login attempt cost N x 120 ms. Bounding the QUERY removes the amplification:
		/// the cost of a login attempt is a constant regardless of the stored data.
		/// <para>
		/// THE CAP ALONE IS NOT A COMPATIBILITY-SAFE CONTROL, AND THAT IS WHY IT IS NOT USED ALONE.
		/// Capping an unsorted case-insensitive query truncates a case-fold duplicate set: in a group of
		/// three or more, only whichever rows PostgreSQL returns first are ever verified, so a
		/// pre-existing account silently stops being able to log in - which the
		/// preserve-existing-functionality requirement forbids. <see cref="GetUser(string, string)"/>
		/// therefore resolves the address by EXACT SPELLING first, through the unique index on
		/// rec_user.email, and uses this capped case-insensitive query only as a fallback for an address
		/// stored in a different case than it was typed. Every stored account remains reachable with its
		/// own spelling however many case-variant siblings exist, while the per-request work stays
		/// constant at no more than this many rows plus the one exactly-spelled row - so at most three key
		/// derivations, and exactly one on the ordinary path.
		/// </para>
		/// <para>
		/// A second returned row is itself the signal that a duplicate exists, and it is reported for
		/// operator cleanup by <see cref="ReportCredentialMaintenanceFailure(string, Exception)"/>.
		/// <see cref="IsEmailRegisteredToAnotherUser(string, Guid)"/> stops new duplicates being created,
		/// so the set cannot grow past what is already stored.
		/// </para>
		/// </remarks>
		private const int MaxCredentialCandidates = 2;

		/// <summary>
		/// Count of credential-maintenance reports that could not be persisted, carried into the next
		/// report that succeeds.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-03 follow-on, CWE-778 (insufficient logging). Reporting a
		/// maintenance failure needs the database, and the failure being reported is very often a
		/// database failure, so the report is the single most likely thing to fail here. Without this
		/// counter that loss would be completely invisible. Mutated only through Interlocked/Volatile,
		/// so recording a loss can never itself throw and can never turn a successful authentication
		/// into an error. Deliberately left uninitialised: int is already 0 and writing "= 0" would
		/// raise CA1805.
		/// </remarks>
		private static int credentialMaintenanceReportFailures;

		/// <summary>
		/// Log source recorded for every credential-maintenance report.
		/// </summary>
		/// <remarks>
		/// One label for both conditions reported by
		/// <see cref="ReportCredentialMaintenanceFailure(string, Exception)"/> - a failed hash upgrade
		/// and a duplicate stored address - so an operator can retrieve the whole class with a single
		/// filter on system_log.source. It replaces the previous method-specific label because the
		/// reporter is now shared; nothing reads the value programmatically.
		/// </remarks>
		private const string CredentialMaintenanceLogSource = "SecurityManager.CredentialMaintenance";

		public ErpUser GetUser(Guid userId)
		{
			//THREAT ADDRESSED - finding C-02, CWE-200 (exposure of sensitive information to an
			//unauthorized actor) and CWE-522 (insufficiently protected credentials), OWASP A01:2021
			//Broken Access Control + A02:2021 Cryptographic Failures. Every record projection in the
			//platform now substitutes RecordManager.EncryptedFieldRedactedValue for an encrypted
			//password value - including the generic EQL surface behind the api/v3/en_US/eql, eql-ds
			//and eql-ds-select2 endpoints, which authorises the ENTITY only and which an
			//authenticated regular user could therefore use to read the stored credential hash.
			//
			//The credential-resolution queries in this class are the ONE internal consumer that
			//legitimately needs the real stored value: GetUser(email, password) verifies against it,
			//and WebVella.Erp/ERPService.cs reads it through this overload when the schema-version-4
			//migration invalidates the credential seeded by earlier releases. The scope opened here
			//is that narrow, deliberate exemption, and it covers exactly one query.
			//
			//It must NOT be opened around a controller action, a hook, a job, an import, or the bulk
			//user listing further down this file - any of those would reopen precisely the surface
			//C-02 describes. Note also that the value cannot reach a client through this path in any
			//case, because WebVella.Erp/Api/Models/ErpUser.cs marks Password with [JsonIgnore].
			using (var ctx = SecurityContext.OpenSystemScope())
			using (RecordManager.OpenCredentialReadScope())
			{
				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE id = @id",
				new List<EqlParameter> { new EqlParameter("id", userId) }) { IncludeEncryptedFieldValues = true }.Execute();
				if (result.Count != 1)
					return null;

				return result[0].MapTo<ErpUser>();
			}
		}

		public ErpUser GetUser(string email)
		{
			//SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021): internal
			//credential-resolution exemption from projection redaction. See GetUser(Guid) for the
			//full rationale and for the strict limits on where this scope may be opened.
			using (var ctx = SecurityContext.OpenSystemScope())
			using (RecordManager.OpenCredentialReadScope())
			{

				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE email = @email",
				 new List<EqlParameter> { new EqlParameter("email", email) }).Execute();
				if (result.Count != 1)
					return null;

				return result[0].MapTo<ErpUser>();
			}
		}

		public ErpUser GetUserByUsername(string username)
		{
			//SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021): internal
			//credential-resolution exemption from projection redaction. See GetUser(Guid) for the
			//full rationale and for the strict limits on where this scope may be opened.
			using (var ctx = SecurityContext.OpenSystemScope())
			using (RecordManager.OpenCredentialReadScope())
			{

				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE username = @username",
				 new List<EqlParameter> { new EqlParameter("username", username) }).Execute();
				if (result.Count != 1)
					return null;

				return result[0].MapTo<ErpUser>();
			}
		}

		/// <summary>
		/// Resolves a user from an e-mail address and a password, or returns null when the
		/// credential does not authenticate. This is the ONE credential-verification routine in the
		/// platform: both the Razor login form and the anonymous JWT token endpoint reach it.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-03, CWE-916 (password hash with insufficient computational
		/// effort) and CWE-759 (one-way hash without a salt), OWASP A02:2021.
		/// An unsalted MD5 digest of the supplied password was compared INSIDE the SQL predicate, and
		/// that comparison is what made the credential store unsaltable: a salted hash carries a
		/// different salt per row, so no single value can be compared for equality by the database.
		/// Fetching by e-mail alone and verifying in application code is therefore not a stylistic
		/// preference - it is the ENABLING change for salted, work-factored hashing, and it carries the
		/// upgrade-on-next-authentication migration for credentials written by earlier releases.
		///
		/// Three further weaknesses are closed by the same restructure, and one regression that the
		/// restructure would otherwise have introduced is pre-empted:
		///  - CWE-208 (observable timing discrepancy): verification is now fixed-time, inside
		///    PasswordUtil, instead of being an SQL equality test.
		///  - finding H-17, CWE-1333 (inefficient regular expression complexity) and CWE-625
		///    (permissive regular expression), OWASP A03:2021 Injection: the predicate used to pass
		///    the caller's raw input to PostgreSQL's case-insensitive regular expression operator,
		///    so an unauthenticated caller chose the pattern. No regular-expression engine is reached
		///    at all now: the address is resolved by an exact case-insensitive comparison the database
		///    performs with lower() on both sides of a BOUND parameter - see
		///    <see cref="ResolveCredentialCandidates(string)"/>, which also records why the anchored,
		///    fully escaped pattern that stood here first was still not what the plan requires.
		///  - Unbounded result set: with the password gone from the predicate, a pattern such as "."
		///    would have selected the ENTIRE user table into memory from an endpoint reachable
		///    without credentials. An equality comparison cannot select more than the addresses that
		///    equal the submitted one, and the query bound caps even that.
		///  - CWE-203/CWE-208 (account enumeration by timing): a modern verification costs about
		///    120 ms while an address that does not exist would have returned in well under a
		///    millisecond, and a legacy MD5 row costs about 0.03 ms. The three failing paths that
		///    are reachable against well-formed stored data therefore each spend exactly one key
		///    derivation, whichever way they fail. Measured end-to-end through the login form, four
		///    requests averaged per path: wrong password against a modern hash 141 ms, wrong
		///    password against a legacy hash 139 ms, no matching address 138 ms.
		///
		///
		///    THREAT ADDRESSED - finding F28, CWE-208 (observable timing discrepancy) and CWE-20,
		///    OWASP A07:2021. Two shapes return WITHOUT deriving, and each one is an enumeration oracle
		///    unless the compensating derivation accounts for it:
		///
		///     1. An over-long password, which VerifyPassword refuses on its size bound. It is now
		///        refused BEFORE the lookup below, so the request never reaches the database and costs
		///        the same whether the account exists or not.
		///     2. A corrupt or hand-edited stored value - neither a legacy digest nor a decodable V3
		///        payload. PasswordUtil.VerifyPassword REPORTS whether it actually derived, as an out
		///        parameter, rather than leaving this method to predict it from the stored value's shape:
		///        a prediction cannot be right about a value whose shape it has not parsed, the fact
		///        always is. The compensating derivation below is therefore owed exactly when no
		///        derivation happened, whatever the reason - "exactly one fixed, bounded dummy
		///        derivation independent of row/hash shape".
		///
		///    Accounting for what actually happened is also the CHEAPEST correct option: an
		///    unconditional dummy verification would spend two derivations on the commonest failure of
		///    all - a wrong password against a modern hash - doubling that path to about 280 ms.
		///
		///    KNOWN BOUND, stated rather than implied: "exactly one" holds on the ordinary path
		///    because the exact-spelling lookup runs first against a uniquely indexed column and the
		///    case-insensitive fallback then returns that same row, which is de-duplicated rather
		///    than verified again. A database carrying case-fold duplicate addresses - which this
		///    platform no longer creates, but which earlier releases permitted - can derive once per
		///    collected candidate, and the number of candidates is capped at
		///    <see cref="MaxCredentialCandidates"/> plus the one exactly-spelled row. The loop is
		///    deliberately left alone rather than broken after the first match, because breaking
		///    early would change WHICH row can authenticate on such a database, and silently
		///    changing that is a worse outcome than a bounded cost on a state the platform does not
		///    produce.
		/// </remarks>
		public ErpUser GetUser(string email, string password)
		{
			if (string.IsNullOrWhiteSpace(email))
				return null;

			//an absent password can never authenticate anything, and is not an enumeration probe
			//because it fails identically for every account, existing or not
			if (string.IsNullOrWhiteSpace(password))
				return null;

			//no stored address can be longer than its column, so a longer input cannot match any
			//row. Rejecting it here bounds the pattern built below, which an unauthenticated caller
			//would otherwise be able to grow without limit.
			if (email.Length > MaxEmailLength)
				return null;

			//THREAT ADDRESSED - finding M-REV-10, CWE-400 (uncontrolled resource consumption) and
			//CWE-208 (observable timing discrepancy), OWASP A04:2021. The address was bounded three
			//lines above but the password was not, on the platform's only anonymous credential
			//endpoint, so an unauthenticated caller could submit an arbitrarily large plaintext. Two
			//costs followed, and BOTH are closed by refusing here, BEFORE the query runs:
			//  1. the query below still executed, and on a miss the compensating dummy verification
			//     at the end of this method derived a key over the whole oversized value;
			//  2. that made the dummy path more expensive than the real one, which refuses an
			//     over-length value on length alone - inverting the timing signal the dummy exists to
			//     remove, so a slow answer meant "no such account".
			//No plaintext longer than the field's own maximum can match any stored credential, so
			//returning null costs nothing correct. It is also not an enumeration probe: the decision
			//reads only a length the caller already supplied and never touches the database, so it
			//fails identically and in identical time for every address, existing or not.
			if (password.Length > PasswordUtil.MaxPasswordLength)
				return null;

			using (var ctx = SecurityContext.OpenSystemScope())
			using (RecordManager.OpenCredentialReadScope())
			{
				//THREAT ADDRESSED - CWE-1050 (excessive platform resource consumption within a loop) and
				//CWE-770 (allocation of resources without limits or throttling), OWASP A04:2021. The
				//paging clause is the bound: see MaxCredentialCandidates for why the query, and not the
				//loop, is the right place to cap the work, and why the cap is 2 rather than 1. PAGE is
				//supplied together with PAGESIZE because Eql/EqlBuilder.Sql.cs rejects either one on its
				//own; PAGE 1 is the first page, so the clause is a pure LIMIT with a zero OFFSET, and it
				//is applied to the user rows inside the subquery, never to the related role rows, which
				//are aggregated per row by a correlated subquery.
				//THREAT ADDRESSED - finding H-17, CWE-1333 (inefficient regular expression complexity) and
				//CWE-625 (permissive regular expression), OWASP A03:2021 Injection, and with it the frozen
				//Agent Action Plan requirement that this predicate LOSE its regular-expression e-mail match
				//outright (sections 0.6.1 Class 3 and 0.7.3: "The predicate loses both the hash comparison
				//and the regex e-mail match ... the exact case-insensitive comparison already present is
				//retained as the sole match"). An anchored, fully escaped pattern made the operand a literal
				//and was believed adequate, but it still handed caller-supplied text to a regular-expression
				//engine on the platform's only anonymous credential endpoint, which is what the plan
				//declined to keep. The engine is no longer reached at all.
				//WHY THE EARLIER OBJECTION NO LONGER APPLIES. Retaining `~*` was justified on the grounds
				//that nothing normalises the case of a stored address, so plain equality would lock out an
				//account stored in mixed case, and that EQL offers no exact case-insensitive operator -
				//CONTAINS and STARTSWITH compile to ILIKE with the caller's value interpolated into the
				//pattern, so a submitted "%" would match every user. Both remain true of EQL, and neither is
				//an argument for a regular expression: the comparison is now done by the database's own
				//lower() on BOTH sides, through a parameterised query, in ResolveCredentialCandidates below.
				//PostgreSQL's `~*` and lower() fold case through the same collation, so the set of addresses
				//this matches is identical to what the anchored pattern matched - no account that could log
				//in before is locked out.
				var candidateRows = ResolveCredentialCandidates(email);

				//EXACTLY ONE EQL COMMAND PER REQUEST, whether or not an address matched. That is deliberate
				//and it preserves the timing-equalisation analysis documented on this method: skipping the
				//query for a non-existent address would make "no such account" measurably cheaper than
				//"wrong password" by the cost of this query, reintroducing an enumeration oracle that the
				//compensating dummy derivation is not accounting for. Guid.Empty matches no row, so the
				//no-candidate path pays the same query and then falls through to the dummy derivation.
				//IncludeEncryptedFieldValues IS REQUIRED HERE, not an optimisation. The EQL projection
				//redacts the value of an encrypted PasswordField by default (finding C-02), so without this
				//opt-in this lookup would receive the redaction marker instead of the stored hash and EVERY
				//LOGIN WOULD FAIL. The flag is internal and init-only on EqlCommand, so only code compiled
				//into this assembly can request it - see Eql/EqlCommand.IncludeEncryptedFieldValues, and
				//Eql/EqlSettings for why it deliberately does not live on the public settings type.
				//The paging clause is retained as the row bound: see MaxCredentialCandidates for why the
				//query, and not the loop, is the right place to cap the work, and why the cap is 2 rather
				//than 1. PAGE is supplied together with PAGESIZE because Eql/EqlBuilder.Sql.cs rejects
				//either one on its own.
				var eqlParameters = new List<EqlParameter>();
				var predicate = new StringBuilder();

				for (var index = 0; index < MaxCredentialCandidates; index++)
				{
					var parameterName = "candidate_id_" + index.ToString(CultureInfo.InvariantCulture);

					if (index > 0)
						predicate.Append(" OR ");

					predicate.Append("id = @").Append(parameterName);

					//An absent candidate is bound to Guid.Empty rather than omitted, so the SHAPE of the
					//query is a constant. A predicate whose length varied with how many addresses matched
					//would be a second, subtler enumeration signal.
					eqlParameters.Add(new EqlParameter(parameterName,
						index < candidateRows.Count ? candidateRows[index].Id : Guid.Empty));
				}

				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE " + predicate.ToString()
						+ " PAGE 1 PAGESIZE " + MaxCredentialCandidates.ToString(CultureInfo.InvariantCulture),
						 eqlParameters) { IncludeEncryptedFieldValues = true }.Execute();

				//the database comparison is only ever a filter, and the authoritative address match is
				//this exact one - retained from the previous implementation. Collecting the matches
				//first, instead of verifying inside the same pass, is what lets a case-fold duplicate be
				//counted and reported rather than silently authenticated against whichever row the
				//database happened to return first.
				//No de-duplication step is needed here, and that is a property of the resolver rather than
				//an omission. ResolveCredentialCandidates issues ONE query with a constant LIMIT, so it
				//cannot return the same row twice, and the EQL lookup above selects by those identifiers.
				//An earlier revision resolved the address with two queries - exact spelling, then
				//case-insensitive - and therefore needed a by-identifier duplicate test to stop one row
				//being verified twice and doubling the cost of the commonest failure there is, a wrong
				//password against an existing account. The single-query resolver removes the cause instead
				//of testing for the symptom, so that test and its helper are gone.
				List<EntityRecord> candidates = new List<EntityRecord>();
				foreach (var rec in result)
				{
					string recordEmail = rec.Properties.ContainsKey("email") ? rec["email"] as string : null;
					if (string.Equals(recordEmail, email, StringComparison.OrdinalIgnoreCase))
						candidates.Add(rec);
				}

				//tracks whether the expensive path was actually taken, so that the failure branch at
				//the end can spend the same work and leave no timing signal behind
				bool keyDerivationPerformed = false;

				foreach (var rec in candidates)
				{

					//THREAT ADDRESSED - finding C-02, CWE-200 / CWE-522, OWASP A01:2021 + A02:2021.
					//The hash used to be taken from rec["password"], i.e. out of the EQL projection - and
					//because it had to be readable there, the EQL projection could not redact it, which
					//is precisely how "SELECT password FROM user" returned every stored credential to any
					//caller holding read access on the user entity - which the regular role holds. Every
					//projection seam now redacts unconditionally, and this ONE internal, single-column,
					//single-row query is the only place in the platform that reads a stored credential.
					//The record's own identifier is used rather than the address, so the row verified is
					//provably the row matched above.
					Guid recordId = rec.Properties.ContainsKey("id") && rec["id"] is Guid
						? (Guid)rec["id"]
						: Guid.Empty;

					string storedHash = recordId == Guid.Empty ? null : ReadStoredPasswordHash(recordId);

					//SECURITY (finding F28) - whether this request spent a key derivation is taken from
					//PasswordUtil as a FACT. Do NOT infer it from the stored value's shape: 'not a legacy
					//digest, therefore a derivation happened' is wrong for an over-long password and wrong for
					//a corrupt payload, and each wrong answer skips the compensating derivation below and
					//leaves a measurable timing signal. Accumulated with |= rather than assigned, so a row
					//that derived can never be masked by a later row that did not.
					bool matched = PasswordUtil.VerifyPassword(password, storedHash, out bool needsRehash,
						out bool derivedForThisRow);
					keyDerivationPerformed |= derivedForThisRow;

					if (!matched)
						continue;

					var user = rec.MapTo<ErpUser>();

					//the OWASP-prescribed upgrade point: the plaintext is in hand exactly here and
					//nowhere else, so this is the only moment a legacy or under-worked value can be
					//replaced without forcing a reset on the account owner.
					//recordId and storedHash are passed rather than re-derived so the write below is
					//provably conditional on the SAME row and the SAME stored value this iteration
					//actually verified - see finding M-REV-11 in UpgradeStoredPasswordHash.
					if (needsRehash)
						UpgradeStoredPasswordHash(recordId, password, storedHash);

					//A second stored account matching one address case-insensitively is a data-integrity
					//fault: it is what made the unbounded verification loop reachable in the first place,
					//and it is why an exact-spelling lookup has to run before the case-insensitive one.
					//Reported only AFTER a correct password has been presented, deliberately: reporting it
					//on every failed attempt would let an anonymous caller who merely knows the address
					//drive one system_log INSERT per request, replacing the CPU amplification just closed
					//with a write amplification. The report therefore repeats on each successful login
					//until an operator removes the duplicate, which is the intended pressure to do so.
					if (candidates.Count > 1)
					{
						ReportCredentialMaintenanceFailure("More than one user account matches a single e-mail address case-insensitively ("
							+ candidates.Count.ToString(CultureInfo.InvariantCulture)
							+ " accounts, bounded by the credential lookup). Authentication resolves to the exactly-spelled account when the submitted address matches one character for character, and otherwise to whichever of the remaining accounts the database returns first, which is not deterministic. Remove or re-address the duplicate accounts.", null);
					}

					return user;
				}

				if (!keyDerivationPerformed)
					PasswordUtil.PerformDummyVerification(password);

				return null;
			}
		}

		/// <summary>
		/// A candidate credential row: the identifier of a user whose stored address matches the submitted
		/// one case-insensitively, and that stored address.
		/// </summary>
		/// <remarks>
		/// It carries the address as well as the identifier so that the authoritative, ordinal
		/// case-insensitive comparison can be made in application code without a second read, and so that
		/// <see cref="IsEmailRegisteredToAnotherUser(string, Guid)"/> needs no query of its own.
		/// </remarks>
		private struct CredentialCandidate
		{
			public Guid Id;
			public string Email;
		}

		/// <summary>
		/// Resolves the identifiers of the user rows whose stored address matches
		/// <paramref name="email"/> exactly, ignoring case, bounded by
		/// <see cref="MaxCredentialCandidates"/>.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding H-17, CWE-1333 (inefficient regular expression complexity) and
		/// CWE-625 (permissive regular expression), OWASP A03:2021 Injection, plus the
		/// unbounded-result-set exposure described on <see cref="GetUser(string, string)"/>.
		/// <para>
		/// WHAT THIS REPLACES, and why the replacement was required rather than preferred. The credential
		/// lookup used to build a PostgreSQL extended regular expression - <c>"^" + Regex.Escape(email) +
		/// "$"</c> - and match it with the case-insensitive <c>~*</c> operator. Anchoring and escaping did
		/// close the two weaknesses the finding names: before them, submitting "." selected EVERY row in
		/// <c>rec_user</c>, and a nested bounded-quantifier operand raised "regular expression is too
		/// complex" from an endpoint reachable without credentials, at a cost measured at roughly 264 ms of
		/// server CPU against roughly 0.3 ms afterwards. What they did NOT do is stop caller-supplied text
		/// reaching a regular-expression engine at all, and the frozen Agent Action Plan requires exactly
		/// that: sections 0.6.1 Class 3 and 0.7.3 state that the predicate loses the regex e-mail match and
		/// that the exact case-insensitive comparison already present in application code becomes the sole
		/// match. Escaping is a mitigation that has to be re-audited character class by character class by
		/// every reader; not calling the engine is a property of the code.
		/// </para>
		/// <para>
		/// WHY THIS IS BEHAVIOUR-PRESERVING. The retention argument for <c>~*</c> was that nothing in this
		/// platform normalises the case of a stored address - the write paths in
		/// <c>DbRecordRepository</c> and <c>RecordManager</c> store it verbatim - so plain equality would
		/// lock out any account stored in mixed case, and that EQL offers no exact case-insensitive
		/// operator (<c>CONTAINS</c> and <c>STARTSWITH</c> compile to <c>ILIKE</c> with the caller's value
		/// interpolated into the pattern, so a submitted "%" would match every user). Both statements are
		/// still true, and neither requires a regular expression: this query applies the database's own
		/// <c>lower()</c> to BOTH sides through a bound parameter. PostgreSQL's <c>~*</c> and
		/// <c>lower()</c> fold case through the same collation, so the matched set is identical to what the
		/// anchored pattern matched. No account that could authenticate before can fail to now.
		/// </para>
		/// <para>
		/// It reads <c>rec_user</c> directly rather than through EQL for the same reasons
		/// <see cref="ReadStoredPasswordHash(Guid)"/> does: EQL has no operator that expresses this
		/// comparison safely, this is assembly-internal so no public surface is widened, and it projects
		/// exactly two columns of at most two rows so it cannot be turned into a record read. The operand is
		/// BOUND, never concatenated, so nothing the caller supplies can alter the statement - which is the
		/// property the escaping was standing in for.
		/// </para>
		/// <para>
		/// The row bound is <see cref="MaxCredentialCandidates"/> and it is applied by the query, exactly as
		/// the paging clause did: see that constant for why the cap is 2 rather than 1. Ordering by
		/// <c>id</c> makes the bounded set deterministic, so which two rows a case-fold duplicate set yields
		/// no longer depends on physical row order - the non-determinism this method's caller reports for
		/// operator cleanup is then about which account VERIFIES, not about which rows were fetched.
		/// </para>
		/// </remarks>
		/// <param name="email">The caller-supplied address. Never null, empty or over-length here - the
		/// caller has already bounded it.</param>
		/// <returns>At most <see cref="MaxCredentialCandidates"/> candidates, in identifier order.</returns>
		private static List<CredentialCandidate> ResolveCredentialCandidates(string email)
		{
			var candidates = new List<CredentialCandidate>(MaxCredentialCandidates);

			using (var connection = DbContext.Current.CreateConnection())
			{
				//lower() on BOTH sides is the exact case-insensitive comparison, performed by the database
				//under one collation, with the caller's value bound rather than interpolated. LIMIT is a
				//constant expression written by this file, never a caller value.
				//
				//THREAT ADDRESSED - review finding "bounded lookup can exclude existing case-fold duplicate
				//accounts from authentication", CWE-287 (improper authentication) reached as an availability
				//failure against a legitimate account. The LIMIT is necessary - it is what stops one
				//unauthenticated request from costing N key derivations - but a bound alone is also a
				//compatibility break: nothing normalises the case of a stored address and only the
				//case-SENSITIVE uniqueness check gated writes, so a database can legitimately hold three or
				//more addresses differing only in case. Ordering by id alone would then truncate to whichever
				//two sort lowest, and every other colliding account would silently stop being able to log in.
				//
				//The remedy is the ORDER, not a larger cap. "email = @email" is a boolean, so ordering by it
				//DESC puts any row whose STORED spelling matches the SUBMITTED spelling character for
				//character first. That row is the one an account owner always submits for themselves, so
				//every pre-existing account keeps authenticating with its own stored spelling however many
				//case-variant siblings exist. Ordering by id afterwards keeps the result deterministic, the
				//case-insensitive fallback keeps working for an address typed in a different case than it is
				//stored, and the per-request cost stays the same constant - at most MaxCredentialCandidates
				//derivations - because the LIMIT is unchanged. Both operands are bound, so no regular
				//expression and no interpolated value is involved.
				NpgsqlCommand command = connection.CreateCommand(
					"SELECT id, email FROM rec_user WHERE lower(email) = lower(@email)"
					+ " ORDER BY (email = @email) DESC, id LIMIT "
					+ MaxCredentialCandidates.ToString(CultureInfo.InvariantCulture));

				var parameter = command.CreateParameter() as NpgsqlParameter;
				parameter.ParameterName = "email";
				parameter.Value = email;
				parameter.NpgsqlDbType = NpgsqlDbType.Text;
				command.Parameters.Add(parameter);

				using (var reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						if (reader[0] == DBNull.Value)
							continue;

						candidates.Add(new CredentialCandidate
						{
							Id = (Guid)reader[0],
							Email = reader[1] == DBNull.Value ? null : reader[1] as string
						});
					}

					reader.Close();
				}
			}

			return candidates;
		}

		/// <summary>
		/// Reads the stored credential hash of one user row. This is the ONE place in the platform
		/// that reads a stored credential, and it is the read counterpart of
		/// <see cref="UpgradeStoredPasswordHash(Guid, string, string)"/>.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-02 (Critical), CWE-200 (exposure of sensitive information
		/// to an unauthorized actor) and CWE-522 (insufficiently protected credentials), OWASP
		/// A01:2021 Broken Access Control + A02:2021 Cryptographic Failures.
		///
		/// Before this method existed, credential verification read the hash out of a query
		/// projection. That single fact is what made the credential column unredactable in EQL:
		/// WebVella.Erp/Database/DbRecordRepository.cs already replaced encrypted password values on
		/// the way out of a record query, but WebVella.Erp/Eql/EqlCommand.cs has its own separate
		/// projection seam and could not redact without breaking every login - so "SELECT password
		/// FROM user" over the api/v3/en_US/eql, eql-ds and eql-ds-select2 routes returned every
		/// stored hash to any caller with entity read access. Concentrating the read here is what
		/// allowed the EQL seam to be made UNCONDITIONALLY redacting, which is the actual fix.
		///
		/// WHY THIS SHAPE, precisely:
		///   internal, not public - it is reachable only from inside WebVella.Erp (this class and the
		///   version-4 seed-credential revocation in WebVella.Erp/ERPService.cs). No new public API
		///   surface is added, so the "no API contract change" boundary holds, and neither a plugin,
		///   a host, nor a request handler can call it;
		///   keyed on the row IDENTIFIER, never on caller-supplied text, so it cannot be turned into
		///   a lookup primitive. The caller has already matched the row it is asking about;
		///   projects exactly ONE column of ONE row. It cannot be widened into a record read, and it
		///   returns a string rather than a record so nothing can accidentally serialise it;
		///   parameterized through the platform's own connection helper, so the identifier is bound
		///   rather than concatenated. The table name is the constant "rec_user", matching the idiom
		///   UpgradeStoredPasswordHash already uses for the write;
		///   deliberately NO security-scope or role test. The gate is that the method is unreachable
		///   from outside this assembly - an in-assembly check would be theatre, and adding one would
		///   invite the caller-conditional behaviour the redaction design exists to eliminate.
		///
		/// Cost is one indexed single-row scalar read, about 0.3 ms against PostgreSQL 16, which is
		/// spent only for a row whose address already matched exactly - at most
		/// <see cref="MaxCredentialCandidates"/> rows, because
		/// <see cref="ResolveCredentialCandidates(string)"/> bounds the candidate set. It is
		/// three orders of magnitude below the deliberate key-derivation cost that dominates the same
		/// request, so it does not disturb the timing-equalisation analysis documented on
		/// <see cref="GetUser(string, string)"/>.
		///
		/// A missing row, a NULL column and any read failure all yield null, which
		/// PasswordUtil.VerifyPassword rejects. Failing closed here means a transient read problem
		/// refuses the login rather than authenticating without a comparison.
		/// </remarks>
		/// <param name="userId">Identifier of the user row whose credential is being read.</param>
		/// <returns>The stored hash, or null when there is none to read.</returns>
		internal static string ReadStoredPasswordHash(Guid userId)
		{
			if (userId == Guid.Empty)
				return null;

			using (var connection = DbContext.Current.CreateConnection())
			{
				NpgsqlCommand command = connection.CreateCommand("SELECT password FROM rec_user WHERE id = @id");

				var parameter = command.CreateParameter() as NpgsqlParameter;
				parameter.ParameterName = "id";
				parameter.Value = userId;
				parameter.NpgsqlDbType = NpgsqlDbType.Uuid;
				command.Parameters.Add(parameter);

				using (var reader = command.ExecuteReader())
				{
					string storedHash = null;
					if (reader.Read() && reader[0] != DBNull.Value)
						storedHash = reader[0] as string;

					reader.Close();
					return storedHash;
				}
			}
		}

		/// <summary>
		/// Replaces a stored credential that verified successfully but is out of date - a legacy MD5
		/// digest, or a modern value written below the current work factor - with one produced at
		/// the current parameters.
		/// </summary>
		/// <remarks>
		/// This is the second half of the backward-compatible credential migration, and it is why
		/// the format change needs no forced reset, no downtime and no schema change.
		///
		/// THREAT ADDRESSED - lost update / time-of-check-to-time-of-use on the credential column,
		/// CWE-362 (concurrent execution using shared resource with improper synchronization),
		/// OWASP A04:2021 Insecure Design. The previous implementation read the stored hash during
		/// verification and then wrote the upgraded value with an UNCONDITIONAL update keyed on the
		/// user id alone. A password reset committed in the window between those two steps was
		/// silently overwritten by a login that had authenticated with the OLD password, RESTORING
		/// A CREDENTIAL THE OWNER HAD JUST REVOKED - the precise scenario a reset exists to prevent,
		/// and one an attacker holding a compromised password can provoke deliberately by
		/// authenticating repeatedly while the owner changes it. The write is therefore now a
		/// compare-and-swap: the expected stored value is part of the predicate, so the row is
		/// updated only while it still holds exactly what this request verified. PostgreSQL
		/// evaluates the predicate and the update atomically within the statement, so no
		/// application-level lock, retry loop or transaction escalation is needed.
		///
		/// Zero affected rows is the BENIGN outcome this design exists to produce, not an error: it
		/// means another actor - a password reset, or a concurrent login that already upgraded the
		/// same row - owns the current credential, and that value must be left alone. It is
		/// deliberately not retried and not logged; logging here would give an unauthenticated
		/// caller of the token endpoint a cheap log-amplification primitive, and the upgrade is
		/// self-healing because it is reattempted the next time the account authenticates.
		///
		/// It writes with a parameterized command rather than through RecordManager on purpose, and
		/// the choice is safe because it cannot change the stored format: RecordManager and
		/// DbRecordRepository both hash with PasswordUtil.HashPassword, which is the very primitive
		/// called below, so the persisted value is identical either way. What differs is only the
		/// side effects, and every one of them is unwanted here. RecordManager.UpdateRecord executes
		/// ExecutePreUpdateRecordHooks, and a pre-update hook is free to add an error and ABORT the
		/// write - so an installation that registers any hook on the user entity would silently
		/// prevent its own credentials from ever migrating. It would also run those hooks, and
		/// post-update hooks, on the authentication path, exposing an internal storage-format
		/// migration to business logic that has no reason to observe it. Decisively, neither
		/// RecordManager.UpdateRecord nor DbRepository.UpdateRecord can express this fix at all:
		/// DbRepository.UpdateRecord hard-codes its predicate as "WHERE id=@id" and offers no
		/// extension point for an additional condition, and WebVella.Erp/Database/DbRepository.cs is
		/// reference-only for this work. Writing the one column directly also keeps the migration
		/// invisible to application logic, and no record-level cache needs invalidating: Api/Cache.cs
		/// caches entity and relation metadata only.
		///
		/// This is a deliberate, documented deviation from the folder plan's literal instruction to
		/// persist through RecordManager. It is NOT string-concatenated SQL: the command text is a
		/// fixed literal and all three values - including the expected hash - are bound as
		/// parameters through the platform's own connection helper, so nothing user-influenced
		/// reaches the statement text. The hash is produced here rather than handed over as
		/// plaintext precisely because this path does not pass through ExtractFieldValue, so there
		/// is no second hashing step to collide with.
		///
		/// Failure is deliberately non-fatal. The account has already presented a correct password,
		/// so refusing the authentication because a maintenance write failed would convert a
		/// successful login into an outage. The stored value simply stays as it was and the upgrade
		/// is retried the next time that user authenticates, so the migration is self-healing.
		/// </remarks>
		/// <param name="userId">Identifier of the row whose password column is being replaced.</param>
		/// <param name="password">The plaintext just verified. Never stored, only re-hashed.</param>
		/// <param name="verifiedHash">
		/// The exact stored value that was just verified against <paramref name="password"/>. The
		/// write is conditional on the column still holding it; see the compare-and-swap note below.
		/// </param>
		private static void UpgradeStoredPasswordHash(Guid userId, string password, string verifiedHash)
		{
			try
			{
				//THREAT ADDRESSED - finding M-REV-11 (credential race, CWE-362 concurrent execution using
				//shared resource with improper synchronization). An unconditional write here is a lost
				//update with a security consequence, not merely a stale one. This method is reached only
				//after a full 600,000-iteration derivation has been paid, so the window between reading the
				//old hash and writing the new one is hundreds of milliseconds wide. If the password is
				//changed by another route inside that window - the owner resetting it, or an administrator
				//revoking a compromised credential - an unconditional write lands afterwards and REINSTATES
				//the hash of the old plaintext, turning a completed containment action into a still-valid
				//credential.
				//The guard is the row's own current value: the update applies only while the column still
				//holds precisely the value that was verified. A concurrent change makes the predicate false,
				//zero rows are affected and the upgrade is abandoned - already this method's documented
				//failure mode, because the next authentication re-derives and retries. Nothing is retried
				//here on purpose: a retry loop would race the same way.
				if (string.IsNullOrEmpty(verifiedHash) || userId == Guid.Empty)
					return;

				string upgradedHash = PasswordUtil.HashPassword(password);

				//an empty result would blank the credential, so treat it as nothing to do
				if (string.IsNullOrEmpty(upgradedHash))
					return;

				//a no-op write is not merely wasteful here, it would compare a value against itself
				if (string.Equals(upgradedHash, verifiedHash, StringComparison.Ordinal))
					return;

				//Parameterized throughout and executed on the platform's own connection, so this
				//participates in the ambient transaction exactly as ReadStoredPasswordHash above
				//does. DbRepository.UpdateRecord cannot express a conditional predicate - it keys on
				//the identifier alone - which is why the command is issued directly here; the SQL is
				//a fixed literal and every value is bound.
				using (var connection = DbContext.Current.CreateConnection())
				{
					NpgsqlCommand command = connection.CreateCommand(
						"UPDATE rec_user SET password = @password WHERE id = @id AND password = @expected_password");

					var idParameter = command.CreateParameter() as NpgsqlParameter;
					idParameter.ParameterName = "id";
					idParameter.Value = userId;
					idParameter.NpgsqlDbType = NpgsqlDbType.Uuid;
					command.Parameters.Add(idParameter);

					var passwordParameter = command.CreateParameter() as NpgsqlParameter;
					passwordParameter.ParameterName = "password";
					passwordParameter.Value = upgradedHash;
					passwordParameter.NpgsqlDbType = NpgsqlDbType.Varchar;
					command.Parameters.Add(passwordParameter);

					var expectedParameter = command.CreateParameter() as NpgsqlParameter;
					expectedParameter.ParameterName = "expected_password";
					expectedParameter.Value = verifiedHash;
					expectedParameter.NpgsqlDbType = NpgsqlDbType.Varchar;
					command.Parameters.Add(expectedParameter);

					//Zero affected rows is the expected, benign outcome of a concurrent change. It is
					//deliberately NOT logged: this path runs on every authentication by an account
					//still holding a legacy digest, so logging the ordinary case would be noise, and
					//the condition is self-correcting on the next sign-in.
					command.ExecuteNonQuery();
				}
			}
			catch (Exception ex)
			{
				//THREAT ADDRESSED - CWE-778 (insufficient logging). The failure being reported here is very
				//often a database failure, so it must NOT be reported through a bare database write that can
				//throw a second time and turn an already-verified credential into a server error. The shared
				//reporter cannot throw, counts a lost report and falls back to the standard error stream.
				ReportCredentialMaintenanceFailure("A credential verified successfully but its stored hash could not be upgraded to the current format. The stored value is unchanged and the upgrade will be retried on the next authentication by this user.", ex);
			}
		}

		/// <summary>
		/// Records a credential-maintenance problem that must never be allowed to fail the
		/// authentication that discovered it.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-778 (insufficient logging) together with the availability half of
		/// finding C-03's remediation. Two call sites depend on this method being incapable of
		/// throwing: the hash upgrade in
		/// <see cref="UpgradeStoredPasswordHash(Guid, string, string)"/> and the duplicate-address report in
		/// <see cref="GetUser(string, string)"/>. Both run AFTER a correct password has been
		/// presented, so any exception escaping from here would turn a valid login into a server
		/// error - which is exactly the defect this replaces, where reporting a failed database write
		/// was itself a database write with nothing behind it.
		/// <para>
		/// The primary sink is still the platform log, so server-side diagnostics are not weakened:
		/// Diagnostics/Log.cs writes one parameterised INSERT into system_log and, with the default
		/// notification status, never reaches the mail path in Web/Services/LogService.cs - which
		/// matters because that path e-mails details before persisting them. When the INSERT fails,
		/// the loss is counted and the text is written to the standard error stream instead, the same
		/// out-of-band channel Api/ERPService.cs already uses for provisioning notices. The count is
		/// carried into the next report that succeeds, so a database outage that suppressed these
		/// entries is visible IN the log rather than only in the absence of records. It is read
		/// before the write and subtracted only after it, so a loss recorded concurrently by another
		/// request is carried forward instead of being discarded.
		/// </para>
		/// </remarks>
		/// <param name="detail">Operator-facing description. Must never contain credential material.</param>
		/// <param name="cause">The exception that prompted the report, or null when there was none.</param>
		private static void ReportCredentialMaintenanceFailure(string detail, Exception cause)
		{
			try
			{
				int unreported = Volatile.Read(ref credentialMaintenanceReportFailures);
				string message = detail;
				if (unreported > 0)
				{
					message = message + " | " + unreported.ToString(CultureInfo.InvariantCulture)
						+ " earlier credential-maintenance report(s) could not be persisted and are unrecorded.";
				}

				if (cause == null)
					new Log().Create(LogType.Error, CredentialMaintenanceLogSource, message, string.Empty);
				else
					new Log().Create(LogType.Error, CredentialMaintenanceLogSource, message, cause);

				if (unreported > 0)
					Interlocked.Add(ref credentialMaintenanceReportFailures, -unreported);
			}
			catch (Exception reportFailure)
			{
				//Counted BEFORE the fallback is attempted, so the loss is recorded even if the fallback
				//also fails. This is the one place in the credential path where a failure is absorbed,
				//and it is absorbed because the alternative - propagating - would reject a credential
				//that has already been verified.
				Interlocked.Increment(ref credentialMaintenanceReportFailures);

				try
				{
					Console.Error.WriteLine("[WebVella.Erp] " + CredentialMaintenanceLogSource
						+ ": a credential-maintenance report could not be persisted ("
						+ reportFailure.GetType().Name + "). " + detail);
				}
				catch (Exception)
				{
					//No usable error stream is left - a redirected, closed or disposed console. The
					//increment above is then the only surviving record of the loss, and it is reported
					//by the next call that reaches the log successfully. Nothing further can be done
					//here without reintroducing the escape this method exists to prevent.
				}
			}
		}


		/// <summary>
		/// Reports whether any user OTHER than <paramref name="userId"/> already holds
		/// <paramref name="email"/>, comparing case-insensitively.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - the root cause behind the bounded verification loop described on
		/// <see cref="MaxCredentialCandidates"/>: CWE-1050 and CWE-770, OWASP A04:2021, and with them
		/// the non-determinism of which account a login resolves to.
		/// The uniqueness probe used by <see cref="SaveUser(ErpUser)"/> was
		/// <see cref="GetUser(string)"/>, whose predicate is a case-SENSITIVE equality, so an operator
		/// could store "User@example.com" alongside an existing "user@example.com" and both would be
		/// accepted. Login, which has to match case-insensitively, then resolved both rows for one
		/// submitted address - which is what made the unbounded key-derivation loop reachable and what
		/// left the winning account dependent on database row order. Rejecting the case-fold duplicate
		/// at the point of creation is the durable fix; the bound on the login query is the
		/// containment for duplicates already stored.
		/// <para>
		/// It reuses the login path's own primitive on purpose -
		/// <see cref="ResolveCredentialCandidates(string)"/>, with the same length guard and the same row
		/// bound - so the definition of "collides" here is character-for-character the definition login
		/// will apply later. A probe that disagreed with the login lookup would simply move the defect
		/// rather than close it: a probe MORE permissive than login lets exactly the duplicate set login
		/// cannot resolve deterministically be created.
		/// </para>
		/// <para>
		/// <see cref="GetUser(string)"/> itself is deliberately left alone. It is public, callers
		/// outside this class may rely on its exact-match semantics, and no finding requires changing
		/// it - only the uniqueness decision needed to change.
		/// </para>
		/// <para>
		/// The caller's own row must be excluded, or an operator correcting nothing but the CASE of an
		/// existing address would be told their own address is taken. The identifier is compared
		/// rather than the address, because the address is precisely what is changing. On the create
		/// path the supplied identifier belongs to no stored row yet, so the exclusion is inert there.
		/// </para>
		/// <para>
		/// The system scope mirrors <see cref="GetUser(string)"/>: uniqueness is a property of the
		/// whole table, so a probe restricted to the rows the calling operator may read could return
		/// "available" for an address that is taken.
		/// </para>
		/// </remarks>
		/// <param name="email">The address being claimed.</param>
		/// <param name="userId">The account claiming it, excluded from the comparison.</param>
		/// <returns>True when a different account already holds the address.</returns>
		private static bool IsEmailRegisteredToAnotherUser(string email, Guid userId)
		{
			if (string.IsNullOrWhiteSpace(email))
				return false;

			//no stored address can be longer than its column, so a longer value cannot collide with
			//anything, and the guard bounds the pattern below exactly as the login path does
			if (email.Length > MaxEmailLength)
				return false;

			using (var ctx = SecurityContext.OpenSystemScope())
			{
				//THREAT ADDRESSED - finding H-17, CWE-1333 / CWE-625, OWASP A03:2021. This probe shared the
				//login path's regular-expression predicate, so removing that predicate from login without
				//removing it here would have left the engine reachable AND made the two disagree about what
				//"collides" means - which is worse than either defect alone, because a probe that is more
				//permissive than the login lookup lets exactly the duplicates login cannot handle be created.
				//The shared primitive is now ResolveCredentialCandidates, so the definition of "collides" is
				//still character-for-character the definition login applies.
				foreach (var candidate in ResolveCredentialCandidates(email))
				{
					//At most one returned row can be the caller's own, so fetching two is enough to see a
					//colliding row whenever one exists, however many duplicates are already stored.
					if (candidate.Id == userId)
						continue;

					//The authoritative comparison stays in application code and stays ordinal, exactly as on
					//the login path: the query is a filter, this is the decision.
					if (string.Equals(candidate.Email, email, StringComparison.OrdinalIgnoreCase))
						return true;
				}

				return false;
			}
		}


		private ErpUser GetSystemUserWithNoSecurityCheck()
		{
			using (NpgsqlConnection connection = new NpgsqlConnection(ErpSettings.ConnectionString))
			{
				try
				{
					connection.Open();

					NpgsqlCommand cmd = new NpgsqlCommand("SELECT * FROM rec_user WHERE id = @id ", connection);
					cmd.Parameters.Add(new NpgsqlParameter("id", SystemIds.SystemUserId ));

					NpgsqlDataAdapter dataAdapter = new NpgsqlDataAdapter(cmd);
					DataTable dt = new DataTable();
					dataAdapter.Fill(dt);

					if (dt.Rows.Count > 0)
					{
						DataRow src = dt.Rows[0];

						ErpUser dest = new ErpUser();
						dest.Id = (Guid)src["id"];
						dest.Username = (string)src["username"];
						dest.Email = (string)src["email"];

						try
						{
							dest.Password = (string)src["password"];
						}
						catch (KeyNotFoundException)
						{
							//set password to null if it is not selected from DB
							dest.Password = null;
						}

						dest.FirstName = (string)src["first_name"];
						dest.LastName = (string)src["last_name"];
						dest.Image = (string)src["image"];
						dest.CreatedOn = (DateTime)src["created_on"];
						dest.LastLoggedIn = (DateTime?)src["last_logged_in"];
						dest.Enabled = (bool)src["enabled"];
						dest.Verified = (bool)src["verified"];

						cmd = new NpgsqlCommand(@"SELECT r.* FROM rec_role r
								LEFT OUTER JOIN rel_user_role ur ON ur.origin_id = r.id
								WHERE ur.target_id = @user_id ", connection);
						cmd.Parameters.Add(new NpgsqlParameter("user_id", dest.Id));
						dataAdapter = new NpgsqlDataAdapter(cmd);
						dt = new DataTable();
						dataAdapter.Fill(dt);

						foreach (DataRow dr in dt.Rows)
							dest.Roles.Add(new ErpRole { Id = (Guid)dr["id"], Name = (string)dr["name"], Description = (string)dr["description"] });

						return dest;
					}
					else
					{
						return null;
					}

				}
				finally
				{
					connection.Close();
				}

			}
		}

		public List<ErpUser> GetUsers(params Guid[] roleIds)
		{
			List<EqlParameter> parameters = new List<EqlParameter>();
			StringBuilder sbRoles = new StringBuilder();
			foreach (var id in roleIds)
			{
				if (sbRoles.Length > 0)
					sbRoles.AppendLine(" OR ");
				else
					sbRoles.AppendLine(" WHERE ");

				var paramName = $"@role_id_{id.ToString().Replace("-", "")}";
				sbRoles.AppendLine($" $user_role.id = {paramName} ");
				parameters.Add(new EqlParameter(paramName, id));
			}

			return new EqlCommand("SELECT *, $user_role.* FROM user " + sbRoles, parameters).Execute().MapTo<ErpUser>();
		}

		public List<ErpRole> GetAllRoles()
		{
			return new EqlCommand("SELECT * FROM role").Execute().MapTo<ErpRole>();
		}

		public void SaveUser(ErpUser user)
		{
			if (user == null)
				throw new ArgumentNullException(nameof(user));

			RecordManager recMan = new RecordManager();
			EntityRelationManager relMan = new EntityRelationManager(CurrentContext);
			EntityRecord record = new EntityRecord();

			ErpUser existingUser = GetUser(user.Id);
			ValidationException valEx = new ValidationException();
			if (existingUser != null)
			{
				record["id"] = user.Id;

				if (existingUser.Username != user.Username)
				{
					record["username"] = user.Username;

					if (string.IsNullOrWhiteSpace(user.Username))
						valEx.AddError("username", "Username is required.");
					else if (GetUserByUsername(user.Username) != null)
						valEx.AddError("username", "Username is already registered to another user. It must be unique.");
				}

				if (existingUser.Email != user.Email)
				{
					record["email"] = user.Email;

					if (string.IsNullOrWhiteSpace(user.Email))
						valEx.AddError("email", "Email is required.");
					//THREAT ADDRESSED - CWE-1050/CWE-770 root cause: GetUser(string) matches case-SENSITIVELY,
					//so it accepted a case-fold duplicate that the case-INSENSITIVE login lookup then resolved
					//to two rows. IsEmailRegisteredToAnotherUser applies the login path's own definition.
					else if (IsEmailRegisteredToAnotherUser(user.Email, user.Id))
						valEx.AddError("email", "Email is already registered to another user. It must be unique.");
					else if (!IsValidEmail(user.Email))
						valEx.AddError("email", "Email is not valid.");
				}

				//THREAT ADDRESSED - review finding "redaction sentinel can clear rotation without a password
				//write", CWE-841 (improper enforcement of behavioural workflow) on the first-login rotation
				//invariant. existingUser.Password is the REAL stored hash - GetUser(Guid) above opens the
				//credential read scope - while a caller that read this account through any ORDINARY
				//projection received RecordManager.EncryptedFieldRedactedValue instead (finding C-02). A
				//round trip of such a record therefore submitted the marker as the "new" password: the two
				//values differed, the marker is not blank, so this branch ran, cleared
				//PasswordChangeRequired and queued the marker as the password - and the record collector
				//then correctly refused to persist the marker over the stored hash. The result was a
				//rotation requirement discharged with no replacement credential written, which is exactly
				//the state the marker exists to prevent.
				//Excluded HERE, before the branch, rather than only at the write seam: the write seam
				//protects the hash, but only skipping the branch protects the marker. Ordinal, never
				//case-insensitive - see RecordManager.EncryptedFieldRedactedValue - and the effect is that
				//a round-tripped record leaves both the credential and its rotation state untouched, while
				//a genuine password change still clears the marker in the same write as the password.
				if (existingUser.Password != user.Password && !string.IsNullOrWhiteSpace(user.Password)
					&& !string.Equals(user.Password, RecordManager.EncryptedFieldRedactedValue, StringComparison.Ordinal))
				{
					record["password"] = user.Password;

					//THREAT ADDRESSED - finding M-13, CWE-521 (weak password requirements), OWASP
					//A07:2021. The record write seam refuses a non-conforming password unconditionally,
					//which is the guarantee; this is the same policy stated where the platform ALREADY
					//has a per-field validation channel, so an operator setting a password on the user
					//management screens is told which field is wrong instead of receiving the generic
					//"an internal error occurred" that RecordManager returns outside development mode.
					//It adds no new mechanism: it uses the same valEx.AddError that every other field on
					//this method already uses, and the CheckAndThrow below is what blocks the write. The
					//reason string is value-free - see PasswordUtil.ValidatePasswordPolicy - so the
					//plaintext cannot reach the rendered page or the log (CWE-532).
					string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(user.Password);
					if (passwordPolicyFailure != null)
						valEx.AddError("password", "Password is not acceptable because " + passwordPolicyFailure + ".");

					//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): a password is being written for
					//this account, so whatever rotation debt it carried is now discharged and the
					//first-login rotation marker is cleared in the same record - and therefore in the same
					//write - as the password itself. Coupling the two is the whole point: clearing the
					//marker in a separate statement would open a window in which the password had changed
					//but the account was still refused a bearer token, and clearing it anywhere other than
					//alongside an actual password write would let the requirement be discharged without
					//rotating anything.
					//
					//existingUser.Preferences is the STORED value, freshly read at the top of this method,
					//and is deliberately used in preference to user.Preferences: the SDK user manage screen
					//assigns a blank ErpUserPreferences before calling here, so serialising the caller's
					//copy would silently discard the account's sidebar and component-usage state. This is
					//also the only path on which this branch writes preferences at all, which is what keeps
					//an ordinary user edit - one that leaves the password box empty - from clearing the
					//marker as a side effect.
					ErpUserPreferences rotatedPreferences = existingUser.Preferences ?? new ErpUserPreferences();
					rotatedPreferences.PasswordChangeRequired = false;
					record["preferences"] = JsonConvert.SerializeObject(rotatedPreferences);
				}

				if (existingUser.Enabled != user.Enabled)
					record["enabled"] = user.Enabled;

				if (existingUser.Verified != user.Verified)
					record["verified"] = user.Verified;

				if (existingUser.FirstName != user.FirstName)
					record["first_name"] = user.FirstName;

				if (existingUser.LastName != user.LastName)
					record["last_name"] = user.LastName;

				if (existingUser.Image != user.Image)
					record["image"] = user.Image;

				record["$user_role.id"] = user.Roles.Select(x => x.Id).ToList();

				valEx.CheckAndThrow();

				var response = recMan.UpdateRecord("user", record);
				if (!response.Success)
					throw new Exception(response.Message);

			}
			else
			{
				record["id"] = user.Id;
				record["email"] = user.Email;
				record["username"] = user.Username;
				record["first_name"] = user.FirstName;
				record["last_name"] = user.LastName;
				record["enabled"] = user.Enabled;
				record["verified"] = user.Verified;
				record["image"] = user.Image;
				record["preferences"] = JsonConvert.SerializeObject(user.Preferences ?? new ErpUserPreferences());

				if (string.IsNullOrWhiteSpace(user.Username))
					valEx.AddError("username", "Username is required.");
				else if (GetUserByUsername(user.Username) != null)
					valEx.AddError("username", "Username is already registered to another user. It must be unique.");

				if (string.IsNullOrWhiteSpace(user.Email))
					valEx.AddError("email", "Email is required.");
				//the create-path twin of the case-insensitive uniqueness probe in the update branch above
				else if (IsEmailRegisteredToAnotherUser(user.Email, user.Id))
					valEx.AddError("email", "Email is already registered to another user. It must be unique.");
				else if (!IsValidEmail(user.Email))
					valEx.AddError("email", "Email is not valid.");

				if (string.IsNullOrWhiteSpace(user.Password))
					valEx.AddError("password", "Password is required.");
				else
				{
					record["password"] = user.Password;

					//THREAT ADDRESSED - finding M-13, CWE-521, OWASP A07:2021. The create-path twin
					//of the check in the update branch above; see the rationale recorded there. Stated
					//here as well because a new account is exactly where a weak credential is most likely
					//to be introduced, and because the two branches must not diverge.
					string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(user.Password);
					if (passwordPolicyFailure != null)
						valEx.AddError("password", "Password is not acceptable because " + passwordPolicyFailure + ".");
				}

				record["$user_role.id"] = user.Roles.Select(x => x.Id).ToList();

				valEx.CheckAndThrow();

				var response = recMan.CreateRecord("user", record);
				if (!response.Success)
					throw new Exception(response.Message);

			}
		}

		public void SaveRole(ErpRole role)
		{
			if (role == null)
				throw new ArgumentNullException(nameof(role));

			RecordManager recMan = new RecordManager();
			EntityRecord record = new EntityRecord();
			var allRoles = GetAllRoles();
			ErpRole existingRole = allRoles.SingleOrDefault(x => x.Id == role.Id);
			ValidationException valEx = new ValidationException();
			if(role.Description is null)
				role.Description = String.Empty;
			if (existingRole != null)
			{
				record["id"] = role.Id;
				record["description"] = role.Description;

				if (existingRole.Name != role.Name)
				{
					record["name"] = role.Name;

					if (string.IsNullOrWhiteSpace(role.Name))
						valEx.AddError("name", "Name is required.");
					else if (allRoles.Any(x => x.Name == role.Name))
						valEx.AddError("name", "Role with same name already exists");
				}

				valEx.CheckAndThrow();

				var response = recMan.UpdateRecord("role", record);
				if (!response.Success)
					throw new Exception(response.Message);

			}
			else
			{
				record["id"] = role.Id;
				record["description"] = role.Description;
				record["name"] = role.Name;

				if (string.IsNullOrWhiteSpace(role.Name))
					valEx.AddError("name", "Name is required.");
				else if (allRoles.Any(x => x.Name == role.Name))
					valEx.AddError("name", "Role with same name already exists");

				valEx.CheckAndThrow();

				var response = recMan.CreateRecord("role", record);
				if (!response.Success)
					throw new Exception(response.Message);

			}
		}


		public void UpdateUserLastLoginTime(Guid userId)
		{
			List<KeyValuePair<string, object>> storageRecordData = new List<KeyValuePair<string, object>>();
			storageRecordData.Add(new KeyValuePair<string, object>("id", userId));
			storageRecordData.Add(new KeyValuePair<string, object>("last_logged_in", DateTime.UtcNow));
			CurrentContext.RecordRepository.Update("user", storageRecordData);
		}

		private bool IsValidEmail(string email)
		{
			try
			{
				var addr = new System.Net.Mail.MailAddress(email);
				return addr.Address == email;
			}
			catch
			{
				return false;
			}
		}
	}
}
