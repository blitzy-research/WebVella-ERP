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
		/// Upper bound on an address this class will look up: the width of the column that stores it.
		/// A longer value cannot match any stored row, so rejecting it early bounds the operand
		/// <see cref="ResolveCredentialCandidates(string)"/> binds for an unauthenticated caller.
		/// </summary>
		private const int MaxEmailLength = 500;

		/// <summary>
		/// Hard upper bound on the rows any address lookup here fetches, and so on the key derivations one
		/// request can trigger (CWE-1050, CWE-770 / OWASP A04:2021): stored addresses are not
		/// case-normalised, so a case-fold duplicate set legitimately matches N rows for one address. The
		/// cap alone would truncate that set, which is why <see cref="ResolveCredentialCandidates(string)"/>
		/// orders exact spelling first.
		/// </summary>
		private const int MaxCredentialCandidates = 2;

		/// <summary>
		/// Count of credential-maintenance reports that could not be persisted, carried into the next report
		/// that succeeds.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-03 follow-on, CWE-778 (insufficient logging). Reporting a maintenance
		/// failure needs the database, and the failure being reported is very often a database failure, so the
		/// report is the single most likely thing to fail here; without this counter that loss would be
		/// invisible. Mutated only through Interlocked/Volatile, so recording a loss can never itself throw and
		/// can never turn a successful authentication into an error. Deliberately left uninitialised: int is
		/// already 0 and writing "= 0" would raise CA1805.
		/// </remarks>
		private static int credentialMaintenanceReportFailures;

		/// <summary>
		/// Log source for every credential-maintenance report - a failed hash upgrade or a duplicate stored
		/// address - so one filter on system_log.source retrieves the class. Nothing reads it in code.
		/// </summary>
		private const string CredentialMaintenanceLogSource = "SecurityManager.CredentialMaintenance";

		public ErpUser GetUser(Guid userId)
		{
			//C-02 (CWE-200, CWE-522 / OWASP A01:2021 + A02:2021): every record and EQL projection
			//substitutes RecordManager.EncryptedFieldRedactedValue for an encrypted password value, because
			//EQL authorises the ENTITY only. This scope is one of only two exemptions - credential
			//resolution here and the schema-version-4 migration in ERPService - and it must NOT be opened
			//around a controller action, hook, job, import or the bulk user listing below.
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
			//C-02 credential-resolution exemption from projection redaction; see GetUser(Guid) for the
			//rationale and for the limits on where this scope may be opened.
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
			//C-02 credential-resolution exemption from projection redaction; see GetUser(Guid) for the
			//rationale and for the limits on where this scope may be opened.
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
		/// Resolves a user from an e-mail address and a password, or null when the credential does not
		/// authenticate. This is the ONE credential-verification routine in the platform: both the Razor login
		/// form and the anonymous JWT token endpoint reach it.
		/// </summary>
		/// <remarks>
		/// C-03 (CWE-916, CWE-759 / OWASP A02:2021). An unsalted MD5 digest was compared INSIDE the SQL
		/// predicate, which is what made the store unsaltable: a per-row salt means no single value can be
		/// compared for equality by the database. Fetching by address and verifying in application code is the
		/// ENABLING change for salted, work-factored hashing; it also carries the upgrade-on-next-authentication
		/// migration, makes verification fixed-time (CWE-208) and reaches no regular-expression engine (H-17).
		/// It would otherwise expose an enumeration oracle (CWE-203, CWE-208), a verification costing about
		/// 120 ms against well under a millisecond for an unknown address, so VerifyPassword REPORTS whether it
		/// derived and the compensating derivation is owed exactly when none happened.
		/// </remarks>
		public ErpUser GetUser(string email, string password)
		{
			if (string.IsNullOrWhiteSpace(email))
				return null;

			//an absent password authenticates nothing and is not an enumeration probe: it fails
			//identically for every account, existing or not
			if (string.IsNullOrWhiteSpace(password))
				return null;

			//no stored address can be longer than its column, so a longer input cannot match any row, and
			//rejecting it here bounds the operand an unauthenticated caller can submit
			if (email.Length > MaxEmailLength)
				return null;

			//THREAT ADDRESSED - CWE-400 (uncontrolled resource consumption) with CWE-208 (observable
			//timing discrepancy), OWASP A04:2021. The platform's only anonymous credential endpoint
			//accepted an unbounded plaintext, so a miss derived a key over the whole oversized value -
			//making the compensating dummy MORE expensive than the real path, which refuses on length
			//alone, and inverting the timing signal the dummy exists to remove. Refused BEFORE the query,
			//on a length the caller already supplied, so it touches no database and fails in identical
			//time for every address. No plaintext longer than the field maximum can match a stored hash.
			if (password.Length > PasswordUtil.MaxPasswordLength)
				return null;

			using (var ctx = SecurityContext.OpenSystemScope())
			using (RecordManager.OpenCredentialReadScope())
			{
				//THREAT ADDRESSED - H-17, CWE-1333 (inefficient regular expression complexity) and CWE-625
				//(permissive regular expression), OWASP A03:2021. Address resolution reaches no
				//regular-expression engine: the comparison is the database's own lower() on BOTH sides of a
				//BOUND parameter, which folds case through the same collation `~*` did, so the matched set
				//is unchanged and no account that could sign in before is locked out. EQL cannot express it
				//- CONTAINS and STARTSWITH compile to ILIKE with the caller's value interpolated, so "%"
				//would match every user - which is why the resolver issues its own parameterised query.
				var candidateRows = ResolveCredentialCandidates(email);

				//EXACTLY ONE EQL COMMAND PER REQUEST, matched or not, and a predicate of CONSTANT SHAPE:
				//skipping the query for an unknown address, or varying the predicate with the number of
				//matches, would make "no such account" cheaper than "wrong password" and reintroduce the
				//enumeration oracle (CWE-203, CWE-208). Absent candidates bind Guid.Empty, which matches no
				//row. IncludeEncryptedFieldValues IS REQUIRED, not an optimisation: the EQL projection
				//redacts an encrypted PasswordField by default (C-02), so without the opt-in every login
				//would fail; it is internal and init-only, so only this assembly can request it. PAGE
				//accompanies PAGESIZE because Eql/EqlBuilder.Sql.cs rejects either alone.
				var eqlParameters = new List<EqlParameter>();
				var predicate = new StringBuilder();

				for (var index = 0; index < MaxCredentialCandidates; index++)
				{
					var parameterName = "candidate_id_" + index.ToString(CultureInfo.InvariantCulture);

					if (index > 0)
						predicate.Append(" OR ");

					predicate.Append("id = @").Append(parameterName);

					eqlParameters.Add(new EqlParameter(parameterName,
						index < candidateRows.Count ? candidateRows[index].Id : Guid.Empty));
				}

				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE " + predicate.ToString()
						+ " PAGE 1 PAGESIZE " + MaxCredentialCandidates.ToString(CultureInfo.InvariantCulture),
						 eqlParameters) { IncludeEncryptedFieldValues = true }.Execute();

				//the database comparison is only a filter; this ordinal match is the authoritative decision.
				//Collecting matches before verifying is what lets a case-fold duplicate be counted and
				//reported rather than silently authenticated against whichever row came back first. No
				//de-duplication is needed: one query with a constant LIMIT cannot return a row twice.
				List<EntityRecord> candidates = new List<EntityRecord>();
				foreach (var rec in result)
				{
					string recordEmail = rec.Properties.ContainsKey("email") ? rec["email"] as string : null;
					if (string.Equals(recordEmail, email, StringComparison.OrdinalIgnoreCase))
						candidates.Add(rec);
				}

				//tracks whether the expensive path was actually taken, so the failure branch at the end can
				//spend the same work and leave no timing signal behind
				bool keyDerivationPerformed = false;

				foreach (var rec in candidates)
				{

					//THREAT ADDRESSED - C-02, CWE-200 / CWE-522, OWASP A01:2021 + A02:2021. The hash used to be
					//read out of the EQL projection, so that projection could not redact it - which is how
					//"SELECT password FROM user" returned every stored credential to any caller holding read
					//access on the user entity, as the regular role does. Every projection seam now redacts
					//unconditionally and this one internal single-column, single-row query is the only place
					//a stored credential is read. Keyed on the record's own identifier, so the row verified
					//is provably the row matched above.
					Guid recordId = rec.Properties.ContainsKey("id") && rec["id"] is Guid
						? (Guid)rec["id"]
						: Guid.Empty;

					string storedHash = recordId == Guid.Empty ? null : ReadStoredPasswordHash(recordId);

					//Whether this request spent a key derivation is taken from PasswordUtil as a FACT, never
					//inferred from the stored value's shape: "not a legacy digest, therefore a derivation
					//happened" is wrong for an over-long password and for a corrupt payload, and each wrong
					//answer skips the compensating derivation below and leaves a measurable timing signal.
					//Accumulated with |=, so a row that derived cannot be masked by a later row that did not.
					bool matched = PasswordUtil.VerifyPassword(password, storedHash, out bool needsRehash,
						out bool derivedForThisRow);
					keyDerivationPerformed |= derivedForThisRow;

					if (!matched)
						continue;

					var user = rec.MapTo<ErpUser>();

					//the OWASP-prescribed upgrade point: the plaintext is in hand here and nowhere else, so this
					//is the only moment a legacy or under-worked value can be replaced without forcing a
					//reset on the owner. recordId and storedHash are passed rather than re-derived, so the
					//compare-and-swap below is conditional on the SAME row and value this iteration verified.
					if (needsRehash)
						UpgradeStoredPasswordHash(recordId, password, storedHash);

					//A second stored account matching one address case-insensitively is a data-integrity fault -
					//it is what made the unbounded verification loop reachable. Reported only AFTER a correct
					//password has been presented, deliberately: reporting on every failed attempt would let
					//an anonymous caller who merely knows the address drive one system_log INSERT per
					//request, trading the CPU amplification just closed for a write amplification. It
					//repeats on each successful login until an operator removes the duplicate.
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
		/// one case-insensitively, and that stored address. The address travels with the identifier so the
		/// authoritative ordinal comparison can be made in application code without a second read, and so
		/// <see cref="IsEmailRegisteredToAnotherUser(string, Guid)"/> needs no query of its own.
		/// </summary>
		private struct CredentialCandidate
		{
			public Guid Id;
			public string Email;
		}

		/// <summary>
		/// Resolves the at most <see cref="MaxCredentialCandidates"/> stored rows whose address matches the
		/// submitted one case-insensitively, exact spelling first, projecting only the identifier and the stored
		/// address so the authoritative ordinal comparison can be made in application code.
		/// </summary>
		/// <remarks>
		/// H-17 (CWE-1333, CWE-625 / OWASP A03:2021). The lookup this replaces matched a PostgreSQL extended
		/// regular expression with <c>~*</c>, so caller-supplied text reached a regular-expression engine;
		/// <c>lower()</c> on BOTH sides of a bound parameter is behaviour-preserving, because both fold case
		/// through the same collation. It reads <c>rec_user</c> directly for the same reasons
		/// <see cref="ReadStoredPasswordHash(Guid)"/> does: EQL cannot express the comparison safely, and two
		/// columns of at most two rows cannot become a record read.
		/// </remarks>
		private static List<CredentialCandidate> ResolveCredentialCandidates(string email)
		{
			var candidates = new List<CredentialCandidate>(MaxCredentialCandidates);

			using (var connection = DbContext.Current.CreateConnection())
			{
				//lower() on both sides is the exact case-insensitive comparison, made by the database under one
				//collation with the caller's value bound; LIMIT is a constant written here.
				//THE ORDER IS THE CONTROL, NOT THE CAP - CWE-287 reached as an availability failure against
				//a legitimate account. The LIMIT stops one request costing N derivations, but a bound alone
				//truncates a duplicate set to whichever two ids sort lowest, locking the others out.
				//"email = @email" is a boolean, so DESC puts any row whose STORED spelling matches the
				//SUBMITTED spelling first, and id keeps the result deterministic.
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
		/// Reads the stored credential hash of one user row: the ONE place in the platform that reads a stored
		/// credential, and the read counterpart of
		/// <see cref="UpgradeStoredPasswordHash(Guid, string, string)"/>.
		/// </summary>
		/// <remarks>
		/// C-02 (CWE-200, CWE-522 / OWASP A01:2021 + A02:2021). Verification used to read the hash out of a query
		/// projection, which is what made the column unredactable in EQL; concentrating the read here is what let
		/// that seam become UNCONDITIONALLY redacting. The shape is the control: internal, and keyed on the row
		/// IDENTIFIER rather than caller-supplied text, so it cannot become a lookup primitive. A missing row, a
		/// NULL column and any read failure all yield null, which VerifyPassword rejects.
		/// </remarks>
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
		/// Replaces a stored credential that verified successfully but is out of date - a legacy MD5 digest, or a
		/// modern value written below the current work factor - with one produced at the current parameters. The
		/// second half of the backward-compatible migration, and why the format change needs no forced reset, no
		/// downtime and no schema change.
		/// </summary>
		/// <remarks>
		/// The write is a compare-and-swap, against a lost update with a security consequence (CWE-362, OWASP
		/// A04:2021): keyed on the user id alone, a login that authenticated with the OLD password could
		/// overwrite a reset committed in the meantime, RESTORING A CREDENTIAL THE OWNER HAD JUST REVOKED. With
		/// the expected value in the predicate the row is updated only while it still holds what this request
		/// verified, evaluated atomically, so no lock or retry loop is needed; zero affected rows is the benign
		/// outcome and is left unlogged, because logging it would give an unauthenticated caller of the token
		/// endpoint a log-amplification primitive. It writes a parameterized command rather than going through
		/// RecordManager because a pre-update hook may ABORT the write, so an installation with a hook on the
		/// user entity would silently never migrate - and DbRepository.UpdateRecord hard-codes "WHERE id=@id" and
		/// cannot express the compare-and-swap at all. Failure is non-fatal: the account has already presented a
		/// correct password, so failing the login over a maintenance write would be an outage.
		/// </remarks>
		/// <param name="userId">Identifier of the row whose password column is being replaced.</param>
		/// <param name="password">The plaintext just verified. Never stored, only re-hashed.</param>
		/// <param name="verifiedHash">The exact stored value just verified; the write is conditional on it.</param>
		private static void UpgradeStoredPasswordHash(Guid userId, string password, string verifiedHash)
		{
			try
			{
				//THREAT ADDRESSED - CWE-362. The window between reading the old hash and writing the new one is
				//hundreds of milliseconds wide, because a 600,000-iteration derivation has been paid in
				//between; a password changed by another route inside it would be REINSTATED by an
				//unconditional write. The guard is the row's own current value, so a concurrent change
				//affects zero rows and the upgrade is abandoned to the next authentication.
				if (string.IsNullOrEmpty(verifiedHash) || userId == Guid.Empty)
					return;

				string upgradedHash = PasswordUtil.HashPassword(password);

				//an empty result would blank the credential, so treat it as nothing to do
				if (string.IsNullOrEmpty(upgradedHash))
					return;

				//a no-op write is not merely wasteful here, it would compare a value against itself
				if (string.Equals(upgradedHash, verifiedHash, StringComparison.Ordinal))
					return;

				//Parameterized and executed on the platform's own connection, so it participates in the ambient
				//transaction exactly as ReadStoredPasswordHash does. The SQL is a fixed literal, every value
				//is bound, and it is issued directly because UpdateRecord keys on the identifier alone.
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

					//Zero affected rows is the expected, benign outcome of a concurrent change, deliberately not
					//logged: the condition is self-correcting on the next sign-in.
					command.ExecuteNonQuery();
				}
			}
			catch (Exception ex)
			{
				//THREAT ADDRESSED - CWE-778 (insufficient logging). The failure reported here is usually a
				//database failure, so it must not go through a bare database write that can throw again and
				//turn an already-verified credential into a server error; the shared reporter cannot throw.
				ReportCredentialMaintenanceFailure("A credential verified successfully but its stored hash could not be upgraded to the current format. The stored value is unchanged and the upgrade will be retried on the next authentication by this user.", ex);
			}
		}

		/// <summary>
		/// Records a credential-maintenance problem that must never be allowed to fail the authentication that
		/// discovered it.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-778 (insufficient logging) with the availability half of C-03. Both call sites
		/// run AFTER a correct password has been presented, so any exception escaping here would turn a valid
		/// login into a server error. The primary sink is still the platform log, which writes one parameterised
		/// INSERT and at the default notification status never reaches the mail path that e-mails details before
		/// persisting them; when that INSERT fails the loss is counted and the text goes to the standard error
		/// stream, and the count rides the next report that succeeds so a suppressing outage is visible IN the
		/// log. It is read before the write and subtracted only after it, so a concurrent loss is carried forward.
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
				//Counted BEFORE the fallback is attempted, so the loss is recorded even if the fallback also
				//fails. The one place in the credential path where a failure is absorbed, because
				//propagating would reject a credential that has already been verified.
				Interlocked.Increment(ref credentialMaintenanceReportFailures);

				try
				{
					Console.Error.WriteLine("[WebVella.Erp] " + CredentialMaintenanceLogSource
						+ ": a credential-maintenance report could not be persisted ("
						+ reportFailure.GetType().Name + "). " + detail);
				}
				catch (Exception)
				{
					//No usable error stream is left - a redirected, closed or disposed console. The increment
					//above is then the only surviving record of the loss, reported by the next call that
					//reaches the log. Anything further would reintroduce the escape this method prevents.
				}
			}
		}


		/// <summary>
		/// Reports whether any user OTHER than <paramref name="userId"/> already holds
		/// <paramref name="email"/>, comparing case-insensitively.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - the root cause behind the bounded verification loop described on
		/// <see cref="MaxCredentialCandidates"/> (CWE-1050, CWE-770 / OWASP A04:2021). The uniqueness probe was
		/// <see cref="GetUser(string)"/>, a case-SENSITIVE equality, so "User@example.com" could be stored
		/// alongside an existing "user@example.com" and the case-insensitive login lookup then resolved both rows
		/// for one address. Rejecting the duplicate at creation is the durable fix, and it reuses
		/// <see cref="ResolveCredentialCandidates(string)"/> so that "collides" here is character-for-character
		/// what login applies - a MORE permissive probe would let exactly the set login cannot resolve be
		/// created. The caller's own row is excluded by IDENTIFIER, because the address is what is changing, and
		/// the system scope is required because uniqueness is a property of the whole table.
		/// </remarks>
		/// <param name="email">The address being claimed.</param>
		/// <param name="userId">The account claiming it, excluded from the comparison.</param>
		/// <returns>True when a different account already holds the address.</returns>
		private static bool IsEmailRegisteredToAnotherUser(string email, Guid userId)
		{
			if (string.IsNullOrWhiteSpace(email))
				return false;

			//no stored address can be longer than its column, so a longer value cannot collide, and the
			//guard bounds the lookup exactly as the login path does
			if (email.Length > MaxEmailLength)
				return false;

			using (var ctx = SecurityContext.OpenSystemScope())
			{
				//THREAT ADDRESSED - H-17, CWE-1333 / CWE-625, OWASP A03:2021. This probe shared the login
				//path's regular-expression predicate, so it has to lose it too - and sharing
				//ResolveCredentialCandidates is what keeps the two definitions of "collides" identical.
				foreach (var candidate in ResolveCredentialCandidates(email))
				{
					//At most one returned row can be the caller's own, so two rows are enough to see a collision
					//whenever one exists, however many duplicates are already stored.
					if (candidate.Id == userId)
						continue;

					//as on the login path, the query is a filter and this ordinal comparison is the decision
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
					//THREAT ADDRESSED - CWE-1050/CWE-770 root cause: GetUser(string) matches case-SENSITIVELY, so
					//it accepted a case-fold duplicate that the case-INSENSITIVE login lookup then resolved to
					//two rows. IsEmailRegisteredToAnotherUser applies the login path's own definition.
					else if (IsEmailRegisteredToAnotherUser(user.Email, user.Id))
						valEx.AddError("email", "Email is already registered to another user. It must be unique.");
					else if (!IsValidEmail(user.Email))
						valEx.AddError("email", "Email is not valid.");
				}

				//THREAT ADDRESSED - CWE-841 (improper enforcement of behavioural workflow) on the first-login
				//rotation invariant. existingUser.Password is the REAL stored hash, but a caller that read
				//this account through any ORDINARY projection received
				//RecordManager.EncryptedFieldRedactedValue (C-02), so a round trip submitted the marker as
				//the "new" password: that cleared PasswordChangeRequired while the write seam correctly
				//refused to persist the marker over the hash, discharging the rotation requirement with no
				//replacement credential written. Excluded here rather than only at the write seam, because
				//the seam protects the hash and only skipping the branch protects the marker.
				if (existingUser.Password != user.Password && !string.IsNullOrWhiteSpace(user.Password)
					&& !string.Equals(user.Password, RecordManager.EncryptedFieldRedactedValue, StringComparison.Ordinal))
				{
					record["password"] = user.Password;

					//THREAT ADDRESSED - M-13, CWE-521 (weak password requirements), OWASP A07:2021. The record
					//write seam refuses a non-conforming password unconditionally and is the guarantee; this
					//restates the policy where a per-field validation channel exists, so an operator is told
					//which field is wrong instead of the generic "an internal error occurred". The reason
					//string is value-free, so the plaintext cannot reach the page or the log (CWE-532).
					string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(user.Password);
					if (passwordPolicyFailure != null)
						valEx.AddError("password", "Password is not acceptable because " + passwordPolicyFailure + ".");

					//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): a password is being written, so the
					//rotation debt is discharged and the first-login marker is cleared in the SAME record and
					//therefore the same write - clearing it separately would leave a window in which the
					//password had changed but a bearer token was still refused, and clearing it anywhere but
					//alongside a password write would discharge the requirement without rotating anything.
					//existingUser.Preferences is the STORED value and is used in preference to
					//user.Preferences because the SDK user manage screen assigns a blank ErpUserPreferences
					//before calling here, so the caller's copy would discard sidebar and usage state.
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

					//THREAT ADDRESSED - M-13, CWE-521, OWASP A07:2021. The create-path twin of the check in the
					//update branch above; the two branches must not diverge.
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
