using Npgsql;
using Storage.Net;
using Storage.Net.Blobs;
using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Diagnostics;

namespace WebVella.Erp.Database
{
	public class DbFileRepository
	{
		public const string FOLDER_SEPARATOR = "/";
		public const string TMP_FOLDER_NAME = "tmp";

		// SECURITY - review finding INT-13 (Major), CWE-770 allocation of resources without limits, and the
		// latent half of the same defect, CWE-200 exposure of sensitive information. The ILIKE pattern that
		// matches every staged file and nothing else. Staged paths are `/tmp/<section>/<name>` - see
		// CreateTempFile - so the pattern must be ANCHORED AT THE START. The previous `%/tmp` form matched only
		// paths ENDING in `/tmp`, which no staged path ever does, so both queries that used it silently matched
		// nothing: CleanupExpiredTempFiles deleted no abandoned upload at all, and FindAll's `includeTempFiles:
		// false` excluded no staged file from a listing it promised not to include them in. Expressed once here,
		// from the same two constants IsStagedFilePath composes, so the SQL definition of "staged" cannot drift
		// from the C# one that guards access to those same files.
		private const string STAGED_PATH_PATTERN = FOLDER_SEPARATOR + TMP_FOLDER_NAME + FOLDER_SEPARATOR + "%";

		// SECURITY - finding F24 (High), CWE-639 authorization bypass through user-controlled key, OWASP
		// A01:2021 Broken Access Control. Bounds the caller-influenced path written into the audit record so a
		// very long staged path cannot inflate the system_log table one refusal at a time. The value matches
		// MAX_LOGGED_PATH_LENGTH in WebApiController, which bounds the same class of value for the same reason.
		private const int MAX_LOGGED_FILE_PATH_LENGTH = 400;

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

		public DbFileRepository(DbContext currentContext = null)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
		}
		/// <summary>
		/// Resolves a stored file by its path, refusing a staged (temp) file the caller does not own.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding F24 (High), CWE-639 authorization bypass through user-controlled key,
		/// OWASP A01:2021 Broken Access Control.
		/// THREAT: temp files were created with <c>created_by</c> NULL and every consumer accepted a
		/// caller-supplied path, so the GUID section in <c>/tmp/&lt;section&gt;/&lt;name&gt;</c> WAS the
		/// authorization. Anyone who learned or guessed a staged path could download another user's staged
		/// upload, promote it into their own <c>user_file</c> record through
		/// <c>UserFileService.CreateUserFile</c>, attach it to their own record through the file-field
		/// promotion in <c>RecordManager</c>, or feed it to the CSV import - an insecure direct object
		/// reference on a value that is not, and was never intended to be, a secret.
		/// <para>
		/// WHY THE CHECK LIVES HERE AND ONLY HERE: this repository is the single object every one of those
		/// consumers goes through, and <see cref="Copy"/>, <see cref="Move"/> and <see cref="Delete"/> each
		/// resolve their operands through this method before acting - so gating this one method gates read,
		/// consume, move and delete from ONE implementation, which is exactly what the finding requires. The
		/// eight consumer call sites span two assemblies; eight local copies would be neither reviewable nor
		/// reliably identical, and a ninth consumer added later would silently miss the control.
		/// </para>
		/// <para>
		/// SCOPE IS DELIBERATELY LIMITED TO STAGED PATHS. Permanent files are shared by design - a file
		/// attached to a record must be readable by everyone who may read that record, and <c>/fs/</c> is a
		/// live inline asset origin that PcFieldImage and PcFieldFile render into <c>img</c> tags - so an
		/// owner-only rule over all files would break record attachments platform-wide and breach the
		/// requirement that existing functionality be preserved. Permanent files stay governed by the entity
		/// and record permissions already enforced in the data layer for the records that reference them, and
		/// nothing changes for them here. A staged file, by contrast, is private scratch space: it exists only
		/// between an upload and the save that promotes it, and no shipped flow has one user consume another
		/// user's staged file.
		/// </para>
		/// <para>
		/// WHY REFUSAL IS EXPRESSED AS "NOT FOUND" rather than as an exception: every caller already has a
		/// not-found path - the download action answers 404, the CSV import answers "File does not exist!",
		/// and <c>CreateUserFile</c> and <see cref="Move"/> raise their own "cannot be found" - so the control
		/// reuses behaviour that already exists instead of introducing a new failure mode, and it does not
		/// confirm to someone probing paths that a guessed value names a real file.
		/// </para>
		/// </remarks>
		public DbFile Find(string filepath)
		{
			return Find(filepath, out _);
		}

		/// <summary>
		/// Resolves a stored file by its path exactly as <see cref="Find(string)"/> does, and additionally
		/// reports whether a row WAS present at that path but was withheld by the staged-ownership rule.
		/// </summary>
		/// <param name="filepath">Caller-supplied stored path.</param>
		/// <param name="withheldByStagedOwnership">
		/// True when a row exists at <paramref name="filepath"/> and this caller may not have it. False both
		/// when the file was returned and when no row exists at all.
		/// </param>
		/// <remarks>
		/// SECURITY - finding F24 (High), CWE-639, OWASP A01:2021. The ACCESS DECISION is unchanged: this is
		/// the same single implementation, the same ownership test and the same audit record, and the
		/// returned file is null in exactly the same cases. Only the CALLER'S ability to tell the two null
		/// cases apart is new.
		/// <para>
		/// WHY IT IS NEEDED. <see cref="Find(string)"/> expresses a refusal AS "not found", which is the
		/// right answer to a client but the wrong input to a caller that has to classify the outcome: a
		/// deliberate access-control refusal was reaching <c>UserFileService.CreateUserFile</c>'s plain
		/// "file not found" throw and being filed by the API surface as an unhandled system fault, while the
		/// dedicated <c>UnauthorizedAccessException</c> guard written for exactly that case could never run.
		/// The web-API move action had the mirror-image defect: its target-side authorization guard was
		/// skipped because the withheld row read as absent, and the operation was stopped only by a UNIQUE
		/// constraint surfacing as an unhandled exception - a zero-length response body instead of the
		/// endpoint's own refusal envelope.
		/// <para>
		/// THE FLAG MUST NOT REACH A CLIENT AS A DISTINGUISHING SIGNAL. It exists so a caller can pick the
		/// correct SERVER-SIDE classification - a refusal rather than a fault - and so it can answer with
		/// its own generic denial. Every caller must map both null cases onto the SAME response text it
		/// already uses, or the "not found is indistinguishable from not yours" property this control relies
		/// on is lost. Both current consumers do exactly that.
		/// </para>
		/// </para>
		/// </remarks>
		public DbFile Find(string filepath, out bool withheldByStagedOwnership)
		{
			withheldByStagedOwnership = false;

			if (string.IsNullOrWhiteSpace(filepath))
				throw new ArgumentException("filepath cannot be null or empty");

			var file = FindInternal(filepath);

			if (file != null && !IsStagedFileAccessAuthorized(file))
			{
				withheldByStagedOwnership = true;
				return null;
			}

			return file;
		}

		/// <summary>
		/// Unauthorized lookup. Used only where the ownership test must NOT apply.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F24 (High), CWE-639, OWASP A01:2021. Three call sites need the raw row and would
		/// malfunction, not merely refuse, if they went through <see cref="Find"/>:
		/// <c>Create</c>'s duplicate guard (a refusal there would let a second row be inserted for a filepath
		/// that already exists, after which the single-row lookup would never resolve it again), <c>Create</c>'s
		/// two reads of the row it has just inserted (a refusal would return null from a create that
		/// succeeded, and <c>CreateTempFile</c>'s caller dereferences the result), and <see cref="Move"/>'s
		/// post-commit read (the move has already been committed, so a refusal would make
		/// <c>UserFileService</c> roll back a completed promotion). None of the three is an access-control
		/// decision: each operates on a row the same call has just created or just moved. Every path that IS
		/// an access-control decision goes through <see cref="Find"/>.
		/// </remarks>
		private DbFile FindInternal(string filepath)
		{
			//all filepaths are lowercase and all starts with folder separator
			filepath = filepath.ToLowerInvariant();
			if (!filepath.StartsWith(FOLDER_SEPARATOR))
				filepath = FOLDER_SEPARATOR + filepath;

			using (var connection = CurrentContext.CreateConnection())
			{
				var command = connection.CreateCommand("SELECT * FROM files WHERE filepath = @filepath ");
				command.Parameters.Add(new NpgsqlParameter("@filepath", filepath));
				DataTable dataTable = new DataTable();
				new NpgsqlDataAdapter(command).Fill(dataTable);

				if (dataTable.Rows.Count == 1)
					return new DbFile(dataTable.Rows[0]);
			}

			return null;
		}

		/// <summary>
		/// Resolves a stored file by its ALREADY-NORMALISED path on the SUPPLIED connection, taking a row
		/// lock that is held until the surrounding transaction ends.
		/// </summary>
		/// <param name="connection">
		/// The connection the caller has already begun a transaction on. The lock belongs to that
		/// transaction, so passing a connection with no transaction acquires and immediately releases it,
		/// which would prove nothing - every caller must therefore be inside <c>BeginTransaction</c>.
		/// </param>
		/// <param name="normalizedFilepath">
		/// A path already lower-cased and prefixed with the folder separator, exactly as
		/// <see cref="FindInternal"/> normalises. No normalisation is repeated here, so the caller and this
		/// method cannot disagree about which row is being locked.
		/// </param>
		/// <returns>The locked row, or null when no row exists at that path.</returns>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-367 (time-of-check to time-of-use race condition), OWASP A01:2021 Broken
		/// Access Control. Comparing an identifier against a row read on an EARLIER connection only narrows
		/// the race window; it does not close it, because the row can still change between that read and the
		/// write. <c>FOR UPDATE</c> is what closes it: once this returns, no other transaction can update or
		/// delete that row until this one ends, so an authorization decision taken on it stays true for the
		/// duration of the mutation.
		/// <para>
		/// THIS IS A LOCK, NOT AN ACCESS DECISION, and the distinction is deliberate. It deliberately does
		/// NOT apply the staged-ownership rule, because <see cref="Find(string)"/> remains the single place
		/// that rule lives - see the remarks on <see cref="FindInternal"/> for why that invariant matters.
		/// Callers take the lock first and then call <see cref="Find(string)"/> on the locked row, so the
		/// decision is still made in exactly one implementation, and it is made on a row that can no longer
		/// change underneath it. Re-implementing the rule here would create a second copy of it to audit.
		/// </para>
		/// <para>
		/// A path with NO row cannot be locked - there is nothing to lock - so absence must be defended a
		/// different way. The <c>files.filepath</c> UNIQUE constraint supplies it: a concurrent request that
		/// occupies the path is serialised by that index, and the losing statement fails rather than
		/// silently overwriting. See <see cref="Move(string, string, bool, Guid?, bool, Guid?)"/>.
		/// </para>
		/// </remarks>
		private static DbFile FindForUpdate(DbConnection connection, string normalizedFilepath)
		{
			var command = connection.CreateCommand("SELECT * FROM files WHERE filepath = @filepath FOR UPDATE");
			command.Parameters.Add(new NpgsqlParameter("@filepath", normalizedFilepath));
			DataTable dataTable = new DataTable();
			new NpgsqlDataAdapter(command).Fill(dataTable);

			if (dataTable.Rows.Count == 1)
				return new DbFile(dataTable.Rows[0]);

			return null;
		}

		/// <summary>
		/// Resolves the recorded owner of each supplied file path in a single round trip.
		/// </summary>
		/// <param name="filepaths">Paths to resolve. Normalised the same way <see cref="Find(string)"/> normalises.</param>
		/// <returns>
		/// A map from normalised path to the identifier recorded in created_by, which is null for a file
		/// stored without an owner. Paths with no matching row are absent from the map.
		/// </returns>
		/// <remarks>
		/// THREAT ADDRESSED - insecure direct object reference through list enumeration, CWE-639
		/// (authorization bypass through a user-controlled key), OWASP A01:2021 Broken Access Control. The
		/// user-file listing returns every stored media record to any caller holding the entity read
		/// permission, and that permission is granted to the regular role - so one user could enumerate
		/// another's uploads. The owner is recorded on the FILE row rather than on the record, and the record
		/// table has no owner column, so the listing has to consult this table to make an ownership decision.
		/// <para>
		/// It is a BULK lookup on purpose. Resolving each row with <see cref="Find(string)"/> would issue one
		/// query per listed item - thirty per page at the default page size - and turn an authorization filter
		/// into a measurable regression on a listing endpoint. One parameterised query with an ANY(...) array
		/// predicate keeps the added cost at a single round trip. The array is bound as a parameter, so no
		/// caller-supplied path is ever concatenated into the statement.
		/// </para>
		/// <para>
		/// Only the identifier is selected. The bytes are never touched, so this stays cheap regardless of how
		/// large the listed files are.
		/// </para>
		/// </remarks>
		public Dictionary<string, Guid?> FindOwnersByPaths(ICollection<string> filepaths)
		{
			var owners = new Dictionary<string, Guid?>(StringComparer.Ordinal);
			if (filepaths == null || filepaths.Count == 0)
				return owners;

			//normalised exactly as Find normalises, so a caller may pass the value it holds without having to
			//know the storage convention
			var normalized = new List<string>();
			foreach (var filepath in filepaths)
			{
				if (string.IsNullOrWhiteSpace(filepath))
					continue;

				var candidate = filepath.ToLowerInvariant();
				if (!candidate.StartsWith(FOLDER_SEPARATOR, StringComparison.Ordinal))
					candidate = FOLDER_SEPARATOR + candidate;

				if (!normalized.Contains(candidate))
					normalized.Add(candidate);
			}

			if (normalized.Count == 0)
				return owners;

			using (var connection = CurrentContext.CreateConnection())
			{
				var command = connection.CreateCommand("SELECT filepath, created_by FROM files WHERE filepath = ANY(@filepaths) ");
				command.Parameters.Add(new NpgsqlParameter("@filepaths", normalized.ToArray()));
				DataTable dataTable = new DataTable();
				new NpgsqlDataAdapter(command).Fill(dataTable);

				foreach (DataRow row in dataTable.Rows)
				{
					var storedPath = (string)row["filepath"];
					Guid? createdBy = row["created_by"] == DBNull.Value ? (Guid?)null : (Guid)row["created_by"];
					owners[storedPath] = createdBy;
				}
			}

			return owners;
		}

		/// <summary>
		/// The single ownership decision for staged (temp) files.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding F24 (High), CWE-639, OWASP A01:2021. Called from <see cref="Find"/> and
		/// therefore reached from every read, consume, move and delete path in the platform.
		/// Deny-by-default applies at each uncertain edge, which is the first clause of the authorization
		/// standard this audit applies: an unresolvable principal refuses, and a staged file with no recorded
		/// owner refuses for anyone who is not an administrator. That last rule is not invented here - it is
		/// exactly what <c>WebApiController.IsFileMutationAuthorized</c> already does for the move and delete
		/// actions, and matching it keeps one consistent rule across the platform instead of two that
		/// disagree. It is also what makes the pre-existing ownerless rows left behind by earlier releases
		/// fail closed rather than open.
		/// </remarks>
		private static bool IsStagedFileAccessAuthorized(DbFile file)
		{
			//permanent files are out of scope by design - see the remarks on Find
			if (!IsStagedFilePath(file.FilePath))
				return true;

			var currentUser = SecurityContext.CurrentUser;
			if (currentUser != null)
			{
				//ErpUser.IsAdmin is the platform's own role test rather than a hand-rolled comparison, and it
				//also covers the built-in system principal, which SecurityContext grants the administrator
				//role - so background jobs, provisioning and plugin code running inside OpenSystemScope are
				//unaffected and need no special case here.
				if (currentUser.IsAdmin)
					return true;

				if (file.CreatedBy.HasValue && file.CreatedBy.Value == currentUser.Id)
					return true;
			}

			LogStagedFileAccessRefusal(file, currentUser);
			return false;
		}

		/// <summary>
		/// True when the supplied stored path names a staged (temp) file.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F24 (High), CWE-639, OWASP A01:2021. The test is ANCHORED at the start of the
		/// path and requires the segment to end at a separator, so a permanent path that merely contains the
		/// three characters - <c>/document/tmp-report.pdf</c>, or a hypothetical <c>/tmproot/x</c> - is not
		/// mistaken for staged space and does not acquire an owner-only rule it was never meant to have.
		/// The comparison is ordinal and needs no case handling because both operands are already lower-case:
		/// every stored filepath is lower-cased by <c>Create</c> and every lookup path by
		/// <c>FindInternal</c>. The segment boundary is expressed exactly as <c>RecordManager</c>'s own two
		/// promotion tests express it - the constant pair, not a literal - so the definition of "staged"
		/// cannot drift between the place that promotes such a file and the place that guards it.
		/// </remarks>
		private static bool IsStagedFilePath(string storedFilePath)
		{
			var prefix = FOLDER_SEPARATOR + TMP_FOLDER_NAME;

			if (string.IsNullOrEmpty(storedFilePath) || !storedFilePath.StartsWith(prefix, StringComparison.Ordinal))
				return false;

			return storedFilePath.Length == prefix.Length
				|| storedFilePath.Substring(prefix.Length, 1) == FOLDER_SEPARATOR;
		}

		/// <summary>
		/// Records a refused staged-file access.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F24 (High), CWE-639, OWASP A01:2021. "Log authorization failures" is an
		/// explicit, separate clause of the authorization standard this audit applies, so a refusal is
		/// recorded rather than merely returned.
		/// <para>
		/// THE OVERLOAD AND THE NOTIFICATION STATUS ARE BOTH DELIBERATE. The message-and-details overload is
		/// used, and <c>DoNotNotify</c> is passed EXPLICITLY because the parameter's default is
		/// <c>NotNotified</c> - the mailing path - and <c>Log</c>'s exception overload sends an outbound SMTP
		/// message before it persists. Routing a refusal through either would let someone enumerating staged
		/// paths generate one e-mail per attempt, turning an access-control log into an unauthenticated
		/// amplification primitive. Only the acting identity, the requested path and the reason are recorded;
		/// no file content is, and the caller-supplied path is length-bounded, quoted and neutralised by
		/// <see cref="AuditField(string, int)"/> so it can forge neither a field nor a record.
		/// </para>
		/// </remarks>
		private static void LogStagedFileAccessRefusal(DbFile file, ErpUser currentUser)
		{
			var reason = currentUser == null
				? "unresolved principal"
				: (file.CreatedBy.HasValue ? "caller is not the owner of the staged file" : "staged file has no recorded owner");

			// THREAT ADDRESSED - CWE-117 (improper output neutralisation for logs), OWASP A09:2021
			// Security Logging and Monitoring Failures. This record is "name=value; name=value" text and
			// requested_path is the CALLER'S path, so the length bound that stood alone here was not
			// sufficient: the delimiters are PRINTABLE, so no control character was even needed. A staged
			// file relocated to `/tmp/x; reason=caller is the owner; extra=pwned.txt` - which MoveFile
			// accepts, since it only lower-cases the target - read back as a well-formed record whose
			// reason field the attacker chose, placing a forged exculpatory value AHEAD of the genuine
			// one. A literal line feed in the same position forged an entire additional record, complete
			// with a fabricated user_id. Either way the party this refusal exists to incriminate wrote
			// part of it. AuditField quotes the value, escapes the quote and the escape character so a
			// delimiter inside it cannot end the field, and neutralises control characters so it cannot
			// forge a record.
			//
			// user_id and reason are deliberately left unquoted: the first is a Guid or the fixed literal
			// "anonymous", and the second is one of three fixed literals chosen immediately above, so
			// neither can carry a delimiter and only the caller-supplied field needs quoting.
			//
			// The neutraliser is a local helper rather than WebVella.Erp.Web.Utils.SecurityAuditLog.Field,
			// which applies the identical treatment at the sibling refusal writer in
			// WebApiController.LogFileAuthorizationFailure: that type is internal to WebVella.Erp.Web and
			// this repository is in WebVella.Erp (core), which that assembly depends ON, so it is not
			// reachable from here in either accessibility or dependency terms. See AuditField.
			new Log().Create(LogType.Error, "DbFileRepository:Find",
				"Authorization failure: access to a staged file refused.",
				"user_id=" + (currentUser == null ? "anonymous" : currentUser.Id.ToString("D", CultureInfo.InvariantCulture))
					+ "; requested_path=" + AuditField(file.FilePath, MAX_LOGGED_FILE_PATH_LENGTH)
					+ "; reason=" + reason,
				LogNotificationStatus.DoNotNotify);
		}

		/// <summary>
		/// Renders a caller-supplied value as a single, unambiguous, quoted audit field.
		/// </summary>
		/// <param name="value">
		/// The caller-supplied value. A null or empty value yields <c>""</c> - an explicitly empty field
		/// rather than nothing at all, so "absent" and "blank" stay distinguishable from a missing field.
		/// </param>
		/// <param name="maxLength">Maximum number of characters retained from <paramref name="value"/>.</param>
		/// <remarks>
		/// SECURITY - CWE-117, OWASP A09:2021. Quoting is what removes the ambiguity a printable
		/// delimiter creates - a semicolon inside quotes is unmistakably part of the value - and escaping
		/// the quote and the escape character is what stops the quoting itself from being escaped out of.
		/// Control characters are REPLACED rather than stripped: replacement removes the record-forging
		/// primitive while keeping the surrounding text legible and the same length, so a reader can
		/// still see that something odd was submitted.
		/// <para>
		/// Escaping is deliberately done in ONE pass that inspects each source character and emits its
		/// escape immediately. That structure makes the classic failure here impossible rather than
		/// merely avoided: written as two sequential replacements the passes must run backslash-first,
		/// because a quote-first pass introduces a backslash the later pass then doubles - turning
		/// <c>\"</c> into <c>\\"</c> and handing the closing quote straight back to the attacker. Anyone
		/// refactoring this into sequential replacements reintroduces that ordering obligation.
		/// </para>
		/// <para>
		/// Bounding is applied to the RAW value before escaping - it is also the only bound applied to
		/// this value now, replacing the truncation that used to stand at the call site - so the retained
		/// amount of caller data is exactly <see cref="MAX_LOGGED_FILE_PATH_LENGTH"/> and does not shrink
		/// as a function of how many characters needed escaping. Escaping can therefore expand the result
		/// past <paramref name="maxLength"/>, which is intended: the bound governs attacker-supplied
		/// content, not the delimiters this method adds. It cannot throw for any input, because the
		/// caller is an authorization refusal that must still refuse when logging misbehaves.
		/// </para>
		/// <para>
		/// This mirrors <c>WebVella.Erp.Web.Utils.SecurityAuditLog.Field</c> character for character. The
		/// duplication is deliberate and unavoidable: that helper is internal to WebVella.Erp.Web, which
		/// depends on this assembly, so sharing it would invert the dependency direction. Any change to
		/// the escaping rules must be made in both places, which is why both carry the same rationale.
		/// </para>
		/// </remarks>
		private static string AuditField(string value, int maxLength)
		{
			if (string.IsNullOrEmpty(value) || maxLength <= 0)
				return "\"\"";

			var bounded = value.Length <= maxLength ? value : value.Substring(0, maxLength);

			// Sized for the common case where nothing needs escaping: the value plus its two quotes.
			var builder = new StringBuilder(bounded.Length + 2);
			builder.Append('"');
			foreach (var character in bounded)
			{
				if (char.IsControl(character))
				{
					// Replaced, not stripped, so length and legibility survive while the record-forging
					// primitive does not.
					builder.Append(' ');
				}
				else if (character == '\\' || character == '"')
				{
					// Both the escape character and the quote are escaped, in the same pass that reads
					// them, so an escape this method emits is never itself re-escaped. See the remarks.
					builder.Append('\\');
					builder.Append(character);
				}
				else
				{
					builder.Append(character);
				}
			}

			builder.Append('"');
			return builder.ToString();
		}

		public List<DbFile> FindAll(string startsWithPath = null, bool includeTempFiles = false, int? skip = null, int? limit = null)
		{
			//all filepaths are lowercase and all starts with folder separator
			if (!string.IsNullOrWhiteSpace(startsWithPath))
			{
				startsWithPath = startsWithPath.ToLowerInvariant();

				if (!startsWithPath.StartsWith(FOLDER_SEPARATOR))
					startsWithPath = FOLDER_SEPARATOR + startsWithPath;
			}

			string pagingSql = string.Empty;
			if (limit != null || skip != null)
			{
				pagingSql = " LIMIT ";
				if (limit.HasValue)
					pagingSql = pagingSql + limit + " ";
				else
					pagingSql = pagingSql + "ALL ";

				if (skip.HasValue)
					pagingSql = pagingSql + " OFFSET " + skip;
			}

			DataTable table = new DataTable();
			using (var connection = CurrentContext.CreateConnection())
			{
				var command = connection.CreateCommand(string.Empty);
				if (!includeTempFiles && !string.IsNullOrWhiteSpace(startsWithPath))
				{
					command.CommandText = "SELECT * FROM files WHERE filepath NOT ILIKE @tmp_path AND filepath ILIKE @startswith" + pagingSql;
					command.Parameters.Add(new NpgsqlParameter("@tmp_path", STAGED_PATH_PATTERN));
					command.Parameters.Add(new NpgsqlParameter("@startswith", "%" + startsWithPath));
					new NpgsqlDataAdapter(command).Fill(table);
				}
				else if (!string.IsNullOrWhiteSpace(startsWithPath))
				{
					command.CommandText = "SELECT * FROM files WHERE filepath ILIKE @startswith" + pagingSql;
					command.Parameters.Add(new NpgsqlParameter("@startswith", "%" + startsWithPath));
					new NpgsqlDataAdapter(command).Fill(table);
				}
				else if (!includeTempFiles)
				{
					command.CommandText = "SELECT * FROM files WHERE filepath NOT ILIKE @tmp_path " + pagingSql;
					command.Parameters.Add(new NpgsqlParameter("@tmp_path", STAGED_PATH_PATTERN));
					new NpgsqlDataAdapter(command).Fill(table);
				}
				else
				{
					command.CommandText = "SELECT * FROM files " + pagingSql;
					new NpgsqlDataAdapter(command).Fill(table);
				}
			}

			List<DbFile> files = new List<DbFile>();
			foreach (DataRow row in table.Rows)
				files.Add(new DbFile(row));

			return files;
		}

		public DbFile Create(string filepath, byte[] buffer, DateTime? createdOn, Guid? createdBy)
		{
			if (string.IsNullOrWhiteSpace(filepath))
				throw new ArgumentException("filepath cannot be null or empty");

			//all filepaths are lowercase and all starts with folder separator
			filepath = filepath.ToLowerInvariant();
			if (!filepath.StartsWith(FOLDER_SEPARATOR))
				filepath = FOLDER_SEPARATOR + filepath;

			//SECURITY - finding F24: FindInternal, not Find. A duplicate guard is not an access-control
			//decision, and a refusal here would let a second row be inserted for an existing filepath, after
			//which the single-row lookup could never resolve it again. See the remarks on FindInternal.
			if (FindInternal(filepath) != null)
				throw new ArgumentException(filepath + ": file already exists");

			using (var connection = CurrentContext.CreateConnection())
			{
				try
				{
					uint objectId = 0;
					connection.BeginTransaction();

					if (!ErpSettings.EnableFileSystemStorage)
					{
						var manager = new NpgsqlLargeObjectManager(connection.connection);
						objectId = manager.Create();

						using (var stream = manager.OpenReadWrite(objectId))
						{
							stream.Write(buffer, 0, buffer.Length);
							stream.Close();
						}
					}


					var command = connection.CreateCommand(@"INSERT INTO files(id,object_id,filepath,created_on,modified_on,created_by,modified_by)
															 VALUES (@id,@object_id,@filepath,@created_on,@modified_on,@created_by,@modified_by)");

					command.Parameters.Add(new NpgsqlParameter("@id", Guid.NewGuid()));
					command.Parameters.Add(new NpgsqlParameter("@object_id", (decimal)objectId));
					command.Parameters.Add(new NpgsqlParameter("@filepath", filepath));
					var date = createdOn ?? DateTime.UtcNow;
					command.Parameters.Add(new NpgsqlParameter("@created_on", date));
					command.Parameters.Add(new NpgsqlParameter("@modified_on", date));
					command.Parameters.Add(new NpgsqlParameter("@created_by", (object)createdBy ?? DBNull.Value));
					command.Parameters.Add(new NpgsqlParameter("@modified_by", (object)createdBy ?? DBNull.Value));

					command.ExecuteNonQuery();

					//SECURITY - finding F24: FindInternal, not Find. This reads back the row this call has
					//just inserted, so it is not an access-control decision; going through Find would return
					//null from a create that succeeded. See the remarks on FindInternal.
					var result = FindInternal(filepath);

					if(ErpSettings.EnableCloudBlobStorage)
					{
						var path = GetBlobPath(result);
						using (IBlobStorage storage = GetBlobStorage())
						{
							storage.WriteAsync(path,
								buffer).Wait();
						}
					}
					else if (ErpSettings.EnableFileSystemStorage)
					{
						var path = GetFileSystemPath(result);
						var folderPath = Path.GetDirectoryName(path);
						if (!Directory.Exists(folderPath))
							Directory.CreateDirectory(folderPath);
						using (Stream stream = File.Open(path, FileMode.CreateNew, FileAccess.ReadWrite))
						{
							stream.Write(buffer, 0, buffer.Length);
							stream.Close();
						}
					}

					connection.CommitTransaction();
				}
				catch (Exception)
				{
					connection.RollbackTransaction();
					throw;
				}
			}

			//SECURITY - finding F24: FindInternal, not Find. This is Create's own return value, read back
			//after a committed insert, so it is not an access-control decision. Going through Find would make
			//CreateTempFile return null to a caller that dereferences it. See the remarks on FindInternal.
			return FindInternal(filepath);
		}

		public DbFile UpdateModificationDate(string filepath, DateTime modificationDate)
		{
			if (string.IsNullOrWhiteSpace(filepath))
				throw new ArgumentException("filepath cannot be null or empty");

			//all filepaths are lowercase and all starts with folder separator
			filepath = filepath.ToLowerInvariant();
			if (!filepath.StartsWith(FOLDER_SEPARATOR))
				filepath = FOLDER_SEPARATOR + filepath;

			using (var connection = CurrentContext.CreateConnection())
			{
				var file = Find(filepath);
				if (file == null)
					throw new ArgumentException("file does not exist");

				var command = connection.CreateCommand(@"UPDATE files SET modified_on = @modified_on WHERE id = @id");
				command.Parameters.Add(new NpgsqlParameter("@id", Guid.NewGuid()));
				command.Parameters.Add(new NpgsqlParameter("@modified_on", modificationDate));
				command.ExecuteNonQuery();

				return Find(filepath);
			}
		}

		/// <summary>
		/// copy file from source to destination location
		/// </summary>
		/// <param name="sourceFilepath"></param>
		/// <param name="destinationFilepath"></param>
		/// <param name="overwrite"></param>
		/// <returns></returns>
		public DbFile Copy(string sourceFilepath, string destinationFilepath, bool overwrite = false)
		{
			if (string.IsNullOrWhiteSpace(sourceFilepath))
				throw new ArgumentException("sourceFilepath cannot be null or empty");

			if (string.IsNullOrWhiteSpace(destinationFilepath))
				throw new ArgumentException("destinationFilepath cannot be null or empty");

			sourceFilepath = sourceFilepath.ToLowerInvariant();
			destinationFilepath = destinationFilepath.ToLowerInvariant();

			if (!sourceFilepath.StartsWith(FOLDER_SEPARATOR))
				sourceFilepath = FOLDER_SEPARATOR + sourceFilepath;

			if (!destinationFilepath.StartsWith(FOLDER_SEPARATOR))
				destinationFilepath = FOLDER_SEPARATOR + destinationFilepath;

			var srcFile = Find(sourceFilepath);
			var destFile = Find(destinationFilepath);

			if (srcFile == null)
				throw new Exception("Source file cannot be found.");

			if (destFile != null && overwrite == false)
				throw new Exception("Destination file already exists and no overwrite specified.");

			using (var connection = CurrentContext.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();

					if (destFile != null && overwrite)
						Delete(destFile.FilePath);

					var bytes = srcFile.GetBytes(connection);
					var newFile = Create(destinationFilepath, bytes, srcFile.CreatedOn, srcFile.CreatedBy);

					connection.CommitTransaction();
					return newFile;
				}
				catch
				{
					connection.RollbackTransaction();
					throw;
				}
			}
		}

		/// <summary>
		/// moves file from source to destination location
		/// </summary>
		/// <param name="sourceFilepath"></param>
		/// <param name="destinationFilepath"></param>
		/// <param name="overwrite"></param>
		/// <param name="expectedSourceId">
		/// Identifier of the row the CALLER authorized. When supplied, the move is applied only if the row
		/// still at <paramref name="sourceFilepath"/> is that exact row, and the method returns null when it
		/// is not. Mandatory when <paramref name="enforceExpectedTarget"/> is set.
		/// </param>
		/// <param name="enforceExpectedTarget">
		/// True when the caller has authorized the DESTINATION as well as the source and requires this
		/// method to apply the mutation only to the destination state it authorized. Defaults to false, in
		/// which case every existing caller behaves exactly as before.
		/// </param>
		/// <param name="expectedTargetId">
		/// Meaningful only when <paramref name="enforceExpectedTarget"/> is set. A value means "the caller
		/// authorized exactly this destination row"; null means "the caller authorized an ABSENT
		/// destination". The two are different authorizations and must not be conflated, which is why the
		/// expectation needs its own flag rather than being inferred from a null identifier.
		/// </param>
		/// <returns>
		/// The moved file, or null when the authorized state no longer holds - the source row is gone or is
		/// no longer <paramref name="expectedSourceId"/>, or the destination no longer matches the
		/// authorized expectation.
		/// </returns>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-367 (time-of-check to time-of-use race condition) and CWE-639
		/// (authorization bypass through a user-controlled key), OWASP A01:2021 Broken Access Control. Every
		/// object-level authorization for a file mutation is necessarily performed on a row read by an
		/// EARLIER call - Find opens and closes its own connection - so between the check and this write
		/// another request can move a different user's file onto the authorized path. The mutation would then
		/// be applied to a row nobody authorized, and because this method also DELETES the destination when
		/// overwrite is set, the consequence is destructive rather than merely wrong.
		/// <para>
		/// THE DESTINATION HALF WAS THE UNCLOSED HALF, and it was the dangerous one. An earlier revision
		/// pinned only the SOURCE, and pinned it with an identifier comparison against a row this method
		/// re-read on its own connection - which narrowed the window without closing it. The destination was
		/// not pinned at all: the caller authorized one destination row and this method then resolved the
		/// destination AGAIN, so <c>overwrite</c> deleted whichever row happened to be at that path when the
		/// second read ran. A caller who legitimately owned the source could therefore have another user's
		/// file destroyed under them by a concurrent move that landed on the authorized target path between
		/// the two reads - the authorization was real, but it was not the authorization that got applied.
		/// </para>
		/// <para>
		/// HOW IT IS CLOSED. Both operands are now resolved INSIDE the single transaction that performs the
		/// delete and the update, and each is locked with <see cref="FindForUpdate"/> before it is resolved,
		/// so no other transaction can change either row while this one runs. The access decision is still
		/// taken by <see cref="Find(string)"/> on the locked row, so the staged-ownership rule keeps living
		/// in exactly one place. When <paramref name="enforceExpectedTarget"/> is set, the locked
		/// destination's identity must equal <paramref name="expectedTargetId"/> - including the
		/// absent-equals-absent case - and any mismatch is refused rather than applied. The UPDATE
		/// additionally re-asserts that the source row is still AT the source path, which the previous
		/// identifier-only predicate did not.
		/// </para>
		/// <para>
		/// AN ABSENT DESTINATION CANNOT BE LOCKED, so it is defended by the <c>files.filepath</c> UNIQUE
		/// constraint instead: a concurrent request that occupies the path is serialised by that index and
		/// this statement fails rather than overwriting. In enforced mode that failure is translated into the
		/// same refusal as any other mismatch, so a race answers the endpoint's own denial envelope instead
		/// of escaping as an unhandled fault with an empty body.
		/// </para>
		/// <para>
		/// THE UPDATE IS A COMPARE-AND-SWAP ON THE PATH, not on the identifier. An earlier predicate read
		/// "id = @id AND id = @expected_id", whose second conjunct was a tautology once the identifier had
		/// already been compared above: it re-asserted the identifier and never the PATH, while every
		/// storage-side operation further down addresses the object BY PATH -
		/// <c>storage.DeleteAsync(sourceFilepath)</c> and <c>File.Move(GetFileSystemPath(...))</c>. The
		/// predicate therefore also requires the row to still be AT the source path, and the affected-row
		/// count must be exactly ONE before any storage-side operation runs. With the row lock held that
		/// count cannot be zero, and the primary key makes more than one impossible; the assertion is kept
		/// regardless, because an irreversible storage operation must never proceed on the strength of an
		/// unchecked count. <see cref="Delete"/> applies the same rule through
		/// <see cref="TryLockRowByPath"/>, which proves an identifier and a path still belong together for
		/// callers that hold no prior lock on the row.
		/// </para>
		/// <para>
		/// Returning null rather than throwing is deliberate: the caller is an HTTP action that must answer a
		/// generic refusal, and an exception there would surface as a 500 carrying internal detail.
		/// </para>
		/// </remarks>
		public DbFile Move(string sourceFilepath, string destinationFilepath, bool overwrite = false, Guid? expectedSourceId = null, bool enforceExpectedTarget = false, Guid? expectedTargetId = null)
		{
			if (string.IsNullOrWhiteSpace(sourceFilepath))
				throw new ArgumentException("sourceFilepath cannot be null or empty");

			if (string.IsNullOrWhiteSpace(destinationFilepath))
				throw new ArgumentException("destinationFilepath cannot be null or empty");

			sourceFilepath = sourceFilepath.ToLowerInvariant();
			destinationFilepath = destinationFilepath.ToLowerInvariant();

			if (!sourceFilepath.StartsWith(FOLDER_SEPARATOR))
				sourceFilepath = FOLDER_SEPARATOR + sourceFilepath;

			if (!destinationFilepath.StartsWith(FOLDER_SEPARATOR))
				destinationFilepath = FOLDER_SEPARATOR + destinationFilepath;

			//An enforced target expectation without a source expectation would authorize the destination
			//while leaving the source unpinned, which is half a control. This is an internal contract
			//violation rather than a runtime condition - the only enforcing caller always supplies both - so
			//it is raised the same way this method already raises its other argument violations, and it fails
			//closed rather than degrading silently into the unpinned behaviour.
			if (enforceExpectedTarget && !expectedSourceId.HasValue)
				throw new ArgumentException("expectedSourceId is required when enforceExpectedTarget is set");

			using (var connection = CurrentContext.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();

					//THREAT ADDRESSED - CWE-367, OWASP A01:2021. Both operands are resolved INSIDE this
					//transaction and each is LOCKED before it is resolved. The lock comes first so that the
					//row Find then reads, and the row the statements below mutate, are provably the same
					//row: FindForUpdate holds it for the whole transaction. Resolution used to happen before
					//the transaction opened, on connections that were closed again before the write, which
					//is what left a window for another request to substitute a different file behind either
					//path. See the remarks above for why the destination half was the dangerous one.
					//
					//THREAT ADDRESSED - CWE-833 (deadlock). BOTH locks are taken here, up front, and in
					//ORDINAL PATH ORDER rather than source-then-destination. Two concurrent moves naming the
					//same pair of paths in opposite directions would otherwise each hold the row the other
					//needs: PostgreSQL detects that and aborts one transaction with an error, which on this
					//path escapes as an unhandled fault instead of this method's own generic refusal - the
					//exact outcome the whole check exists to avoid. Ordering both acquisitions by the path
					//string makes the two requests contend on the SAME row first, so one queues behind the
					//other and both still resolve to a refusal or a completed move.
					DbFile lockedSourceRow;
					DbFile lockedTargetRow;
					if (string.CompareOrdinal(sourceFilepath, destinationFilepath) <= 0)
					{
						lockedSourceRow = FindForUpdate(connection, sourceFilepath);
						lockedTargetRow = FindForUpdate(connection, destinationFilepath);
					}
					else
					{
						lockedTargetRow = FindForUpdate(connection, destinationFilepath);
						lockedSourceRow = FindForUpdate(connection, sourceFilepath);
					}

					DbFile srcFile = null;
					if (lockedSourceRow != null)
					{
						//Find, not the locked row, is the ACCESS decision - it applies the staged-ownership
						//rule and records a refusal. Reading through it here keeps that rule in one place
						//while still deciding on a row that can no longer change.
						srcFile = Find(sourceFilepath);
					}

					if (srcFile == null)
					{
						if (enforceExpectedTarget)
						{
							//An enforcing caller has its own refusal envelope to answer with. Throwing here
							//would reach it as an unhandled fault - an empty response body - and would file a
							//deliberate access-control outcome as a system error.
							connection.RollbackTransaction();
							return null;
						}

						//The rollback is left to the catch below rather than performed here: DbConnection
						//clears its transaction on the first rollback, so rolling back and then throwing
						//would make that catch's own rollback the failure the caller sees.
						throw new Exception("Source file cannot be found.");
					}

					//see the remarks above - the authorized row must still be the row at this path, and the
					//same identifier is then carried into the UPDATE below
					if (expectedSourceId.HasValue && srcFile.Id != expectedSourceId.Value)
					{
						connection.RollbackTransaction();
						return null;
					}

					//lockedTargetRow was acquired above, together with the source lock and in ordinal path
					//order, so that the two acquisitions cannot deadlock against a concurrent move of the
					//same pair in the opposite direction.

					//THREAT ADDRESSED - CWE-367 and CWE-639, OWASP A01:2021, on the DESTRUCTIVE half of this
					//operation. The identity of the locked destination must be exactly the destination state
					//the caller authorized. Nullable equality covers all three outcomes in one comparison: a
					//caller who authorized an existing row requires that same row, a caller who authorized an
					//absent destination requires it to still be absent, and anything else - including a row
					//withheld from this caller by the staged-ownership rule, which reads as absent through
					//Find but is visible to the lock - is a mismatch and is refused.
					if (enforceExpectedTarget && lockedTargetRow?.Id != expectedTargetId)
					{
						connection.RollbackTransaction();
						return null;
					}

					//In enforced mode the row to overwrite is the LOCKED row: the caller has already taken
					//the access decision on that exact identity, and the line above proved the row still
					//carries it, so resolving it through Find a second time would only add a query and, on a
					//raced substitution, a second refusal record for one refusal. In the default mode the
					//destination is resolved through Find exactly as before, so a destination withheld by the
					//staged-ownership rule keeps its existing behaviour rather than silently becoming
					//overwritable.
					var destFileToOverwrite = enforceExpectedTarget
						? lockedTargetRow
						: (lockedTargetRow == null ? null : Find(destinationFilepath));

					//As above, the rollback belongs to the catch below and must not be duplicated here.
					if (destFileToOverwrite != null && overwrite == false)
						throw new Exception("Destination file already exists and no overwrite specified.");

					if (destFileToOverwrite != null && overwrite)
						Delete(destFileToOverwrite.FilePath, destFileToOverwrite.Id);

					//The predicate is widened from "id = @id" to also require the row to still be the
					//authorized one AND to still be at the source path - an identifier alone would have let a
					//row that had been moved elsewhere be relocated to this destination. Every half is
					//parameterised, so no value is concatenated into SQL.
					var command = connection.CreateCommand(expectedSourceId.HasValue
						? @"UPDATE files SET filepath = @filepath WHERE id = @id AND id = @expected_id AND filepath = @source_filepath"
						: @"UPDATE files SET filepath = @filepath WHERE id = @id AND filepath = @source_filepath");
					command.Parameters.Add(new NpgsqlParameter("@source_filepath", sourceFilepath));
					command.Parameters.Add(new NpgsqlParameter("@id", srcFile.Id));
					command.Parameters.Add(new NpgsqlParameter("@filepath", destinationFilepath));
					command.Parameters.Add(new NpgsqlParameter("@source_filepath", sourceFilepath));

					if (command.ExecuteNonQuery() != 1)
					{
						//Exactly one row, or nothing happens. Zero cannot occur while the FindForUpdate locks
						//taken above are held, and more than one is impossible under the primary key, so either
						//is a fault that must stop before the storage-side move. The assertion is kept even
						//though it is unreachable, because an irreversible storage operation must never run on
						//the strength of an unchecked affected-row count.
						connection.RollbackTransaction();

						//Any caller that supplied an expectation - of the source row, of the destination row, or
						//of both - is answered with the refusal envelope its endpoint already renders, never an
						//exception: a 500 carrying internal detail is exactly what the callers must not emit.
						if (expectedSourceId.HasValue || enforceExpectedTarget)
							return null;

						//An unpinned caller is refused with the same message this method already raises for a
						//source path that resolves to no row, because that is precisely what has become true of
						//the path it named. The type is the specific FileNotFoundException rather than the bare
						//Exception used by the absent-source check near the top of this method: CA2201 refuses
						//the reserved base type in new code, and that pre-existing raise is left untouched under
						//the minimal-change constraint. Nothing observable changes for a caller - the message is
						//byte-identical and a derived type is still caught by any catch(Exception).
						throw new FileNotFoundException("Source file cannot be found.");
					}

					if(ErpSettings.EnableCloudBlobStorage)
					{
						var srcPath = StoragePath.Combine(StoragePath.RootFolderPath, sourceFilepath);
						var destinationPath = StoragePath.Combine(StoragePath.RootFolderPath, destinationFilepath);
						using (IBlobStorage storage = GetBlobStorage())
						{
							using (Stream original = storage.OpenReadAsync(srcPath).Result)
							{
								if (original != null)
								{
									storage.WriteAsync(destinationPath, original).Wait();
									storage.DeleteAsync(sourceFilepath).Wait();
								}
							}

						}
					}
					else if (ErpSettings.EnableFileSystemStorage)
					{
						var srcFileName = Path.GetFileName(sourceFilepath);
						var destFileName = Path.GetFileName(destinationFilepath);
						if (srcFileName != destFileName)
						{
							var fsSrcFilePath = GetFileSystemPath(srcFile);
							srcFile.FilePath = destinationFilepath;
							var fsDestFilePath = GetFileSystemPath(srcFile);
							File.Move(fsSrcFilePath, fsDestFilePath);
						}
					}

					connection.CommitTransaction();
					//SECURITY - finding F24: FindInternal, not Find. The move is already committed at this
					//point, so this read is not an access-control decision - the decision was taken above,
					//where the SOURCE was resolved through Find. Going through Find here would return null
					//after a successful move, which UserFileService interprets as "File move from temp folder
					//failed" and rolls a completed promotion back. See the remarks on FindInternal.
					return FindInternal(destinationFilepath);
				}
				//THREAT ADDRESSED - CWE-367, OWASP A01:2021, at the ONE case a row lock cannot cover: a
				//destination the caller authorized as ABSENT. There is no row to lock, so a concurrent
				//request can occupy that path after the absence was established. The files.filepath UNIQUE
				//constraint is what stops the overwrite - the losing UPDATE is serialised by that index and
				//then fails - but an unhandled failure is the wrong ANSWER: it reaches the caller as a system
				//fault with an empty body and is filed as a bug rather than as the access-control outcome it
				//is. Translating it into the same refusal every other mismatch produces keeps the response
				//indistinguishable, so a race cannot be used to discover which target paths hold real files.
				//Scoped to enforced callers by the filter, so no existing caller's exception behaviour
				//changes, and scoped to the unique-violation state alone, so no other database fault is
				//swallowed.
				catch (PostgresException uniqueViolation) when (enforceExpectedTarget
					&& uniqueViolation.SqlState == PostgresErrorCodes.UniqueViolation)
				{
					connection.RollbackTransaction();
					return null;
				}
				catch
				{
					connection.RollbackTransaction();
					throw;
				}
			}
		}


		/// <summary>
		/// deletes file
		/// </summary>
		/// <param name="filepath"></param>
		/// <param name="expectedFileId">
		/// Identifier of the row the CALLER authorized. When supplied, the delete is abandoned if the row now
		/// at <paramref name="filepath"/> is a different one.
		/// </param>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-367 (time-of-check to time-of-use race condition) on an IRREVERSIBLE
		/// operation, OWASP A01:2021 Broken Access Control. See the remarks on
		/// <see cref="Move(string, string, bool, Guid?, bool, Guid?)"/>: the ownership check that permits a delete is
		/// performed on a row read by an earlier call on an earlier connection, so without pinning a
		/// concurrent move could place another user's file at this path and have it destroyed under an
		/// authorization that was never granted for it.
		/// <para>
		/// The pin is applied whether or not <paramref name="expectedFileId"/> is supplied, so the parameter
		/// no longer decides WHETHER the row is proved - only that the caller has an identifier to state.
		/// Review finding CR3-H-05 records why: the guard used to run AFTER the external bytes had already
		/// been removed, and its affected-row count was discarded, so the condition could not prevent
		/// anything. Identity is now proved by <see cref="TryLockRowByPath"/> and re-asserted by the
		/// <c>DELETE</c>, whose affected-row count must be exactly one, BEFORE any byte is touched.
		/// </para>
		/// </remarks>
		public void Delete(string filepath, Guid? expectedFileId = null)
		{
			if (string.IsNullOrWhiteSpace(filepath))
				throw new ArgumentException("filepath cannot be null or empty");

			//all filepaths are lowercase and all starts with folder separator
			filepath = filepath.ToLowerInvariant();
			if (!filepath.StartsWith(FOLDER_SEPARATOR))
				filepath = FOLDER_SEPARATOR + filepath;

			var file = Find(filepath);

			if (file == null)
				return;

			//the authorized row must still be the row at this path - see the remarks above
			if (expectedFileId.HasValue && file.Id != expectedFileId.Value)
				return;

			using (var connection = CurrentContext.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();

					//THREAT ADDRESSED - review finding CR3-H-05, CWE-367 (time-of-check to time-of-use) on
					//an IRREVERSIBLE operation, OWASP A01:2021. The previous ordering removed the external
					//bytes FIRST and only then ran a conditional DELETE whose affected-row count it discarded,
					//which inverted the whole point of the condition: by the time the database was asked
					//whether this row was still the authorized one, the object it described had already been
					//destroyed. A concurrent move that put another user's file at this path therefore
					//destroyed that user's bytes and then left their metadata row intact, so the refusal was
					//recorded nowhere and the loss was silent.
					//Identity is now proved BEFORE anything irreversible happens, in two steps that are both
					//required. SELECT ... FOR UPDATE proves the identifier and the path still belong together
					//and holds a row lock for the rest of the transaction, so no concurrent writer can
					//separate them afterwards; the DELETE then re-asserts the same pair and its affected-row
					//count is CHECKED rather than ignored, because an irreversible operation must never
					//proceed on an unverified count.
					//The pin is applied whether or not expectedFileId was supplied. An unpinned caller
					//resolved this row by path a moment ago through Find, so requiring the pair to still hold
					//is the semantics it already believed it had; the only behaviour that changes is that a
					//raced delete is abandoned instead of applied to whatever row now holds the identifier.
					if (!TryLockRowByPath(connection, file.Id, filepath))
					{
						//Nothing has been touched. Returning matches this method's existing contract for a
						//path that resolves to no row - which is exactly what a concurrent move has made
						//true - and it leaves the other user's file intact.
						connection.RollbackTransaction();
						return;
					}

					//Ordered BEFORE the byte removal, deliberately. The row is the only durable record of
					//which object these bytes belong to, so proving we may remove it is the precondition for
					//removing them - not a formality to be completed afterwards.
					var command = connection.CreateCommand(
						@"DELETE FROM files WHERE id = @id AND filepath = @filepath");
					command.Parameters.Add(new NpgsqlParameter("@id", file.Id));
					command.Parameters.Add(new NpgsqlParameter("@filepath", filepath));

					if (command.ExecuteNonQuery() != 1)
					{
						//Exactly one row, or nothing happens. Zero cannot occur while the lock above is held
						//and more than one is impossible under the primary key, so either is a fault that
						//must stop before the bytes are gone.
						connection.RollbackTransaction();
						return;
					}

					//COMPENSATION, stated rather than implied. From here the two stores are removed in the
					//order that makes a partial failure recoverable in the SAFE direction:
					//  * the large-object path enlists in this transaction, so Unlink and the row DELETE
					//    commit or roll back together and cannot diverge at all;
					//  * the blob and filesystem paths cannot enlist. Both are guarded by an existence check
					//    and are therefore idempotent, so a retry converges. If one throws, the catch below
					//    rolls the row back and the metadata survives while the bytes may already be gone -
					//    an orphaned row, which is reportable and repairable. That is the deliberate choice
					//    over the alternative ordering, which on the same failure destroys bytes the database
					//    still claims are present and, before this change, could destroy bytes belonging to a
					//    row the caller was never authorized to touch.
					if(ErpSettings.EnableCloudBlobStorage && file.ObjectId == 0)
					{
						var path = GetBlobPath(file);
						using (IBlobStorage storage = GetBlobStorage())
						{
							if (storage.ExistsAsync(path).Result)
							{
								storage.DeleteAsync(path).Wait();
							}
						}
					} else if (ErpSettings.EnableFileSystemStorage && file.ObjectId == 0)
					{
						var path = GetFileSystemPath(file);
						if( File.Exists(path))
							File.Delete(path);
					}
					else
					{
						if( file.ObjectId != 0 )
							new NpgsqlLargeObjectManager(connection.connection).Unlink(file.ObjectId);
					}

					connection.CommitTransaction();
				}
				catch
				{
					connection.RollbackTransaction();
					throw;
				}
			}
		}

		/// <summary>
		/// Takes a row lock on the <c>files</c> row with the given identifier, and reports whether that row
		/// is still the row at the given path.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - review finding CR3-H-05, CWE-367 (time-of-check to time-of-use race condition),
		/// OWASP A01:2021 Broken Access Control.
		/// <para>
		/// Every object-level authorization for a file mutation is necessarily performed on a row read by an
		/// EARLIER call on an EARLIER connection, because <see cref="Find(string)"/> opens and closes its own.
		/// Re-reading the row inside the mutating transaction narrows that window but does not close it: a
		/// concurrent writer can still change the row between the re-read and the write. <c>FOR UPDATE</c> is
		/// what closes it, by holding the lock until the transaction ends, so the identifier-and-path pair
		/// this method proves is still true when the caller acts on it.
		/// </para>
		/// <para>
		/// It exists as one shared helper rather than as two inline queries because both mutating paths need
		/// the identical guarantee and the two must not be allowed to drift - one of them having a weaker
		/// predicate than the other is exactly the defect this finding reported.
		/// </para>
		/// <para>
		/// Both values are bound as parameters. <c>NOWAIT</c> is deliberately NOT used: a concurrent mutation
		/// of the same row is rare and short, so waiting for it is correct, whereas failing immediately would
		/// turn ordinary contention into a refusal. The surrounding transaction's own timeout bounds the wait.
		/// </para>
		/// </remarks>
		/// <param name="connection">The connection carrying the mutating transaction.</param>
		/// <param name="fileId">Identifier of the row the caller resolved and was authorized for.</param>
		/// <param name="filepath">Normalised path that row must still hold.</param>
		/// <returns>True when the row exists at that path and is now locked; false otherwise.</returns>
		private static bool TryLockRowByPath(DbConnection connection, Guid fileId, string filepath)
		{
			var command = connection.CreateCommand(
				@"SELECT id FROM files WHERE id = @id AND filepath = @filepath FOR UPDATE");
			command.Parameters.Add(new NpgsqlParameter("@id", fileId));
			command.Parameters.Add(new NpgsqlParameter("@filepath", filepath));

			using (var reader = command.ExecuteReader())
			{
				var located = reader.Read();
				reader.Close();
				return located;
			}
		}

		//THREAT ADDRESSED - finding F-05, insecure direct object reference (OWASP A01:2021 - Broken
		//Access Control). The object-level authorization guard on the file move and delete actions in
		//WebVella.Erp.Web/Controllers/WebApiController.cs proves ownership from files.created_by, and
		//denies by default when that column is null. Every temporary file was created here with a
		//hardcoded null, so an upload could never be proved to belong to the caller who made it: the
		//ownership test silently degraded into an administrator-only test, and the upload-then-move
		//workflow the file components rely on stopped working for every other role. Recording the
		//creator is what makes that guard a real ownership check rather than a role check. The value
		//survives promotion to a permanent path, because Move updates only the filepath column.
		//The audit inventory records the file-lifecycle authorization findings under OWASP A01 with NO
		//CWE assigned, so none is claimed here. The parameter is optional and defaults to the previous
		//null so platform-internal callers, which have no authenticated principal to record, keep their
		//existing behaviour byte for byte.
		/// <summary>
		/// create temp file
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="extension"></param>
		/// <param name="createdBy">the authenticated principal to record as the file's creator, or null
		/// when the platform itself creates the file rather than acting on behalf of a caller</param>
		/// <returns></returns>
		/// <summary>
		/// Creates a file in the temporary namespace.
		/// </summary>
		/// <param name="filename">The already-validated file name.</param>
		/// <param name="buffer">The file content.</param>
		/// <param name="extension">Optional extension appended to the name.</param>
		/// <param name="createdBy">
		/// Identifier of the principal the file belongs to, or null when it is created by the platform itself
		/// rather than on behalf of a user.
		/// </param>
		/// <remarks>
		/// THREAT ADDRESSED - insecure direct object reference, OWASP A01:2021 Broken Access Control. Every
		/// temporary file this method created carried NO owner, because the created-by argument was hard-wired
		/// to null. That has two consequences once the file paths are authorized by ownership, and they pull
		/// in opposite directions, which is why the owner has to be recorded rather than worked around: an
		/// unowned file cannot be attributed to the caller who uploaded it, so the uploader is denied their
		/// own file moments later when the record save moves it out of the temporary namespace; and if the
		/// ownership checks instead accepted unowned files from anyone in order to keep that workflow
		/// alive, the temporary namespace would become a shared area in which any authenticated caller could
		/// operate on any other caller's pending upload.
		/// The parameter is optional and defaults to null, so the platform's own callers - which have no user
		/// context - are unaffected.
		/// </remarks>
		public DbFile CreateTempFile(string filename, byte[] buffer, string extension = null, Guid? createdBy = null)
		{
			if (!string.IsNullOrWhiteSpace(extension))
			{
				extension = extension.Trim().ToLowerInvariant();
				if (!extension.StartsWith("."))
					extension = "." + extension;
			}

			string section = Guid.NewGuid().ToString().Replace("-", "").ToLowerInvariant();
			var tmpFilePath = FOLDER_SEPARATOR + TMP_FOLDER_NAME + FOLDER_SEPARATOR + section + FOLDER_SEPARATOR + filename + extension ?? string.Empty;

			// THREAT ADDRESSED - finding F24 (High), CWE-639 authorization bypass through user-controlled key,
			// OWASP A01:2021 Broken Access Control. createdBy was hard-coded null here, and that is precisely
			// what made a staged file ownerless and left its "/tmp/<section>/" path as the only thing standing
			// between an attacker and another user's upload. Recording the creator is the ENABLING half of the
			// control in Find: without an owner there is nothing for the ownership test to compare against.
			// BOTH CHANNELS ARE HONOURED, explicit first. This method DOES take a createdBy parameter - the four
			// upload actions in Controllers/WebApiController.cs resolve the owner themselves and pass it - so
			// that argument wins and is never overridden. SecurityContext.CurrentUser is the FALLBACK for a
			// caller that passes nothing, which the pipeline can almost always supply: ErpMiddleware opens a
			// scope for every authenticated request, and background, provisioning and plugin code runs inside
			// OpenSystemScope. A null remains possible only when neither is available, and it is left null
			// rather than defaulted to any identity: Find refuses an ownerless staged file for every
			// non-administrator, so the deny-by-default outcome is preserved rather than papered over.
			return Create(tmpFilePath, buffer, DateTime.UtcNow, createdBy ?? SecurityContext.CurrentUser?.Id);
		}

		/// <summary>
		/// Deletes staged (temporary) files that were created longer ago than <paramref name="expiration"/>.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding INT-13 (Major), CWE-770 allocation of resources without limits or
		/// throttling, OWASP A04:2021 Insecure Design.
		/// THREAT ADDRESSED: this is the only cleanup the platform has for abandoned uploads, and it deleted
		/// NOTHING. Staged files live at <c>/tmp/&lt;section&gt;/&lt;name&gt;</c> - see
		/// <see cref="CreateTempFile(string, byte[], string, System.Guid?)"/> - while the pattern matched paths
		/// ENDING in <c>/tmp</c>, which no staged path ever does, so the query returned an empty set on every
		/// call. An upload that was never promoted to a permanent path therefore persisted for the lifetime of
		/// the installation, at up to the per-request upload ceiling each, and the store grew without bound for
		/// any caller willing to upload and walk away. The <paramref name="expiration"/> argument was also
		/// accepted and then ignored, so a caller asking for a conservative age filter silently got none - which
		/// is why fixing the pattern without honouring the age would have been the more dangerous half-fix,
		/// turning an inert method into one that could delete an upload still in flight.
		/// <para>
		/// AGE IS TAKEN FROM <c>created_on</c>, not <c>modified_on</c>: staging time is what "abandoned" means
		/// here, and <see cref="UpdateModificationDate(string, System.DateTime)"/> can move the modified stamp
		/// forward for reasons that have nothing to do with the upload being live. Both values are
		/// parameterised, and the comparison is against UTC because <c>Create</c> stamps UTC.
		/// </para>
		/// <para>
		/// FAILURES ARE ACCOUNTED PER ROW rather than allowed to abort the pass. One unreadable blob, one
		/// missing file on a storage backend or one row another caller has already removed used to stop the
		/// whole cleanup, leaving every later row in place - the same shape of defect as the queue starvation in
		/// the mail plugin. Each failure is recorded with its backend error text, so an operator can alert on
		/// those records rather than inferring success from the absence of an exception. The signature is left
		/// exactly as it was, deliberately: this is a public member of a published library, and returning a count
		/// would be a binary-breaking change to a method whose defect is fixable without one.
		/// </para>
		/// <para>
		/// CALL IT INSIDE <c>SecurityContext.OpenSystemScope()</c>, or as an administrator. <see cref="Delete"/>
		/// resolves the path through <see cref="Find(string)"/>, which refuses a staged file belonging to
		/// another non-administrative principal (finding F24) and returns null - so under an ordinary user's
		/// scope this method would silently skip every upload except that user's own and report no failures at
		/// all. NOTHING IN THE PLATFORM CALLS THIS YET, deliberately: scheduling it is a deployment decision,
		/// and adding a background job to drive it would be feature work outside this remediation. The operator
		/// guidance is recorded in docs/security/secure-configuration.md and the residual in
		/// docs/security/risk-register.md.
		/// </para>
		/// </remarks>
		/// <param name="expiration">Minimum age a staged file must have reached before it is deleted.</param>
		public void CleanupExpiredTempFiles(TimeSpan expiration)
		{
			DataTable table = new DataTable();
			using (var connection = CurrentContext.CreateConnection())
			{
				var command = connection.CreateCommand(string.Empty);
				command.CommandText = "SELECT filepath FROM files WHERE filepath ILIKE @tmp_path AND created_on < @expired_before";
				command.Parameters.Add(new NpgsqlParameter("@tmp_path", STAGED_PATH_PATTERN));
				command.Parameters.Add(new NpgsqlParameter("@expired_before", DateTime.UtcNow.Subtract(expiration)));
				new NpgsqlDataAdapter(command).Fill(table);
			}

			foreach (DataRow row in table.Rows)
			{
				var filepath = (string)row["filepath"];
				try
				{
					Delete(filepath);
				}
				catch (Exception ex)
				{
					//INT-13: one row must not cost the rest of the pass. The path is length-bounded and
					//neutralised by AuditField for the same reason it is everywhere else in this file - it is
					//caller-supplied text reaching a "name=value" log record (CWE-117).
					new Log().Create(LogType.Error, "DbFileRepository.CleanupExpiredTempFiles",
						"A staged file could not be deleted during cleanup; the pass continued.",
						$"filepath={AuditField(filepath, MAX_LOGGED_FILE_PATH_LENGTH)}; error={AuditField(ex.Message, MAX_LOGGED_FILE_PATH_LENGTH)}",
						LogNotificationStatus.DoNotNotify);
				}
			}
		}

		internal static IBlobStorage GetBlobStorage(string overrideConnectionString = null)
		{
			return StorageFactory.Blobs.FromConnectionString(string.IsNullOrWhiteSpace(overrideConnectionString) ? ErpSettings.CloudBlobStorageConnectionString : overrideConnectionString);
		}

		internal static string GetFileSystemPath(DbFile file)
		{
			var guidIinitialPart = file.Id.ToString().Split(new[] { '-' })[0];
			var fileName = file.FilePath.Split(new[] { '/' }).Last();
			var depth1Folder = guidIinitialPart.Substring(0, 2);
			var depth2Folder = guidIinitialPart.Substring(2, 2);
			// BUG: https://docs.microsoft.com/en-us/dotnet/api/system.io.path.getextension?view=net-5.0
			// Path.GetExtension includes the "." which means further on we are adding double "."
			// Would probably ruin too many databases to just fix here though
			string filenameExt = Path.GetExtension(fileName);

			if (!string.IsNullOrWhiteSpace(filenameExt))
				return Path.Combine(ErpSettings.FileSystemStorageFolder, depth1Folder, depth2Folder, file.Id + "." + filenameExt);

			else
				return Path.Combine(ErpSettings.FileSystemStorageFolder, depth1Folder, depth2Folder, file.Id.ToString());
		}


		internal static string GetBlobPath(DbFile file)
		{
			var guidIinitialPart = file.Id.ToString().Split(new[] { '-' })[0];
			var fileName = file.FilePath.Split(new[] { '/' }).Last();
			var depth1Folder = guidIinitialPart.Substring(0, 2);
			var depth2Folder = guidIinitialPart.Substring(2, 2);
			string filenameExt = Path.GetExtension(fileName);


			if (!string.IsNullOrWhiteSpace(filenameExt))
				return StoragePath.Combine(depth1Folder, depth2Folder, file.Id + filenameExt);
			else
				return StoragePath.Combine(depth1Folder, depth2Folder, file.Id.ToString());

		}

	}
}
