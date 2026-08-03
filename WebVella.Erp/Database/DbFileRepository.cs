using Npgsql;
using Storage.Net;
using Storage.Net.Blobs;
using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Diagnostics;

namespace WebVella.Erp.Database
{
	public class DbFileRepository
	{
		public const string FOLDER_SEPARATOR = "/";
		public const string TMP_FOLDER_NAME = "tmp";

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
			if (string.IsNullOrWhiteSpace(filepath))
				throw new ArgumentException("filepath cannot be null or empty");

			var file = FindInternal(filepath);

			if (file != null && !IsStagedFileAccessAuthorized(file))
				return null;

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
		/// no file content is, and the path is length-bounded.
		/// </para>
		/// </remarks>
		private static void LogStagedFileAccessRefusal(DbFile file, ErpUser currentUser)
		{
			var loggedPath = file.FilePath ?? string.Empty;
			if (loggedPath.Length > MAX_LOGGED_FILE_PATH_LENGTH)
				loggedPath = loggedPath.Substring(0, MAX_LOGGED_FILE_PATH_LENGTH);

			var reason = currentUser == null
				? "unresolved principal"
				: (file.CreatedBy.HasValue ? "caller is not the owner of the staged file" : "staged file has no recorded owner");

			new Log().Create(LogType.Error, "DbFileRepository:Find",
				"Authorization failure: access to a staged file refused.",
				"user_id=" + (currentUser == null ? "anonymous" : currentUser.Id.ToString("D", CultureInfo.InvariantCulture))
					+ "; requested_path=" + loggedPath
					+ "; reason=" + reason,
				LogNotificationStatus.DoNotNotify);
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
					command.Parameters.Add(new NpgsqlParameter("@tmp_path", "%" + FOLDER_SEPARATOR + TMP_FOLDER_NAME));
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
					command.Parameters.Add(new NpgsqlParameter("@tmp_path", "%" + FOLDER_SEPARATOR + TMP_FOLDER_NAME));
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
		/// is not.
		/// </param>
		/// <returns>
		/// The moved file, or null when <paramref name="expectedSourceId"/> was supplied and the row at the
		/// source path is no longer the authorized one.
		/// </returns>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-367 (time-of-check to time-of-use race condition), OWASP A01:2021 Broken
		/// Access Control. Every object-level authorization for a file mutation is necessarily performed on a
		/// row read by an EARLIER call on an EARLIER connection - Find opens and closes its own connection -
		/// so between the check and this write another request can move a different user's file onto the
		/// authorized path. The mutation would then be applied to a row nobody authorized, and because this
		/// method also DELETES the destination when overwrite is set, the consequence is destructive rather
		/// than merely wrong.
		/// <para>
		/// The optional identifier closes that window without changing any existing call: it defaults to
		/// null, and when it is null this method behaves exactly as before. When it is supplied, the row is
		/// pinned - the UPDATE carries "AND id = @expected_id", so the database itself decides whether the
		/// authorized row is still the one at that path, and a raced request affects zero rows and is
		/// reported back as a refusal instead of being silently applied.
		/// </para>
		/// <para>
		/// Returning null rather than throwing is deliberate: the caller is an HTTP action that must answer a
		/// generic refusal, and an exception there would surface as a 500 carrying internal detail.
		/// </para>
		/// </remarks>
		public DbFile Move(string sourceFilepath, string destinationFilepath, bool overwrite = false, Guid? expectedSourceId = null)
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

			//see the remarks above - the authorized row must still be the row at this path, and the same
			//identifier is then carried into the UPDATE so the decision is re-made inside the transaction
			if (expectedSourceId.HasValue && srcFile.Id != expectedSourceId.Value)
				return null;

			if (destFile != null && overwrite == false)
				throw new Exception("Destination file already exists and no overwrite specified.");

			using (var connection = CurrentContext.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();

					if (destFile != null && overwrite)
						Delete(destFile.FilePath, destFile.Id);

					//The predicate is widened from "id = @id" to also require the row to still be the
					//authorized one. Both halves are parameterised, so no value is concatenated into SQL.
					var command = connection.CreateCommand(expectedSourceId.HasValue
						? @"UPDATE files SET filepath = @filepath WHERE id = @id AND id = @expected_id"
						: @"UPDATE files SET filepath = @filepath WHERE id = @id");
					command.Parameters.Add(new NpgsqlParameter("@id", srcFile.Id));
					command.Parameters.Add(new NpgsqlParameter("@filepath", destinationFilepath));
					if (expectedSourceId.HasValue)
						command.Parameters.Add(new NpgsqlParameter("@expected_id", expectedSourceId.Value));

					if (command.ExecuteNonQuery() == 0 && expectedSourceId.HasValue)
					{
						//the authorized row was moved or removed by a concurrent request - abandon rather
						//than proceed to the storage-side move, which would operate on the wrong file
						connection.RollbackTransaction();
						return null;
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
		/// <see cref="Move(string, string, bool, Guid?)"/>: the ownership check that permits a delete is
		/// performed on a row read by an earlier call on an earlier connection, so without pinning a
		/// concurrent move could place another user's file at this path and have it destroyed under an
		/// authorization that was never granted for it. The parameter defaults to null, so every existing
		/// caller is unaffected.
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

					//The predicate re-asserts, inside the transaction, that the row being removed is still
					//the one whose path was resolved and authorized above. Both values are parameterised.
					var command = connection.CreateCommand(expectedFileId.HasValue
						? @"DELETE FROM files WHERE id = @id AND filepath = @filepath"
						: @"DELETE FROM files WHERE id = @id");
					command.Parameters.Add(new NpgsqlParameter("@id", file.Id));
					if (expectedFileId.HasValue)
						command.Parameters.Add(new NpgsqlParameter("@filepath", filepath));

					command.ExecuteNonQuery();

					connection.CommitTransaction();
				}
				catch
				{
					connection.RollbackTransaction();
					throw;
				}
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
		/// cleanup expired temp files 
		/// </summary>
		/// <param name="expiration"></param>
		public void CleanupExpiredTempFiles(TimeSpan expiration)
		{

			DataTable table = new DataTable();
			using (var connection = CurrentContext.CreateConnection())
			{
				var command = connection.CreateCommand(string.Empty);
				command.CommandText = "SELECT filepath FROM files WHERE filepath ILIKE @tmp_path";
				command.Parameters.Add(new NpgsqlParameter("@tmp_path", "%" + FOLDER_SEPARATOR + TMP_FOLDER_NAME));
				new NpgsqlDataAdapter(command).Fill(table);
			}

			foreach (DataRow row in table.Rows)
				Delete((string)row["filepath"]);
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
