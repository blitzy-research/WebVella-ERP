using Newtonsoft.Json;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
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
		/// costs nothing and bounds the pattern built by
		/// <see cref="BuildExactEmailPattern(string)"/> for an unauthenticated caller.
		/// </summary>
		private const int MaxEmailLength = 500;

		public ErpUser GetUser(Guid userId)
		{
			using (var ctx = SecurityContext.OpenSystemScope())
			{
				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE id = @id",
				new List<EqlParameter> { new EqlParameter("id", userId) }).Execute();
				if (result.Count != 1)
					return null;

				return result[0].MapTo<ErpUser>();
			}
		}

		public ErpUser GetUser(string email)
		{
			using (var ctx = SecurityContext.OpenSystemScope())
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
			using (var ctx = SecurityContext.OpenSystemScope())
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
		/// This method used to compute an unsalted MD5 digest of the supplied password and compare
		/// it INSIDE the SQL predicate. That comparison is what made the whole credential store
		/// unsaltable: a salted hash carries a different salt per row, so no single value can be
		/// compared for equality by the database. Restructuring the lookup to fetch by e-mail alone
		/// and verify in application code is therefore not a stylistic preference - it is the
		/// enabling change for salted, work-factored hashing, and it also carries the
		/// upgrade-on-next-authentication migration for credentials written by earlier releases.
		///
		/// Three further weaknesses are closed by the same restructure, and one regression that the
		/// restructure would otherwise have introduced is pre-empted:
		///  - CWE-208 (observable timing discrepancy): verification is now fixed-time, inside
		///    PasswordUtil, instead of being an SQL equality test.
		///  - CWE-1333 (inefficient regular expression complexity): the predicate used to pass the
		///    caller's raw input to PostgreSQL's case-insensitive regular expression operator, so an
		///    unauthenticated caller chose the pattern. It is now an anchored, fully escaped literal
		///    - see <see cref="BuildExactEmailPattern(string)"/>.
		///  - Unbounded result set: with the password gone from the predicate, a pattern such as "."
		///    would have selected the ENTIRE user table into memory from an endpoint reachable
		///    without credentials. The anchored literal pattern makes at most one row match.
		///  - CWE-203/CWE-208 (account enumeration by timing): a modern verification costs about
		///    120 ms while an address that does not exist would have returned in well under a
		///    millisecond, and a legacy MD5 row costs about 0.03 ms. Every failing path below
		///    therefore spends exactly one key derivation, whichever way it fails.
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

			using (var ctx = SecurityContext.OpenSystemScope())
			{
				var result = new EqlCommand("SELECT *, $user_role.* FROM user WHERE email ~* @email",
						 new List<EqlParameter> { new EqlParameter("email", BuildExactEmailPattern(email)) }).Execute();

				//tracks whether the expensive path was actually taken, so that the failure branch at
				//the end can spend the same work and leave no timing signal behind
				bool keyDerivationPerformed = false;

				foreach (var rec in result)
				{
					string recordEmail = rec.Properties.ContainsKey("email") ? rec["email"] as string : null;

					//retained from the previous implementation: the database comparison is only ever
					//a filter, and the authoritative address match is this exact one
					if (!string.Equals(recordEmail, email, StringComparison.OrdinalIgnoreCase))
						continue;

					string storedHash = rec.Properties.ContainsKey("password") ? rec["password"] as string : null;

					//a legacy digest is verified in microseconds, so it does NOT discharge the
					//obligation to spend a key derivation on this request
					if (!PasswordUtil.IsLegacyHash(storedHash))
						keyDerivationPerformed = true;

					if (!PasswordUtil.VerifyPassword(password, storedHash, out bool needsRehash))
						continue;

					var user = rec.MapTo<ErpUser>();

					//the OWASP-prescribed upgrade point: the plaintext is in hand exactly here and
					//nowhere else, so this is the only moment a legacy or under-worked value can be
					//replaced without forcing a reset on the account owner
					if (needsRehash)
						UpgradeStoredPasswordHash(user.Id, password);

					return user;
				}

				if (!keyDerivationPerformed)
					PasswordUtil.PerformDummyVerification(password);

				return null;
			}
		}

		/// <summary>
		/// Builds a PostgreSQL extended regular expression that matches one exact address and
		/// nothing else, case-insensitively.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-1333 (inefficient regular expression complexity) and the
		/// unbounded-result-set exposure described on <see cref="GetUser(string, string)"/>.
		/// The case-insensitive regular expression operator is retained deliberately rather than
		/// replaced with plain equality: nothing in this platform normalises the case of a stored
		/// address - the write paths in DbRecordRepository and RecordManager return the value
		/// verbatim - so an exact comparison would lock out any account whose address was stored in
		/// mixed case, which the requirement that existing credentials keep working forbids. EQL
		/// offers no exact case-insensitive operator: CONTAINS and STARTSWITH compile to ILIKE with
		/// the caller's value interpolated into the pattern, so a submitted "%" would match every
		/// user. Anchoring and escaping the operand keeps the exact previous semantics while making
		/// the pattern a literal, which is linear to match and can select at most one address.
		/// </remarks>
		/// <param name="email">The caller-supplied address. Never null or empty here.</param>
		/// <returns>An anchored pattern in which every metacharacter has been neutralised.</returns>
		private static string BuildExactEmailPattern(string email)
		{
			StringBuilder pattern = new StringBuilder(email.Length * 2 + 2);
			pattern.Append('^');

			foreach (char c in email)
			{
				//PostgreSQL's rule is that a backslash before a NON-alphanumeric character always
				//yields that literal character, while a backslash before an alphanumeric one is
				//either a special escape or an outright error. Escaping exactly the non-alphanumerics
				//is therefore both sufficient and safe. Surrogates are left untouched so that a pair
				//is never split, which would corrupt the encoded pattern rather than escape anything.
				if (!char.IsLetterOrDigit(c) && !char.IsSurrogate(c))
					pattern.Append('\\');

				pattern.Append(c);
			}

			pattern.Append('$');
			return pattern.ToString();
		}

		/// <summary>
		/// Replaces a stored credential that verified successfully but is out of date - a legacy MD5
		/// digest, or a modern value written below the current work factor - with one produced at
		/// the current parameters.
		/// </summary>
		/// <remarks>
		/// This is the second half of the backward-compatible credential migration, and it is why
		/// the format change needs no forced reset, no downtime and no schema change.
		/// It writes with the parameterized repository helper rather than through RecordManager on
		/// purpose. RecordManager would run record hooks and field validation, and validation now
		/// enforces a minimum password length that a credential written by an earlier release is
		/// very likely to fail - which would make the upgrade impossible for exactly the accounts
		/// that need it most. It would also expose an internal storage-format migration to business
		/// logic and to any hook an installation happens to have registered. Only the one column
		/// changes, and the platform holds no record-level cache to invalidate: Api/Cache.cs caches
		/// entity and relation metadata only.
		/// Failure is deliberately non-fatal. The account has already presented a correct password,
		/// so refusing the authentication because a maintenance write failed would convert a
		/// successful login into an outage. The stored value simply stays as it was and the upgrade
		/// is retried the next time that user authenticates, so the migration is self-healing.
		/// </remarks>
		/// <param name="userId">Identifier of the row whose password column is being replaced.</param>
		/// <param name="password">The plaintext just verified. Never stored, only re-hashed.</param>
		private static void UpgradeStoredPasswordHash(Guid userId, string password)
		{
			try
			{
				string upgradedHash = PasswordUtil.HashPassword(password);

				//an empty result would blank the credential, so treat it as nothing to do
				if (string.IsNullOrEmpty(upgradedHash))
					return;

				DbRepository.UpdateRecord("rec_user", new List<DbParameter>
				{
					new DbParameter { Name = "id", Value = userId, Type = NpgsqlDbType.Uuid },
					new DbParameter { Name = "password", Value = upgradedHash, Type = NpgsqlDbType.Varchar }
				});
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "SecurityManager.UpgradeStoredPasswordHash",
					"A credential verified successfully but its stored hash could not be upgraded to the current format. The stored value is unchanged and the upgrade will be retried on the next authentication by this user.", ex);
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
					else if (GetUser(user.Email) != null)
						valEx.AddError("email", "Email is already registered to another user. It must be unique.");
					else if (!IsValidEmail(user.Email))
						valEx.AddError("email", "Email is not valid.");
				}

				if (existingUser.Password != user.Password && !string.IsNullOrWhiteSpace(user.Password))
					record["password"] = user.Password;

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
				else if (GetUser(user.Email) != null)
					valEx.AddError("email", "Email is already registered to another user. It must be unique.");
				else if (!IsValidEmail(user.Email))
					valEx.AddError("email", "Email is not valid.");

				if (string.IsNullOrWhiteSpace(user.Password))
					valEx.AddError("password", "Password is required.");
				else
					record["password"] = user.Password;

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
