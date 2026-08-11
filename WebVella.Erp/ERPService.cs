using System;
using System.Collections.Generic;
// Invariant culture, so the administrator password-policy message states its bounds identically on
// every host locale (C-01, CWE-521).
using System.Globalization;
using System.Linq;
// CSPRNG for the generated local system credential that replaced a fixed literal (C-01,
// CWE-798/CWE-1392).
using System.Security.Cryptography;
// Serialises the first-login rotation marker through the ErpUserPreferences model into the user
// entity's existing preferences column, so no JSON literal is hand-written (C-01, CWE-1392).
using Newtonsoft.Json;
// NpgsqlParameter for the transaction-scoped advisory lock that serialises provisioning and the
// version-gated migration across hosts (CWE-367).
using Npgsql;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Hooks;
using WebVella.Erp.Jobs;
// PasswordUtil, whose assembly-internal legacy verification members let the version 4 migration
// recognise a deployment still carrying the credential earlier releases shipped, without recomputing
// MD5 here (C-01, CWE-798/CWE-1392).
using WebVella.Erp.Utilities;

namespace WebVella.Erp
{
	public class ErpService : IErpService
	{
		public List<ErpPlugin> Plugins { get; set; } = new List<ErpPlugin>();
		public List<ErpJob> Jobs { get; set; } = new List<ErpJob>();

		/// <summary>
		/// Minimum length provisioned onto the user entity's password field (M-13, CWE-521): twelve, the
		/// mandated floor, replacing six. It REFERENCES the bound PasswordUtil enforces rather than repeating
		/// it, and is shared by the version 1 seed and the version 4 migration so the two cannot diverge.
		/// </summary>
		private const int PasswordMinLength = Utilities.PasswordUtil.MinPasswordLength;

		/// <summary>
		/// Fixed advisory-lock key serialising schema provisioning and version-gated migration (CWE-367): the
		/// ASCII of "WvErpSch" as a 64-bit integer. It must never be derived from anything that varies by host,
		/// environment or release, because two hosts computing different keys are not serialised at all.
		/// </summary>
		private const long SchemaMigrationLockKey = 0x5776457270536368L;

		/// <summary>
		/// Upper bound, in seconds, on waiting for a peer host to finish provisioning.
		/// </summary>
		private const int SchemaMigrationLockTimeoutSeconds = 300;

		/// <summary>
		/// Maximum length provisioned onto the user entity's password field (M-13, CWE-521). The previous
		/// 24-character ceiling obstructed strong passphrases; expressed as the bound PasswordUtil enforces, so
		/// the advertised policy cannot drift from the length the hashing primitive will accept.
		/// </summary>
		private const int PasswordMaxLength = Utilities.PasswordUtil.MaxPasswordLength;

		public void InitializeSystemEntities()
		{
			FieldResponse fieldResponse = null;
			EntityManager entMan = new EntityManager();
			EntityRelationManager rm = new EntityRelationManager();
			RecordManager recMan = new RecordManager(null, true);

			using (var connection = DbContext.Current.CreateConnection())
			{
				//setup necessary extensions
				DbRepository.CreatePostgresqlExtensions();
				//setup casts
				DbRepository.CreatePostgresqlCasts();

				try
				{
					connection.BeginTransaction();

					//THREAT ADDRESSED - CWE-367 (time-of-check to time-of-use race), OWASP A04:2021 with A07:2021.
					//Nothing serialised the schema-version read from the migration acting on it, so two hosts starting
					//together could both observe version 3 and both run the version 4 migration, which rewrites the
					//administrator credential and creates entities, fields and grants.
					//THE LOCK MUST BE TAKEN HERE, before CheckCreateSystemTables and before the version is read, and it is
					//transaction-scoped so PostgreSQL releases it on COMMIT or ROLLBACK with no unlock call an exception
					//path could skip. pg_advisory_xact_lock BLOCKS, unlike the pg_try_advisory_xact_lock helper, because
					//"another host is migrating" must mean "wait", never "carry on regardless".
					var migrationLockCommand = connection.CreateCommand("SELECT pg_advisory_xact_lock(@key);");
					migrationLockCommand.Parameters.Add(new NpgsqlParameter("@key", SchemaMigrationLockKey));
					//First-time provisioning can outlast the 30-second default; five minutes is long enough that only
					//a genuinely stuck peer reaches it, and a timeout fails the start loudly rather than
					//silently skipping.
					migrationLockCommand.CommandTimeout = SchemaMigrationLockTimeoutSeconds;
					migrationLockCommand.ExecuteNonQuery();

					//THREAT ADDRESSED (CWE-532, OWASP A09:2021): notices are held back until this transaction commits, and
					//cleared on entry rather than trusted to be empty, because the core service is a singleton - a
					//rolled-back attempt would otherwise leave a stale notice for a later one to emit.
					pendingProvisioningNotices.Clear();

					CheckCreateSystemTables();

					DbSystemSettings storeSystemSettings = DbContext.Current.SettingsRepository.Read();

					Guid systemSettingsId = new Guid("F3223177-B2FF-43F5-9A4B-FF16FC67D186");
					SystemSettings systemSettings = new SystemSettings();
					systemSettings.Id = systemSettingsId;

					int currentVersion = 0;
					if (storeSystemSettings != null)
					{
						systemSettings = new SystemSettings(storeSystemSettings);
						currentVersion = systemSettings.Version;
					}

					if (currentVersion < 1)
					{
						systemSettings.Version = 1;

						List<Guid> allowedRoles = new List<Guid>();
						allowedRoles.Add(SystemIds.AdministratorRoleId);

						#region << create user entity >>
						{

							var systemItemIdDictionary = new Dictionary<string, Guid>();
							systemItemIdDictionary["id"] = new Guid("24cdb49a-cb1f-4a38-bc99-a6137ade9949");

							InputEntity userEntity = new InputEntity();
							userEntity.Id = SystemIds.UserEntityId;
							userEntity.Name = "user";
							userEntity.Label = "User";
							userEntity.LabelPlural = "Users";
							userEntity.System = true;
							userEntity.Color = "#f44336";
							userEntity.IconName = "fa fa-user";
							userEntity.RecordPermissions = new RecordPermissions();
							userEntity.RecordPermissions.CanCreate = new List<Guid>();
							userEntity.RecordPermissions.CanRead = new List<Guid>();
							userEntity.RecordPermissions.CanUpdate = new List<Guid>();
							userEntity.RecordPermissions.CanDelete = new List<Guid>();
							//SECURITY - C-05 (CWE-269, CWE-732) and C-02 (CWE-200, CWE-522), OWASP A01:2021 + A02:2021. Two
							//grants were seeded here for Guest, the role every unauthenticated caller is evaluated as when no
							//user resolves: CREATE was self-registration into the identity store, and READ exposed the whole
							//user collection including the stored hash column. Both are removed. The Regular READ grant stays,
							//because removing it would break every screen resolving the signed-in user's own name and avatar;
							//the hash is protected by the administrator-only field permissions below and by projection redaction.
							userEntity.RecordPermissions.CanCreate.Add(SystemIds.AdministratorRoleId);
							userEntity.RecordPermissions.CanRead.Add(SystemIds.RegularRoleId);
							userEntity.RecordPermissions.CanRead.Add(SystemIds.AdministratorRoleId);
							userEntity.RecordPermissions.CanUpdate.Add(SystemIds.AdministratorRoleId);
							userEntity.RecordPermissions.CanDelete.Add(SystemIds.AdministratorRoleId);
							var response = entMan.CreateEntity(userEntity, systemItemIdDictionary);

							#region <--- created_on --->
							{
								InputDateTimeField createdOn = new InputDateTimeField();
								createdOn.Id = new Guid("6fda5e6b-80e6-4d8a-9e2a-d983c3694e96");
								createdOn.Name = "created_on";
								createdOn.Label = "Created On";
								createdOn.PlaceholderText = "";
								createdOn.Description = "";
								createdOn.HelpText = "";
								createdOn.Required = true;
								createdOn.Unique = false;
								createdOn.Searchable = true;
								createdOn.Auditable = true;
								createdOn.System = true;
								createdOn.DefaultValue = null;
								createdOn.Format = "dd MMM yyyy HH:mm:ss";
								createdOn.UseCurrentTimeAsDefaultValue = true;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, createdOn, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: created_on" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- first_name --->
							{
								InputTextField firstName = new InputTextField();
								firstName.Id = new Guid("DF211549-41CC-4D11-BB43-DACA4C164411");
								firstName.Name = "first_name";
								firstName.Label = "First Name";
								firstName.PlaceholderText = "";
								firstName.Description = "First name of the user";
								firstName.HelpText = "";
								firstName.Required = false;
								firstName.Unique = false;
								firstName.Searchable = false;
								firstName.Auditable = false;
								firstName.System = true;
								firstName.DefaultValue = "";
								firstName.MaxLength = 200;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, firstName, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: first_name" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- last_name --->
							{
								InputTextField lastName = new InputTextField();
								lastName.Id = new Guid("63E685B1-B2C6-4961-B393-2B6723EBD1BF");
								lastName.Name = "last_name";
								lastName.Label = "Last Name";
								lastName.PlaceholderText = "";
								lastName.Description = "Last name of the user";
								lastName.HelpText = "";
								lastName.Required = false;
								lastName.Unique = false;
								lastName.Searchable = false;
								lastName.Auditable = false;
								lastName.System = true;
								lastName.DefaultValue = "";
								lastName.MaxLength = 200;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, lastName, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: last_name" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- username --->
							{
								InputTextField userName = new InputTextField();
								userName.Id = new Guid("263c0b21-88c1-4c2b-80b4-db7402b0d2e2");
								userName.Name = "username";
								userName.Label = "User Name";
								userName.PlaceholderText = "";
								userName.Description = "screen name for the user";
								userName.HelpText = "";
								userName.Required = true;
								userName.Unique = true;
								userName.Searchable = true;
								userName.Auditable = false;
								userName.System = true;
								userName.DefaultValue = string.Empty;
								userName.MaxLength = 200;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, userName, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: userName" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- email --->
							{
								InputEmailField email = new InputEmailField();
								email.Id = new Guid("9FC75C8F-CE80-4A64-81D7-E2BEFA5E4815");
								email.Name = "email";
								email.Label = "Email";
								email.PlaceholderText = "";
								email.Description = "Email address of the user";
								email.HelpText = "";
								email.Required = true;
								email.Unique = true;
								email.Searchable = true;
								email.Auditable = false;
								email.System = true;
								email.DefaultValue = string.Empty;
								email.MaxLength = 255;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, email, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: email" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- password --->
							{
								InputPasswordField password = new InputPasswordField();
								password.Id = new Guid("4EDE88D9-217A-4462-9300-EA0D6AFCDCEA");
								password.Name = "password";
								password.Label = "Password";
								password.PlaceholderText = "";
								password.Description = "Password for the user account";
								password.HelpText = "";
								password.Required = true;
								password.Unique = false;
								password.Searchable = false;
								password.Auditable = false;
								password.System = true;
								//SECURITY - M-13, CWE-521. The bounds were 6 to 24: six falls to an offline guess in seconds, and the
								//24-character ceiling was the more damaging half because it obstructed the compensating passphrase.
								password.MinLength = PasswordMinLength;
								password.MaxLength = PasswordMaxLength;
								password.Encrypted = true;
								//SECURITY - C-02, CWE-200 / CWE-522, OWASP A01:2021 + A02:2021. This field holds the stored
								//credential and provisioning assigned it NO field permissions at all, leaving only the presentation
								//layer - which the Authorization Enforcement standard rules out, because authorization must hold on
								//every request. BOTH LINES BELOW ARE LOAD-BEARING: PcFieldBase gates the entire field-permission
								//evaluation behind EnableSecurity, which DEFAULTS TO FALSE, so Permissions alone is inert.
								//Administrator only, so the field hides for non-administrators - the remediation working, not a defect.
								password.EnableSecurity = true;
								password.Permissions = new FieldPermissions();
								password.Permissions.CanRead = new List<Guid>();
								password.Permissions.CanUpdate = new List<Guid>();
								//READ
								password.Permissions.CanRead.Add(SystemIds.AdministratorRoleId);
								//UPDATE
								password.Permissions.CanUpdate.Add(SystemIds.AdministratorRoleId);

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, password, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: password" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- last_logged_in --->
							{
								InputDateTimeField lastLoggedIn = new InputDateTimeField();
								lastLoggedIn.Id = new Guid("3C85CCEC-D526-4E47-887F-EE169D1F508D");
								lastLoggedIn.Name = "last_logged_in";
								lastLoggedIn.Label = "Last Logged In";
								lastLoggedIn.PlaceholderText = "";
								lastLoggedIn.Description = "";
								lastLoggedIn.HelpText = "";
								lastLoggedIn.Required = false;
								lastLoggedIn.Unique = false;
								lastLoggedIn.Searchable = false;
								lastLoggedIn.Auditable = true;
								lastLoggedIn.System = true;
								lastLoggedIn.DefaultValue = null;
								lastLoggedIn.Format = "dd MMM yyyy HH:mm:ss";
								lastLoggedIn.UseCurrentTimeAsDefaultValue = true;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, lastLoggedIn, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: lastLoggedIn" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- enabled --->
							{
								InputCheckboxField enabledField = new InputCheckboxField();
								enabledField.Id = new Guid("C0C63650-7572-4252-8E4B-4E25C94897A6");
								enabledField.Name = "enabled";
								enabledField.Label = "Enabled";
								enabledField.PlaceholderText = "";
								enabledField.Description = "Shows if the user account is enabled";
								enabledField.HelpText = "";
								enabledField.Required = true;
								enabledField.Unique = false;
								enabledField.Searchable = false;
								enabledField.Auditable = false;
								enabledField.System = true;
								enabledField.DefaultValue = false;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, enabledField, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: enabled" + " Message:" + createResponse.Message);
							}
							#endregion

							#region <--- verified --->
							{
								InputCheckboxField verifiedUserField = new InputCheckboxField();
								verifiedUserField.Id = new Guid("F1BA5069-8CC9-4E66-BCC3-60E33C79C265");
								verifiedUserField.Name = "verified";
								verifiedUserField.Label = "Verified";
								verifiedUserField.PlaceholderText = "";
								verifiedUserField.Description = "Shows if the user email is verified";
								verifiedUserField.HelpText = "";
								verifiedUserField.Required = true;
								verifiedUserField.Unique = false;
								verifiedUserField.Searchable = false;
								verifiedUserField.Auditable = false;
								verifiedUserField.System = true;
								verifiedUserField.DefaultValue = false;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, verifiedUserField, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: verified" + " Message:" + createResponse.Message);
							}

							#endregion

							#region <--- preferences --->
							{
								InputTextField preferences = new InputTextField();
								preferences.Id = new Guid("29d46dac-b477-48f8-9f3a-22d7e95ae1cc");
								preferences.Name = "preferences";
								preferences.Label = "Preferences";
								preferences.PlaceholderText = "";
								preferences.Description = "Preferences json field.";
								preferences.HelpText = "";
								preferences.Required = true;
								preferences.Unique = false;
								preferences.Searchable = false;
								preferences.Auditable = false;
								preferences.System = true;
								preferences.DefaultValue = "{}";

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, preferences, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: preferences" + " Message:" + createResponse.Message);
							}

							#endregion

							#region <---  image --- >
							{
								InputImageField imageField = new InputImageField();
								imageField.Id = new Guid("bf199b74-4448-4f58-93f5-6b86d888843b");
								imageField.Name = "image";
								imageField.Label = "Image";
								imageField.PlaceholderText = "";
								imageField.Description = "";
								imageField.HelpText = "";
								imageField.Required = false;
								imageField.Unique = false;
								imageField.Searchable = false;
								imageField.Auditable = false;
								imageField.System = true;
								imageField.DefaultValue = string.Empty;
								imageField.EnableSecurity = false;

								var createResponse = entMan.CreateField(SystemIds.UserEntityId, imageField, false);
								if (!createResponse.Success)
									throw new Exception("System error 10060. Entity: user. Field: image" + " Message:" + createResponse.Message);
							}
							#endregion
						}

						#endregion

						#region << create role entity >>

						{
							var systemItemIdDictionary = new Dictionary<string, Guid>();
							systemItemIdDictionary["id"] = new Guid("0c5679f4-a290-4923-ad2b-d304cbc79937");

							InputEntity roleEntity = new InputEntity();
							roleEntity.Id = SystemIds.RoleEntityId;
							roleEntity.Name = "role";
							roleEntity.Label = "Role";
							roleEntity.LabelPlural = "Roles";
							roleEntity.System = true;
							roleEntity.Color = "#f44336";
							roleEntity.IconName = "fa fa-key";
							roleEntity.RecordPermissions = new RecordPermissions();
							roleEntity.RecordPermissions.CanCreate = new List<Guid>();
							roleEntity.RecordPermissions.CanRead = new List<Guid>();
							roleEntity.RecordPermissions.CanUpdate = new List<Guid>();
							roleEntity.RecordPermissions.CanDelete = new List<Guid>();
							//THREAT ADDRESSED - C-05, CWE-269 / CWE-732 / CWE-200, OWASP A01:2021. Both Guest grants are absent
							//from this seed. CREATE let an unauthenticated caller author a role, which with the Guest CREATE grant
							//removed from the user entity above was a complete privilege-escalation chain; READ was anonymous
							//enumeration of the whole authorization vocabulary, and was unnecessary because login-time role
							//resolution runs in a system scope and no [AllowAnonymous] endpoint reads this entity. Only CREATE is
							//also revoked on already-provisioned installations; the READ residual is in the risk register.
							roleEntity.RecordPermissions.CanCreate.Add(SystemIds.AdministratorRoleId);
							roleEntity.RecordPermissions.CanRead.Add(SystemIds.RegularRoleId);
							roleEntity.RecordPermissions.CanRead.Add(SystemIds.AdministratorRoleId);
							roleEntity.RecordPermissions.CanUpdate.Add(SystemIds.AdministratorRoleId);
							roleEntity.RecordPermissions.CanDelete.Add(SystemIds.AdministratorRoleId);
							var response = entMan.CreateEntity(roleEntity, systemItemIdDictionary);

							InputTextField nameRoleField = new InputTextField();

							nameRoleField.Id = new Guid("36F91EBD-5A02-4032-8498-B7F716F6A349");
							nameRoleField.Name = "name";
							nameRoleField.Label = "Name";
							nameRoleField.PlaceholderText = "";
							nameRoleField.Description = "The name of the role";
							nameRoleField.HelpText = "";
							nameRoleField.Required = true;
							nameRoleField.Unique = false;
							nameRoleField.Searchable = false;
							nameRoleField.Auditable = false;
							nameRoleField.System = true;
							nameRoleField.DefaultValue = "";
							nameRoleField.MaxLength = 200;
							nameRoleField.EnableSecurity = true;
							nameRoleField.Permissions = new FieldPermissions();
							nameRoleField.Permissions.CanRead = new List<Guid>();
							nameRoleField.Permissions.CanUpdate = new List<Guid>();
							//READ
							nameRoleField.Permissions.CanRead.Add(SystemIds.AdministratorRoleId);
							nameRoleField.Permissions.CanRead.Add(SystemIds.RegularRoleId);
							//UPDATE
							nameRoleField.Permissions.CanUpdate.Add(SystemIds.AdministratorRoleId);

							fieldResponse = entMan.CreateField(roleEntity.Id.Value, nameRoleField, false);

							InputTextField descriptionRoleField = new InputTextField();

							descriptionRoleField.Id = new Guid("4A8B9E0A-1C36-40C6-972B-B19E2B5D265B");
							descriptionRoleField.Name = "description";
							descriptionRoleField.Label = "Description";
							descriptionRoleField.PlaceholderText = "";
							descriptionRoleField.Description = "";
							descriptionRoleField.HelpText = "";
							descriptionRoleField.Required = true;
							descriptionRoleField.Unique = false;
							descriptionRoleField.Searchable = false;
							descriptionRoleField.Auditable = false;
							descriptionRoleField.System = true;
							descriptionRoleField.DefaultValue = "";

							descriptionRoleField.MaxLength = 200;

							fieldResponse = entMan.CreateField(roleEntity.Id.Value, descriptionRoleField, false);
						}

						#endregion

						#region << create user - role relation >>
						{
							var userEntity = entMan.ReadEntity(SystemIds.UserEntityId).Object;
							var roleEntity = entMan.ReadEntity(SystemIds.RoleEntityId).Object;

							EntityRelation userRoleRelation = new EntityRelation();
							userRoleRelation.Id = SystemIds.UserRoleRelationId;
							userRoleRelation.Name = "user_role";
							userRoleRelation.Label = "User-Role";
							userRoleRelation.System = true;
							userRoleRelation.RelationType = EntityRelationType.ManyToMany;
							userRoleRelation.TargetEntityId = userEntity.Id;
							userRoleRelation.TargetFieldId = userEntity.Fields.Single(x => x.Name == "id").Id;
							userRoleRelation.OriginEntityId = roleEntity.Id;
							userRoleRelation.OriginFieldId = roleEntity.Fields.Single(x => x.Name == "id").Id;
							{
								var result = rm.Create(userRoleRelation);
								if (!result.Success)
									throw new Exception("CREATE USER-ROLE RELATION:" + result.Message);
							}
						}
						#endregion

						#region << create system records >>

						{
							EntityRecord user = new EntityRecord();
							user["id"] = SystemIds.SystemUserId;
							user["first_name"] = "Local";
							user["last_name"] = "System";
							//SECURITY - CWE-521 (weak password requirements), OWASP A07:2021. The local system account exists
							//only so background work has an identity and nobody authenticates as it. Its value was a random GUID
							//string, which is all lower case and so fails the mixed-case rule ValidatePasswordPolicy now enforces
							//at the record-write boundary; the generator is reused instead, satisfying every rule by construction
							//with at least the 122 random bits of a version-4 GUID. Hashed on write, never printed.
							user["password"] = GenerateInitialAdministratorPassword();
							user["email"] = "system@webvella.com";
							user["username"] = "system";
							user["created_on"] = new DateTime(2010, 10, 10);
							user["enabled"] = true;

							QueryResponse result = recMan.CreateRecord("user", user);
							if (!result.Success)
								throw new Exception("CREATE SYSTEM USER RECORD:" + result.Message);
						}

						{
							EntityRecord user = new EntityRecord();
							user["id"] = SystemIds.FirstUserId;
							user["first_name"] = "WebVella";
							user["last_name"] = "Erp";
							//SECURITY - C-01, CWE-798 (hard-coded credentials) and CWE-1392 (default credentials), OWASP A07:2021.
							//THREAT: this record is the platform's first administrator and used to be provisioned with the literal
							//password "erp" from this public source tree, so every installation shipped a publicly known
							//administrator credential at a publicly known address.
							//INVARIANT: no password literal may be assigned here again. The value comes from
							//'Settings:InitialAdministratorPassword' and nowhere else; RecordManager hashes it on write.
							user["password"] = ResolveInitialAdministratorPassword();
							user["email"] = "erp@webvella.com";
							user["username"] = "administrator";
							user["created_on"] = new DateTime(2010, 10, 10);
							user["enabled"] = true;
							//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): this credential reaches the account through a
							//deployment setting - a multi-reader store - rather than being chosen by the person who will use it,
							//so it is marked as owing a rotation. AuthService refuses to mint or refresh a bearer token while the
							//marker stands; interactive sign-in stays available because it is the only route to the screen that
							//clears it. Serialised through the model so the property name cannot drift.
							user["preferences"] = JsonConvert.SerializeObject(
								new ErpUserPreferences { PasswordChangeRequired = true });

							QueryResponse result = recMan.CreateRecord("user", user);
							if (!result.Success)
								throw new Exception("CREATE FIRST USER RECORD:" + result.Message);
						}

						{
							EntityRecord adminRole = new EntityRecord();
							adminRole["id"] = SystemIds.AdministratorRoleId;
							adminRole["name"] = "administrator";
							adminRole["description"] = "";

							QueryResponse result = recMan.CreateRecord("role", adminRole);
							if (!result.Success)
								throw new Exception("CREATE ADMINITRATOR ROLE RECORD:" + result.Message);
						}

						{
							EntityRecord regularRole = new EntityRecord();
							regularRole["id"] = SystemIds.RegularRoleId;
							regularRole["name"] = "regular";
							regularRole["description"] = "";

							QueryResponse result = recMan.CreateRecord("role", regularRole);
							if (!result.Success)
								throw new Exception("CREATE REGULAR ROLE RECORD:" + result.Message);
						}

						{
							EntityRecord guestRole = new EntityRecord();
							guestRole["id"] = SystemIds.GuestRoleId;
							guestRole["name"] = "guest";
							guestRole["description"] = "";

							QueryResponse result = recMan.CreateRecord("role", guestRole);
							if (!result.Success)
								throw new Exception("CREATE GUEST ROLE RECORD:" + result.Message);
						}

						{
							QueryResponse result = recMan.CreateRelationManyToManyRecord(SystemIds.UserRoleRelationId, SystemIds.AdministratorRoleId, SystemIds.SystemUserId);
							if (!result.Success)
								throw new Exception("CREATE SYSTEM-USER <-> ADMINISTRATOR ROLE RELATION RECORD:" + result.Message);
						}

						{
							QueryResponse result = recMan.CreateRelationManyToManyRecord(SystemIds.UserRoleRelationId, SystemIds.AdministratorRoleId, SystemIds.FirstUserId);
							if (!result.Success)
								throw new Exception("CREATE FIRST-USER <-> ADMINISTRATOR ROLE RELATION RECORD:" + result.Message);


							result = recMan.CreateRelationManyToManyRecord(SystemIds.UserRoleRelationId, SystemIds.RegularRoleId, SystemIds.FirstUserId);
							if (!result.Success)
								throw new Exception("CREATE FIRST-USER <-> REGULAR ROLE RELATION RECORD:" + result.Message);

						}

						#endregion

						#region << create user_file entity >>
						{

							#region << ***Create entity*** Entity name: user_file >>
							{
								#region << entity >>
								{
									var systemFieldIdDictionary = new Dictionary<string, Guid>();
									systemFieldIdDictionary["id"] = new Guid("14369619-fe7b-423f-bf60-3e7f8b35b840");

									var entity = new InputEntity();
									entity.Id = new Guid("5c666c54-9e76-4327-ac7a-55851037810c");
									entity.Name = "user_file";
									entity.Label = "User File";
									entity.LabelPlural = "User Files";
									entity.System = true;
									entity.IconName = "fa fa-file";
									entity.Color = "#f44336";
									entity.RecordPermissions = new RecordPermissions();
									entity.RecordPermissions.CanCreate = new List<Guid>();
									entity.RecordPermissions.CanRead = new List<Guid>();
									entity.RecordPermissions.CanUpdate = new List<Guid>();
									entity.RecordPermissions.CanDelete = new List<Guid>();
									//Create
									entity.RecordPermissions.CanCreate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
									entity.RecordPermissions.CanCreate.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
									//READ
									entity.RecordPermissions.CanRead.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
									entity.RecordPermissions.CanRead.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
									//UPDATE
									entity.RecordPermissions.CanUpdate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
									entity.RecordPermissions.CanUpdate.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
									//DELETE
									entity.RecordPermissions.CanDelete.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
									entity.RecordPermissions.CanDelete.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
									{
										var response = entMan.CreateEntity(entity, systemFieldIdDictionary);
										if (!response.Success)
											throw new Exception("System error 10050. Entity: user_file creation Message: " + response.Message);
									}
								}
								#endregion
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: created_on >>
							{

								InputDateTimeField createdOn = new InputDateTimeField();

								createdOn.Id = new Guid("7bc7c1a2-93aa-40bc-8374-fd350cdc7fac");
								createdOn.Name = "created_on";
								createdOn.Label = "Created On";
								createdOn.PlaceholderText = "";
								createdOn.Description = "";
								createdOn.HelpText = "";
								createdOn.Required = true;
								createdOn.Unique = false;
								createdOn.Searchable = true;
								createdOn.Auditable = true;
								createdOn.System = true;
								createdOn.DefaultValue = null;

								createdOn.Format = "dd MMM yyyy HH:mm:ss";
								createdOn.UseCurrentTimeAsDefaultValue = true;
								createdOn.EnableSecurity = false;
								createdOn.Permissions = new FieldPermissions();
								createdOn.Permissions.CanRead = new List<Guid>();
								createdOn.Permissions.CanUpdate = new List<Guid>();

								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), createdOn, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: created_on:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: alt >>
							{
								InputTextField textboxField = new InputTextField();
								textboxField.Id = new Guid("168a9777-a156-4b0b-9b18-909fec043ce5");
								textboxField.Name = "alt";
								textboxField.Label = "Alt";
								textboxField.PlaceholderText = "";
								textboxField.Description = "";
								textboxField.HelpText = "";
								textboxField.Required = false;
								textboxField.Unique = false;
								textboxField.Searchable = true;
								textboxField.Auditable = false;
								textboxField.System = true;
								textboxField.DefaultValue = null;
								textboxField.MaxLength = null;
								textboxField.EnableSecurity = false;
								textboxField.Permissions = new FieldPermissions();
								textboxField.Permissions.CanRead = new List<Guid>();
								textboxField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), textboxField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: alt Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: caption >>
							{
								InputTextField textboxField = new InputTextField();
								textboxField.Id = new Guid("6796c578-22f4-4b07-8568-99f9d6600294");
								textboxField.Name = "caption";
								textboxField.Label = "Caption";
								textboxField.PlaceholderText = "";
								textboxField.Description = "";
								textboxField.HelpText = "";
								textboxField.Required = false;
								textboxField.Unique = false;
								textboxField.Searchable = true;
								textboxField.Auditable = false;
								textboxField.System = true;
								textboxField.DefaultValue = null;
								textboxField.MaxLength = null;
								textboxField.EnableSecurity = false;
								textboxField.Permissions = new FieldPermissions();
								textboxField.Permissions.CanRead = new List<Guid>();
								textboxField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), textboxField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: caption Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: height >>
							{
								InputNumberField numberField = new InputNumberField();
								numberField.Id = new Guid("a7a06f28-5893-4890-a8a7-fd794c741cf9");
								numberField.Name = "height";
								numberField.Label = "Height";
								numberField.PlaceholderText = "";
								numberField.Description = "";
								numberField.HelpText = "";
								numberField.Required = true;
								numberField.Unique = false;
								numberField.Searchable = false;
								numberField.Auditable = false;
								numberField.System = true;
								numberField.DefaultValue = Decimal.Parse("0.0");
								numberField.MinValue = null;
								numberField.MaxValue = null;
								numberField.DecimalPlaces = byte.Parse("0");
								numberField.EnableSecurity = false;
								numberField.Permissions = new FieldPermissions();
								numberField.Permissions.CanRead = new List<Guid>();
								numberField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), numberField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: height Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: name >>
							{
								InputTextField textboxField = new InputTextField();
								textboxField.Id = new Guid("cc2730d3-7711-4d8a-bdc2-1d11c3eae5c2");
								textboxField.Name = "name";
								textboxField.Label = "Name";
								textboxField.PlaceholderText = "";
								textboxField.Description = "";
								textboxField.HelpText = "";
								textboxField.Required = true;
								textboxField.Unique = false;
								textboxField.Searchable = true;
								textboxField.Auditable = false;
								textboxField.System = true;
								textboxField.DefaultValue = "file-name";
								textboxField.MaxLength = null;
								textboxField.EnableSecurity = false;
								textboxField.Permissions = new FieldPermissions();
								textboxField.Permissions.CanRead = new List<Guid>();
								textboxField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), textboxField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: name Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: size >>
							{
								InputNumberField numberField = new InputNumberField();
								numberField.Id = new Guid("6a66fbd8-fb5a-4e48-882f-b760475bf2f0");
								numberField.Name = "size";
								numberField.Label = "Size";
								numberField.PlaceholderText = "";
								numberField.Description = "";
								numberField.HelpText = "";
								numberField.Required = true;
								numberField.Unique = false;
								numberField.Searchable = false;
								numberField.Auditable = false;
								numberField.System = true;
								numberField.DefaultValue = Decimal.Parse("0.0");
								numberField.MinValue = null;
								numberField.MaxValue = null;
								numberField.DecimalPlaces = byte.Parse("0");
								numberField.EnableSecurity = false;
								numberField.Permissions = new FieldPermissions();
								numberField.Permissions.CanRead = new List<Guid>();
								numberField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), numberField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: size Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: type >>
							{
								InputSelectField dropdownField = new InputSelectField();
								dropdownField.Id = new Guid("e856b229-ab8c-440c-8b6d-f817cc2776f0");
								dropdownField.Name = "type";
								dropdownField.Label = "Type";
								dropdownField.PlaceholderText = "";
								dropdownField.Description = "";
								dropdownField.HelpText = "";
								dropdownField.Required = true;
								dropdownField.Unique = false;
								dropdownField.Searchable = true;
								dropdownField.Auditable = false;
								dropdownField.System = true;
								dropdownField.DefaultValue = "image";
								dropdownField.Options = new List<SelectOption>
								{
									new SelectOption() { Value = "image", Label = "image"},
									new SelectOption() { Value = "document", Label = "document"},
									new SelectOption() { Value = "audio", Label = "audio"},
									new SelectOption() { Value = "video", Label = "video"},
									new SelectOption() { Value = "other", Label = "other"}
								};
								dropdownField.EnableSecurity = false;
								dropdownField.Permissions = new FieldPermissions();
								dropdownField.Permissions.CanRead = new List<Guid>();
								dropdownField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), dropdownField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: type Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: width >>
							{
								InputNumberField numberField = new InputNumberField();
								numberField.Id = new Guid("c2b8fee6-81a4-4cb0-adac-f19f734f6380");
								numberField.Name = "width";
								numberField.Label = "Width";
								numberField.PlaceholderText = "";
								numberField.Description = "";
								numberField.HelpText = "";
								numberField.Required = true;
								numberField.Unique = false;
								numberField.Searchable = false;
								numberField.Auditable = false;
								numberField.System = true;
								numberField.DefaultValue = Decimal.Parse("0.0");
								numberField.MinValue = null;
								numberField.MaxValue = null;
								numberField.DecimalPlaces = byte.Parse("0");
								numberField.EnableSecurity = false;
								numberField.Permissions = new FieldPermissions();
								numberField.Permissions.CanRead = new List<Guid>();
								numberField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), numberField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: width Message:" + response.Message);
								}
							}
							#endregion

							#region << ***Create field***  Entity: user_file Field Name: path >>
							{
								InputFileField fileField = new InputFileField();
								fileField.Id = new Guid("3f4e8056-6e94-4304-8fd7-8f151c81bc19");
								fileField.Name = "path";
								fileField.Label = "File";
								fileField.PlaceholderText = "";
								fileField.Description = "";
								fileField.HelpText = "";
								fileField.Required = true;
								fileField.Unique = true;
								fileField.Searchable = true;
								fileField.Auditable = false;
								fileField.System = false;
								fileField.DefaultValue = "no-file-error.txt";
								fileField.EnableSecurity = false;
								fileField.Permissions = new FieldPermissions();
								fileField.Permissions.CanRead = new List<Guid>();
								fileField.Permissions.CanUpdate = new List<Guid>();
								//READ
								//UPDATE
								{
									var response = entMan.CreateField(new Guid("5c666c54-9e76-4327-ac7a-55851037810c"), fileField, false);
									if (!response.Success)
										throw new Exception("System error 10060. Entity: user_file Field: path Message:" + response.Message);
								}
							}
							#endregion

						}
						#endregion
					}
					if (currentVersion < 2)
					{
						systemSettings.Version = 2;
						UpdateSitemapNodeTable1();
					}

					if (currentVersion < 3)
					{
						systemSettings.Version = 3;
						UpdateSitemapNodeTable2();
					}

					if (currentVersion < 4)
					{
						systemSettings.Version = 4;
						//SECURITY - carries the C-01, C-02, C-05 and M-13 provisioning corrections above to installations
						//ALREADY PROVISIONED by an earlier release. Every one of them sits inside the currentVersion < 1 gate,
						//so a source-only fix would leave the deployed estate holding the published default password, the
						//anonymous grants and an unprotected credential column while the source read as fixed. DATA AND
						//METADATA ONLY - no schema definition statement at any point.
						MigrateSecurityDefaults4(entMan, recMan);
					}

					new DbSystemSettingsRepository(DbContext.Current).Save(new DbSystemSettings { Id = systemSettings.Id, Version = systemSettings.Version });

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					var exception = ex;
					connection.RollbackTransaction();
					//Nothing was persisted, so nothing is announced: discarding stops a notice describing a
					//rolled-back installation being emitted by a later call on this singleton.
					pendingProvisioningNotices.Clear();
					throw;
				}

				//THREAT ADDRESSED - CWE-532 (insertion of sensitive information into a log) compounded by CWE-460
				//(improper cleanup on a thrown exception), OWASP A09:2021.
				//WHAT IS EMITTED: nothing queued carries a credential, a length or a digest - see
				//pendingProvisioningNotices. Standard error is captured and retained wholesale by journald, the Docker
				//log driver, IIS stdout redirection, Kubernetes logs and CI transcripts.
				//WHERE: OUTSIDE the try/catch. Inside it, a failure in the output stream was caught by the clause
				//above, which then called RollbackTransaction on a transaction that had ALREADY COMMITTED DURABLY. A
				//finally block would be wrong for the same reason: it would also run on the rollback path.
				FlushProvisioningNotices();
			}
		}

		#region <--- Initial administrator credential (finding C-01) --->

		/// <remarks>
		/// THREAT ADDRESSED - C-01 with CWE-532 (insertion of sensitive information into a log), OWASP A09:2021.
		/// <para>
		/// THE INVARIANT THIS BUFFER EXISTS TO CARRY: <b>no value added here may be, contain, measure or digest
		/// a credential.</b> Every notice names a configuration SETTING and what provisioning did with it,
		/// because standard error is captured and retained wholesale by journald, the Docker log driver, IIS
		/// stdout redirection, Kubernetes logs and CI transcripts. Queuing is required for a second reason: a
		/// notice asserts something only true once the transaction commits, and the flush sits OUTSIDE the
		/// transaction's <c>catch</c> so an output failure can never reach a transaction-control statement. No
		/// locking is needed because every writer runs inside that one transaction, on the thread that opened it.
		/// </para>
		/// </remarks>
		private readonly List<string> pendingProvisioningNotices = new List<string>();

		/// <remarks>
		/// SECURITY - C-01. Standard error, never <c>LogService</c>, and the choice is load-bearing: the log
		/// writer persists through the very database connection this transaction is still building. The notices
		/// carry no credential material - see <see cref="pendingProvisioningNotices"/> - and the buffer is
		/// emptied as it drains, so no notice can be emitted twice by a later call on this singleton.
		/// </remarks>
		private void FlushProvisioningNotices()
		{
			foreach (string notice in pendingProvisioningNotices)
			{
				Console.Error.WriteLine(notice);
			}

			pendingProvisioningNotices.Clear();
		}

		/// <summary>
		/// Configuration key that lets an operator choose the first administrator's password up front.
		/// Supplied as the environment variable <c>Settings__InitialAdministratorPassword</c>, or through
		/// user secrets in development.
		/// </summary>
		private const string InitialAdministratorPasswordSettingKey = "Settings:InitialAdministratorPassword";

		/// <summary>
		/// Alphabet <see cref="GenerateInitialAdministratorPassword"/> draws from: upper case, lower case,
		/// digits and symbols, the complexity the mandated Authentication Hardening standard requires.
		/// Visually ambiguous characters are excluded - no capital O or I, no lower-case l, no digit 0 or 1 -
		/// so a value remains safe to transcribe. Nothing in the platform prints one: the generator's only live
		/// caller is the Local System identity, whose credential is written hashed and never disclosed.
		/// </summary>
		private const string InitialAdministratorPasswordAlphabet =
			"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%*+-=?@";

		/// <summary>
		/// The four character classes the mandated standard names, as disjoint slices of
		/// <see cref="InitialAdministratorPasswordAlphabet"/>; concatenated they reproduce it exactly, which is
		/// what keeps the two constants from drifting. They exist so class coverage is GUARANTEED rather than
		/// merely likely - see <see cref="GenerateInitialAdministratorPassword"/> (C-01).
		/// </summary>
		private static readonly string[] InitialAdministratorPasswordCharacterClasses = new[]
		{
			"ABCDEFGHJKLMNPQRSTUVWXYZ",
			"abcdefghijkmnopqrstuvwxyz",
			"23456789",
			"!#%*+-=?@"
		};

		/// <summary>
		/// Length of the generated credential: well above the mandated twelve-character floor and drawn from a
		/// 66-character alphabet, so it carries roughly 120 bits of entropy - which is what matters for a
		/// credential that is never rotated because nobody ever signs in as its account.
		/// </summary>
		private const int InitialAdministratorPasswordLength = 20;

		/// <remarks>
		/// SECURITY - C-01, CWE-798 (hard-coded credentials) and CWE-1392 (default credentials), OWASP A07:2021,
		/// with CWE-532 (insertion of sensitive information into a log), OWASP A09:2021. The literal password
		/// this replaces shipped in the public source tree, so any installation that had not changed it could be
		/// signed into as administrator by anybody.
		/// <para>
		/// ONE SUPPLY ROUTE, AND IT IS REQUIRED. Nothing is generated for the administrator account, because any
		/// credential the platform invents has to be communicated back and every channel reachable from inside a
		/// provisioning transaction is durable and multi-reader; an installation configured with no value
		/// therefore fails to start, loudly, naming the setting. First-login rotation is then ENFORCED through
		/// <see cref="ErpUserPreferences.PasswordChangeRequired"/>, which needs no schema change: AuthService
		/// refuses to mint or refresh a bearer token while it stands, while interactive login stays open because
		/// it is the only route to the screen that changes the password.
		/// </para>
		/// </remarks>
		private string ResolveInitialAdministratorPassword()
		{
			// ErpSettings.Initialize always runs first, so Configuration is populated. The null-condition operator
			// is kept so a future caller that provisions without initialising settings reaches the actionable
			// failure below rather than a NullReferenceException inside a transaction.
			string configuredPassword = ErpSettings.Configuration?[InitialAdministratorPasswordSettingKey];

			// THREAT ADDRESSED - CWE-532, OWASP A09:2021. Absence is a hard failure, not a fallback: there is
			// deliberately no second route, because a method that never invents a credential never has to
			// disclose one through an output stream every hosting substrate captures and retains.
			if (string.IsNullOrWhiteSpace(configuredPassword))
			{
				throw new InvalidOperationException(MissingAdministratorPasswordMessage);
			}

			// THREAT ADDRESSED - C-01 (CWE-521 weak password requirements, CWE-1392 default credential), OWASP
			// A07:2021. Accepted on non-blankness alone, this setting let the literal removed from the source be
			// reinstated verbatim through configuration. Validated BEFORE it is returned to be hashed, and a
			// failure aborts provisioning rather than substituting another value.
			ValidateInitialAdministratorPassword(configuredPassword, ConfiguredPasswordSourceDescription);

			// Only the setting NAME appears - never the value, its length or a digest of it (CWE-532) - and it
			// is queued rather than printed because it asserts that the configured password is now the
			// administrator's, which is only true once the transaction commits.
			pendingProvisioningNotices.Add("info: WebVella.Erp.ErpService[1] The first administrator password was taken from " +
				"'" + InitialAdministratorPasswordSettingKey + "'. It is not echoed here.");

			return configuredPassword;
		}

		/// <remarks>
		/// SECURITY - CWE-532, OWASP A09:2021. One constant, so the two credential paths cannot describe the
		/// same requirement differently, worded to be actionable without describing any value. It necessarily
		/// appears in a startup failure, which is a captured output stream.
		/// </remarks>
		// static readonly rather than const: the bounds are read from PasswordMinLength/PasswordMaxLength, so
		// the stated policy cannot drift from the applied one. A const would force the two numbers to be
		// repeated as literals - the defect M-13 records.
		private static readonly string MissingAdministratorPasswordMessage =
			"SECURITY: no administrator password is configured. Supply '" + InitialAdministratorPasswordSettingKey +
			"' - as the environment variable 'Settings__InitialAdministratorPassword', or through user secrets in " +
			"development - and start again. It must be " + PasswordMinLength.ToString(CultureInfo.InvariantCulture) +
			" to " + PasswordMaxLength.ToString(CultureInfo.InvariantCulture) + " characters and contain an upper case " +
			"letter, a lower case letter, a digit and a symbol. The platform deliberately does NOT generate one: any " +
			"value it invented would have to be reported back through an output stream that hosting substrates capture " +
			"and retain, which is the credential-disclosure defect this behaviour replaces. See " +
			"docs/security/credential-migration.md.";

		/// <summary>
		/// Describes the operator-supplied credential route in a policy-failure message. Held as a constant
		/// so the two call sites cannot describe the same route differently.
		/// </summary>
		private const string ConfiguredPasswordSourceDescription =
			"The value came from '" + InitialAdministratorPasswordSettingKey + "'.";

		/// <summary>
		/// Describes the generated credential route in a policy-failure message. Reaching it means the
		/// generator no longer satisfies the policy - a defect in this file rather than an operator error.
		/// </summary>
		private const string GeneratedPasswordSourceDescription =
			"The value was generated internally, so this indicates a defect in the generator constants " +
			"rather than a configuration mistake.";

		/// <remarks>
		/// THREAT ADDRESSED - C-01 (CWE-521 weak password requirements, CWE-1392 default credential), OWASP
		/// A07:2021. Without this the configured supply route accepted any non-blank string, so the default
		/// credential deleted from the source could be restored through configuration.
		/// <para>
		/// THE UPPER BOUND IS A CORRECTNESS FIX, NOT SYMMETRY: <c>PasswordUtil.HashPassword</c> THROWS
		/// <see cref="ArgumentOutOfRangeException"/> above its 128-character bound and the field's
		/// <c>MaxLength</c> metadata is not enforced on write, so an over-long value would abort provisioning
		/// from inside the record write, naming a parameter rather than the setting to correct. The message never
		/// describes the value - not its length, which clause failed, or a digest (CWE-532). The class tests do
		/// not reuse <see cref="InitialAdministratorPasswordCharacterClasses"/>, which is pruned of ambiguous
		/// characters and would reject a strong password for containing a capital O or a dollar sign.
		/// </para>
		/// </remarks>
		private static void ValidateInitialAdministratorPassword(string password, string sourceDescription)
		{
			// Size before content, as PasswordUtil does: an oversized value is refused on one integer
			// comparison rather than after a full character scan.
			bool lengthWithinPolicy = password.Length >= PasswordMinLength
				&& password.Length <= PasswordMaxLength;

			bool hasUpperCase = false;
			bool hasLowerCase = false;
			bool hasDigit = false;
			bool hasSymbol = false;

			if (lengthWithinPolicy)
			{
				// "Symbol" is defined by exclusion rather than by an allow-list, so any non-alphanumeric character an
				// operator can type counts. The four tests partition the character space, which is what makes the
				// composition check total: every character advances exactly one flag and none falls through.
				foreach (char character in password)
				{
					if (char.IsUpper(character))
						hasUpperCase = true;
					else if (char.IsLower(character))
						hasLowerCase = true;
					else if (char.IsDigit(character))
						hasDigit = true;
					else
						hasSymbol = true;
				}
			}

			if (lengthWithinPolicy && hasUpperCase && hasLowerCase && hasDigit && hasSymbol)
			{
				return;
			}

			throw new InvalidOperationException(
				"SECURITY - the administrator password does not meet the required password policy, so " +
				"provisioning was aborted and no administrator credential was written. " + sourceDescription +
				" Supply a value of " + PasswordMinLength.ToString(CultureInfo.InvariantCulture) + " to " +
				PasswordMaxLength.ToString(CultureInfo.InvariantCulture) + " characters containing at least " +
				"one upper case letter, one lower case letter, one digit and one symbol in '" +
				InitialAdministratorPasswordSettingKey + "', then start the application again. There is " +
				"deliberately no generated fallback, because a credential the platform invented would have to " +
				"be reported back through an output stream hosting substrates capture and retain. The " +
				"value supplied is not echoed here or " +
				"anywhere else, and neither is its length. See docs/security/secure-configuration.md.");
		}

		/// <remarks>
		/// SECURITY (C-01, and the mandated cryptographic standard's CSPRNG clause): every character comes from
		/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, never <c>System.Random</c>, and
		/// through <c>GetItems</c> rather than a modulo over random bytes, which would bias towards the
		/// alphabet's first characters. CLASS COVERAGE IS GUARANTEED, NOT ASSUMED, because the write-path policy
		/// is enforced rather than advisory: a uniform draw would leave about one value in thirteen with no digit
		/// and provisioning would fail on a valid-looking line. One character is drawn per class, the remainder
		/// from the full alphabet, and the buffer is then shuffled with the same generator - the shuffle being
		/// the load-bearing half, since without it the first four positions would be determined by class.
		/// </remarks>
		private static string GenerateInitialAdministratorPassword()
		{
			char[] buffer = new char[InitialAdministratorPasswordLength];

			// One character per mandated class, so composition is a property of the construction rather than
			// of chance. The length constant is well above the class count, so this cannot overrun.
			for (int index = 0; index < InitialAdministratorPasswordCharacterClasses.Length; index++)
			{
				buffer[index] = RandomNumberGenerator.GetItems<char>(
					InitialAdministratorPasswordCharacterClasses[index].AsSpan(), 1)[0];
			}

			// the balance is drawn uniformly from the whole alphabet, which supplies essentially all the entropy
			RandomNumberGenerator.GetItems<char>(
				InitialAdministratorPasswordAlphabet.AsSpan(),
				buffer.AsSpan(InitialAdministratorPasswordCharacterClasses.Length));

			// Removes the positional structure the seeding step introduced. Fisher-Yates driven by the same
			// CSPRNG, so the permutation is unpredictable; a non-cryptographic shuffle would hand back
			// exactly the bias this call removes.
			RandomNumberGenerator.Shuffle(buffer.AsSpan());

			string generatedPassword = new string(buffer);

			// A self-check that lives HERE rather than at the call site, so a future caller cannot bypass it. The
			// generator's length and class coverage are properties of three constants a later edit could change
			// independently of the policy, and the account this secures holds the administrator role and bypasses
			// permission checks for background work. It reads no configuration and never echoes the value.
			ValidateInitialAdministratorPassword(generatedPassword, GeneratedPasswordSourceDescription);

			return generatedPassword;
		}

		#endregion

		public void InitializePlugins(IServiceProvider serviceProvider)
		{
			foreach (ErpPlugin plugin in Plugins)
				plugin.Initialize(serviceProvider);

			JobManager.Current.RegisterJobTypes(this);
			HookManager.RegisterHooks(this);
		}

		public void SetAutoMapperConfiguration()
		{
			foreach (ErpPlugin plugin in Plugins)
				plugin.SetAutoMapperConfiguration(ErpAutoMapperConfiguration.MappingExpressions);
		}

		public void InitializeBackgroundJobs(List<JobType> additionalJobTypes = null)
		{
			JobManagerSettings settings = new JobManagerSettings();
			settings.DbConnectionString = ErpSettings.ConnectionString;
			settings.Enabled = ErpSettings.EnableBackgroundJobs;

			JobManager.Initialize(settings, additionalJobTypes);
			ScheduleManager.Initialize(settings);
		}

		public void StartBackgroundJobProcess()
		{
			JobManager.Current.ProcessJobsAsync();
			ScheduleManager.Current.ProcessSchedulesAsync();
		}

		private void CheckCreateSystemTables()
		{
			using (var connection = DbContext.Current.CreateConnection())
			{
				bool entitiesTableExists = false;
				var command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'entities' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					entitiesTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!entitiesTableExists)
				{
					command = connection.CreateCommand("CREATE TABLE public.entities(  id uuid NOT NULL, \"json\"  json NOT NULL,  CONSTRAINT entities_pkey	PRIMARY KEY (id)) WITH(	OIDS = FALSE  )");
					command.ExecuteNonQuery();
				}

				bool relationsTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'entity_relations' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					relationsTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!relationsTableExists)
				{
					command = connection.CreateCommand("CREATE TABLE public.entity_relations(  id uuid NOT NULL, \"json\"  json NOT NULL,  CONSTRAINT entity_relations_pkey	PRIMARY KEY (id)) WITH(	OIDS = FALSE  )");
					command.ExecuteNonQuery();
				}


				bool settingsTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'system_settings' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					settingsTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!settingsTableExists)
				{
					command = connection.CreateCommand("CREATE TABLE public.system_settings (  id uuid NOT NULL,  version  integer NOT NULL, CONSTRAINT system_settings_pkey	PRIMARY KEY(id)) WITH(	OIDS = FALSE  )");
					command.ExecuteNonQuery();
				}


				bool systemSearchTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'system_search' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					systemSearchTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!systemSearchTableExists)
				{
					const string filesTableSql = @"CREATE TABLE public.system_search (
  id UUID NOT NULL,
  entities TEXT DEFAULT ''::text NOT NULL,
  apps TEXT DEFAULT ''::text NOT NULL,
  records TEXT DEFAULT ''::text NOT NULL,
  content TEXT DEFAULT ''::text NOT NULL,
  snippet TEXT DEFAULT ''::text NOT NULL,
  url TEXT DEFAULT ''::text NOT NULL,
  aux_data TEXT DEFAULT ''::text NOT NULL,
  ""timestamp"" TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  stem_content TEXT DEFAULT ''::text NOT NULL,
  CONSTRAINT system_search_pkey PRIMARY KEY(id)
) 
WITH(oids = false); ";

					command = connection.CreateCommand(filesTableSql);
					command.ExecuteNonQuery();

					command = connection.CreateCommand("CREATE INDEX system_search_fts_idx ON system_search USING gin( to_tsvector( 'english', stem_content) )");
					command.ExecuteNonQuery();
				}


				bool filesTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'files' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					filesTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!filesTableExists)
				{
					const string filesTableSql = @"CREATE TABLE public.files (
					  id           uuid NOT NULL,
					  object_id    numeric(18) NOT NULL,
					  filepath     text NOT NULL,
					  created_on   timestamp WITHOUT TIME ZONE NOT NULL,
					  modified_on  timestamp WITHOUT TIME ZONE NOT NULL,
					  created_by   uuid,
					  modified_by  uuid,
					  /* Keys */
					  CONSTRAINT files_pkey
						PRIMARY KEY (id), 
					  CONSTRAINT udx_filepath
						UNIQUE (filepath), 
					  CONSTRAINT udx_object_id
						UNIQUE (object_id)
					) WITH (
						OIDS = FALSE
					  )";

					command = connection.CreateCommand(filesTableSql);
					command.ExecuteNonQuery();

					DbRepository.CreateIndex("idx_filepath", "files", "filepath", null, true);
				}

				//drop unique constraint for object id - to support FS storage (object id is 0 for all files stored on file system)
				if (!filesTableExists)
				{
					DbRepository.DropUniqueConstraint("udx_object_id", "files");
				}


				bool jobsTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'jobs' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					jobsTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!jobsTableExists)
				{
					const string jobTableSql = @"CREATE TABLE public.jobs (
					  id	uuid NOT NULL,
					  type_id	uuid NOT NULL,
					  type_name text NOT NULL,
					  complete_class_name text NOT NULL,
					  attributes text,
					  status	integer NOT NULL,
					  priority	integer NOT NULL,
					  started_on	timestamp WITH TIME ZONE,
					  finished_on	timestamp WITH TIME ZONE,
					  aborted_by	uuid,
					  canceled_by	uuid,
					  error_message text,
					  schedule_plan_id	uuid,
					  created_on   timestamp WITH TIME ZONE NOT NULL,
					  last_modified_on  timestamp WITH TIME ZONE NOT NULL,
					  created_by   uuid,
					  last_modified_by  uuid,
					  /* Keys */
					  CONSTRAINT jobs_pkey
						PRIMARY KEY (id)
					) WITH (
						OIDS = FALSE
					  )";

					command = connection.CreateCommand(jobTableSql);
					command.ExecuteNonQuery();
				}

				bool schedulePlanTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'schedule_plan' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					schedulePlanTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!schedulePlanTableExists)
				{
					const string schedulePlanTableSql = @"CREATE TABLE public.schedule_plan (
					  id	uuid NOT NULL,
					  name text NOT NULL,
					  type	integer NOT NULL,
					  start_date	timestamp WITH TIME ZONE,
					  end_date	timestamp WITH TIME ZONE,
					  schedule_days json,
					  interval_in_minutes integer,
					  start_timespan	integer,
					  end_timespan	integer,
					  last_trigger_time	timestamp WITH TIME ZONE,
					  next_trigger_time	timestamp WITH TIME ZONE,
					  job_type_id	uuid NOT NULL,
					  job_attributes text,
					  enabled	boolean NOT NULL,
					  last_started_job_id	uuid,
					  created_on   timestamp WITH TIME ZONE NOT NULL,
					  last_modified_on  timestamp WITH TIME ZONE NOT NULL,
					  last_modified_by  uuid,
					  /* Keys */
					  CONSTRAINT schedule_plan_pkey
						PRIMARY KEY (id)
					) WITH (
						OIDS = FALSE
					  )";

					command = connection.CreateCommand(schedulePlanTableSql);
					command.ExecuteNonQuery();
				}

				//added result column into system table jobs
				bool jobsResultColumnExists = false;
				command = connection.CreateCommand("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='jobs' AND column_name='result')");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					jobsResultColumnExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!jobsResultColumnExists)
				{
					command = connection.CreateCommand("ALTER TABLE public.jobs  ADD COLUMN result text");
					command.ExecuteNonQuery();
				}

				bool systemLogTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'system_log' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					systemLogTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!systemLogTableExists)
				{
					command = connection.CreateCommand(@"
CREATE TABLE public.system_log (
  id UUID NOT NULL,
  created_on TIMESTAMP WITH TIME ZONE DEFAULT '2011-11-11 02:11:11+02'::timestamp with time zone NOT NULL,
  type INTEGER DEFAULT 1 NOT NULL,
  message TEXT DEFAULT 'message'::text NOT NULL,
  source TEXT DEFAULT 'source'::text NOT NULL,
  details TEXT,
  notification_status INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT system_log_pkey PRIMARY KEY(id)
) 
WITH (oids = false);

CREATE INDEX idx_system_log_created_on ON public.system_log
  USING btree (created_on);

CREATE INDEX idx_system_log_message ON public.system_log
  USING btree (message COLLATE pg_catalog.""default"");

CREATE INDEX idx_system_log_notification_status ON public.system_log
    USING btree(notification_status);

CREATE INDEX idx_system_log_source ON public.system_log
  USING btree(source COLLATE pg_catalog.""default"");

CREATE INDEX idx_system_log_type ON public.system_log
  USING btree(type);
");
					command.ExecuteNonQuery();
				}

				bool pluginDataTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'plugin_data' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					pluginDataTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!pluginDataTableExists)
				{
					command = connection.CreateCommand(@"
CREATE TABLE plugin_data(
  id UUID NOT NULL,
  name TEXT DEFAULT ''::text NOT NULL,
  data TEXT DEFAULT ''::text,
  CONSTRAINT idx_u_plugin_data_name UNIQUE(name),
  CONSTRAINT plugin_data_pkey PRIMARY KEY(id)
)
WITH(oids = false);");
					command.ExecuteNonQuery();
				}


				bool appTableExists = false;
				command = connection.CreateCommand("SELECT EXISTS (  SELECT 1 FROM   information_schema.tables  WHERE  table_schema = 'public' AND table_name = 'app' ) ");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					appTableExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!appTableExists)
				{
					const string sql = @"
CREATE TABLE public.app (
    id uuid NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    label text NOT NULL,
    description text,
    icon_class text,
    author text,
    color text,
    weight integer DEFAULT '-1'::integer NOT NULL,
    access uuid[]
)
WITH (oids = false);

CREATE TABLE public.app_sitemap_area (
    id uuid NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    label text,
    label_translations text,
    description text,
    description_translations text,
    icon_class text,
    weight integer DEFAULT '-1'::integer NOT NULL,
    color text,
    show_group_names boolean DEFAULT false NOT NULL,
    access_roles uuid[] NOT NULL,
    app_id uuid NOT NULL
)
WITH (oids = false);

CREATE TABLE public.app_sitemap_area_group (
    id uuid NOT NULL,
    area_id uuid NOT NULL,
    weight integer DEFAULT '-1'::integer NOT NULL,
    name text NOT NULL,
    label text,
    label_translations text,
    render_roles uuid[] NOT NULL
)
WITH (oids = false);

CREATE TABLE public.app_sitemap_area_node (
    id uuid NOT NULL,
    area_id uuid NOT NULL,
    name text NOT NULL,
    label text,
    label_translations text,
    icon_class text,
    url text,
    weight integer NOT NULL,
    access_roles uuid[] NOT NULL,
    type integer NOT NULL,
    entity_id uuid
)
WITH (oids = false);

CREATE TABLE public.app_page (
    id uuid NOT NULL,
    name text NOT NULL,
    label text,
    icon_class text,
    system boolean DEFAULT false,
    type integer NOT NULL,
    weight integer DEFAULT '-1'::integer NOT NULL,
    label_translations text,
	razor_body text,
    area_id uuid,
    node_id uuid,
    app_id uuid,
    entity_id uuid,
    is_razor_body boolean DEFAULT false NOT NULL
)
WITH (oids = false);

CREATE TABLE public.app_page_body_node (
    id uuid NOT NULL,
    parent_id uuid,
    node_id uuid,
	page_id uuid NOT NULL,
    weight integer DEFAULT '-1'::integer NOT NULL,
    component_name text,
    options text
)
WITH (oids = false);


ALTER TABLE public.app_page_body_node
    ADD COLUMN container_id text;

CREATE INDEX idx_app_page_body_node_page_id ON app_page_body_node USING btree (page_id);
CREATE INDEX idx_app_page_app_id ON app_page USING btree (app_id);
CREATE INDEX fki_app_page_body_node_parent_id ON app_page_body_node USING btree (parent_id);
CREATE INDEX fki_app_page_area_id ON app_page USING btree (area_id);
CREATE INDEX fki_app_page_node_id ON app_page USING btree (node_id);
CREATE INDEX fki_app_page_entity_id ON app_page USING btree (entity_id);

ALTER TABLE ONLY app_page_body_node
    ADD CONSTRAINT app_page_body_node_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app
    ADD CONSTRAINT app_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app_sitemap_area
    ADD CONSTRAINT app_sitemap_area_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app_sitemap_area_group
    ADD CONSTRAINT app_sitemap_area_group_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app_sitemap_area_node
    ADD CONSTRAINT app_sitemap_area_node_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app_page
    ADD CONSTRAINT app_page_pkey
    PRIMARY KEY (id);

ALTER TABLE ONLY app_page_body_node
    ADD CONSTRAINT fkey_app_page_body_node_parent_id
    FOREIGN KEY (parent_id) REFERENCES app_page_body_node(id);

ALTER TABLE ONLY app_page_body_node
    ADD CONSTRAINT fkey_app_page_body_node_page_id
    FOREIGN KEY (page_id) REFERENCES app_page(id);

ALTER TABLE ONLY app_sitemap_area
    ADD CONSTRAINT fkey_app_id
    FOREIGN KEY (app_id) REFERENCES app(id);

ALTER TABLE ONLY app_sitemap_area_group
    ADD CONSTRAINT fkey_area_id
    FOREIGN KEY (area_id) REFERENCES app_sitemap_area(id);

ALTER TABLE ONLY app_sitemap_area_node
    ADD CONSTRAINT fkey_area_id
    FOREIGN KEY (area_id) REFERENCES app_sitemap_area(id);

ALTER TABLE ONLY app_page
    ADD CONSTRAINT fkey_app_id
    FOREIGN KEY (app_id) REFERENCES app(id);

ALTER TABLE ONLY app_page
    ADD CONSTRAINT fkey_area_id
    FOREIGN KEY (area_id) REFERENCES app_sitemap_area(id);

ALTER TABLE ONLY app_page
    ADD CONSTRAINT fkey_node_id
    FOREIGN KEY (node_id) REFERENCES app_sitemap_area_node(id);

ALTER TABLE ONLY app
    ADD CONSTRAINT ux_app_name
    UNIQUE (name);	

ALTER TABLE public.app_page
	ADD COLUMN layout text NOT NULL DEFAULT '';	
	
CREATE TABLE public.data_source (
  id UUID NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  weight INTEGER NOT NULL,
  eql_text TEXT NOT NULL,
  sql_text TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  fields_json TEXT NOT NULL,
  entity_name TEXT NOT NULL,
  CONSTRAINT data_source_pkey PRIMARY KEY(id),
  CONSTRAINT ux_data_source_name UNIQUE(name)
) 
WITH (oids = false);


CREATE TABLE public.app_page_data_source (
  parameters TEXT NOT NULL,
  name TEXT NOT NULL,
  id UUID NOT NULL,
  page_id UUID NOT NULL,
  data_source_id UUID NOT NULL,
  CONSTRAINT app_page_data_source_pkey PRIMARY KEY(id),
  CONSTRAINT app_page_data_uxc_name_page_id UNIQUE(name, page_id)
) 
WITH (oids = false);

ALTER TABLE public.app_page_data_source
  ADD CONSTRAINT fkey_page_id FOREIGN KEY (page_id)
    REFERENCES public.app_page(id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
    NOT DEFERRABLE;

CREATE INDEX fki_app_page_data_fkc_page_id ON public.app_page_data_source
  USING btree (page_id);";

					command = connection.CreateCommand(sql);
					command.ExecuteNonQuery();
				}

				bool datasourceReturnTotalColumnExists = false;
				command = connection.CreateCommand("SELECT EXISTS ( SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'data_source' AND column_name = 'return_total' )");
				using (var reader = command.ExecuteReader())
				{
					reader.Read();
					datasourceReturnTotalColumnExists = reader.GetBoolean(0);
					reader.Close();
				}

				if (!datasourceReturnTotalColumnExists)
				{
					command = connection.CreateCommand(@"ALTER TABLE data_source ADD COLUMN return_total boolean NOT NULL DEFAULT true;");
					command.ExecuteNonQuery();
				}
			}
		}

		private void UpdateSitemapNodeTable1()
		{
			using (var connection = DbContext.Current.CreateConnection())
			{
				const string updateTable = @"ALTER TABLE public.app_sitemap_area_node 
                  ADD COLUMN entity_list_pages uuid[] NOT NULL DEFAULT array[]::uuid[],
                  ADD COLUMN entity_create_pages uuid[] NOT NULL DEFAULT array[]::uuid[],
                  ADD COLUMN entity_details_pages uuid[] NOT NULL DEFAULT array[]::uuid[],
                  ADD COLUMN entity_manage_pages uuid[] NOT NULL DEFAULT array[]::uuid[];";

				var command = connection.CreateCommand(updateTable);
				command.ExecuteNonQuery();
			}
		}

		private void UpdateSitemapNodeTable2()
		{
			using (var connection = DbContext.Current.CreateConnection())
			{
				const string updateTable = @"ALTER TABLE public.app_sitemap_area_node 
                  ADD COLUMN parent_id uuid DEFAULT NULL;

						ALTER TABLE ONLY public.app_sitemap_area_node
						ADD CONSTRAINT fkey_app_sitemap_area_node_parent_id
						FOREIGN KEY (parent_id) REFERENCES app_sitemap_area_node(id);";

				var command = connection.CreateCommand(updateTable);
				command.ExecuteNonQuery();
			}
		}

		#region <--- schema version 4 security migration (findings C-01, C-02, C-05, M-13) --->

		/// <remarks>
		/// SECURITY - the version-gated half of four findings whose provisioning half is in
		/// <see cref="InitializeSystemEntities"/>: C-01 revokes the shipped default administrator credential,
		/// C-02 revokes the anonymous read grant on the user entity and gives the password field
		/// administrator-only permissions, C-05 revokes the anonymous create grants, and M-13 raises the
		/// password length bounds from 6-24 to 12-128.
		/// <para>
		/// FOUR PROPERTIES A LATER EDIT COULD QUIETLY BREAK. IDEMPOTENT: every step is a no-op once its target
		/// is correct. FAILS LOUDLY: nothing here catches, because swallowing an error would advance the stored
		/// schema version past work that did not happen. TOUCHES ONLY ONE CREDENTIAL: ordinary passwords are
		/// re-hashed individually on their owner's next sign-in instead. EMITS NO SCHEMA DEFINITION STATEMENT,
		/// which is why <see cref="SecurePasswordFieldMetadata4(EntityManager)"/> writes through
		/// <c>DbEntityRepository.Update</c> rather than <c>EntityManager.UpdateField</c>, whose apparently
		/// metadata-only call issues <c>ALTER TABLE ... ALTER COLUMN</c> and <c>DROP INDEX</c>.
		/// </para>
		/// </remarks>
		private void MigrateSecurityDefaults4(EntityManager entMan, RecordManager recMan)
		{
			// The metadata writes require administrator meta permission and the credential read requires a security
			// context to exist at all. Both hosts already provide one, so this scope is nested; it is opened anyway
			// so a security migration is not defeasible by a caller that forgot to establish a context.
			using (SecurityContext.OpenSystemScope())
			{
				// ORDER MATTERS and is LOAD-BEARING. SecurePasswordFieldMetadata4 raises the declared bounds from the
				// 6-24 an unmigrated installation still carries to 12-128; RevokeSeedAdministratorCredential4 then
				// WRITES the operator's own passphrase, which may legitimately exceed 24 characters and is validated
				// against those bounds first. The dependency runs one way, and all three steps stay idempotent.
				SecurePasswordFieldMetadata4(entMan);
				RevokeSeedAdministratorCredential4(recMan);
				RevokeGuestRecordPermissions4(entMan);
			}
		}

		/// <remarks>
		/// SECURITY - C-01, CWE-798 (hard-coded credentials) and CWE-1392 (default credentials), OWASP A07:2021.
		/// THREAT: every installation provisioned by an earlier release holds an administrator account at a
		/// published address whose password is in this repository's own history, and correcting provisioning does
		/// not touch it, because provisioning has already run.
		/// <para>
		/// The hash is read through <c>SecurityManager.ReadStoredPasswordHash</c>, not through the record or EQL
		/// path: every projection seam now replaces an encrypted password value with a redaction marker, so those
		/// routes would hand this guard the marker and the migration would silently do nothing. It is keyed on the
		/// account id, because an operator may have changed the address. The value is replaced only when it still
		/// has the legacy digest shape AND verifies against the published default, so an operator who has already
		/// chosen their own password is never disrupted; the replacement comes from
		/// <see cref="InitialAdministratorPasswordSettingKey"/> and is marked for rotation.
		/// </para>
		/// </remarks>
		private void RevokeSeedAdministratorCredential4(RecordManager recMan)
		{
			ErpUser seedAdministrator = new SecurityManager().GetUser(SystemIds.FirstUserId);

			// an installation whose seeded administrator row was removed or renumbered has nothing to revoke,
			// which is not an error
			if (seedAdministrator == null)
			{
				return;
			}

			// SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021). Read through
			// SecurityManager.ReadStoredPasswordHash - the platform's ONE system-only credential query - and never
			// from seedAdministrator.Password, which comes from a projection and is therefore the redaction marker;
			// reading the property would make the comparison below never match and THIS REVOCATION WOULD SILENTLY
			// STOP WORKING on exactly the deployments that need it.
			string storedHash = SecurityManager.ReadStoredPasswordHash(SystemIds.FirstUserId);

			// THE GUARD. Anything other than the published default - a modern hash, a legacy hash of a password the
			// operator chose, an empty or absent column - is left exactly as it is, which is what makes this
			// revocation SAFE rather than destructive.
			// The literal below is a REVOCATION TARGET, NOT A CREDENTIAL: nothing assigns it, no code path can
			// provision it, and it carries no confidentiality to protect, being in this repository's public history
			// and in docs/security/security-audit-report.md as C-01. Its presence here strictly LOWERS risk,
			// because this comparison is how the value stops working. Verification is delegated to PasswordUtil, and
			// both members fail closed on a null, empty or malformed stored value.
			if (!PasswordUtil.IsLegacyHash(storedHash)
				|| !PasswordUtil.VerifyMd5Hash("erp", storedHash))
			{
				return;
			}

			// THREAT ADDRESSED - CWE-532 (insertion of sensitive information into a log), OWASP A09:2021.
			// Deliberately the SAME operator-supplied route as fresh provisioning: a migration can no more report a
			// secret it invents than provisioning can. Absence abandons the whole version 4 migration - the version
			// is not advanced, the transaction rolls back at the caller's catch, and the upgrade is retried once the
			// setting is supplied. Only installations that STILL carry the published default reach this line.
			string replacementPassword = ErpSettings.Configuration?[InitialAdministratorPasswordSettingKey];
			if (string.IsNullOrWhiteSpace(replacementPassword))
			{
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. " + MissingAdministratorPasswordMessage);
			}

			// The same policy gate provisioning applies, and for the same reason: without it the literal this
			// migration revokes could be reinstated verbatim through configuration. Applied BEFORE the write, so a
			// non-conforming value aborts the migration instead of becoming the credential.
			ValidateInitialAdministratorPassword(replacementPassword, ConfiguredPasswordSourceDescription);

			EntityRecord administratorRecord = new EntityRecord();
			administratorRecord["id"] = SystemIds.FirstUserId;
			// Plaintext on purpose: RecordManager's encrypted-password branch hashes it on write with the
			// current primitive, so it is never persisted as supplied. Pre-hashing here would store a hash of
			// a hash and lock the account out.
			administratorRecord["password"] = replacementPassword;

			//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): the replacement written above came from
			//'Settings:InitialAdministratorPassword', so it reached the account through a deployment setting - a
			//multi-reader store - rather than being chosen by the person who will use it, and is owed a rotation
			//exactly as a freshly provisioned credential is. Marking it here extends first-login rotation to
			//installations that were ALREADY deployed. Read-modify-write, not overwrite: this account may have
			//accumulated real preferences, and a fresh instance would discard its sidebar and usage state.
			ErpUserPreferences rotationRequiredPreferences = seedAdministrator.Preferences ?? new ErpUserPreferences();
			rotationRequiredPreferences.PasswordChangeRequired = true;
			administratorRecord["preferences"] = JsonConvert.SerializeObject(rotationRequiredPreferences);

			QueryResponse result = recMan.UpdateRecord("user", administratorRecord);
			if (!result.Success)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. The administrator credential shipped by earlier releases could not be revoked. Message:" + result.Message);

			// THREAT ADDRESSED - CWE-532, OWASP A09:2021. The notice carries NO credential: it names the SETTING
			// the replacement came from and what the migration did. Still QUEUED rather than written here, because
			// this runs inside the provisioning transaction: a failure in any later step rolls the password change
			// back, and emitting now would assert a revocation that had not happened.
			pendingProvisioningNotices.Add("warn: WebVella.Erp.ErpService[3] SECURITY - this installation's administrator account " +
				"(" + SystemIds.FirstUserId + ") still carried the default password published in earlier releases, so it has " +
				"been revoked and replaced with the value supplied in '" + InitialAdministratorPasswordSettingKey + "'. That " +
				"value is not echoed here or anywhere else. Sign in with it and change it immediately, and remove it from the " +
				"deployment configuration once you have. No other account's password was changed. See " +
				"docs/security/credential-migration.md.");
		}

		/// <remarks>
		/// SECURITY - C-05 (CWE-269, CWE-732) and C-02 (CWE-200, CWE-522), OWASP A01:2021. Guest is the role an
		/// unauthenticated caller is evaluated against, and earlier releases granted it create on the user
		/// entity, read on the user entity and create on the role entity, so an anonymous caller could enumerate
		/// every account and author both users and roles. Removing the grants from provisioning protects new
		/// installations only; this protects the ones already running. The role entity's Guest READ grant is NOT
		/// revoked here - this migration carries exactly the Critical scope, and that residual is recorded in
		/// <c>docs/security/risk-register.md</c>. Carried-over values are read back from the stored entity rather
		/// than restated, so a customised label, icon or colour survives.
		/// </remarks>
		private static void RevokeGuestRecordPermissions4(EntityManager entMan)
		{
			// The user entity: revoke anonymous create AND anonymous read. The Regular read grant survives, because
			// removing it would break every screen resolving the signed-in user's own name and avatar.
			RevokeGuestRecordPermissions4(entMan, SystemIds.UserEntityId, "user", true, "SCHEMA VERSION 4 MIGRATION.");

			// The role entity: revoke anonymous create only. Its anonymous READ grant sits in the tier this
			// engagement documents rather than migrates, and is recorded in
			// docs/security/risk-register.md.
			RevokeGuestRecordPermissions4(entMan, SystemIds.RoleEntityId, "role", false, "SCHEMA VERSION 4 MIGRATION.");
		}

		/// <remarks>
		/// SECURITY - C-05 and C-02; see <see cref="RevokeGuestRecordPermissions4(EntityManager)"/> for the
		/// threat. The permission lists are rebuilt as fresh copies rather than mutated in place, because
		/// <c>EntityManager.ReadEntity</c> serves entities from a process-wide metadata cache: mutating what it
		/// hands back would edit that cache, so a later rollback would leave the in-memory model disagreeing
		/// with the database. <c>RemoveAll</c> rather than <c>Remove</c>, so a duplicated grant cannot leave one
		/// copy behind, and its count is what lets this method write nothing when there was nothing to revoke -
		/// which matters because the version gate advances only after the whole migration commits.
		/// </remarks>
		private static void RevokeGuestRecordPermissions4(EntityManager entMan, Guid entityId, string entityName, bool revokeRead, string migrationLabel)
		{
			Entity storedEntity = entMan.ReadEntity(entityId).Object;
			if (storedEntity == null)
				throw new InvalidOperationException(migrationLabel + " Entity: " + entityName + ". The entity could not be read, so its anonymous record permissions could not be revoked.");

			// Entity.RecordPermissions carries no property initialiser, unlike the four lists inside it, so an older
			// or hand-edited definition can present it as absent. Reading that as "no grants recorded" stops the
			// upgrade aborting on a NullReferenceException - a security migration that crashes leaves the grants it
			// exists to remove in place.
			RecordPermissions storedPermissions = storedEntity.RecordPermissions ?? new RecordPermissions();

			// Copied rather than mutated: ReadEntity serves from a process-wide metadata cache, so editing the
			// lists it returns would write into that cache and survive a rollback.
			List<Guid> canCreate = new List<Guid>(storedPermissions.CanCreate);
			List<Guid> canRead = new List<Guid>(storedPermissions.CanRead);
			List<Guid> canUpdate = new List<Guid>(storedPermissions.CanUpdate);
			List<Guid> canDelete = new List<Guid>(storedPermissions.CanDelete);

			int revokedGrants = canCreate.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);
			if (revokeRead)
				revokedGrants += canRead.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);

			// Nothing was revoked, so nothing is written: this is what makes a replay free on an installation
			// already narrowed, since the version gate rolls back with the transaction. The test is on what was
			// actually REMOVED, so "there was something to fix" has exactly one definition here.
			if (revokedGrants == 0)
				return;

			InputEntity inputEntity = new InputEntity();
			inputEntity.Id = storedEntity.Id;
			inputEntity.Name = storedEntity.Name;
			inputEntity.Label = storedEntity.Label;
			inputEntity.LabelPlural = storedEntity.LabelPlural;
			inputEntity.System = storedEntity.System;
			inputEntity.IconName = storedEntity.IconName;
			inputEntity.Color = storedEntity.Color;
			inputEntity.RecordScreenIdField = storedEntity.RecordScreenIdField;
			inputEntity.RecordPermissions = new RecordPermissions();
			inputEntity.RecordPermissions.CanCreate = canCreate;
			inputEntity.RecordPermissions.CanRead = canRead;
			inputEntity.RecordPermissions.CanUpdate = canUpdate;
			inputEntity.RecordPermissions.CanDelete = canDelete;

			EntityResponse response = entMan.UpdateEntity(inputEntity);
			if (!response.Success)
				throw new InvalidOperationException(migrationLabel + " Entity: " + entityName + ". The anonymous record permissions could not be revoked. Message:" + response.Message);
		}

		/// <remarks>
		/// SECURITY - C-02 (CWE-200, CWE-522 / OWASP A01:2021 + A02:2021) and M-13 (CWE-521). Earlier releases
		/// provisioned this field with NO field permissions at all, so the only restriction on the stored
		/// credential was the presentation layer, which the Authorization Enforcement standard rules out.
		/// <c>EnableSecurity</c> is the load-bearing line and the easiest thing here to lose, because
		/// <c>PcFieldBase</c> gates the whole field-permission evaluation behind it and it defaults to false. The
		/// stored field is mutated IN PLACE so no property can be lost, and located by NAME so a field recreated
		/// under a different identifier is still migrated. No schema definition statement is emitted: the bounds
		/// are metadata and the column is <c>varchar(500)</c>, whose width does not derive from them.
		/// </remarks>
		private static void SecurePasswordFieldMetadata4(EntityManager entMan)
		{
			Entity userEntity = entMan.ReadEntity(SystemIds.UserEntityId).Object;
			if (userEntity == null)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. The entity could not be read, so the password field could not be secured.");

			// Located by NAME, so a field recreated under a different identifier is still migrated. Entity.Fields
			// carries no property initialiser, so the null-conditional is load-bearing: without it an entity read
			// returning no field collection would abort the upgrade on a NullReferenceException.
			PasswordField storedPasswordField = userEntity.Fields?
				.SingleOrDefault(field => field.Name == "password") as PasswordField;
			if (storedPasswordField == null)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The field is missing or is not a password field, so it could not be secured.");

			//THREAT ADDRESSED - M-13, and the acceptance criterion that no schema definition statement is emitted.
			//EntityManager.UpdateField is deliberately NOT used: it calls DbRecordRepository.UpdateRecordField,
			//which issues ALTER TABLE ... ALTER COLUMN and DROP INDEX against rec_user. Those were harmless in
			//EFFECT, but the criterion is about what is emitted. Mutating in place is also safer than the rebuild it
			//replaces, which REPLACED the whole definition and would silently erase any property a later release
			//added. The meta-permission assertion is retained because UpdateField performed one.
			if (!SecurityContext.HasMetaPermission())
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. Metadata permission is required, so the field could not be secured.");

			//SECURITY - finding M-13, CWE-521. Raised from the 6-24 this installation was provisioned with.
			storedPasswordField.MinLength = PasswordMinLength;
			storedPasswordField.MaxLength = PasswordMaxLength;
			//SECURITY - finding C-02. EnableSecurity without Permissions denies everyone; Permissions
			//without EnableSecurity denies nobody. Both are required, and administrator only - no Regular
			//and no Guest entry belongs in either list.
			storedPasswordField.EnableSecurity = true;
			storedPasswordField.Permissions = new FieldPermissions();
			storedPasswordField.Permissions.CanRead = new List<Guid>();
			storedPasswordField.Permissions.CanUpdate = new List<Guid>();
			//READ
			storedPasswordField.Permissions.CanRead.Add(SystemIds.AdministratorRoleId);
			//UPDATE
			storedPasswordField.Permissions.CanUpdate.Add(SystemIds.AdministratorRoleId);

			//Mirrors the metadata half of EntityManager.UpdateField - map the entity, update the metadata row -
			//minus the UpdateRecordField call that emitted the DDL. Cache.Clear is unconditional and runs before the
			//result is inspected, as UpdateField does: a failed update must not leave a stale definition cached.
			DbEntity updatedEntity = userEntity.MapTo<DbEntity>();
			bool updated = DbContext.Current.EntityRepository.Update(updatedEntity);
			Cache.Clear();
			if (!updated)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The entity metadata update did not apply, so the field could not be secured.");
		}

		#endregion
	}
}
