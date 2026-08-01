using System;
using System.Collections.Generic;
using System.Linq;
// SECURITY (finding C-01, CWE-798/CWE-1392): supplies the cryptographically secure random source used
// to generate the initial administrator credential that replaced the shipped literal password.
using System.Security.Cryptography;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Hooks;
using WebVella.Erp.Jobs;
// SECURITY (finding C-01, CWE-798/CWE-1392): supplies PasswordUtil, whose assembly-internal legacy
// verification members let the schema version 4 data migration below recognise a deployment that still
// carries the administrator credential earlier releases shipped, without recomputing MD5 here.
using WebVella.Erp.Utilities;

namespace WebVella.Erp
{
	public class ErpService : IErpService
	{
		public List<ErpPlugin> Plugins { get; set; } = new List<ErpPlugin>();
		public List<ErpJob> Jobs { get; set; } = new List<ErpJob>();

		/// <summary>
		/// Minimum length provisioned onto the user entity's password field.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding M-13, CWE-521 weak password requirements. Twelve implements the mandated
		/// Authentication Hardening standard's "12+ characters" literally, replacing a six-character floor.
		/// Declared once and consumed by BOTH the version 1 provisioning seed and the version 4 data
		/// migration below, so a freshly provisioned installation and an upgraded one can never end up
		/// under different policies - which is exactly the class of defect that makes a seed-only fix look
		/// correct while deployed instances stay weak.
		/// </remarks>
		private const int PasswordMinLength = 12;

		/// <summary>
		/// Maximum length provisioned onto the user entity's password field.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding M-13, CWE-521. The previous ceiling of 24 characters was itself an obstacle
		/// to a strong passphrase. This value deliberately equals the input bound enforced by
		/// <c>WebVella.Erp.Utilities.PasswordUtil</c>, so the policy advertised by the field metadata and
		/// the length the hashing primitive will actually accept are the same number and cannot drift into
		/// a state where the platform advertises a password it would then refuse to hash.
		/// </remarks>
		private const int PasswordMaxLength = 128;

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
							//SECURITY - findings C-05 (Critical) and C-02 (Critical). C-05: CWE-269 improper
							//privilege management, CWE-732 incorrect permission assignment for a critical
							//resource, OWASP A01:2021 Broken Access Control. C-02: CWE-200 exposure of
							//sensitive information to an unauthorized actor, CWE-522 insufficiently protected
							//credentials, OWASP A01:2021 + A02:2021.
							//THREAT: two grants were seeded here for the Guest role - the role every
							//unauthenticated caller is evaluated as when no user is resolved (see
							//SecurityContext.HasEntityPermission, which falls back to the Guest grants
							//precisely when CurrentUser is null). Guest CREATE on the user entity was
							//self-registration into the identity store, i.e. a privilege-escalation primitive:
							//an anonymous caller could insert a user row and then have it granted a role.
							//Guest READ on the user entity exposed the whole user collection - including the
							//stored password hash column - to anonymous callers.
							//REMEDIATION, per the mandated Authorization Enforcement standard's
							//deny-by-default clause: both Guest grants are removed. The Administrator grants
							//below are retained, and the Regular READ grant is retained deliberately -
							//removing it would break every screen that resolves the signed-in user's own name
							//and avatar, which the preservation requirement forbids. The hash itself is
							//protected by two narrower controls instead: the administrator-only field
							//permissions assigned to the password field further down, and the read-projection
							//redaction in Api/RecordManager.cs and Database/DbRecordRepository.cs. That
							//layering is why the entity-level Regular grant can safely stay.
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
								//SECURITY - finding M-13, CWE-521 weak password requirements. The bounds were
								//6 to 24 characters.
								//THREAT: a six-character minimum permits a credential that falls to an offline
								//guess in seconds, and the low CEILING was the more damaging half - a
								//24-character maximum is itself an obstacle to a strong passphrase, so the
								//policy actively discouraged the one thing that would have compensated for the
								//weak floor.
								//REMEDIATION: 12 implements the mandated Authentication Hardening standard's
								//"12+ characters" literally; 128 removes the ceiling as an obstacle while still
								//bounding the input the key-derivation primitive will process (PasswordUtil
								//refuses anything longer, so the two limits are deliberately identical).
								password.MinLength = PasswordMinLength;
								password.MaxLength = PasswordMaxLength;
								password.Encrypted = true;
								//SECURITY - finding C-02 (Critical), CWE-200 exposure of sensitive information
								//to an unauthorized actor, CWE-522 insufficiently protected credentials, OWASP
								//A01:2021 Broken Access Control + A02:2021 Cryptographic Failures.
								//THREAT: this field holds the stored credential, and provisioning assigned it NO
								//field permissions at all. The only thing that ever restricted it was the
								//presentation layer - Web/Components/PcFieldBase/PcFieldBase.cs - which the
								//mandated Authorization Enforcement standard rules out explicitly: authorization
								//must be validated "on every request, not just in the UI". Any caller reaching
								//the field through a route that does not render through that component was
								//unconstrained.
								//THE NON-OBVIOUS HALF, and the one thing that must never be dropped from this
								//block: PcFieldBase gates the ENTIRE field-permission evaluation behind
								//"if (entityField.EnableSecurity)", and InputField.EnableSecurity DEFAULTS TO
								//FALSE. Assigning Permissions without also setting EnableSecurity leaves the
								//permissions completely INERT - the field stays readable exactly as before, and
								//the fix silently does nothing. Both lines are load-bearing.
								//Administrator only, on purpose: no Regular and no Guest entry belongs in
								//either list, because no non-administrator has any legitimate need to read or
								//write another account's stored hash. Consequence, which is the remediation
								//working rather than a defect: the field now hides for non-administrators,
								//since the presentation layer treats an absent read grant as denial.
								//Shaped after the role.name field below, the only other seeded field in this
								//method that enables security.
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
							//SECURITY - finding C-05 (Critical), CWE-269 improper privilege management,
							//CWE-732 incorrect permission assignment for a critical resource, OWASP A01:2021
							//Broken Access Control.
							//THREAT: CREATE on the role entity was seeded for the Guest role, so an
							//unauthenticated caller could author a role. Combined with the guest CREATE grant
							//on the user entity that has just been removed above, that was a complete
							//privilege-escalation chain against the authorization model itself. Removed, per
							//the mandated Authorization Enforcement standard's deny-by-default clause.
							//DELIBERATELY NOT REMOVED: the guest READ grant on the next line but one. It is
							//how role names resolve for a caller who has not yet authenticated, and revoking
							//it is neither required by C-05 - which is scoped to the two CREATE grants - nor
							//safe under the preservation requirement. It is recorded as a residual rather than
							//fixed, in accordance with the Minimal Change Clause's guidelines 1, 3 and 8.
							roleEntity.RecordPermissions.CanCreate.Add(SystemIds.AdministratorRoleId);
							roleEntity.RecordPermissions.CanRead.Add(SystemIds.RegularRoleId);
							roleEntity.RecordPermissions.CanRead.Add(SystemIds.GuestRoleId);
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
							user["password"] = Guid.NewGuid().ToString();
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
							//SECURITY - finding C-01 (Critical), CWE-798 use of hard-coded credentials,
							//CWE-1392 use of default credentials, OWASP A07:2021 Identification and
							//Authentication Failures.
							//THREAT: this record is the platform's first administrator, and it used to be
							//provisioned with the literal password "erp" straight from this public source
							//tree. Every WebVella ERP installation therefore shipped with a publicly known
							//administrator credential at a publicly known address - a complete
							//authentication bypass to full administrative privilege, exploitable by anyone
							//who can reach /login, and requiring no vulnerability beyond reading this file.
							//INVARIANT: no password literal may ever be assigned here again. The value is
							//either supplied by the operator or generated from a cryptographically secure
							//random source; see ResolveInitialAdministratorPassword below. RecordManager
							//hashes it on write (PBKDF2-HMAC-SHA-256), so the plaintext resolved here is
							//never persisted.
							user["password"] = ResolveInitialAdministratorPassword();
							user["email"] = "erp@webvella.com";
							user["username"] = "administrator";
							user["created_on"] = new DateTime(2010, 10, 10);
							user["enabled"] = true;

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
									//entity.Weight = (decimal)100.0;
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
						//SECURITY - carries the C-01, C-02, C-05 and M-13 provisioning corrections made above
						//to installations that were ALREADY PROVISIONED by an earlier release.
						//WHY THIS BLOCK IS INDISPENSABLE: every correction above executes inside
						//"if (currentVersion < 1)", so it runs once, at first provisioning, and never again.
						//A source-only fix therefore protects new installations and NOTHING ELSE - the
						//deployed estate keeps the published default administrator password, keeps the
						//anonymous create and read grants, and keeps an unprotected credential column, while
						//the source tree reads as though all of it were remediated. That gap is the single
						//highest-leverage item in this remediation, and this block is what closes it.
						//It sits inside the existing transaction and BEFORE the settings Save below, so a
						//failure anywhere inside it rolls the whole migration back at the catch and the
						//version is not advanced - the migration is then retried on the next startup.
						//DATA ONLY: it changes rows and metadata, never column or table definitions. No
						//schema definition statement is emitted at any point.
						MigrateSecurityDefaults4(entMan, recMan);
					}

					new DbSystemSettingsRepository(DbContext.Current).Save(new DbSystemSettings { Id = systemSettings.Id, Version = systemSettings.Version });

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					var exception = ex;
					connection.RollbackTransaction();
					throw;
				}

			}
		}

		#region <--- Initial administrator credential (finding C-01) --->

		/// <summary>
		/// Configuration key that lets an operator choose the first administrator's password up front.
		/// Supplied as the environment variable <c>Settings__InitialAdministratorPassword</c>, or through
		/// user secrets in development.
		/// </summary>
		private const string InitialAdministratorPasswordSettingKey = "Settings:InitialAdministratorPassword";

		/// <summary>
		/// Alphabet the generated credential is drawn from: upper case, lower case, digits and symbols, which
		/// is the complexity the engagement's authentication-hardening standard requires.
		/// </summary>
		/// <remarks>
		/// Visually ambiguous characters are excluded on purpose - no capital O or I, no lower-case l, no
		/// digit 0 or 1 - because this value is read off a console once and typed in by hand, and a
		/// transcription failure would push an operator towards choosing a weak password instead.
		/// </remarks>
		private const string InitialAdministratorPasswordAlphabet =
			"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%*+-=?@";

		/// <summary>
		/// The four character classes the mandated Authentication Hardening standard names - upper case,
		/// lower case, digits and symbols - as disjoint slices of
		/// <see cref="InitialAdministratorPasswordAlphabet"/>. Concatenated they reproduce that alphabet
		/// exactly, which is what keeps the two constants from drifting apart.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding C-01. These exist so that class coverage is GUARANTEED rather than merely
		/// likely: see <see cref="GenerateInitialAdministratorPassword"/> for why that distinction matters.
		/// </remarks>
		private static readonly string[] InitialAdministratorPasswordCharacterClasses = new[]
		{
			"ABCDEFGHJKLMNPQRSTUVWXYZ",
			"abcdefghijkmnopqrstuvwxyz",
			"23456789",
			"!#%*+-=?@"
		};

		/// <summary>
		/// Length of the generated credential. Well above the twelve-character floor the
		/// authentication-hardening standard sets, and drawn from a 65-character alphabet, so the value
		/// carries roughly 120 bits of entropy - far beyond offline-guessing range even though it is only
		/// ever meant to survive until the operator's first sign-in. The class-coverage constraint applied
		/// by <see cref="GenerateInitialAdministratorPassword"/> costs a fraction of one bit of that.
		/// </summary>
		private const int InitialAdministratorPasswordLength = 20;

		/// <summary>
		/// Resolves the password for the first administrator account created during system provisioning.
		/// </summary>
		/// <returns>
		/// The operator-supplied value when one was configured; otherwise a freshly generated
		/// cryptographically random password, which is reported once on the standard error stream.
		/// </returns>
		/// <remarks>
		/// SECURITY - finding C-01 (Critical), CWE-798 use of hard-coded credentials, CWE-1392 use of default
		/// credentials, OWASP A07:2021 Identification and Authentication Failures.
		/// THREAT: the literal password this replaces shipped in the public source tree, so every
		/// installation that had not changed it could be signed into as administrator by anybody. Seeding a
		/// fixed value is what made the compromise universal; seeding a per-installation value is what ends
		/// it.
		/// <para>
		/// Two supply routes, in this order, and no third:
		/// </para>
		/// <list type="number">
		/// <item><description>
		/// the operator's own value from <see cref="InitialAdministratorPasswordSettingKey"/>. Preferred,
		/// because nothing then has to be transcribed off a console, and the value never appears in any
		/// output stream at all.
		/// </description></item>
		/// <item><description>
		/// a cryptographically random password, reported ONCE while it is still recoverable. Provisioning
		/// runs exactly once per database, and <c>RecordManager</c> hashes the value on write, so a
		/// generated password that was never displayed would leave the account permanently unreachable -
		/// which is why this is reported rather than silently discarded, as the system account's random
		/// password legitimately is.
		/// </description></item>
		/// </list>
		/// <para>
		/// The report goes to standard error rather than through <c>LogService</c>, deliberately and for two
		/// independent reasons. Logging is not usable at this point - it persists through the very database
		/// connection this provisioning transaction is still building - and a credential written to the log
		/// table would then be readable by every account holding log access, turning a one-time console
		/// notice into durable stored plaintext (CWE-532).
		/// </para>
		/// <para>
		/// RESIDUAL, recorded rather than glossed over: the engagement's plan also asks for a
		/// change-required-on-first-login marker. There is no such field on the user entity, and adding one
		/// would be a schema definition change, which the same plan forbids outright. The obligation is
		/// therefore discharged the only way it can be without that change - the credential is unique per
		/// installation, and the notice below instructs the operator to replace it immediately. The residual
		/// is documented in docs/security/risk-register.md.
		/// </para>
		/// </remarks>
		private static string ResolveInitialAdministratorPassword()
		{
			// ErpSettings.Initialize always runs before provisioning - the hosts call it from UseErp, and the
			// console application from its own startup - so Configuration is populated here. The null-condition
			// operator is nevertheless kept so a future caller that provisions without initialising settings
			// gets a generated credential rather than a NullReferenceException in the middle of a transaction.
			string configuredPassword = ErpSettings.Configuration?[InitialAdministratorPasswordSettingKey];
			if (!string.IsNullOrWhiteSpace(configuredPassword))
			{
				// Reported so the operator can tell the two routes apart in the provisioning output. Only the
				// setting NAME appears - never the value, its length or a digest of it (CWE-532).
				Console.Error.WriteLine("info: WebVella.Erp.ErpService[1] The first administrator password was taken from " +
					"'" + InitialAdministratorPasswordSettingKey + "'. It is not echoed here.");
				return configuredPassword;
			}

			string generatedPassword = GenerateInitialAdministratorPassword();

			// The one and only place this value is ever emitted. It is unavoidable: the hash is one-way, so a
			// credential that is never shown is a locked-out installation.
			Console.Error.WriteLine("warn: WebVella.Erp.ErpService[2] SECURITY - no '" + InitialAdministratorPasswordSettingKey +
				"' was supplied, so a random password was generated for the first administrator account " +
				"(erp@webvella.com). It is shown ONCE, here, and cannot be recovered afterwards:" +
				Environment.NewLine + "    " + generatedPassword + Environment.NewLine +
				"Sign in with it and change it immediately, then remove it from any terminal scrollback or " +
				"captured log. Supplying '" + InitialAdministratorPasswordSettingKey + "' instead avoids " +
				"printing a credential at all. See docs/security/credential-migration.md.");

			return generatedPassword;
		}

		/// <summary>
		/// Generates the random initial administrator password.
		/// </summary>
		/// <remarks>
		/// SECURITY (C-01, and the engagement's cryptographic standard "CSPRNG"): every character comes from
		/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, never from
		/// <c>System.Random</c>, whose output is predictable from its seed and would make the generated
		/// credential guessable - reintroducing the finding in a form that merely looks random.
		/// <c>GetItems</c> is used rather than a hand-rolled modulo over random bytes because a modulo of a
		/// byte by a 65-character alphabet is measurably biased towards the alphabet's first characters;
		/// this overload draws uniformly.
		/// <para>
		/// CLASS COVERAGE IS GUARANTEED, NOT ASSUMED. The mandated Authentication Hardening standard
		/// requires "12+ characters, mixed case, numbers, symbols". A uniform draw over the whole alphabet
		/// satisfies the length clause with certainty but the composition clauses only on average: with
		/// eight digits and nine symbols in a 65-character alphabet, roughly one generated value in
		/// fourteen would contain no digit and one in twenty no symbol. One character is therefore drawn
		/// from each of the four classes first, the remainder is drawn from the full alphabet, and the
		/// whole buffer is then shuffled with the same cryptographic generator - so no class can be absent
		/// and no class occupies a predictable position. Shuffling is the load-bearing half: without it the
		/// first four characters would be positionally determined by class, which is a structure an
		/// attacker could exploit to prune a search space.
		/// </para>
		/// <para>
		/// The entropy cost of the constraint is negligible - it excludes only the roughly one eighth of
		/// the space that omits a class, so the value still carries well over 115 bits, far beyond
		/// offline-guessing range - and it is paid once, for a credential that is meant to survive only
		/// until the operator's first sign-in.
		/// </para>
		/// </remarks>
		private static string GenerateInitialAdministratorPassword()
		{
			char[] buffer = new char[InitialAdministratorPasswordLength];

			// One character per mandated class, so composition is a property of the construction rather
			// than an outcome of chance. The length constant is well above the class count, so this can
			// never overrun the buffer; a shorter length would be a policy violation caught by the
			// twelve-character floor long before it reached here.
			for (int index = 0; index < InitialAdministratorPasswordCharacterClasses.Length; index++)
			{
				buffer[index] = RandomNumberGenerator.GetItems<char>(
					InitialAdministratorPasswordCharacterClasses[index].AsSpan(), 1)[0];
			}

			// The balance is drawn uniformly from the whole alphabet, which is where essentially all of the
			// entropy comes from.
			RandomNumberGenerator.GetItems<char>(
				InitialAdministratorPasswordAlphabet.AsSpan(),
				buffer.AsSpan(InitialAdministratorPasswordCharacterClasses.Length));

			// Removes the positional structure the seeding step introduced. RandomNumberGenerator.Shuffle
			// is a Fisher-Yates shuffle driven by the same CSPRNG, so the permutation is unpredictable -
			// using a non-cryptographic shuffle here would hand back exactly the bias this call removes.
			RandomNumberGenerator.Shuffle(buffer.AsSpan());

			return new string(buffer);
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

		/// <summary>
		/// Carries the version 1 provisioning corrections for findings C-01, C-02, C-05 and M-13 to an
		/// installation that was already provisioned by an earlier release.
		/// </summary>
		/// <param name="entMan">
		/// The entity manager already in use by <see cref="InitializeSystemEntities"/>. Passed in rather
		/// than constructed here so that this migration participates in the same ambient database context
		/// and transaction as every other block in that method - constructing a fresh manager would be
		/// harmless today but would invite a later edit that opened its own connection and silently escaped
		/// the rollback.
		/// </param>
		/// <param name="recMan">
		/// The record manager already in use by <see cref="InitializeSystemEntities"/>. It was constructed
		/// with password-field encryption enabled, which is what routes the replacement credential through
		/// the current hashing primitive rather than storing it in the clear.
		/// </param>
		/// <remarks>
		/// SECURITY - the version-gated half of four findings whose provisioning half is in
		/// <see cref="InitializeSystemEntities"/>:
		/// <list type="bullet">
		/// <item><description>
		/// C-01 (Critical, CWE-798 use of hard-coded credentials, CWE-1392 use of default credentials,
		/// OWASP A07:2021) - the shipped default administrator credential is revoked.
		/// </description></item>
		/// <item><description>
		/// C-02 (Critical, CWE-200, CWE-522, OWASP A01:2021 + A02:2021) - the anonymous read grant on the
		/// user entity is revoked and the password field is given administrator-only field permissions,
		/// which earlier releases never assigned at all.
		/// </description></item>
		/// <item><description>
		/// C-05 (Critical, CWE-269, CWE-732, OWASP A01:2021) - the anonymous create grants on the user and
		/// role entities are revoked.
		/// </description></item>
		/// <item><description>
		/// M-13 (CWE-521) - the password length bounds are raised from 6-24 to 12-128.
		/// </description></item>
		/// </list>
		/// <para>
		/// FOUR PROPERTIES THIS METHOD MUST KEEP, each of which a later edit could quietly break:
		/// </para>
		/// <para>
		/// 1. IDEMPOTENT. Every step is a no-op when its target is already correct - grant removal by
		/// <c>List.RemoveAll</c> is a no-op when the value is absent, the metadata writes are assignments
		/// to fixed values, and the credential step is gated on the stored hash still having the legacy
		/// shape, which it cannot have after the first successful run. Re-running provisioning against an
		/// already-migrated database therefore changes nothing.
		/// </para>
		/// <para>
		/// 2. FAILS LOUDLY. Every step throws on failure and nothing here catches. That is deliberate: the
		/// caller's transaction is what makes this migration atomic, so swallowing an error would advance
		/// the stored schema version past work that did not actually happen - leaving an installation
		/// permanently unmigrated with no signal that it needs to be.
		/// </para>
		/// <para>
		/// 3. TOUCHES ONLY ONE CREDENTIAL. Ordinary user passwords are NOT reset. They keep working and are
		/// re-hashed individually on their owner's next sign-in by the upgrade path in
		/// <c>Api/SecurityManager.cs</c> - no forced reset, no downtime, nobody locked out. The single
		/// credential written here is the published default one, and only while it is still in place.
		/// </para>
		/// <para>
		/// 4. EMITS NO SCHEMA DEFINITION STATEMENT. It changes rows and entity metadata through the manager
		/// APIs and never composes SQL. The password column is already <c>varchar(500)</c>, and the length
		/// bounds raised here are field metadata that the column width does not depend on, so no column is
		/// altered, added or dropped. Unlike the two sitemap migrations above, this method deliberately
		/// opens no connection and issues no command text.
		/// </para>
		/// </remarks>
		private void MigrateSecurityDefaults4(EntityManager entMan, RecordManager recMan)
		{
			// The metadata writes below require administrator meta permission, and the entity read used to
			// resolve the stored credential requires a security context to exist at all. Both hosts that
			// reach this code already provide one - Web/ErpMvcExtensions.cs wraps the whole of UseErp in a
			// system scope, and the console application wraps its Main - so this scope is nested and changes
			// nothing about the effective principal, which is already the system user. It is opened anyway
			// because a security migration must not be defeasible by a caller that forgot to establish a
			// context: without it, EntityManager would return "no permissions to manipulate erp meta", this
			// method would throw, and an upgrade would fail rather than silently skip - loud, but avoidable.
			using (SecurityContext.OpenSystemScope())
			{
				RevokeSeedAdministratorCredential4(recMan);
				RevokeGuestRecordPermissions4(entMan);
				SecurePasswordFieldMetadata4(entMan);
			}
		}

		/// <summary>
		/// Revokes the administrator credential that earlier releases shipped, if and only if it is still
		/// in place.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding C-01 (Critical), CWE-798 use of hard-coded credentials, CWE-1392 use of
		/// default credentials, OWASP A07:2021 Identification and Authentication Failures.
		/// THREAT: every installation provisioned by an earlier release holds an administrator account at a
		/// published address whose password is published in this repository's own history. That is an
		/// authentication bypass to full administrative privilege requiring no vulnerability at all, and
		/// correcting the provisioning code does not touch it, because provisioning has already run.
		/// <para>
		/// HOW THE STORED VALUE IS READ, and why not through the obvious route: the record projections in
		/// <c>Api/RecordManager.cs</c> and <c>Database/DbRecordRepository.cs</c> now replace every encrypted
		/// password value with a redaction marker for every role, so reading this account through
		/// <c>RecordManager.Find</c> would return the marker rather than the hash and the comparison below
		/// would never match - the migration would silently do nothing. <c>SecurityManager.GetUser(Guid)</c>
		/// resolves through the query-language path, which is deliberately exempt from that redaction
		/// because credential verification depends on the real value. Keying on the account id rather than
		/// on the seeded e-mail address is also deliberate: an operator may have changed the address, and
		/// the account that has to be secured is the row, not the label.
		/// </para>
		/// <para>
		/// HOW THE GUARD WORKS: the stored value is only replaced when it still has the legacy digest shape
		/// AND verifies against the published default. Legacy verification lives in
		/// <c>Utilities/PasswordUtil</c> and is reused here rather than recomputed, so this method contains
		/// no cryptographic primitive of its own and cannot drift from the platform's. Both halves of the
		/// test are kept: the shape test rejects a modern value before it reaches a legacy comparison, and
		/// the verification test is what distinguishes the published default from any other password an
		/// operator happened to set while an earlier release was in use. An operator who has already chosen
		/// their own password is therefore never disrupted, which is what the preservation requirement
		/// demands.
		/// </para>
		/// <para>
		/// RESIDUAL, recorded rather than glossed over: the replacement is not accompanied by a
		/// change-required-on-first-login marker. No field on the user entity can carry one - and, more to
		/// the point, nothing in the platform reads such a marker, so setting one would enforce nothing -
		/// while adding a field would be the schema definition change the constraints forbid. The
		/// obligation is discharged the only way it can be without that change: the replacement is unique
		/// per installation, and the notice below instructs the operator to replace it at once. Tracked as
		/// RISK-027 in docs/security/risk-register.md.
		/// </para>
		/// </remarks>
		private void RevokeSeedAdministratorCredential4(RecordManager recMan)
		{
			ErpUser seedAdministrator = new SecurityManager().GetUser(SystemIds.FirstUserId);

			// An installation whose seeded administrator row was removed or renumbered has nothing to
			// revoke. Absent is not an error - it is simply not this migration's business.
			if (seedAdministrator == null)
			{
				return;
			}

			string storedHash = seedAdministrator.Password;

			// THE GUARD. Anything other than the published default - a modern hash, a legacy hash of a
			// password the operator chose, an empty or absent column - is left exactly as it is.
			//
			// The literal below is a REVOCATION TARGET, NOT A CREDENTIAL. It is the administrator password
			// that releases before this remediation seeded into every installation, and it appears here at
			// its single point of use for one reason only: it is the operand that distinguishes "this
			// deployment still carries the published default" from "an operator has already chosen their
			// own password". Nothing assigns it to anything, and no code path can provision it.
			//
			// Comparing against it is precisely what makes this revocation SAFE rather than destructive.
			// Invalidating the administrator credential unconditionally would overwrite a password an
			// operator had already set, which the preservation requirement forbids outright - so the guard
			// is not defensive tidiness, it is the difference between a security fix and data loss.
			//
			// It carries no confidentiality to protect: it is in this repository's public commit history,
			// in the platform's own published setup instructions, and in docs/security/security-audit-report.md
			// as finding C-01. Its presence here strictly LOWERS risk, because this comparison is the
			// mechanism by which the value stops working.
			//
			// Verification is delegated to PasswordUtil rather than recomputed, so this file contains no
			// cryptographic primitive of its own and cannot drift from the platform's. Both halves of the
			// test are load-bearing: the shape test rejects a modern hash before it ever reaches a legacy
			// comparison, and both members fail closed on a null, empty or malformed stored value, so a
			// corrupt column makes this a no-op instead of a startup failure.
			if (!PasswordUtil.IsLegacyHash(storedHash)
				|| !PasswordUtil.VerifyMd5Hash("erp", storedHash))
			{
				return;
			}

			// Deliberately the same generator as fresh provisioning: cryptographically random, and long
			// enough to sit inside BOTH the 6-24 bounds this installation still has at this instant and the
			// 12-128 bounds SecurePasswordFieldMetadata4 is about to set. That is why this step runs first
			// and why it cannot be invalidated by the order of the two - a value that satisfied only the new
			// bounds would be a latent ordering bug.
			string replacementPassword = GenerateInitialAdministratorPassword();

			EntityRecord administratorRecord = new EntityRecord();
			administratorRecord["id"] = SystemIds.FirstUserId;
			// Plaintext on purpose. RecordManager's encrypted-password branch hashes this on write with the
			// current primitive, exactly as it does for provisioning, so the value is never persisted as
			// supplied. Pre-hashing here would store a hash of a hash and lock the account out.
			administratorRecord["password"] = replacementPassword;

			QueryResponse result = recMan.UpdateRecord("user", administratorRecord);
			if (!result.Success)
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: user. The administrator credential shipped by earlier releases could not be revoked. Message:" + result.Message);

			// Reported once, on the standard error stream, for the same reason provisioning reports its
			// generated credential: the stored value is a one-way hash, so a replacement that is never
			// shown is an administrator account nobody can reach. It is deliberately NOT written through
			// LogService - that would persist a live credential into a database table readable by every
			// account with log access (CWE-532), turning a transient notice into stored plaintext.
			Console.Error.WriteLine("warn: WebVella.Erp.ErpService[3] SECURITY - this installation's administrator account " +
				"(" + SystemIds.FirstUserId + ") still carried the default password published in earlier releases, so it has " +
				"been revoked. A random replacement was generated and is shown ONCE, here, and cannot be recovered " +
				"afterwards:" + Environment.NewLine + "    " + replacementPassword + Environment.NewLine +
				"Sign in with it and change it immediately, then remove it from any terminal scrollback or captured log. " +
				"No other account's password was changed. See docs/security/credential-migration.md.");
		}

		/// <summary>
		/// Revokes the over-permissive Guest-role record permissions that earlier releases seeded onto the
		/// user and role entities.
		/// </summary>
		/// <remarks>
		/// SECURITY - findings C-05 (Critical, CWE-269 improper privilege management, CWE-732 incorrect
		/// permission assignment for a critical resource) and C-02 (Critical, CWE-200, CWE-522), OWASP
		/// A01:2021 Broken Access Control.
		/// THREAT: the Guest role is the role an unauthenticated caller is evaluated against - see
		/// <c>SecurityContext.HasEntityPermission</c>, which falls back to the Guest grants exactly when no
		/// user is resolved. Earlier releases granted it create on the user entity, read on the user entity
		/// and create on the role entity, so an anonymous caller could enumerate every account and author
		/// both users and roles. Removing the grants from provisioning protects new installations only;
		/// this is what protects the ones already running.
		/// <para>
		/// The role entity's Guest READ grant is deliberately preserved, mirroring the provisioning
		/// decision: it is how role names resolve before authentication, C-05 is scoped to the two create
		/// grants, and revoking it is neither required nor safe under the preservation requirement.
		/// </para>
		/// <para>
		/// <c>EntityManager.UpdateEntity</c> copies only the entity's own scalars and its four permission
		/// lists onto the stored definition and leaves the field collection untouched, so this cannot
		/// disturb field metadata. Every carried-over value is read back from the stored entity rather than
		/// restated as a literal, so an installation whose label, icon or colour was customised keeps it.
		/// </para>
		/// </remarks>
		private void RevokeGuestRecordPermissions4(EntityManager entMan)
		{
			// The user entity: revoke anonymous create AND anonymous read. The Regular read grant survives,
			// because removing it would break every screen that resolves the signed-in user's own name and
			// avatar; the credential itself is protected by SecurePasswordFieldMetadata4 and by the
			// read-projection redaction instead.
			RevokeGuestRecordPermissions4(entMan, SystemIds.UserEntityId, "user", true);

			// The role entity: revoke anonymous create only.
			RevokeGuestRecordPermissions4(entMan, SystemIds.RoleEntityId, "role", false);
		}

		/// <summary>
		/// Removes the Guest role from one entity's create permissions, and optionally from its read
		/// permissions, without altering anything else about that entity.
		/// </summary>
		/// <param name="entMan">The entity manager participating in the migration transaction.</param>
		/// <param name="entityId">Identifier of the entity whose record permissions are being narrowed.</param>
		/// <param name="entityName">Entity name, used only to make a failure message diagnostic.</param>
		/// <param name="revokeRead">
		/// True to also remove the Guest role from the read permissions. False for the role entity, whose
		/// anonymous read grant is preserved by design.
		/// </param>
		/// <remarks>
		/// SECURITY - findings C-05 and C-02; see
		/// <see cref="RevokeGuestRecordPermissions4(EntityManager)"/> for the threat.
		/// The permission lists are rebuilt as fresh copies of the stored ones rather than mutated in
		/// place, because <c>EntityManager.ReadEntity</c> serves entities from a process-wide metadata
		/// cache - mutating the lists it hands back would edit that cache directly, so a later failure and
		/// rollback would leave the in-memory model disagreeing with the database until the next cache
		/// clear. <c>RemoveAll</c> is used rather than <c>Remove</c> so that a duplicated grant, which the
		/// permission model does not prevent, cannot leave one copy behind; it also makes the operation a
		/// no-op when the grant is already absent, which is what makes re-running this migration harmless.
		/// </remarks>
		private void RevokeGuestRecordPermissions4(EntityManager entMan, Guid entityId, string entityName, bool revokeRead)
		{
			Entity storedEntity = entMan.ReadEntity(entityId).Object;
			if (storedEntity == null)
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: " + entityName + ". The entity could not be read, so its anonymous record permissions could not be revoked.");

			// Entity.RecordPermissions carries no property initialiser, unlike the four lists inside it, so
			// a definition written by an older release or edited by hand can present it as absent. Reading
			// that as "no grants recorded" is both the correct interpretation - an entity with no recorded
			// permissions grants nothing, so there is nothing here to revoke - and what stops an upgrade
			// aborting on a NullReferenceException. A security migration that crashes leaves the very
			// grants it exists to remove in place, so the defensive read is the security-relevant behaviour.
			RecordPermissions storedPermissions = storedEntity.RecordPermissions ?? new RecordPermissions();

			// Copied rather than mutated in place: ReadEntity serves entities from a process-wide metadata
			// cache, so editing the lists it returns would write straight into that cache and leave the
			// in-memory model disagreeing with the database if the transaction later rolled back.
			List<Guid> canCreate = new List<Guid>(storedPermissions.CanCreate);
			List<Guid> canRead = new List<Guid>(storedPermissions.CanRead);
			List<Guid> canUpdate = new List<Guid>(storedPermissions.CanUpdate);
			List<Guid> canDelete = new List<Guid>(storedPermissions.CanDelete);

			canCreate.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);
			if (revokeRead)
				canRead.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);

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
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: " + entityName + ". The anonymous record permissions could not be revoked. Message:" + response.Message);
		}

		/// <summary>
		/// Turns on field-level security for the user entity's password field, restricts it to
		/// administrators, and raises its length bounds.
		/// </summary>
		/// <remarks>
		/// SECURITY - findings C-02 (Critical, CWE-200 exposure of sensitive information to an unauthorized
		/// actor, CWE-522 insufficiently protected credentials, OWASP A01:2021 + A02:2021) and M-13
		/// (CWE-521 weak password requirements).
		/// THREAT: earlier releases provisioned this field with NO field permissions whatsoever, so the only
		/// thing that ever restricted the stored credential was the presentation layer - which the mandated
		/// Authorization Enforcement standard rules out explicitly, because authorization must be validated
		/// on every request and not just in the UI.
		/// <para>
		/// <c>EnableSecurity</c> is the load-bearing line and the easiest thing here to lose in a later
		/// edit: <c>Web/Components/PcFieldBase/PcFieldBase.cs</c> gates the whole field-permission
		/// evaluation behind it, and it defaults to false, so assigning permissions without it leaves them
		/// completely inert and the field readable exactly as before.
		/// </para>
		/// <para>
		/// Every other property is carried over from the field as it is currently stored rather than
		/// restated as a literal, because <c>EntityManager.UpdateField</c> REPLACES the whole field
		/// definition - anything not supplied would be silently reset, so an installation that had
		/// customised the label or help text would lose it. The field is located by NAME rather than by the
		/// identifier provisioning uses, so an installation whose field was recreated under a different
		/// identifier is still migrated.
		/// </para>
		/// <para>
		/// NO SCHEMA DEFINITION CHANGE RESULTS. The bounds are field metadata; the column is
		/// <c>varchar(500)</c> and its width does not derive from them. The update path re-asserts the
		/// column's existing nullability and default and drops a search index the field never had, all of
		/// which are no-ops against the definition this platform already provisions.
		/// </para>
		/// </remarks>
		private void SecurePasswordFieldMetadata4(EntityManager entMan)
		{
			Entity userEntity = entMan.ReadEntity(SystemIds.UserEntityId).Object;
			if (userEntity == null)
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: user. The entity could not be read, so the password field could not be secured.");

			// Located by NAME rather than by the identifier provisioning uses, so an installation whose
			// field was recreated under a different identifier is still migrated. Entity.Fields carries no
			// property initialiser, so the null-conditional is load-bearing: without it an entity read that
			// returned no field collection would abort the upgrade on a NullReferenceException instead of
			// reaching the diagnostic below.
			PasswordField storedPasswordField = userEntity.Fields?
				.SingleOrDefault(field => field.Name == "password") as PasswordField;
			if (storedPasswordField == null)
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The field is missing or is not a password field, so it could not be secured.");

			InputPasswordField password = new InputPasswordField();
			password.Id = storedPasswordField.Id;
			password.Name = storedPasswordField.Name;
			password.Label = storedPasswordField.Label;
			password.PlaceholderText = storedPasswordField.PlaceholderText;
			password.Description = storedPasswordField.Description;
			password.HelpText = storedPasswordField.HelpText;
			password.Required = storedPasswordField.Required;
			password.Unique = storedPasswordField.Unique;
			password.Searchable = storedPasswordField.Searchable;
			password.Auditable = storedPasswordField.Auditable;
			password.System = storedPasswordField.System;
			password.Encrypted = storedPasswordField.Encrypted;
			//SECURITY - finding M-13, CWE-521. Raised from the 6-24 this installation was provisioned with.
			password.MinLength = PasswordMinLength;
			password.MaxLength = PasswordMaxLength;
			//SECURITY - finding C-02. EnableSecurity without Permissions denies everyone; Permissions
			//without EnableSecurity denies nobody. Both are required, and administrator only - no Regular
			//and no Guest entry belongs in either list.
			password.EnableSecurity = true;
			password.Permissions = new FieldPermissions();
			password.Permissions.CanRead = new List<Guid>();
			password.Permissions.CanUpdate = new List<Guid>();
			//READ
			password.Permissions.CanRead.Add(SystemIds.AdministratorRoleId);
			//UPDATE
			password.Permissions.CanUpdate.Add(SystemIds.AdministratorRoleId);

			FieldResponse response = entMan.UpdateField(SystemIds.UserEntityId, password);
			if (!response.Success)
				throw new Exception("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The field could not be secured. Message:" + response.Message);
		}

		#endregion
	}
}
