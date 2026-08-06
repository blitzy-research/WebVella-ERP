using System;
using System.Collections.Generic;
// SECURITY (finding C-01, CWE-521): supplies the invariant culture used when the first administrator
// password policy states its length bounds, so the message is identical on every host locale.
using System.Globalization;
using System.Linq;
// SECURITY (finding C-01, CWE-798/CWE-1392): supplies the cryptographically secure random source used
// to generate the initial administrator credential that replaced the shipped literal password.
using System.Security.Cryptography;
// SECURITY (finding C-01, CWE-1392): serialises the first-login rotation marker into the user entity's
// existing preferences column through the ErpUserPreferences model, so the persisted property name cannot
// drift from the type and no JSON literal is hand-written.
using Newtonsoft.Json;
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
		/// <para>
		/// Finding M-13: this now REFERENCES the bound the write path enforces rather than repeating
		/// its value. The two were equal by comment alone, and a policy that is advertised by metadata in
		/// one file and enforced by a literal in another is one edit away from disagreeing - the exact
		/// failure mode the finding describes, where the interface promised twelve characters and the
		/// write path accepted two.
		/// </para>
		/// </remarks>
		private const int PasswordMinLength = Utilities.PasswordUtil.MinPasswordLength;

		/// <summary>
		/// Maximum length provisioned onto the user entity's password field.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding M-13, CWE-521. The previous ceiling of 24 characters was itself an obstacle
		/// to a strong passphrase. This value equals the input bound enforced by
		/// <c>WebVella.Erp.Utilities.PasswordUtil</c>, so the policy advertised by the field metadata and
		/// the length the hashing primitive will actually accept are the same number and cannot drift into
		/// a state where the platform advertises a password it would then refuse to hash.
		/// Finding M-13: that equality is now expressed in code rather than asserted in prose.
		/// </remarks>
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

					//THREAT ADDRESSED (CWE-532, OWASP A09:2021): the one-time provisioning notices are held
					//back until this transaction actually commits, so the buffer starts empty for every
					//attempt. Clearing on entry rather than trusting it to be empty matters because the core
					//service is registered as a singleton: a first attempt that rolled back would otherwise
					//leave a stale notice queued and a later successful attempt would emit it, asserting
					//something about an installation state that was never persisted.
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
							//THREAT ADDRESSED - findings C-05 (Critical) and F17 (Authorization Residual),
							//CWE-269 improper privilege management, CWE-732 incorrect permission assignment for
							//a critical resource, CWE-200 exposure of sensitive information, OWASP A01:2021
							//Broken Access Control.
							//THREAT (C-05): CREATE on the role entity was seeded for the Guest role, so an
							//unauthenticated caller could author a role. Combined with the guest CREATE grant
							//on the user entity that has just been removed above, that was a complete
							//privilege-escalation chain against the authorization model itself.
							//THREAT (F17): READ on the role entity was seeded for the Guest role too. Guest is
							//the role an unauthenticated caller is evaluated against - SecurityContext's entity
							//permission check falls back to the Guest grants exactly when no user is resolved -
							//so that grant is anonymous enumeration of the platform's whole authorization
							//vocabulary: every role name and identifier, which is reconnaissance for the
							//privilege-escalation attempt above and for social engineering generally.
							//An earlier pass preserved that READ grant on the stated ground that it is "how
							//role names resolve for a caller who has not yet authenticated". That justification
							//does not survive inspection and is retracted here. Login-time role resolution runs
							//in a SYSTEM scope: SecurityManager.GetUser opens SecurityContext.OpenSystemScope
							//before projecting $user_role.*, so it never consults the Guest grants at all. Every
							//other reader of role metadata - SecurityManager.GetAllRoles and its SDK callers,
							//the role list page, the console application - is either authenticated,
							//administrator-facing or already inside a system scope. No [AllowAnonymous] endpoint
							//in the solution reads the role entity. The grant was therefore unnecessary, and an
							//unnecessary grant to the anonymous pseudo-role is precisely what the mandated
							//Authorization Enforcement standard's deny-by-default clause forbids.
							//Both Guest grants are consequently absent from this seed. The two tiers differ in
							//how far the remediation reaches, deliberately: C-05 is Critical, so
							//MigrateSecurityDefaults4 also revokes the CREATE grant on installations that were
							//already provisioned by an earlier release, whereas F17 sits in the tier the
							//engagement documents with fix guidance rather than migrates. No version gate
							//therefore touches the READ grant on an existing installation; that residual is
							//recorded in docs/security/risk-register.md. Regular and Administrator keep READ,
							//so no authenticated screen loses anything.
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
							//SECURITY - finding F25, CWE-521 (weak password requirements), OWASP A07:2021.
							//This is the local system account, which exists only so background work has an
							//identity; nobody is ever meant to authenticate as it, and the value was a random
							//GUID string purely to make that impossible in practice. A GUID string is however
							//all lower case, so it does not satisfy the mixed-case rule that
							//PasswordUtil.ValidatePasswordPolicy now enforces at the record-write boundary -
							//provisioning would fail on this very line. The generator used for the first
							//administrator is reused instead: it draws from the operating system CSPRNG, is
							//guaranteed to satisfy every rule, and carries at least as much entropy as the
							//122 random bits of a version-4 GUID. The value is hashed on write and is never
							//printed, stored in plaintext or returned to anyone.
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
							//supplied by the operator through 'Settings:InitialAdministratorPassword' and from
							//no other source - see ResolveInitialAdministratorPassword below, and review
							//finding OBS-01 for why the platform no longer generates one. RecordManager
							//hashes it on write (PBKDF2-HMAC-SHA-256), so the plaintext resolved here is
							//never persisted.
							user["password"] = ResolveInitialAdministratorPassword();
							user["email"] = "erp@webvella.com";
							user["username"] = "administrator";
							user["created_on"] = new DateTime(2010, 10, 10);
							user["enabled"] = true;
							//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): this credential reaches the
							//account through a deployment setting rather than being chosen at a keyboard by the
							//person who will use it - so it lives in an environment variable, a container
							//manifest or a CI variable, all of which are multi-reader stores - so it is marked
							//as owing a rotation. AuthService refuses to mint or refresh a bearer token while
							//the marker stands, which keeps a credential nobody selected out of automation;
							//interactive sign-in stays available because it is the only route to the screen that
							//clears the marker by actually setting a password. Serialised through the model
							//rather than as a JSON literal so the property name cannot drift from the type, and
							//written here rather than left to the field default so provisioning never produces
							//an unmarked bootstrap account.
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
						//WHY THIS BLOCK IS INDISPENSABLE: every correction above runs inside the currentVersion < 1
						//gate, so it executes once, at first provisioning, and never again. A source-only fix therefore
						//protects new installations and NOTHING ELSE: the deployed estate keeps the published default
						//administrator password, the anonymous create and read grants and an unprotected credential
						//column, while the source reads as though all of it were remediated.
						//It sits inside the existing transaction and BEFORE the settings Save below, so any failure
						//rolls the whole migration back at the catch without advancing the version, and it is retried
						//on the next startup. DATA AND METADATA ONLY - rows and entity definitions, never column or
						//table definitions, and no schema definition statement at any point. That is a property of HOW
						//it writes: SecurePasswordFieldMetadata4 deliberately bypasses EntityManager.UpdateField,
						//because that method issues ALTER TABLE ... ALTER COLUMN and CREATE/DROP INDEX before storing
						//the metadata. Anything added here must go through the repositories directly for that reason.
						MigrateSecurityDefaults4(entMan, recMan);
					}

					new DbSystemSettingsRepository(DbContext.Current).Save(new DbSystemSettings { Id = systemSettings.Id, Version = systemSettings.Version });

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					var exception = ex;
					connection.RollbackTransaction();
					//Nothing was persisted, so nothing is announced. Discarding rather than leaving the
					//buffer intact is what stops a notice describing a rolled-back installation from being
					//emitted by a later call on this singleton.
					pendingProvisioningNotices.Clear();
					throw;
				}

				//THREAT ADDRESSED - review finding OBS-01 / CWE-532 (insertion of sensitive information into
				//a log) compounded by CWE-460 (improper cleanup on a thrown exception), OWASP A09:2021.
				//
				//TWO PROPERTIES, AND BOTH ARE LOAD-BEARING.
				//
				//FIRST, WHAT IS EMITTED. Nothing queued here carries a credential, a credential length or a
				//digest of one - see pendingProvisioningNotices. The notices name the SETTING an operator
				//supplied a value through and state what the provisioning transaction did with it, which is
				//information the operator already holds. An earlier revision queued the plaintext
				//administrator password itself so it could be read back off a console, and no placement of
				//that write could have made it safe: standard error is captured and retained wholesale by
				//systemd's journal, the Docker log driver, IIS stdout redirection, Kubernetes container logs
				//and CI transcripts, so a notice described as one-time was in fact durable plaintext readable
				//by everyone holding log or host access. The credential is not printed anywhere because the
				//platform no longer holds one it has to disclose: ResolveInitialAdministratorPassword requires
				//the operator's own value and generates nothing.
				//
				//SECOND, WHERE IT IS EMITTED. OUTSIDE the try/catch, not inside it. Flushing after
				//CommitTransaction but still within the try meant that a failure in the output stream itself -
				//a closed, full or redirected standard error - was caught by the clause above, which then
				//called RollbackTransaction on a transaction that had ALREADY COMMITTED DURABLY. The
				//provisioning result was therefore reported as failed while the database retained every change
				//it had made, and the rollback attempt could raise a second exception that replaced the first.
				//Placed here the notices still describe only a committed outcome - the catch above rethrows, so
				//this line is unreachable on the failure path - while an output fault propagates as itself and
				//can no longer reach any transaction-control statement. A finally block would be wrong for the
				//same reason it was wrong before: it would also run on the rollback path, announcing an
				//installation state that was never persisted.
				FlushProvisioningNotices();
			}
		}

		#region <--- Initial administrator credential (finding C-01) --->

		/// <summary>
		/// One-time, credential-free provisioning notices withheld until the provisioning transaction has
		/// committed.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - review finding OBS-01 and finding C-01 / CWE-532 (insertion of sensitive
		/// information into a log), OWASP A09:2021.
		/// <para>
		/// THE INVARIANT THIS BUFFER EXISTS TO CARRY, and it is the whole point of the type: <b>no value
		/// added here may be, contain, measure or digest a credential.</b> Every notice names a configuration
		/// SETTING and states what provisioning did, which is information the operator supplied in the first
		/// place. An earlier revision queued the plaintext administrator password so it could be read back
		/// off a console, and that could not be made safe by any amount of care about WHEN it was written:
		/// standard error is captured and retained wholesale by systemd's journal, the Docker log driver, IIS
		/// stdout redirection, Kubernetes container logs and CI transcripts, so the "one-time" notice was
		/// durable plaintext readable by everyone holding log or host access. The platform no longer holds a
		/// credential it has to disclose - <see cref="ResolveInitialAdministratorPassword"/> requires the
		/// operator's own value and generates nothing - so there is nothing left to queue.
		/// </para>
		/// <para>
		/// Queuing rather than writing immediately is still required, for a different reason: a notice
		/// asserts something about the installation, and that assertion is only true once the transaction
		/// commits. Flushing after <c>CommitTransaction</c> returns is what ties every statement to the
		/// durable outcome, and the flush deliberately sits OUTSIDE the transaction's <c>catch</c> so that a
		/// failure in the output stream itself can never reach a transaction-control statement.
		/// </para>
		/// <para>
		/// A plain <see cref="List{T}"/> with no locking is correct here rather than merely convenient:
		/// every writer runs inside the single provisioning transaction on the thread that opened it, and
		/// the buffer is cleared on entry to that transaction and again on both exits, so no two threads can
		/// observe it in a partially written state.
		/// </para>
		/// </remarks>
		private readonly List<string> pendingProvisioningNotices = new List<string>();

		/// <summary>
		/// Writes every queued provisioning notice to standard error and empties the buffer.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding OBS-01, finding C-01. Standard error, never <c>LogService</c>, and that
		/// choice is load-bearing: the log writer persists through the very database connection this
		/// provisioning transaction is still building, so it is not usable at this point at all. The notices
		/// carry no credential material (see <see cref="pendingProvisioningNotices"/>), so standard error is
		/// an appropriate destination for them - which is precisely what it was not while they carried a
		/// password. The buffer is emptied as it is drained so a notice can never be emitted twice by a later
		/// call on this singleton.
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
		/// authentication-hardening standard sets, and drawn from a 66-character alphabet, so the value
		/// carries roughly 120 bits of entropy - far beyond offline-guessing range even though it is only
		/// ever meant to survive until the operator's first sign-in. The class-coverage constraint applied
		/// by <see cref="GenerateInitialAdministratorPassword"/> costs a fraction of one bit of that.
		/// </summary>
		private const int InitialAdministratorPasswordLength = 20;

		/// <summary>
		/// Resolves the password for the first administrator account created during system provisioning.
		/// </summary>
		/// <returns>
		/// The operator-supplied value from <see cref="InitialAdministratorPasswordSettingKey"/>. There is no
		/// other outcome: an absent or non-conforming value aborts provisioning.
		/// </returns>
		/// <remarks>
		/// SECURITY - finding C-01 (Critical), CWE-798 use of hard-coded credentials, CWE-1392 use of default
		/// credentials, OWASP A07:2021 Identification and Authentication Failures; and review finding OBS-01
		/// (Critical), CWE-532 insertion of sensitive information into a log, OWASP A09:2021.
		/// THREAT: the literal password this replaces shipped in the public source tree, so every
		/// installation that had not changed it could be signed into as administrator by anybody. Seeding a
		/// fixed value is what made the compromise universal; seeding a per-installation value is what ends
		/// it.
		/// <para>
		/// ONE SUPPLY ROUTE, AND IT IS REQUIRED: the operator's own value from
		/// <see cref="InitialAdministratorPasswordSettingKey"/>. Nothing is generated here, and no credential
		/// is written to standard error, standard output, the log table or an exception message.
		/// </para>
		/// <para>
		/// WHY THE GENERATOR ROUTE WAS REMOVED RATHER THAN HARDENED (review finding OBS-01). An earlier
		/// revision produced a cryptographically random password when the setting was absent and emitted it
		/// once on the standard error stream so the operator could read it back. The emission was itself a
		/// vulnerability, and no placement could fix it: any credential the platform invents must be
		/// communicated back to the operator, and every channel reachable from inside a provisioning
		/// transaction is a durable, multi-reader one. Standard error is captured and retained wholesale by
		/// systemd's journal, the Docker log driver, IIS stdout redirection, Kubernetes container logs and CI
		/// transcripts, so a "one-time" notice was in fact durable plaintext readable by everyone holding log
		/// or host access - a live administrator credential, at a published address, for as long as the log
		/// was kept. <c>LogService</c> would have been worse still: it persists into a database table any
		/// account with log access can read. Requiring the operator's own value is the only shape of this
		/// method that never holds a credential it has to disclose.
		/// </para>
		/// <para>
		/// THE COST IS STATED RATHER THAN HIDDEN: an installation that reaches provisioning with no value
		/// configured fails to start, loudly, naming the setting to supply. That is the intended behaviour -
		/// the alternatives are shipping a known default (the finding this replaces) or disclosing an invented
		/// one (the finding this closes). Provisioning runs once per database, so the requirement is paid once.
		/// </para>
		/// <para>
		/// The notice this method queues names only the SETTING, never the value, its length or a digest of
		/// it. It is QUEUED rather than written here - see <see cref="pendingProvisioningNotices"/> - because
		/// it asserts that the configured password is now the administrator's, which is only true once the
		/// transaction commits; on a rollback it would be a false statement about the installation.
		/// </para>
		/// <para>
		/// FIRST-LOGIN ROTATION IS ENFORCED, NOT MERELY REQUESTED: the change-required marker is set here
		/// through <see cref="ErpUserPreferences.PasswordChangeRequired"/>. It needs no schema change and
		/// none is made - the user entity already carries a <c>preferences</c> text column holding per-user
		/// JSON state, so the marker is simply a new property on a type that column already stores, and no
		/// data definition statement is emitted.
		/// </para>
		/// <para>
		/// The marker has teeth in two places and stays deliberately toothless in a third.
		/// <c>AuthService</c> refuses to mint or refresh a bearer token for an account still carrying it,
		/// which is what stops a credential the operator never chose from being wired into automation.
		/// The interactive login page records a warning audit entry on every sign-in that still uses it,
		/// so the condition is visible rather than silent. Interactive login itself stays OPEN on
		/// purpose - it is the only route to the screen that changes the password, so closing it would
		/// lock the operator out of the very action being demanded of them, converting a hardening
		/// measure into a denial of service against a brand-new installation.
		/// </para>
		/// </remarks>
		// Not static, deliberately: this queues its notice into the instance buffer that
		// FlushProvisioningNotices drains after the provisioning transaction commits (finding C-01, review
		// finding OBS-01, CWE-532). It is private and has a single caller, so narrowing it from static costs
		// nothing.
		private string ResolveInitialAdministratorPassword()
		{
			// ErpSettings.Initialize always runs before provisioning - the hosts call it from UseErp, and the
			// console application from its own startup - so Configuration is populated here. The null-condition
			// operator is nevertheless kept so a future caller that provisions without initialising settings
			// reaches the actionable failure below rather than a NullReferenceException in the middle of a
			// transaction.
			string configuredPassword = ErpSettings.Configuration?[InitialAdministratorPasswordSettingKey];

			// THREAT ADDRESSED - review finding OBS-01 (Critical), CWE-532, OWASP A09:2021. Absence is a
			// hard failure, not a fallback. The branch this replaces generated a credential and emitted it on
			// the standard error stream, which every hosting substrate captures and retains - so the
			// convenience of a self-provisioning installation was paid for with durable plaintext disclosure
			// of the account holding every administrative permission. There is deliberately no second route:
			// a method that never invents a credential is a method that never has to disclose one.
			if (string.IsNullOrWhiteSpace(configuredPassword))
			{
				throw new InvalidOperationException(MissingAdministratorPasswordMessage);
			}

			// THREAT ADDRESSED - finding C-01 (CWE-521 weak password requirements, CWE-1392 use of a
			// default credential), OWASP A07:2021. This value was previously accepted on the strength of
			// being non-blank alone, so the literal "erp" that this finding removed from the source could
			// be reinstated verbatim through configuration, and the twelve-character mixed-class floor the
			// mandated Authentication Hardening standard sets applied to nothing whatsoever. It is
			// validated BEFORE it is returned to be hashed, and a failure aborts provisioning rather than
			// silently substituting some other value: quietly ignoring an operator's explicit choice would
			// leave them believing a password they never saw is in force.
			ValidateInitialAdministratorPassword(configuredPassword, ConfiguredPasswordSourceDescription);

			// Only the setting NAME appears - never the value, its length or a digest of it (CWE-532).
			// Queued rather than printed (review finding OBS-01, finding C-01): this notice asserts that the
			// configured password is now the administrator's, which is only true once the transaction commits.
			// On a rollback it would be a false statement about the state of the installation.
			pendingProvisioningNotices.Add("info: WebVella.Erp.ErpService[1] The first administrator password was taken from " +
				"'" + InitialAdministratorPasswordSettingKey + "'. It is not echoed here.");

			return configuredPassword;
		}

		/// <summary>
		/// Failure message used by both credential paths - first provisioning and the schema version 4
		/// revocation - when no administrator password has been configured.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding OBS-01 (Critical), CWE-532, OWASP A09:2021. Held as one constant so the
		/// two paths cannot describe the same requirement differently, and worded to be actionable without
		/// describing any value: it names the setting, states the policy, and names the operator guide. It
		/// necessarily appears in a startup failure, which is a captured output stream, so it is written to be
		/// safe there - a message that quoted, measured or digested a credential would reintroduce the very
		/// disclosure this finding closes.
		/// </remarks>
		// static readonly rather than const, deliberately: the bounds are read from PasswordMinLength and
		// PasswordMaxLength, which derive from the PasswordUtil constants the write path actually enforces, so
		// the policy this message states cannot drift from the policy the platform applies. A const would have
		// forced the two numbers to be repeated as literals here - the exact defect finding M-13 records.
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
		/// Describes the generated credential route in a policy-failure message. Reaching this outcome means
		/// the generator itself no longer satisfies the policy, which is a defect in this file rather than an
		/// operator error, so the wording says so instead of asking the operator to change a setting.
		/// </summary>
		private const string GeneratedPasswordSourceDescription =
			"The value was generated internally, so this indicates a defect in the generator constants " +
			"rather than a configuration mistake.";

		/// <summary>
		/// Applies the mandated Authentication Hardening password policy - twelve to one hundred and
		/// twenty-eight characters, with an upper case letter, a lower case letter, a digit and a symbol all
		/// present - to a candidate first administrator password, and aborts provisioning when it is not met.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-01 (CWE-521 weak password requirements, CWE-1392 use of a default
		/// credential), OWASP A07:2021. Without this, the configured supply route accepted any non-blank
		/// string, so the default credential this remediation deleted from the source could be restored
		/// through configuration and the standard's complexity floor bound nothing.
		/// <para>
		/// THE UPPER BOUND IS A CORRECTNESS FIX, NOT SYMMETRY. <c>PasswordUtil.HashPassword</c> returns
		/// <see cref="string.Empty"/> for input longer than its own 128-character resource bound, and the
		/// password field's <c>MaxLength</c> metadata is not enforced on write, so an over-long configured
		/// value used to hash to nothing at all. That left the administrator account of a brand-new
		/// installation with a stored value no password can ever verify - unreachable, unrecoverable, and
		/// reported nowhere. Refusing the value here is what makes that outcome impossible; it is the reason
		/// the maximum is tested rather than assumed to be unreachable.
		/// </para>
		/// <para>
		/// THE MESSAGE NEVER DESCRIBES THE VALUE. It names the setting and restates the policy in full, but
		/// it does not echo the password, report its length, identify which clause failed, or emit a digest
		/// (CWE-532). Provisioning output is routinely captured into build logs, container logs and terminal
		/// scrollback, and "too short" together with a length is a substantial head start for anyone who
		/// later obtains the hash. The operator already knows what they supplied, so the policy text alone
		/// is enough to act on and the diagnostic value of naming the failed clause is close to zero.
		/// </para>
		/// <para>
		/// THE CLASS TESTS DELIBERATELY DO NOT REUSE
		/// <see cref="InitialAdministratorPasswordCharacterClasses"/>. That constant is pruned of visually
		/// ambiguous characters because a generated value has to be transcribed by hand, and its symbol slice
		/// lists only nine punctuation marks. Validating an operator's own password against it would reject
		/// strong passwords for containing a capital O or a dollar sign - a functional outage dressed up as
		/// hardening, and exactly the over-narrow allow-list this engagement has had to reverse elsewhere.
		/// The general character predicates used below are the correct reading of "mixed case, numbers,
		/// symbols", and every generator class is a subset of them, so the generated route satisfies this
		/// policy by construction rather than by coincidence.
		/// </para>
		/// </remarks>
		/// <param name="password">The candidate password. Never logged, echoed or measured in output.</param>
		/// <param name="sourceDescription">
		/// Which supply route produced the value, so the remedy offered matches the mistake made.
		/// </param>
		/// <exception cref="InvalidOperationException">
		/// The password does not satisfy the policy. Thrown rather than reported through a return value so
		/// the failure cannot be ignored by a caller: this runs inside the provisioning transaction, which is
		/// consequently abandoned, leaving no half-configured installation and - critically - no
		/// administrator account holding a credential that is weak or that nothing can verify.
		/// </exception>
		// DELIBERATELY STRICTER THAN PasswordUtil.ValidatePasswordPolicy - do not "simplify" this into a call
		// to that method. The platform-wide gate enforces LENGTH ONLY (non-blank, >= MinPasswordLength,
		// <= MaxPasswordLength); it accepts a twelve-character all-lowercase value. The mandated
		// Authentication Hardening standard requires mixed case, digits AND symbols, and this is the one
		// credential that standard must hold for unconditionally: the first full administrator on a new
		// installation, created before any operator can review policy. The BOUNDS below cannot drift from
		// the primitive because PasswordMinLength/PasswordMaxLength derive from the PasswordUtil constants;
		// the composition test is an additional provisioning-time constraint, not a duplicate of one.
		private static void ValidateInitialAdministratorPassword(string password, string sourceDescription)
		{
			// Size before content, matching the discipline PasswordUtil already applies: an oversized value is
			// refused on a single integer comparison instead of paying for a full character scan first.
			bool lengthWithinPolicy = password.Length >= PasswordMinLength
				&& password.Length <= PasswordMaxLength;

			bool hasUpperCase = false;
			bool hasLowerCase = false;
			bool hasDigit = false;
			bool hasSymbol = false;

			if (lengthWithinPolicy)
			{
				// "Symbol" is defined by exclusion rather than by an allow-list of punctuation, so any
				// non-alphanumeric character an operator can type counts. The four tests are a partition of
				// the character space, which is what makes the composition check total: every character
				// advances exactly one of the four flags and none can fall through unclassified.
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
				"deliberately no generated fallback: review finding OBS-01 records why a credential the " +
				"platform invents cannot be reported back safely. The value supplied is not echoed here or " +
				"anywhere else, and neither is its length. See docs/security/secure-configuration.md.");
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
		/// byte by a 66-character alphabet is measurably biased towards the alphabet's first characters;
		/// this overload draws uniformly.
		/// <para>
		/// CLASS COVERAGE IS GUARANTEED, NOT ASSUMED. The mandated Authentication Hardening standard
		/// requires "12+ characters, mixed case, numbers, symbols". A uniform draw over the whole alphabet
		/// satisfies the length clause with certainty but the composition clauses only on average: with
		/// eight digits and nine symbols in a 66-character alphabet, roughly one generated value in
		/// thirteen would contain no digit and one in nineteen no symbol. One character is therefore drawn
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

			string generatedPassword = new string(buffer);

			// A self-check, not defensive clutter, and it lives HERE rather than at the call site so that it
			// cannot be bypassed by a future caller. The generator's length and class coverage are properties
			// of three separate constants that a later edit could change independently of the policy, and the
			// only account this value now secures is the local system identity - which holds the administrator
			// role and bypasses permission checks for background work. Validating the generator's own output
			// means such an edit fails loudly here, once per database, instead of quietly writing a credential
			// weaker than the standard demands. The check reads no configuration and never echoes the value.
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
		/// 4. EMITS NO SCHEMA DEFINITION STATEMENT. It changes rows and entity definitions, and it composes
		/// no SQL of its own. The password column is already <c>varchar(500)</c>, and the length bounds
		/// raised here are field metadata that the column width does not depend on, so no column is
		/// altered, added or dropped. Unlike the two sitemap migrations above, this method deliberately
		/// opens no connection and issues no command text.
		/// <para>
		/// GOING THROUGH A MANAGER API IS NOT BY ITSELF SUFFICIENT FOR THAT GUARANTEE, which is the subtle
		/// part. <c>EntityManager.UpdateField</c> looks like a pure metadata call and is not: it calls
		/// <c>DbRecordRepository.UpdateRecordField</c> first, which issues <c>ALTER TABLE ... ALTER
		/// COLUMN</c> for the default and the nullability and then a <c>CREATE INDEX</c> or <c>DROP
		/// INDEX</c>. <see cref="SecurePasswordFieldMetadata4(EntityManager)"/> therefore writes the entity
		/// document through <c>DbEntityRepository.Update</c> instead. Any future addition to this migration
		/// needs the same care: prefer the repository when only metadata is meant to change.
		/// </para>
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
				// ORDER MATTERS, and it is ordered deliberately rather than incidentally.
				//
				// SecurePasswordFieldMetadata4 raises the password field's declared length bounds from the
				// 6-24 an unmigrated installation still carries to 12-128. RevokeSeedAdministratorCredential4
				// then WRITES a password, so it runs against the bounds this release declares rather than the
				// ones it is in the middle of replacing.
				//
				// That sequencing is now LOAD-BEARING rather than belt-and-braces, and review finding OBS-01
				// is what made it so. The replacement credential used to be a generated, fixed 20-character
				// value that sat inside BOTH bound sets by construction; since OBS-01 removed the generator,
				// it is the OPERATOR'S OWN passphrase, which may legitimately be longer than the 24 characters
				// an unmigrated installation still declares and is validated against
				// PasswordMinLength/PasswordMaxLength before it is written. Raising the bounds first is
				// therefore the difference between accepting that passphrase and rejecting it in the middle of
				// a security migration. The earlier revision of this comment anticipated exactly this change
				// and asked that the ordering not be treated as arbitrary; it no longer needs to ask.
				//
				// The dependency runs one way only - raising the bounds neither reads nor needs the stored
				// credential - and all three steps remain individually idempotent, so this ordering does not
				// weaken the re-run guarantee documented above.
				SecurePasswordFieldMetadata4(entMan);
				RevokeSeedAdministratorCredential4(recMan);
				RevokeGuestRecordPermissions4(entMan);
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
		/// HOW THE STORED VALUE IS READ, and why not through the obvious route: EVERY projection seam in the
		/// platform - <c>Api/RecordManager.cs</c>, <c>Database/DbRecordRepository.cs</c> and, since finding
		/// C-02, <c>Eql/EqlCommand.cs</c> - now replaces every encrypted password value with a redaction
		/// marker, unconditionally and for every role. There is no exempt projection left, deliberately: the
		/// query-language path used to be the exemption, and that exemption WAS the vulnerability, because
		/// "SELECT password FROM user" is reachable by any caller holding read access on the user entity.
		/// So neither <c>RecordManager.Find</c> nor <c>SecurityManager.GetUser(Guid)</c> can supply the hash
		/// any more - both would hand this guard the marker, the comparison below would never match, and the
		/// migration would silently do nothing. The value is therefore read through
		/// <c>SecurityManager.ReadStoredPasswordHash</c>, the platform's one internal, system-only,
		/// single-column credential query. Keying on the account id rather than on the seeded e-mail address
		/// is also deliberate: an operator may have changed the address, and the account that has to be
		/// secured is the row, not the label.
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
		/// The replacement is ALSO marked for rotation: <c>PasswordChangeRequired</c> is set below on the
		/// account's existing <c>preferences</c> JSON, so no schema definition statement is emitted. The
		/// marker has teeth - <c>AuthService</c> refuses to mint or refresh a bearer token while it is set,
		/// the login page records a warning audit entry on each sign-in that still uses the credential, and
		/// <c>SecurityManager</c> clears it when the password is actually changed. Interactive login stays
		/// open on purpose, being the only route to the screen that performs that change. The replacement is
		/// the operator's own value and the notice below tells them to rotate it and remove it from the
		/// deployment configuration.
		/// </para>
		/// <para>
		/// WHERE THE REPLACEMENT COMES FROM - review finding OBS-01 (Critical), CWE-532, OWASP A09:2021. It is
		/// read from <see cref="InitialAdministratorPasswordSettingKey"/>, exactly as first provisioning reads
		/// it, and the migration ABORTS when no value is configured. The revision this replaces generated a
		/// random replacement and emitted it on the standard error stream so the operator could read it back,
		/// which published a live administrator credential into every substrate that captures process output.
		/// A migration can no more report an invented secret safely than provisioning can, so it does not
		/// invent one. The abort is reached only by installations that still carry the published default,
		/// because the guard below returns first.
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

			// SECURITY C-02 (Critical, CWE-200 / CWE-522, OWASP A01:2021 + A02:2021). The hash is read
			// through SecurityManager.ReadStoredPasswordHash - the platform's ONE system-only credential
			// query - and no longer from seedAdministrator.Password. That property is populated from a query
			// projection, and every projection seam now redacts encrypted password fields unconditionally so
			// that a hash cannot be retrieved through EQL. Reading the property here would therefore hand
			// this guard the redaction marker instead of the stored value, the comparison below would never
			// match, and THIS REVOCATION WOULD SILENTLY STOP WORKING on exactly the deployments that need it
			// - every installation still carrying the published default. Do not "simplify" it back.
			string storedHash = SecurityManager.ReadStoredPasswordHash(SystemIds.FirstUserId);

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

			// THREAT ADDRESSED - review finding OBS-01 (Critical), CWE-532 insertion of sensitive information
			// into a log, OWASP A09:2021. Deliberately the SAME operator-supplied route as fresh provisioning,
			// and for the same reason: the replacement this migration writes used to be generated here and
			// then emitted on the standard error stream so the operator could read it back, which published a
			// live administrator credential into every substrate that captures process output. A migration
			// cannot report a secret it invents any more safely than provisioning can, so it does not invent
			// one. Requiring the operator's own value is what leaves this method with nothing to disclose.
			//
			// Absence is a hard failure that abandons the whole version 4 migration: the version is not
			// advanced, the transaction rolls back at the caller's catch, and the upgrade is retried on the
			// next start once the setting is supplied. That is the correct trade - the alternative outcomes
			// are leaving the published default in force (the vulnerability this method exists to close) or
			// disclosing an invented replacement (the vulnerability OBS-01 records). Only installations that
			// STILL carry the published default reach this line at all, because the guard above returns
			// first, so an operator who has already chosen their own password is never asked for a setting.
			string replacementPassword = ErpSettings.Configuration?[InitialAdministratorPasswordSettingKey];
			if (string.IsNullOrWhiteSpace(replacementPassword))
			{
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. " + MissingAdministratorPasswordMessage);
			}

			// The same policy gate provisioning applies, for the same reason: without it the literal this
			// migration is revoking could be reinstated verbatim through configuration. It is applied BEFORE
			// the write, so a non-conforming value aborts the migration instead of becoming the account's
			// credential. The caller runs SecurePasswordFieldMetadata4 first, which raises the declared bounds
			// from the 6-24 an unmigrated installation still carries to 12-128; that ordering is now
			// LOAD-BEARING rather than belt-and-braces, because an operator passphrase may legitimately exceed
			// 24 characters - see the ordering rationale at the call site.
			ValidateInitialAdministratorPassword(replacementPassword, ConfiguredPasswordSourceDescription);

			EntityRecord administratorRecord = new EntityRecord();
			administratorRecord["id"] = SystemIds.FirstUserId;
			// Plaintext on purpose. RecordManager's encrypted-password branch hashes this on write with the
			// current primitive, exactly as it does for provisioning, so the value is never persisted as
			// supplied. Pre-hashing here would store a hash of a hash and lock the account out.
			administratorRecord["password"] = replacementPassword;

			//THREAT ADDRESSED (CWE-1392/CWE-798, OWASP A07:2021): the replacement below is generated by the
			//platform and read off a console, so like a freshly provisioned credential it is owed a rotation
			//and is marked as such. Setting it here is what extends first-login rotation to installations
			//that were ALREADY deployed - correcting the source alone would have left every existing
			//deployment holding an unmarked machine-chosen credential.
			//Read-modify-write, not overwrite: this account may well have accumulated real preferences, and
			//serialising a fresh instance would silently discard its sidebar and component-usage state. The
			//existing value was already deserialised into seedAdministrator above, so this costs no
			//additional query.
			ErpUserPreferences rotationRequiredPreferences = seedAdministrator.Preferences ?? new ErpUserPreferences();
			rotationRequiredPreferences.PasswordChangeRequired = true;
			administratorRecord["preferences"] = JsonConvert.SerializeObject(rotationRequiredPreferences);

			QueryResponse result = recMan.UpdateRecord("user", administratorRecord);
			if (!result.Success)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. The administrator credential shipped by earlier releases could not be revoked. Message:" + result.Message);

			// THREAT ADDRESSED - review finding OBS-01 (Critical), CWE-532, OWASP A09:2021. This notice carries
			// NO credential, and that is the whole of the fix: it names the SETTING the replacement came from
			// and states what the migration did, both of which the operator already knows, so nothing here is
			// worth capturing out of a container log or a CI transcript. The revision this replaces embedded
			// the plaintext replacement password so it could be read off a console, which turned an upgrade
			// into a durable disclosure of the account holding every administrative permission.
			//
			// Still QUEUED rather than written here (see pendingProvisioningNotices): this runs inside the
			// schema version 4 migration, which is inside the provisioning transaction, so a failure in any
			// later migration step rolls this password change back. Emitting the notice here would assert a
			// revocation that had not happened, while the account silently kept the published default. It is
			// emitted only once the commit has returned.
			pendingProvisioningNotices.Add("warn: WebVella.Erp.ErpService[3] SECURITY - this installation's administrator account " +
				"(" + SystemIds.FirstUserId + ") still carried the default password published in earlier releases, so it has " +
				"been revoked and replaced with the value supplied in '" + InitialAdministratorPasswordSettingKey + "'. That " +
				"value is not echoed here or anywhere else. Sign in with it and change it immediately, and remove it from the " +
				"deployment configuration once you have. No other account's password was changed. See " +
				"docs/security/credential-migration.md.");
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
		/// The role entity's Guest READ grant is NOT revoked here, and that is a statement about severity
		/// tiers rather than about the grant. What this migration carries is exactly the Critical scope:
		/// C-05's two create grants and C-02's read grant on the user entity. The role entity's read grant
		/// is finding F17, an information-disclosure weakness whose severity places it in the tier this
		/// engagement documents with fix guidance rather than remediates, so no migration reaches it on an
		/// already-provisioned installation and the residual is recorded in
		/// <c>docs/security/risk-register.md</c>. Provisioning no longer seeds that grant, so a new
		/// installation never has it in the first place.
		/// </para>
		/// <para>
		/// <c>EntityManager.UpdateEntity</c> copies only the entity's own scalars and its four permission
		/// lists onto the stored definition and leaves the field collection untouched, so this cannot
		/// disturb field metadata. Every carried-over value is read back from the stored entity rather than
		/// restated as a literal, so an installation whose label, icon or colour was customised keeps it.
		/// </para>
		/// </remarks>
		private static void RevokeGuestRecordPermissions4(EntityManager entMan)
		{
			// The user entity: revoke anonymous create AND anonymous read. The Regular read grant survives,
			// because removing it would break every screen that resolves the signed-in user's own name and
			// avatar; the credential itself is protected by SecurePasswordFieldMetadata4 and by the
			// read-projection redaction instead.
			RevokeGuestRecordPermissions4(entMan, SystemIds.UserEntityId, "user", true, "SCHEMA VERSION 4 MIGRATION.");

			// The role entity: revoke anonymous create only. Its anonymous READ grant is finding F17,
			// which this engagement documents with fix guidance rather than migrates, so it is left in
			// place here and recorded in docs/security/risk-register.md instead.
			RevokeGuestRecordPermissions4(entMan, SystemIds.RoleEntityId, "role", false, "SCHEMA VERSION 4 MIGRATION.");
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
		/// anonymous read grant is finding F17 - documented with fix guidance rather than migrated - so
		/// this migration deliberately leaves it in place on an already-provisioned installation.
		/// </param>
		/// <param name="migrationLabel">
		/// Prefix for any failure message, naming the migration on whose behalf the revocation is running,
		/// so that an operator reading the exception is sent to the right place. It is a parameter rather
		/// than a literal because the message is assembled here while the identity of the migration is
		/// known only to the caller.
		/// </param>
		/// <remarks>
		/// SECURITY - findings C-05 and C-02; see
		/// <see cref="RevokeGuestRecordPermissions4(EntityManager)"/> for the threat.
		/// The permission lists are rebuilt as fresh copies of the stored ones rather than mutated in
		/// place, because <c>EntityManager.ReadEntity</c> serves entities from a process-wide metadata
		/// cache - mutating the lists it hands back would edit that cache directly, so a later failure and
		/// rollback would leave the in-memory model disagreeing with the database until the next cache
		/// clear. <c>RemoveAll</c> is used rather than <c>Remove</c> so that a duplicated grant, which the
		/// permission model does not prevent, cannot leave one copy behind; it also reports how many grants
		/// it removed, which is what lets this method write nothing at all when there was nothing to revoke.
		/// <para>
		/// That makes re-running it harmless AND free, which matters because the version gate advances
		/// only after the whole migration commits: a failure anywhere later in the transaction rolls the
		/// version back, so this method is replayed on the next startup against an entity it may already
		/// have narrowed.
		/// </para>
		/// </remarks>
		private static void RevokeGuestRecordPermissions4(EntityManager entMan, Guid entityId, string entityName, bool revokeRead, string migrationLabel)
		{
			Entity storedEntity = entMan.ReadEntity(entityId).Object;
			if (storedEntity == null)
				throw new InvalidOperationException(migrationLabel + " Entity: " + entityName + ". The entity could not be read, so its anonymous record permissions could not be revoked.");

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

			int revokedGrants = canCreate.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);
			if (revokeRead)
				revokedGrants += canRead.RemoveAll(roleId => roleId == SystemIds.GuestRoleId);

			// Nothing was revoked, so nothing is written. This guard is what makes a replay free on an
			// installation that has already been narrowed: without it, a migration retried after a rolled
			// back transaction would issue two entity updates and two process-wide metadata cache clears
			// in order to store permission lists identical to the ones already stored. The test is on what
			// was actually REMOVED rather than on whether a grant looks present, so "there was something
			// to fix" has exactly one definition here.
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
		/// The stored field is mutated IN PLACE rather than rebuilt, so no property can be lost. It is
		/// located by NAME rather than by the identifier provisioning uses, so an installation whose field
		/// was recreated under a different identifier is still migrated; and any property this method does
		/// not name - a customised label or help text, or a property added to the type by a later release -
		/// is carried through untouched, because the object is never reconstructed.
		/// </para>
		/// <para>
		/// NO SCHEMA DEFINITION STATEMENT IS EMITTED, which the constraints require. The bounds of finding
		/// M-13 are field metadata; the column is <c>varchar(500)</c> and its width does not derive from
		/// them. Only the entity metadata row is written. See the body for why <c>EntityManager.UpdateField</c> is deliberately not used
		/// here, and for what it would have emitted against <c>rec_user</c> if it were.
		/// </para>
		/// </remarks>
		private static void SecurePasswordFieldMetadata4(EntityManager entMan)
		{
			Entity userEntity = entMan.ReadEntity(SystemIds.UserEntityId).Object;
			if (userEntity == null)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. The entity could not be read, so the password field could not be secured.");

			// Located by NAME rather than by the identifier provisioning uses, so an installation whose
			// field was recreated under a different identifier is still migrated. Entity.Fields carries no
			// property initialiser, so the null-conditional is load-bearing: without it an entity read that
			// returned no field collection would abort the upgrade on a NullReferenceException instead of
			// reaching the diagnostic below.
			PasswordField storedPasswordField = userEntity.Fields?
				.SingleOrDefault(field => field.Name == "password") as PasswordField;
			if (storedPasswordField == null)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The field is missing or is not a password field, so it could not be secured.");

			//THREAT ADDRESSED - finding M-13, and the engagement's own acceptance criterion that no
			//schema definition statement is emitted at any point. This step used to rebuild the field as an
			//InputPasswordField and push it through EntityManager.UpdateField. UpdateField calls
			//Database/DbRecordRepository.cs.UpdateRecordField, which issues, against rec_user:
			//  ALTER TABLE ONLY "rec_user" ALTER COLUMN "password" SET DEFAULT ...
			//  ALTER TABLE "rec_user" ALTER COLUMN "password" {SET|DROP} NOT NULL
			//  DROP INDEX IF EXISTS "idx_s_user_password"
			//Those three were harmless in EFFECT here - they re-asserted the column's existing default and
			//nullability and dropped a search index this field has never had - but harmless DDL is still
			//DDL, and the criterion is about what is emitted, not about what it happens to change. So
			//effect is not the test, and this path emits none of it: it writes the entity metadata row and
			//nothing else. UpdateEntity, used by the sibling step for record permissions, is already
			//metadata-only, so this brings the two halves of the migration into line.
			//
			//Mutating the stored field in place is also strictly safer than the rebuild it replaces:
			//UpdateField REPLACES the whole field definition from the InputField handed to it, so every
			//property not explicitly copied across was silently reset. That made the copy list above
			//load-bearing and easy to break - a property added to PasswordField by a later release would
			//have started being erased by this migration, silently. Mutation cannot lose a property it does
			//not mention.
			//
			//The meta-permission assertion is retained because UpdateField performed one and bypassing the
			//manager would otherwise drop it: a security migration must not become MORE permissive than the
			//call it replaces. MigrateSecurityDefaults4 opens a system scope, so this holds in both hosts.
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

			//Mirrors the metadata half of EntityManager.UpdateField exactly - map the whole entity, update
			//the metadata row - minus the UpdateRecordField call that emitted the DDL. Cache.Clear is
			//unconditional and runs before the result is inspected, which is what UpdateField does too: a
			//failed update must not leave a stale entity definition cached either.
			DbEntity updatedEntity = userEntity.MapTo<DbEntity>();
			bool updated = DbContext.Current.EntityRepository.Update(updatedEntity);
			Cache.Clear();
			if (!updated)
				throw new InvalidOperationException("SCHEMA VERSION 4 MIGRATION. Entity: user. Field: password. The entity metadata update did not apply, so the field could not be secured.");
		}

		#endregion
	}
}
