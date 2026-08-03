using System;
using System.Collections.Generic;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;

namespace WebVella.Erp.Plugins.Mail
{
	public partial class MailPlugin : ErpPlugin
	{
		/// <summary>
		/// Restricts the <c>smtp_service</c> entity and its <c>password</c> field to administrators on
		/// installations that an earlier release already provisioned.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F31 (High), CWE-200 exposure of sensitive information to an unauthorized actor,
		/// CWE-522 insufficiently protected credentials, CWE-732 incorrect permission assignment,
		/// OWASP A01:2021 Broken Access Control + A02:2021 Cryptographic Failures.
		/// THREAT: the <c>smtp_service</c> entity stores the SMTP relay username and password, and every
		/// earlier release granted the Regular role create, read, update AND delete on it. Entity record
		/// permissions are enforced in the data layer, so any authenticated non-administrator could read the
		/// relay credential through the record API, the query language or the <c>AllSmtpSevices</c> data
		/// source - and could rewrite the server address, redirecting the relay to an attacker-controlled host
		/// with a valid certificate so that every subsequent outbound message and its credentials went there.
		/// <para>
		/// WHY THIS PATCH EXISTS AT ALL: correcting <see cref="Patch20190215"/> protects only installations
		/// provisioned after the correction. Provisioning has already run everywhere else, so without this
		/// patch the source would look remediated while every deployed instance kept the grant. This is the
		/// same seed-plus-migration pairing the core platform uses for its own credential findings.
		/// </para>
		/// <para>
		/// IDEMPOTENT BY CONSTRUCTION, which matters because the dated-patch harness in
		/// <c>MailPlugin._.cs</c> is version-gated but this method may also be re-run by hand: it removes
		/// roles rather than replacing lists, and removal of an absent role is a no-op.
		/// </para>
		/// <para>
		/// NOTHING LEGITIMATE LOSES ACCESS, verified rather than assumed. The mail application sitemap access
		/// list is already Administrator-only - set by <see cref="Patch20190419"/> and reasserted by
		/// <see cref="Patch20200610"/> - and <c>Web/Models/BaseErpPageModel</c> enforces that list
		/// deny-by-default, so every mail screen was already unreachable for a Regular user. The background
		/// queue processor in <c>Services/SmtpInternalService</c> runs inside a system scope whose principal
		/// holds the Administrator role, and the record hook that clears the service cache only fires on
		/// mutations that are now administrator-only anyway.
		/// </para>
		/// <para>
		/// THE DATA SOURCE IS CLOSED BY THE SAME CHANGE, and deliberately not edited: <c>AllSmtpSevices</c>
		/// stores a generated SQL text that selects the password column, but that text is never executed -
		/// it is a display and code-generation artifact. <c>Api/DataSourceManager</c> executes the EQL text
		/// through <c>Eql/EqlCommand</c>, which enforces the entity read permission narrowed below. Rewriting
		/// the stored SQL would therefore change no behaviour, so it is left alone.
		/// </para>
		/// <para>
		/// AT-REST ENCRYPTION OF THE SECRET IS DECLINED, and the reasoning is recorded in
		/// docs/security/risk-register.md rather than left implicit. First, it does not mitigate the stated
		/// exploit: the finding describes a Regular user reading the credential THROUGH the application, which
		/// would decrypt it for them - the authorization narrowing below is what closes that. Second, the only
		/// symmetric primitive in the platform carries a documented, deliberately unfixed deterministic
		/// initialisation-vector weakness with no active callers, so adopting it would convert a latent defect
		/// into an active one. Third, a new cryptographic dependency is out of scope. Fourth and decisively,
		/// the administrator edit form round-trips this field: ciphertext would be displayed and re-saved,
		/// double-encrypting the value and silently breaking all mail delivery, and preventing that needs a
		/// sentinel protocol plus presentation changes - the exact ripple class the change constraints forbid.
		/// </para>
		/// <para>
		/// EVERY FAILURE PATH BELOW THROWS <c>InvalidOperationException</c>, deliberately unlike the bare
		/// <c>Exception</c> the sibling patches in this plugin use. The message text follows their
		/// convention exactly and the behaviour is identical - the harness in <c>MailPlugin._.cs</c> catches
		/// <c>Exception</c>, rolls the transaction back and rethrows - but the specific type is the framework
		/// one for "the metadata is not in a state this operation can proceed from", is catchable on its own,
		/// and carries no CA2201 diagnostic. Nothing observes the difference.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Entity manager participating in the patch transaction.</param>
		/// <param name="relMan">Unused. Present because the patch harness invokes every patch uniformly.</param>
		/// <param name="recMan">Unused. No record data is altered by this patch, only metadata.</param>
		private static void Patch20260802(EntityManager entMan, EntityRelationManager relMan, RecordManager recMan)
		{
			RevokeSmtpServiceNonAdministratorPermissions20260802(entMan);
			SecureSmtpServicePasswordFieldMetadata20260802(entMan);
		}

		/// <summary>
		/// Removes the platform's two built-in non-administrative roles from every record permission of the
		/// <c>smtp_service</c> entity, leaving everything else about the entity untouched.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F31; see <see cref="Patch20260802"/> for the threat.
		/// <para>
		/// WHICH ROLES, and why not simply "replace the lists with Administrator": the finding's required
		/// outcome is administrator-only access, and Regular and Guest are the only non-administrative roles
		/// this platform provisions - Regular is the grant the finding names, and an anonymous grant on a
		/// credential store could never be a defensible operator choice. Any OTHER role in these lists was
		/// created by an operator, and overwriting the lists wholesale would silently revoke a delegation they
		/// chose deliberately, which the preservation requirement forbids. Such a grant survives and is
		/// recorded as the operator's own decision in docs/security/risk-register.md.
		/// </para>
		/// <para>
		/// The permission lists are rebuilt as fresh copies rather than mutated in place, because
		/// <c>EntityManager.ReadEntity</c> serves entities from a process-wide metadata cache: editing the
		/// lists it hands back would write straight into that cache, so a later failure and rollback would
		/// leave the in-memory model disagreeing with the database until the next cache clear.
		/// <c>RemoveAll</c> rather than <c>Remove</c> so a duplicated grant, which the permission model does
		/// not prevent, cannot leave one copy behind - and so re-running this patch is harmless.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Entity manager participating in the patch transaction.</param>
		private static void RevokeSmtpServiceNonAdministratorPermissions20260802(EntityManager entMan)
		{
			var smtpServiceEntityId = new Guid("17698b9f-e533-4f8d-a651-a00f7de2989e");

			Entity storedEntity = entMan.ReadEntity(smtpServiceEntityId).Object;
			if (storedEntity == null)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260802. Entity: smtp_service. The entity could not be read, so its non-administrative record permissions could not be revoked.");

			//RecordPermissions itself carries no property initialiser, unlike the four lists inside it, so a
			//definition written by an older release or edited by hand can present it as absent. Reading that as
			//"no grants recorded" is both correct - an entity with no recorded permissions grants nothing, so
			//there is nothing to revoke - and what stops an upgrade aborting on a NullReferenceException. A
			//security patch that crashes leaves the grants it exists to remove in place.
			RecordPermissions storedPermissions = storedEntity.RecordPermissions ?? new RecordPermissions();

			List<Guid> canCreate = new List<Guid>(storedPermissions.CanCreate);
			List<Guid> canRead = new List<Guid>(storedPermissions.CanRead);
			List<Guid> canUpdate = new List<Guid>(storedPermissions.CanUpdate);
			List<Guid> canDelete = new List<Guid>(storedPermissions.CanDelete);

			foreach (List<Guid> permission in new[] { canCreate, canRead, canUpdate, canDelete })
			{
				permission.RemoveAll(roleId => roleId == SystemIds.RegularRoleId || roleId == SystemIds.GuestRoleId);
			}

			//Every property is carried over from the entity as it is currently stored rather than restated as a
			//literal, because UpdateEntity REPLACES the definition: anything omitted would be silently reset, so
			//an installation that had customised the label, icon or colour would lose it.
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
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260802. Entity: smtp_service. The non-administrative record permissions could not be revoked. Message:" + response.Message);
		}

		/// <summary>
		/// Turns on field-level security for the <c>smtp_service</c> entity's <c>password</c> field and
		/// restricts it to administrators.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F31; see <see cref="Patch20260802"/> for the threat. Defence in depth behind
		/// <see cref="RevokeSmtpServiceNonAdministratorPermissions20260802"/>: that stops a non-administrator
		/// reaching these records at all, and this stops the relay credential being rendered into an editing
		/// surface for anyone who reaches them by another route.
		/// <para>
		/// <c>EnableSecurity</c> is the load-bearing line and the easiest thing here to lose in a later edit:
		/// <c>Web/Components/PcFieldBase/PcFieldBase.cs</c> gates the whole field-permission evaluation behind
		/// it and it defaults to false, so assigning permissions without it leaves them completely inert and
		/// the field readable exactly as before. The administrator experience is unchanged: that evaluation
		/// grants full access when the update list contains one of the caller's roles.
		/// </para>
		/// <para>
		/// Every other property is carried over from the field as currently stored rather than restated as a
		/// literal, because <c>EntityManager.UpdateField</c> REPLACES the whole field definition - anything
		/// not supplied would be silently reset. The field is located by NAME rather than by the identifier
		/// provisioning uses, so an installation whose field was recreated under a different identifier is
		/// still migrated.
		/// </para>
		/// <para>
		/// NO SCHEMA DEFINITION CHANGE RESULTS, and the field type is deliberately NOT changed to a password
		/// field: that type routes writes through the platform's one-way credential hash, which would destroy
		/// a secret the SMTP client must present in plaintext and break all mail delivery.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Entity manager participating in the patch transaction.</param>
		private static void SecureSmtpServicePasswordFieldMetadata20260802(EntityManager entMan)
		{
			var smtpServiceEntityId = new Guid("17698b9f-e533-4f8d-a651-a00f7de2989e");

			Entity storedEntity = entMan.ReadEntity(smtpServiceEntityId).Object;
			if (storedEntity == null)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260802. Entity: smtp_service. The entity could not be read, so its password field could not be secured.");

			//Entity.Fields carries no property initialiser, so the null-conditional is load-bearing: without it
			//an entity read that returned no field collection would abort the upgrade on a
			//NullReferenceException instead of reaching the diagnostic below.
			TextField storedPasswordField = storedEntity.Fields?
				.SingleOrDefault(field => field.Name == "password") as TextField;
			if (storedPasswordField == null)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260802. Entity: smtp_service. Field: password. The field is missing or is not a text field, so it could not be secured.");

			InputTextField password = new InputTextField();
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
			password.DefaultValue = storedPasswordField.DefaultValue;
			password.MaxLength = storedPasswordField.MaxLength;
			//SECURITY - finding F31. EnableSecurity without Permissions denies everyone; Permissions without
			//EnableSecurity denies nobody. Both are required, and administrator only - no Regular and no Guest
			//entry belongs in either list.
			password.EnableSecurity = true;
			password.Permissions = new FieldPermissions();
			password.Permissions.CanRead = new List<Guid>();
			password.Permissions.CanUpdate = new List<Guid>();
			//READ
			password.Permissions.CanRead.Add(SystemIds.AdministratorRoleId);
			//UPDATE
			password.Permissions.CanUpdate.Add(SystemIds.AdministratorRoleId);

			FieldResponse response = entMan.UpdateField(smtpServiceEntityId, password);
			if (!response.Success)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260802. Entity: smtp_service. Field: password. The field could not be secured. Message:" + response.Message);
		}
	}
}
