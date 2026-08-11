using System;
using System.Collections.Generic;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
//SECURITY - review finding MAJ-03. Required by the metadata-only field update that replaced
//EntityManager.UpdateField: MapTo lives in the AutoMapper namespace, DbContext and DbEntity in Database.
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;

namespace WebVella.Erp.Plugins.Mail
{
	public partial class MailPlugin : ErpPlugin
	{
		/// <summary>
		/// Makes the <c>smtp_service</c> connection-security field default to a mandatory encrypted transport,
		/// and labels the cleartext-capable modes as such, on installations that an earlier release already
		/// provisioned.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive information,
		/// CWE-311 missing encryption of sensitive data, OWASP A02:2021 Cryptographic Failures.
		/// THREAT: the field was provisioned with default <c>"1"</c> - <c>Auto</c> - which MailKit resolves to
		/// <c>StartTlsWhenAvailable</c> on every port except 465. Any relay that does not advertise STARTTLS, a
		/// condition an active man-in-the-middle produces by stripping the advertisement from the EHLO response,
		/// therefore received the relay credential and every message in cleartext - and on an unencrypted session
		/// the certificate validation restored by H-11 never runs at all. The list also advertised <c>None</c> and
		/// <c>StartTlsWhenAvailable</c> as ordinary choices, with nothing in the UI to say either is refused
		/// outside development posture.
		/// <para>
		/// WHY THIS PATCH EXISTS AT ALL: correcting the seed in <see cref="Patch20190215"/> protects only
		/// databases provisioned after the correction. Provisioning has already run everywhere else, so without
		/// this patch the source would look remediated while every deployed instance kept offering <c>Auto</c> as
		/// the default for the next SMTP service somebody creates. Same seed-plus-migration pairing as
		/// <see cref="Patch20260802"/> and <see cref="Patch20260806"/>.
		/// </para>
		/// <para>
		/// EXISTING RECORDS ARE DELIBERATELY NOT REWRITTEN, and that is a decision rather than an omission. A
		/// stored <c>Auto</c> or <c>StartTlsWhenAvailable</c> is raised to a mandatory mode at send time by
		/// <c>SmtpService.ResolveConnectionSecurity</c>, so those relays keep delivering and are now encrypted
		/// without a data change; and a stored <c>None</c> is refused there with an actionable diagnostic, which
		/// is what the finding requires - silently rewriting it would hide an operator's explicit statement that
		/// encryption is not wanted. Rewriting rows would also break the development escape hatch, because the
		/// migration cannot know which installations are development ones at upgrade time.
		/// </para>
		/// <para>
		/// IDEMPOTENT, and safe against local customisation. The default is changed ONLY when it currently names
		/// a cleartext-capable mode, so an installation that had already chosen <c>SslOnConnect</c> keeps it, and
		/// re-running finds nothing to do. A label is rewritten ONLY when it is still the shipped literal, so an
		/// installation that renamed its options - a translated deployment, for instance - is left alone rather
		/// than overwritten. When nothing qualifies, no write is issued at all.
		/// </para>
		/// <para>
		/// A NO-OP ON A FRESH INSTALL: <see cref="Patch20190215"/> has already created the field with the
		/// corrected default and labels inside this same transaction, and the entity manager participates in that
		/// transaction, so this patch reads the corrected definition and finds nothing to change.
		/// </para>
		/// <para>
		/// NO SCHEMA DEFINITION CHANGE RESULTS. Only field metadata - a default value and three option labels -
		/// is altered; the column, its type and its stored values are untouched.
		/// </para>
		/// <para>
		/// FAILURE PATHS THROW <c>InvalidOperationException</c>, matching <see cref="Patch20260802"/>: the
		/// harness in <c>MailPlugin._.cs</c> catches, rolls the transaction back and rethrows, so a half-applied
		/// migration is impossible.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Entity manager participating in the patch transaction.</param>
		/// <param name="relMan">Unused. Present because the patch harness invokes every patch uniformly.</param>
		/// <param name="recMan">Unused. No record data is altered by this patch, only field metadata.</param>
		private static void Patch20260807(EntityManager entMan, EntityRelationManager relMan, RecordManager recMan)
		{
			RequireEncryptedSmtpTransportMetadata20260807(entMan);
		}

		/// <summary>
		/// Connection-security modes that permit an unencrypted session, keyed by the value the field stores.
		/// </summary>
		/// <remarks>
		/// Review finding H-OPEN-03. The keys are the stored strings rather than enum members because the field
		/// stores strings, and the values are the shipped labels that this migration is permitted to replace -
		/// see the customisation note on <see cref="Patch20260807"/>. <c>None</c> is 0, <c>Auto</c> is 1 and
		/// <c>StartTlsWhenAvailable</c> is 4 in <c>MailKit.Security.SecureSocketOptions</c>; the mandatory modes
		/// 2 and 3 are deliberately absent, so nothing here can relabel a mode that is already safe.
		/// </remarks>
		private static readonly Dictionary<string, string> CleartextCapableModeLabels20260807 = new Dictionary<string, string>
		{
			{ "0", "None (cleartext - development posture only)" },
			{ "1", "Auto (raised to StartTls outside development posture)" },
			{ "4", "StartTlsWhenAvailable (raised to StartTls outside development posture)" }
		};

		/// <summary>
		/// The shipped labels of the three cleartext-capable modes, as every earlier release provisioned them.
		/// </summary>
		/// <remarks>
		/// Review finding H-OPEN-03. A label is only replaced when it still reads exactly like one of these, so a
		/// deployment that translated or reworded its options keeps its wording. Keyed by stored value for the
		/// same reason as the dictionary above.
		/// </remarks>
		private static readonly Dictionary<string, string> LegacyModeLabels20260807 = new Dictionary<string, string>
		{
			{ "0", "None" },
			{ "1", "Auto" },
			{ "4", "StartTlsWhenAvailable" }
		};

		/// <summary>
		/// The mode this migration installs as the field default: <c>StartTls</c>, which MailKit requires the
		/// relay to advertise and fails when it does not.
		/// </summary>
		private const string MandatoryStartTlsValue20260807 = "3";

		/// <summary>
		/// Rewrites the stored <c>connection_security</c> field definition so its default is a mandatory
		/// encrypted mode and its cleartext-capable options say so.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding H-OPEN-03; see <see cref="Patch20260807"/> for the threat and for why
		/// records are not rewritten. The field is located by NAME rather than by the identifier provisioning
		/// uses, so an installation whose field was recreated under a different identifier is still migrated.
		/// <para>
		/// The stored field is MUTATED IN PLACE and only the entity metadata row is written, so NO SCHEMA
		/// DEFINITION STATEMENT IS EMITTED - see the body, and
		/// <see cref="SecureSmtpServicePasswordFieldMetadata20260802"/>, for what
		/// <c>EntityManager.UpdateField</c> emitted when it was used here and why mutation is also safer than
		/// the rebuild it replaces.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Entity manager participating in the patch transaction.</param>
		private static void RequireEncryptedSmtpTransportMetadata20260807(EntityManager entMan)
		{
			var smtpServiceEntityId = new Guid("17698b9f-e533-4f8d-a651-a00f7de2989e");

			Entity storedEntity = entMan.ReadEntity(smtpServiceEntityId).Object;
			if (storedEntity == null)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260807. Entity: smtp_service. The entity could not be read, so its connection security could not be made mandatory.");

			//Entity.Fields carries no property initialiser, so the null-conditional is load-bearing: without it an
			//entity read that returned no field collection would abort the upgrade on a NullReferenceException
			//instead of reaching the diagnostic below.
			SelectField storedField = storedEntity.Fields?
				.SingleOrDefault(field => field.Name == "connection_security") as SelectField;
			if (storedField == null)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260807. Entity: smtp_service. Field: connection_security. The field is missing or is not a select field, so connection security could not be made mandatory.");

			//SECURITY - review finding H-OPEN-03. Only a cleartext-capable default is replaced. An installation
			//that had already chosen SslOnConnect or StartTls keeps its choice, and a re-run changes nothing.
			bool defaultNeedsChange = storedField.DefaultValue == null
				|| CleartextCapableModeLabels20260807.ContainsKey(storedField.DefaultValue);

			List<SelectOption> migratedOptions = new List<SelectOption>();
			bool optionsNeedChange = false;
			foreach (SelectOption storedOption in storedField.Options ?? new List<SelectOption>())
			{
				//Carry the option over verbatim, then replace the label only when it is still the shipped literal
				//for a cleartext-capable mode. Value, icon and colour are never touched: rewriting a value would
				//orphan every record storing it.
				SelectOption migratedOption = new SelectOption
				{
					Value = storedOption.Value,
					Label = storedOption.Label,
					IconClass = storedOption.IconClass,
					Color = storedOption.Color
				};

				if (storedOption.Value != null
					&& LegacyModeLabels20260807.TryGetValue(storedOption.Value, out string legacyLabel)
					&& string.Equals(storedOption.Label, legacyLabel, StringComparison.Ordinal))
				{
					migratedOption.Label = CleartextCapableModeLabels20260807[storedOption.Value];
					optionsNeedChange = true;
				}

				migratedOptions.Add(migratedOption);
			}

			//Nothing qualifying means nothing to write. Issuing an UpdateField anyway would rewrite the whole
			//definition for no reason, which on a customised installation is exactly the risk worth avoiding.
			if (!defaultNeedsChange && !optionsNeedChange)
				return;

			//THREAT ADDRESSED - review finding MAJ-03, and the engagement's own acceptance criterion that no
			//schema definition statement is emitted at any point. This step used to rebuild the field as an
			//InputSelectField and push it through EntityManager.UpdateField, which reaches
			//Database/DbRecordRepository.cs.UpdateRecordField and issues, against rec_smtp_service:
			//  ALTER TABLE ONLY "rec_smtp_service" ALTER COLUMN "connection_security" SET DEFAULT ...
			//  ALTER TABLE "rec_smtp_service" ALTER COLUMN "connection_security" {SET|DROP} NOT NULL
			//  DROP INDEX IF EXISTS "idx_s_smtp_service_connection_security"
			//Harmless in effect, but the criterion is about what is EMITTED. This path writes the entity
			//metadata row and nothing else, and it drops the property-copy list the rebuild required - a
			//property added to SelectField by a later release would have been silently erased by that list,
			//whereas mutation cannot lose a property it does not mention.
			//
			//The assertion sits AFTER the no-op return above, exactly where UpdateField's own permission check
			//used to sit: a run in which nothing qualifies must still be a clean no-op and must not start
			//failing on permissions. It is retained at all because bypassing the manager would otherwise drop
			//the check, and a security migration must not become MORE permissive than the call it replaces.
			if (!SecurityContext.HasMetaPermission())
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260807. Entity: smtp_service. Field: connection_security. Metadata permission is required, so connection security could not be made mandatory.");

			//SECURITY - review finding H-OPEN-03. The two lines this patch exists for, now applied to the
			//stored field itself. DefaultValue is left alone unless it is cleartext-capable, so an
			//installation that had already chosen SslOnConnect or StartTls keeps its choice.
			if (defaultNeedsChange)
				storedField.DefaultValue = MandatoryStartTlsValue20260807;
			storedField.Options = migratedOptions;

			//Mirrors the metadata half of EntityManager.UpdateField exactly - map the whole entity, update the
			//metadata row - minus the UpdateRecordField call that emitted the DDL. The repository's own Update
			//clears the entity cache in a finally block (Database/DbEntityRepository.cs:208-211), so a stale
			//definition cannot survive this write whether it succeeds or fails.
			DbEntity updatedEntity = storedEntity.MapTo<DbEntity>();
			bool updated = DbContext.Current.EntityRepository.Update(updatedEntity);
			if (!updated)
				throw new InvalidOperationException("MAIL PLUGIN PATCH 20260807. Entity: smtp_service. Field: connection_security. The entity metadata update did not apply, so connection security could not be made mandatory.");
		}
	}
}
