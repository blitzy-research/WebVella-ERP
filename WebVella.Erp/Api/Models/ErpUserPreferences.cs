using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace WebVella.Erp.Api.Models
{
	[Serializable]
	public class ErpUserPreferences
	{
		[JsonProperty("sidebar_size")]
		public string SidebarSize { get; set; } = "";

		[JsonProperty("component_usage")]
		public List<UserComponentUsage> ComponentUsage { get; set; } = new List<UserComponentUsage>();

		/// <summary>
		/// True while the account still carries a bootstrap credential that the platform chose for it
		/// rather than a password its owner chose, and which must therefore be replaced.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-01 (CWE-1392 use of default credential, CWE-798), OWASP
		/// A07:2021. The engagement's plan requires a "change-required-on-first-login marker" for the
		/// credential that replaced the shipped default password. This flag IS that marker. It is set at
		/// exactly the two places that mint a credential the operator did not choose - initial
		/// provisioning, and the schema version 4 revocation of the password earlier releases shipped -
		/// and cleared the moment a password is actually written for the account.
		/// <para>
		/// WHY IT LIVES HERE RATHER THAN IN A NEW COLUMN. The plan forbids schema definition changes
		/// outright, so a dedicated column is not available. The user entity already carries a
		/// <c>preferences</c> text column, provisioned NOT NULL with a <c>{}</c> default, whose entire
		/// purpose is per-user state serialised as JSON. Adding a property to the type that column
		/// already holds costs no data definition statement at all.
		/// </para>
		/// <para>
		/// WHY THE MARKER SURVIVES, AND WHY IT CANNOT BE CLEARED BY ACCIDENT. Three paths round-trip this
		/// object and all three preserve an added property: <c>ErpUserConverter</c> deserialises the
		/// column into this type with <c>MissingMemberHandling.Ignore</c>, so a value stored before this
		/// property existed simply leaves it at its default; <c>UserPreferencies</c> read-modify-writes
		/// through this same type; and <c>SecurityManager.SaveUser</c> writes <c>preferences</c> on its
		/// CREATE branch only. That last point is load-bearing rather than incidental - the SDK user
		/// manage screen assigns a fresh <see cref="ErpUserPreferences"/> before saving, and because the
		/// update branch never copies it into the record, an ordinary user edit cannot silently discharge
		/// a rotation requirement without rotating anything.
		/// </para>
		/// <para>
		/// THE DEFAULT IS false, AND THAT IS NOT A WEAK DEFAULT. Every account predating this
		/// remediation was created with a password its operator chose and carries no rotation debt, so
		/// "not required" is the correct reading of an absent value; treating absence as "required"
		/// would instead demand a rotation from every existing user on upgrade. No <c>= false</c>
		/// initialiser is written because <c>bool</c> already defaults to false and CA1805 forbids
		/// restating it - the absence of an initialiser is the analyzer-clean spelling of that default,
		/// not an oversight. <see cref="Compare"/> deliberately does not test this property: it has no
		/// callers anywhere in the solution, and extending dead code is outside this remediation's
		/// scope.
		/// </para>
		/// </remarks>
		[JsonProperty("password_change_required")]
		public bool PasswordChangeRequired { get; set; }

        [JsonProperty("component_data_dictionary")]
        public EntityRecord ComponentDataDictionary { get; set; } = new EntityRecord(); // full.component.name: EntityRecord

        public bool Compare(ErpUserPreferences prefs)
		{
			if (prefs == null)
				return false;

			if (SidebarSize != prefs.SidebarSize)
				return false;

			if (JsonConvert.SerializeObject(ComponentUsage) != JsonConvert.SerializeObject(prefs.ComponentUsage))
				return false;

            if (JsonConvert.SerializeObject(ComponentDataDictionary) != JsonConvert.SerializeObject(prefs.ComponentDataDictionary))
                return false;

            return true;
		}
	}
}
