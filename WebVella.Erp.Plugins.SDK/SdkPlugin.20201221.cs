using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;

namespace WebVella.Erp.Plugins.SDK
{
    public partial class SdkPlugin : ErpPlugin
    {
        private static void Patch20201221(EntityManager entMan, EntityRelationManager relMan, RecordManager recMan)
        {
            #region << ***Update entity*** Entity name: role >>
            {
                var updateObject = new InputEntity();
                updateObject.Id = new Guid("c4541fee-fbb6-4661-929e-1724adec285a");
                updateObject.Name = "role";
                updateObject.Label = "Role";
                updateObject.LabelPlural = "Roles";
                updateObject.System = true;
                updateObject.IconName = "fa fa-key";
                updateObject.Color = "#f44336";
                updateObject.RecordScreenIdField = null;
                updateObject.RecordPermissions = new RecordPermissions();
                updateObject.RecordPermissions.CanRead = new List<Guid>();
                updateObject.RecordPermissions.CanCreate = new List<Guid>();
                updateObject.RecordPermissions.CanUpdate = new List<Guid>();
                updateObject.RecordPermissions.CanDelete = new List<Guid>();
                //SECURITY - findings C-05 (Critical, CWE-269 improper privilege management, CWE-732
                //incorrect permission assignment for a critical resource) and C-02 (Critical, CWE-200
                //exposure of sensitive information to an unauthorized actor, CWE-522 insufficiently
                //protected credentials), OWASP A01:2021 Broken Access Control.
                //THREAT: this patch restates the role entity's COMPLETE record-permission set and applies
                //it with EntityManager.UpdateEntity, which replaces the stored lists outright. Plugin
                //patches are gated on the plugin's own stored version, which begins at 0, and plugin
                //initialisation runs after ERPService provisioning - so on a fresh installation this block
                //executed after the corrected seed and after the schema version 4 migration and added the
                //Guest CREATE grant back, re-opening the anonymous privilege-escalation chain that
                //ERPService.cs closes. The Guest role is the role an unauthenticated caller is evaluated
                //against - SecurityContext.HasEntityPermission falls back to the Guest grants exactly when
                //no user is resolved - so that grant let an anonymous caller author a role.
                //REMEDIATION, per the mandated Authorization Enforcement standard's deny-by-default clause:
                //the Guest CREATE grant is removed, so this patch can no longer widen what provisioning and
                //the migration record. The Guest READ grant is removed as well, under review finding F17
                //(CWE-200 exposure of sensitive information to an unauthorized actor, CWE-732 incorrect
                //permission assignment for a critical resource): MigrateSecurityDefaults5 in ERPService.cs revokes
                //anonymous READ on the role entity at schema version 5, and this patch runs AFTER the migrations,
                //so retaining the grant here reinstated exactly what version 5 removes. The earlier justification -
                //that anonymous READ is how role names resolve before sign-in - does not hold: credential
                //resolution and role hydration both run inside SecurityContext.OpenSystemScope in
                //SecurityManager.GetUser, so the sign-in path never consults the Guest grants, and no anonymous
                //endpoint in the solution reads the role entity. Regular and Administrator keep their READ grants
                //below, so nothing an authenticated caller can see changes.
                updateObject.RecordPermissions.CanRead.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanRead.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                // THREAT ADDRESSED - finding C-05, CWE-269 (improper privilege management) and CWE-732
                // (incorrect permission assignment for critical resource), OWASP A01: Broken Access
                // Control. EntityManager.UpdateEntity REPLACES the entire record-permission set rather
                // than merging into it, so the anonymous Guest CREATE grant that this patch used to
                // re-add here silently overwrote the revocation performed both by the core seed and by
                // the schema version 4 migration. Plugin patches run after core provisioning, so every
                // deployment that loads this plugin had anonymous role creation restored - which is
                // privilege escalation, because a role is the unit that carries permissions. The grant
                // is therefore removed here too.
                //
                // ALSO REMOVED, under review finding F17: the anonymous Guest READ grant this region used to
                // add. It was previously retained on the premise that role names must still resolve for a
                // caller who has not yet authenticated; MigrateSecurityDefaults5 in ERPService.cs establishes
                // that they do not - the sign-in path hydrates roles under a system scope - and revokes that
                // grant at schema version 5. Because plugin patches run after the migrations, retaining it here
                // reopened F17 on every installation that loads this plugin.
                updateObject.RecordPermissions.CanCreate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanUpdate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanDelete.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                var updateEntityResult = entMan.UpdateEntity(updateObject);
                if (!updateEntityResult.Success)
                {
                    throw new Exception("System error 10060. Entity update with name : role. Message:" + updateEntityResult.Message);
                }
            }
            #endregion

            #region << ***Update entity*** Entity name: user >>
            {
                var updateObject = new InputEntity();
                updateObject.Id = new Guid("b9cebc3b-6443-452a-8e34-b311a73dcc8b");
                updateObject.Name = "user";
                updateObject.Label = "User";
                updateObject.LabelPlural = "Users";
                updateObject.System = true;
                updateObject.IconName = "fa fa-user";
                updateObject.Color = "#f44336";
                updateObject.RecordScreenIdField = null;
                updateObject.RecordPermissions = new RecordPermissions();
                updateObject.RecordPermissions.CanRead = new List<Guid>();
                updateObject.RecordPermissions.CanCreate = new List<Guid>();
                updateObject.RecordPermissions.CanUpdate = new List<Guid>();
                updateObject.RecordPermissions.CanDelete = new List<Guid>();
                //SECURITY - findings C-02 (Critical, CWE-200 exposure of sensitive information to an
                //unauthorized actor, CWE-522 insufficiently protected credentials) and C-05 (Critical,
                //CWE-269, CWE-732), OWASP A01:2021 Broken Access Control.
                //THREAT: exactly as in the role region above, this patch restates the user entity's COMPLETE
                //record-permission set and applies it with UpdateEntity, so on a fresh installation it ran
                //after the corrected provisioning seed and after the schema version 4 migration and added
                //both Guest grants back. Guest CREATE on the user entity was anonymous self-registration
                //into the identity store - a privilege-escalation primitive, because the inserted row can
                //then be granted a role - and Guest READ exposed the entire user collection, including the
                //stored credential column, to unauthenticated callers.
                //REMEDIATION: both Guest grants are removed, matching ERPService.cs and
                //RevokeGuestRecordPermissions4(..., "user", revokeRead: true). The Regular READ grant is
                //retained deliberately - removing it would break every screen that resolves the signed-in
                //user's own name and avatar, which the preservation requirement forbids - and the credential
                //stays protected by the administrator-only password field permissions and the
                //read-projection redaction instead.
                updateObject.RecordPermissions.CanRead.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanRead.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanCreate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanUpdate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanDelete.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                var updateEntityResult = entMan.UpdateEntity(updateObject);
                if (!updateEntityResult.Success)
                {
                    throw new Exception("System error 10060. Entity update with name : user. Message:" + updateEntityResult.Message);
                }
            }
            #endregion

            #region << ***Update entity*** Entity name: user_file >>
            {
                var updateObject = new InputEntity();
                updateObject.Id = new Guid("5c666c54-9e76-4327-ac7a-55851037810c");
                updateObject.Name = "user_file";
                updateObject.Label = "User File";
                updateObject.LabelPlural = "User Files";
                updateObject.System = true;
                updateObject.IconName = "fa fa-file";
                updateObject.Color = "#f44336";
                updateObject.RecordScreenIdField = null;
                updateObject.RecordPermissions = new RecordPermissions();
                updateObject.RecordPermissions.CanRead = new List<Guid>();
                updateObject.RecordPermissions.CanCreate = new List<Guid>();
                updateObject.RecordPermissions.CanUpdate = new List<Guid>();
                updateObject.RecordPermissions.CanDelete = new List<Guid>();
                updateObject.RecordPermissions.CanRead.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanRead.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanCreate.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanCreate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanUpdate.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanUpdate.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                updateObject.RecordPermissions.CanDelete.Add(new Guid("f16ec6db-626d-4c27-8de0-3e7ce542c55f"));
                updateObject.RecordPermissions.CanDelete.Add(new Guid("bdc56420-caf0-4030-8a0e-d264938e0cda"));
                var updateEntityResult = entMan.UpdateEntity(updateObject);
                if (!updateEntityResult.Success)
                {
                    throw new Exception("System error 10060. Entity update with name : user_file. Message:" + updateEntityResult.Message);
                }
            }
            #endregion

        }
    }
}
