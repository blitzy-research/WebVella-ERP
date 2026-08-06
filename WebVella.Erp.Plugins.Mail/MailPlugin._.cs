using Newtonsoft.Json;
using System;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Exceptions;

namespace WebVella.Erp.Plugins.Mail
{
	public partial class MailPlugin : ErpPlugin
	{
		private const int WEBVELLA_MAIL_INIT_VERSION = 20190101;

		public void ProcessPatches()
		{
			
			using (SecurityContext.OpenSystemScope())
			{

				var entMan = new EntityManager();
				var relMan = new EntityRelationManager();
				var recMan = new RecordManager();
				var storeSystemSettings = DbContext.Current.SettingsRepository.Read();
				var systemSettings = new SystemSettings(storeSystemSettings);

				//Create transaction
				using (var connection = DbContext.Current.CreateConnection())
				{
					try
					{
						connection.BeginTransaction();

						//Here we need to initialize or update the environment based on the plugin requirements.
						//The default place for the plugin data is the "plugin_data" entity -> the "data" text field, which is used to store stringified JSON
						//containing the plugin settings or version

						//TODO: Develop a way to check for installed plugins
						#region << 1.Get the current ERP database version and checks for other plugin dependencies >>

						if (systemSettings.Version > 0)
						{
							//Do something if database version is not what you expect
						}

						#endregion

						#region << 2.Get the current plugin settings from the database >>

						var currentPluginSettings = new PluginSettings() { Version = WEBVELLA_MAIL_INIT_VERSION };
						string jsonData = GetPluginData();
						if (!string.IsNullOrWhiteSpace(jsonData))
							currentPluginSettings = JsonConvert.DeserializeObject<PluginSettings>(jsonData);

						#endregion

						#region << 3. Run methods based on the current installed version of the plugin >>

						//Patch 20190215
						{
							var patchVersion = 20190215;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20190215(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						//Patch 20190419
						{
							var patchVersion = 20190419;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20190419(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						//Patch 20190420
						{
							var patchVersion = 20190420;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20190420(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						{
							var patchVersion = 20190422;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20190422(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						{
							var patchVersion = 20190529;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20190529(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						
						{
							var patchVersion = 20200610;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20200610(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						{
							var patchVersion = 20200611;
							if (currentPluginSettings.Version < patchVersion)
							{
								try
								{
									currentPluginSettings.Version = patchVersion;
									Patch20200611(entMan, relMan, recMan);
								}
								catch (ValidationException ex)
								{
									var exception = ex;
									throw ex;
								}
								catch (Exception)
								{
									throw;
								}
							}
						}

						//SECURITY - finding F31 (High), CWE-200 + CWE-522 + CWE-732, OWASP A01:2021 + A02:2021.
						//Carries the smtp_service authorization corrections made in MailPlugin.20190215 to
						//installations that an earlier release already provisioned. Without this block the seed is
						//fixed and every deployed instance still grants the Regular role read and update on the SMTP
						//relay credential, so the source would look remediated while the vulnerability stayed live
						//everywhere it actually matters.
						//NO INNER try/catch, deliberately unlike the seven blocks above: theirs catch only to rethrow,
						//and the ValidationException arm rethrows the caught variable rather than rebubbling, which
						//resets the stack trace and loses the origin of a failed security migration. The outer handler
						//in this method already rolls the transaction back and rethrows both families, so omitting the
						//inner one is behaviourally identical for the caller and strictly better for diagnosis. The
						//existing blocks are left exactly as they are - not refactoring them is the change constraint,
						//but replicating a defect into new code is not required by it.
						{
							var patchVersion = 20260802;
							if (currentPluginSettings.Version < patchVersion)
							{
								currentPluginSettings.Version = patchVersion;
								Patch20260802(entMan, relMan, recMan);
							}
						}

						//SECURITY - review finding INT-14 (Major), CWE-79 stored cross-site scripting, CWE-116, OWASP
						//A03:2021. Carries the output-encoding correction made to the all_emails error-icon node in
						//MailPlugin.20190215 to installations an earlier release already provisioned. Without this block
						//the seed is fixed while the node code that actually runs - already stored in
						//app_page_body_node.options - keeps interpolating unencoded SMTP response text into an HTML
						//attribute on an administrator-facing screen.
						//A SEPARATE, LATER PATCH VERSION than 20260802 deliberately: that one has already been applied
						//wherever this branch has run, so folding this migration into it would silently skip every such
						//installation. Its own version gate is what makes this reach them.
						//NO INNER try/catch, for the same reason as the block above: the outer handler already rolls the
						//transaction back and rethrows both exception families, and the ValidationException arm of the
						//legacy blocks rethrows the caught variable, which resets the stack trace of a failed security
						//migration.
						{
							var patchVersion = 20260806;
							if (currentPluginSettings.Version < patchVersion)
							{
								currentPluginSettings.Version = patchVersion;
								Patch20260806(entMan, relMan, recMan);
							}
						}

						//SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive
						//information, CWE-311 missing encryption of sensitive data, OWASP A02:2021.
						//Carries the connection-security metadata correction made in MailPlugin.20190215 to
						//installations that an earlier release already provisioned: the field defaulted to Auto, which
						//MailKit resolves to StartTlsWhenAvailable on every port except 465, so the next SMTP service
						//an administrator created would still have sent the relay credential and every message in
						//cleartext against a relay that does not advertise STARTTLS. Without this block the seed is
						//fixed while every deployed instance keeps offering that default.
						//A SEPARATE, LATER PATCH VERSION than 20260806 deliberately, for the same reason that one is
						//separate from 20260802: the earlier versions have already been applied wherever this branch
						//has run, so folding this migration into one of them would silently skip every such
						//installation. Its own version gate is what makes this reach them.
						//NO INNER try/catch, as with the two blocks above: the outer handler already rolls the
						//transaction back and rethrows both exception families, while the ValidationException arm of
						//the legacy blocks rethrows the caught variable and resets the stack trace of a failed
						//security migration.
						{
							var patchVersion = 20260807;
							if (currentPluginSettings.Version < patchVersion)
							{
								currentPluginSettings.Version = patchVersion;
								Patch20260807(entMan, relMan, recMan);
							}
						}

						#endregion


						SavePluginData(JsonConvert.SerializeObject(currentPluginSettings));

						connection.CommitTransaction();
					}
					catch (ValidationException ex)
					{
						connection.RollbackTransaction();
						throw ex;
					}
					catch (Exception)
					{
						connection.RollbackTransaction();
						throw;
					}
				}
			}
		}
	}
}
