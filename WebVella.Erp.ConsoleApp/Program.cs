using Microsoft.Extensions.Configuration;
using System;
using System.Globalization;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Eql;
using WebVella.Erp.Hooks;

namespace WebVella.Erp.ConsoleApp
{
	class Program
	{
		static void Main()
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				//call this method once to initialize erp engine
				InitErpEngine();

				var usersRecordList = SampleGetAllErpUsers();

				// THREAT ADDRESSED - CWE-359 exposure of private personal information compounding CWE-532 insertion
				// of sensitive information into a log, OWASP A09. This sample printed every returned account's
				// username and e-mail to standard output, and console output is routinely captured into transcripts,
				// scheduled-task logs and CI job logs that carry no access control and no retention rule. The
				// demonstration is preserved: what the pre-search hook is being shown to do is proved by the COUNT
				// and the surrogate identifier, neither of which is personal data.
				Console.WriteLine($"=== existing users ( filtered by pre search hook by current user id ) ===");
				Console.WriteLine($"=== should return only current user ===");
				Console.WriteLine($"records returned: {usersRecordList.Count}");
				foreach (var rec in usersRecordList)
					Console.WriteLine($"id:{rec["id"]}\t\t(username and email deliberately not printed)");

				RecordHookSample();
			}
		}

		private static void InitErpEngine()
		{
			CultureInfo customCulture = new CultureInfo("en-US");
			customCulture.NumberFormat.NumberDecimalSeparator = ".";
			CultureInfo.DefaultThreadCurrentCulture = customCulture;
			CultureInfo.DefaultThreadCurrentUICulture = customCulture;

			// SECURITY - findings C-04 (CWE-798 hard-coded credentials, CWE-321 hard-coded key), H-04 and H-05,
			// OWASP A02 / A05: this host initializes ErpSettings from its own builder rather than through AddErp,
			// so with a JSON-only chain the connection string and encryption key had no supply channel other than
			// a tracked file. PROVIDER ORDER IS LOAD-BEARING - the JSON source stays FIRST and NON-optional,
			// because the blanked files retain every key and a later provider wins, so a JSON source placed last
			// would overwrite an operator-supplied value with an empty string.
			//
			// SECURITY - CWE-178 improper handling of case sensitivity and CWE-706 incorrectly resolved name,
			// OWASP A05: the published name is "Config.json", so a lowercase spelling aborted every
			// case-sensitive run and invited a hand-made unscrubbed copy, while ToApplicationPath returned an
			// empty root off Windows and let the launcher choose the platform's secrets. Both candidates now
			// resolve against AppContext.BaseDirectory - tolerating the legacy NAME must not tolerate an
			// attacker-chosen LOCATION - and the correct casing is probed first, lowercase accepted only so
			// deployments produced by the earlier code path keep starting.
			string configPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Config.json");
			if (!System.IO.File.Exists(configPath))
			{
				string lowerCaseConfigPath = System.IO.Path.Combine(AppContext.BaseDirectory, "config.json");
				if (System.IO.File.Exists(lowerCaseConfigPath))
					configPath = lowerCaseConfigPath;
			}

			var configurationBuilder = new ConfigurationBuilder()
				.AddJsonFile(configPath)
				.AddEnvironmentVariables();

			// User secrets come LAST, and only in development, so a developer's own store outranks an ambient
			// machine-wide environment variable. The store is unencrypted on disk and must never be a production
			// channel, so outside development it is not added at all. This is a console app with no
			// IHostEnvironment, so the environment is read from DOTNET_ENVIRONMENT then ASPNETCORE_ENVIRONMENT.
			var environmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
			if (string.IsNullOrWhiteSpace(environmentName))
			{
				environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
			}

			if (string.Equals(environmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				// The manifest declares a stable UserSecretsId, so the Development supply channel the
				// secure-configuration guide advertises actually resolves without editing the tracked, blanked
				// Config.json. optional: true is stated explicitly because every AddUserSecrets overload given
				// optional: false throws when a developer has set no secret yet, turning this fix into an outage.
				var entryAssembly = System.Reflection.Assembly.GetEntryAssembly();
				if (entryAssembly != null)
				{
					configurationBuilder.AddUserSecrets(entryAssembly, optional: true);
				}
			}

			ErpSettings.Initialize(configurationBuilder.Build());
			DbContext.CreateContext(ErpSettings.ConnectionString);
			ErpService service = new ErpService();

			ErpAutoMapperConfiguration.Configure(ErpAutoMapperConfiguration.MappingExpressions);
            // SECURITY - finding H-01 (CWE-674 uncontrolled recursion), OWASP A06: AutoMapper below 15.1.1 allows
            // denial of service through uncontrolled recursion (GHSA-rvv3-g6hj-g44x), so the pin was raised to
            // [15.1.3]. From 15.x MapperConfiguration requires an ILoggerFactory; a no-op factory is supplied in
            // ErpAutoMapper.Initialize, the repository's only construction site, so this call site is unchanged.
            ErpAutoMapper.Initialize(ErpAutoMapperConfiguration.MappingExpressions);

            service.InitializeSystemEntities();


			//register hooks
			HookManager.RegisterHooks(service);

			DbContext.CloseContext();
		}

		private static EntityRecordList SampleGetAllErpUsers()
		{
			EntityRecordList result = null;

			//you need to create manually database context
			using (var dbCtx = DbContext.CreateContext(ErpSettings.ConnectionString))
			{
				//create connection
				using (var connection = dbCtx.CreateConnection())
				{
					//create security context - in this sample we use OpenSystemScope method,
					//which used system user with all privileges and rights to erp data
					using (var scope = SecurityContext.OpenSystemScope())
					{
						try
						{
							connection.BeginTransaction();

							result = new EqlCommand("SELECT * FROM user").Execute();

							connection.CommitTransaction();
						}
						catch
						{
							connection.RollbackTransaction();
							throw;
						}
					}
				}
			}
			return result;
		}

		private static void RecordHookSample()
		{
			//you need to create manually database context
			using (var dbCtx = DbContext.CreateContext(ErpSettings.ConnectionString))
			{
				//create connection
				using (var connection = dbCtx.CreateConnection())
				{
					//create security context - in this sample we use OpenSystemScope method,
					//which used system user with all privileges and rights to erp data
					using (var scope = SecurityContext.OpenSystemScope())
					{
						try
						{
							connection.BeginTransaction();

							RecordManager recMan = new RecordManager();

							//list all records from role entity
							var existingRoles = new EqlCommand("SELECT * FROM role").Execute();
							Console.WriteLine();
							Console.WriteLine($"=== existing roles ===");
							foreach (var rec in existingRoles)
								Console.WriteLine($"name:{rec["name"]}");

							//create new role record to triger record hook
							EntityRecord newRec = new EntityRecord();
							newRec["id"] = Guid.NewGuid();
							newRec["name"] = "New Role";
							var result = recMan.CreateRecord("role", newRec);
							if (!result.Success)
								throw new Exception(result.Message);

							Console.WriteLine($"=== roles after create ===");
							existingRoles = new EqlCommand("SELECT * FROM role").Execute();
							foreach (var rec in existingRoles)
								Console.WriteLine($"name:{rec["name"]}");


							newRec["name"] = "New changed Role";
							result = recMan.UpdateRecord("role", newRec);
							if (!result.Success)
								throw new Exception(result.Message);

							Console.WriteLine($"=== roles after update ===");
							existingRoles = new EqlCommand("SELECT * FROM role").Execute();
							foreach (var rec in existingRoles)
								Console.WriteLine($"name:{rec["name"]}");

							result = recMan.DeleteRecord("role", (Guid)newRec["id"]);
							if (!result.Success)
								throw new Exception(result.Message);

							Console.WriteLine($"=== roles after delete ===");
							existingRoles = new EqlCommand("SELECT * FROM role").Execute();
							foreach (var rec in existingRoles)
								Console.WriteLine($"name:{rec["name"]}");

						}
						finally
						{
							//we allways rollback transaction - this method is only for presentation how hooks are triggered from console app
							connection.RollbackTransaction();
						}
					}
				}
			}
		}
	}
}
