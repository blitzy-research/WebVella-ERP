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

				// THREAT ADDRESSED - review finding OBS-11, CWE-359 (exposure of private personal information
				// to an unauthorized actor) compounding CWE-532 (insertion of sensitive information into a
				// log), OWASP A09:2021. This sample printed every returned account's username AND e-mail
				// address to standard output. Nothing about that is remotely reachable - the console
				// application is operator-invoked - but its output is routinely captured: a redirected
				// transcript, a scheduled-task log, a CI job's console, a terminal scrollback shared in a
				// support ticket. Personal data therefore came to rest in stores with no access control and no
				// retention rule, from a program whose only purpose is to demonstrate an API.
				//
				// The DEMONSTRATION IS PRESERVED EXACTLY, which is the point of fixing it this way rather than
				// deleting the sample. What the pre-search hook is being shown to do is restrict the result set
				// to the current user, and the property that proves it is the COUNT together with the record
				// identity - not the personal fields. The account identifier is a surrogate key, not personal
				// data, so it identifies the row for a developer reading along without publishing anything
				// about the person behind it. A developer who genuinely needs to see the personal fields can
				// add them locally; nothing in the shipped sample invites them into a captured log.
				Console.WriteLine($"=== existing users ( filtered by pre search hook by current user id ) ===");
				Console.WriteLine($"=== should return only current user ===");
				Console.WriteLine($"records returned: {usersRecordList.Count}");
				foreach (var rec in usersRecordList)
					Console.WriteLine($"id:{rec["id"]}\t\t(username and email deliberately not printed - review finding OBS-11)");

				RecordHookSample();
			}
		}

		private static void InitErpEngine()
		{
			CultureInfo customCulture = new CultureInfo("en-US");
			customCulture.NumberFormat.NumberDecimalSeparator = ".";
			CultureInfo.DefaultThreadCurrentCulture = customCulture;
			CultureInfo.DefaultThreadCurrentUICulture = customCulture;

			// SECURITY - findings C-04 (CWE-798 hard-coded credentials / CWE-321 hard-coded cryptographic key),
			// H-04 and H-05 (CWE-798), OWASP A02 and A05. THREAT: this console host initializes ErpSettings from
			// its own builder rather than through AddErp, so with a JSON-only chain the connection string and
			// encryption key had no supply channel other than a file tracked in source control - which is why
			// they were committed to it. Adding environment variables is the ordering precondition for blanking
			// Config.json: scrubbing values before a channel exists would leave the application unstartable.
			// PROVIDER ORDER IS LOAD-BEARING: the JSON source stays FIRST and stays NON-optional. The blanked
			// files retain every key and a later provider wins, so a JSON source placed after the others would
			// overwrite an operator-supplied value with an empty string and abort startup on ErpSettings'
			// fail-fast validation. Non-optional so an absent file fails loudly rather than yielding a silently
			// empty configuration.
			//
			// SECURITY - CWE-178 improper handling of case sensitivity, CWE-706 incorrectly resolved name,
			// OWASP A05. Two defects decided WHICH file supplies the connection string and the encryption key:
			//  - The tracked and published file is "Config.json"; the lowercase spelling this replaced does not
			//    resolve on a case-sensitive filesystem, so this non-optional source aborted every Linux run,
			//    and the field workaround of hand-placing a lowercase copy beside the binaries substitutes an
			//    unreviewed, unscrubbed file for the audited one.
			//  - ToApplicationPath returned an EMPTY root unless the executable directory matched a Windows
			//    drive-letter pattern, which degrades to a path relative to the process working directory - so
			//    the launcher, or anyone able to write to it, chose the platform's secrets. AppContext
			//    .BaseDirectory is where the entry assembly loaded from, and this project copies Config.json to
			//    both the build and publish output, so the audited file resolves deterministically.
			// The lowercase name is accepted ONLY as a fallback: the correctly cased file is probed first and
			// wins whenever it exists. The fallback is needed because deployments produced by the earlier
			// lowercase code path carry only config.json, so refusing it would break existing installations.
			// Both candidates resolve against AppContext.BaseDirectory, never ToApplicationPath - tolerating the
			// legacy NAME must not also tolerate an attacker-chosen LOCATION. Existence is tested here rather
			// than in the provider so a missing file yields the provider's own message naming the expected file.
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
			// machine-wide environment variable. The store sits unencrypted on disk and must never be a
			// production channel, so outside development it is not added at all, leaving every non-development
			// chain as exactly JSON file then environment variables. This is a Microsoft.NET.Sdk console app with
			// no IHostEnvironment to ask, so the environment is read from DOTNET_ENVIRONMENT falling back to
			// ASPNETCORE_ENVIRONMENT, rather than introducing a host builder for the sake of one boolean.
			var environmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
			if (string.IsNullOrWhiteSpace(environmentName))
			{
				environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
			}

			if (string.Equals(environmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				// THREAT ADDRESSED - review finding CR3-M-07 (secret management, OWASP A05:2021). This used to
				// be justified by "this project declares no UserSecretsId", which meant the provider resolved
				// no store and silently loaded nothing: the Development supply channel the secure-configuration
				// guide advertises did not exist for this executable, so editing the tracked, blanked
				// Config.json was the only way to run it. The manifest now declares a stable id.
				// optional: true is RETAINED and still stated explicitly: a developer who has not yet run
				// 'dotnet user-secrets set' has no store file, and every AddUserSecrets overload given
				// optional: false throws InvalidOperationException in that case - turning a secret-management
				// fix into an outage on every run. The type-parameter overloads are unusable for the same
				// reason. The entry assembly is null-checked because a host loading this code without one has
				// no store to resolve.
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
            //here put additional automapper configuration if needed
            // SECURITY - finding H-01 (CWE-674 uncontrolled recursion), OWASP A06. THREAT: AutoMapper below
            // 15.1.1 allows denial of service through uncontrolled recursion (GHSA-rvv3-g6hj-g44x), so the pin
            // was raised to [15.1.3] in WebVella.Erp.csproj. From 15.x MapperConfiguration requires an
            // ILoggerFactory; a no-op factory is supplied inside ErpAutoMapper.Initialize, the repository's only
            // mapping-configuration construction site, so this call site is deliberately unchanged.
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
							//use transaction if needed
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
