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

				Console.WriteLine($"=== existing users ( filtered by pre search hook by current user id ) ===");
				Console.WriteLine($"=== should return only current user ===");
				foreach (var rec in usersRecordList)
					Console.WriteLine($"username:{rec["username"]} \t\t email:{rec["email"]}");

				RecordHookSample();
			}
		}

		private static void InitErpEngine()
		{
			CultureInfo customCulture = new CultureInfo("en-US");
			customCulture.NumberFormat.NumberDecimalSeparator = ".";
			CultureInfo.DefaultThreadCurrentCulture = customCulture;
			CultureInfo.DefaultThreadCurrentUICulture = customCulture;

			// SECURITY - findings C-04 (Critical, CWE-798 hard-coded credentials / CWE-321 hard-coded
			// cryptographic key), H-04 and H-05 (High, CWE-798), OWASP A02 and A05.
			// THREAT: this console host initializes ErpSettings from its own builder rather than through
			// AddErp, so it needed the same treatment as the web hosts: with a JSON-only chain the connection
			// string and encryption key had no supply channel other than a file tracked in source control -
			// which is exactly why they were committed to it. Environment variables, and user secrets in
			// development, give an operator an out-of-band channel; this is the ordering precondition for
			// blanking Config.json, because scrubbing values before a channel exists would leave the
			// application unstartable.
			// PROVIDER ORDER IS LOAD-BEARING: the JSON source stays FIRST and stays NON-optional. The shipped
			// Config.json files are blanked but retain every key, and a later provider wins, so a JSON source
			// placed after the others would overwrite an operator-supplied value with an empty string and abort
			// startup on ErpSettings' fail-fast validation. Non-optional so an absent file still fails loudly
			// rather than yielding a silently empty configuration. Nothing is defaulted or logged here.
			//
			// SECURITY - CWE-178 improper handling of case sensitivity and CWE-706 use of an incorrectly
			// resolved name, OWASP A05 Security Misconfiguration. Two defects in one expression, both of
			// which decided WHICH file supplies the connection string and the data-at-rest encryption key:
			//  - The tracked and published file is named "Config.json". The lowercase spelling this replaced
			//    does not resolve on a case-sensitive filesystem, so this non-optional source aborted every
			//    Linux and container run, and the obvious field workaround - hand-placing a lowercase copy
			//    beside the binaries - silently substitutes an unreviewed, unscrubbed file for the audited one.
			//  - ToApplicationPath matched the executable directory against a Windows drive-letter pattern
			//    ("[A-Za-z]:\\...") and returned an EMPTY application root whenever that pattern did not
			//    match, which is always on Linux and also on Windows once the application is published
			//    outside a "\bin\" tree. An empty root degrades to a path relative to the process working
			//    directory, so the launcher - or anyone able to write to the directory the process is started
			//    from - chose the platform's secrets. AppContext.BaseDirectory is the directory the entry
			//    assembly was loaded from, and this project copies Config.json to both the build output and
			//    the publish output (see the Content item in WebVella.Erp.ConsoleApp.csproj), so the audited
			//    file is found deterministically no matter where the process is launched from.
			//
			// THE LOWERCASE NAME IS ACCEPTED AS A FALLBACK, AND ONLY AS A FALLBACK. The correctly cased file
			// is probed first and wins whenever it exists, so the audited file is still the one that loads;
			// the lowercase name is consulted only when it is the sole candidate. That case is real rather
			// than hypothetical - deployments produced by the earlier lowercase code path, and the publish
			// tooling that emitted a lowercase copy to satisfy it, carry only config.json - so refusing it
			// would trade one startup failure for another and break existing installations. Both candidates
			// are resolved against AppContext.BaseDirectory, NOT through ToApplicationPath, so the fallback
			// inherits the deterministic root above and cannot reintroduce the working-directory defect:
			// tolerating the legacy NAME must not also tolerate an attacker-chosen LOCATION. Existence is
			// tested here rather than inside the provider so that when neither name is present the
			// provider's own message names the file the deployment is supposed to hold.
			// System.IO is fully qualified rather than imported, matching this repository's existing idiom for
			// a single path call (see ErpMvcExtensions.UseErp).
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
			// machine-wide environment variable - which is the whole reason the store exists. It is never
			// load-bearing: the store sits unencrypted on disk and must never be a production supply channel,
			// so outside development this provider is not added at all, leaving every non-development chain as
			// exactly JSON file then environment variables. Registering it here is what makes the supply
			// channel ErpSettings' own startup failure message names - "user secrets in development" - real for
			// this process rather than merely advertised.
			// This is a Microsoft.NET.Sdk console application with no IHostEnvironment to ask, so the
			// environment is read from DOTNET_ENVIRONMENT, falling back to ASPNETCORE_ENVIRONMENT, rather than
			// by introducing a host builder or a DI container for the sake of one boolean.
			var environmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
			if (string.IsNullOrWhiteSpace(environmentName))
			{
				environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
			}

			if (string.Equals(environmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				// optional: true is stated EXPLICITLY rather than left to an overload default, because this
				// project declares no UserSecretsId and every AddUserSecrets overload given optional: false
				// throws InvalidOperationException when that attribute is absent - which would turn a
				// secret-management fix into an outage on every run. The type-parameter overloads are
				// unusable here for the same reason. The entry assembly is this executable, so it resolves
				// this application's own store, and it is null-checked because a host that loads this code
				// without an entry assembly has none to resolve.
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
            // SECURITY - finding H-01 (High, CWE-674 uncontrolled recursion), OWASP A06 Vulnerable and
            // Outdated Components. THREAT: AutoMapper below 15.1.1 allows denial of service through
            // uncontrolled recursion (GHSA-rvv3-g6hj-g44x / CVE-2026-32933), so the pin was raised to
            // [15.1.3] in WebVella.Erp.csproj. From 15.x MapperConfiguration requires an ILoggerFactory; a
            // no-op factory is supplied inside ErpAutoMapper.Initialize, the repository's only
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
