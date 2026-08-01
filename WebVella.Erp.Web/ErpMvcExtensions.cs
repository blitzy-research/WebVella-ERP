using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading.RateLimiting;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Jobs;
using WebVella.Erp.Web.Middleware;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Models.AutoMapper;
using WebVella.Erp.Web.Services;
using WebVella.TagHelpers;

namespace WebVella.Erp.Web
{
	public static class ErpMvcServicesExtensions
	{
		public static IServiceCollection AddErp(this IServiceCollection services)
		{
			services.AddSingleton<IErpService, ErpService>();
			services.AddTransient<AuthService>();
			services.AddScoped<ErpRequestContext>();

			// THREAT ADDRESSED - finding H-08 / M-01 (OWASP A05: Security Misconfiguration):
			// SecurityHeadersMiddleware existed but was never reachable - no host registered its
			// options and no host inserted it into a pipeline - so not one of the seven mandated
			// security response headers was actually emitted. Registering the options here, at the
			// platform's single canonical service-registration extension, means all seven hosts
			// inherit it from one edit. The options type carries the mandated Content-Security-Policy
			// as a get-only computed property, so this registration cannot be used to weaken it; only
			// the report-only/enforcing switch is settable.
			services.AddOptions<SecurityHeadersOptions>();

			// THREAT ADDRESSED - finding H-16, CWE-307 (Improper Restriction of Excessive
			// Authentication Attempts), OWASP A07: LoginThrottleService existed but was never
			// registered and never resolved, so the mandated five-attempt account lockout was dead
			// code and every credential-verification entry point still accepted unlimited attempts.
			// Registering it here, at the platform's single canonical service-registration extension,
			// means all seven hosts inherit it from one edit.
			//
			// Singleton is required, not merely convenient: the failure counters live in the
			// service's own in-process store, so a transient or scoped lifetime would hand every
			// request a brand new, empty set of counters and the threshold would never be reached.
			// The container disposes it on shutdown, which releases that store.
			services.AddSingleton<LoginThrottleService>();

			// THREAT ADDRESSED - finding H-08 / H-16, CWE-307 (improper restriction of excessive
			// authentication attempts) and CWE-770 (allocation without limits), OWASP A07: no
			// transport-level request throttling existed anywhere in the platform, so a single client
			// could issue unlimited requests - including unlimited POSTs to the login page and to the
			// anonymous token endpoints. This is the transport-level layer only; the per-account login
			// lockout is a separate, narrower control applied at the login entry point.
			//
			// A fixed window partitioned by remote address is chosen as the least invasive option that
			// closes the gap: it comes from the shared framework, so it adds no package, and it needs
			// no store, no schema change and no configuration. The permit limit is deliberately
			// generous - a single page in this application issues on the order of twenty-five requests -
			// so that ordinary interactive use, including rapid navigation, is never throttled while
			// automated abuse still meets a ceiling.
			//
			// Documented limitation: partitioning by remote address means every client behind a shared
			// egress address - a corporate NAT or a reverse proxy that does not forward the caller's
			// address - shares one partition. Deployments terminating traffic at a proxy should enable
			// forwarded-headers processing so the partition key is the real caller.
			services.AddRateLimiter(rateLimiterOptions =>
			{
				rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
				rateLimiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
					RateLimitPartition.GetFixedWindowLimiter(
						// A missing remote address is bucketed under a single shared key rather than
						// being waved through, so an unidentifiable caller cannot escape the limit.
						partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
						factory: _ => new FixedWindowRateLimiterOptions
						{
							PermitLimit = 600,
							Window = TimeSpan.FromMinutes(1),
							// No queueing: a caller over the limit is refused immediately rather than
							// parked, because holding requests open is itself a resource-exhaustion
							// vector.
							QueueLimit = 0,
							QueueProcessingOrder = QueueProcessingOrder.OldestFirst
						}));
			});
			services.Configure<RazorViewEngineOptions>(options => { options.ViewLocationExpanders.Add(new ErpViewLocationExpander()); });
			services.ConfigureOptions(typeof(WebConfigurationOptions));
			services.AddSingleton<IHostedService, ErpJobScheduleService>();
			services.AddSingleton<IHostedService, ErpJobProcessService>();
			services.AddScoped<CircuitHandler, SecuritityCircuitHandler>();
			return services;
		}

		public static IApplicationBuilder UseErp(this IApplicationBuilder app, List<JobType> additionalJobTypes = null, string configFolder = null)
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
				IWebHostEnvironment env = app.ApplicationServices.GetService<IWebHostEnvironment>();

				if (!ErpSettings.IsInitialized) {
					string configPath = "config.json";
					if (!string.IsNullOrWhiteSpace(configFolder))
						configPath = System.IO.Path.Combine(configFolder, configPath);

					// SECURITY - finding M-2 (CWE-20 improper input validation, CWE-798 hard-coded credentials),
					// OWASP A05 Security Misconfiguration.
					// THREAT: this is the single initialization path that feeds ErpSettings for every one of the
					// seven hosts, and it consumed the JSON file and nothing else. Config.json was therefore the
					// ONLY channel through which a secret could ever be supplied, which had two consequences:
					// the platform's own startup errors named environment variables that no provider could
					// satisfy, and blanking those files - the next step of this remediation - would have left
					// every host permanently unstartable with no way to supply a replacement value.
					//
					// Provider order deliberately mirrors the framework's own convention in
					// WebHost.CreateDefaultBuilder: JSON file first, then user secrets in development, then
					// environment variables LAST. Later providers win, so an operator-supplied environment
					// variable always overrides a value committed to the repository. That precedence IS the
					// control - it is what lets a deployment replace a shipped default without editing a tracked
					// file, and what makes the secret scrub survivable.
					var configurationBuilder = new ConfigurationBuilder().SetBasePath(env.ContentRootPath).AddJsonFile(configPath);

					if (env.IsDevelopment())
					{
						// The entry assembly is the host executable, so each host resolves its own secret store
						// rather than sharing this library's. optional: true means a host that has never run
						// 'dotnet user-secrets init' - i.e. carries no UserSecretsId - is skipped silently
						// instead of throwing during startup. Development only, by design: user secrets are a
						// developer convenience with no protection at rest and must never be a production channel.
						var entryAssembly = Assembly.GetEntryAssembly();
						if (entryAssembly != null)
							configurationBuilder.AddUserSecrets(entryAssembly, optional: true);
					}

					configurationBuilder.AddEnvironmentVariables();

					ErpSettings.Initialize(configurationBuilder.Build());
				}

				var defaultThreadCulture = CultureInfo.DefaultThreadCurrentCulture;
				var defaultThreadUICulture = CultureInfo.DefaultThreadCurrentUICulture;

				CultureInfo customCulture = new CultureInfo("en-US");
				customCulture.NumberFormat.NumberDecimalSeparator = ".";

				IErpService service = null;
				try
				{
					DbContext.CreateContext(ErpSettings.ConnectionString);

					service = app.ApplicationServices.GetService<IErpService>();

					var cfg = ErpAutoMapperConfiguration.MappingExpressions; // var cfg = new AutoMapper.Configuration.MapperConfigurationExpression();
					ErpAutoMapperConfiguration.Configure(cfg);
					ErpWebAutoMapperConfiguration.Configure(cfg);

					//this method append plugin automapper configuration
					service.SetAutoMapperConfiguration();

					//this should be called after plugin init
					ErpAutoMapper.Initialize(cfg);

					//we used en-US based culture settings for initialization and patch execution
					{
						CultureInfo.DefaultThreadCurrentCulture = customCulture;
						CultureInfo.DefaultThreadCurrentUICulture = customCulture;

						service.InitializeSystemEntities();

						CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
						CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
					}

					CheckCreateHomePage();

					service.InitializeBackgroundJobs(additionalJobTypes);

					ErpAppContext.Init(app.ApplicationServices);

					{
						//switch culture for patch executions and initializations
						CultureInfo.DefaultThreadCurrentCulture = customCulture;
						CultureInfo.DefaultThreadCurrentUICulture = customCulture;

						//this is called after automapper setup
						service.InitializePlugins(app.ApplicationServices);

						CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
						CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
					}

				}
				finally
				{
					DbContext.CloseContext();
					CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
					CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
				}

				//this is handled by background services now
				//if (service != null)
				//	service.StartBackgroundJobProcess();

				return app;
			}
		}

		public static IApplicationBuilder UseErpPlugin<T>(this IApplicationBuilder app) where T : ErpPlugin, new()
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				var plugin = new T();
				var service = app.ApplicationServices.GetService<IErpService>();
				service.Plugins.Add(plugin);
				return app;
			}
		}

		private static void CheckCreateHomePage()
		{
			var pageSrv = new PageService();

			var pageId = new Guid("560e77c5-6184-418e-8d49-51ae83c9773d");
			var name = @"home";
			var label = "Home";
			string iconClass = null;
			var system = false;
			var layout = @"";
			var weight = 10;
			var type = (PageType)((int)0);
			var isRazorBody = false;
			Guid? appId = null;
			Guid? entityId = null;
			Guid? nodeId = null;
			Guid? areaId = null;
			string razorBody = null;
			var labelTranslations = new List<TranslationResource>();

			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					if (!pageSrv.GetAll(transaction: DbContext.Current.Transaction, useCache: false).Any(x => x.Id == pageId))
					{
						pageSrv.CreatePage(pageId, name, label, labelTranslations, iconClass, system, weight, type, appId, entityId, nodeId, areaId, isRazorBody, razorBody, layout, WebVella.Erp.Database.DbContext.Current.Transaction);
						pageSrv.CreatePageBodyNode(new Guid("3a4e8154-9f48-4ba5-9e11-36fa5e7a80c9"), null, pageId, null, 1, "WebVella.Erp.Web.Components.PcApplications", "", @"""{}""", WebVella.Erp.Database.DbContext.Current.Transaction);
					}
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
}
