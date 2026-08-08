using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
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
		// Configuration key selecting the Content-Security-Policy delivery mode. Held as a constant so the
		// lookup and the diagnostic that names it cannot drift - a message quoting an unread key misdirects.
		private const string ContentSecurityPolicyReportOnlyConfigurationKey = "SecurityHeaders:ContentSecurityPolicyReportOnly";

		// Configuration section carrying the trusted reverse-proxy declaration consumed by
		// UseErpForwardedHeaders.
		private const string ForwardedHeadersConfigurationSection = "Settings:ForwardedHeaders";

		// Separators accepted in the KnownProxies and KnownNetworks lists. Both, because operators supply
		// these through environment variables, where a semicolon is familiar, and through JSON, where a comma is.
		private static readonly char[] ForwardedHeadersListSeparators = new[] { ',', ';' };

		// Default number of forwarded entries consumed from a single X-Forwarded-For header.
		// THREAT ADDRESSED - CWE-348 (use of less trusted source): the header is a LIST appended to by every
		// hop, and only the entry added by the nearest trusted proxy is trustworthy. One entry per hop IS the
		// control - raise this only to a KNOWN number of trusted proxies sitting in front of the application.
		private const int DefaultForwardedHeadersForwardLimit = 1;

		// The platform's session contract, applied identically by all seven hosts through
		// ConfigureErpAuthenticationCookie so no host can drift from it.
		private const double AuthenticationCookieLifetimeMinutes = 1440;

		// Directory holding the Data Protection key ring. Deliberately OPTIONAL: when the key is absent the
		// framework's own default location stands, so configuring nothing cannot break a working deployment.
		private const string DataProtectionKeyDirectoryConfigurationKey = "Settings:DataProtectionKeyDirectory";

		// The configuration key the framework's HTTPS redirection middleware reads for the public HTTPS port.
		// ASPNETCORE_HTTPS_PORT, HTTPS_PORT and an ANCM site's ASPNETCORE_ANCM_HTTPS_PORT all land on it. It
		// configures the REDIRECT TARGET only and never binds a listener. The PLURAL spelling is a different
		// key entirely - see the pair below.
		private const string HttpsRedirectionPortConfigurationKey = "HTTPS_PORT";

		// The key the ASP.NET Core Module writes when the IIS site hosting this process has an HTTPS binding.
		// Treated differently from the key above on purpose: it is produced by the module rather than asserted
		// by an operator, so it reports an OBSERVED topology. The redirection middleware consults it second.
		private const string AncmHttpsPortConfigurationKey = "ANCM_HTTPS_PORT";

		// TCP port bounds, used to range-check every port read from configuration: a value outside them cannot
		// name a listening endpoint, so accepting one would accept "there is HTTPS somewhere" from a typo.
		private const int MinimumTcpPort = 1;
		private const int MaximumTcpPort = 65535;

		// The hosting-layer port keys, WebHostDefaults.HttpPortsKey and WebHostDefaults.HttpsPortsKey;
		// ASPNETCORE_HTTP_PORTS and ASPNETCORE_HTTPS_PORTS land on them. They are NOT Kestrel keys and NOT
		// synonyms of the singular redirect key above: GenericWebHostService expands them into addresses, but
		// only when 'urls' is empty and only under the GENERIC host. All seven of this platform's hosts are
		// built by WebHost.CreateDefaultBuilder(args).UseStartup<Startup>(), whose legacy IWebHost resolves
		// addresses from 'urls' alone, so here they are visible in configuration and consumed by nothing.
		// They are held so the transport check below can name the key an operator set and give the remedy, and
		// are deliberately NOT accepted as evidence of an HTTPS path, which would make that check fail open.
		private const string HttpsPortsConfigurationKey = "https_ports";
		private const string HttpPortsConfigurationKey = "http_ports";

		// Kestrel's declarative endpoint section, consulted alongside the bound addresses so an operator who
		// declares HTTPS there rather than through ASPNETCORE_URLS is never told they have no HTTPS path.
		private const string KestrelEndpointsConfigurationSection = "Kestrel:Endpoints";

		// Scheme prefix identifying an endpoint that can carry an HTTPS request.
		private const string HttpsUriSchemePrefix = "https://";

		public static IServiceCollection AddErp(this IServiceCollection services)
		{
			services.AddSingleton<IErpService, ErpService>();
			services.AddTransient<AuthService>();
			services.AddScoped<ErpRequestContext>();

			// THREAT ADDRESSED - finding M-01 (OWASP A05: Security Misconfiguration): SecurityHeadersMiddleware
			// existed but was unreachable - no host registered its options and none inserted it - so not one of
			// the seven mandated security response headers was emitted. Registering here, at the platform's single
			// canonical service-registration extension, means all seven hosts inherit it from one edit, and the
			// options type carries the mandated Content-Security-Policy as a const with no setter, so this cannot
			// weaken it. REGISTRATION ONLY: the middleware's pipeline POSITION must never be set here, because
			// UseErp runs late while UseStaticFiles terminates the pipeline for a matched asset, so each host
			// calls UseSecurityHeaders() early in its own Configure method or static responses ship bare.
			// Exactly ONE member is bound - the report-only/enforce switch - from
			// "SecurityHeaders:ContentSecurityPolicyReportOnly"; the policy TEXT stays unbindable so no
			// configuration source can inject 'unsafe-inline' and void the header. ABSENT or blank keeps the
			// compiled report-only default, the mandated shipping posture; PRESENT but unparseable ABORTS startup,
			// because either guess is wrong. The value is never echoed, only the key name.
			services.AddOptions<SecurityHeadersOptions>()
				.Configure<IConfiguration>((securityHeadersOptions, configuration) =>
				{
					string configuredReportOnly = configuration?[ContentSecurityPolicyReportOnlyConfigurationKey];
					if (string.IsNullOrWhiteSpace(configuredReportOnly))
					{
						return;
					}

					if (!bool.TryParse(configuredReportOnly, out bool contentSecurityPolicyReportOnly))
					{
						throw new InvalidOperationException(
							$"WebVella ERP startup aborted - configuration key '{ContentSecurityPolicyReportOnlyConfigurationKey}' " +
							$"(environment variable '{ContentSecurityPolicyReportOnlyConfigurationKey.Replace(":", "__", StringComparison.Ordinal)}') " +
							"must be either 'true' (emit Content-Security-Policy-Report-Only) or 'false' (emit the enforcing " +
							"Content-Security-Policy). The supplied value could not be interpreted as a boolean and has been " +
							"rejected rather than guessed, because either guess would be wrong: assuming report-only would leave " +
							"the policy unenforced while the operator believed otherwise, and assuming enforcing would block the " +
							"platform's inline scripts. Remove the key to keep the shipping default of report-only. See " +
							"docs/security/secure-configuration.md.");
					}

					securityHeadersOptions.ContentSecurityPolicyReportOnly = contentSecurityPolicyReportOnly;
				});

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive information) and
			// CWE-614 (sensitive cookie without 'Secure'), OWASP A02 / A05. Every host called app.UseHsts() but
			// none configured HstsOptions, so the framework default of thirty days without subdomains reached the
			// wire: HstsMiddleware and SecurityHeadersMiddleware both assign Strict-Transport-Security by indexer
			// and HstsMiddleware runs later, so it decided the value. Pinning the framework's own options here
			// makes both writers emit the identical mandated string, so the overwrite is a no-op in either order.
			// MaxAge 365 days and IncludeSubDomains true are mandated; Preload is false DELIBERATELY, because it
			// is not in the mandated value and preload-list submission is effectively irreversible. ExcludedHosts
			// stays at the framework loopback default, matching SecurityHeadersMiddleware's Development guard.
			services.AddHsts(hstsOptions =>
			{
				hstsOptions.MaxAge = TimeSpan.FromDays(365);
				hstsOptions.IncludeSubDomains = true;
				hstsOptions.Preload = false;
			});

			// THREAT ADDRESSED - finding M-02, CWE-614 (sensitive cookie in HTTPS session without the 'Secure'
			// attribute) and CWE-1004, OWASP A05: the antiforgery cookie was left at the framework default of
			// CookieSecurePolicy.None, so the request-verification token - what authorises every state-changing
			// Razor Pages POST, the login form included - travelled in plaintext whenever a client reached the site
			// over HTTP, where an attacker on the network path could capture it and pair it with a session. No host
			// calls AddAntiforgery, so one IConfigureOptions registration here is the only edit reaching all seven;
			// only SecurePolicy is set, so token validation, the cookie name and its SameSite=Strict default are
			// untouched and no working request is affected.
			// Always OUTSIDE Development; SameAsRequest INSIDE it, because an unconditional Always makes the
			// platform UNUSABLE over plain HTTP: DefaultAntiforgery.CheckSSLConfig validates its own configuration
			// on every token issue and throws whenever Request.IsHttps is false, so every Razor Pages form - login
			// included - answered HTTP 500 and there was no way to authenticate. This is the same Development
			// carve-out every host applies to UseHsts and UseHttpsRedirection, and SameAsRequest rather than None
			// keeps the attribute on a Development request that IS over HTTPS.
			services.AddOptions<Microsoft.AspNetCore.Antiforgery.AntiforgeryOptions>()
				.Configure<IHostEnvironment>((antiforgeryOptions, hostEnvironment) =>
				{
					// Fail-safe direction: an unresolvable environment is treated as NOT Development, so
					// the hardened value is the default and a missing or misspelled ASPNETCORE_ENVIRONMENT
					// can never silently relax the production posture.
					bool isDevelopment = hostEnvironment != null
						&& string.Equals(hostEnvironment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase);

					antiforgeryOptions.Cookie.SecurePolicy = isDevelopment
						? CookieSecurePolicy.SameAsRequest
						: CookieSecurePolicy.Always;
				});

			// THREAT ADDRESSED - finding H-16, CWE-307 (improper restriction of excessive authentication
			// attempts), OWASP A07: LoginThrottleService existed but was never registered and never resolved, so
			// the mandated five-attempt lockout was dead code. Registering it here means all seven hosts inherit
			// it from one edit. Singleton is REQUIRED, not convenient: the failure counters live in the service's
			// own in-process store, so a transient or scoped lifetime would hand every request an empty set of
			// counters and the threshold would never be reached. The store is released with the process.
			services.AddSingleton<LoginThrottleService>();

			// SECURITY (CWE-522 insufficiently protected credentials, CWE-565 reliance on cookies without
			// integrity checking), OWASP A05:2021: nothing configured Data Protection at all, so the key ring
			// protecting every authentication ticket, antiforgery token and Blazor circuit descriptor was left to
			// framework defaults - and two of those defaults fail in opposite directions.
			// FIRST, the application discriminator defaults to the CONTENT ROOT PATH, a deployment location rather
			// than an identity: republishing to another directory invalidates every outstanding ticket, while two
			// hosts sharing a content root become mutually decryptable. Binding it to the application name makes
			// isolation a property of WHICH application this is, and the seven hosts have seven distinct names.
			// SECOND, the default ring is written unencrypted under the running account's profile; in a container
			// that directory is often not persisted, so every restart mints a fresh ring and logs every user out.
			// The persistence half is OPT-IN while the discriminator half is unconditional: a discriminator cannot
			// break anything, whereas redirecting the ring to a path this code invented would move an existing
			// deployment's keys out from under it. Encrypting at rest needs a certificate this registration cannot
			// assume - see docs/security/secure-configuration.md.
			services.AddDataProtection();

			services.AddOptions<DataProtectionOptions>()
				.Configure<IHostEnvironment>((dataProtectionOptions, hostEnvironment) =>
				{
					// Guarded rather than assigned unconditionally: an empty application name would produce an EMPTY
					// discriminator, materially WORSE than the default it replaces, because every application with an
					// empty discriminator shares one purpose chain. Leaving the default is the fail-safe direction.
					if (!string.IsNullOrWhiteSpace(hostEnvironment?.ApplicationName))
					{
						dataProtectionOptions.ApplicationDiscriminator = hostEnvironment.ApplicationName;
					}
				});

			services.AddOptions<KeyManagementOptions>()
				.Configure<IConfiguration, ILoggerFactory>((keyManagementOptions, configuration, loggerFactory) =>
				{
					string configuredKeyDirectory = configuration?[DataProtectionKeyDirectoryConfigurationKey];
					if (string.IsNullOrWhiteSpace(configuredKeyDirectory))
					{
						return;
					}

					// Created when absent so a fresh deployment need not pre-create it, and deliberately NOT wrapped in a
					// catch: a key ring that silently fell back to the profile directory would leave an operator
					// believing the ring is durable when it is not.
					DirectoryInfo keyDirectory = Directory.CreateDirectory(configuredKeyDirectory);
					keyManagementOptions.XmlRepository = new FileSystemXmlRepository(keyDirectory, loggerFactory);
				});

			// THREAT ADDRESSED - session hijacking, CWE-613 (insufficient session expiration), OWASP A07: the
			// cookie authentication ticket is entirely self-contained, so signing out only deleted the cookie in
			// the browser that asked for it. A ticket copied beforehand - from a shared machine, a proxy log, a
			// backup, or exfiltrated by script - stayed valid for its whole lifetime and nothing could stop it.
			// NO REGISTRATION IS NEEDED FOR THE REVOCATION STORE, and its absence is deliberate: the store is
			// process-wide static (Services/SessionRevocationService.cs) because the bearer-token validators are
			// static code with no service provider in reach, so an injected singleton confined the control to
			// consumers able to resolve one - and an unresolvable service read as "not revoked".

			// The control only exists once the session identifier is CONSULTED, on every authenticated request
			// rather than at the login page. This is that point: the framework's own ticket-validation hook, which
			// runs for each request presenting a cookie, before the endpoint sees the principal.
			// AuthService.Authenticate mints a fresh CLAIM_SESSION_ID into every ticket and LogoutAsync revokes it,
			// so after a sign-out every other copy of the same ticket is rejected on its next request.
			// PostConfigureAll rather than Configure, for three reasons: it applies to EVERY named cookie options
			// instance, so a host adding a scheme is covered without a further edit; it runs AFTER each host's own
			// AddCookie callback, so a host cannot overwrite the hook by assigning Events itself; and it keeps the
			// control in the single canonical registration extension. CAPTURING AND INVOKING THE PREVIOUS DELEGATE
			// FIRST IS LOAD-BEARING, NOT DEFENSIVE: ConfigureErpAuthenticationCookie, which all seven hosts pass to
			// AddCookie, assigns AuthService.ValidateSessionHorizonAsync - the absolute horizon that stops a slid
			// cookie living for ever - so dropping the capture would overwrite it and reduce the sliding 24-hour
			// idle window to an unbounded session. The horizon runs first, and its rejection is honoured below.
			services.PostConfigureAll<CookieAuthenticationOptions>(cookieOptions =>
			{
				cookieOptions.Events ??= new CookieAuthenticationEvents();

				var previouslyConfigured = cookieOptions.Events.OnValidatePrincipal;
				cookieOptions.Events.OnValidatePrincipal = async validationContext =>
				{
					if (previouslyConfigured != null)
						await previouslyConfigured(validationContext);

					// A principal the host's own delegate already rejected is left rejected. RejectPrincipal
					// nulls Principal, so this is the check for "someone upstream already said no".
					if (validationContext.Principal == null)
						return;

					// SECURITY (CWE-613 insufficient session expiration, CWE-636 not failing securely), OWASP A07: this
					// pair of checks used to RETURN - accepting the principal - whenever the ticket carried no parseable
					// session identifier, which made revocation opt-in from the ticket's own point of view: a ticket
					// without the claim was never revocable, so "log out everywhere" silently did not apply to it. It
					// FAILS CLOSED instead, with the same rejection the horizon check performs. AuthService.Authenticate
					// stamps the identifier in the same operation that mints the ticket, so a ticket without it is not
					// one this build issues, and bearer principals are refused by their own validators rather than here.
					// Cost, stated plainly: sessions held from before this deployment are signed out once. The claim
					// travels inside the encrypted, signed ticket, so a client can neither strip nor forge one.
					var sessionClaim = validationContext.Principal.FindFirst(AuthService.CLAIM_SESSION_ID);
					if (sessionClaim == null || !Guid.TryParse(sessionClaim.Value, out var sessionId) || sessionId == Guid.Empty)
					{
						validationContext.RejectPrincipal();
						await SignOutQuietlyAsync(validationContext);
						return;
					}

					// Consulted through the process-wide store rather than a resolved service instance. The previous
					// lookup treated an unresolvable service as "not revoked", so a host that had not registered it
					// accepted every revoked ticket while appearing to enforce revocation. There is no null case now.
					if (!SessionRevocationService.IsSessionIdentifierRevoked(sessionId))
						return;

					// Reject first, then clear the cookie. Ordered this way the CURRENT request is already
					// unauthenticated even if the sign-out itself fails, so the security outcome does not
					// depend on the cleanup succeeding.
					validationContext.RejectPrincipal();
					await SignOutQuietlyAsync(validationContext);
				};
			});

			// THREAT ADDRESSED - finding H-16, CWE-307 (improper restriction of excessive authentication attempts)
			// and CWE-770 (allocation without limits), OWASP A07: no transport-level request throttling existed
			// anywhere in the platform, so a single client could issue unlimited requests, including unlimited
			// POSTs to the login page and the anonymous token endpoints. This is the transport-level layer only;
			// the per-account login lockout is a separate, narrower control at the login entry point. A fixed
			// window partitioned by remote address is the least invasive option that closes the gap - shared
			// framework, so no package, no store, no schema change - and the permit limit is deliberately generous,
			// because one page issues on the order of twenty-five requests.
			// The partition key comes from DescribeRemoteAddress, which reads the address AFTER the trusted
			// forwarded-headers middleware has had its chance to replace it (CWE-348 use of less trusted source):
			// read straight off the connection, every caller behind a reverse proxy collapsed into ONE partition
			// keyed on the proxy, inverting the control so ordinary users starve each other while an abuser hides
			// in the crowd. The trust half lives in UseErpForwardedHeaders, which honours no forwarded address
			// until an operator names the proxies that may send one.
			services.AddRateLimiter(rateLimiterOptions =>
			{
				rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
				rateLimiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
					RateLimitPartition.GetFixedWindowLimiter(
						// A missing remote address is bucketed under a single shared key rather than
						// being waved through, so an unidentifiable caller cannot escape the limit.
						partitionKey: DescribeRemoteAddress(httpContext),
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

		// The single cookie-clearing step used by both refusals in the ticket-validation hook above, so the
		// two cannot diverge. The principal is ALREADY rejected before this is called, which is what makes
		// swallowing safe: the request is unauthenticated whether or not the deletion header reaches the
		// response, and an exception escaping a validation hook would 500 every request presenting a cookie.
		private static async Task SignOutQuietlyAsync(CookieValidatePrincipalContext validationContext)
		{
			try
			{
				await validationContext.HttpContext.SignOutAsync(validationContext.Scheme.Name);
			}
			catch (Exception)
			{
				// Deliberately silent - see above. Rejection has already taken effect.
			}
		}

		public static IApplicationBuilder UseErp(this IApplicationBuilder app, List<JobType> additionalJobTypes = null, string configFolder = null)
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
				IWebHostEnvironment env = app.ApplicationServices.GetService<IWebHostEnvironment>();

				if (!ErpSettings.IsInitialized) {
					// DEFECT ADDRESSED (CWE-16, OWASP A05:2021 Security Misconfiguration) on the single initialization
					// path for all seven hosts. The tracked file is Config.json, which is the name the SDK copies to the
					// output, but this chain asked for lower-case config.json: the same file on a case-insensitive
					// filesystem, a different one on Linux - and because this JSON source is deliberately NON-optional,
					// the host aborted before AddEnvironmentVariables below could supply any secret. Deployments only
					// worked because publish tooling wrote a lower-case duplicate, which is why the probe PREFERS the
					// correctly cased name and falls back rather than switching.
					string configPath = "Config.json";
					string lowerCaseConfigPath = "config.json";
					if (!string.IsNullOrWhiteSpace(configFolder))
					{
						configPath = System.IO.Path.Combine(configFolder, configPath);
						lowerCaseConfigPath = System.IO.Path.Combine(configFolder, lowerCaseConfigPath);
					}

					// Resolved against AppContext.BaseDirectory, which is EXACTLY the base path the builder below sets,
					// so the probe tests the same location the provider will read. It deliberately does NOT use
					// env.ContentRootPath: WebHost.CreateDefaultBuilder defaults that to Directory.GetCurrentDirectory(),
					// so probing it would test whatever working directory the process was launched with, making this
					// fallback both unreliable and unsound - a file found in an attacker-writable working directory would
					// decide which path is selected. An absolute configFolder is honoured unchanged by Path.Combine.
					if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
						&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, lowerCaseConfigPath)))
						configPath = lowerCaseConfigPath;

					// SECURITY - findings C-04, H-04 and H-05 (CWE-798 use of hard-coded credentials, CWE-321 use of a
					// hard-coded cryptographic key), OWASP A05 Security Misconfiguration: this single initialization path
					// feeds ErpSettings for all seven hosts and consumed the JSON file and nothing else, so Config.json was
					// the ONLY channel a secret could arrive through - the platform's own startup errors named environment
					// variables no provider could satisfy, and blanking those files would have left every host unstartable.
					// Provider ORDER is the control, not an incidental detail. Later providers win, so the tracked JSON file
					// stays FIRST and environment variables come immediately AFTER: the shipped secret values are blanked
					// to empty strings rather than removed, so only a later provider can put a real secret back, and
					// reversing the two would let the blank string clobber the operator's variable and abort startup. Keys
					// use the framework's section separator - Settings__ConnectionString, Settings__EncryptionKey,
					// Settings__Jwt__Key; the complete list is in docs/security/secure-configuration.md. The JSON source
					// stays NON-optional because the files are blanked and never deleted, so an absent one must fail loudly.
					// CWE-706 (use of an incorrectly resolved name): the base path is AppContext.BaseDirectory, where both
					// build and publish place Config.json - NOT env.ContentRootPath, which defaults to the launch working
					// directory and would let whoever controls it decide which Config.json the platform trusts.
					var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);
					configurationBuilder.AddEnvironmentVariables();

					if (env.IsDevelopment())
					{
						// User secrets come LAST, and only in Development, so a developer's own store outranks an ambient
						// machine-wide environment variable. It is never load-bearing: outside Development the provider is not
						// added at all, because the store sits unencrypted on disk, so every non-development chain is exactly
						// JSON file then environment variables. The store resolves FROM the entry assembly's
						// UserSecretsIdAttribute, so each host resolves its own rather than this library's - this library
						// declares no UserSecretsId and must not - and all eight executable manifests declare a stable id,
						// without which this call reads nothing and cannot even say so. optional: true is stated explicitly
						// because the tolerance is deliberate: the fail-fast that matters is ErpSettings' secret validation.
						var entryAssembly = Assembly.GetEntryAssembly();
						if (entryAssembly != null)
							configurationBuilder.AddUserSecrets(entryAssembly, optional: true);
					}

					ErpSettings.Initialize(configurationBuilder.Build());
				}

				// SECURITY (OWASP A05: Security Misconfiguration): force the security-header options to materialise
				// here, immediately after the configuration provider chain is in place, so the
				// Content-Security-Policy posture is parsed and validated at startup - otherwise the binding delegate
				// first runs when the pipeline is built and a malformed value surfaces as an opaque middleware
				// construction failure on the first request. The resolved instance is inspected rather than discarded
				// so options that register but resolve to null are caught here too.
				IOptions<Middleware.SecurityHeadersOptions> securityHeaderOptions =
					app.ApplicationServices.GetService<IOptions<Middleware.SecurityHeadersOptions>>();

				if (securityHeaderOptions?.Value == null)
				{
					throw new InvalidOperationException(
						"Security response header options could not be resolved. AddErp() must be called during ConfigureServices before UseErp() is called, so that the Content-Security-Policy posture configured through '"
						+ ContentSecurityPolicyReportOnlyConfigurationKey
						+ "' is applied.");
				}

				// THREAT ADDRESSED - the availability half of findings M-02 and H-15 (CWE-16 configuration, CWE-1188
				// insecure default, OWASP A05:2021): the antiforgery and authentication cookies are both Secure-only by
				// design - relaxing either is the CWE-614 vulnerability those findings remediate - so a deployment with
				// no HTTPS request path answers 500 from DefaultAntiforgery.CheckSSLConfig on EVERY form-bearing page,
				// /login included, while still starting healthy, redirecting / and emitting all seven headers, so
				// health probes and header audits pass while nobody can sign in. The posture is consulted at startup in
				// the same shape as ErpSettings' required-secret validation, and deliberately AFTER it: a deployment
				// missing both must still fail on the secret, which the operator has to fix first.
				ValidateTransportSecurityPosture(app, configuration, env);

				var defaultThreadCulture = CultureInfo.DefaultThreadCurrentCulture;
				var defaultThreadUICulture = CultureInfo.DefaultThreadCurrentUICulture;

				CultureInfo customCulture = new CultureInfo("en-US");
				customCulture.NumberFormat.NumberDecimalSeparator = ".";

				IErpService service = null;
				try
				{
					DbContext.CreateContext(ErpSettings.ConnectionString);

					service = app.ApplicationServices.GetService<IErpService>();

					var cfg = ErpAutoMapperConfiguration.MappingExpressions;
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

				return app;
			}
		}

		// Enables trusted reverse-proxy forwarded-header processing, and nothing else.
		//
		// SECURITY (CWE-348 use of less trusted source, CWE-290 authentication bypass by spoofing, CWE-307
		// improper restriction of excessive attempts), OWASP A05: no forwarded-header processing existed
		// anywhere in the platform, so behind a reverse proxy - the topology WebVella.Erp.Site's own web.config
		// describes - three controls degraded at once. The request-rate partition collapsed onto the proxy's
		// address, so no individual abuser could be isolated; the per-address half of the login lockout keyed
		// on the proxy too, so one attacker's failures counted against every other user of it; and
		// Request.IsHttps read false for requests the client actually made over TLS, which HTTPS redirection
		// and the Secure cookie policy both read.
		//
		// DENY BY DEFAULT, EXPRESSED AS "DO NOT REGISTER" RATHER THAN "REGISTER WITH AN EMPTY LIST" - the
		// load-bearing detail of the whole fix. ForwardedHeadersMiddleware checks the peer against the trusted
		// lists only when one of them is non-empty, so registering it with BOTH empty disables the check and
		// the middleware honours X-Forwarded-For from ANY peer on the internet: the exact spoofing primitive
		// this finding is about, installed by the fix meant to prevent it. An unconfigured deployment therefore
		// gets no middleware, X-Forwarded-* is ignored and RemoteIpAddress stays the true transport peer.
		// Operators opt in by naming their proxies - Settings__ForwardedHeaders__KnownProxies and/or
		// __KnownNetworks - and the framework's loopback defaults are CLEARED first, so the trust set is exactly
		// what was declared. Pipeline position is the caller's responsibility and is documented at every call
		// site: this must run before UseSecurityHeaders, UseHsts, UseHttpsRedirection and UseRateLimiter, each
		// of which reads the scheme or the address it corrects.
		public static IApplicationBuilder UseErpForwardedHeaders(this IApplicationBuilder app)
		{
			ArgumentNullException.ThrowIfNull(app);

			IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
			ForwardedHeadersOptions options = BuildForwardedHeadersOptions(configuration);

			// No trusted proxy declared: forwarded headers are not processed at all. See above for why
			// this is a non-registration rather than an empty allow-list.
			if (options == null)
				return app;

			app.UseForwardedHeaders(options);
			return app;
		}

		// Builds the forwarded-header options from configuration, or returns null when no proxy is trusted.
		// Malformed entries abort startup rather than being skipped: silently dropping a mistyped proxy
		// address would leave an operator believing the caller's real address was being recovered while the
		// rate limiter and the login lockout continued to key on the proxy. The offending entry is named
		// because a network address is operator-supplied topology, not a secret.
		private static ForwardedHeadersOptions BuildForwardedHeadersOptions(IConfiguration configuration)
		{
			if (configuration == null)
				return null;

			IConfiguration section = configuration.GetSection(ForwardedHeadersConfigurationSection);

			List<IPAddress> knownProxies = ParseKnownProxies(section["KnownProxies"]);
			List<System.Net.IPNetwork> knownNetworks = ParseKnownNetworks(section["KnownNetworks"]);

			if (knownProxies.Count == 0 && knownNetworks.Count == 0)
				return null;

			var options = new ForwardedHeadersOptions
			{
				// Only the two headers the platform actually consumes are honoured. X-Forwarded-Host is deliberately
				// NOT included: accepting it would let a trusted proxy - or anything that compromised it - rewrite
				// the host this application believes it is serving, a host-header injection and absolute-URL
				// poisoning primitive with no offsetting benefit here.
				ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
					| Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto,
				ForwardLimit = ParseForwardLimit(section["ForwardLimit"])
			};

			// The framework seeds these with loopback entries. They are cleared so that the trust set is
			// exactly the declared one - an inherited entry nobody wrote down is precisely the kind of
			// implicit trust this finding is about.
			options.KnownProxies.Clear();
			options.KnownIPNetworks.Clear();

			foreach (IPAddress knownProxy in knownProxies)
				options.KnownProxies.Add(knownProxy);

			foreach (System.Net.IPNetwork knownNetwork in knownNetworks)
				options.KnownIPNetworks.Add(knownNetwork);

			return options;
		}

		private static List<IPAddress> ParseKnownProxies(string configuredValue)
		{
			var parsed = new List<IPAddress>();
			foreach (string entry in SplitForwardedHeadersList(configuredValue))
			{
				if (!IPAddress.TryParse(entry, out IPAddress address))
					throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:KnownProxies contains '{entry}', which is not a valid IP address. Supply a comma or semicolon separated list of the reverse-proxy addresses this application may trust, or remove the setting to disable forwarded-header processing entirely.");

				parsed.Add(address);
			}

			return parsed;
		}

		private static List<System.Net.IPNetwork> ParseKnownNetworks(string configuredValue)
		{
			var parsed = new List<System.Net.IPNetwork>();
			foreach (string entry in SplitForwardedHeadersList(configuredValue))
			{
				// System.Net.IPNetwork rather than the Microsoft.AspNetCore.HttpOverrides type of the same name, and
				// KnownIPNetworks rather than KnownNetworks, because both older spellings are obsolete in this
				// framework version and using them would introduce new build warnings.
				if (!System.Net.IPNetwork.TryParse(entry, out System.Net.IPNetwork network))
					throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:KnownNetworks contains '{entry}', which is not a valid CIDR network. Supply a comma or semicolon separated list such as '10.0.0.0/8;192.168.0.0/16', or remove the setting to disable forwarded-header processing entirely.");

				parsed.Add(network);
			}

			return parsed;
		}

		private static int ParseForwardLimit(string configuredValue)
		{
			if (string.IsNullOrWhiteSpace(configuredValue))
				return DefaultForwardedHeadersForwardLimit;

			// A non-positive or unparseable limit is rejected rather than coerced. ForwardLimit is nullable in the
			// framework and null means "consume every entry in the header", which hands the caller control of the
			// address this application believes it is talking to; that value is unreachable from configuration.
			if (!int.TryParse(configuredValue.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int limit) || limit < 1)
				throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:ForwardLimit must be a positive whole number naming how many trusted proxies sit in front of this application. Remove the setting to use the default of {DefaultForwardedHeadersForwardLimit}.");

			return limit;
		}

		private static IEnumerable<string> SplitForwardedHeadersList(string configuredValue)
		{
			if (string.IsNullOrWhiteSpace(configuredValue))
				return Enumerable.Empty<string>();

			return configuredValue
				.Split(ForwardedHeadersListSeparators, StringSplitOptions.RemoveEmptyEntries)
				.Select(entry => entry.Trim())
				.Where(entry => entry.Length > 0);
		}

		// Refuses - or, in Development only, reports - a deployment in which no request can ever reach this
		// application over HTTPS. The threat is stated at the call site in UseErp.
		// The decision is evidence-based rather than heuristic: any ONE of the channels below gives this process
		// a way to SEE an HTTPS request, and finding one ends the check silently. Nothing is inferred from the
		// environment name alone, and no cookie policy is weakened.
		// SECURITY (CWE-1188 insecure default initialization, CWE-755), OWASP A05:2021 - three ways this check
		// could pass, or merely warn, on exactly the posture it exists to prevent are closed. Any non-blank
		// HTTPS_PORT satisfied it, though that key only selects the TARGET of a redirect and was never parsed;
		// merely DECLARING a trusted proxy satisfied it, though trusting a proxy says who may be believed
		// rather than that anything terminates TLS, so it now counts only with a declared public HTTPS port;
		// and when NO endpoints were declared the identical diagnosis was a warning and startup continued,
		// waving through the most likely broken deployment there is, because the server's own default binding
		// is PLAINTEXT. Outside Development an unproven posture is refused; Development stays exempt because
		// its antiforgery cookie follows the request scheme, and the auth cookie is Secure-only everywhere.
		private static void ValidateTransportSecurityPosture(IApplicationBuilder app, IConfiguration configuration, IWebHostEnvironment env)
		{
			ICollection<string> declaredEndpoints = app?.ServerFeatures
				?.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()?.Addresses;

			// 1. An HTTPS endpoint this process binds itself.
			if (declaredEndpoints != null && declaredEndpoints.Any(endpoint =>
				endpoint != null && endpoint.StartsWith(HttpsUriSchemePrefix, StringComparison.OrdinalIgnoreCase)))
				return;

			// 2. An HTTPS endpoint declared in Kestrel's own configuration section instead.
			if (IsKestrelHttpsEndpointDeclared(configuration))
				return;

			// Both ports are parsed and range-checked here rather than at their point of use, so a
			// mistyped value aborts startup with a message naming it instead of silently counting as
			// evidence or silently disarming the redirect.
			int? ancmHttpsPort = ReadPublicHttpsPort(configuration, AncmHttpsPortConfigurationKey);
			int? redirectionHttpsPort = ReadPublicHttpsPort(configuration, HttpsRedirectionPortConfigurationKey);

			// 3. A public HTTPS port supplied by the ASP.NET Core Module. This one IS evidence on its own: the
			// module writes it only when the IIS site in front of this process actually has an HTTPS binding, so
			// it reports an observed topology rather than an operator's assertion. In-process hosting also
			// preserves the original request scheme, so Request.IsHttps is true and the Secure cookie policy is
			// satisfied without any forwarded-header configuration.
			if (ancmHttpsPort.HasValue)
				return;

			// 4. A trusted reverse proxy that terminates TLS and forwards the scheme, TOGETHER WITH the public
			// HTTPS port. The option builder is REUSED rather than its keys re-read, so "a proxy is trusted" here
			// means exactly what UseErpForwardedHeaders acts on. Neither half suffices alone: a trusted proxy that
			// terminates plaintext leaves this host unusable, and a redirect port with nothing trusted in front of
			// it means X-Forwarded-Proto is ignored. Whether the proxy sends it cannot be known at startup.
			if (redirectionHttpsPort.HasValue && BuildForwardedHeadersOptions(configuration) != null)
				return;

			bool endpointsWereDeclared = declaredEndpoints != null && declaredEndpoints.Count > 0;
			bool isDevelopment = env != null && env.IsDevelopment();

			// The plural hosting-layer port keys, read for the DIAGNOSTIC only - never as evidence, for the reason
			// recorded at their declaration. An operator who set one has already decided to serve HTTPS and
			// believes they said so, so the message they need is not "no HTTPS path was found" but "this hosting
			// model does not read that key, here is the one it does read".
			string configuredHttpsPorts = configuration?[HttpsPortsConfigurationKey];
			string configuredHttpPorts = configuration?[HttpPortsConfigurationKey];
			bool pluralPortKeyWasSet = !string.IsNullOrWhiteSpace(configuredHttpsPorts)
				|| !string.IsNullOrWhiteSpace(configuredHttpPorts);

			// The key NAME an operator set, so the message can quote it back. The value is not echoed: a
			// port is not a secret, but naming only the key keeps this message's one rule - no
			// configuration VALUE is ever printed (CWE-532) - true without exception.
			string pluralPortKeyNote = string.Empty;
			if (pluralPortKeyWasSet)
			{
				pluralPortKeyNote = $"{Environment.NewLine}  '"
					+ (!string.IsNullOrWhiteSpace(configuredHttpsPorts)
						? "ASPNETCORE_HTTPS_PORTS"
						: "ASPNETCORE_HTTP_PORTS")
					+ "' IS set, and it is the reason this message may look wrong. That variable supplies the hosting-layer key '"
					+ (!string.IsNullOrWhiteSpace(configuredHttpsPorts)
						? HttpsPortsConfigurationKey
						: HttpPortsConfigurationKey)
					+ "', which binds a listener only under the GENERIC host - it is resolved by GenericWebHostService, and only when 'urls' is empty. This host is built by WebHost.CreateDefaultBuilder, whose legacy IWebHost resolves its addresses from 'urls' alone, so the value is visible in configuration and consumed by nothing: no endpoint is bound and no redirect is armed. Translate it to 'ASPNETCORE_URLS=https://*:<that port>' and supply a certificate, which is the first option below. Do not confuse it with the singular 'ASPNETCORE_HTTPS_PORT', which sets the redirect TARGET and likewise binds nothing.";
			}

			// The endpoint list is operator-supplied deployment topology, not a secret - the same reasoning that
			// lets the KnownProxies diagnostic name the offending address - so quoting it makes this message
			// actionable rather than a rule restatement. No configuration VALUE is ever echoed (CWE-532).
			string observedEndpoints = endpointsWereDeclared
				? string.Join(", ", declaredEndpoints)
				: "none declared, so the server's own defaults decide them";

			// One sentence explaining why this message is a refusal or a report, so the two paths can never
			// be confused for one another in a log.
			string closingNote;
			if (isDevelopment)
			{
				closingNote = "Development is exempt from this startup refusal, so the host will start and its antiforgery cookie will follow the request scheme; local plaintext sign-in remains supported. Configure HTTPS to exercise the production transport posture.";
			}
			else if (endpointsWereDeclared)
			{
				closingNote = "Startup is refused rather than left to fail one request at a time, which is how this misconfiguration used to surface. Development is exempt from the refusal.";
			}
			else
			{
				// Previously a warning. It is a refusal now because "not declared" is not an unknown
				// posture in practice: it means the server binds its own defaults, and those are plaintext,
				// which is the exact condition this check exists to prevent.
				closingNote = "No endpoint is declared in configuration, so this process will bind the server's own defaults - which are plaintext - and no sign-in would be possible. Startup is therefore refused rather than continued; declare the endpoints, or one of the alternatives above, and start again. Development is exempt from the refusal.";
			}

			string diagnosis = "no HTTPS request path was found in the transport configuration visible at startup."
				+ $"{Environment.NewLine}  Observed endpoints: " + observedEndpoints + "."
				+ pluralPortKeyNote
				+ $"{Environment.NewLine}  Outside Development, the antiforgery cookie is Secure-only BY DESIGN (finding M-02 - CWE-614, CWE-319), so if this host resolves to plaintext only, form generation fails inside DefaultAntiforgery.CheckSSLConfig with 'the current request is not an SSL request' and every form-bearing page - '/login' included - answers HTTP 500. The authentication cookie remains Secure-only in every environment (finding H-15 - CWE-614, CWE-1004, CWE-319). Development deliberately makes only the antiforgery cookie follow the request scheme so local plaintext forms remain usable. Weakening the non-Development antiforgery policy or the authentication-cookie policy is NOT the remedy: it reinstates the vulnerability those findings closed."
				+ $"{Environment.NewLine}  Supply ANY ONE of the following, then restart:"
				+ $"{Environment.NewLine}    - an HTTPS endpoint of this process: 'ASPNETCORE_URLS' including an https:// address, together with 'Kestrel__Certificates__Default__Path' and 'Kestrel__Certificates__Default__Password' - or a '"
				+ KestrelEndpointsConfigurationSection
				+ "' entry whose Url is https;"
				+ $"{Environment.NewLine}    - BOTH trust for the reverse proxy that terminates TLS AND the public HTTPS port, when TLS is terminated in front of this process: '"
				+ ForwardedHeadersConfigurationSection.Replace(":", "__", StringComparison.Ordinal)
				+ "__KnownProxies' or '"
				+ ForwardedHeadersConfigurationSection.Replace(":", "__", StringComparison.Ordinal)
				+ "__KnownNetworks', TOGETHER WITH 'ASPNETCORE_HTTPS_PORT' or 'HTTPS_PORT' (configuration key '"
				+ HttpsRedirectionPortConfigurationKey
				+ "'), and configure that proxy to forward 'X-Forwarded-Proto: https' - trusting a proxy that does not send it leaves this failure in place. Neither half counts on its own: the port only selects the target of a redirect and does not make an HTTPS endpoint exist, and trusting a proxy says who may be believed rather than that anything terminates TLS. The port must be a whole number between 1 and 65535. The PLURAL 'ASPNETCORE_HTTPS_PORTS' is a DIFFERENT key ('"
				+ HttpsPortsConfigurationKey
				+ "', WebHostDefaults.HttpsPortsKey) and substitutes for neither half: it is resolved by GenericWebHostService, and only under the GENERIC host with 'urls' empty, so on this host - built by WebHost.CreateDefaultBuilder - it binds no endpoint and arms no redirect;"
				+ $"{Environment.NewLine}    - nothing at all when hosted in-process behind IIS: the ASP.NET Core Module supplies '"
				+ AncmHttpsPortConfigurationKey
				+ "' by itself whenever the site has an HTTPS binding, and in-process hosting preserves the request scheme."
				+ $"{Environment.NewLine}  See docs/security/secure-configuration.md for the complete transport-security configuration."
				+ $"{Environment.NewLine}  " + closingNote;

			if (!isDevelopment)
				throw new InvalidOperationException("WebVella ERP startup aborted - " + diagnosis);

			// Reported in the same shape as the platform's other startup security notice - the disabled
			// token-route warning in ErpSettings - so both read alike in a host log and an operator has
			// one idiom to recognise rather than two.
			Console.Error.WriteLine("warn: WebVella.Erp.Web.ErpMvcServicesExtensions[1] SECURITY - " + diagnosis);
		}

		// Reads one public HTTPS port from configuration, or null when the key is absent or blank.
		// SECURITY (CWE-1188 insecure default initialization), OWASP A05:2021: the port used to be tested for
		// non-blankness alone, so any string whatsoever counted as proof that this application had an HTTPS
		// request path. A malformed value ABORTS startup rather than being treated as absent, because the
		// redirect it was meant to arm is silently inert and an operator who mistyped it would otherwise be
		// told nothing at all. The value is quoted because a port is operator-supplied topology, not a secret.
		private static int? ReadPublicHttpsPort(IConfiguration configuration, string configurationKey)
		{
			string configuredValue = configuration?[configurationKey];
			if (string.IsNullOrWhiteSpace(configuredValue))
				return null;

			if (!int.TryParse(configuredValue.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int port)
				|| port < MinimumTcpPort || port > MaximumTcpPort)
			{
				throw new InvalidOperationException($"Configuration key '{configurationKey}' is set to '{configuredValue}', which is not a TCP port. Supply the public HTTPS port as a whole number between {MinimumTcpPort.ToString(CultureInfo.InvariantCulture)} and {MaximumTcpPort.ToString(CultureInfo.InvariantCulture)} - for example 443 - or remove the setting. While it is malformed, HTTPS redirection is silently inert and no plaintext request is redirected. See docs/security/secure-configuration.md.");
			}

			return port;
		}

		// True when Kestrel's configuration declares at least one endpoint whose Url is https. Read directly
		// rather than through KestrelServerOptions because this runs while the pipeline is being built, before
		// the server has bound anything, and the configuration section is the only declaration knowable then.
		private static bool IsKestrelHttpsEndpointDeclared(IConfiguration configuration)
		{
			IConfiguration endpointsSection = configuration?.GetSection(KestrelEndpointsConfigurationSection);
			if (endpointsSection == null)
				return false;

			foreach (IConfigurationSection endpoint in endpointsSection.GetChildren())
			{
				string url = endpoint["Url"];
				if (!string.IsNullOrWhiteSpace(url) && url.TrimStart().StartsWith(HttpsUriSchemePrefix, StringComparison.OrdinalIgnoreCase))
					return true;
			}

			return false;
		}

		// The single normalisation of a caller's address used by every per-source security control in the
		// platform - the request-rate partition above and the Content-Security-Policy report budget in
		// SecurityHeadersMiddleware. Two evasions are closed here (CWE-348 use of less trusted source). The
		// address is read from Connection.RemoteIpAddress, which UseErpForwardedHeaders has already replaced
		// with the real caller when - and only when - a trusted proxy supplied it, so a per-source budget
		// behind a proxy is per CALLER rather than per PROXY. And an IPv4 caller arriving over IPv4-mapped
		// IPv6 presents as "::ffff:203.0.113.7" while the same caller over IPv4 presents as "203.0.113.7", so
		// the mapped form is folded back or one client would hold two independent budgets. An unresolvable
		// address is bucketed under one shared key: an unidentifiable caller must not be the only one with no limit.
		internal static string DescribeRemoteAddress(HttpContext httpContext)
		{
			IPAddress address = httpContext?.Connection?.RemoteIpAddress;
			if (address == null)
				return "unknown";

			if (address.IsIPv4MappedToIPv6)
				address = address.MapToIPv4();

			return address.ToString();
		}

		// Applies the platform's authentication-cookie security contract.
		//
		// SECURITY (CWE-614 sensitive cookie without the Secure attribute, CWE-1275 improper SameSite attribute,
		// CWE-613 insufficient session expiration), OWASP A02 / A05, and Agent Action Plan section 0.6.1 Class
		// 6, which mandates "an always-secure policy, a same-site policy, an explicit expiry window and sliding
		// expiration". Each of the seven hosts carried its own copy and the copies had drifted from the frozen
		// contract: the secure policy relaxed to SameAsRequest whenever ASPNETCORE_ENVIRONMENT read
		// "Development", and sliding expiration was disabled. Seven duplicated copies is the ROOT CAUSE of that
		// drift, so the settings live here once and every host delegates to them.
		// SecurePolicy is Always UNCONDITIONALLY, Development included: http://localhost is a "potentially
		// trustworthy origin" under the W3C Secure Contexts specification and every current browser accepts a
		// Secure cookie over it, so the relaxation bought nothing and let a raw environment-variable read
		// decide a security attribute. SameSite is Lax and must NOT be "upgraded" to Strict, which withholds
		// the cookie on the return-URL round trip back from the login page and would break a working sign-in.
		// SlidingExpiration is true per the mandated contract, so the 24-hour window is an IDLE timeout, paired
		// with the absolute horizon in AuthService.ValidateSessionHorizonAsync because sliding renewal alone
		// would let a stolen cookie be kept alive for ever.
		public static void ConfigureErpAuthenticationCookie(CookieAuthenticationOptions options)
		{
			ArgumentNullException.ThrowIfNull(options);

			options.Cookie.HttpOnly = true;
			options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
			options.Cookie.SameSite = SameSiteMode.Lax;

			// The declared window and the ticket's explicit ExpiresUtc must agree, because an explicit
			// ExpiresUtc overrides ExpireTimeSpan and would otherwise make this line inert configuration.
			// AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES is the other half of that pair.
			options.ExpireTimeSpan = TimeSpan.FromMinutes(AuthenticationCookieLifetimeMinutes);
			options.SlidingExpiration = true;

			// Events is null until the framework's post-configuration step runs, which is after this method, so it
			// is created here when absent rather than dereferenced. No host sets a principal-validation handler of
			// its own - verified across all seven - so assigning this one cannot displace host behaviour.
			CookieAuthenticationEvents events = options.Events ?? new CookieAuthenticationEvents();
			events.OnValidatePrincipal = AuthService.ValidateSessionHorizonAsync;
			options.Events = events;
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
