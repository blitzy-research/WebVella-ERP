using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
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
		// The single configuration key that selects the Content-Security-Policy delivery mode. Held as
		// a constant so the lookup and the diagnostic message that names it can never drift apart -
		// a message quoting a key the code does not actually read would send an operator to fix the
		// wrong setting. Declared private because it is a binding detail of AddErp, not public API.
		private const string ContentSecurityPolicyReportOnlyConfigurationKey = "SecurityHeaders:ContentSecurityPolicyReportOnly";

		// Configuration section carrying the trusted reverse-proxy declaration consumed by
		// UseErpForwardedHeaders.
		private const string ForwardedHeadersConfigurationSection = "Settings:ForwardedHeaders";

		// Separators accepted between entries in the KnownProxies and KnownNetworks lists. Both are
		// accepted because operators supply these through environment variables, where a semicolon is
		// the more familiar separator, and through JSON, where a comma is.
		private static readonly char[] ForwardedHeadersListSeparators = new[] { ',', ';' };

		// Default number of forwarded entries consumed from a single X-Forwarded-For header.
		//
		// THREAT ADDRESSED - CWE-348 (use of less trusted source): X-Forwarded-For is a LIST, appended to
		// by every hop. Only the entry appended by the trusted proxy nearest to this application is
		// trustworthy; every entry to its left was supplied by something further out, ultimately
		// including the caller itself. Consuming one entry per hop is therefore the whole control - raise
		// this only when a KNOWN number of trusted proxies sit in front of the application, and never to
		// a value larger than that number.
		private const int DefaultForwardedHeadersForwardLimit = 1;

		// The platform's session contract, applied identically by all seven hosts through
		// ConfigureErpAuthenticationCookie so no host can drift from it.
		private const double AuthenticationCookieLifetimeMinutes = 1440;

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
			// as a compile-time const with no setter, so this registration cannot be used to weaken
			// it; only the report-only/enforcing switch is settable.
			//
			// Registration only. The middleware's pipeline POSITION is deliberately NOT set here and must
			// never be: UseErp runs late in every host pipeline, whereas the headers have to be emitted
			// ahead of UseResponseCompression and ahead of both UseStaticFiles calls or they never reach
			// static and compressed responses at all. Each host therefore calls UseSecurityHeaders()
			// early in its own Configure method. This extension registers; the hosts order.
			//
			// THREAT ADDRESSED - finding CFG-02 (OWASP A05: Security Misconfiguration): the mandated
			// report-then-enforce Content-Security-Policy rollout was documented as being under
			// operator control, but the switch that selects the mode was bound to nothing.
			// AddOptions<T>() on its own only materialises the type with its compiled defaults, so no
			// configuration source could move the platform from report-only to enforcing. An operator
			// following the documented rollout would have set a value that was silently ignored and
			// would have believed the policy was enforcing when it was still only reporting.
			//
			// Exactly ONE member is bound - the report-only/enforce switch - from configuration key
			// "SecurityHeaders:ContentSecurityPolicyReportOnly" (environment variable
			// SecurityHeaders__ContentSecurityPolicyReportOnly, matching the environment-variable
			// supply model every other platform secret already uses). The policy TEXT is deliberately
			// left unbindable, so no configuration source - however trusted - can inject
			// 'unsafe-inline' or "default-src *" and void the header.
			//
			// Two failure directions are handled differently, deliberately:
			//
			//  - ABSENT or blank: the compiled default - report-only - stands. That is the mandated
			//    shipping posture, so an unconfigured deployment is correct rather than broken.
			//
			//  - PRESENT but not parseable as a boolean: startup is ABORTED. Silently ignoring such a
			//    value is the very defect this finding is about, and here it is the dangerous
			//    direction: the operator believes the policy is enforcing while it is still only
			//    reporting, so the platform would be less protected than its own documentation
			//    claims. Guessing "enforcing" instead is equally unacceptable - it would block the
			//    four components that deliberately emit inline script and break the interface. The
			//    only correct response to an ambiguous security-mode value is to refuse to run, which
			//    is the same fail-fast posture ErpSettings.ValidateRequiredSecurityConfiguration
			//    already applies to missing secrets. The supplied value is not echoed, only the key
			//    name and the accepted values, so a value pasted into the wrong variable cannot leak
			//    into a log or a console.
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

			// THREAT ADDRESSED - finding F-06, CWE-319 (cleartext transmission of sensitive information)
			// and CWE-614 (sensitive cookie without 'Secure' attribute), OWASP A02 / A05. Every host calls
			// app.UseHsts(), but no host ever configured HstsOptions - and the framework's defaults are
			// thirty days with subdomains excluded, not the mandated one year including subdomains.
			// HstsMiddleware assigns Strict-Transport-Security by indexer, exactly as
			// SecurityHeadersMiddleware does, so whichever runs LAST decides the wire value. Because
			// UseSecurityHeaders() must be ordered early - ahead of response compression and both
			// UseStaticFiles calls - HstsMiddleware always ran after it and always won, and the wire value
			// on every HTTPS response was "max-age=2592000": the mandated header was written and then
			// silently overwritten with a weaker one. Configuring the framework's own options here makes
			// the two writers emit the identical string, so the overwrite is a genuine no-op in either
			// order and there is exactly ONE exact HSTS value in the application.
			//
			// Registered at the platform's single canonical service-registration extension so all seven
			// hosts inherit it from one edit, matching how the header middleware's own options are
			// registered immediately above. Values are the mandated ones, single-sourced conceptually with
			// SecurityHeadersMiddleware.StrictTransportSecurityValue ("max-age=31536000; includeSubDomains"):
			//   MaxAge            365 days = 31536000 seconds
			//   IncludeSubDomains true, which the mandated value requires
			//   Preload           false - deliberately. Preload is NOT in the mandated value, and submitting
			//                     an origin to the browser preload list is effectively irreversible, so it
			//                     must never be switched on implicitly by a security fix.
			// ExcludedHosts is left at the framework default (localhost, 127.0.0.1, [::1]): it suppresses
			// the header only for loopback, which is the same protection the Development guard in
			// SecurityHeadersMiddleware provides, and narrowing or clearing it would pin developers' whole
			// localhost origin to HTTPS for a year.
			services.AddHsts(hstsOptions =>
			{
				hstsOptions.MaxAge = TimeSpan.FromDays(365);
				hstsOptions.IncludeSubDomains = true;
				hstsOptions.Preload = false;
			});

			// THREAT ADDRESSED - finding M-02, CWE-614 (sensitive cookie in HTTPS session without the
			// 'Secure' attribute) and CWE-1004, OWASP A05: the antiforgery cookie was left entirely at
			// the framework default, which is CookieSecurePolicy.None. Only the authentication cookie was
			// hardened, so the request-verification token travelled over plaintext whenever a client
			// reached the site over HTTP - and because that token is what authorises every state-changing
			// Razor Pages POST, including the login form, an attacker on the network path could capture it
			// and pair it with a captured session.
			//
			// Configured here rather than per host for the same register-once reason as the header and
			// HSTS options above: no host calls AddAntiforgery at all, so a single IConfigureOptions
			// registration is the only edit that reaches all seven of them. Only SecurePolicy is set; the
			// token validation behaviour, the cookie name and its SameSite=Strict default are all left
			// exactly as the framework and the existing clients expect them, so no working request is
			// affected.
			//
			// Always, with NO Development carve-out, because that is precisely the contract
			// ConfigureErpAuthenticationCookie applies to the authentication cookie - unconditionally,
			// including in Development. The two cookies must not disagree, and a Development-only
			// relaxation here would buy nothing: http://localhost is a potentially trustworthy origin and
			// browsers accept a Secure cookie over it, which is the same reason the authentication cookie
			// needs no carve-out. Making this one environment-dependent would leave the platform with a
			// single security attribute whose value turns on an environment name, and a developer running
			// over plain HTTP on a non-loopback host would then get a validating antiforgery token while
			// holding no authentication cookie at all - a state no deployment posture actually wants. No
			// IWebHostEnvironment is taken for the same reason: there is nothing left to branch on.
			services.AddOptions<Microsoft.AspNetCore.Antiforgery.AntiforgeryOptions>().Configure(antiforgeryOptions =>
			{
				antiforgeryOptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;
			});

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
			// The service holds one process-lifetime WebVella.Erp.Web.Utils.Cache and exposes no
			// disposal surface, matching the platform's own cache usage in ErpAppContext; the store is
			// released with the process.
			services.AddSingleton<LoginThrottleService>();

			// THREAT ADDRESSED - finding F8 (session hijacking), CWE-613 (insufficient session
			// expiration), OWASP A07: the cookie authentication ticket is entirely self-contained, so
			// signing out only deleted the cookie in the browser that asked for it. A ticket copied
			// beforehand - lifted from a shared machine, a proxy or reverse-proxy log, a backup, or
			// exfiltrated by script - stayed valid for the whole eight-hour ticket lifetime, and nothing
			// the user or an administrator could do would stop it. Logging out did not end the session;
			// it only forgot one copy of it.
			//
			// Singleton for the same reason as the throttle above, and not merely for convenience: the
			// revocation entries live in the service's own in-process store, so a transient or scoped
			// lifetime would hand every request a brand new, empty store and nothing would ever be seen
			// as revoked. The container disposes it on shutdown, which releases that store.
			services.AddSingleton<SessionRevocationService>();

			// THREAT ADDRESSED - finding F8, continued. Registering the service is inert on its own; the
			// control only exists once the identifier is CONSULTED, which has to happen on every
			// authenticated request rather than at the login page. This is that consultation point: the
			// framework's own ticket-validation hook, which runs for each request that presents a cookie,
			// before the endpoint sees the principal. AuthService.Authenticate mints a fresh
			// CLAIM_SESSION_ID into every ticket and AuthService.LogoutAsync revokes it, so after a sign-out
			// every other copy of the same ticket is rejected on its next request no matter which browser
			// holds it. That is what turns "delete my cookie" into "end this session".
			//
			// PostConfigureAll is chosen deliberately over Configure, for three reasons:
			//   * it applies to EVERY named cookie options instance, so a host that registers an additional
			//     cookie scheme is covered without a further edit - the seven hosts each name their own
			//     cookie (erp_auth_base, erp_auth_mail and so on) and must not have to remember this;
			//   * post-configuration runs AFTER each host's own AddCookie callback, so a host cannot
			//     accidentally overwrite the hook by assigning Events itself;
			//   * it keeps the control in the single canonical registration extension, so all seven hosts
			//     inherit it from one edit, exactly as the headers middleware and the throttle do.
			// The previously configured delegate is captured and invoked FIRST, so this composes with the
			// handler already in place instead of replacing it. THAT CHAINING IS LOAD-BEARING, NOT
			// DEFENSIVE: ConfigureErpAuthenticationCookie - which all seven hosts pass to AddCookie -
			// assigns AuthService.ValidateSessionHorizonAsync, the absolute session horizon that stops a
			// slid cookie living for ever. Post-configuration runs after that assignment, so dropping the
			// capture-and-invoke would overwrite the horizon check and silently reduce the sliding
			// 24-hour idle window back to an unbounded session, trading one session-expiry finding for a
			// worse one. Order matters too: the horizon runs first, and its rejection is honoured by the
			// Principal null check below.
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

					// A ticket with no session claim is left alone rather than refused. That is deliberate and
					// is what makes this control deployable without logging everyone out: tickets minted before
					// this change carry no claim, and bearer principals never carry one at all.
					var sessionClaim = validationContext.Principal.FindFirst(AuthService.CLAIM_SESSION_ID);
					if (sessionClaim == null || !Guid.TryParse(sessionClaim.Value, out var sessionId))
						return;

					// GetService, not GetRequiredService: a host that configures cookie authentication without
					// calling AddErp must not be broken by a hook it never asked for. Where the service IS
					// registered - every ERP host - an identifier it has never been told about is simply not
					// revoked, so this cannot refuse a legitimate session.
					var revocationService = validationContext.HttpContext.RequestServices.GetService<SessionRevocationService>();
					if (revocationService == null || !revocationService.IsRevoked(sessionId))
						return;

					// Reject first, then clear the cookie. Ordered this way the CURRENT request is already
					// unauthenticated even if the sign-out itself fails, so the security outcome does not
					// depend on the cleanup succeeding.
					validationContext.RejectPrincipal();
					await validationContext.HttpContext.SignOutAsync(validationContext.Scheme.Name);
				};
			});

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
			// THREAT ADDRESSED - review finding M-REV-08 (CWE-348, use of less trusted source; CWE-307):
			// the partition key was read straight off the transport connection with no forwarded-header
			// processing anywhere in the platform. Behind the reverse proxy this application is designed
			// to run behind - WebVella.Erp.Site ships a web.config for IIS hosting - every caller
			// therefore collapsed into ONE partition keyed on the proxy's own address, which inverts the
			// control completely: ordinary users starve each other out of a shared 600-request budget
			// while a single abusive client is indistinguishable from the crowd it is hidden behind. The
			// key is now taken from DescribeRemoteAddress, which reads the address AFTER the trusted
			// forwarded-headers middleware has had its chance to replace it, and normalises the two
			// spellings of the same IPv4 caller so a client cannot buy a second budget by connecting
			// over IPv4-mapped IPv6.
			//
			// The trust half of that fix lives in UseErpForwardedHeaders, which every host calls FIRST in
			// its pipeline and which refuses to honour a forwarded address at all until an operator names
			// the proxies that may send one. Nothing here trusts a header directly.
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

		public static IApplicationBuilder UseErp(this IApplicationBuilder app, List<JobType> additionalJobTypes = null, string configFolder = null)
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
				IWebHostEnvironment env = app.ApplicationServices.GetService<IWebHostEnvironment>();

				if (!ErpSettings.IsInitialized) {
					// DEFECT ADDRESSED - review finding F30 (Configuration / Availability), CWE-16, OWASP
					// A05:2021 Security Misconfiguration. Same defect as WebVella.Erp.ConsoleApp/Program.cs,
					// and this is the single initialization path for all seven hosts, so it matters more here.
					// THREAT: the tracked file is Config.json and that is the name the SDK copies to the output,
					// but this chain asked for lower-case config.json. On a case-insensitive filesystem they are
					// the same file; on Linux they are not, and because this JSON source is deliberately
					// NON-optional - the shipped files are blanked rather than deleted, so an absent file must
					// fail loudly - the host aborted before AddEnvironmentVariables below could supply any
					// secret. Deployments only worked because publish tooling wrote a lower-case duplicate. That
					// duplicate is why the probe PREFERS the correctly cased name and falls back rather than
					// switching: every existing deployment carrying only config.json must keep starting.
					string configPath = "Config.json";
					string lowerCaseConfigPath = "config.json";
					if (!string.IsNullOrWhiteSpace(configFolder))
					{
						configPath = System.IO.Path.Combine(configFolder, configPath);
						lowerCaseConfigPath = System.IO.Path.Combine(configFolder, lowerCaseConfigPath);
					}

					// Resolved against AppContext.BaseDirectory, which is EXACTLY the base path the builder
					// below sets - so the probe tests the same location the provider will actually read. It
					// deliberately does NOT use env.ContentRootPath: WebHost.CreateDefaultBuilder defaults that
					// to Directory.GetCurrentDirectory(), so probing it would test whatever working directory
					// the process happened to be launched with while the provider read from the assembly
					// directory. The two disagree in every deployment launched from anywhere other than the
					// application folder, which would make this fallback both unreliable (a lower-case-only
					// publish output goes undetected, and the host still aborts) and unsound (a file found in
					// an attacker-writable working directory decides which path is selected). An absolute
					// configFolder is honoured unchanged by Path.Combine, matching the pre-existing behaviour
					// of that parameter.
					if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
						&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, lowerCaseConfigPath)))
						configPath = lowerCaseConfigPath;

					// SECURITY - findings C-04, H-04 and H-05 (CWE-798 use of hard-coded credentials, CWE-321
					// use of a hard-coded cryptographic key; review finding M-2, CWE-20 improper input
					// validation), OWASP A05 Security Misconfiguration.
					// THREAT: this is the single initialization path that feeds ErpSettings for every one of the
					// seven hosts, and it consumed the JSON file and nothing else. Config.json was therefore the
					// ONLY channel through which a secret could ever be supplied, which had two consequences:
					// the platform's own startup errors named environment variables that no provider could
					// satisfy, and blanking those files - the paired step of this remediation - would have left
					// every host permanently unstartable with no way to supply a replacement value.
					//
					// Provider ORDER is the control, not an incidental detail. Later providers win, so the
					// tracked JSON file stays FIRST and environment variables come immediately AFTER it: the
					// shipped secret values are blanked to empty strings rather than removed, so only a later
					// provider can put a real secret back. Reverse the two and the blank JSON string would
					// clobber the operator's environment variable and every host would abort on ErpSettings'
					// fail-fast validation. Keys use the framework's section separator - for example
					// Settings__ConnectionString, Settings__EncryptionKey and Settings__Jwt__Key; the complete
					// list is in docs/security/secure-configuration.md. Nothing is defaulted or logged here.
					// The JSON source stays NON-optional on purpose: the Config.json files are blanked, never
					// deleted, so an absent file must still fail loudly rather than yield a silently empty
					// configuration.
					//
					// SECURITY - CWE-706 use of an incorrectly resolved name, same OWASP A05 category. The
					// base path is AppContext.BaseDirectory, the directory the entry assembly was loaded
					// from and exactly where both the build and the publish output place Config.json. It is
					// NOT env.ContentRootPath, which WebHost.CreateDefaultBuilder defaults to
					// Directory.GetCurrentDirectory() - so the file supplying the connection string, the
					// data-at-rest encryption key and the token signing key would otherwise be selected by
					// whatever working directory the process was launched with. That lets a launcher, or
					// anyone able to write to a directory the service is started from, decide which
					// Config.json the platform trusts.
					var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);
					configurationBuilder.AddEnvironmentVariables();

					if (env.IsDevelopment())
					{
						// User secrets come LAST, and only in Development, so a developer's own store takes
						// precedence over an ambient machine-wide environment variable - which is the whole
						// reason the store exists. It is never load-bearing: outside Development this provider is
						// not added at all, because the store sits unencrypted on disk and must never be a
						// production supply channel. Every non-development chain is therefore exactly
						// JSON file then environment variables.
						// The entry assembly is the host executable, so each host resolves its own store rather
						// than this library's - this library declares no UserSecretsId and must not.
						// optional: true is stated EXPLICITLY rather than left to an overload default, because
						// only ONE of the seven hosts declares a UserSecretsId at all and every AddUserSecrets
						// overload given optional: false throws InvalidOperationException when that attribute is
						// absent - which would abort startup for the other six hosts and the console
						// application, turning a secret-management fix into an outage. Pinning the value here
						// means the tolerant behaviour is a contract at this call site rather than an
						// invisible default that a later overload change could silently flip.
						var entryAssembly = Assembly.GetEntryAssembly();
						if (entryAssembly != null)
							configurationBuilder.AddUserSecrets(entryAssembly, optional: true);
					}

					ErpSettings.Initialize(configurationBuilder.Build());
				}

				// THREAT ADDRESSED - review finding F12 (OWASP A05: Security Misconfiguration): force the
				// security-header options to materialise here, immediately after the configuration provider
				// chain is in place, so that the Content-Security-Policy posture is parsed and validated at
				// startup. Without this the binding delegate would first run when the pipeline is built, and a
				// malformed value would surface as an opaque middleware construction failure on the first
				// request rather than as an actionable startup error naming the key and the bad value.
				//
				// The resolved instance is inspected rather than discarded so that a container misconfiguration
				// - options registered but resolving to null - is caught here too, instead of silently falling
				// back inside the middleware constructor and leaving an operator unable to tell whether their
				// configured posture took effect.
				IOptions<Middleware.SecurityHeadersOptions> securityHeaderOptions =
					app.ApplicationServices.GetService<IOptions<Middleware.SecurityHeadersOptions>>();

				if (securityHeaderOptions?.Value == null)
				{
					throw new InvalidOperationException(
						"Security response header options could not be resolved. AddErp() must be called during ConfigureServices before UseErp() is called, so that the Content-Security-Policy posture configured through '"
						+ ContentSecurityPolicyReportOnlyConfigurationKey
						+ "' is applied.");
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

		// Enables trusted reverse-proxy forwarded-header processing, and nothing else.
		//
		// THREAT ADDRESSED - review finding M-REV-08 (CWE-348 use of less trusted source, CWE-290
		// authentication bypass by spoofing, CWE-307 improper restriction of excessive attempts), OWASP
		// A05 Security Misconfiguration. No forwarded-header processing existed anywhere in the platform,
		// so behind a reverse proxy - the topology WebVella.Erp.Site's own web.config describes - three
		// separate security controls silently degraded at once:
		//   * the request-rate partition collapsed onto the proxy's address, so every caller shared one
		//     budget and no individual abuser could be isolated;
		//   * the per-address half of the login lockout keyed on the proxy too, so one attacker's failures
		//     counted against every other user of that proxy;
		//   * Request.IsHttps read false for requests the client actually made over TLS, which is what
		//     HTTPS redirection and the Secure cookie policy both read.
		//
		// DENY BY DEFAULT, AND WHY IT IS EXPRESSED AS "DO NOT REGISTER" RATHER THAN "REGISTER WITH AN
		// EMPTY LIST". This is the load-bearing detail of the whole fix. ForwardedHeadersMiddleware
		// decides whether to check the peer against the trusted lists with, in effect,
		// `checkKnownIps = KnownIPNetworks.Count > 0 || KnownProxies.Count > 0`. Registering it with BOTH
		// lists empty therefore disables the check altogether and the middleware honours X-Forwarded-For
		// from ANY peer on the internet - the exact spoofing primitive this finding is about, installed by
		// the fix meant to prevent it. The only configuration that genuinely trusts nobody is not to add
		// the middleware, so that is what an unconfigured deployment gets: X-Forwarded-* is ignored
		// entirely and Connection.RemoteIpAddress stays the true transport peer.
		//
		// Operators opt in by naming their proxies - Settings__ForwardedHeaders__KnownProxies and/or
		// Settings__ForwardedHeaders__KnownNetworks. When they do, the framework's own defaults
		// (loopback only) are CLEARED first, so the effective trust set is exactly what was declared and
		// never that plus something inherited.
		//
		// Pipeline position is the caller's responsibility and is documented at every call site: this must
		// run before UseSecurityHeaders, UseHsts, UseHttpsRedirection and UseRateLimiter, because each of
		// those reads either the scheme or the remote address that this middleware corrects.
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

		// Builds the forwarded-header options from configuration, or returns null when no proxy is
		// trusted. Malformed entries abort startup rather than being skipped: silently dropping a
		// mistyped proxy address would leave an operator believing the caller's real address was being
		// recovered while the rate limiter and the login lockout continued to key on the proxy. The
		// offending entry is named in the message because a network address is operator-supplied topology,
		// not a secret, and naming it is the difference between an actionable error and a guessing game.
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
				// Only the two headers the platform actually consumes are honoured. X-Forwarded-Host is
				// deliberately NOT included: accepting it would let a trusted proxy - or anything that
				// compromised it - rewrite the host this application believes it is serving, which is a
				// host-header injection and absolute-URL poisoning primitive with no offsetting benefit
				// here, because nothing in this platform builds absolute URLs from Request.Host for
				// security decisions.
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
				// System.Net.IPNetwork is used rather than the Microsoft.AspNetCore.HttpOverrides type of
				// the same name, and KnownIPNetworks rather than KnownNetworks, because both of the older
				// spellings are marked obsolete in this framework version and using them would introduce
				// new build warnings.
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

			// A non-positive or unparseable limit is rejected rather than coerced. ForwardLimit is
			// nullable in the framework and null means "consume every entry in the header", which hands
			// the caller control of the address this application believes it is talking to; that value is
			// unreachable from configuration on purpose.
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

		// The single normalisation of a caller's address used by every per-source security control in the
		// platform - the request-rate partition above and the Content-Security-Policy report budget in
		// SecurityHeadersMiddleware.
		//
		// THREAT ADDRESSED - review findings M-REV-08 and L-REV-03: two distinct evasions are closed
		// here. First, the address is read from Connection.RemoteIpAddress, which
		// UseErpForwardedHeaders has already replaced with the real caller when - and only when - a
		// trusted proxy supplied it, so a per-source budget behind a proxy is per CALLER rather than per
		// PROXY. Second, an IPv4 caller reaching the server over IPv4-mapped IPv6 presents as
		// "::ffff:203.0.113.7" while the same caller over IPv4 presents as "203.0.113.7"; keying on the
		// raw string would give one client two independent budgets, so the mapped form is folded back to
		// its IPv4 spelling.
		//
		// An unresolvable address is bucketed under one shared key rather than being waved through: an
		// unidentifiable caller must not be the only caller with no limit.
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
		// THREAT ADDRESSED - review finding M-REV-09 (CWE-614 sensitive cookie without the Secure
		// attribute, CWE-1275 improper SameSite attribute, CWE-613 insufficient session expiration),
		// OWASP A02 / A05, and Agent Action Plan section 0.6.1 Class 6, which mandates "an always-secure
		// policy, a same-site policy, an explicit expiry window and sliding expiration". Each of the seven
		// hosts previously carried its own copy of these settings, and the copies had drifted from the
		// frozen contract in two ways that mattered: the secure policy relaxed itself to SameAsRequest
		// whenever ASPNETCORE_ENVIRONMENT read "Development", and sliding expiration was disabled. Seven
		// duplicated copies is also the ROOT CAUSE of that drift, not merely where it showed up, so the
		// settings now live here once and every host delegates to them. A future edit cannot desynchronise
		// six hosts from the seventh because there is only one place left to edit.
		//
		// SecurePolicy is Always UNCONDITIONALLY, including in Development. The previous Development
		// relaxation was justified by local development being served over plaintext, but that
		// justification does not hold: http://localhost is a "potentially trustworthy origin" under the
		// W3C Secure Contexts specification, and every current browser therefore accepts a Secure cookie
		// over it - Chromium since 89, Firefox since 75. The relaxation bought nothing and cost the
		// mandated attribute, and worse, it keyed off a raw environment variable read, so an unset or
		// misspelled variable silently decided a security attribute.
		//
		// SameSite is Lax and must not be "upgraded" to Strict: Strict withholds the cookie on the
		// return-URL round trip back from the login page, which would break a working sign-in. Lax is the
		// framework's own default posture and still withholds the cookie from cross-site POSTs.
		//
		// SlidingExpiration is true, per the mandated contract, and the 24-hour window is therefore an
		// IDLE timeout rather than an absolute one. Sliding renewal on its own would let a stolen cookie
		// be kept alive for ever, so it is paired with an absolute session horizon enforced in
		// AuthService.ValidateSessionHorizonAsync - the same ceiling the bearer-token path already
		// applies. Enabling one without the other would trade a session-expiry finding for a worse one.
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

			// Events is null until the framework's post-configuration step runs, which is after this
			// method, so it is created here when absent rather than dereferenced. No host sets a
			// principal-validation handler of its own - verified across all seven - so assigning this one
			// cannot displace host behaviour.
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
